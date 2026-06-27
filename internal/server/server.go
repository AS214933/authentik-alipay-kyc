package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/alipay"
	aliyunkyc "github.com/example/authentik-alipay-kyc/internal/aliyun"
	"github.com/example/authentik-alipay-kyc/internal/authentik"
	"github.com/example/authentik-alipay-kyc/internal/config"
	identitycrypto "github.com/example/authentik-alipay-kyc/internal/crypto"
	"github.com/example/authentik-alipay-kyc/internal/oidc"
	"github.com/example/authentik-alipay-kyc/internal/piistore"
	"github.com/example/authentik-alipay-kyc/internal/session"
	"github.com/example/authentik-alipay-kyc/internal/stats"
)

const (
	ProviderAlipay = "alipay"
	ProviderAliyun = "aliyun"

	AlipayPendingTTL = 23 * time.Hour
	AliyunPendingTTL = 30 * time.Minute
)

type OIDCClient interface {
	AuthCodeURL(state, nonce string) string
	Exchange(ctx context.Context, code, nonce string) (oidc.Claims, error)
}

type AuthentikClient interface {
	GetUser(ctx context.Context, userID string) (authentik.User, error)
	MarkVerified(ctx context.Context, userID string, attr authentik.KYCAttribute) error
}

type AlipayClient interface {
	Initialize(ctx context.Context, outerOrderNo, certName, certNo, returnURL string) (alipay.InitializeResponse, error)
	CertifyURL(certifyID string) (string, error)
	Query(ctx context.Context, certifyID string) (alipay.QueryResponse, error)
}

type AliyunClient interface {
	Initialize(ctx context.Context, req aliyunkyc.InitializeRequest) (aliyunkyc.InitializeResponse, error)
	Query(ctx context.Context, certifyID string) (aliyunkyc.QueryResponse, error)
}

type StatsStore interface {
	Snapshot() (stats.Counters, error)
	IncrementTotal() error
	IncrementSuccess() error
	IncrementFailure() error
}

type PIIStore interface {
	Append(entry piistore.Entry) error
}

type Dependencies struct {
	Config     config.Config
	Logger     *slog.Logger
	OIDC       OIDCClient
	Authentik  AuthentikClient
	Alipay     AlipayClient
	Aliyun     AliyunClient
	Stats      StatsStore
	PII        PIIStore
	StaticFS   http.FileSystem
	HTTPClient *http.Client
}

type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	oidc      OIDCClient
	authentik AuthentikClient
	alipay    AlipayClient
	aliyun    AliyunClient
	stats     StatsStore
	pii       PIIStore
	staticFS  http.FileSystem
	sessions  *session.Store
	pendingMu sync.Mutex
	settleMu  sync.Mutex
	pending   map[string]pendingKYC
	terminal  map[string]terminalKYC
}

type errorResponse struct {
	Error string `json:"error"`
}

type pendingKYC struct {
	State      string
	Provider   string
	CertifyID  string
	UserID     string
	NameMasked string
	IDHash     string
	IDLast4    string
	ExpiresAt  time.Time
}

type kycStartResult struct {
	Provider     string
	CertifyID    string
	CertifyURL   string
	AppLaunchURL string
}

type kycStartInput struct {
	State          string
	OuterOrderNo   string
	Name           string
	IDNumber       string
	MetaInfo       string
	CertifyURLType string
	UserID         string
}

type settleKYCResult struct {
	Passed    bool
	Expired   bool
	Attribute authentik.KYCAttribute
}

type verifiedIdentity struct {
	UserID       string
	Username     string
	State        string
	CertifyID    string
	OuterOrderNo string
	Name         string
	IDNumber     string
	Channel      string
	Verified     bool
}

type terminalKYC struct {
	Expired   bool
	Attribute authentik.KYCAttribute
	ExpiresAt time.Time
}

func New(deps Dependencies) *Server {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if deps.Config.KYCTimeout <= 0 {
		deps.Config.KYCTimeout = AlipayPendingTTL
	}
	if deps.Config.KYCPollInterval <= 0 {
		deps.Config.KYCPollInterval = time.Minute
	}
	return &Server{
		cfg:       deps.Config,
		logger:    logger,
		oidc:      deps.OIDC,
		authentik: deps.Authentik,
		alipay:    deps.Alipay,
		aliyun:    deps.Aliyun,
		stats:     deps.Stats,
		pii:       deps.PII,
		staticFS:  deps.StaticFS,
		sessions:  session.New(deps.Config.Session),
		pending:   map[string]pendingKYC{},
		terminal:  map[string]terminalKYC{},
	}
}

func (s *Server) StartKYCWorker(ctx context.Context) {
	interval := s.cfg.KYCPollInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkPendingKYC(ctx)
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.oidcCallback)
	mux.HandleFunc("GET /verify/callback", s.alipayReturn)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/stats", s.statsSnapshot)
	mux.HandleFunc("GET /api/admin/status", s.adminStatus)
	mux.HandleFunc("POST /api/admin/login", s.adminLogin)
	mux.HandleFunc("POST /api/admin/logout", s.adminLogout)
	mux.HandleFunc("POST /api/admin/import", s.adminImport)
	mux.HandleFunc("POST /api/kyc/start", s.startKYC)
	mux.HandleFunc("POST /api/kyc/confirm", s.confirmKYC)
	mux.HandleFunc("POST /api/alipay/notify", s.alipayNotify)
	mux.HandleFunc("/", s.spa)
	return requestLogger(s.logger, secureHeaders(mux))
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	state, err := oidc.RandomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create state")
		return
	}
	nonce, err := oidc.RandomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create nonce")
		return
	}
	if err := s.sessions.Save(r, w, map[interface{}]interface{}{
		session.OIDCStateKey: state,
		session.OIDCNonceKey: nonce,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save session")
		return
	}
	http.Redirect(w, r, s.oidc.AuthCodeURL(state, nonce), http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Get(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session")
		return
	}
	expectedState, _ := sess.Values[session.OIDCStateKey].(string)
	nonce, _ := sess.Values[session.OIDCNonceKey].(string)
	if expectedState == "" || nonce == "" || r.URL.Query().Get("state") != expectedState {
		writeError(w, http.StatusBadRequest, "invalid oidc state")
		return
	}
	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		writeError(w, http.StatusBadRequest, "oidc error: "+oauthErr)
		return
	}
	claims, err := s.oidc.Exchange(r.Context(), r.URL.Query().Get("code"), nonce)
	if err != nil {
		s.logger.Warn("oidc exchange failed", "error", err)
		writeError(w, http.StatusBadRequest, "oidc login failed")
		return
	}
	userID := claims.ClaimString(s.cfg.Authentik.UserIDClaim)
	if userID == "" {
		writeError(w, http.StatusBadRequest, "oidc token is missing authentik user id claim "+s.cfg.Authentik.UserIDClaim)
		return
	}
	displayName := firstNonEmpty(claims.Name, claims.Nickname, claims.PreferredUsername, claims.Email, claims.Subject)
	if err := s.sessions.Save(r, w, map[interface{}]interface{}{
		session.UserIDKey:      userID,
		session.UsernameKey:    claims.PreferredUsername,
		session.EmailKey:       claims.Email,
		session.DisplayNameKey: displayName,
		session.OIDCStateKey:   nil,
		session.OIDCNonceKey:   nil,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save login")
		return
	}
	http.Redirect(w, r, s.cfg.PublicURL+"/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.sessions.Clear(r, w); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to clear session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.currentUserID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"login_url": s.cfg.PublicURL + "/auth/login"})
		return
	}

	sess, _ := s.sessions.Get(r)
	user := map[string]interface{}{
		"id":           userID,
		"username":     stringValue(sess.Values[session.UsernameKey]),
		"email":        stringValue(sess.Values[session.EmailKey]),
		"display_name": stringValue(sess.Values[session.DisplayNameKey]),
	}
	response := map[string]interface{}{
		"authenticated":  true,
		"user":           user,
		"verified":       false,
		"qr_notice_html": s.cfg.QRNoticeHTML,
		"providers":      s.enabledProviders(),
	}

	akUser, err := s.authentik.GetUser(r.Context(), userID)
	if err != nil {
		s.logger.Warn("failed to load authentik user", "user_id", userID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to load authentik user")
		return
	}
	if attr, ok := akUser.Attributes[s.cfg.Authentik.AttributeKey]; ok {
		response["kyc"] = attr
		response["verified"] = kycAttributeVerified(attr)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) statsSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeStatsAPI(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="stats"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.stats == nil {
		writeError(w, http.StatusInternalServerError, "stats store is not configured")
		return
	}
	counters, err := s.stats.Snapshot()
	if err != nil {
		s.logger.Warn("failed to read stats", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read stats")
		return
	}
	writeJSON(w, http.StatusOK, counters)
}

func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := s.adminAuthenticated(r)
	response := map[string]interface{}{
		"enabled":       s.cfg.Admin.Enabled,
		"authenticated": authenticated,
	}
	if authenticated {
		if token, ok := s.adminCSRFToken(r); ok {
			response["csrf_token"] = token
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Admin.Enabled {
		writeError(w, http.StatusNotFound, "admin import is disabled")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if !s.compareAdminPassword(req.Password) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	csrfToken, err := oidc.RandomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create admin csrf token")
		return
	}
	if err := s.sessions.Save(r, w, map[interface{}]interface{}{
		session.AdminKey:     "true",
		session.AdminCSRFKey: csrfToken,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save admin session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"csrf_token":    csrfToken,
	})
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if !s.validAdminCSRF(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.sessions.Save(r, w, map[interface{}]interface{}{
		session.AdminKey:     nil,
		session.AdminCSRFKey: nil,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to clear admin session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (s *Server) adminImport(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Admin.Enabled {
		writeError(w, http.StatusNotFound, "admin import is disabled")
		return
	}
	if !s.validAdminCSRF(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		UserID   string `json:"user_id"`
		Name     string `json:"name"`
		IDNumber string `json:"id_number"`
		Verified *bool  `json:"verified"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	userID := strings.TrimSpace(req.UserID)
	name := strings.TrimSpace(req.Name)
	idNumber := identitycrypto.NormalizeIDNumber(req.IDNumber)
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if name == "" || len([]rune(name)) > 64 {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(idNumber) != 15 && len(idNumber) != 18 {
		writeError(w, http.StatusBadRequest, "id_number must be a 15 or 18 character identity card number")
		return
	}
	verified := true
	if req.Verified != nil {
		verified = *req.Verified
	}
	importToken, err := oidc.RandomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create import record id")
		return
	}
	importID := "admin-" + importToken[:16]
	attr, err := s.recordVerifiedIdentity(r.Context(), verifiedIdentity{
		UserID:       userID,
		State:        importID,
		CertifyID:    importID,
		OuterOrderNo: importID,
		Name:         name,
		IDNumber:     idNumber,
		Channel:      "admin",
		Verified:     verified,
	})
	if err != nil {
		s.logger.Warn("failed to import admin verification", "user_id", userID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to import verification")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"imported": true,
		"user_id":  userID,
		"kyc":      attr,
	})
}

func (s *Server) startKYC(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.currentUserID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"login_url": s.cfg.PublicURL + "/auth/login"})
		return
	}
	var req struct {
		Name           string `json:"name"`
		IDNumber       string `json:"id_number"`
		Provider       string `json:"provider"`
		MetaInfo       string `json:"meta_info"`
		CertifyURLType string `json:"certify_url_type"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	idNumber := identitycrypto.NormalizeIDNumber(req.IDNumber)
	if req.Name == "" || len([]rune(req.Name)) > 64 {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(idNumber) != 15 && len(idNumber) != 18 {
		writeError(w, http.StatusBadRequest, "id_number must be a 15 or 18 character identity card number")
		return
	}
	sess, err := s.sessions.Get(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session")
		return
	}
	s.recordTotal()
	state, err := oidc.RandomToken()
	if err != nil {
		s.recordFailure()
		writeError(w, http.StatusInternalServerError, "failed to create verification state")
		return
	}
	orderToken, err := oidc.RandomToken()
	if err != nil {
		s.recordFailure()
		writeError(w, http.StatusInternalServerError, "failed to create order number")
		return
	}
	provider := normalizeProvider(req.Provider)
	if !s.providerEnabled(provider) {
		s.recordFailure()
		writeError(w, http.StatusBadRequest, "unsupported verification provider")
		return
	}
	if provider == ProviderAliyun && strings.TrimSpace(req.MetaInfo) == "" {
		s.recordFailure()
		writeError(w, http.StatusBadRequest, "meta_info is required for aliyun verification")
		return
	}
	if provider == ProviderAliyun && !validAliyunCertifyURLType(req.CertifyURLType) {
		s.recordFailure()
		writeError(w, http.StatusBadRequest, "certify_url_type must be WEB or H5 for aliyun verification")
		return
	}
	s.clearExistingPendingFromSession(sess.Values)
	outerOrderNo := "ak" + time.Now().UTC().Format("20060102150405") + orderToken[:16]
	idHash := identitycrypto.IDHash(idNumber, s.cfg.HashPepper)

	startResp, err := s.startProviderKYC(r.Context(), provider, kycStartInput{
		State:          state,
		OuterOrderNo:   outerOrderNo,
		Name:           req.Name,
		IDNumber:       idNumber,
		MetaInfo:       req.MetaInfo,
		CertifyURLType: req.CertifyURLType,
		UserID:         userID,
	})
	if err != nil {
		s.recordFailure()
		s.logger.Warn("kyc initialize failed", "provider", provider, "user_id", userID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to initialize verification")
		return
	}
	if s.pii != nil {
		if err := s.pii.Append(piistore.Entry{
			UserID:       userID,
			Username:     stringValue(sess.Values[session.UsernameKey]),
			State:        state,
			Provider:     provider,
			CertifyID:    startResp.CertifyID,
			OuterOrderNo: outerOrderNo,
			IDHash:       idHash,
			Name:         req.Name,
			IDNumber:     idNumber,
		}); err != nil {
			s.recordFailure()
			s.logger.Warn("failed to store encrypted pii", "user_id", userID, "certify_id", startResp.CertifyID, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to store verification identity")
			return
		}
	}
	pending := pendingKYC{
		State:      state,
		Provider:   provider,
		CertifyID:  startResp.CertifyID,
		UserID:     userID,
		NameMasked: identitycrypto.MaskChineseName(req.Name),
		IDHash:     idHash,
		IDLast4:    identitycrypto.Last4(idNumber),
		ExpiresAt:  time.Now().UTC().Add(s.pendingTTLForProvider(provider)),
	}

	if err := s.sessions.Save(r, w, map[interface{}]interface{}{
		session.KYCStateKey:       state,
		session.CertifyIDKey:      startResp.CertifyID,
		session.KYCProviderKey:    provider,
		session.PendingExpiresKey: pending.ExpiresAt.Format(time.RFC3339),
		session.PendingNameKey:    pending.NameMasked,
		session.PendingIDHashKey:  pending.IDHash,
		session.PendingLast4Key:   pending.IDLast4,
	}); err != nil {
		s.recordFailure()
		writeError(w, http.StatusInternalServerError, "failed to save verification session")
		return
	}
	s.storePendingKYC(pending)

	writeJSON(w, http.StatusOK, map[string]string{
		"provider":       provider,
		"redirect_url":   startResp.CertifyURL,
		"certify_url":    startResp.CertifyURL,
		"alipay_app_url": startResp.AppLaunchURL,
		"certify_id":     startResp.CertifyID,
		"state":          state,
		"expires_at":     pending.ExpiresAt.Format(time.RFC3339),
		"qr_notice_html": s.cfg.QRNoticeHTML,
	})
}

func (s *Server) confirmKYC(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.currentUserID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"login_url": s.cfg.PublicURL + "/auth/login"})
		return
	}
	var req struct {
		State string `json:"state"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
	}

	sess, err := s.sessions.Get(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session")
		return
	}
	expectedState, _ := sess.Values[session.KYCStateKey].(string)
	if expectedState == "" || (req.State != "" && req.State != expectedState) {
		writeError(w, http.StatusBadRequest, "invalid verification state")
		return
	}
	certifyID, _ := sess.Values[session.CertifyIDKey].(string)
	if certifyID == "" {
		writeError(w, http.StatusBadRequest, "no pending verification")
		return
	}
	pending, ok := s.pendingKYC(expectedState)
	if !ok {
		if terminal, ok := s.terminalKYC(expectedState); ok {
			if err := s.clearPendingKYC(r, w); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to clear verification session")
				return
			}
			if terminal.Expired {
				writeError(w, http.StatusGone, "verification has expired")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"verified": true,
				"kyc":      terminal.Attribute,
			})
			return
		}
		if restored, ok := s.pendingKYCFromSession(sess.Values, expectedState, certifyID, userID); ok {
			pending = restored
			s.storePendingKYC(pending)
		} else {
			if err := s.clearPendingKYC(r, w); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to clear verification session")
				return
			}
			writeError(w, http.StatusGone, "verification has expired")
			return
		}
	}
	if pending.UserID != userID || pending.CertifyID != certifyID {
		writeError(w, http.StatusBadRequest, "invalid verification state")
		return
	}

	result, err := s.settlePendingKYC(r.Context(), pending)
	if err != nil {
		s.logger.Warn("failed to settle verification", "user_id", userID, "certify_id", certifyID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to confirm alipay verification")
		return
	}
	if result.Expired {
		if err := s.clearPendingKYC(r, w); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to clear verification session")
			return
		}
		writeError(w, http.StatusGone, "verification has expired")
		return
	}
	if !result.Passed {
		writeError(w, http.StatusConflict, providerPendingMessage(pending.Provider))
		return
	}
	if err := s.clearPendingKYC(r, w); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to clear verification session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verified": true,
		"kyc":      result.Attribute,
	})
}

func (s *Server) alipayNotify(w http.ResponseWriter, r *http.Request) {
	// The browser return flow performs the authoritative query and Authentik update.
	// This endpoint exists so operators can configure a notify URL without causing retries.
	writePlain(w, http.StatusOK, "success")
}

func (s *Server) alipayReturn(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if _, ok := s.currentUserID(r); ok && state != "" {
		http.Redirect(w, r, s.cfg.PublicURL+"/?state="+url.QueryEscape(state), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>支付宝认证已返回</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      box-sizing: border-box;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f4f6f8;
      color: #17202a;
    }
    main {
      width: min(100%, 420px);
      padding: 24px;
      border: 1px solid #d7dde4;
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 18px 55px rgba(23, 32, 42, 0.12);
    }
    h1 {
      margin: 0 0 12px;
      font-size: 22px;
      line-height: 1.3;
    }
    p {
      margin: 0;
      color: #344055;
      line-height: 1.7;
    }
  </style>
</head>
<body>
  <main>
    <h1>已返回认证结果</h1>
    <p>请回到刚才显示二维码的电脑页面，点击“我已完成，检查结果”。这个手机页面可以直接关闭。</p>
  </main>
</body>
</html>`)
}

func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	clean := path.Clean("/" + r.URL.Path)
	if clean == "/" {
		serveStaticFile(w, r, s.staticFS, "index.html")
		return
	}
	name := strings.TrimPrefix(clean, "/")
	if fileExists(s.staticFS, name) {
		serveStaticFile(w, r, s.staticFS, name)
		return
	}
	serveStaticFile(w, r, s.staticFS, "index.html")
}

func (s *Server) currentUserID(r *http.Request) (string, bool) {
	sess, err := s.sessions.Get(r)
	if err != nil {
		return "", false
	}
	userID, _ := sess.Values[session.UserIDKey].(string)
	return userID, userID != ""
}

func (s *Server) startProviderKYC(ctx context.Context, provider string, input kycStartInput) (kycStartResult, error) {
	switch provider {
	case ProviderAlipay:
		if s.alipay == nil {
			return kycStartResult{}, errors.New("alipay provider is not configured")
		}
		returnURL := addQuery(s.cfg.Alipay.ReturnURL, "state", input.State)
		initResp, err := s.alipay.Initialize(ctx, input.OuterOrderNo, input.Name, input.IDNumber, returnURL)
		if err != nil {
			return kycStartResult{}, err
		}
		certifyURL, err := s.alipay.CertifyURL(initResp.CertifyID)
		if err != nil {
			return kycStartResult{}, err
		}
		return kycStartResult{
			Provider:     ProviderAlipay,
			CertifyID:    initResp.CertifyID,
			CertifyURL:   certifyURL,
			AppLaunchURL: alipay.CertifyAppURL(certifyURL),
		}, nil
	case ProviderAliyun:
		if s.aliyun == nil {
			return kycStartResult{}, errors.New("aliyun provider is not configured")
		}
		certifyURLType := strings.ToUpper(strings.TrimSpace(input.CertifyURLType))
		initResp, err := s.aliyun.Initialize(ctx, aliyunkyc.InitializeRequest{
			OuterOrderNo:   input.OuterOrderNo,
			CertName:       input.Name,
			CertNo:         input.IDNumber,
			ReturnURL:      addQuery(s.cfg.Aliyun.ReturnURL, "state", input.State),
			MetaInfo:       input.MetaInfo,
			CertifyURLType: certifyURLType,
			UserID:         input.UserID,
		})
		if err != nil {
			return kycStartResult{}, err
		}
		return kycStartResult{
			Provider:   ProviderAliyun,
			CertifyID:  initResp.CertifyID,
			CertifyURL: initResp.CertifyURL,
		}, nil
	default:
		return kycStartResult{}, errors.New("unsupported verification provider")
	}
}

func (s *Server) queryKYC(ctx context.Context, provider, certifyID string) (bool, error) {
	switch normalizeProvider(provider) {
	case ProviderAlipay:
		if s.alipay == nil {
			return false, errors.New("alipay provider is not configured")
		}
		queryResp, err := s.alipay.Query(ctx, certifyID)
		if err != nil {
			return false, err
		}
		return strings.ToUpper(queryResp.Passed) == "T", nil
	case ProviderAliyun:
		if s.aliyun == nil {
			return false, errors.New("aliyun provider is not configured")
		}
		queryResp, err := s.aliyun.Query(ctx, certifyID)
		if err != nil {
			return false, err
		}
		return strings.ToUpper(queryResp.Passed) == "T", nil
	default:
		return false, errors.New("unsupported verification provider")
	}
}

func (s *Server) pendingTTLForProvider(provider string) time.Duration {
	switch normalizeProvider(provider) {
	case ProviderAliyun:
		return AliyunPendingTTL
	default:
		if s.cfg.KYCTimeout > 0 {
			return s.cfg.KYCTimeout
		}
		return AlipayPendingTTL
	}
}

func (s *Server) enabledProviders() []string {
	providers := []string{ProviderAlipay}
	if s.cfg.Aliyun.Enabled && s.aliyun != nil {
		providers = append(providers, ProviderAliyun)
	}
	return providers
}

func (s *Server) providerEnabled(provider string) bool {
	for _, enabled := range s.enabledProviders() {
		if enabled == provider {
			return true
		}
	}
	return false
}

func (s *Server) clearExistingPendingFromSession(values map[interface{}]interface{}) {
	state := stringValue(values[session.KYCStateKey])
	if state == "" {
		return
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	delete(s.pending, state)
	delete(s.terminal, state)
}

func (s *Server) adminAuthenticated(r *http.Request) bool {
	if !s.cfg.Admin.Enabled {
		return false
	}
	sess, err := s.sessions.Get(r)
	if err != nil {
		return false
	}
	value, _ := sess.Values[session.AdminKey].(string)
	return value == "true"
}

func (s *Server) adminCSRFToken(r *http.Request) (string, bool) {
	if !s.adminAuthenticated(r) {
		return "", false
	}
	sess, err := s.sessions.Get(r)
	if err != nil {
		return "", false
	}
	token, _ := sess.Values[session.AdminCSRFKey].(string)
	return token, token != ""
}

func (s *Server) validAdminCSRF(r *http.Request) bool {
	expected, ok := s.adminCSRFToken(r)
	if !ok {
		return false
	}
	actual := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if actual == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func (s *Server) compareAdminPassword(password string) bool {
	if s.cfg.Admin.Password == "" {
		return false
	}
	got := sha256.Sum256([]byte(password))
	want := sha256.Sum256([]byte(s.cfg.Admin.Password))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func (s *Server) authorizeStatsAPI(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || s.cfg.StatsAPIToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.StatsAPIToken)) == 1
}

func (s *Server) recordVerifiedIdentity(ctx context.Context, identity verifiedIdentity) (authentik.KYCAttribute, error) {
	identity.UserID = strings.TrimSpace(identity.UserID)
	identity.Username = strings.TrimSpace(identity.Username)
	identity.Name = strings.TrimSpace(identity.Name)
	identity.IDNumber = identitycrypto.NormalizeIDNumber(identity.IDNumber)
	identity.Channel = strings.TrimSpace(identity.Channel)
	if identity.UserID == "" || identity.Name == "" || identity.IDNumber == "" || identity.Channel == "" {
		return authentik.KYCAttribute{}, errors.New("verified identity is missing required fields")
	}
	idHash := identitycrypto.IDHash(identity.IDNumber, s.cfg.HashPepper)
	if s.pii != nil {
		if err := s.pii.Append(piistore.Entry{
			UserID:       identity.UserID,
			Username:     identity.Username,
			State:        firstNonEmpty(identity.State, identity.Channel),
			Provider:     identity.Channel,
			CertifyID:    firstNonEmpty(identity.CertifyID, identity.Channel),
			OuterOrderNo: firstNonEmpty(identity.OuterOrderNo, identity.Channel),
			IDHash:       idHash,
			Name:         identity.Name,
			IDNumber:     identity.IDNumber,
		}); err != nil {
			return authentik.KYCAttribute{}, err
		}
	}
	attr := authentik.KYCAttribute{
		Verified:   identity.Verified,
		Channel:    identity.Channel,
		IDHash:     idHash,
		IDLast4:    identitycrypto.Last4(identity.IDNumber),
		NameMasked: identitycrypto.MaskChineseName(identity.Name),
	}
	if identity.Verified {
		attr.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return s.markKYCAttribute(ctx, identity.UserID, attr)
}

func (s *Server) markKYCAttribute(ctx context.Context, userID string, attr authentik.KYCAttribute) (authentik.KYCAttribute, error) {
	if attr.IDHash == "" || attr.IDLast4 == "" || attr.NameMasked == "" || attr.Channel == "" {
		return authentik.KYCAttribute{}, errors.New("verification data is missing")
	}
	if attr.Verified && attr.VerifiedAt == "" {
		attr.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := s.authentik.MarkVerified(ctx, userID, attr); err != nil {
		return authentik.KYCAttribute{}, err
	}
	return attr, nil
}

func (s *Server) recordTotal() {
	if s.stats == nil {
		return
	}
	if err := s.stats.IncrementTotal(); err != nil {
		s.logger.Warn("failed to increment total stats", "error", err)
	}
}

func (s *Server) recordSuccess() {
	if s.stats == nil {
		return
	}
	if err := s.stats.IncrementSuccess(); err != nil {
		s.logger.Warn("failed to increment success stats", "error", err)
	}
}

func (s *Server) recordFailure() {
	if s.stats == nil {
		return
	}
	if err := s.stats.IncrementFailure(); err != nil {
		s.logger.Warn("failed to increment failure stats", "error", err)
	}
}

func (s *Server) storePendingKYC(pending pendingKYC) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.pending[pending.State] = pending
	delete(s.terminal, pending.State)
}

func (s *Server) pendingKYC(state string) (pendingKYC, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	pending, ok := s.pending[state]
	return pending, ok
}

func (s *Server) pendingKYCFromSession(values map[interface{}]interface{}, state, certifyID, userID string) (pendingKYC, bool) {
	pending := pendingKYC{
		State:      state,
		CertifyID:  certifyID,
		Provider:   normalizeProvider(stringValue(values[session.KYCProviderKey])),
		UserID:     userID,
		NameMasked: stringValue(values[session.PendingNameKey]),
		IDHash:     stringValue(values[session.PendingIDHashKey]),
		IDLast4:    stringValue(values[session.PendingLast4Key]),
		ExpiresAt:  time.Now().UTC().Add(s.cfg.KYCTimeout),
	}
	if rawExpiresAt := stringValue(values[session.PendingExpiresKey]); rawExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, rawExpiresAt)
		if err != nil {
			return pendingKYC{}, false
		}
		pending.ExpiresAt = expiresAt.UTC()
		if time.Now().UTC().After(pending.ExpiresAt) {
			return pendingKYC{}, false
		}
	}
	if pending.State == "" || pending.CertifyID == "" || pending.UserID == "" || pending.NameMasked == "" || pending.IDHash == "" || pending.IDLast4 == "" {
		return pendingKYC{}, false
	}
	return pending, true
}

func (s *Server) terminalKYC(state string) (terminalKYC, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	terminal, ok := s.terminal[state]
	if !ok {
		return terminalKYC{}, false
	}
	if time.Now().UTC().After(terminal.ExpiresAt) {
		delete(s.terminal, state)
		return terminalKYC{}, false
	}
	return terminal, true
}

func (s *Server) finishPendingKYC(state string, terminal terminalKYC) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	provider := ProviderAlipay
	if pending, ok := s.pending[state]; ok {
		provider = pending.Provider
	}
	delete(s.pending, state)
	terminal.ExpiresAt = time.Now().UTC().Add(s.pendingTTLForProvider(provider))
	s.terminal[state] = terminal
}

func (s *Server) pendingKYCSnapshot() []pendingKYC {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	now := time.Now().UTC()
	items := make([]pendingKYC, 0, len(s.pending))
	for _, pending := range s.pending {
		items = append(items, pending)
	}
	for state, terminal := range s.terminal {
		if now.After(terminal.ExpiresAt) {
			delete(s.terminal, state)
		}
	}
	return items
}

func (s *Server) settlePendingKYC(ctx context.Context, pending pendingKYC) (settleKYCResult, error) {
	s.settleMu.Lock()
	defer s.settleMu.Unlock()

	current, ok := s.pendingKYC(pending.State)
	if !ok {
		if terminal, ok := s.terminalKYC(pending.State); ok {
			if terminal.Expired {
				return settleKYCResult{Expired: true}, nil
			}
			return settleKYCResult{Passed: true, Attribute: terminal.Attribute}, nil
		}
		return settleKYCResult{Expired: true}, nil
	}
	pending = current

	if time.Now().UTC().After(pending.ExpiresAt) {
		s.finishPendingKYC(pending.State, terminalKYC{Expired: true})
		s.recordFailure()
		return settleKYCResult{Expired: true}, nil
	}
	passed, err := s.queryKYC(ctx, pending.Provider, pending.CertifyID)
	if err != nil {
		return settleKYCResult{}, err
	}
	if !passed {
		return settleKYCResult{Passed: false}, nil
	}
	attr, err := s.markKYCAttribute(ctx, pending.UserID, authentik.KYCAttribute{
		Verified:   true,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
		Channel:    pending.Provider,
		IDHash:     pending.IDHash,
		IDLast4:    pending.IDLast4,
		NameMasked: pending.NameMasked,
	})
	if err != nil {
		return settleKYCResult{}, err
	}
	s.finishPendingKYC(pending.State, terminalKYC{Attribute: attr})
	s.recordSuccess()
	return settleKYCResult{Passed: true, Attribute: attr}, nil
}

func (s *Server) checkPendingKYC(ctx context.Context) {
	for _, pending := range s.pendingKYCSnapshot() {
		result, err := s.settlePendingKYC(ctx, pending)
		if err != nil {
			s.logger.Warn("failed to poll pending verification", "provider", pending.Provider, "user_id", pending.UserID, "certify_id", pending.CertifyID, "error", err)
			continue
		}
		if result.Expired {
			s.logger.Info("pending verification expired", "provider", pending.Provider, "user_id", pending.UserID, "certify_id", pending.CertifyID)
			continue
		}
		if result.Passed {
			s.logger.Info("pending verification completed", "provider", pending.Provider, "user_id", pending.UserID, "certify_id", pending.CertifyID)
		}
	}
}

func (s *Server) clearPendingKYC(r *http.Request, w http.ResponseWriter) error {
	return s.sessions.Save(r, w, map[interface{}]interface{}{
		session.KYCStateKey:       nil,
		session.CertifyIDKey:      nil,
		session.KYCProviderKey:    nil,
		session.PendingExpiresKey: nil,
		session.PendingNameKey:    nil,
		session.PendingIDHashKey:  nil,
		session.PendingLast4Key:   nil,
	})
}

func readJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple json values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func writePlain(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message))
}

func serveStaticFile(w http.ResponseWriter, r *http.Request, fs http.FileSystem, name string) {
	file, err := fs.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}
	if ctype := mime.TypeByExtension(path.Ext(name)); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	http.ServeContent(w, r, name, stat.ModTime(), file)
}

func fileExists(fs http.FileSystem, name string) bool {
	file, err := fs.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()
	stat, err := file.Stat()
	return err == nil && !stat.IsDir()
}

func addQuery(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", ProviderAlipay:
		return ProviderAlipay
	case ProviderAliyun:
		return ProviderAliyun
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func providerPendingMessage(provider string) string {
	switch normalizeProvider(provider) {
	case ProviderAliyun:
		return "aliyun verification has not passed"
	default:
		return "alipay verification has not passed"
	}
}

func validAliyunCertifyURLType(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "WEB", "H5":
		return true
	default:
		return false
	}
}

func stringValue(value interface{}) string {
	typed, _ := value.(string)
	return typed
}

func boolValue(value interface{}) bool {
	typed, _ := value.(bool)
	return typed
}

func kycAttributeVerified(value interface{}) bool {
	switch typed := value.(type) {
	case authentik.KYCAttribute:
		return typed.Verified
	case map[string]interface{}:
		return boolValue(typed["verified"])
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if !strings.HasPrefix(r.URL.Path, "/assets/") {
			logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration_ms", time.Since(start).Milliseconds())
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
