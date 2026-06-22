package server

import (
	"context"
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
	"time"

	"github.com/example/authentik-alipay-kyc/internal/alipay"
	"github.com/example/authentik-alipay-kyc/internal/authentik"
	"github.com/example/authentik-alipay-kyc/internal/config"
	identitycrypto "github.com/example/authentik-alipay-kyc/internal/crypto"
	"github.com/example/authentik-alipay-kyc/internal/oidc"
	"github.com/example/authentik-alipay-kyc/internal/session"
	"github.com/example/authentik-alipay-kyc/internal/stats"
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

type StatsStore interface {
	Snapshot() (stats.Counters, error)
	IncrementTotal() error
	IncrementSuccess() error
	IncrementFailure() error
}

type Dependencies struct {
	Config     config.Config
	Logger     *slog.Logger
	OIDC       OIDCClient
	Authentik  AuthentikClient
	Alipay     AlipayClient
	Stats      StatsStore
	StaticFS   http.FileSystem
	HTTPClient *http.Client
}

type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	oidc      OIDCClient
	authentik AuthentikClient
	alipay    AlipayClient
	stats     StatsStore
	staticFS  http.FileSystem
	sessions  *session.Store
}

type errorResponse struct {
	Error string `json:"error"`
}

func New(deps Dependencies) *Server {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:       deps.Config,
		logger:    logger,
		oidc:      deps.OIDC,
		authentik: deps.Authentik,
		alipay:    deps.Alipay,
		stats:     deps.Stats,
		staticFS:  deps.StaticFS,
		sessions:  session.New(deps.Config.Session),
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
		"authenticated": true,
		"user":          user,
		"verified":      false,
	}

	akUser, err := s.authentik.GetUser(r.Context(), userID)
	if err != nil {
		s.logger.Warn("failed to load authentik user", "user_id", userID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to load authentik user")
		return
	}
	if attr, ok := akUser.Attributes[s.cfg.Authentik.AttributeKey]; ok {
		response["kyc"] = attr
		response["verified"] = true
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

func (s *Server) startKYC(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.currentUserID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"login_url": s.cfg.PublicURL + "/auth/login"})
		return
	}
	var req struct {
		Name     string `json:"name"`
		IDNumber string `json:"id_number"`
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
	returnURL := addQuery(s.cfg.Alipay.ReturnURL, "state", state)
	outerOrderNo := "ak" + time.Now().UTC().Format("20060102150405") + orderToken[:16]

	initResp, err := s.alipay.Initialize(r.Context(), outerOrderNo, req.Name, idNumber, returnURL)
	if err != nil {
		s.recordFailure()
		s.logger.Warn("alipay initialize failed", "user_id", userID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to initialize alipay verification")
		return
	}
	certifyURL, err := s.alipay.CertifyURL(initResp.CertifyID)
	if err != nil {
		s.recordFailure()
		writeError(w, http.StatusBadGateway, "failed to create alipay certify url")
		return
	}

	if err := s.sessions.Save(r, w, map[interface{}]interface{}{
		session.KYCStateKey:      state,
		session.CertifyIDKey:     initResp.CertifyID,
		session.PendingNameKey:   identitycrypto.MaskChineseName(req.Name),
		session.PendingIDHashKey: identitycrypto.IDHash(idNumber, s.cfg.HashPepper),
		session.PendingLast4Key:  identitycrypto.Last4(idNumber),
	}); err != nil {
		s.recordFailure()
		writeError(w, http.StatusInternalServerError, "failed to save verification session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_url": certifyURL,
		"certify_url":  certifyURL,
		"certify_id":   initResp.CertifyID,
		"state":        state,
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

	queryResp, err := s.alipay.Query(r.Context(), certifyID)
	if err != nil {
		s.settleFailure(r, w)
		s.logger.Warn("alipay query failed", "user_id", userID, "certify_id", certifyID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to confirm alipay verification")
		return
	}
	if strings.ToUpper(queryResp.Passed) != "T" {
		writeError(w, http.StatusConflict, "alipay verification has not passed")
		return
	}

	attr := authentik.KYCAttribute{
		Verified:   true,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
		Channel:    "alipay",
		IDHash:     stringValue(sess.Values[session.PendingIDHashKey]),
		IDLast4:    stringValue(sess.Values[session.PendingLast4Key]),
		NameMasked: stringValue(sess.Values[session.PendingNameKey]),
	}
	if attr.IDHash == "" || attr.IDLast4 == "" || attr.NameMasked == "" {
		s.settleFailure(r, w)
		writeError(w, http.StatusBadRequest, "pending verification data is missing")
		return
	}
	if err := s.authentik.MarkVerified(r.Context(), userID, attr); err != nil {
		s.settleFailure(r, w)
		s.logger.Warn("authentik update failed", "user_id", userID, "error", err)
		writeError(w, http.StatusBadGateway, "failed to write verification to authentik")
		return
	}
	if err := s.clearPendingKYC(r, w); err != nil {
		s.settleFailure(r, w)
		writeError(w, http.StatusInternalServerError, "failed to clear verification session")
		return
	}
	s.recordSuccess()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verified": true,
		"kyc":      attr,
	})
}

func (s *Server) alipayNotify(w http.ResponseWriter, r *http.Request) {
	// The browser return flow performs the authoritative query and Authentik update.
	// This endpoint exists so operators can configure a notify URL without causing retries.
	writePlain(w, http.StatusOK, "success")
}

func (s *Server) alipayReturn(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) authorizeStatsAPI(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || s.cfg.StatsAPIToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.StatsAPIToken)) == 1
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

func (s *Server) settleFailure(r *http.Request, w http.ResponseWriter) {
	s.recordFailure()
	if err := s.clearPendingKYC(r, w); err != nil {
		s.logger.Warn("failed to clear failed verification session", "error", err)
	}
}

func (s *Server) clearPendingKYC(r *http.Request, w http.ResponseWriter) error {
	return s.sessions.Save(r, w, map[interface{}]interface{}{
		session.KYCStateKey:      nil,
		session.CertifyIDKey:     nil,
		session.PendingNameKey:   nil,
		session.PendingIDHashKey: nil,
		session.PendingLast4Key:  nil,
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

func stringValue(value interface{}) string {
	typed, _ := value.(string)
	return typed
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
