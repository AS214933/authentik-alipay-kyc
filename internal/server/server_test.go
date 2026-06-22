package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/alipay"
	"github.com/example/authentik-alipay-kyc/internal/authentik"
	"github.com/example/authentik-alipay-kyc/internal/config"
	"github.com/example/authentik-alipay-kyc/internal/oidc"
	"github.com/example/authentik-alipay-kyc/internal/piistore"
	"github.com/example/authentik-alipay-kyc/internal/stats"
)

type fakeOIDC struct{}

func (fakeOIDC) AuthCodeURL(state, nonce string) string {
	return "/fake-login?state=" + state + "&nonce=" + nonce
}

func (fakeOIDC) Exchange(context.Context, string, string) (oidc.Claims, error) {
	return oidc.Claims{}, nil
}

type fakeAuthentik struct {
	user authentik.User
	attr authentik.KYCAttribute
}

func (f *fakeAuthentik) GetUser(context.Context, string) (authentik.User, error) {
	return f.user, nil
}

func (f *fakeAuthentik) MarkVerified(_ context.Context, _ string, attr authentik.KYCAttribute) error {
	f.attr = attr
	if f.user.Attributes == nil {
		f.user.Attributes = map[string]interface{}{}
	}
	f.user.Attributes["alipay_kyc"] = attr
	return nil
}

type fakeAlipay struct {
	certifyID string
	passed    string
	queryErr  error
}

func (f fakeAlipay) Initialize(context.Context, string, string, string, string) (alipay.InitializeResponse, error) {
	return alipay.InitializeResponse{CertifyID: f.certifyID}, nil
}

func (f fakeAlipay) CertifyURL(certifyID string) (string, error) {
	return "https://alipay.example/gateway.do?method=alipay.user.certify.open.certify&certify_id=" + certifyID, nil
}

func (f fakeAlipay) Query(context.Context, string) (alipay.QueryResponse, error) {
	if f.queryErr != nil {
		return alipay.QueryResponse{}, f.queryErr
	}
	return alipay.QueryResponse{Passed: f.passed}, nil
}

type sequenceAlipay struct {
	fakeAlipay
	passes []string
	errs   []error
	calls  int
}

func (f *sequenceAlipay) Query(context.Context, string) (alipay.QueryResponse, error) {
	if f.calls < len(f.errs) && f.errs[f.calls] != nil {
		err := f.errs[f.calls]
		f.calls++
		return alipay.QueryResponse{}, err
	}
	passed := f.fakeAlipay.passed
	if f.calls < len(f.passes) {
		passed = f.passes[f.calls]
	}
	f.calls++
	return alipay.QueryResponse{Passed: passed}, nil
}

type fakePIIStore struct {
	entries []piistore.Entry
	err     error
}

func (f *fakePIIStore) Append(entry piistore.Entry) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, entry)
	return nil
}

func TestKYCFlowWritesAuthentikAttribute(t *testing.T) {
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	piiStore := &fakePIIStore{}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     statsStore,
		PII:       piiStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()

	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", body)
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State        string `json:"state"`
		CertifyURL   string `json:"certify_url"`
		RedirectURL  string `json:"redirect_url"`
		AlipayAppURL string `json:"alipay_app_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	if startResp.State == "" {
		t.Fatal("expected state")
	}
	if startResp.CertifyURL == "" || startResp.CertifyURL != startResp.RedirectURL {
		t.Fatalf("unexpected certify url response: %+v", startResp)
	}
	if !strings.HasPrefix(startResp.AlipayAppURL, "alipays://platformapi/startapp?appId=20000067&url=") {
		t.Fatalf("unexpected alipay app url: %+v", startResp)
	}
	if !strings.Contains(startResp.AlipayAppURL, "alipay.user.certify.open.certify") {
		t.Fatalf("alipay app url did not contain encoded certify method: %+v", startResp)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !ak.attr.Verified || ak.attr.Channel != "alipay" || ak.attr.IDLast4 != "002X" || ak.attr.NameMasked != "*三" || ak.attr.IDHash == "" {
		t.Fatalf("unexpected authentik attr: %+v", ak.attr)
	}
	if len(piiStore.entries) != 1 {
		t.Fatalf("pii entries = %d, want 1", len(piiStore.entries))
	}
	if piiStore.entries[0].Name != "张三" || piiStore.entries[0].IDNumber != "11010519491231002X" {
		t.Fatalf("unexpected pii entry: %+v", piiStore.entries[0])
	}
	if piiStore.entries[0].CertifyID != "CERT123" || piiStore.entries[0].State != startResp.State {
		t.Fatalf("unexpected pii entry identity: %+v", piiStore.entries[0])
	}
	if piiStore.entries[0].IDHash != ak.attr.IDHash {
		t.Fatalf("pii id hash = %q, authentik id hash = %q", piiStore.entries[0].IDHash, ak.attr.IDHash)
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 || counters.Success != 1 || counters.Failure != 0 {
		t.Fatalf("unexpected counters: %+v", counters)
	}
}

func TestKYCConfirmCanBeRetriedAfterNotPassed(t *testing.T) {
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	alipayClient := &sequenceAlipay{
		fakeAlipay: fakeAlipay{certifyID: "CERT123"},
		passes:     []string{"F", "T"},
	}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    alipayClient,
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("first confirm status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !ak.attr.Verified {
		t.Fatalf("expected authentik attr to be verified: %+v", ak.attr)
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 || counters.Success != 1 || counters.Failure != 0 {
		t.Fatalf("unexpected counters after retry: %+v", counters)
	}
}

func TestKYCStartFailsWhenPIIStoreFails(t *testing.T) {
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     statsStore,
		PII:       &fakePIIStore{err: errors.New("disk full")},
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 || counters.Success != 0 || counters.Failure != 1 {
		t.Fatalf("unexpected counters after pii failure: %+v", counters)
	}
}

func TestKYCConfirmCanBeRetriedAfterQueryError(t *testing.T) {
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	alipayClient := &sequenceAlipay{
		fakeAlipay: fakeAlipay{certifyID: "CERT123"},
		errs:       []error{errors.New("temporary network error")},
		passes:     []string{"", "T"},
	}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    alipayClient,
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("first confirm status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !ak.attr.Verified {
		t.Fatalf("expected authentik attr to be verified: %+v", ak.attr)
	}
}

func TestKYCConfirmRestoresPendingFromSessionAfterRestart(t *testing.T) {
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	srv.pendingMu.Lock()
	delete(srv.pending, startResp.State)
	srv.pendingMu.Unlock()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !ak.attr.Verified {
		t.Fatalf("expected authentik attr to be verified: %+v", ak.attr)
	}
}

func TestPendingKYCWorkerCanCompleteVerification(t *testing.T) {
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	srv.checkPendingKYC(context.Background())
	if !ak.attr.Verified {
		t.Fatalf("expected worker to mark user verified: %+v", ak.attr)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm after worker status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPendingKYCExpiresAfterTimeout(t *testing.T) {
	cfg := testConfig()
	cfg.KYCTimeout = time.Nanosecond
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "F"},
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	time.Sleep(time.Millisecond)
	srv.checkPendingKYC(context.Background())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("expired confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 || counters.Success != 0 || counters.Failure != 1 {
		t.Fatalf("unexpected counters after timeout: %+v", counters)
	}
}

func TestAlipayReturnShowsDesktopInstruction(t *testing.T) {
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html>spa</html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify/callback?state=state-123", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("callback content type = %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "回到刚才显示二维码的电脑页面") {
		t.Fatalf("callback body did not contain desktop instruction: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "spa") {
		t.Fatalf("callback unexpectedly served SPA body: %s", rec.Body.String())
	}
}

func TestStatsAPIRequiresBearerToken(t *testing.T) {
	statsStore := testStats(t)
	if err := statsStore.IncrementTotal(); err != nil {
		t.Fatal(err)
	}
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stats status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer stats-token")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated stats status = %d body=%s", rec.Code, rec.Body.String())
	}
	var counters stats.Counters
	if err := json.Unmarshal(rec.Body.Bytes(), &counters); err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 {
		t.Fatalf("stats total = %d, want 1", counters.Total)
	}
}

func TestAdminImportRequiresLogin(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Password = "admin-secret"
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     testStats(t),
		PII:       &fakePIIStore{},
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"张三","id_number":"11010519491231002X","verified":true}`))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin import status = %d, want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAdminImportWritesPIIAndAuthentikWithoutStats(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Password = "admin-secret"
	ak := &fakeAuthentik{user: authentik.User{
		ID:         5,
		Username:   "bob",
		Attributes: map[string]interface{}{},
	}}
	piiStore := &fakePIIStore{}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     statsStore,
		PII:       piiStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()

	cookies := adminCookies(t, handler, "admin-secret")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"李四","id_number":"440524188001010014","verified":true}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin import status = %d body=%s", rec.Code, rec.Body.String())
	}
	var importResp struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &importResp); err != nil {
		t.Fatal(err)
	}
	if importResp.UserID != "5" {
		t.Fatalf("admin import user_id = %q, want 5", importResp.UserID)
	}
	if !ak.attr.Verified || ak.attr.Channel != "admin" || ak.attr.NameMasked != "*四" || ak.attr.IDLast4 != "0014" || ak.attr.IDHash == "" || ak.attr.VerifiedAt == "" {
		t.Fatalf("unexpected admin authentik attr: %+v", ak.attr)
	}
	if len(piiStore.entries) != 1 {
		t.Fatalf("pii entries = %d, want 1", len(piiStore.entries))
	}
	if piiStore.entries[0].UserID != "5" || piiStore.entries[0].Name != "李四" || piiStore.entries[0].IDNumber != "440524188001010014" {
		t.Fatalf("unexpected pii entry: %+v", piiStore.entries[0])
	}
	if piiStore.entries[0].IDHash != ak.attr.IDHash {
		t.Fatalf("pii id hash = %q, authentik id hash = %q", piiStore.entries[0].IDHash, ak.attr.IDHash)
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 0 || counters.Success != 0 || counters.Failure != 0 {
		t.Fatalf("manual import changed stats: %+v", counters)
	}
}

func TestAdminImportCanWriteUnverifiedAttribute(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Password = "admin-secret"
	ak := &fakeAuthentik{user: authentik.User{
		ID:         5,
		Username:   "bob",
		Attributes: map[string]interface{}{},
	}}
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     testStats(t),
		PII:       &fakePIIStore{},
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()

	cookies := adminCookies(t, handler, "admin-secret")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"李四","id_number":"440524188001010014","verified":false}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin import status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ak.attr.Verified || ak.attr.VerifiedAt != "" || ak.attr.Channel != "admin" {
		t.Fatalf("unexpected unverified admin attr: %+v", ak.attr)
	}
}

func userCookie(t *testing.T, srv *Server) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := srv.sessions.Save(req, rec, map[interface{}]interface{}{
		"user_id":      "1",
		"username":     "alice",
		"display_name": "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

func adminCookies(t *testing.T, handler http.Handler, password string) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login status = %d body=%s", rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()
}

func mergeCookies(existing, updates []*http.Cookie) []*http.Cookie {
	byName := map[string]*http.Cookie{}
	for _, cookie := range existing {
		byName[cookie.Name] = cookie
	}
	for _, cookie := range updates {
		byName[cookie.Name] = cookie
	}
	out := make([]*http.Cookie, 0, len(byName))
	for _, cookie := range byName {
		out = append(out, cookie)
	}
	return out
}

func testConfig() config.Config {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 64))
	sessionKeys, _ := base64.StdEncoding.DecodeString(key)
	return config.Config{
		HTTPAddr:        ":8080",
		PublicURL:       "https://kyc.example.com",
		HashPepper:      "pepper",
		StatsAPIToken:   "stats-token",
		KYCTimeout:      30 * time.Minute,
		KYCPollInterval: time.Minute,
		OIDC: config.OIDCConfig{
			Issuer:       "https://authentik.example.com/application/o/alipay-kyc/",
			ClientID:     "client",
			ClientSecret: "secret",
			RedirectURL:  "https://kyc.example.com/auth/callback",
			Scopes:       []string{"openid"},
		},
		Authentik: config.AuthentikConfig{
			BaseURL:       "https://authentik.example.com",
			Token:         "token",
			UserIDClaim:   "ak_user_id",
			AttributeKey:  "alipay_kyc",
			MergeExisting: true,
		},
		Alipay: config.AlipayConfig{
			BizCode:   "FACE",
			CertType:  "IDENTITY_CARD",
			ReturnURL: "https://kyc.example.com/verify/callback",
		},
		Session: config.SessionConfig{
			Name:     "test",
			KeyPairs: [][]byte{sessionKeys},
			MaxAge:   3600,
		},
	}
}

func testStats(t *testing.T) *stats.Store {
	t.Helper()
	store, err := stats.NewStore(filepath.Join(t.TempDir(), "stats.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
