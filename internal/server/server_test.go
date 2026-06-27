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
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/alipay"
	aliyunkyc "github.com/example/authentik-alipay-kyc/internal/aliyun"
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
	user   authentik.User
	userID string
	attr   authentik.KYCAttribute
}

func (f *fakeAuthentik) GetUser(context.Context, string) (authentik.User, error) {
	return f.user, nil
}

func (f *fakeAuthentik) MarkVerified(_ context.Context, userID string, attr authentik.KYCAttribute) error {
	f.userID = userID
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

type fakeAliyun struct {
	certifyID      string
	certifyURL     string
	passed         string
	initMetaInfo   string
	initURLType    string
	initializeCall int
	queryCall      int
}

func (f *fakeAliyun) Initialize(_ context.Context, req aliyunkyc.InitializeRequest) (aliyunkyc.InitializeResponse, error) {
	f.initializeCall++
	f.initMetaInfo = req.MetaInfo
	f.initURLType = req.CertifyURLType
	if f.certifyID == "" {
		f.certifyID = "ALIYUN123"
	}
	if f.certifyURL == "" {
		f.certifyURL = "https://aliyun.example/certify"
	}
	return aliyunkyc.InitializeResponse{CertifyID: f.certifyID, CertifyURL: f.certifyURL}, nil
}

func (f *fakeAliyun) Query(context.Context, string) (aliyunkyc.QueryResponse, error) {
	f.queryCall++
	return aliyunkyc.QueryResponse{Passed: f.passed}, nil
}

type sequenceAliyun struct {
	fakeAliyun
	passes []string
	calls  int
}

func (f *sequenceAliyun) Query(context.Context, string) (aliyunkyc.QueryResponse, error) {
	passed := f.fakeAliyun.passed
	if f.calls < len(f.passes) {
		passed = f.passes[f.calls]
	}
	f.calls++
	f.queryCall++
	return aliyunkyc.QueryResponse{Passed: passed}, nil
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

func TestAliyunKYCRequiresMetaInfo(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    &fakeAliyun{passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"provider":"aliyun","name":"张三","id_number":"11010519491231002X","certify_url_type":"WEB"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAliyunKYCRequiresCertifyURLType(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    &fakeAliyun{passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"provider":"aliyun","name":"张三","id_number":"11010519491231002X","meta_info":"{}"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAliyunKYCFlowWritesAuthentikAttribute(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	piiStore := &fakePIIStore{}
	aliyunClient := &fakeAliyun{certifyID: "ALIYUN123", certifyURL: "https://aliyun.example/certify", passed: "T"}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    aliyunClient,
		Stats:     statsStore,
		PII:       piiStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"provider":"aliyun","name":"张三","id_number":"11010519491231002X","meta_info":"{\"deviceType\":\"web\"}","certify_url_type":"WEB"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		Provider   string `json:"provider"`
		State      string `json:"state"`
		CertifyID  string `json:"certify_id"`
		CertifyURL string `json:"certify_url"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	if startResp.Provider != ProviderAliyun || startResp.CertifyID != "ALIYUN123" || startResp.CertifyURL != "https://aliyun.example/certify" {
		t.Fatalf("unexpected aliyun start response: %+v", startResp)
	}
	expiresAt, err := time.Parse(time.RFC3339, startResp.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	ttl := time.Until(expiresAt)
	if ttl < 29*time.Minute || ttl > 31*time.Minute {
		t.Fatalf("aliyun pending ttl = %s, want about 30m", ttl)
	}
	if aliyunClient.initMetaInfo == "" || aliyunClient.initURLType != "WEB" {
		t.Fatalf("unexpected aliyun init fields: meta=%q type=%q", aliyunClient.initMetaInfo, aliyunClient.initURLType)
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
	if !ak.attr.Verified || ak.attr.Channel != ProviderAliyun || ak.attr.IDLast4 != "002X" || ak.attr.NameMasked != "*三" || ak.attr.IDHash == "" {
		t.Fatalf("unexpected authentik attr: %+v", ak.attr)
	}
	if len(piiStore.entries) != 1 || piiStore.entries[0].Provider != ProviderAliyun || piiStore.entries[0].CertifyID != "ALIYUN123" {
		t.Fatalf("unexpected pii entries: %+v", piiStore.entries)
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 || counters.Success != 1 || counters.Failure != 0 {
		t.Fatalf("unexpected counters: %+v", counters)
	}
}

func TestAliyunKYCConfirmCanBeRetriedAfterNotPassed(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	ak := &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}}
	aliyunClient := &sequenceAliyun{passes: []string{"F", "T"}}
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    aliyunClient,
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"provider":"aliyun","name":"张三","id_number":"11010519491231002X","meta_info":"{}","certify_url_type":"H5"}`))
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

	for i, want := range []int{http.StatusConflict, http.StatusOK} {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
		req.Header.Set("Content-Type", "application/json")
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("confirm %d status = %d body=%s", i+1, rec.Code, rec.Body.String())
		}
	}
	if !ak.attr.Verified || ak.attr.Channel != ProviderAliyun {
		t.Fatalf("expected aliyun verified attr: %+v", ak.attr)
	}
	counters, err := statsStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if counters.Total != 1 || counters.Success != 1 || counters.Failure != 0 {
		t.Fatalf("unexpected counters after retry: %+v", counters)
	}
}

func TestAliyunPendingKYCExpiresAfterThirtyMinutes(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	statsStore := testStats(t)
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    &fakeAliyun{passed: "F"},
		Stats:     statsStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	cookies := userCookie(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"provider":"aliyun","name":"张三","id_number":"11010519491231002X","meta_info":"{}","certify_url_type":"WEB"}`))
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

	pending, ok := srv.pendingKYC(startResp.State)
	if !ok {
		t.Fatal("pending aliyun verification was not stored")
	}
	pending.ExpiresAt = time.Now().UTC().Add(-time.Second)
	srv.storePendingKYC(pending)
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

func TestStartingNewKYCLeavesPreviousPendingAvailable(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	aliyunClient := &fakeAliyun{passed: "T"}
	alipayClient := &sequenceAlipay{
		fakeAlipay: fakeAlipay{certifyID: "CERT123"},
		passes:     []string{"T"},
	}
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    alipayClient,
		Aliyun:    aliyunClient,
		Stats:     testStats(t),
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
		t.Fatalf("alipay start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var first struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	cookies = mergeCookies(cookies, rec.Result().Cookies())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"provider":"aliyun","name":"张三","id_number":"11010519491231002X","meta_info":"{}","certify_url_type":"WEB"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("aliyun start status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := srv.pendingKYC(first.State); !ok {
		t.Fatalf("old alipay pending state %q was not retained", first.State)
	}
	srv.checkPendingKYC(context.Background())
	if alipayClient.calls != 1 {
		t.Fatalf("old alipay pending was polled %d times", alipayClient.calls)
	}
}

func TestMeReturnsQRNoticeHTML(t *testing.T) {
	cfg := testConfig()
	cfg.QRNoticeHTML = `<p>扫码后请完成支付宝人脸认证。</p>`
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		QRNoticeHTML string `json:"qr_notice_html"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.QRNoticeHTML != cfg.QRNoticeHTML {
		t.Fatalf("qr_notice_html = %q, want %q", body.QRNoticeHTML, cfg.QRNoticeHTML)
	}
}

func TestMeReturnsEnabledProviders(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    &fakeAliyun{passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Providers []string `json:"providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Join(body.Providers, ",") != "alipay,aliyun" {
		t.Fatalf("providers = %+v, want alipay,aliyun", body.Providers)
	}
}

func TestMeReturnsOnlyAliyunWhenAlipayDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.Alipay.Enabled = false
	cfg.Aliyun.Enabled = true
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Aliyun:    &fakeAliyun{passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Providers []string `json:"providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Join(body.Providers, ",") != "aliyun" {
		t.Fatalf("providers = %+v, want aliyun", body.Providers)
	}
}

func TestStartKYCDefaultsToAlipayWhenBothProvidersEnabled(t *testing.T) {
	cfg := testConfig()
	cfg.Aliyun.Enabled = true
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Aliyun:    &fakeAliyun{passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Provider != ProviderAlipay {
		t.Fatalf("provider = %q, want alipay", body.Provider)
	}
}

func TestStartKYCDefaultsToAliyunWhenOnlyAliyunEnabled(t *testing.T) {
	cfg := testConfig()
	cfg.Alipay.Enabled = false
	cfg.Aliyun.Enabled = true
	aliyunClient := &fakeAliyun{passed: "T"}
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Aliyun:    aliyunClient,
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X","meta_info":"{}","certify_url_type":"WEB"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Provider != ProviderAliyun || aliyunClient.initializeCall != 1 {
		t.Fatalf("provider = %q initializeCall=%d, want aliyun/1", body.Provider, aliyunClient.initializeCall)
	}
}

func TestStartKYCReturnsQRNoticeHTML(t *testing.T) {
	cfg := testConfig()
	cfg.QRNoticeHTML = `<strong>请使用本人支付宝扫码。</strong>`
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: &fakeAuthentik{user: authentik.User{Attributes: map[string]interface{}{}}},
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     testStats(t),
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"name":"张三","id_number":"11010519491231002X"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range userCookie(t, srv) {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		QRNoticeHTML string `json:"qr_notice_html"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.QRNoticeHTML != cfg.QRNoticeHTML {
		t.Fatalf("qr_notice_html = %q, want %q", body.QRNoticeHTML, cfg.QRNoticeHTML)
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
	if !ak.attr.Verified || ak.attr.Channel != ProviderAlipay {
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
	cfg.Admin.AllowedUsernames = []string{"admin"}
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

func TestAdminImportRequiresAllowedUsername(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	handler := srv.Handler()
	cookies := adminCookie(t, srv, "bob")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"张三","id_number":"11010519491231002X","verified":true}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin import with disallowed username status = %d, want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAdminImportRequiresCSRFToken(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	handler := srv.Handler()
	cookies := adminCookie(t, srv, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"\u5f20\u4e09","id_number":"11010519491231002X","verified":true}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin import without csrf status = %d, want %d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAdminStatusReturnsAllowedWhenUsernameMatches(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	handler := srv.Handler()
	cookies := adminCookie(t, srv, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/status", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Enabled       bool   `json:"enabled"`
		Authenticated bool   `json:"authenticated"`
		Allowed       bool   `json:"allowed"`
		LoginURL      string `json:"login_url"`
		CSRFToken     string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || !body.Authenticated || !body.Allowed || !strings.Contains(body.LoginURL, "/auth/login") || body.CSRFToken == "" {
		t.Fatalf("unexpected admin status body: %+v", body)
	}
}

func TestAdminStatusShowsAuthenticatedButNotAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	handler := srv.Handler()
	cookies := adminCookie(t, srv, "bob")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/status", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Authenticated bool   `json:"authenticated"`
		Allowed       bool   `json:"allowed"`
		CSRFToken     string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Authenticated || body.Allowed || body.CSRFToken != "" {
		t.Fatalf("unexpected admin status body: %+v", body)
	}
}

func TestAdminImportWritesPIIAndAuthentikWithoutStats(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	admin := adminSession(t, handler, srv, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"李四","id_number":"440524188001010014","verified":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", admin.csrfToken)
	for _, cookie := range admin.cookies {
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

func TestAdminImportCreatesKYCInviteWhenRequired(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	admin := adminSession(t, handler, srv, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"李四","id_number":"440524188001010014","requires_kyc":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", admin.csrfToken)
	for _, cookie := range admin.cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin import status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		RequiresKYC bool   `json:"requires_kyc"`
		InviteToken string `json:"invite_token"`
		InviteURL   string `json:"invite_url"`
		NameMasked  string `json:"name_masked"`
		IDLast4     string `json:"id_last4"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.RequiresKYC || body.InviteToken == "" || !strings.Contains(body.InviteURL, "invite=") {
		t.Fatalf("unexpected invite body: %+v", body)
	}
	if body.NameMasked != "*四" || body.IDLast4 != "0014" {
		t.Fatalf("unexpected invite identity summary: %+v", body)
	}
	if ak.attr.Channel != "" {
		t.Fatalf("admin invite should not write authentik attr: %+v", ak.attr)
	}
}

func TestAdminKYCInviteCanStartWithoutLoginAndWritesTargetUser(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
	ak := &fakeAuthentik{user: authentik.User{
		ID:         5,
		Username:   "bob",
		Attributes: map[string]interface{}{},
	}}
	piiStore := &fakePIIStore{}
	srv := New(Dependencies{
		Config:    cfg,
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
		Stats:     testStats(t),
		PII:       piiStore,
		StaticFS: http.FS(fstest.MapFS{
			"index.html": {Data: []byte("<html></html>"), ModTime: time.Now()},
		}),
	})
	handler := srv.Handler()
	admin := adminSession(t, handler, srv, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"李四","id_number":"440524188001010014","requires_kyc":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", admin.csrfToken)
	for _, cookie := range admin.cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin import status = %d body=%s", rec.Code, rec.Body.String())
	}
	var inviteResp struct {
		InviteToken string `json:"invite_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inviteResp); err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"invite_token":"`+inviteResp.InviteToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invite start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/confirm", strings.NewReader(`{"state":"`+startResp.State+`"}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invite confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ak.userID != "5" || !ak.attr.Verified || ak.attr.Channel != ProviderAlipay || ak.attr.IDLast4 != "0014" {
		t.Fatalf("unexpected invite authentik write: user=%q attr=%+v", ak.userID, ak.attr)
	}
	if len(piiStore.entries) != 1 || piiStore.entries[0].UserID != "5" || piiStore.entries[0].IDNumber != "440524188001010014" {
		t.Fatalf("unexpected invite pii entries: %+v", piiStore.entries)
	}
}

func TestAdminKYCInviteReturnRedirectsWithoutLogin(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.AllowedUsernames = []string{"admin"}
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
	handler := srv.Handler()
	admin := adminSession(t, handler, srv, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/import", strings.NewReader(`{"user_id":"5","name":"李四","id_number":"440524188001010014","requires_kyc":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", admin.csrfToken)
	for _, cookie := range admin.cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin import status = %d body=%s", rec.Code, rec.Body.String())
	}
	var inviteResp struct {
		InviteToken string `json:"invite_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inviteResp); err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/kyc/start", strings.NewReader(`{"invite_token":"`+inviteResp.InviteToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invite start status = %d body=%s", rec.Code, rec.Body.String())
	}
	var startResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/verify/callback?state="+url.QueryEscape(startResp.State), nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("return status = %d body=%s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != cfg.PublicURL+"/?state="+url.QueryEscape(startResp.State) {
		t.Fatalf("return location = %q", location)
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

func adminCookie(t *testing.T, srv *Server, username string) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := srv.sessions.Save(req, rec, map[interface{}]interface{}{
		"user_id":      "99",
		"username":     username,
		"display_name": username,
	}); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

type adminTestSession struct {
	cookies   []*http.Cookie
	csrfToken string
}

func adminSession(t *testing.T, handler http.Handler, srv *Server, username string) adminTestSession {
	t.Helper()
	cookies := adminCookie(t, srv, username)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/status", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CSRFToken == "" {
		t.Fatal("admin status did not return csrf token")
	}
	return adminTestSession{cookies: mergeCookies(cookies, rec.Result().Cookies()), csrfToken: body.CSRFToken}
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
		KYCTimeout:      AlipayPendingTTL,
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
			Enabled:   true,
			BizCode:   "FACE",
			CertType:  "IDENTITY_CARD",
			ReturnURL: "https://kyc.example.com/verify/callback",
		},
		Aliyun: config.AliyunConfig{
			AccessKeyID:     "ak",
			AccessKeySecret: "secret",
			SceneID:         1000000006,
			Endpoints:       []string{"cloudauth.cn-shanghai.aliyuncs.com", "cloudauth.cn-beijing.aliyuncs.com"},
			ProductCode:     "ID_PRO",
			Model:           "MOVE_ACTION",
			CertType:        "IDENTITY_CARD",
			ReturnURL:       "https://kyc.example.com/verify/callback",
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
