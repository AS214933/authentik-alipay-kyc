package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/alipay"
	"github.com/example/authentik-alipay-kyc/internal/authentik"
	"github.com/example/authentik-alipay-kyc/internal/config"
	"github.com/example/authentik-alipay-kyc/internal/oidc"
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
}

func (f fakeAlipay) Initialize(context.Context, string, string, string, string) (alipay.InitializeResponse, error) {
	return alipay.InitializeResponse{CertifyID: f.certifyID}, nil
}

func (f fakeAlipay) CertifyURL(certifyID string) (string, error) {
	return "https://alipay.example/certify?certify_id=" + certifyID, nil
}

func (f fakeAlipay) Query(context.Context, string) (alipay.QueryResponse, error) {
	return alipay.QueryResponse{Passed: f.passed}, nil
}

func TestKYCFlowWritesAuthentikAttribute(t *testing.T) {
	ak := &fakeAuthentik{user: authentik.User{
		ID:         1,
		Username:   "alice",
		Attributes: map[string]interface{}{},
	}}
	srv := New(Dependencies{
		Config:    testConfig(),
		Logger:    slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		OIDC:      fakeOIDC{},
		Authentik: ak,
		Alipay:    fakeAlipay{certifyID: "CERT123", passed: "T"},
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
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	if startResp.State == "" {
		t.Fatal("expected state")
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
		HTTPAddr:   ":8080",
		PublicURL:  "https://kyc.example.com",
		HashPepper: "pepper",
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
