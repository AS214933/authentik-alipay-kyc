package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/authentik-alipay-kyc/internal/config"
)

func TestNewRetriesIssuerWithTrailingSlash(t *testing.T) {
	var issuerWithSlash string
	discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") &&
			!strings.Contains(r.URL.Path, "/.well-known/openid-configuration/") {
			http.NotFound(w, r)
			return
		}
		writeDiscovery(t, w, map[string]interface{}{
			"issuer":                                issuerWithSlash,
			"authorization_endpoint":                issuerWithSlash + "authorize/",
			"token_endpoint":                        issuerWithSlash + "token/",
			"jwks_uri":                              issuerWithSlash + "jwks/",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer discovery.Close()
	issuerWithSlash = discovery.URL + "/application/o/alipay-kyc/"

	client, err := New(context.Background(), config.OIDCConfig{
		Issuer:       strings.TrimSuffix(issuerWithSlash, "/"),
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://kyc.example.com/auth/callback",
		Scopes:       []string{"openid"},
		UserIDClaim:  "sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("expected client")
	}
}

func writeDiscovery(t *testing.T, w http.ResponseWriter, payload map[string]interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatal(err)
	}
}
