package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestLoadPreservesOIDCIssuerTrailingSlash(t *testing.T) {
	t.Setenv("PUBLIC_URL", "https://kyc.example.com")
	t.Setenv("SESSION_KEYS", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 64)))
	t.Setenv("HASH_PEPPER", "pepper")
	t.Setenv("STATS_API_TOKEN", "stats-token")
	t.Setenv("OIDC_ISSUER", "https://auth.example.com/application/o/alipay-kyc/")
	t.Setenv("OIDC_CLIENT_ID", "client")
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	t.Setenv("AUTHENTIK_BASE_URL", "https://auth.example.com")
	t.Setenv("AUTHENTIK_TOKEN", "token")
	t.Setenv("ALIPAY_APP_ID", "app-id")
	t.Setenv("ALIPAY_APP_PRIVATE_KEY", "private-key")
	t.Setenv("ALIPAY_PUBLIC_KEY", "public-key")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Issuer != "https://auth.example.com/application/o/alipay-kyc/" {
		t.Fatalf("OIDC issuer = %q", cfg.OIDC.Issuer)
	}
}
