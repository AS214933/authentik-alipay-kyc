package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPreservesOIDCIssuerTrailingSlash(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Issuer != "https://auth.example.com/application/o/alipay-kyc/" {
		t.Fatalf("OIDC issuer = %q", cfg.OIDC.Issuer)
	}
}

func TestLoadReadsPIIPublicKeyFromFile(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PII_ENCRYPTION_PUBLIC_KEY", "")
	path := filepath.Join(t.TempDir(), "pii-public.pem")
	if err := os.WriteFile(path, []byte(testRSAPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PII_ENCRYPTION_PUBLIC_KEY_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PIIPublicKeyPEM != testRSAPublicKey {
		t.Fatalf("PII public key was not loaded from file")
	}
}

func TestLoadRejectsBothPIIPublicKeyEnvForms(t *testing.T) {
	setRequiredEnv(t)
	path := filepath.Join(t.TempDir(), "pii-public.pem")
	if err := os.WriteFile(path, []byte(testRSAPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PII_ENCRYPTION_PUBLIC_KEY_FILE", path)

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "cannot both be set") {
		t.Fatalf("Load error = %v, want both key forms rejected", err)
	}
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PUBLIC_URL", "https://kyc.example.com")
	t.Setenv("SESSION_KEYS", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 64)))
	t.Setenv("HASH_PEPPER", "pepper")
	t.Setenv("STATS_API_TOKEN", "stats-token")
	t.Setenv("PII_ENCRYPTION_PUBLIC_KEY", testRSAPublicKey)
	t.Setenv("OIDC_ISSUER", "https://auth.example.com/application/o/alipay-kyc/")
	t.Setenv("OIDC_CLIENT_ID", "client")
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	t.Setenv("AUTHENTIK_BASE_URL", "https://auth.example.com")
	t.Setenv("AUTHENTIK_TOKEN", "token")
	t.Setenv("ALIPAY_APP_ID", "app-id")
	t.Setenv("ALIPAY_APP_PRIVATE_KEY", "private-key")
	t.Setenv("ALIPAY_PUBLIC_KEY", "public-key")
}

const testRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApX3v1V9E7Z5SJNm6FX5Q
BTQx9tK5rQ7ysnKw6RTgFKU/XKPwmbeXS13C6HJLn95Pp+JT6e5F5ceec2uRHmH0
EZgmy20aS7xnS0KLFrH8BvB5vjEEXRf3KqhDX8roaxUu2dtDrpgeE0tVgsyNrdLj
q24hqC7e1ydVL7M4G/wtPv2TSqtviG4obQ9dqUfwLg7yHpNPZZG7KTTkBmlwd2xJ
p/omP0X9OglcewF5taVD7gq50QkJxQHd1rvUM4JLqpDBMnnMEby85AF16/LgxnLG
h4gPg/y641TUjmvsMNgEqW8TzUyPnvqbKwZxAcz0bmHPkySrBN/4CRBTkuVLMbsL
ywIDAQAB
-----END PUBLIC KEY-----`
