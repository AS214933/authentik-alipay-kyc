package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestLoadRequiresAdminAllowedUsernamesWhenEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ADMIN_ENABLED", "true")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ADMIN_ALLOWED_USERNAMES is required") {
		t.Fatalf("Load error = %v, want admin username allowlist required", err)
	}
}

func TestLoadAcceptsAdminAllowedUsernamesWhenEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ADMIN_ENABLED", "true")
	t.Setenv("ADMIN_ALLOWED_USERNAMES", "alice, bob")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Admin.Enabled || len(cfg.Admin.AllowedUsernames) != 2 || cfg.Admin.AllowedUsernames[0] != "alice" || cfg.Admin.AllowedUsernames[1] != "bob" {
		t.Fatalf("unexpected admin config: %+v", cfg.Admin)
	}
}

func TestLoadReadsQRNoticeHTML(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("KYC_QR_NOTICE_HTML", `<p>认证前请确认信息。</p>`)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QRNoticeHTML != `<p>认证前请确认信息。</p>` {
		t.Fatalf("QRNoticeHTML = %q", cfg.QRNoticeHTML)
	}
}

func TestLoadDefaultsQRNoticeHTMLToEmpty(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QRNoticeHTML != "" {
		t.Fatalf("QRNoticeHTML = %q, want empty", cfg.QRNoticeHTML)
	}
}

func TestLoadDefaultsAlipayKYCTimeoutTo23Hours(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KYCTimeout != 23*time.Hour {
		t.Fatalf("KYCTimeout = %s, want 23h", cfg.KYCTimeout)
	}
}

func TestLoadDefaultsAlipayKYCEnabled(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Alipay.Enabled {
		t.Fatal("expected alipay kyc to be enabled by default")
	}
}

func TestLoadRequiresAlipayConfigWhenEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ALIPAY_APP_ID", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ALIPAY_APP_ID") {
		t.Fatalf("Load error = %v, want alipay config required", err)
	}
}

func TestLoadAllowsAlipayConfigMissingWhenDisabledAndAliyunEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ALIPAY_KYC_ENABLED", "false")
	t.Setenv("ALIPAY_APP_ID", "")
	t.Setenv("ALIPAY_APP_PRIVATE_KEY", "")
	t.Setenv("ALIPAY_PUBLIC_KEY", "")
	t.Setenv("ALIYUN_KYC_ENABLED", "true")
	t.Setenv("ALIYUN_ACCESS_KEY_ID", "ak")
	t.Setenv("ALIYUN_ACCESS_KEY_SECRET", "secret")
	t.Setenv("ALIYUN_SCENE_ID", "1000000006")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alipay.Enabled || !cfg.Aliyun.Enabled {
		t.Fatalf("unexpected provider flags: alipay=%t aliyun=%t", cfg.Alipay.Enabled, cfg.Aliyun.Enabled)
	}
}

func TestLoadRequiresAtLeastOneKYCProvider(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ALIPAY_KYC_ENABLED", "false")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "at least one KYC provider") {
		t.Fatalf("Load error = %v, want provider requirement", err)
	}
}

func TestLoadRequiresAliyunConfigWhenEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ALIYUN_KYC_ENABLED", "true")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ALIYUN_ACCESS_KEY_ID") {
		t.Fatalf("Load error = %v, want aliyun config required", err)
	}
}

func TestLoadAcceptsAliyunConfigWhenEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ALIYUN_KYC_ENABLED", "true")
	t.Setenv("ALIYUN_ACCESS_KEY_ID", "ak")
	t.Setenv("ALIYUN_ACCESS_KEY_SECRET", "secret")
	t.Setenv("ALIYUN_SCENE_ID", "1000000006")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Aliyun.Enabled || cfg.Aliyun.SceneID != 1000000006 || cfg.Aliyun.ProductCode != "ID_PRO" || cfg.Aliyun.Model != "MOVE_ACTION" {
		t.Fatalf("unexpected aliyun config: %+v", cfg.Aliyun)
	}
	if len(cfg.Aliyun.Endpoints) != 2 || cfg.Aliyun.Endpoints[0] != "cloudauth.cn-shanghai.aliyuncs.com" || cfg.Aliyun.Endpoints[1] != "cloudauth.cn-beijing.aliyuncs.com" {
		t.Fatalf("unexpected aliyun endpoints: %+v", cfg.Aliyun.Endpoints)
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
