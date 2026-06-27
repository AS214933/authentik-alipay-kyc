package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr         string
	PublicURL        string
	HashPepper       string
	TrustedProxies   []string
	StatsFile        string
	StatsAPIToken    string
	PIIDir           string
	PIIPublicKeyType string
	PIIPublicKeyPEM  string
	QRNoticeHTML     string
	KYCTimeout       time.Duration
	KYCPollInterval  time.Duration
	OIDC             OIDCConfig
	Authentik        AuthentikConfig
	Alipay           AlipayConfig
	Aliyun           AliyunConfig
	Admin            AdminConfig
	Session          SessionConfig
}

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	UserIDClaim  string
}

type AuthentikConfig struct {
	BaseURL       string
	Token         string
	UserIDClaim   string
	AttributeKey  string
	Timeout       time.Duration
	InsecureHTTP  bool
	MergeExisting bool
}

type AlipayConfig struct {
	GatewayURL         string
	AppID              string
	AppPrivateKeyPEM   string
	AlipayPublicKeyPEM string
	EncryptKey         string
	BizCode            string
	CertType           string
	CallbackURL        string
	ReturnURL          string
	Timeout            time.Duration
}

type AliyunConfig struct {
	Enabled         bool
	AccessKeyID     string
	AccessKeySecret string
	SceneID         int64
	Endpoints       []string
	ProductCode     string
	Model           string
	CertType        string
	ReturnURL       string
	Timeout         time.Duration
}

type AdminConfig struct {
	Enabled  bool
	Password string
}

type SessionConfig struct {
	Name     string
	KeyPairs [][]byte
	Secure   bool
	MaxAge   int
}

func Load() (Config, error) {
	publicURL := strings.TrimRight(getenv("PUBLIC_URL", ""), "/")
	if publicURL == "" {
		return Config{}, errors.New("PUBLIC_URL is required")
	}
	if _, err := url.ParseRequestURI(publicURL); err != nil {
		return Config{}, fmt.Errorf("PUBLIC_URL must be an absolute URL: %w", err)
	}

	sessionKeys, err := parseSessionKeys(getenv("SESSION_KEYS", ""))
	if err != nil {
		return Config{}, err
	}

	redirectURL := getenv("OIDC_REDIRECT_URL", publicURL+"/auth/callback")
	callbackURL := getenv("ALIPAY_CALLBACK_URL", publicURL+"/api/alipay/notify")
	returnURL := getenv("ALIPAY_RETURN_URL", publicURL+"/verify/callback")
	aliyunReturnURL := getenv("ALIYUN_RETURN_URL", publicURL+"/verify/callback")
	piiPublicKeyPEM, err := loadPEMEnv("PII_ENCRYPTION_PUBLIC_KEY", "PII_ENCRYPTION_PUBLIC_KEY_FILE")
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		HTTPAddr:         getenv("HTTP_ADDR", ":8080"),
		PublicURL:        publicURL,
		HashPepper:       getenv("HASH_PEPPER", ""),
		TrustedProxies:   splitCSV(getenv("TRUSTED_PROXIES", "")),
		StatsFile:        getenv("STATS_FILE", "/data/stats.json"),
		StatsAPIToken:    getenv("STATS_API_TOKEN", ""),
		PIIDir:           getenv("KYC_PII_DIR", "/data/kyc_pii"),
		PIIPublicKeyType: strings.ToLower(getenv("PII_ENCRYPTION_PUBLIC_KEY_TYPE", "rsa")),
		PIIPublicKeyPEM:  piiPublicKeyPEM,
		QRNoticeHTML:     getenv("KYC_QR_NOTICE_HTML", ""),
		KYCTimeout:       secondsEnv("KYC_TIMEOUT_SECONDS", 82800),
		KYCPollInterval:  secondsEnv("KYC_POLL_INTERVAL_SECONDS", 60),
		OIDC: OIDCConfig{
			Issuer:       getenv("OIDC_ISSUER", ""),
			ClientID:     getenv("OIDC_CLIENT_ID", ""),
			ClientSecret: getenv("OIDC_CLIENT_SECRET", ""),
			RedirectURL:  redirectURL,
			Scopes:       append([]string{"openid", "profile", "email"}, splitCSV(getenv("OIDC_EXTRA_SCOPES", ""))...),
			UserIDClaim:  getenv("OIDC_USER_ID_CLAIM", "sub"),
		},
		Authentik: AuthentikConfig{
			BaseURL:       strings.TrimRight(getenv("AUTHENTIK_BASE_URL", ""), "/"),
			Token:         getenv("AUTHENTIK_TOKEN", ""),
			UserIDClaim:   getenv("AUTHENTIK_USER_ID_CLAIM", "ak_user_id"),
			AttributeKey:  getenv("AUTHENTIK_ATTRIBUTE_KEY", "alipay_kyc"),
			Timeout:       secondsEnv("AUTHENTIK_TIMEOUT_SECONDS", 10),
			InsecureHTTP:  boolEnv("AUTHENTIK_INSECURE_HTTP", false),
			MergeExisting: boolEnv("AUTHENTIK_MERGE_EXISTING_ATTRIBUTES", true),
		},
		Alipay: AlipayConfig{
			GatewayURL:         getenv("ALIPAY_GATEWAY_URL", "https://openapi.alipay.com/gateway.do"),
			AppID:              getenv("ALIPAY_APP_ID", ""),
			AppPrivateKeyPEM:   normalizePEM(getenv("ALIPAY_APP_PRIVATE_KEY", "")),
			AlipayPublicKeyPEM: normalizePEM(getenv("ALIPAY_PUBLIC_KEY", "")),
			EncryptKey:         getenv("ALIPAY_ENCRYPT_KEY", ""),
			BizCode:            getenv("ALIPAY_BIZ_CODE", "FACE"),
			CertType:           getenv("ALIPAY_CERT_TYPE", "IDENTITY_CARD"),
			CallbackURL:        callbackURL,
			ReturnURL:          returnURL,
			Timeout:            secondsEnv("ALIPAY_TIMEOUT_SECONDS", 15),
		},
		Aliyun: AliyunConfig{
			Enabled:         boolEnv("ALIYUN_KYC_ENABLED", false),
			AccessKeyID:     getenv("ALIYUN_ACCESS_KEY_ID", ""),
			AccessKeySecret: getenv("ALIYUN_ACCESS_KEY_SECRET", ""),
			SceneID:         int64Env("ALIYUN_SCENE_ID", 0),
			Endpoints:       splitCSV(getenv("ALIYUN_ENDPOINTS", "cloudauth.cn-shanghai.aliyuncs.com,cloudauth.cn-beijing.aliyuncs.com")),
			ProductCode:     getenv("ALIYUN_PRODUCT_CODE", "ID_PRO"),
			Model:           getenv("ALIYUN_MODEL", "MOVE_ACTION"),
			CertType:        getenv("ALIYUN_CERT_TYPE", "IDENTITY_CARD"),
			ReturnURL:       aliyunReturnURL,
			Timeout:         secondsEnv("ALIYUN_TIMEOUT_SECONDS", 10),
		},
		Admin: AdminConfig{
			Enabled:  boolEnv("ADMIN_ENABLED", false),
			Password: getenv("ADMIN_PASSWORD", ""),
		},
		Session: SessionConfig{
			Name:     getenv("SESSION_NAME", "alipay_kyc"),
			KeyPairs: sessionKeys,
			Secure:   boolEnv("SESSION_SECURE", strings.HasPrefix(publicURL, "https://")),
			MaxAge:   int(secondsEnv("SESSION_MAX_AGE_SECONDS", 86400).Seconds()),
		},
	}

	if cfg.HashPepper == "" {
		return Config{}, errors.New("HASH_PEPPER is required")
	}
	if cfg.StatsAPIToken == "" {
		return Config{}, errors.New("STATS_API_TOKEN is required")
	}
	if cfg.PIIDir == "" || cfg.PIIPublicKeyPEM == "" {
		return Config{}, errors.New("KYC_PII_DIR and PII_ENCRYPTION_PUBLIC_KEY or PII_ENCRYPTION_PUBLIC_KEY_FILE are required")
	}
	if cfg.PIIPublicKeyType != "rsa" && cfg.PIIPublicKeyType != "sm2" {
		return Config{}, errors.New("PII_ENCRYPTION_PUBLIC_KEY_TYPE must be rsa or sm2")
	}
	if cfg.OIDC.Issuer == "" || cfg.OIDC.ClientID == "" || cfg.OIDC.ClientSecret == "" {
		return Config{}, errors.New("OIDC_ISSUER, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET are required")
	}
	if cfg.Authentik.BaseURL == "" || cfg.Authentik.Token == "" {
		return Config{}, errors.New("AUTHENTIK_BASE_URL and AUTHENTIK_TOKEN are required")
	}
	if cfg.Alipay.AppID == "" || cfg.Alipay.AppPrivateKeyPEM == "" || cfg.Alipay.AlipayPublicKeyPEM == "" {
		return Config{}, errors.New("ALIPAY_APP_ID, ALIPAY_APP_PRIVATE_KEY, and ALIPAY_PUBLIC_KEY are required")
	}
	if cfg.Aliyun.Enabled {
		if cfg.Aliyun.AccessKeyID == "" || cfg.Aliyun.AccessKeySecret == "" || cfg.Aliyun.SceneID <= 0 {
			return Config{}, errors.New("ALIYUN_ACCESS_KEY_ID, ALIYUN_ACCESS_KEY_SECRET, and ALIYUN_SCENE_ID are required when ALIYUN_KYC_ENABLED is true")
		}
		if len(cfg.Aliyun.Endpoints) == 0 {
			return Config{}, errors.New("ALIYUN_ENDPOINTS must contain at least one endpoint when ALIYUN_KYC_ENABLED is true")
		}
	}
	if cfg.Admin.Enabled && cfg.Admin.Password == "" {
		return Config{}, errors.New("ADMIN_PASSWORD is required when ADMIN_ENABLED is true")
	}
	return cfg, nil
}

func LogLevelFromEnv(name string, fallback slog.Level) slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return fallback
	}
}

func getenv(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return strings.TrimSpace(value)
	}
	return fallback
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func secondsEnv(name string, fallback int) time.Duration {
	value := getenv(name, "")
	if value == "" {
		return time.Duration(fallback) * time.Second
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return time.Duration(fallback) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func int64Env(name string, fallback int64) int64 {
	value := getenv(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func boolEnv(name string, fallback bool) bool {
	value := getenv(name, "")
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	case "0", "f", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func normalizePEM(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `\n`, "\n")
	return value
}

func loadPEMEnv(valueName, fileName string) (string, error) {
	value := getenv(valueName, "")
	filePath := getenv(fileName, "")
	if value != "" && filePath != "" {
		return "", fmt.Errorf("%s and %s cannot both be set", valueName, fileName)
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read %s %q: %w", fileName, filePath, err)
		}
		return normalizePEM(string(data)), nil
	}

	value = normalizePEM(value)
	if value == "" || strings.Contains(value, "-----BEGIN ") {
		return value, nil
	}
	if data, err := os.ReadFile(value); err == nil {
		return normalizePEM(string(data)), nil
	}
	return value, nil
}

func parseSessionKeys(value string) ([][]byte, error) {
	if value == "" {
		key := make([]byte, 64)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate session key: %w", err)
		}
		return [][]byte{key}, nil
	}
	parts := splitCSV(value)
	if len(parts) == 0 {
		return nil, errors.New("SESSION_KEYS must contain at least one key")
	}
	keys := make([][]byte, 0, len(parts))
	for _, part := range parts {
		decoded, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(part)
		}
		if err != nil {
			return nil, fmt.Errorf("SESSION_KEYS must be base64 encoded: %w", err)
		}
		if len(decoded) < 32 {
			return nil, errors.New("each SESSION_KEYS value must decode to at least 32 bytes")
		}
		keys = append(keys, decoded)
	}
	return keys, nil
}
