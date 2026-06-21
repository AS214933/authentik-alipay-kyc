package alipay

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/config"
)

const (
	MethodInitialize = "alipay.user.certify.open.initialize"
	MethodQuery      = "alipay.user.certify.open.query"
	MethodCertify    = "alipay.user.certify.open.certify"
)

type Client struct {
	gatewayURL  string
	appID       string
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	bizCode     string
	certType    string
	callbackURL string
	returnURL   string
	httpClient  *http.Client
}

type InitializeRequest struct {
	OuterOrderNo  string `json:"outer_order_no"`
	BizCode       string `json:"biz_code"`
	IdentityParam struct {
		IdentityType string `json:"identity_type"`
		CertType     string `json:"cert_type"`
		CertName     string `json:"cert_name"`
		CertNo       string `json:"cert_no"`
	} `json:"identity_param"`
	MerchantConfig struct {
		ReturnURL string `json:"return_url"`
	} `json:"merchant_config"`
}

type InitializeResponse struct {
	CertifyID string `json:"certify_id"`
}

type QueryResponse struct {
	Passed       string                 `json:"passed"`
	IdentityInfo map[string]interface{} `json:"identity_info"`
	MaterialInfo map[string]interface{} `json:"material_info"`
}

func NewClient(cfg config.AlipayConfig) *Client {
	privateKey, _ := parsePrivateKey(cfg.AppPrivateKeyPEM)
	publicKey, _ := parsePublicKey(cfg.AlipayPublicKeyPEM)
	return &Client{
		gatewayURL:  cfg.GatewayURL,
		appID:       cfg.AppID,
		privateKey:  privateKey,
		publicKey:   publicKey,
		bizCode:     cfg.BizCode,
		certType:    cfg.CertType,
		callbackURL: cfg.CallbackURL,
		returnURL:   cfg.ReturnURL,
		httpClient:  &http.Client{Timeout: cfg.Timeout},
	}
}

func (c *Client) Initialize(ctx context.Context, outerOrderNo, certName, certNo, returnURL string) (InitializeResponse, error) {
	if c.privateKey == nil {
		return InitializeResponse{}, errors.New("invalid app private key")
	}
	req := InitializeRequest{
		OuterOrderNo: outerOrderNo,
		BizCode:      c.bizCode,
	}
	req.IdentityParam.IdentityType = "CERT_INFO"
	req.IdentityParam.CertType = c.certType
	req.IdentityParam.CertName = certName
	req.IdentityParam.CertNo = certNo
	if returnURL == "" {
		returnURL = c.returnURL
	}
	req.MerchantConfig.ReturnURL = returnURL

	var response InitializeResponse
	if err := c.call(ctx, MethodInitialize, req, &response); err != nil {
		return InitializeResponse{}, err
	}
	if response.CertifyID == "" {
		return InitializeResponse{}, errors.New("alipay initialize response missing certify_id")
	}
	return response, nil
}

func (c *Client) CertifyURL(certifyID string) (string, error) {
	bizContent, err := json.Marshal(map[string]string{"certify_id": certifyID})
	if err != nil {
		return "", err
	}
	params := c.commonParams(MethodCertify, string(bizContent))
	sign, err := c.sign(params)
	if err != nil {
		return "", err
	}
	params.Set("sign", sign)
	return c.gatewayURL + "?" + params.Encode(), nil
}

func (c *Client) Query(ctx context.Context, certifyID string) (QueryResponse, error) {
	if certifyID == "" {
		return QueryResponse{}, errors.New("certify_id is required")
	}
	var response QueryResponse
	if err := c.call(ctx, MethodQuery, map[string]string{"certify_id": certifyID}, &response); err != nil {
		return QueryResponse{}, err
	}
	return response, nil
}

func (c *Client) call(ctx context.Context, method string, biz interface{}, out interface{}) error {
	bizContent, err := json.Marshal(biz)
	if err != nil {
		return err
	}
	params := c.commonParams(method, string(bizContent))
	sign, err := c.sign(params)
	if err != nil {
		return err
	}
	params.Set("sign", sign)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.gatewayURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alipay http status=%d body=%s", resp.StatusCode, string(body))
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("decode alipay response: %w", err)
	}
	responseKey := strings.ReplaceAll(method, ".", "_") + "_response"
	raw, ok := envelope[responseKey]
	if !ok {
		return fmt.Errorf("alipay response missing %s: %s", responseKey, string(body))
	}
	if sigRaw, ok := envelope["sign"]; ok && c.publicKey != nil {
		var sig string
		if err := json.Unmarshal(sigRaw, &sig); err != nil {
			return fmt.Errorf("decode alipay sign: %w", err)
		}
		if err := c.verifyResponse(raw, sig); err != nil {
			return err
		}
	}

	var apiResponse struct {
		Code    string `json:"code"`
		Msg     string `json:"msg"`
		SubCode string `json:"sub_code"`
		SubMsg  string `json:"sub_msg"`
	}
	if err := json.Unmarshal(raw, &apiResponse); err != nil {
		return fmt.Errorf("decode alipay api response: %w", err)
	}
	if apiResponse.Code != "10000" {
		return fmt.Errorf("alipay api error code=%s msg=%s sub_code=%s sub_msg=%s", apiResponse.Code, apiResponse.Msg, apiResponse.SubCode, apiResponse.SubMsg)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode alipay business response: %w", err)
	}
	return nil
}

func (c *Client) commonParams(method, bizContent string) url.Values {
	params := url.Values{}
	params.Set("app_id", c.appID)
	params.Set("method", method)
	params.Set("format", "JSON")
	params.Set("charset", "utf-8")
	params.Set("sign_type", "RSA2")
	params.Set("timestamp", time.Now().Format("2006-01-02 15:04:05"))
	params.Set("version", "1.0")
	params.Set("biz_content", bizContent)
	if c.callbackURL != "" && method == MethodInitialize {
		params.Set("notify_url", c.callbackURL)
	}
	return params
}

func (c *Client) sign(params url.Values) (string, error) {
	canonical := canonicalize(params)
	hashed := sha256.Sum256([]byte(canonical))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (c *Client) verifyResponse(raw json.RawMessage, signature string) error {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode alipay response signature: %w", err)
	}
	hashed := sha256.Sum256(raw)
	if err := rsa.VerifyPKCS1v15(c.publicKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
		return fmt.Errorf("verify alipay response signature: %w", err)
	}
	return nil
}

func canonicalize(params url.Values) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		if key == "sign" || key == "sign_type" {
			continue
		}
		if params.Get(key) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+params.Get(key))
	}
	return strings.Join(parts, "&")
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	raw = ensurePEM(raw, "RSA PRIVATE KEY")
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func parsePublicKey(raw string) (*rsa.PublicKey, error) {
	raw = ensurePEM(raw, "PUBLIC KEY")
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ensurePEM(raw, blockType string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "-----BEGIN ") {
		return raw
	}
	if raw == "" {
		return raw
	}
	var b strings.Builder
	b.WriteString("-----BEGIN ")
	b.WriteString(blockType)
	b.WriteString("-----\n")
	for len(raw) > 64 {
		b.WriteString(raw[:64])
		b.WriteByte('\n')
		raw = raw[64:]
	}
	b.WriteString(raw)
	b.WriteString("\n-----END ")
	b.WriteString(blockType)
	b.WriteString("-----")
	return b.String()
}
