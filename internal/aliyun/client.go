package aliyun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cloudauth "github.com/alibabacloud-go/cloudauth-20190307/v4/client"
	openapiutil "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/example/authentik-alipay-kyc/internal/config"
)

const Provider = "aliyun"

type Client struct {
	clients     []*endpointClient
	sceneID     int64
	productCode string
	model       string
	certType    string
	returnURL   string
}

type endpointClient struct {
	endpoint string
	client   aliyunSDK
}

type aliyunSDK interface {
	InitFaceVerify(request *cloudauth.InitFaceVerifyRequest) (*cloudauth.InitFaceVerifyResponse, error)
	DescribeFaceVerify(request *cloudauth.DescribeFaceVerifyRequest) (*cloudauth.DescribeFaceVerifyResponse, error)
}

type InitializeRequest struct {
	OuterOrderNo   string
	CertName       string
	CertNo         string
	ReturnURL      string
	MetaInfo       string
	CertifyURLType string
	UserID         string
	IP             string
}

type InitializeResponse struct {
	CertifyID  string
	CertifyURL string
}

type QueryResponse struct {
	Passed string
}

func NewClient(cfg config.AliyunConfig) (*Client, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" || cfg.SceneID <= 0 {
		return nil, errors.New("aliyun kyc credentials and scene id are required")
	}
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("aliyun kyc endpoints are required")
	}
	clients := make([]*endpointClient, 0, len(cfg.Endpoints))
	for _, endpoint := range cfg.Endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		sdk, err := cloudauth.NewClient(&openapiutil.Config{
			AccessKeyId:     &cfg.AccessKeyID,
			AccessKeySecret: &cfg.AccessKeySecret,
			Endpoint:        &endpoint,
		})
		if err != nil {
			return nil, fmt.Errorf("create aliyun cloudauth client for %s: %w", endpoint, err)
		}
		clients = append(clients, &endpointClient{endpoint: endpoint, client: sdk})
	}
	if len(clients) == 0 {
		return nil, errors.New("aliyun kyc endpoints are required")
	}
	return &Client{
		clients:     clients,
		sceneID:     cfg.SceneID,
		productCode: firstNonEmpty(cfg.ProductCode, "ID_PRO"),
		model:       firstNonEmpty(cfg.Model, "MOVE_ACTION"),
		certType:    firstNonEmpty(cfg.CertType, "IDENTITY_CARD"),
		returnURL:   cfg.ReturnURL,
	}, nil
}

func (c *Client) Initialize(ctx context.Context, req InitializeRequest) (InitializeResponse, error) {
	if c == nil {
		return InitializeResponse{}, errors.New("aliyun client is not configured")
	}
	req.CertifyURLType = strings.ToUpper(strings.TrimSpace(req.CertifyURLType))
	if req.CertifyURLType != "WEB" && req.CertifyURLType != "H5" {
		return InitializeResponse{}, errors.New("aliyun certify_url_type must be WEB or H5")
	}
	req.MetaInfo = strings.TrimSpace(req.MetaInfo)
	if req.MetaInfo == "" {
		return InitializeResponse{}, errors.New("aliyun meta_info is required")
	}
	returnURL := strings.TrimSpace(req.ReturnURL)
	if returnURL == "" {
		returnURL = c.returnURL
	}
	request := &cloudauth.InitFaceVerifyRequest{
		SceneId:        &c.sceneID,
		OuterOrderNo:   stringPtr(req.OuterOrderNo),
		ProductCode:    stringPtr(c.productCode),
		CertType:       stringPtr(c.certType),
		CertName:       stringPtr(req.CertName),
		CertNo:         stringPtr(req.CertNo),
		ReturnUrl:      stringPtr(returnURL),
		MetaInfo:       stringPtr(req.MetaInfo),
		CertifyUrlType: stringPtr(req.CertifyURLType),
		Model:          stringPtr(c.model),
		UserId:         optionalStringPtr(req.UserID),
		Ip:             optionalStringPtr(req.IP),
	}
	var lastErr error
	for _, item := range c.clients {
		if err := ctx.Err(); err != nil {
			return InitializeResponse{}, err
		}
		resp, err := item.client.InitFaceVerify(request)
		if err != nil {
			lastErr = fmt.Errorf("aliyun init endpoint=%s request failed", item.endpoint)
			continue
		}
		body := resp.GetBody()
		if body == nil {
			lastErr = fmt.Errorf("aliyun init endpoint=%s missing response body", item.endpoint)
			continue
		}
		if body.GetCode() == nil || *body.GetCode() != "200" {
			lastErr = fmt.Errorf("aliyun init endpoint=%s code=%s", item.endpoint, safeString(body.GetCode()))
			continue
		}
		result := body.GetResultObject()
		if result == nil || result.GetCertifyId() == nil || result.GetCertifyUrl() == nil || *result.GetCertifyId() == "" || *result.GetCertifyUrl() == "" {
			lastErr = fmt.Errorf("aliyun init endpoint=%s missing certify result", item.endpoint)
			continue
		}
		return InitializeResponse{
			CertifyID:  *result.GetCertifyId(),
			CertifyURL: *result.GetCertifyUrl(),
		}, nil
	}
	if lastErr != nil {
		return InitializeResponse{}, lastErr
	}
	return InitializeResponse{}, errors.New("aliyun init failed")
}

func (c *Client) Query(ctx context.Context, certifyID string) (QueryResponse, error) {
	if c == nil {
		return QueryResponse{}, errors.New("aliyun client is not configured")
	}
	certifyID = strings.TrimSpace(certifyID)
	if certifyID == "" {
		return QueryResponse{}, errors.New("certify_id is required")
	}
	request := &cloudauth.DescribeFaceVerifyRequest{
		SceneId:   &c.sceneID,
		CertifyId: &certifyID,
	}
	var lastErr error
	for _, item := range c.clients {
		if err := ctx.Err(); err != nil {
			return QueryResponse{}, err
		}
		resp, err := item.client.DescribeFaceVerify(request)
		if err != nil {
			lastErr = fmt.Errorf("aliyun query endpoint=%s request failed", item.endpoint)
			continue
		}
		body := resp.GetBody()
		if body == nil {
			lastErr = fmt.Errorf("aliyun query endpoint=%s missing response body", item.endpoint)
			continue
		}
		if body.GetCode() == nil || *body.GetCode() != "200" {
			lastErr = fmt.Errorf("aliyun query endpoint=%s code=%s", item.endpoint, safeString(body.GetCode()))
			continue
		}
		result := body.GetResultObject()
		if result == nil || result.GetPassed() == nil {
			lastErr = fmt.Errorf("aliyun query endpoint=%s missing passed result", item.endpoint)
			continue
		}
		return QueryResponse{Passed: *result.GetPassed()}, nil
	}
	if lastErr != nil {
		return QueryResponse{}, lastErr
	}
	return QueryResponse{}, errors.New("aliyun query failed")
}

func stringPtr(value string) *string {
	return &value
}

func optionalStringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func safeString(value *string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return "<empty>"
	}
	return strings.TrimSpace(*value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
