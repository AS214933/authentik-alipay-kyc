package aliyun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cloudauth "github.com/alibabacloud-go/cloudauth-20190307/v4/client"
	"github.com/example/authentik-alipay-kyc/internal/config"
)

type fakeSDK struct {
	initResp  *cloudauth.InitFaceVerifyResponse
	queryResp *cloudauth.DescribeFaceVerifyResponse
	err       error
	initReq   *cloudauth.InitFaceVerifyRequest
}

func (f *fakeSDK) InitFaceVerify(req *cloudauth.InitFaceVerifyRequest) (*cloudauth.InitFaceVerifyResponse, error) {
	f.initReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.initResp, nil
}

func (f *fakeSDK) DescribeFaceVerify(*cloudauth.DescribeFaceVerifyRequest) (*cloudauth.DescribeFaceVerifyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.queryResp, nil
}

func TestInitializeFallsBackAcrossEndpoints(t *testing.T) {
	secondary := &fakeSDK{initResp: initResponse("CERT123", "https://aliyun.example/certify")}
	client := &Client{
		clients: []*endpointClient{
			{endpoint: "primary", client: &fakeSDK{err: errors.New("temporary")}},
			{endpoint: "secondary", client: secondary},
		},
		sceneID:     1000000006,
		productCode: "ID_PRO",
		model:       "MOVE_ACTION",
		certType:    "IDENTITY_CARD",
		returnURL:   "https://kyc.example.com/verify/callback",
	}

	resp, err := client.Initialize(context.Background(), InitializeRequest{
		OuterOrderNo:   "order",
		CertName:       "张三",
		CertNo:         "11010519491231002X",
		MetaInfo:       "{}",
		CertifyURLType: "WEB",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.CertifyID != "CERT123" || resp.CertifyURL != "https://aliyun.example/certify" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if secondary.initReq == nil || secondary.initReq.VideoEvidence == nil || *secondary.initReq.VideoEvidence != "true" {
		t.Fatalf("VideoEvidence = %v, want true", secondary.initReq.GetVideoEvidence())
	}
}

func TestInitializeRedactsUpstreamError(t *testing.T) {
	client := &Client{
		clients: []*endpointClient{
			{endpoint: "primary", client: &fakeSDK{err: errors.New("张三 11010519491231002X")}},
		},
		sceneID:     1000000006,
		productCode: "ID_PRO",
		model:       "MOVE_ACTION",
		certType:    "IDENTITY_CARD",
		returnURL:   "https://kyc.example.com/verify/callback",
	}

	_, err := client.Initialize(context.Background(), InitializeRequest{
		OuterOrderNo:   "order",
		CertName:       "张三",
		CertNo:         "11010519491231002X",
		MetaInfo:       "{}",
		CertifyURLType: "WEB",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, sensitive := range []string{"张三", "11010519491231002X"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, err.Error())
		}
	}
}

func TestQueryReturnsPassed(t *testing.T) {
	client := &Client{
		clients: []*endpointClient{
			{endpoint: "primary", client: &fakeSDK{queryResp: queryResponse("T")}},
		},
		sceneID: 1000000006,
	}

	resp, err := client.Query(context.Background(), "CERT123")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Passed != "T" {
		t.Fatalf("Passed = %q, want T", resp.Passed)
	}
}

func TestNewOpenAPIConfigAppliesTimeout(t *testing.T) {
	cfg := config.AliyunConfig{
		AccessKeyID:     "ak",
		AccessKeySecret: "secret",
		Timeout:         10 * time.Second,
	}
	sdkConfig := newOpenAPIConfig(cfg, "cloudauth.cn-shanghai.aliyuncs.com")
	if sdkConfig.ReadTimeout == nil || *sdkConfig.ReadTimeout != 10000 {
		t.Fatalf("ReadTimeout = %v, want 10000", sdkConfig.ReadTimeout)
	}
	if sdkConfig.ConnectTimeout == nil || *sdkConfig.ConnectTimeout != 10000 {
		t.Fatalf("ConnectTimeout = %v, want 10000", sdkConfig.ConnectTimeout)
	}
}

func initResponse(certifyID, certifyURL string) *cloudauth.InitFaceVerifyResponse {
	return &cloudauth.InitFaceVerifyResponse{
		Body: &cloudauth.InitFaceVerifyResponseBody{
			Code: stringPtr("200"),
			ResultObject: &cloudauth.InitFaceVerifyResponseBodyResultObject{
				CertifyId:  stringPtr(certifyID),
				CertifyUrl: stringPtr(certifyURL),
			},
		},
	}
}

func queryResponse(passed string) *cloudauth.DescribeFaceVerifyResponse {
	return &cloudauth.DescribeFaceVerifyResponse{
		Body: &cloudauth.DescribeFaceVerifyResponseBody{
			Code: stringPtr("200"),
			ResultObject: &cloudauth.DescribeFaceVerifyResponseBodyResultObject{
				Passed: stringPtr(passed),
			},
		},
	}
}
