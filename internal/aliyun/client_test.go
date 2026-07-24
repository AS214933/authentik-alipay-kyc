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
	initResp    *cloudauth.InitFaceVerifyResponse
	queryResp   *cloudauth.DescribeFaceVerifyResponse
	id2Resp     *cloudauth.Id2MetaVerifyResponse
	mobile3Resp *cloudauth.Mobile3MetaDetailVerifyResponse
	err         error
	initReq     *cloudauth.InitFaceVerifyRequest
	id2Req      *cloudauth.Id2MetaVerifyRequest
	mobile3Req  *cloudauth.Mobile3MetaDetailVerifyRequest
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

func (f *fakeSDK) Id2MetaVerify(req *cloudauth.Id2MetaVerifyRequest) (*cloudauth.Id2MetaVerifyResponse, error) {
	f.id2Req = req
	if f.err != nil {
		return nil, f.err
	}
	return f.id2Resp, nil
}

func (f *fakeSDK) Mobile3MetaDetailVerify(req *cloudauth.Mobile3MetaDetailVerifyRequest) (*cloudauth.Mobile3MetaDetailVerifyResponse, error) {
	f.mobile3Req = req
	if f.err != nil {
		return nil, f.err
	}
	return f.mobile3Resp, nil
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

func TestVerifyID2MetaReturnsPassed(t *testing.T) {
	sdk := &fakeSDK{id2Resp: id2Response("1")}
	client := &Client{
		clients: []*endpointClient{
			{endpoint: "primary", client: sdk},
		},
	}

	resp, err := client.VerifyID2Meta(context.Background(), ID2MetaVerifyRequest{
		Name:     "张三",
		IDNumber: "11010519491231002X",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Passed || resp.BizCode != "1" {
		t.Fatalf("unexpected id2 response: %+v", resp)
	}
	if sdk.id2Req == nil || safeValue(sdk.id2Req.UserName) != "张三" || safeValue(sdk.id2Req.IdentifyNum) != "11010519491231002X" || safeValue(sdk.id2Req.ParamType) != "normal" {
		t.Fatalf("unexpected id2 request: %+v", sdk.id2Req)
	}
}

func TestVerifyMobile3MetaDetailReturnsDetail(t *testing.T) {
	sdk := &fakeSDK{mobile3Resp: mobile3Response("1", "101", "CMCC")}
	client := &Client{
		clients: []*endpointClient{
			{endpoint: "primary", client: sdk},
		},
	}

	resp, err := client.VerifyMobile3MetaDetail(context.Background(), Mobile3MetaDetailVerifyRequest{
		Name:     "张三",
		IDNumber: "11010519491231002X",
		Mobile:   "13800138000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Passed || resp.BizCode != "1" || resp.SubCode != "101" || resp.ISPName != "CMCC" {
		t.Fatalf("unexpected mobile3 response: %+v", resp)
	}
	if sdk.mobile3Req == nil || safeValue(sdk.mobile3Req.UserName) != "张三" || safeValue(sdk.mobile3Req.IdentifyNum) != "11010519491231002X" || safeValue(sdk.mobile3Req.Mobile) != "13800138000" || safeValue(sdk.mobile3Req.ParamType) != "normal" {
		t.Fatalf("unexpected mobile3 request: %+v", sdk.mobile3Req)
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

func TestNewClientAllowsMetaVerifyWithoutSceneID(t *testing.T) {
	client, err := NewClient(config.AliyunConfig{
		AccessKeyID:          "ak",
		AccessKeySecret:      "secret",
		Endpoints:            []string{"cloudauth.cn-shanghai.aliyuncs.com"},
		ID2MetaVerifyEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("expected aliyun client")
	}
	if client.sceneID != 0 || len(client.clients) != 1 {
		t.Fatalf("unexpected aliyun client: sceneID=%d endpoints=%d", client.sceneID, len(client.clients))
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

func id2Response(bizCode string) *cloudauth.Id2MetaVerifyResponse {
	return &cloudauth.Id2MetaVerifyResponse{
		Body: &cloudauth.Id2MetaVerifyResponseBody{
			Code:      stringPtr("200"),
			Message:   stringPtr("success"),
			RequestId: stringPtr("REQ123"),
			ResultObject: &cloudauth.Id2MetaVerifyResponseBodyResultObject{
				BizCode: stringPtr(bizCode),
			},
		},
	}
}

func mobile3Response(bizCode, subCode, ispName string) *cloudauth.Mobile3MetaDetailVerifyResponse {
	return &cloudauth.Mobile3MetaDetailVerifyResponse{
		Body: &cloudauth.Mobile3MetaDetailVerifyResponseBody{
			Code:      stringPtr("200"),
			Message:   stringPtr("success"),
			RequestId: stringPtr("REQ123"),
			ResultObject: &cloudauth.Mobile3MetaDetailVerifyResponseBodyResultObject{
				BizCode: stringPtr(bizCode),
				SubCode: stringPtr(subCode),
				IspName: stringPtr(ispName),
			},
		},
	}
}
