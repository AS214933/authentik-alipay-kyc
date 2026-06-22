package alipay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCanonicalizeSkipsSignOnly(t *testing.T) {
	params := url.Values{}
	params.Set("method", "alipay.user.certify.open.query")
	params.Set("app_id", "2021000000000000")
	params.Set("sign_type", "RSA2")
	params.Set("sign", "ignored")
	params.Set("empty", "")
	params.Set("biz_content", `{"certify_id":"abc"}`)

	got := canonicalize(params)
	want := `app_id=2021000000000000&biz_content={"certify_id":"abc"}&method=alipay.user.certify.open.query&sign_type=RSA2`
	if got != want {
		t.Fatalf("canonicalize() = %q, want %q", got, want)
	}
}

func TestCertifyAppURL(t *testing.T) {
	certifyURL := "https://openapi.alipay.com/gateway.do?method=alipay.user.certify.open.certify&biz_content=%7B%22certify_id%22%3A%22abc%22%7D"
	got := CertifyAppURL(certifyURL)
	want := "alipays://platformapi/startapp?appId=20000067&url=https%3A%2F%2Fopenapi.alipay.com%2Fgateway.do%3Fmethod%3Dalipay.user.certify.open.certify%26biz_content%3D%257B%2522certify_id%2522%253A%2522abc%2522%257D"
	if got != want {
		t.Fatalf("CertifyAppURL() = %q, want %q", got, want)
	}
}

func TestQueryResponseIgnoresStringMaterialInfo(t *testing.T) {
	body := []byte(`{
		"code": "10000",
		"msg": "Success",
		"passed": "T",
		"identity_info": "{}",
		"material_info": "{}"
	}`)
	var response QueryResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("unmarshal query response: %v", err)
	}
	if response.Passed != "T" {
		t.Fatalf("passed = %q, want T", response.Passed)
	}
}

func TestCallQueryResponseIgnoresStringMaterialInfo(t *testing.T) {
	client := testClient(t, `{
		"alipay_user_certify_open_query_response": {
			"code": "10000",
			"msg": "Success",
			"passed": "T",
			"identity_info": "{}",
			"material_info": "{}"
		}
	}`)

	var response QueryResponse
	if err := client.call(context.Background(), MethodQuery, map[string]string{"certify_id": "abc"}, &response); err != nil {
		t.Fatalf("call query: %v", err)
	}
	if response.Passed != "T" {
		t.Fatalf("passed = %q, want T", response.Passed)
	}
}

func TestCallRedactsSensitiveUpstreamError(t *testing.T) {
	client := testClient(t, `{
		"alipay_user_certify_open_query_response": {
			"code": "40002",
			"msg": "Invalid Arguments",
			"sub_code": "isv.invalid-signature",
			"sub_msg": "验签字符串 cert_name=张三&cert_no=11010519491231002X"
		}
	}`)

	var response QueryResponse
	err := client.call(context.Background(), MethodQuery, map[string]string{"certify_id": "abc"}, &response)
	if err == nil {
		t.Fatal("expected alipay error")
	}
	message := err.Error()
	for _, sensitive := range []string{"张三", "11010519491231002X", "cert_no", "sub_msg"} {
		if strings.Contains(message, sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, message)
		}
	}
	if !strings.Contains(message, "code=40002") || !strings.Contains(message, "sub_code=isv.invalid-signature") {
		t.Fatalf("error lost useful codes: %s", message)
	}
}

func TestCallRedactsUnexpectedHTTPBody(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "张三 11010519491231002X", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	client := &Client{
		gatewayURL: server.URL,
		appID:      "2021000000000000",
		privateKey: privateKey,
		httpClient: server.Client(),
	}

	var response QueryResponse
	err = client.call(context.Background(), MethodQuery, map[string]string{"certify_id": "abc"}, &response)
	if err == nil {
		t.Fatal("expected http error")
	}
	message := err.Error()
	for _, sensitive := range []string{"张三", "11010519491231002X"} {
		if strings.Contains(message, sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, message)
		}
	}
	if !strings.Contains(message, "<redacted len=") {
		t.Fatalf("error did not include redacted summary: %s", message)
	}
}

func testClient(t *testing.T, responseBody string) *Client {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("method") != MethodQuery {
			t.Fatalf("method param = %q, want %q", r.Form.Get("method"), MethodQuery)
		}
		if r.Form.Get("biz_content") != `{"certify_id":"abc"}` {
			t.Fatalf("biz_content = %q", r.Form.Get("biz_content"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(server.Close)

	return &Client{
		gatewayURL: server.URL,
		appID:      "2021000000000000",
		privateKey: privateKey,
		httpClient: server.Client(),
	}
}
