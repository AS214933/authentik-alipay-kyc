package authentik

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetUserRedactsUpstreamErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"attributes":{"alipay_kyc":{"name_masked":"*三","id_last4":"002X","id_hash":"abc"}}}`, http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:    server.URL,
		token:      "token",
		httpClient: server.Client(),
	}
	_, err := client.GetUser(context.Background(), "5")
	if err == nil {
		t.Fatal("expected authentik error")
	}
	message := err.Error()
	for _, sensitive := range []string{"alipay_kyc", "*三", "002X", "id_hash"} {
		if strings.Contains(message, sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, message)
		}
	}
	if !strings.Contains(message, "<redacted len=") {
		t.Fatalf("error did not include redacted summary: %s", message)
	}
}

func TestHasSMSDeviceReturnsConfirmedSMSDevice(t *testing.T) {
	var requestedPath string
	var requestedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		requestedQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"type": "totp", "confirmed": true},
				{"type": "SMS Device", "confirmed": true},
			},
		})
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:    server.URL,
		token:      "token",
		httpClient: server.Client(),
	}
	bound, err := client.HasSMSDevice(context.Background(), "5")
	if err != nil {
		t.Fatal(err)
	}
	if !bound {
		t.Fatal("HasSMSDevice = false, want true")
	}
	if requestedPath != "/api/v3/authenticators/admin/all/" || requestedQuery != "user=5" {
		t.Fatalf("unexpected request target: path=%q query=%q", requestedPath, requestedQuery)
	}
}

func TestHasSMSDeviceIgnoresUnconfirmedSMSDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"meta_model_name": "authentik_stages_authenticator_sms.smsdevice", "confirmed": false},
			},
		})
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:    server.URL,
		token:      "token",
		httpClient: server.Client(),
	}
	bound, err := client.HasSMSDevice(context.Background(), "5")
	if err != nil {
		t.Fatal(err)
	}
	if bound {
		t.Fatal("HasSMSDevice = true, want false")
	}
}

func TestHasSMSDeviceRedactsUpstreamErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"phone":"+8613800138000","sms":"secret"}`, http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:    server.URL,
		token:      "token",
		httpClient: server.Client(),
	}
	_, err := client.HasSMSDevice(context.Background(), "5")
	if err == nil {
		t.Fatal("expected authentik error")
	}
	message := err.Error()
	for _, sensitive := range []string{"+8613800138000", "secret"} {
		if strings.Contains(message, sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, message)
		}
	}
	if !strings.Contains(message, "<redacted len=") {
		t.Fatalf("error did not include redacted summary: %s", message)
	}
}

func TestMarkVerifiedRedactsUpstreamErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"attributes":{"alipay_kyc":{"name_masked":"*三","id_last4":"002X","id_hash":"abc"}}}`, http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:      server.URL,
		token:        "token",
		attributeKey: "alipay_kyc",
		httpClient:   server.Client(),
	}
	err := client.MarkVerified(context.Background(), "5", KYCAttribute{
		Verified:   true,
		Channel:    "admin",
		IDHash:     strings.Repeat("0", 64),
		IDLast4:    "002X",
		NameMasked: "*三",
	})
	if err == nil {
		t.Fatal("expected authentik error")
	}
	message := err.Error()
	for _, sensitive := range []string{"alipay_kyc", "*三", "002X", "id_hash"} {
		if strings.Contains(message, sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, message)
		}
	}
	if !strings.Contains(message, "<redacted len=") {
		t.Fatalf("error did not include redacted summary: %s", message)
	}
}
