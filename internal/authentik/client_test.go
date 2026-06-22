package authentik

import (
	"context"
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
