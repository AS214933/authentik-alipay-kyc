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

func TestAddUserToGroupPostsUserPK(t *testing.T) {
	var requestedPath string
	var requestedBody map[string]int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&requestedBody); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:    server.URL,
		token:      "token",
		httpClient: server.Client(),
	}
	if err := client.AddUserToGroup(context.Background(), "group-uuid", "5"); err != nil {
		t.Fatal(err)
	}
	if requestedPath != "/api/v3/core/groups/group-uuid/add_user/" {
		t.Fatalf("path = %q", requestedPath)
	}
	if requestedBody["pk"] != 5 {
		t.Fatalf("body = %+v, want pk=5", requestedBody)
	}
}

func TestAddUserToGroupRedactsUpstreamErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"username":"alice","phone":"+8613800138000"}`, http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:    server.URL,
		token:      "token",
		httpClient: server.Client(),
	}
	err := client.AddUserToGroup(context.Background(), "group-uuid", "5")
	if err == nil {
		t.Fatal("expected authentik error")
	}
	message := err.Error()
	for _, sensitive := range []string{"alice", "+8613800138000"} {
		if strings.Contains(message, sensitive) {
			t.Fatalf("error leaked %q: %s", sensitive, message)
		}
	}
	if !strings.Contains(message, "<redacted len=") {
		t.Fatalf("error did not include redacted summary: %s", message)
	}
}

func TestVerifiedUserIDsReturnsUsersWithVerifiedKYCAttribute(t *testing.T) {
	requestedQueries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedQueries = append(requestedQueries, r.URL.RawQuery)
		switch r.URL.Query().Get("page") {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"pagination": map[string]interface{}{"next": 2},
				"results": []map[string]interface{}{
					{"pk": 5, "attributes": map[string]interface{}{"alipay_kyc": map[string]interface{}{"verified": true}}},
					{"pk": 6, "attributes": map[string]interface{}{"alipay_kyc": map[string]interface{}{"verified": false}}},
				},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"pagination": map[string]interface{}{"next": 0},
				"results": []map[string]interface{}{
					{"pk": 7, "attributes": map[string]interface{}{"other": map[string]interface{}{"verified": true}}},
					{"pk": 8, "attributes": map[string]interface{}{"alipay_kyc": map[string]interface{}{"verified": true}}},
				},
			})
		default:
			t.Fatalf("unexpected page query: %s", r.URL.RawQuery)
		}
	}))
	t.Cleanup(server.Close)

	client := &Client{
		baseURL:      server.URL,
		token:        "token",
		attributeKey: "alipay_kyc",
		httpClient:   server.Client(),
	}
	userIDs, err := client.VerifiedUserIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(userIDs, ",") != "5,8" {
		t.Fatalf("userIDs = %+v, want 5,8", userIDs)
	}
	if strings.Join(requestedQueries, "|") != "page=1&page_size=100|page=2&page_size=100" {
		t.Fatalf("queries = %+v", requestedQueries)
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
