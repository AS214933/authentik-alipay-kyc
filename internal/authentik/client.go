package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/example/authentik-alipay-kyc/internal/config"
)

type Client struct {
	baseURL       string
	token         string
	attributeKey  string
	timeout       time.Duration
	mergeExisting bool
	httpClient    *http.Client
}

type User struct {
	ID         int64                  `json:"pk"`
	Username   string                 `json:"username"`
	Name       string                 `json:"name"`
	Email      string                 `json:"email"`
	Attributes map[string]interface{} `json:"attributes"`
}

type usersPage struct {
	Pagination struct {
		Next int `json:"next"`
	} `json:"pagination"`
	Results []User `json:"results"`
}

type KYCAttribute struct {
	Verified   bool   `json:"verified"`
	VerifiedAt string `json:"verified_at"`
	Channel    string `json:"channel"`
	IDHash     string `json:"id_hash"`
	IDLast4    string `json:"id_last4"`
	NameMasked string `json:"name_masked"`
}

type authenticatorDevice struct {
	Type          string          `json:"type"`
	MetaModelName string          `json:"meta_model_name"`
	VerboseName   string          `json:"verbose_name"`
	Confirmed     bool            `json:"confirmed"`
	PK            json.RawMessage `json:"pk"`
	PhoneNumber   string          `json:"phone_number"`
	Phone         string          `json:"phone"`
}

type SMSDevice struct {
	Bound       bool
	PhoneNumber string
}

func NewClient(cfg config.AuthentikConfig) *Client {
	return &Client{
		baseURL:       cfg.BaseURL,
		token:         cfg.Token,
		attributeKey:  cfg.AttributeKey,
		timeout:       cfg.Timeout,
		mergeExisting: cfg.MergeExisting,
		httpClient:    &http.Client{Timeout: cfg.Timeout},
	}
}

func (c *Client) GetUser(ctx context.Context, userID string) (User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v3/core/users/"+userID+"/", nil)
	if err != nil {
		return User{}, err
	}
	c.auth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return User{}, fmt.Errorf("authentik get user failed: status=%d body=%s", resp.StatusCode, safeBodySummary(body))
	}
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return User{}, err
	}
	return user, nil
}

func (c *Client) HasSMSDevice(ctx context.Context, userID string) (bool, error) {
	devices, err := c.authenticatorDevices(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, device := range devices {
		if device.Confirmed && device.isSMS() {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) SMSDevice(ctx context.Context, userID string) (SMSDevice, error) {
	devices, err := c.authenticatorDevices(ctx, userID)
	if err != nil {
		return SMSDevice{}, err
	}
	for _, device := range devices {
		if !device.Confirmed || !device.isSMS() {
			continue
		}
		phoneNumber := device.smsPhoneNumber()
		if phoneNumber == "" {
			detail, err := c.smsDeviceDetail(ctx, device.pkString())
			if err != nil {
				return SMSDevice{}, err
			}
			phoneNumber = detail.smsPhoneNumber()
		}
		return SMSDevice{Bound: true, PhoneNumber: phoneNumber}, nil
	}
	return SMSDevice{}, nil
}

func (c *Client) authenticatorDevices(ctx context.Context, userID string) ([]authenticatorDevice, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("authentik sms device lookup requires user id")
	}
	reqURL := c.baseURL + "/api/v3/authenticators/admin/all/?user=" + url.QueryEscape(userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("authentik sms device lookup failed: status=%d body=%s", resp.StatusCode, safeBodySummary(body))
	}
	return parseAuthenticatorDevices(body)
}

func (c *Client) smsDeviceDetail(ctx context.Context, pk string) (authenticatorDevice, error) {
	pk = strings.TrimSpace(pk)
	if pk == "" {
		return authenticatorDevice{}, nil
	}
	reqURL := c.baseURL + "/api/v3/authenticators/admin/sms/" + url.PathEscape(pk) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return authenticatorDevice{}, err
	}
	c.auth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return authenticatorDevice{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return authenticatorDevice{}, fmt.Errorf("authentik sms device detail failed: status=%d body=%s", resp.StatusCode, safeBodySummary(body))
	}
	var device authenticatorDevice
	if err := json.Unmarshal(body, &device); err != nil {
		return authenticatorDevice{}, err
	}
	return device, nil
}

func (c *Client) AddUserToGroup(ctx context.Context, groupUUID, userID string) error {
	groupUUID = strings.TrimSpace(groupUUID)
	userID = strings.TrimSpace(userID)
	if groupUUID == "" {
		return fmt.Errorf("authentik group sync requires group uuid")
	}
	userPK, err := strconv.ParseInt(userID, 10, 64)
	if err != nil || userPK <= 0 {
		return fmt.Errorf("authentik group sync requires numeric user id")
	}
	payload := map[string]int64{"pk": userPK}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqURL := c.baseURL + "/api/v3/core/groups/" + url.PathEscape(groupUUID) + "/add_user/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	c.auth(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("authentik add user to group failed: status=%d body=%s", resp.StatusCode, safeBodySummary(body))
	}
	return nil
}

func (c *Client) VerifiedUserIDs(ctx context.Context) ([]string, error) {
	const pageSize = 100
	page := 1
	userIDs := []string{}
	for {
		values := url.Values{}
		values.Set("page", strconv.Itoa(page))
		values.Set("page_size", strconv.Itoa(pageSize))
		reqURL := c.baseURL + "/api/v3/core/users/?" + values.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		c.auth(req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("authentik list users failed: status=%d body=%s", resp.StatusCode, safeBodySummary(body))
		}

		users, next, err := parseUsersPage(body)
		if err != nil {
			return nil, err
		}
		for _, user := range users {
			if user.ID > 0 && userKYCVerified(user, c.attributeKey) {
				userIDs = append(userIDs, strconv.FormatInt(user.ID, 10))
			}
		}
		if next <= 0 {
			break
		}
		page = next
	}
	return userIDs, nil
}

func (c *Client) MarkVerified(ctx context.Context, userID string, attr KYCAttribute) error {
	attributes := map[string]interface{}{
		c.attributeKey: attr,
	}
	if c.mergeExisting {
		user, err := c.GetUser(ctx, userID)
		if err != nil {
			return err
		}
		if user.Attributes != nil {
			attributes = user.Attributes
			attributes[c.attributeKey] = attr
		}
	}

	payload := map[string]interface{}{
		"attributes": attributes,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/api/v3/core/users/"+userID+"/", bytes.NewReader(data))
	if err != nil {
		return err
	}
	c.auth(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("authentik update user failed: status=%d body=%s", resp.StatusCode, safeBodySummary(body))
	}
	return nil
}

func parseAuthenticatorDevices(body []byte) ([]authenticatorDevice, error) {
	var page struct {
		Results []authenticatorDevice `json:"results"`
	}
	if err := json.Unmarshal(body, &page); err == nil && page.Results != nil {
		return page.Results, nil
	}
	var devices []authenticatorDevice
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, err
	}
	return devices, nil
}

func parseUsersPage(body []byte) ([]User, int, error) {
	var page usersPage
	if err := json.Unmarshal(body, &page); err == nil && page.Results != nil {
		return page.Results, page.Pagination.Next, nil
	}
	var users []User
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, 0, err
	}
	return users, 0, nil
}

func userKYCVerified(user User, attributeKey string) bool {
	attr, ok := user.Attributes[attributeKey]
	if !ok {
		return false
	}
	if typed, ok := attr.(KYCAttribute); ok {
		return typed.Verified
	}
	if typed, ok := attr.(map[string]interface{}); ok {
		verified, _ := typed["verified"].(bool)
		return verified
	}
	data, err := json.Marshal(attr)
	if err != nil {
		return false
	}
	var typed KYCAttribute
	if err := json.Unmarshal(data, &typed); err != nil {
		return false
	}
	return typed.Verified
}

func (d authenticatorDevice) isSMS() bool {
	for _, value := range []string{d.Type, d.MetaModelName, d.VerboseName} {
		value = strings.ToLower(strings.ReplaceAll(value, " ", ""))
		if strings.Contains(value, "sms") {
			return true
		}
	}
	return false
}

func (d authenticatorDevice) pkString() string {
	if len(d.PK) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(d.PK, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var number int64
	if err := json.Unmarshal(d.PK, &number); err == nil {
		return strconv.FormatInt(number, 10)
	}
	return ""
}

func (d authenticatorDevice) smsPhoneNumber() string {
	for _, value := range []string{d.PhoneNumber, d.Phone} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (c *Client) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.token))
	req.Header.Set("Accept", "application/json")
}

func safeBodySummary(body []byte) string {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return "<empty>"
	}
	return fmt.Sprintf("<redacted len=%d>", len(body))
}
