package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

type KYCAttribute struct {
	Verified   bool   `json:"verified"`
	VerifiedAt string `json:"verified_at"`
	Channel    string `json:"channel"`
	IDHash     string `json:"id_hash"`
	IDLast4    string `json:"id_last4"`
	NameMasked string `json:"name_masked"`
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
