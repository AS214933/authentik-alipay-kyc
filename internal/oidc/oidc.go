package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/example/authentik-alipay-kyc/internal/config"
	"golang.org/x/oauth2"
)

type Client struct {
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauth2      oauth2.Config
	userIDClaim string
}

type Claims struct {
	Subject           string                 `json:"sub"`
	PreferredUsername string                 `json:"preferred_username"`
	Email             string                 `json:"email"`
	Name              string                 `json:"name"`
	Nickname          string                 `json:"nickname"`
	UID               string                 `json:"uid"`
	PK                string                 `json:"ak_proxy_user_id"`
	Raw               map[string]interface{} `json:"-"`
}

func New(ctx context.Context, cfg config.OIDCConfig) (*Client, error) {
	provider, err := discoverProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover issuer: %w", err)
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}
	return &Client{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		}),
		oauth2:      oauthCfg,
		userIDClaim: cfg.UserIDClaim,
	}, nil
}

func discoverProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err == nil {
		return provider, nil
	}
	if strings.HasSuffix(issuer, "/") {
		return nil, err
	}
	retryIssuer := issuer + "/"
	provider, retryErr := oidc.NewProvider(ctx, retryIssuer)
	if retryErr != nil {
		return nil, err
	}
	return provider, nil
}

func (c *Client) AuthCodeURL(state, nonce string) string {
	return c.oauth2.AuthCodeURL(state, oidc.Nonce(nonce))
}

func (c *Client) Exchange(ctx context.Context, code, nonce string) (Claims, error) {
	token, err := c.oauth2.Exchange(ctx, code)
	if err != nil {
		return Claims{}, fmt.Errorf("exchange code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return Claims{}, fmt.Errorf("oidc response missing id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Claims{}, fmt.Errorf("invalid oidc nonce")
	}
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return Claims{}, fmt.Errorf("decode id token claims: %w", err)
	}
	if err := idToken.Claims(&claims.Raw); err != nil {
		return Claims{}, fmt.Errorf("decode raw id token claims: %w", err)
	}
	if claims.Subject == "" {
		return Claims{}, fmt.Errorf("id token subject is empty")
	}
	return claims, nil
}

func (c Claims) ClaimString(name string) string {
	if name == "" {
		return ""
	}
	switch name {
	case "sub":
		return c.Subject
	case "preferred_username":
		return c.PreferredUsername
	case "email":
		return c.Email
	case "name":
		return c.Name
	case "nickname":
		return c.Nickname
	case "uid":
		return c.UID
	case "ak_proxy_user_id":
		return c.PK
	}
	value, ok := c.Raw[name]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case jsonNumber:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

type jsonNumber interface {
	String() string
}

func RandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
