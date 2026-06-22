package alipay

import (
	"net/url"
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
