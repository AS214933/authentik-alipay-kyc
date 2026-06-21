package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

func NormalizeIDNumber(value string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(value)) {
		if unicode.IsDigit(r) || r == 'X' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func IDHash(idNumber, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(NormalizeIDNumber(idNumber)))
	return hex.EncodeToString(mac.Sum(nil))
}

func Last4(value string) string {
	normalized := NormalizeIDNumber(value)
	if len(normalized) <= 4 {
		return normalized
	}
	return normalized[len(normalized)-4:]
}

func MaskChineseName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	runes := []rune(name)
	last := runes[len(runes)-1]
	return strings.Repeat("*", len(runes)-1) + string(last)
}
