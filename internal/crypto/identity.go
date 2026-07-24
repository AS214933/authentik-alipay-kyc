package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
)

const idChecksumMap = "10X98765432"

var idChecksumWeights = [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

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

func ValidIDNumber(value string) bool {
	normalized := NormalizeIDNumber(value)
	switch len(normalized) {
	case 15:
		return validIDNumberDate("19" + normalized[6:12])
	case 18:
		if !allDigits(normalized[:17]) {
			return false
		}
		if !validIDNumberDate(normalized[6:14]) {
			return false
		}
		sum := 0
		for i, weight := range idChecksumWeights {
			sum += int(normalized[i]-'0') * weight
		}
		return normalized[17] == idChecksumMap[sum%11]
	default:
		return false
	}
}

func validIDNumberDate(value string) bool {
	if len(value) != 8 || !allDigits(value) {
		return false
	}
	parsed, err := time.Parse("20060102", value)
	if err != nil {
		return false
	}
	return parsed.Format("20060102") == value
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
