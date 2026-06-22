package piistore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestStoreAppendEncryptsPIIWithRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pii.jsonl")
	store, err := NewStore(path, PublicKeyTypeRSA, rsaPublicKeyPEM(t, &privateKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Append(testEntry()); err != nil {
		t.Fatal(err)
	}

	data := readFile(t, path)
	assertNoPlainPII(t, data)
	assertFileMode(t, path, 0o600)
	rec := decodeRecord(t, data)
	if rec.Envelope.KeyAlgorithm != "rsa-oaep-sha256" || rec.Envelope.DataAlgorithm != "aes-256-gcm" {
		t.Fatalf("unexpected envelope algorithms: %+v", rec.Envelope)
	}
	if _, err := base64.StdEncoding.DecodeString(rec.Envelope.EncryptedKey); err != nil {
		t.Fatalf("encrypted key is not base64: %v", err)
	}
}

func TestStoreAppendEncryptsPIIWithSM2(t *testing.T) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pii.jsonl")
	store, err := NewStore(path, PublicKeyTypeSM2, sm2PublicKeyPEM(t, &privateKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Append(testEntry()); err != nil {
		t.Fatal(err)
	}

	data := readFile(t, path)
	assertNoPlainPII(t, data)
	assertFileMode(t, path, 0o600)
	rec := decodeRecord(t, data)
	if rec.Envelope.KeyAlgorithm != "sm2-asn1" || rec.Envelope.DataAlgorithm != "aes-256-gcm" {
		t.Fatalf("unexpected envelope algorithms: %+v", rec.Envelope)
	}
	if _, err := base64.StdEncoding.DecodeString(rec.Envelope.EncryptedKey); err != nil {
		t.Fatalf("encrypted key is not base64: %v", err)
	}
}

func testEntry() Entry {
	return Entry{
		UserID:       "5",
		Username:     "alice",
		State:        "state-123",
		CertifyID:    "cert-123",
		OuterOrderNo: "order-123",
		Name:         "张三",
		IDNumber:     "11010519491231002X",
	}
}

func rsaPublicKeyPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sm2PublicKeyPEM(t *testing.T, key any) string {
	t.Helper()
	der, err := smx509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNoPlainPII(t *testing.T, data []byte) {
	t.Helper()
	for _, plain := range [][]byte{[]byte("张三"), []byte("11010519491231002X")} {
		if bytes.Contains(data, plain) {
			t.Fatalf("encrypted pii file contains plaintext %q: %s", plain, data)
		}
	}
}

func decodeRecord(t *testing.T, data []byte) record {
	t.Helper()
	var rec record
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("file mode = %v, want %v", got, want)
	}
}
