package piistore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

const (
	PublicKeyTypeRSA = "rsa"
	PublicKeyTypeSM2 = "sm2"
)

type Store struct {
	mu        sync.Mutex
	dir       string
	encrypter keyEncrypter
	random    io.Reader
}

type Entry struct {
	UserID       string `json:"user_id"`
	Username     string `json:"username,omitempty"`
	State        string `json:"state"`
	CertifyID    string `json:"certify_id"`
	OuterOrderNo string `json:"outer_order_no"`
	IDHash       string `json:"id_hash"`
	Name         string `json:"name"`
	IDNumber     string `json:"id_number"`
}

type record struct {
	Version      int               `json:"version"`
	CreatedAt    string            `json:"created_at"`
	UserID       string            `json:"user_id"`
	Username     string            `json:"username,omitempty"`
	State        string            `json:"state"`
	CertifyID    string            `json:"certify_id"`
	OuterOrderNo string            `json:"outer_order_no"`
	IDHash       string            `json:"id_hash"`
	Envelope     encryptedEnvelope `json:"envelope"`
}

type encryptedEnvelope struct {
	KeyAlgorithm  string `json:"key_algorithm"`
	DataAlgorithm string `json:"data_algorithm"`
	EncryptedKey  string `json:"encrypted_key"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

type plaintext struct {
	Name     string `json:"name"`
	IDNumber string `json:"id_number"`
}

type keyEncrypter interface {
	Algorithm() string
	EncryptKey(random io.Reader, key []byte) ([]byte, error)
}

type rsaEncrypter struct {
	key *rsa.PublicKey
}

func (e rsaEncrypter) Algorithm() string {
	return "rsa-oaep-sha256"
}

func (e rsaEncrypter) EncryptKey(random io.Reader, key []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), random, e.key, key, nil)
}

type sm2Encrypter struct {
	key *ecdsa.PublicKey
}

func (e sm2Encrypter) Algorithm() string {
	return "sm2-asn1"
}

func (e sm2Encrypter) EncryptKey(random io.Reader, key []byte) ([]byte, error) {
	return sm2.EncryptASN1(random, e.key, key)
}

func NewStore(dir, publicKeyType, publicKeyPEM string) (*Store, error) {
	return newStore(dir, publicKeyType, publicKeyPEM, rand.Reader)
}

func newStore(dir, publicKeyType, publicKeyPEM string, random io.Reader) (*Store, error) {
	if dir == "" {
		return nil, errors.New("pii directory is required")
	}
	encrypter, err := parseEncrypter(publicKeyType, publicKeyPEM)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create pii directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod pii directory: %w", err)
	}
	return &Store{
		dir:       dir,
		encrypter: encrypter,
		random:    random,
	}, nil
}

func (s *Store) Append(entry Entry) error {
	if strings.TrimSpace(entry.UserID) == "" || strings.TrimSpace(entry.State) == "" || strings.TrimSpace(entry.CertifyID) == "" || strings.TrimSpace(entry.IDHash) == "" || strings.TrimSpace(entry.Name) == "" || strings.TrimSpace(entry.IDNumber) == "" {
		return errors.New("pii entry is missing required fields")
	}
	if !validIDHash(entry.IDHash) {
		return errors.New("pii id_hash must be a 64 character lowercase hex string")
	}
	plain, err := json.Marshal(plaintext{
		Name:     entry.Name,
		IDNumber: entry.IDNumber,
	})
	if err != nil {
		return fmt.Errorf("encode pii plaintext: %w", err)
	}
	envelope, err := s.encrypt(plain)
	if err != nil {
		return err
	}
	rec := record{
		Version:      1,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		UserID:       entry.UserID,
		Username:     entry.Username,
		State:        entry.State,
		CertifyID:    entry.CertifyID,
		OuterOrderNo: entry.OuterOrderNo,
		IDHash:       entry.IDHash,
		Envelope:     envelope,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.pathForHash(entry.IDHash)
	records, err := readRecords(path)
	if err != nil {
		return err
	}
	records = append(records, rec)
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pii records: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(path, data); err != nil {
		return err
	}
	return nil
}

func (s *Store) pathForHash(idHash string) string {
	return filepath.Join(s.dir, idHash)
}

func readRecords(path string) ([]record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read pii file: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode pii file: %w", err)
	}
	return records, nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open pii temp file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write pii temp file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod pii temp file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pii temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace pii file: %w", err)
	}
	return nil
}

func validIDHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func (s *Store) encrypt(plain []byte) (encryptedEnvelope, error) {
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(s.random, dataKey); err != nil {
		return encryptedEnvelope{}, fmt.Errorf("generate pii data key: %w", err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return encryptedEnvelope{}, fmt.Errorf("create pii cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedEnvelope{}, fmt.Errorf("create pii aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return encryptedEnvelope{}, fmt.Errorf("generate pii nonce: %w", err)
	}
	encryptedKey, err := s.encrypter.EncryptKey(s.random, dataKey)
	if err != nil {
		return encryptedEnvelope{}, fmt.Errorf("encrypt pii data key: %w", err)
	}
	return encryptedEnvelope{
		KeyAlgorithm:  s.encrypter.Algorithm(),
		DataAlgorithm: "aes-256-gcm",
		EncryptedKey:  base64.StdEncoding.EncodeToString(encryptedKey),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil)),
	}, nil
}

func parseEncrypter(publicKeyType, rawPEM string) (keyEncrypter, error) {
	block, err := decodePEM(rawPEM)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(publicKeyType)) {
	case "", PublicKeyTypeRSA:
		key, err := parseRSAPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaEncrypter{key: key}, nil
	case PublicKeyTypeSM2:
		key, err := smx509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse sm2 public key: %w", err)
		}
		if !sm2.IsSM2PublicKey(key) {
			return nil, errors.New("configured pii public key is not an SM2 public key")
		}
		sm2Key, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("configured pii public key is not an ECDSA public key")
		}
		return sm2Encrypter{key: sm2Key}, nil
	default:
		return nil, fmt.Errorf("unsupported pii public key type %q", publicKeyType)
	}
}

func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("configured pii public key is not an RSA public key")
	}
	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse rsa public key: %w", err)
	}
	return key, nil
}

func decodePEM(raw string) (*pem.Block, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("pii public key is required")
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("pii public key must be PEM encoded")
	}
	return block, nil
}
