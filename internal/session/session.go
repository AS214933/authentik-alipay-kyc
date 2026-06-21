package session

import (
	"net/http"

	"github.com/example/authentik-alipay-kyc/internal/config"
	"github.com/gorilla/sessions"
)

const (
	UserIDKey        = "user_id"
	UsernameKey      = "username"
	EmailKey         = "email"
	DisplayNameKey   = "display_name"
	OIDCStateKey     = "oidc_state"
	OIDCNonceKey     = "oidc_nonce"
	KYCStateKey      = "kyc_state"
	CertifyIDKey     = "certify_id"
	PendingNameKey   = "pending_name"
	PendingIDHashKey = "pending_id_hash"
	PendingLast4Key  = "pending_last4"
)

type Store struct {
	cookie *sessions.CookieStore
	name   string
}

func New(cfg config.SessionConfig) *Store {
	store := sessions.NewCookieStore(cfg.KeyPairs...)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   cfg.MaxAge,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	}
	return &Store{cookie: store, name: cfg.Name}
}

func (s *Store) Get(r *http.Request) (*sessions.Session, error) {
	return s.cookie.Get(r, s.name)
}

func (s *Store) Save(r *http.Request, w http.ResponseWriter, values map[interface{}]interface{}) error {
	sess, err := s.Get(r)
	if err != nil {
		return err
	}
	for key, value := range values {
		if value == nil {
			delete(sess.Values, key)
			continue
		}
		sess.Values[key] = value
	}
	return sess.Save(r, w)
}

func (s *Store) Clear(r *http.Request, w http.ResponseWriter) error {
	sess, err := s.Get(r)
	if err != nil {
		return err
	}
	sess.Options.MaxAge = -1
	return sess.Save(r, w)
}
