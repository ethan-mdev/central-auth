package jwt

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Config holds the configuration for creating a JWT Manager.
type Config struct {
	Algorithm  string          // "HS256" or "RS256"
	Secret     []byte          // Required for HS256
	PrivateKey *rsa.PrivateKey // Required for RS256 signing
	PublicKey  *rsa.PublicKey  // Required for RS256 validation
	KeyID      string          // Optional: used in JWKS for key rotation
}

// Manager handles JWT token generation and validation.
type Manager struct {
	algorithm  string
	secret     []byte
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewManager creates a new JWT Manager with the given configuration.
func NewManager(cfg Config) (*Manager, error) {
	switch cfg.Algorithm {
	case "HS256":
		if len(cfg.Secret) == 0 {
			return nil, errors.New("secret is required for HS256")
		}
	case "RS256":
		if cfg.PrivateKey == nil && cfg.PublicKey == nil {
			return nil, errors.New("at least one of PrivateKey or PublicKey is required for RS256")
		}
		if cfg.PublicKey == nil && cfg.PrivateKey != nil {
			cfg.PublicKey = &cfg.PrivateKey.PublicKey
		}
	default:
		return nil, errors.New("unsupported algorithm: " + cfg.Algorithm)
	}

	return &Manager{
		algorithm:  cfg.Algorithm,
		secret:     cfg.Secret,
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PublicKey,
		keyID:      cfg.KeyID,
	}, nil
}

// Generate creates a new signed JWT token.
func (m *Manager) Generate(userID string, username string, role string, duration time.Duration) (string, error) {
	now := time.Now()

	token, err := jwt.NewBuilder().
		Subject(userID).
		Claim("username", username).
		Claim("role", role).
		IssuedAt(now).
		Expiration(now.Add(duration)).
		Build()
	if err != nil {
		return "", err
	}

	var signedToken []byte
	switch m.algorithm {
	case "HS256":
		signedToken, err = jwt.Sign(token, jwt.WithKey(jwa.HS256(), m.secret))
	case "RS256":
		if m.privateKey == nil {
			return "", errors.New("private key is required for token generation")
		}
		if m.keyID != "" {
			hdrs := jws.NewHeaders()
			hdrs.Set("kid", m.keyID)
			signedToken, err = jwt.Sign(token, jwt.WithKey(jwa.RS256(), m.privateKey, jws.WithProtectedHeaders(hdrs)))
		} else {
			signedToken, err = jwt.Sign(token, jwt.WithKey(jwa.RS256(), m.privateKey))
		}
	default:
		return "", errors.New("unsupported algorithm")
	}

	if err != nil {
		return "", err
	}
	return string(signedToken), nil
}

// Validate parses and validates a JWT token, returning the claims.
func (m *Manager) Validate(tokenString string) (*Claims, error) {
	var token jwt.Token
	var err error

	switch m.algorithm {
	case "HS256":
		token, err = jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.HS256(), m.secret))
	case "RS256":
		if m.publicKey == nil {
			return nil, errors.New("public key is required for token validation")
		}
		token, err = jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.RS256(), m.publicKey))
	default:
		return nil, errors.New("unsupported algorithm")
	}

	if err != nil {
		return nil, err
	}

	sub, _ := token.Subject()
	return &Claims{
		UserID:   sub,
		Username: getStringClaim(token, "username"),
		Role:     getStringClaim(token, "role"),
	}, nil
}

func getStringClaim(token jwt.Token, key string) string {
	var val string
	if err := token.Get(key, &val); err != nil {
		return ""
	}
	return val
}
