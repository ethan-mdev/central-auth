package jwt

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		// Derive public key from private key if not provided
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
	claims := &Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	var token *jwt.Token
	switch m.algorithm {
	case "HS256":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return token.SignedString(m.secret)
	case "RS256":
		if m.privateKey == nil {
			return "", errors.New("private key is required for token generation")
		}
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if m.keyID != "" {
			token.Header["kid"] = m.keyID
		}
		return token.SignedString(m.privateKey)
	}

	return "", errors.New("unsupported algorithm")
}

// Validate parses and validates a JWT token, returning the claims.
func (m *Manager) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		switch m.algorithm {
		case "HS256":
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return m.secret, nil
		case "RS256":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New("unexpected signing method")
			}
			if m.publicKey == nil {
				return nil, errors.New("public key is required for token validation")
			}
			return m.publicKey, nil
		}
		return nil, errors.New("unsupported algorithm")
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return claims, nil
}
