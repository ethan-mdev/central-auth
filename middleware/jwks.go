package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ethan-mdev/central-auth/jwt"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

// JWKSAuth verifies tokens using a remote JWKS endpoint
type JWKSAuth struct {
	cache   *jwk.Cache
	jwksURL string
}

// NewJWKSAuth creates a new JWKS-based authenticator
func NewJWKSAuth(ctx context.Context, jwksURL string, refreshInterval time.Duration) (*JWKSAuth, error) {
	client := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, err
	}

	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(refreshInterval)); err != nil {
		return nil, err
	}

	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, err
	}

	return &JWKSAuth{cache: cache, jwksURL: jwksURL}, nil
}

// Auth validates the JWT and adds claims to context
func (j *JWKSAuth) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		keySet, err := j.cache.Lookup(r.Context(), j.jwksURL)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		token, err := jwxjwt.Parse(
			[]byte(strings.TrimPrefix(auth, "Bearer ")),
			jwxjwt.WithKeySet(keySet),
		)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		sub, _ := token.Subject()
		claims := &jwt.Claims{
			UserID:   sub,
			Username: getStringClaim(token, "username"),
			Role:     getStringClaim(token, "role"),
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getStringClaim(token jwxjwt.Token, key string) string {
	var val string
	if err := token.Get(key, &val); err != nil {
		return ""
	}
	return val
}
