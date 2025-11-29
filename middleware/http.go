package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/ethan-mdev/central-auth/jwt"
)

type contextKey string

const claimsKey contextKey = "claims"

func Auth(jm *jwt.Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(auth, "Bearer ")
		claims, err := jm.Validate(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaims(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*jwt.Claims)
	return claims, ok
}
