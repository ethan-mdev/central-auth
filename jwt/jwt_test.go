package jwt

import (
	"testing"
	"time"
)

func TestJWTManager(t *testing.T) {
	signingKey := []byte("my_secret_key")
	manager := NewManager(signingKey)
	userID := "12345"
	role := "admin"
	duration := time.Minute * 5
	tokenString, err := manager.Generate(userID, role, duration)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	claims, err := manager.Validate(tokenString)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Expected userID %s, got %s", userID, claims.UserID)
	}
	if claims.Role != role {
		t.Errorf("Expected role %s, got %s", role, claims.Role)
	}
}
