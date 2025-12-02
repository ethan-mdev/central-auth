package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"
)

func TestHS256Manager(t *testing.T) {
	manager, err := NewManager(Config{
		Algorithm: "HS256",
		Secret:    []byte("my_secret_key"),
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	testManager(t, manager)
}

func TestRS256Manager(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	manager, err := NewManager(Config{
		Algorithm:  "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      "key-1",
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	testManager(t, manager)
}

func TestRS256ValidateOnly(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	fullManager, _ := NewManager(Config{
		Algorithm:  "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	tokenString, _ := fullManager.Generate("12345", "username", "admin", time.Minute*5)

	validateOnly, _ := NewManager(Config{
		Algorithm: "RS256",
		PublicKey: &privateKey.PublicKey,
	})

	claims, err := validateOnly.Validate(tokenString)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if claims.UserID != "12345" {
		t.Errorf("Expected userID 12345, got %s", claims.UserID)
	}

	_, err = validateOnly.Generate("12345", "username", "admin", time.Minute*5)
	if err == nil {
		t.Error("Expected error when generating without private key")
	}
}

func TestJWKS(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	manager, _ := NewManager(Config{
		Algorithm:  "RS256",
		PrivateKey: privateKey,
		KeyID:      "test-key-id",
	})

	jwksBytes, err := manager.JWKS()
	if err != nil {
		t.Fatalf("Failed to generate JWKS: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(jwks.Keys))
	}

	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("Expected kty RSA, got %s", key.Kty)
	}
	if key.Kid != "test-key-id" {
		t.Errorf("Expected kid test-key-id, got %s", key.Kid)
	}
	if key.Alg != "RS256" {
		t.Errorf("Expected alg RS256, got %s", key.Alg)
	}
}

func TestHS256RejectsRS256Token(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaManager, _ := NewManager(Config{
		Algorithm:  "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	token, _ := rsaManager.Generate("12345", "username", "admin", time.Minute*5)

	hmacManager, _ := NewManager(Config{
		Algorithm: "HS256",
		Secret:    []byte("secret"),
	})
	_, err := hmacManager.Validate(token)
	if err == nil {
		t.Error("Expected error when validating RS256 token with HS256 manager")
	}
}

func TestRS256RejectsHS256Token(t *testing.T) {
	hmacManager, _ := NewManager(Config{
		Algorithm: "HS256",
		Secret:    []byte("secret"),
	})
	token, _ := hmacManager.Generate("12345", "username", "admin", time.Minute*5)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaManager, _ := NewManager(Config{
		Algorithm:  "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	_, err := rsaManager.Validate(token)
	if err == nil {
		t.Error("Expected error when validating HS256 token with RS256 manager")
	}
}

func TestInvalidConfig(t *testing.T) {
	_, err := NewManager(Config{Algorithm: "HS256"})
	if err == nil {
		t.Error("Expected error for HS256 without secret")
	}

	_, err = NewManager(Config{Algorithm: "RS256"})
	if err == nil {
		t.Error("Expected error for RS256 without keys")
	}

	_, err = NewManager(Config{Algorithm: "invalid"})
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}
}

func testManager(t *testing.T, manager *Manager) {
	t.Helper()

	userID := "12345"
	role := "admin"
	duration := time.Minute * 5

	tokenString, err := manager.Generate(userID, "username", role, duration)
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
