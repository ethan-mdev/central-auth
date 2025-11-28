package password

import (
	"testing"
)

func TestHasher_Verify(t *testing.T) {
	hasher := Default()
	password := "my_secure_password"
	hashedPassword, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hashing failed: %v", err)
	}
	if !hasher.Verify(password, hashedPassword) {
		t.Fatalf("Password verification failed")
	}
}
