package tokens

import "time"

// RefreshToken represents a refresh token.
type RefreshToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
}

// RefreshRepository defines the interface for refresh token data operations.
type RefreshRepository interface {
	Create(rt RefreshToken) error
	Get(id string) (*RefreshToken, error)
	Delete(id string) error
}
