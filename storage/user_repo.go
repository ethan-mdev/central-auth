package storage

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system.
type User struct {
	ID        string
	Username  string
	Email     string
	Password  string
	Role      string
	CreatedAt time.Time
}

// UserRepository defines the interface for user data operations.
type UserRepository interface {
	// CreateUser adds a new user to the repository.
	CreateUser(user *User) error
	// GetUserByUsername retrieves a user by their username.
	GetUserByUsername(username string) (*User, error)
	// GetUserByEmail retrieves a user by their email.
	GetUserByEmail(email string) (*User, error)
	// GetUserByID retrieves a user by their ID.
	GetUserByID(id string) (*User, error)
	// UpdateUserProfile updates an existing user's information.
	UpdateUserProfile(user *User) error
}

// ErrUserNotFound is returned when a user is not found.
var ErrUserNotFound = errors.New("user not found")

// generateID generates a new UUID for a user.
func generateID() string {
	return uuid.New().String()
}
