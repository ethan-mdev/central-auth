package storage

import "time"

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
	// UpdateUser updates an existing user's information.
	UpdateUser(user *User) error
}
