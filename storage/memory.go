package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

// MemoryUserRepository is an in-memory implementation of UserRepository.
// Useful for testing and development.
type MemoryUserRepository struct {
	mu    sync.RWMutex
	users map[string]*User // keyed by ID
}

func NewMemoryUserRepository() *MemoryUserRepository {
	return &MemoryUserRepository{
		users: make(map[string]*User),
	}
}

func (r *MemoryUserRepository) CreateUser(user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicates
	for _, u := range r.users {
		if u.Username == user.Username || u.Email == user.Email {
			return ErrUserAlreadyExists
		}
	}

	// Generate ID if not set
	if user.ID == "" {
		user.ID = generateID()
	}

	r.users[user.ID] = user
	return nil
}

func (r *MemoryUserRepository) GetUserByUsername(username string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

func (r *MemoryUserRepository) GetUserByEmail(email string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

func (r *MemoryUserRepository) GetUserByID(id string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (r *MemoryUserRepository) UpdateUser(user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.users[user.ID]; !ok {
		return ErrUserNotFound
	}

	r.users[user.ID] = user
	return nil
}

func generateID() string {
	// Simple ID generation - in production you'd use UUID
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
