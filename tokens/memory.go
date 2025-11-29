package tokens

import (
	"errors"
	"sync"
	"time"
)

var ErrTokenNotFound = errors.New("token not found")

// MemoryRefreshRepository is an in-memory implementation of RefreshRepository.
type MemoryRefreshRepository struct {
	mu     sync.RWMutex
	tokens map[string]*RefreshToken
}

func NewMemoryRefreshRepository() *MemoryRefreshRepository {
	return &MemoryRefreshRepository{
		tokens: make(map[string]*RefreshToken),
	}
}

func (r *MemoryRefreshRepository) Create(rt RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tokens[rt.Token] = &rt
	return nil
}

func (r *MemoryRefreshRepository) Get(token string) (*RefreshToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rt, ok := r.tokens[token]
	if !ok {
		return nil, ErrTokenNotFound
	}
	return rt, nil
}

func (r *MemoryRefreshRepository) Delete(token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.tokens, token)
	return nil
}

// DeleteExpired removes all expired tokens. Call periodically for cleanup.
func (r *MemoryRefreshRepository) DeleteExpired() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := 0
	now := time.Now()
	for token, rt := range r.tokens {
		if now.After(rt.ExpiresAt) {
			delete(r.tokens, token)
			count++
		}
	}
	return count
}
