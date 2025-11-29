package tokens

import (
	"database/sql"
	"time"
)

// SQLiteRefreshRepository is a SQLite implementation of RefreshRepository.
type SQLiteRefreshRepository struct {
	db *sql.DB
}

func NewSQLiteRefreshRepository(db *sql.DB) *SQLiteRefreshRepository {
	return &SQLiteRefreshRepository{db: db}
}

// CreateTable creates the refresh_tokens table if it doesn't exist.
func (r *SQLiteRefreshRepository) CreateTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL
	)`
	_, err := r.db.Exec(query)
	return err
}

func (r *SQLiteRefreshRepository) Create(rt RefreshToken) error {
	query := `INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)`
	_, err := r.db.Exec(query, rt.Token, rt.UserID, rt.ExpiresAt)
	return err
}

func (r *SQLiteRefreshRepository) Get(token string) (*RefreshToken, error) {
	query := `SELECT token, user_id, expires_at FROM refresh_tokens WHERE token = ?`
	row := r.db.QueryRow(query, token)

	var rt RefreshToken
	err := row.Scan(&rt.Token, &rt.UserID, &rt.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *SQLiteRefreshRepository) Delete(token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = ?`
	_, err := r.db.Exec(query, token)
	return err
}

// DeleteExpired removes all expired tokens.
func (r *SQLiteRefreshRepository) DeleteExpired() error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < ?`
	_, err := r.db.Exec(query, time.Now())
	return err
}

// DeleteByUserID removes all refresh tokens for a user (useful for logout-all).
func (r *SQLiteRefreshRepository) DeleteByUserID(userID string) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = ?`
	_, err := r.db.Exec(query, userID)
	return err
}
