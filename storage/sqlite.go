package storage

import (
	"database/sql"
	"time"
)

// SQLiteUserRepository is a SQLite implementation of UserRepository.
type SQLiteUserRepository struct {
	db *sql.DB
}

func NewSQLiteUserRepository(db *sql.DB) *SQLiteUserRepository {
	return &SQLiteUserRepository{db: db}
}

// CreateTable creates the users table if it doesn't exist.
func (r *SQLiteUserRepository) CreateTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		created_at DATETIME NOT NULL
	)`
	_, err := r.db.Exec(query)
	return err
}

func (r *SQLiteUserRepository) CreateUser(user *User) error {
	if user.ID == "" {
		user.ID = generateID()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	query := `
	INSERT INTO users (id, username, email, password, role, created_at)
	VALUES (?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query, user.ID, user.Username, user.Email, user.Password, user.Role, user.CreatedAt)
	return err
}

func (r *SQLiteUserRepository) GetUserByUsername(username string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE username = ?`
	return r.scanUser(r.db.QueryRow(query, username))
}

func (r *SQLiteUserRepository) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE email = ?`
	return r.scanUser(r.db.QueryRow(query, email))
}

func (r *SQLiteUserRepository) GetUserByID(id string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE id = ?`
	return r.scanUser(r.db.QueryRow(query, id))
}

func (r *SQLiteUserRepository) UpdateUserProfile(user *User) error {
	query := `UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?`
	result, err := r.db.Exec(query, user.Username, user.Email, user.Password, user.ID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *SQLiteUserRepository) scanUser(row *sql.Row) (*User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role, &user.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}
