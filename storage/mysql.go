package storage

import (
	"database/sql"
	"time"
)

// MySQLUserRepository is a MySQL implementation of UserRepository.
type MySQLUserRepository struct {
	db *sql.DB
}

func NewMySQLUserRepository(db *sql.DB) *MySQLUserRepository {
	return &MySQLUserRepository{db: db}
}

// CreateTable creates the users table if it doesn't exist.
func (r *MySQLUserRepository) CreateTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role VARCHAR(50) NOT NULL DEFAULT 'user',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`
	_, err := r.db.Exec(query)
	return err
}

func (r *MySQLUserRepository) CreateUser(user *User) error {
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

func (r *MySQLUserRepository) GetUserByUsername(username string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE username = ?`
	return r.scanUser(r.db.QueryRow(query, username))
}

func (r *MySQLUserRepository) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE email = ?`
	return r.scanUser(r.db.QueryRow(query, email))
}

func (r *MySQLUserRepository) GetUserByID(id string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE id = ?`
	return r.scanUser(r.db.QueryRow(query, id))
}

func (r *MySQLUserRepository) UpdateUserProfile(user *User) error {
	query := `UPDATE users SET username=?, email=?, password=? 
        WHERE id=?`
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

func (r *MySQLUserRepository) scanUser(row *sql.Row) (*User, error) {
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
