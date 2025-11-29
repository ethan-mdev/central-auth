package storage

import (
	"database/sql"
	"time"
)

// PostgresUserRepository is a PostgreSQL implementation of UserRepository.
type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

// CreateTable creates the users table if it doesn't exist.
func (r *PostgresUserRepository) CreateTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role VARCHAR(50) NOT NULL DEFAULT 'user',
		created_at TIMESTAMP NOT NULL DEFAULT NOW()
	)`
	_, err := r.db.Exec(query)
	return err
}

func (r *PostgresUserRepository) CreateUser(user *User) error {
	if user.ID == "" {
		user.ID = generateID()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	query := `
	INSERT INTO users (id, username, email, password, role, created_at)
	VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.db.Exec(query, user.ID, user.Username, user.Email, user.Password, user.Role, user.CreatedAt)
	return err
}

func (r *PostgresUserRepository) GetUserByUsername(username string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE username = $1`
	return r.scanUser(r.db.QueryRow(query, username))
}

func (r *PostgresUserRepository) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE email = $1`
	return r.scanUser(r.db.QueryRow(query, email))
}

func (r *PostgresUserRepository) GetUserByID(id string) (*User, error) {
	query := `SELECT id, username, email, password, role, created_at FROM users WHERE id = $1`
	return r.scanUser(r.db.QueryRow(query, id))
}

func (r *PostgresUserRepository) UpdateUser(user *User) error {
	query := `UPDATE users SET username = $1, email = $2, password = $3, role = $4 WHERE id = $5`
	result, err := r.db.Exec(query, user.Username, user.Email, user.Password, user.Role, user.ID)
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

func (r *PostgresUserRepository) scanUser(row *sql.Row) (*User, error) {
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
