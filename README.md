# central-auth

A lightweight, reusable authentication library for Go applications. Provides JWT-based authentication with RS256/HS256 support, secure password hashing via Argon2id, and flexible storage backends.

## Features

- **JWT Authentication** - Generate and validate access/refresh tokens with RS256 or HS256
- **Secure Password Hashing** - Argon2id with configurable parameters
- **HTTP Handlers** - Ready-to-use registration, login, refresh, and logout endpoints
- **Auth Middleware** - Drop-in middleware for protecting routes
- **Multiple Storage Backends** - PostgreSQL, MySQL, and SQLite implementations
- **Refresh Token Rotation** - Automatic token rotation for security
- **JWKS Support** - Remote JWKS validation for microservices

## Installation

```bash
go get github.com/ethan-mdev/central-auth
```

## Quick Start

```go
package main

import (
    "database/sql"
    "net/http"
    "time"

    authhttp "github.com/ethan-mdev/central-auth/http"
    "github.com/ethan-mdev/central-auth/jwt"
    "github.com/ethan-mdev/central-auth/middleware"
    "github.com/ethan-mdev/central-auth/password"
    "github.com/ethan-mdev/central-auth/storage"
    "github.com/ethan-mdev/central-auth/tokens"
    _ "github.com/lib/pq"
)

func main() {
    // Setup database
    db, _ := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
    
    // Initialize repositories
    users := storage.NewPostgresUserRepository(db)
    users.CreateTable()
    
    refreshTokens := tokens.NewPostgresRefreshRepository(db)
    refreshTokens.CreateTable()

    // Load or generate RSA keys
    privateKey, _ := jwt.LoadPrivateKey([]byte(privateKeyPEM))
    
    // Create JWT manager
    jwtManager, _ := jwt.NewManager(jwt.Config{
        Algorithm:  "RS256",
        PrivateKey: privateKey,
        KeyID:      "key-1",
    })

    // Create auth handler
    authHandler := &authhttp.AuthHandler{
        Users:         users,
        RefreshTokens: refreshTokens,
        Hash:          password.Default(),
        JWT:           jwtManager,
        AccessExpiry:  15 * time.Minute,
        RefreshExpiry: 7 * 24 * time.Hour,
    }

    // Setup routes
    mux := http.NewServeMux()
    mux.HandleFunc("POST /register", authHandler.Register())
    mux.HandleFunc("POST /login", authHandler.Login())
    mux.HandleFunc("POST /refresh", authHandler.RefreshToken())
    mux.HandleFunc("POST /logout", authHandler.Logout())
    mux.Handle("POST /change-password", middleware.Auth(jwtManager, authHandler.ChangePassword()))

    // Protected route
    mux.Handle("GET /profile", middleware.Auth(jwtManager, http.HandlerFunc(profileHandler)))

    http.ListenAndServe(":8080", mux)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    claims, _ := middleware.GetClaims(r.Context())
    // Use claims.UserID, claims.Username, claims.Role
}
```

## Storage Backends

### PostgreSQL

```go
import _ "github.com/lib/pq"

db, _ := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
users := storage.NewPostgresUserRepository(db)
users.CreateTable()
```

### MySQL

```go
import _ "github.com/go-sql-driver/mysql"

db, _ := sql.Open("mysql", "user:pass@tcp(localhost:3306)/dbname")
users := storage.NewMySQLUserRepository(db)
users.CreateTable()
```

### SQLite

```go
import _ "modernc.org/sqlite"

db, _ := sql.Open("sqlite", "./auth.db")
users := storage.NewSQLiteUserRepository(db)
users.CreateTable()
```

> **Note:** Use `modernc.org/sqlite` for pure Go implementation, or `github.com/mattn/go-sqlite3` if you have CGO available.

## JWT Configuration

### RS256 (Recommended for production)

```go
// Generate keys or load from file
privateKey, _ := jwt.GenerateRSAKey(2048)

jwtManager, _ := jwt.NewManager(jwt.Config{
    Algorithm:  "RS256",
    PrivateKey: privateKey,
    KeyID:      "key-1",
})

// Export JWKS for other services
jwks, _ := jwtManager.JWKS()
```

### HS256 (Simpler, single service)

```go
jwtManager, _ := jwt.NewManager(jwt.Config{
    Algorithm: "HS256",
    Secret:    []byte("your-secret-key"),
})
```

## Middleware

### Basic Auth Protection

```go
mux.Handle("GET /protected", middleware.Auth(jwtManager, protectedHandler))
```

### Role-Based Access Control

```go
// Single role
mux.Handle("GET /admin", middleware.Auth(jwtManager, 
    middleware.RequireRole("admin")(adminHandler)))

// Multiple roles (allows any of them)
mux.Handle("POST /articles", middleware.Auth(jwtManager, 
    middleware.RequireRole("admin", "editor")(createArticleHandler)))

// Get user info from claims
func someHandler(w http.ResponseWriter, r *http.Request) {
    claims, _ := middleware.GetClaims(r.Context())
    // claims.UserID, claims.Username, claims.Role
}
```

## Microservices with JWKS

For distributed systems, use JWKS to validate tokens without sharing private keys:

**Auth Service:**
```go
// Expose JWKS endpoint
mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
    jwks, _ := jwtManager.JWKS()
    w.Header().Set("Content-Type", "application/json")
    w.Write(jwks)
})
```

**Other Services:**
```go
import "github.com/ethan-mdev/central-auth/middleware"

jwksAuth, _ := middleware.NewJWKSAuth(
    context.Background(),
    "http://auth-service:8080/.well-known/jwks.json",
    15*time.Minute, // refresh interval
)

mux.Handle("GET /api/data", jwksAuth.Auth(dataHandler))
```

## Extending the User Schema

To add custom fields (e.g., `profile_image`, `bio`), skip `CreateTable()` and manage your own schema:

**Custom Migration:**
```sql
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    -- Custom fields
    profile_image TEXT DEFAULT NULL,
    bio TEXT DEFAULT NULL
);
```

**Extended Repository:**
```go
type ExtendedUserRepository struct {
    storage.UserRepository
    db *sql.DB
}

func NewExtendedUserRepository(repo storage.UserRepository, db *sql.DB) *ExtendedUserRepository {
    return &ExtendedUserRepository{
        UserRepository: repo,
        db:             db,
    }
}

func (r *ExtendedUserRepository) GetUserWithProfile(userID string) (map[string]interface{}, error) {
    var id, username, email, role string
    var profileImage sql.NullString
    
    err := r.db.QueryRow(`
        SELECT id, username, email, role, profile_image 
        FROM users WHERE id = $1
    `, userID).Scan(&id, &username, &email, &role, &profileImage)
    
    if err != nil {
        return nil, err
    }
    
    return map[string]interface{}{
        "id":            id,
        "username":      username,
        "email":         email,
        "role":          role,
        "profile_image": profileImage.String,
    }, nil
}

func (r *ExtendedUserRepository) UpdateProfileImage(userID, image string) error {
    _, err := r.db.Exec("UPDATE users SET profile_image = $1 WHERE id = $2", image, userID)
    return err
}
```

**Usage:**
```go
// Initialize base repository (don't call CreateTable)
baseUsers := storage.NewPostgresUserRepository(db)

// Wrap with extended functionality
users := NewExtendedUserRepository(baseUsers, db)

// Use in auth handler
authHandler := &authhttp.AuthHandler{
    Users: users, // ExtendedUserRepository satisfies UserRepository interface
    // ...
}
```

This pattern keeps central-auth's core simple while allowing full customization.

## API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/register` | POST | Create new user | No |
| `/login` | POST | Authenticate user | No |
| `/refresh` | POST | Refresh access token | No |
| `/logout` | POST | Invalidate refresh token | No |
| `/change-password` | POST | Change user password | Yes |

### Request/Response Examples

**Register:**
```json
POST /register
{
  "username": "john",
  "email": "john@example.com",
  "password": "securepassword"
}

Response: 201 Created
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "random-base64-string",
  "expires_in": 900
}
```

**Login:**
```json
POST /login
{
  "username": "john",
  "password": "securepassword"
}

Response: 200 OK
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "random-base64-string",
  "expires_in": 900
}
```

## Password Hashing

Uses Argon2id with configurable parameters:

```go
hasher := password.Default()

// Hash password
hash, _ := hasher.Hash("mypassword")

// Verify password
valid := hasher.Verify("mypassword", hash) // true
```

Custom parameters:
```go
hasher := &password.Hasher{
    Memory:      128 * 1024, // 128 MB
    Iterations:  4,
    SaltLength:  16,
    KeyLength:   32,
    Parallelism: 4,
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
