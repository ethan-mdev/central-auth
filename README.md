# central-auth

A reusable authentication library for Go applications. Provides JWT-based authentication, secure password hashing, and flexible storage backends.

## Features

- **JWT Management** - Generate and validate access/refresh tokens
- **Password Hashing** - Secure Argon2id hashing with configurable parameters
- **HTTP Middleware** - Drop-in authentication middleware for protected routes
- **Multiple Storage Backends** - In-memory, PostgreSQL, and SQLite implementations
- **Refresh Token Rotation** - Secure token refresh with automatic rotation

## Installation

```bash
go get github.com/ethan-mdev/central-auth
```

## Quick Start

```go
package main

import (
    "net/http"
    "time"

    authhttp "github.com/ethan-mdev/central-auth/http"
    "github.com/ethan-mdev/central-auth/jwt"
    "github.com/ethan-mdev/central-auth/middleware"
    "github.com/ethan-mdev/central-auth/password"
    "github.com/ethan-mdev/central-auth/storage"
    "github.com/ethan-mdev/central-auth/tokens"
)

func main() {
    // Initialize storage (use PostgreSQL/SQLite in production)
    users := storage.NewMemoryUserRepository()
    refreshTokens := tokens.NewMemoryRefreshRepository()

    // Initialize JWT manager
    jwtManager := jwt.NewManager([]byte("your-secret-key"))

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
    mux.Handle("POST /change-password", middleware.Auth(jwtManager, authHandler.ChangePassword()))

    // Protected route example
    mux.Handle("GET /profile", middleware.Auth(jwtManager, http.HandlerFunc(profileHandler)))

    http.ListenAndServe(":8080", mux)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    claims, _ := middleware.GetClaims(r.Context())
    // Use claims.UserID, claims.Role, etc.
}
```

## Role-Based Access Control

The `claims.Role` field lets you implement role-based route protection. Here are some common patterns:

### Flexible Role Middleware

```go
func RequireRole(roles ...string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, ok := middleware.GetClaims(r.Context())
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            for _, role := range roles {
                if claims.Role == role {
                    next.ServeHTTP(w, r)
                    return
                }
            }

            http.Error(w, "Forbidden", http.StatusForbidden)
        })
    }
}

// Usage examples:
mux.Handle("GET /admin/dashboard", middleware.Auth(jwtManager, RequireRole("admin")(dashboardHandler)))
mux.Handle("POST /articles", middleware.Auth(jwtManager, RequireRole("admin", "editor")(createArticleHandler)))
mux.Handle("GET /premium", middleware.Auth(jwtManager, RequireRole("admin", "premium", "subscriber")(premiumHandler)))
```

## Storage Backends

### In-Memory (for testing/development)

```go
users := storage.NewMemoryUserRepository()
refreshTokens := tokens.NewMemoryRefreshRepository()
```

### PostgreSQL

```go
import "database/sql"
import _ "github.com/lib/pq"

db, _ := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")

users := storage.NewPostgresUserRepository(db)
users.CreateTable()

refreshTokens := tokens.NewPostgresRefreshRepository(db)
refreshTokens.CreateTable()
```

### SQLite

```go
import "database/sql"
import _ "github.com/mattn/go-sqlite3"

db, _ := sql.Open("sqlite3", "./auth.db")

users := storage.NewSQLiteUserRepository(db)
users.CreateTable()

refreshTokens := tokens.NewSQLiteRefreshRepository(db)
refreshTokens.CreateTable()
```

## API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/register` | POST | Create new user account | No |
| `/login` | POST | Authenticate and get tokens | No |
| `/refresh` | POST | Exchange refresh token for new tokens | No |
| `/change-password` | POST | Update user password | Yes |

### Request/Response Examples

**Register**
```json
// POST /register
{
  "username": "john",
  "email": "john@example.com",
  "password": "securepassword"
}

// Response: 201 Created
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJl...",
  "expires_in": 900
}
```

**Login**
```json
// POST /login
{
  "username": "john",
  "password": "securepassword"
}

// Response: 200 OK
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJl...",
  "expires_in": 900
}
```

**Refresh Token**
```json
// POST /refresh
{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJl..."
}

// Response: 200 OK
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "bmV3IHJlZnJlc2ggdG9r...",
  "expires_in": 900
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
