package http

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ethan-mdev/central-auth/jwt"
	"github.com/ethan-mdev/central-auth/middleware"
	"github.com/ethan-mdev/central-auth/password"
	"github.com/ethan-mdev/central-auth/storage"
	"github.com/ethan-mdev/central-auth/tokens"
)

type AuthHandler struct {
	Users         storage.UserRepository
	RefreshTokens tokens.RefreshRepository
	Hash          *password.Hasher
	JWT           *jwt.Manager
	AccessExpiry  time.Duration // e.g., 15 minutes
	RefreshExpiry time.Duration // e.g., 7 days
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (h *AuthHandler) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}

		// Basic validation
		if req.Username == "" || req.Email == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "username, email, and password are required"})
			return
		}

		// Check if user already exists
		if existing, _ := h.Users.GetUserByUsername(req.Username); existing != nil {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "username already taken"})
			return
		}
		if existing, _ := h.Users.GetUserByEmail(req.Email); existing != nil {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "email already registered"})
			return
		}

		// Hash password
		hashedPassword, err := h.Hash.Hash(req.Password)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to process password"})
			return
		}

		// Create user
		user := &storage.User{
			Username:  req.Username,
			Email:     req.Email,
			Password:  hashedPassword,
			Role:      "user", // default role
			CreatedAt: time.Now(),
		}

		if err := h.Users.CreateUser(user); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create user"})
			return
		}

		// Generate tokens
		resp, err := h.generateTokens(user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to generate tokens"})
			return
		}

		writeJSON(w, http.StatusCreated, resp)
	}
}

func (h *AuthHandler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}

		// Find user
		input := strings.TrimSpace(req.Username)

		var user *storage.User
		var err error

		// Try username first
		user, err = h.Users.GetUserByUsername(input)
		if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		// Not found? Try email
		if user == nil {
			user, err = h.Users.GetUserByEmail(input)
			if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
		}

		if user == nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Verify password
		if !h.Hash.Verify(req.Password, user.Password) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid credentials"})
			return
		}

		// Generate tokens
		resp, err := h.generateTokens(user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to generate tokens"})
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func (h *AuthHandler) RefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}

		// Validate refresh token
		storedToken, err := h.RefreshTokens.Get(req.RefreshToken)
		if err != nil || storedToken == nil {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid refresh token"})
			return
		}

		// Check expiration
		if time.Now().After(storedToken.ExpiresAt) {
			h.RefreshTokens.Delete(req.RefreshToken)
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "refresh token expired"})
			return
		}

		// Get user
		user, err := h.Users.GetUserByID(storedToken.UserID)
		if err != nil || user == nil {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "user not found"})
			return
		}

		// Delete old refresh token (rotation)
		h.RefreshTokens.Delete(req.RefreshToken)

		// Generate new tokens
		resp, err := h.generateTokens(user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to generate tokens"})
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func (h *AuthHandler) ChangePassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get claims from context (requires Auth middleware)
		claims, ok := middleware.GetClaims(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized"})
			return
		}

		var req ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}

		// Get user
		user, err := h.Users.GetUserByID(claims.UserID)
		if err != nil || user == nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "user not found"})
			return
		}

		// Verify old password
		if !h.Hash.Verify(req.OldPassword, user.Password) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "incorrect password"})
			return
		}

		// Hash new password
		hashedPassword, err := h.Hash.Hash(req.NewPassword)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to process password"})
			return
		}

		// Update user
		user.Password = hashedPassword
		if err := h.Users.UpdateUser(user); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update password"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "password changed successfully"})
	}
}

// generateTokens creates both access and refresh tokens for a user
func (h *AuthHandler) generateTokens(user *storage.User) (*AuthResponse, error) {
	accessToken, err := h.JWT.Generate(user.ID, user.Role, h.AccessExpiry)
	if err != nil {
		return nil, err
	}

	refreshToken := generateRefreshToken()
	rt := tokens.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(h.RefreshExpiry),
	}

	if err := h.RefreshTokens.Create(rt); err != nil {
		return nil, err
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(h.AccessExpiry.Seconds()),
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func generateRefreshToken() string {
	// Generate a secure random token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}
