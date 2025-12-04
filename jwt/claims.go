package jwt

// Claims represents the custom claims in a JWT token.
type Claims struct {
	UserID   string
	Username string
	Role     string
}
