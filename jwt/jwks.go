package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the JSON Web Key Set for the manager's public key.
// This is only applicable for RS256 managers.
func (m *Manager) JWKS() ([]byte, error) {
	if m.algorithm != "RS256" {
		return nil, nil
	}

	var pubKey *rsa.PublicKey
	if m.publicKey != nil {
		pubKey = m.publicKey
	} else if m.privateKey != nil {
		pubKey = &m.privateKey.PublicKey
	} else {
		return nil, nil
	}

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: m.keyID,
		N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	jwks := JWKS{Keys: []JWK{jwk}}
	return json.Marshal(jwks)
}
