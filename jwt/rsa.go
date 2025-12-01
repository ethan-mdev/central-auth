package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// LoadPrivateKey parses a PEM-encoded RSA private key.
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	// Try PKCS#1 format (-----BEGIN RSA PRIVATE KEY-----)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8 format (-----BEGIN PRIVATE KEY-----)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

// LoadPublicKey parses a PEM-encoded RSA public key.
func LoadPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	// Try PKIX format (-----BEGIN PUBLIC KEY-----)
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := pub.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("not an RSA public key")
	}

	// Try PKCS#1 format (-----BEGIN RSA PUBLIC KEY-----)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

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
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pubKey.E)),
	}

	jwks := JWKS{Keys: []JWK{jwk}}
	return json.Marshal(jwks)
}

func bigIntToBytes(i int) []byte {
	b := make([]byte, 0)
	for i > 0 {
		b = append([]byte{byte(i & 0xff)}, b...)
		i >>= 8
	}
	return b
}
