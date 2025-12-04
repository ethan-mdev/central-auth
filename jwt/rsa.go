package jwt

import (
	"crypto/rsa"
	"crypto/x509"
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
