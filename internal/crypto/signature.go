package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"os"
)

// SignatureAlgorithm represents the signing algorithm
type SignatureAlgorithm string

const (
	RSASHA256 SignatureAlgorithm = "RSA-SHA256"
	RSASHA512 SignatureAlgorithm = "RSA-SHA512"
	RSAPSS256 SignatureAlgorithm = "RSA-PSS-SHA256"
	RSAPSS512 SignatureAlgorithm = "RSA-PSS-SHA512"
)

// SignOptions contains the options for signing
type SignOptions struct {
	Algorithm      SignatureAlgorithm
	InputFile      string
	PrivateKeyFile string
	Passphrase     string
	Encoding       string
}

// VerifyOptions contains the options for verification
type VerifyOptions struct {
	Algorithm     SignatureAlgorithm
	InputFile     string
	PublicKeyFile string
	SignatureFile string
	Encoding      string
}

// SignData signs data using RSA private key
func SignData(data []byte, opts SignOptions) ([]byte, error) {
	// Load private key
	privateKey, err := loadPrivateKey(opts.PrivateKeyFile, opts.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Hash the data
	hasher, hashType, err := getHasher(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign based on algorithm
	switch opts.Algorithm {
	case RSASHA256, RSASHA512:
		return rsa.SignPKCS1v15(rand.Reader, privateKey, hashType, hashed)
	case RSAPSS256, RSAPSS512:
		return rsa.SignPSS(rand.Reader, privateKey, hashType, hashed, nil)
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", opts.Algorithm)
	}
}

// SignFile signs a file using RSA private key
func SignFile(opts SignOptions) ([]byte, error) {
	// Read input file
	data, err := os.ReadFile(opts.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %w", err)
	}

	return SignData(data, opts)
}

// VerifyData verifies a signature against data using RSA public key
func VerifyData(data, signature []byte, opts VerifyOptions) error {
	// Load public key
	publicKey, err := loadPublicKey(opts.PublicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	// Hash the data
	hasher, hashType, err := getHasher(opts.Algorithm)
	if err != nil {
		return err
	}

	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Verify based on algorithm
	switch opts.Algorithm {
	case RSASHA256, RSASHA512:
		return rsa.VerifyPKCS1v15(publicKey, hashType, hashed, signature)
	case RSAPSS256, RSAPSS512:
		return rsa.VerifyPSS(publicKey, hashType, hashed, signature, nil)
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", opts.Algorithm)
	}
}

// VerifyFile verifies a signature against a file using RSA public key
func VerifyFile(opts VerifyOptions) error {
	// Read input file
	data, err := os.ReadFile(opts.InputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Read signature file
	signature, err := os.ReadFile(opts.SignatureFile)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	return VerifyData(data, signature, opts)
}

// loadPrivateKey loads and parses an RSA private key from a PEM file
func loadPrivateKey(keyFile, passphrase string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	var der []byte
	if block.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(block) {
		if passphrase == "" {
			return nil, fmt.Errorf("private key is encrypted but no passphrase provided")
		}

		if block.Type == "ENCRYPTED PRIVATE KEY" {
			// PKCS#8 encrypted private key
			der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		} else {
			// Legacy encrypted private key
			der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		}
	} else {
		der = block.Bytes
	}

	// Try to parse as PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// Fall back to PKCS#1
		return x509.ParsePKCS1PrivateKey(der)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	return rsaKey, nil
}

// loadPublicKey loads and parses an RSA public key from a PEM file
func loadPublicKey(keyFile string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaPub, nil
}

// getHasher returns the appropriate hasher and crypto.Hash for the algorithm
func getHasher(algorithm SignatureAlgorithm) (hash.Hash, crypto.Hash, error) {
	switch algorithm {
	case RSASHA256, RSAPSS256:
		return sha256.New(), crypto.SHA256, nil
	case RSASHA512, RSAPSS512:
		return sha512.New(), crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// SignFromReader signs data from an io.Reader
func SignFromReader(reader io.Reader, opts SignOptions) ([]byte, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return SignData(data, opts)
}

// VerifyFromReader verifies a signature against data from an io.Reader
func VerifyFromReader(reader io.Reader, signature []byte, opts VerifyOptions) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	return VerifyData(data, signature, opts)
}
