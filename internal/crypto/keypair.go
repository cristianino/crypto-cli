package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KeyPairType represents the type of key pair to generate
type KeyPairType string

const (
	RSA    KeyPairType = "rsa"
	RSAPSS KeyPairType = "rsa-pss"
)

// KeyFormat represents the output format for keys
type KeyFormat string

const (
	PEM KeyFormat = "pem"
	DER KeyFormat = "der"
)

// KeyPairOptions contains the options for key pair generation
type KeyPairOptions struct {
	Type          KeyPairType
	ModulusLength int // 2048, 3072, or 4096
	Passphrase    string
	Format        KeyFormat
	AESKeySize    int // 128, 192, or 256 for AES encryption of private key
}

// KeyPair represents a generated key pair
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateKeyPair generates a new RSA key pair with the specified options
func GenerateKeyPair(opts KeyPairOptions) (*KeyPair, error) {
	// Validate modulus length
	if opts.ModulusLength != 2048 && opts.ModulusLength != 3072 && opts.ModulusLength != 4096 {
		return nil, fmt.Errorf("invalid modulus length: %d (must be 2048, 3072, or 4096)", opts.ModulusLength)
	}

	// Validate AES key size
	if opts.AESKeySize != 128 && opts.AESKeySize != 192 && opts.AESKeySize != 256 {
		return nil, fmt.Errorf("invalid AES key size: %d (must be 128, 192, or 256)", opts.AESKeySize)
	}

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, opts.ModulusLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate public key
	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey, opts.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	// Generate private key
	privateKeyBytes, err := generatePrivateKey(privateKey, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &KeyPair{
		PublicKey:  publicKeyBytes,
		PrivateKey: privateKeyBytes,
	}, nil
}

// generatePublicKey generates the public key in the specified format
func generatePublicKey(publicKey *rsa.PublicKey, format KeyFormat) ([]byte, error) {
	// Marshal public key to PKIX format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	if format == DER {
		return publicKeyDER, nil
	}

	// Convert to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return publicKeyPEM, nil
}

// generatePrivateKey generates the private key in the specified format with optional encryption
func generatePrivateKey(privateKey *rsa.PrivateKey, opts KeyPairOptions) ([]byte, error) {
	// Marshal private key to PKCS8 format
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	if opts.Format == DER {
		if opts.Passphrase != "" {
			return nil, fmt.Errorf("DER format with passphrase encryption is not supported")
		}
		return privateKeyDER, nil
	}

	// Create PEM block
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}

	// Encrypt private key if passphrase is provided
	if opts.Passphrase != "" {
		var cipher x509.PEMCipher
		switch opts.AESKeySize {
		case 128:
			cipher = x509.PEMCipherAES128
		case 192:
			cipher = x509.PEMCipherAES192
		case 256:
			cipher = x509.PEMCipherAES256
		default:
			return nil, fmt.Errorf("unsupported AES key size: %d", opts.AESKeySize)
		}

		encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(opts.Passphrase), cipher)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		block = encryptedBlock
	}

	privateKeyPEM := pem.EncodeToMemory(block)
	return privateKeyPEM, nil
}

// SaveKeyPairToFiles saves the key pair to files in the specified directory
func SaveKeyPairToFiles(keyPair *KeyPair, outDir string, format KeyFormat) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Determine file extension
	ext := string(format)

	// Save public key
	publicKeyPath := filepath.Join(outDir, "public."+ext)
	if err := os.WriteFile(publicKeyPath, keyPair.PublicKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Save private key
	privateKeyPath := filepath.Join(outDir, "private."+ext)
	if err := os.WriteFile(privateKeyPath, keyPair.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}
