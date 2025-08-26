package crypto

import (
	"crypto/rand"
	"fmt"

	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// KDFAlgorithm represents the key derivation function algorithm
type KDFAlgorithm string

const (
	Scrypt       KDFAlgorithm = "scrypt"
	PBKDF2SHA1   KDFAlgorithm = "pbkdf2-sha1"
	PBKDF2SHA256 KDFAlgorithm = "pbkdf2-sha256"
	PBKDF2SHA512 KDFAlgorithm = "pbkdf2-sha512"
)

// ScryptOptions contains the options for scrypt key derivation
type ScryptOptions struct {
	Password string
	Salt     string
	KeyLen   int // Output key length in bytes
	N        int // CPU/memory cost parameter (must be power of 2)
	R        int // Block size parameter
	P        int // Parallelization parameter
	Encoding string
}

// PBKDF2Options contains the options for PBKDF2 key derivation
type PBKDF2Options struct {
	Password   string
	Salt       string
	KeyLen     int    // Output key length in bytes
	Iterations int    // Number of iterations
	HashFunc   string // Hash function: sha1, sha256, sha512
	Encoding   string
}

// KDFOptions contains the options for key derivation
type KDFOptions struct {
	Algorithm KDFAlgorithm
	Password  string
	Salt      string
	KeyLen    int
	Encoding  string
	// Scrypt specific
	N int // CPU/memory cost (default: 32768)
	R int // Block size (default: 8)
	P int // Parallelization (default: 1)
	// PBKDF2 specific
	Iterations int    // Number of iterations (default: 100000)
	HashFunc   string // Hash function for PBKDF2 (default: sha256)
}

// DeriveKey derives a key using the specified algorithm and parameters
func DeriveKey(opts KDFOptions) ([]byte, error) {
	// Validate common parameters
	if opts.Password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if opts.Salt == "" {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	if opts.KeyLen <= 0 {
		return nil, fmt.Errorf("key length must be positive")
	}

	switch opts.Algorithm {
	case Scrypt:
		return deriveScryptKey(ScryptOptions{
			Password: opts.Password,
			Salt:     opts.Salt,
			KeyLen:   opts.KeyLen,
			N:        opts.N,
			R:        opts.R,
			P:        opts.P,
			Encoding: opts.Encoding,
		})
	case PBKDF2SHA1, PBKDF2SHA256, PBKDF2SHA512:
		return derivePBKDF2Key(PBKDF2Options{
			Password:   opts.Password,
			Salt:       opts.Salt,
			KeyLen:     opts.KeyLen,
			Iterations: opts.Iterations,
			HashFunc:   opts.HashFunc,
			Encoding:   opts.Encoding,
		})
	default:
		return nil, fmt.Errorf("unsupported KDF algorithm: %s", opts.Algorithm)
	}
}

// deriveScryptKey derives a key using scrypt
func deriveScryptKey(opts ScryptOptions) ([]byte, error) {
	// Set default values if not specified
	if opts.N == 0 {
		opts.N = 32768 // 2^15
	}
	if opts.R == 0 {
		opts.R = 8
	}
	if opts.P == 0 {
		opts.P = 1
	}

	// Validate scrypt parameters
	if opts.N <= 0 || (opts.N&(opts.N-1)) != 0 {
		return nil, fmt.Errorf("N must be a positive power of 2")
	}
	if opts.R <= 0 {
		return nil, fmt.Errorf("r must be positive")
	}
	if opts.P <= 0 {
		return nil, fmt.Errorf("p must be positive")
	}

	// Check memory requirements (approximate)
	memoryRequired := 128 * opts.N * opts.R
	if memoryRequired > 1024*1024*1024 { // 1GB limit
		return nil, fmt.Errorf("scrypt parameters require too much memory: %d bytes", memoryRequired)
	}

	// Derive key using scrypt
	derivedKey, err := scrypt.Key(
		[]byte(opts.Password),
		[]byte(opts.Salt),
		opts.N,
		opts.R,
		opts.P,
		opts.KeyLen,
	)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	return derivedKey, nil
}

// derivePBKDF2Key derives a key using PBKDF2
func derivePBKDF2Key(opts PBKDF2Options) ([]byte, error) {
	// Set default iterations if not specified
	if opts.Iterations == 0 {
		opts.Iterations = 100000
	}

	// Validate iterations
	if opts.Iterations <= 0 {
		return nil, fmt.Errorf("iterations must be positive")
	}

	// Get hash function
	var hashFunc func() hash.Hash
	switch opts.HashFunc {
	case "sha1", "SHA1":
		hashFunc = sha1.New
	case "sha256", "SHA256", "":
		hashFunc = sha256.New // Default to SHA256
	case "sha512", "SHA512":
		hashFunc = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hash function: %s", opts.HashFunc)
	}

	// Derive key using PBKDF2
	derivedKey := pbkdf2.Key(
		[]byte(opts.Password),
		[]byte(opts.Salt),
		opts.Iterations,
		opts.KeyLen,
		hashFunc,
	)

	return derivedKey, nil
}

// GenerateRandomSalt generates a random salt of specified length
func GenerateRandomSalt(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("salt length must be positive")
	}

	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	return salt, nil
}

// ValidateScryptParameters validates scrypt parameters for safety
func ValidateScryptParameters(N, r, p int) error {
	if N <= 0 || (N&(N-1)) != 0 {
		return fmt.Errorf("N must be a positive power of 2")
	}
	if r <= 0 {
		return fmt.Errorf("r must be positive")
	}
	if p <= 0 {
		return fmt.Errorf("p must be positive")
	}

	// Check memory requirements
	memoryRequired := 128 * N * r
	if memoryRequired > 1024*1024*1024 { // 1GB limit
		return fmt.Errorf("parameters require too much memory: %d bytes", memoryRequired)
	}

	return nil
}

// GetScryptPresets returns common scrypt parameter presets
func GetScryptPresets() map[string]ScryptOptions {
	return map[string]ScryptOptions{
		"interactive": {
			N: 32768, // 2^15
			R: 8,
			P: 1,
		},
		"sensitive": {
			N: 1048576, // 2^20
			R: 8,
			P: 1,
		},
		"fast": {
			N: 16384, // 2^14
			R: 8,
			P: 1,
		},
	}
}

// GetPBKDF2Presets returns common PBKDF2 iteration presets
func GetPBKDF2Presets() map[string]int {
	return map[string]int{
		"fast":        10000,
		"interactive": 100000,
		"sensitive":   1000000,
	}
}
