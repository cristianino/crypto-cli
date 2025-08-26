package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cristianino/crypto-cli/internal/crypto"
	"github.com/spf13/cobra"
)

var kdfCmd = &cobra.Command{
	Use:   "kdf",
	Short: "Key derivation functions (KDF) - derive keys from passwords",
	Long: `Key derivation functions for deriving cryptographic keys from passwords using scrypt or PBKDF2.

Supports scrypt and PBKDF2 with SHA-1, SHA-256, or SHA-512.
The derived key can be displayed as hex or base64 encoded text.

Examples:
  # Derive key using scrypt (default parameters)
  crypto-cli kdf --algorithm scrypt --password mypassword --salt mysalt --keylen 32

  # Derive key using scrypt with custom parameters
  crypto-cli kdf --algorithm scrypt --password mypassword --salt mysalt --keylen 32 --scrypt-n 65536 --scrypt-r 8 --scrypt-p 1

  # Derive key using scrypt with preset
  crypto-cli kdf --algorithm scrypt --password mypassword --salt mysalt --keylen 32 --preset sensitive

  # Derive key using PBKDF2-SHA256
  crypto-cli kdf --algorithm pbkdf2-sha256 --password mypassword --salt mysalt --keylen 32 --iterations 100000

  # Derive key using PBKDF2-SHA512 with preset
  crypto-cli kdf --algorithm pbkdf2-sha512 --password mypassword --salt mysalt --keylen 32 --preset sensitive

  # Generate random salt and derive key
  crypto-cli kdf --algorithm scrypt --password mypassword --generate-salt 16 --keylen 32

  # Output as hex
  crypto-cli kdf --algorithm scrypt --password mypassword --salt mysalt --keylen 32 --encoding hex`,
	RunE: runKDF,
}

var (
	kdfAlgorithm    string
	kdfPassword     string
	kdfSalt         string
	kdfGenerateSalt int
	kdfKeyLen       int
	kdfEncoding     string
	kdfPreset       string
	// Scrypt specific
	kdfScryptN int
	kdfScryptR int
	kdfScryptP int
	// PBKDF2 specific
	kdfIterations int
	kdfHashFunc   string
)

func init() {
	rootCmd.AddCommand(kdfCmd)

	kdfCmd.Flags().StringVarP(&kdfAlgorithm, "algorithm", "a", "scrypt", "KDF algorithm (scrypt, pbkdf2-sha1, pbkdf2-sha256, pbkdf2-sha512)")
	kdfCmd.Flags().StringVarP(&kdfPassword, "password", "p", "", "Password for key derivation (required)")
	kdfCmd.Flags().StringVarP(&kdfSalt, "salt", "s", "", "Salt for key derivation (required unless --generate-salt is used)")
	kdfCmd.Flags().IntVar(&kdfGenerateSalt, "generate-salt", 0, "Generate random salt with specified length in bytes")
	kdfCmd.Flags().IntVarP(&kdfKeyLen, "keylen", "k", 32, "Output key length in bytes")
	kdfCmd.Flags().StringVarP(&kdfEncoding, "encoding", "e", "base64", "Output encoding (hex, base64)")
	kdfCmd.Flags().StringVar(&kdfPreset, "preset", "", "Parameter preset (fast, interactive, sensitive)")

	// Scrypt specific flags
	kdfCmd.Flags().IntVar(&kdfScryptN, "scrypt-n", 0, "Scrypt N parameter (CPU/memory cost, power of 2)")
	kdfCmd.Flags().IntVar(&kdfScryptR, "scrypt-r", 0, "Scrypt r parameter (block size)")
	kdfCmd.Flags().IntVar(&kdfScryptP, "scrypt-p", 0, "Scrypt p parameter (parallelization)")

	// PBKDF2 specific flags
	kdfCmd.Flags().IntVar(&kdfIterations, "iterations", 0, "PBKDF2 iterations (default: 100000)")
	kdfCmd.Flags().StringVar(&kdfHashFunc, "hash", "", "Hash function for PBKDF2 (sha1, sha256, sha512)")

	// Mark required flags
	kdfCmd.MarkFlagRequired("password")
}

func runKDF(cmd *cobra.Command, args []string) error {
	// Validate parameters
	if err := validateKDFParams(); err != nil {
		return err
	}

	// Generate salt if requested
	var salt string
	if kdfGenerateSalt > 0 {
		saltBytes, err := crypto.GenerateRandomSalt(kdfGenerateSalt)
		if err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
		salt = base64.StdEncoding.EncodeToString(saltBytes)
		fmt.Printf("Generated salt (base64): %s\n", salt)
	} else {
		salt = kdfSalt
	}

	// Apply presets if specified
	if err := applyPresets(); err != nil {
		return err
	}

	// Prepare options
	opts := crypto.KDFOptions{
		Algorithm:  crypto.KDFAlgorithm(kdfAlgorithm),
		Password:   kdfPassword,
		Salt:       salt,
		KeyLen:     kdfKeyLen,
		Encoding:   kdfEncoding,
		N:          kdfScryptN,
		R:          kdfScryptR,
		P:          kdfScryptP,
		Iterations: kdfIterations,
		HashFunc:   kdfHashFunc,
	}

	// Derive key
	derivedKey, err := crypto.DeriveKey(opts)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	// Display results
	return displayKDFResults(derivedKey, opts)
}

func validateKDFParams() error {
	// Validate algorithm
	validAlgorithms := []string{"scrypt", "pbkdf2-sha1", "pbkdf2-sha256", "pbkdf2-sha512"}
	if !contains(validAlgorithms, kdfAlgorithm) {
		return fmt.Errorf("invalid algorithm: %s (must be one of: %s)", kdfAlgorithm, strings.Join(validAlgorithms, ", "))
	}

	// Validate salt or generate-salt
	if kdfSalt == "" && kdfGenerateSalt <= 0 {
		return fmt.Errorf("either --salt or --generate-salt must be specified")
	}
	if kdfSalt != "" && kdfGenerateSalt > 0 {
		return fmt.Errorf("cannot specify both --salt and --generate-salt")
	}

	// Validate key length
	if kdfKeyLen <= 0 {
		return fmt.Errorf("key length must be positive")
	}
	if kdfKeyLen > 1024 {
		return fmt.Errorf("key length too large (max 1024 bytes)")
	}

	// Validate generate salt length
	if kdfGenerateSalt > 256 {
		return fmt.Errorf("salt length too large (max 256 bytes)")
	}

	// Validate encoding
	validEncodings := []string{"hex", "base64"}
	if !contains(validEncodings, kdfEncoding) {
		return fmt.Errorf("invalid encoding: %s (must be one of: %s)", kdfEncoding, strings.Join(validEncodings, ", "))
	}

	// Validate preset
	if kdfPreset != "" {
		validPresets := []string{"fast", "interactive", "sensitive"}
		if !contains(validPresets, kdfPreset) {
			return fmt.Errorf("invalid preset: %s (must be one of: %s)", kdfPreset, strings.Join(validPresets, ", "))
		}
	}

	// Algorithm-specific validation
	if strings.HasPrefix(kdfAlgorithm, "scrypt") {
		// Validate scrypt parameters if provided
		if kdfScryptN > 0 || kdfScryptR > 0 || kdfScryptP > 0 {
			// Set defaults for unspecified parameters
			n, r, p := kdfScryptN, kdfScryptR, kdfScryptP
			if n == 0 {
				n = 32768
			}
			if r == 0 {
				r = 8
			}
			if p == 0 {
				p = 1
			}

			if err := crypto.ValidateScryptParameters(n, r, p); err != nil {
				return fmt.Errorf("invalid scrypt parameters: %w", err)
			}
		}
	}

	if strings.HasPrefix(kdfAlgorithm, "pbkdf2") {
		// Validate PBKDF2 parameters
		if kdfIterations > 0 && kdfIterations < 1000 {
			return fmt.Errorf("PBKDF2 iterations should be at least 1000 for security")
		}
		if kdfHashFunc != "" {
			validHashes := []string{"sha1", "sha256", "sha512"}
			if !contains(validHashes, strings.ToLower(kdfHashFunc)) {
				return fmt.Errorf("invalid hash function: %s (must be one of: %s)", kdfHashFunc, strings.Join(validHashes, ", "))
			}
		}
	}

	return nil
}

func applyPresets() error {
	if kdfPreset == "" {
		return nil
	}

	if strings.HasPrefix(kdfAlgorithm, "scrypt") {
		presets := crypto.GetScryptPresets()
		preset, exists := presets[kdfPreset]
		if !exists {
			return fmt.Errorf("unknown scrypt preset: %s", kdfPreset)
		}

		// Apply preset only if parameters not explicitly set
		if kdfScryptN == 0 {
			kdfScryptN = preset.N
		}
		if kdfScryptR == 0 {
			kdfScryptR = preset.R
		}
		if kdfScryptP == 0 {
			kdfScryptP = preset.P
		}
	}

	if strings.HasPrefix(kdfAlgorithm, "pbkdf2") {
		presets := crypto.GetPBKDF2Presets()
		iterations, exists := presets[kdfPreset]
		if !exists {
			return fmt.Errorf("unknown PBKDF2 preset: %s", kdfPreset)
		}

		// Apply preset only if iterations not explicitly set
		if kdfIterations == 0 {
			kdfIterations = iterations
		}
	}

	return nil
}

func displayKDFResults(derivedKey []byte, opts crypto.KDFOptions) error {
	fmt.Printf("Key derivation completed successfully!\n")
	fmt.Printf("Algorithm: %s\n", opts.Algorithm)
	fmt.Printf("Password: %s\n", maskPassword(opts.Password))

	if kdfGenerateSalt > 0 {
		fmt.Printf("Salt: <generated %d bytes>\n", kdfGenerateSalt)
	} else {
		fmt.Printf("Salt: %s\n", maskString(opts.Salt))
	}

	fmt.Printf("Key length: %d bytes\n", opts.KeyLen)

	// Show algorithm-specific parameters
	if opts.Algorithm == crypto.Scrypt {
		fmt.Printf("Scrypt parameters: N=%d, r=%d, p=%d\n", opts.N, opts.R, opts.P)
		if kdfPreset != "" {
			fmt.Printf("Preset: %s\n", kdfPreset)
		}
	} else if strings.HasPrefix(string(opts.Algorithm), "pbkdf2") {
		fmt.Printf("PBKDF2 iterations: %d\n", opts.Iterations)
		if opts.HashFunc != "" {
			fmt.Printf("Hash function: %s\n", opts.HashFunc)
		}
		if kdfPreset != "" {
			fmt.Printf("Preset: %s\n", kdfPreset)
		}
	}

	fmt.Println()

	// Encode and display derived key
	encoded, err := encodeKey(derivedKey, kdfEncoding)
	if err != nil {
		return fmt.Errorf("failed to encode derived key: %w", err)
	}

	fmt.Printf("Derived key (%s):\n%s\n", kdfEncoding, encoded)

	return nil
}

func encodeKey(data []byte, encoding string) (string, error) {
	switch encoding {
	case "hex":
		return hex.EncodeToString(data), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(data), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

func maskPassword(password string) string {
	if len(password) <= 2 {
		return "***"
	}
	return password[:1] + strings.Repeat("*", len(password)-2) + password[len(password)-1:]
}

func maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
