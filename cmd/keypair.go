package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cristianino/crypto-cli/internal/crypto"
	"github.com/spf13/cobra"
)

var keypairCmd = &cobra.Command{
	Use:   "keypair",
	Short: "Generate RSA key pairs",
	Long: `Generate RSA key pairs for cryptographic operations.

Supports RSA and RSA-PSS key types with various modulus lengths (2048, 3072, 4096).
Keys can be generated in PEM or DER format, with optional passphrase protection.

Examples:
  # Generate RSA-2048 key pair in PEM format
  crypto-cli keypair --type rsa --modulus 2048 --format pem --output ./keys

  # Generate RSA-4096 key pair with passphrase protection
  crypto-cli keypair --type rsa --modulus 4096 --passphrase secret123 --aes-size 256 --output ./keys

  # Generate key pair and display as base64 (no files saved)
  crypto-cli keypair --type rsa --modulus 2048 --encoding base64

  # Generate RSA-PSS key pair in DER format
  crypto-cli keypair --type rsa-pss --modulus 3072 --format der --output ./keys`,
	RunE: runKeypair,
}

var (
	keypairType       string
	keypairModulus    int
	keypairFormat     string
	keypairPassphrase string
	keypairAESSize    int
	keypairOutput     string
	keypairEncoding   string
)

func init() {
	rootCmd.AddCommand(keypairCmd)

	keypairCmd.Flags().StringVarP(&keypairType, "type", "t", "rsa", "Key type (rsa, rsa-pss)")
	keypairCmd.Flags().IntVarP(&keypairModulus, "modulus", "m", 2048, "Modulus length in bits (2048, 3072, 4096)")
	keypairCmd.Flags().StringVarP(&keypairFormat, "format", "f", "pem", "Output format (pem, der)")
	keypairCmd.Flags().StringVarP(&keypairPassphrase, "passphrase", "p", "", "Passphrase to encrypt private key (optional)")
	keypairCmd.Flags().IntVarP(&keypairAESSize, "aes-size", "a", 256, "AES key size for private key encryption (128, 192, 256)")
	keypairCmd.Flags().StringVarP(&keypairOutput, "output", "o", "", "Output directory for key files (if not specified, keys are printed to stdout)")
	keypairCmd.Flags().StringVarP(&keypairEncoding, "encoding", "e", "base64", "Encoding for stdout output (hex, base64)")
}

func runKeypair(cmd *cobra.Command, args []string) error {
	// Validate parameters
	if err := validateKeypairParams(); err != nil {
		return err
	}

	// Prepare options
	opts := crypto.KeyPairOptions{
		Type:          crypto.KeyPairType(keypairType),
		ModulusLength: keypairModulus,
		Passphrase:    keypairPassphrase,
		Format:        crypto.KeyFormat(keypairFormat),
		AESKeySize:    keypairAESSize,
	}

	// Generate key pair
	keyPair, err := crypto.GenerateKeyPair(opts)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Save to files or print to stdout
	if keypairOutput != "" {
		return saveKeypairToFiles(keyPair, keypairOutput)
	} else {
		return printKeypairToStdout(keyPair)
	}
}

func validateKeypairParams() error {
	// Validate key type
	validTypes := []string{"rsa", "rsa-pss"}
	if !contains(validTypes, keypairType) {
		return fmt.Errorf("invalid key type: %s (must be one of: %s)", keypairType, strings.Join(validTypes, ", "))
	}

	// Validate modulus length
	validModulus := []int{2048, 3072, 4096}
	if !containsInt(validModulus, keypairModulus) {
		return fmt.Errorf("invalid modulus length: %d (must be one of: 2048, 3072, 4096)", keypairModulus)
	}

	// Validate format
	validFormats := []string{"pem", "der"}
	if !contains(validFormats, keypairFormat) {
		return fmt.Errorf("invalid format: %s (must be one of: %s)", keypairFormat, strings.Join(validFormats, ", "))
	}

	// Validate AES size
	validAESSizes := []int{128, 192, 256}
	if !containsInt(validAESSizes, keypairAESSize) {
		return fmt.Errorf("invalid AES size: %d (must be one of: 128, 192, 256)", keypairAESSize)
	}

	// Validate encoding for stdout output
	if keypairOutput == "" {
		validEncodings := []string{"hex", "base64"}
		if !contains(validEncodings, keypairEncoding) {
			return fmt.Errorf("invalid encoding: %s (must be one of: %s)", keypairEncoding, strings.Join(validEncodings, ", "))
		}
	}

	// DER format with passphrase is not supported
	if keypairFormat == "der" && keypairPassphrase != "" {
		return fmt.Errorf("DER format with passphrase encryption is not supported")
	}

	return nil
}

func saveKeypairToFiles(keyPair *crypto.KeyPair, outDir string) error {
	// Expand tilde in path
	if strings.HasPrefix(outDir, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		outDir = filepath.Join(homeDir, outDir[2:])
	}

	// Save key pair to files
	if err := crypto.SaveKeyPairToFiles(keyPair, outDir, crypto.KeyFormat(keypairFormat)); err != nil {
		return err
	}

	// Print success message
	fmt.Printf("Key pair generated successfully!\n")
	fmt.Printf("Type: %s\n", keypairType)
	fmt.Printf("Modulus: %d bits\n", keypairModulus)
	fmt.Printf("Format: %s\n", keypairFormat)
	if keypairPassphrase != "" {
		fmt.Printf("Private key encrypted with AES-%d\n", keypairAESSize)
	}
	fmt.Printf("Public key saved to: %s\n", filepath.Join(outDir, "public."+keypairFormat))
	fmt.Printf("Private key saved to: %s\n", filepath.Join(outDir, "private."+keypairFormat))

	return nil
}

func printKeypairToStdout(keyPair *crypto.KeyPair) error {
	fmt.Printf("Key pair generated successfully!\n")
	fmt.Printf("Type: %s\n", keypairType)
	fmt.Printf("Modulus: %d bits\n", keypairModulus)
	fmt.Printf("Format: %s\n", keypairFormat)
	if keypairPassphrase != "" {
		fmt.Printf("Private key encrypted with AES-%d\n", keypairAESSize)
	}
	fmt.Println()

	// Encode and print public key
	publicKeyEncoded, err := encodeBytes(keyPair.PublicKey, keypairEncoding)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}
	fmt.Printf("Public Key (%s):\n%s\n\n", keypairEncoding, publicKeyEncoded)

	// Encode and print private key
	privateKeyEncoded, err := encodeBytes(keyPair.PrivateKey, keypairEncoding)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}
	fmt.Printf("Private Key (%s):\n%s\n", keypairEncoding, privateKeyEncoded)

	return nil
}

func encodeBytes(data []byte, encoding string) (string, error) {
	switch encoding {
	case "hex":
		return hex.EncodeToString(data), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(data), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}
