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

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create digital signatures using RSA keys",
	Long: `Create digital signatures for files or data using RSA private keys.

Supports RSA-SHA256, RSA-SHA512, RSA-PSS-SHA256, and RSA-PSS-SHA512 algorithms.
The signature can be saved to a file or displayed as hex/base64 encoded text.

Examples:
  # Sign a file with RSA-SHA256
  crypto-cli sign --algorithm RSA-SHA256 --input data.txt --private-key private.pem --output signature.bin

  # Sign with passphrase-protected private key
  crypto-cli sign --algorithm RSA-SHA256 --input data.txt --private-key private.pem --passphrase secret123 --output signature.bin

  # Sign and output as base64 to stdout
  crypto-cli sign --algorithm RSA-SHA256 --input data.txt --private-key private.pem --encoding base64

  # Sign using RSA-PSS
  crypto-cli sign --algorithm RSA-PSS-SHA256 --input data.txt --private-key private.pem --output signature.bin

  # Sign from stdin
  cat data.txt | crypto-cli sign --algorithm RSA-SHA256 --private-key private.pem --encoding hex`,
	RunE: runSign,
}

var (
	signAlgorithm  string
	signInput      string
	signPrivateKey string
	signPassphrase string
	signOutput     string
	signEncoding   string
)

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&signAlgorithm, "algorithm", "a", "RSA-SHA256", "Signature algorithm (RSA-SHA256, RSA-SHA512, RSA-PSS-SHA256, RSA-PSS-SHA512)")
	signCmd.Flags().StringVarP(&signInput, "input", "i", "", "Input file to sign (if not specified, reads from stdin)")
	signCmd.Flags().StringVarP(&signPrivateKey, "private-key", "k", "", "Path to RSA private key file (required)")
	signCmd.Flags().StringVarP(&signPassphrase, "passphrase", "p", "", "Passphrase for encrypted private key (optional)")
	signCmd.Flags().StringVarP(&signOutput, "output", "o", "", "Output file for signature (if not specified, prints to stdout)")
	signCmd.Flags().StringVarP(&signEncoding, "encoding", "e", "base64", "Encoding for stdout output (hex, base64)")

	// Don't mark private-key as required here, we'll validate it manually
	// signCmd.MarkFlagRequired("private-key")
}

func runSign(cmd *cobra.Command, args []string) error {
	// Validate parameters
	if err := validateSignParams(); err != nil {
		return err
	}

	// Prepare options
	opts := crypto.SignOptions{
		Algorithm:      crypto.SignatureAlgorithm(signAlgorithm),
		InputFile:      signInput,
		PrivateKeyFile: signPrivateKey,
		Passphrase:     signPassphrase,
		Encoding:       signEncoding,
	}

	var signature []byte
	var err error

	// Sign data
	if signInput != "" {
		signature, err = crypto.SignFile(opts)
	} else {
		signature, err = crypto.SignFromReader(os.Stdin, opts)
	}

	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Output signature
	if signOutput != "" {
		return saveSignatureToFile(signature, signOutput)
	} else {
		return printSignatureToStdout(signature)
	}
}

func validateSignParams() error {
	// Validate that private key is provided
	if signPrivateKey == "" {
		return fmt.Errorf("required flag(s) \"private-key\" not set")
	}

	// Validate algorithm
	validAlgorithms := []string{"RSA-SHA256", "RSA-SHA512", "RSA-PSS-SHA256", "RSA-PSS-SHA512"}
	if !contains(validAlgorithms, signAlgorithm) {
		return fmt.Errorf("invalid algorithm: %s (must be one of: %s)", signAlgorithm, strings.Join(validAlgorithms, ", "))
	}

	// Validate input file if specified (before validating private key file)
	if signInput != "" {
		if _, err := os.Stat(signInput); os.IsNotExist(err) {
			return fmt.Errorf("input file does not exist: %s", signInput)
		}
	}

	// Validate private key file exists
	if _, err := os.Stat(signPrivateKey); os.IsNotExist(err) {
		return fmt.Errorf("private key file does not exist: %s", signPrivateKey)
	}

	// Validate encoding for stdout output
	if signOutput == "" {
		validEncodings := []string{"hex", "base64"}
		if !contains(validEncodings, signEncoding) {
			return fmt.Errorf("invalid encoding: %s (must be one of: %s)", signEncoding, strings.Join(validEncodings, ", "))
		}
	}

	return nil
}

func saveSignatureToFile(signature []byte, outputFile string) error {
	// Expand tilde in path
	if strings.HasPrefix(outputFile, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		outputFile = filepath.Join(homeDir, outputFile[2:])
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write signature to file
	if err := os.WriteFile(outputFile, signature, 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	fmt.Printf("Signature created successfully!\n")
	fmt.Printf("Algorithm: %s\n", signAlgorithm)
	if signInput != "" {
		fmt.Printf("Input file: %s\n", signInput)
	} else {
		fmt.Printf("Input: stdin\n")
	}
	fmt.Printf("Private key: %s\n", signPrivateKey)
	if signPassphrase != "" {
		fmt.Printf("Private key encrypted: yes\n")
	}
	fmt.Printf("Signature saved to: %s\n", outputFile)
	fmt.Printf("Signature size: %d bytes\n", len(signature))

	return nil
}

func printSignatureToStdout(signature []byte) error {
	fmt.Printf("Signature created successfully!\n")
	fmt.Printf("Algorithm: %s\n", signAlgorithm)
	if signInput != "" {
		fmt.Printf("Input file: %s\n", signInput)
	} else {
		fmt.Printf("Input: stdin\n")
	}
	fmt.Printf("Private key: %s\n", signPrivateKey)
	if signPassphrase != "" {
		fmt.Printf("Private key encrypted: yes\n")
	}
	fmt.Printf("Signature size: %d bytes\n", len(signature))
	fmt.Println()

	// Encode and print signature
	encoded, err := encodeSignature(signature, signEncoding)
	if err != nil {
		return fmt.Errorf("failed to encode signature: %w", err)
	}

	fmt.Printf("Signature (%s):\n%s\n", signEncoding, encoded)

	return nil
}

func encodeSignature(data []byte, encoding string) (string, error) {
	switch encoding {
	case "hex":
		return hex.EncodeToString(data), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(data), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}
