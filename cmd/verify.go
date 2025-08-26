package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/cristianino/crypto-cli/internal/crypto"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify digital signatures using RSA keys",
	Long: `Verify digital signatures for files or data using RSA public keys.

Supports RSA-SHA256, RSA-SHA512, RSA-PSS-SHA256, and RSA-PSS-SHA512 algorithms.
The signature can be read from a file or provided as hex/base64 encoded text.

Examples:
  # Verify a file signature
  crypto-cli verify --algorithm RSA-SHA256 --input data.txt --public-key public.pem --signature signature.bin

  # Verify with base64 encoded signature
  crypto-cli verify --algorithm RSA-SHA256 --input data.txt --public-key public.pem --signature-text <base64-signature> --encoding base64

  # Verify using RSA-PSS
  crypto-cli verify --algorithm RSA-PSS-SHA256 --input data.txt --public-key public.pem --signature signature.bin

  # Verify from stdin
  cat data.txt | crypto-cli verify --algorithm RSA-SHA256 --public-key public.pem --signature signature.bin`,
	RunE: runVerify,
}

var (
	verifyAlgorithm     string
	verifyInput         string
	verifyPublicKey     string
	verifySignature     string
	verifySignatureText string
	verifyEncoding      string
)

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVarP(&verifyAlgorithm, "algorithm", "a", "RSA-SHA256", "Signature algorithm (RSA-SHA256, RSA-SHA512, RSA-PSS-SHA256, RSA-PSS-SHA512)")
	verifyCmd.Flags().StringVarP(&verifyInput, "input", "i", "", "Input file to verify (if not specified, reads from stdin)")
	verifyCmd.Flags().StringVarP(&verifyPublicKey, "public-key", "k", "", "Path to RSA public key file (required)")
	verifyCmd.Flags().StringVarP(&verifySignature, "signature", "s", "", "Path to signature file")
	verifyCmd.Flags().StringVarP(&verifySignatureText, "signature-text", "t", "", "Signature as hex/base64 text (alternative to --signature)")
	verifyCmd.Flags().StringVarP(&verifyEncoding, "encoding", "e", "base64", "Encoding of signature text (hex, base64)")

	// Mark required flags
	verifyCmd.MarkFlagRequired("public-key")
}

func runVerify(cmd *cobra.Command, args []string) error {
	// Validate parameters
	if err := validateVerifyParams(); err != nil {
		return err
	}

	var signature []byte
	var err error

	// Get signature data
	if verifySignature != "" {
		signature, err = os.ReadFile(verifySignature)
		if err != nil {
			return fmt.Errorf("failed to read signature file: %w", err)
		}
	} else {
		signature, err = decodeSignature(verifySignatureText, verifyEncoding)
		if err != nil {
			return fmt.Errorf("failed to decode signature text: %w", err)
		}
	}

	// Prepare options
	opts := crypto.VerifyOptions{
		Algorithm:     crypto.SignatureAlgorithm(verifyAlgorithm),
		InputFile:     verifyInput,
		PublicKeyFile: verifyPublicKey,
		Encoding:      verifyEncoding,
	}

	// Verify signature
	var verifyErr error
	if verifyInput != "" {
		// Read input file and verify
		data, err := os.ReadFile(verifyInput)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
		verifyErr = crypto.VerifyData(data, signature, opts)
	} else {
		// Read from stdin and verify
		verifyErr = crypto.VerifyFromReader(os.Stdin, signature, opts)
	}

	// Print verification result
	fmt.Printf("Verification Details:\n")
	fmt.Printf("Algorithm: %s\n", verifyAlgorithm)
	if verifyInput != "" {
		fmt.Printf("Input file: %s\n", verifyInput)
	} else {
		fmt.Printf("Input: stdin\n")
	}
	fmt.Printf("Public key: %s\n", verifyPublicKey)
	if verifySignature != "" {
		fmt.Printf("Signature file: %s\n", verifySignature)
	} else {
		fmt.Printf("Signature text: provided as %s\n", verifyEncoding)
	}
	fmt.Printf("Signature size: %d bytes\n", len(signature))
	fmt.Println()

	if verifyErr != nil {
		fmt.Printf("❌ VERIFICATION FAILED: %v\n", verifyErr)
		return fmt.Errorf("signature verification failed: %w", verifyErr)
	} else {
		fmt.Printf("✅ VERIFICATION SUCCESSFUL: Signature is valid!\n")
	}

	return nil
}

func validateVerifyParams() error {
	// Validate algorithm
	validAlgorithms := []string{"RSA-SHA256", "RSA-SHA512", "RSA-PSS-SHA256", "RSA-PSS-SHA512"}
	if !contains(validAlgorithms, verifyAlgorithm) {
		return fmt.Errorf("invalid algorithm: %s (must be one of: %s)", verifyAlgorithm, strings.Join(validAlgorithms, ", "))
	}

	// Validate public key file exists
	if _, err := os.Stat(verifyPublicKey); os.IsNotExist(err) {
		return fmt.Errorf("public key file does not exist: %s", verifyPublicKey)
	}

	// Validate input file if specified
	if verifyInput != "" {
		if _, err := os.Stat(verifyInput); os.IsNotExist(err) {
			return fmt.Errorf("input file does not exist: %s", verifyInput)
		}
	}

	// Validate that either signature file or signature text is provided
	if verifySignature == "" && verifySignatureText == "" {
		return fmt.Errorf("either --signature or --signature-text must be provided")
	}

	if verifySignature != "" && verifySignatureText != "" {
		return fmt.Errorf("cannot specify both --signature and --signature-text")
	}

	// Validate signature file if specified
	if verifySignature != "" {
		if _, err := os.Stat(verifySignature); os.IsNotExist(err) {
			return fmt.Errorf("signature file does not exist: %s", verifySignature)
		}
	}

	// Validate encoding for signature text
	if verifySignatureText != "" {
		validEncodings := []string{"hex", "base64"}
		if !contains(validEncodings, verifyEncoding) {
			return fmt.Errorf("invalid encoding: %s (must be one of: %s)", verifyEncoding, strings.Join(validEncodings, ", "))
		}
	}

	return nil
}

func decodeSignature(signatureText, encoding string) ([]byte, error) {
	switch encoding {
	case "hex":
		return hex.DecodeString(signatureText)
	case "base64":
		return base64.StdEncoding.DecodeString(signatureText)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}
