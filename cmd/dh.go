package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/cristianino/crypto-cli/internal/crypto"

	"github.com/spf13/cobra"
)

var (
	dhEncoding               string
	dhMode                   string
	dhPrime                  string
	dhPrimeEncoding          string
	dhGenerator              string
	dhGeneratorEncoding      string
	dhPrivateKey             string
	dhPrivateKeyEncoding     string
	dhOtherPublicKey         string
	dhOtherPublicKeyEncoding string
	dhOutputFile             string
)

// dhCmd represents the Diffie-Hellman command
var dhCmd = &cobra.Command{
	Use:   "dh",
	Short: "Generate Diffie-Hellman key pairs and compute shared secrets",
	Long: `Generate Diffie-Hellman key pairs for secure key exchange or compute shared secrets.

Diffie-Hellman is a method for two parties to establish a shared secret over an
insecure communication channel. This implementation uses the standard 2048-bit
MODP Group (similar to RFC 5114).

Modes:
  generate: Generate a new key pair (default)
  compute:  Compute shared secret using existing keys

Examples:
  # Generate new key pair
  crypto-cli dh --mode generate --encoding hex

  # Generate key pair with base64 encoding  
  crypto-cli dh --mode generate --encoding base64 --output keys.json

  # Compute shared secret
  crypto-cli dh --mode compute \
    --prime <prime> --prime-encoding hex \
    --generator <generator> --generator-encoding hex \
    --private-key <your-private-key> --private-key-encoding hex \
    --other-public-key <their-public-key> --other-public-key-encoding hex \
    --encoding hex
`,
	Run: func(cmd *cobra.Command, args []string) {
		switch dhMode {
		case "generate":
			generateKeys()
		case "compute":
			computeSecret()
		default:
			log.Fatalf("Invalid mode: %s. Use 'generate' or 'compute'", dhMode)
		}
	},
}

func generateKeys() {
	result, err := crypto.GenerateDiffieHellmanKeys(dhEncoding)
	if err != nil {
		log.Fatalf("Failed to generate Diffie-Hellman keys: %v", err)
	}

	if dhOutputFile != "" {
		// Save to file as JSON
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal result: %v", err)
		}

		if err := os.WriteFile(dhOutputFile, data, 0644); err != nil {
			log.Fatalf("Failed to write output file: %v", err)
		}

		fmt.Printf("Diffie-Hellman keys saved to: %s\n", dhOutputFile)
	} else {
		// Print to stdout as JSON
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal result: %v", err)
		}
		fmt.Println(string(data))
	}
}

func computeSecret() {
	// Validate required parameters
	if dhPrime == "" {
		log.Fatal("--prime is required for compute mode")
	}
	if dhGenerator == "" {
		log.Fatal("--generator is required for compute mode")
	}
	if dhPrivateKey == "" {
		log.Fatal("--private-key is required for compute mode")
	}
	if dhOtherPublicKey == "" {
		log.Fatal("--other-public-key is required for compute mode")
	}

	params := crypto.DiffieHellmanParams{
		Prime:                  dhPrime,
		PrimeEncoding:          dhPrimeEncoding,
		Generator:              dhGenerator,
		GeneratorEncoding:      dhGeneratorEncoding,
		PrivateKey:             dhPrivateKey,
		PrivateKeyEncoding:     dhPrivateKeyEncoding,
		OtherPublicKey:         dhOtherPublicKey,
		OtherPublicKeyEncoding: dhOtherPublicKeyEncoding,
	}

	result, err := crypto.ComputeDiffieHellmanSecret(params, dhEncoding)
	if err != nil {
		log.Fatalf("Failed to compute shared secret: %v", err)
	}

	if dhOutputFile != "" {
		// Save to file as JSON
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal result: %v", err)
		}

		if err := os.WriteFile(dhOutputFile, data, 0644); err != nil {
			log.Fatalf("Failed to write output file: %v", err)
		}

		fmt.Printf("Shared secret computation result saved to: %s\n", dhOutputFile)
	} else {
		// Print to stdout as JSON
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal result: %v", err)
		}
		fmt.Println(string(data))
	}
}

func init() {
	rootCmd.AddCommand(dhCmd)

	dhCmd.Flags().StringVarP(&dhMode, "mode", "m", "generate", "Mode: generate|compute")
	dhCmd.Flags().StringVarP(&dhEncoding, "encoding", "e", "hex", "Output encoding: hex|base64")
	dhCmd.Flags().StringVarP(&dhOutputFile, "output", "o", "", "Output file (optional, prints to stdout if not specified)")

	// Parameters for compute mode
	dhCmd.Flags().StringVar(&dhPrime, "prime", "", "Prime number (for compute mode)")
	dhCmd.Flags().StringVar(&dhPrimeEncoding, "prime-encoding", "hex", "Prime encoding: hex|base64")
	dhCmd.Flags().StringVar(&dhGenerator, "generator", "", "Generator (for compute mode)")
	dhCmd.Flags().StringVar(&dhGeneratorEncoding, "generator-encoding", "hex", "Generator encoding: hex|base64")
	dhCmd.Flags().StringVar(&dhPrivateKey, "private-key", "", "Your private key (for compute mode)")
	dhCmd.Flags().StringVar(&dhPrivateKeyEncoding, "private-key-encoding", "hex", "Private key encoding: hex|base64")
	dhCmd.Flags().StringVar(&dhOtherPublicKey, "other-public-key", "", "Other party's public key (for compute mode)")
	dhCmd.Flags().StringVar(&dhOtherPublicKeyEncoding, "other-public-key-encoding", "hex", "Other public key encoding: hex|base64")
}
