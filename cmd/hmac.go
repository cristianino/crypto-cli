package cmd

import (
	"fmt"
	"log"

	"github.com/cristianino/crypto-cli/internal/crypto"

	"github.com/spf13/cobra"
)

var (
	hmacAlgorithm string
	hmacKey       string
	hmacEncoding  string
	hmacFile      string
)

// hmacCmd represents the hmac command
var hmacCmd = &cobra.Command{
	Use:   "hmac",
	Short: "Generate HMAC (Hash-based Message Authentication Code)",
	Long: `Generate HMAC for message authentication using different hash algorithms.

HMAC combines a cryptographic hash function with a secret key to provide
both data integrity and authentication. It's used to verify that a message
hasn't been tampered with and comes from the expected sender.

Examples:
  crypto-cli hmac --algorithm sha256 --key mysecret --file ./data.txt --encoding hex
  crypto-cli hmac -a sha512 -k mysecret -f ./image.png -e base64
  cat file.txt | crypto-cli hmac -a sha256 -k mysecret
  echo "hello world" | crypto-cli hmac -a sha512 -k mysecret -e base64
`,
	Run: func(cmd *cobra.Command, args []string) {
		if hmacKey == "" {
			log.Fatal("key is required for HMAC generation")
		}

		output, err := crypto.GenerateHMAC(hmacAlgorithm, hmacKey, hmacEncoding, hmacFile)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(output)
	},
}

func init() {
	rootCmd.AddCommand(hmacCmd)

	hmacCmd.Flags().StringVarP(&hmacAlgorithm, "algorithm", "a", "sha256", "HMAC algorithm: sha256|sha512|sha1|sha3-256|sha3-512")
	hmacCmd.Flags().StringVarP(&hmacKey, "key", "k", "", "Secret key for HMAC (required)")
	hmacCmd.Flags().StringVarP(&hmacEncoding, "encoding", "e", "hex", "Output encoding: hex|base64")
	hmacCmd.Flags().StringVarP(&hmacFile, "file", "f", "", "Input file to authenticate (if empty, reads from stdin)")

	// Mark the key flag as required
	hmacCmd.MarkFlagRequired("key")
}
