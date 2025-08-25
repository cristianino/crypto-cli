package cmd

import (
	"fmt"
	"log"

	"github.com/cristianino/crypto-cli/internal/crypto"

	"github.com/spf13/cobra"
)

var (
	cipherPassword string
	cipherSalt     string
	cipherSize     int
	cipherInput    string
	cipherOutput   string
)

// cipherCmd represents the cipher command
var cipherCmd = &cobra.Command{
	Use:   "cipher",
	Short: "Encrypt a file using AES",
	Long: `Encrypt a file using AES encryption with CBC mode.
The key is derived using scrypt with the provided password and salt.

Examples:
  crypto-cli cipher --password mypass --salt mysalt --size 256 --input data.txt --output encrypted.bin
  crypto-cli cipher -p mypass -s mysalt -z 128 -i image.png -o encrypted_image.bin
`,
	Run: func(cmd *cobra.Command, args []string) {
		if cipherInput == "" {
			log.Fatal("input file is required")
		}
		if cipherOutput == "" {
			log.Fatal("output file is required")
		}
		if cipherPassword == "" {
			log.Fatal("password is required")
		}
		if cipherSalt == "" {
			log.Fatal("salt is required")
		}

		// Validate key size
		if cipherSize != 128 && cipherSize != 192 && cipherSize != 256 {
			log.Fatal("key size must be 128, 192, or 256 bits")
		}

		err := crypto.EncryptFile(cipherPassword, cipherSalt, cipherSize, cipherInput, cipherOutput)
		if err != nil {
			log.Fatalf("encryption failed: %v", err)
		}

		fmt.Printf("File encrypted successfully: %s -> %s\n", cipherInput, cipherOutput)
	},
}

func init() {
	rootCmd.AddCommand(cipherCmd)

	cipherCmd.Flags().StringVarP(&cipherPassword, "password", "p", "", "Password for key derivation (required)")
	cipherCmd.Flags().StringVarP(&cipherSalt, "salt", "s", "", "Salt for key derivation (required)")
	cipherCmd.Flags().IntVarP(&cipherSize, "size", "z", 256, "Key size in bits (128, 192, or 256)")
	cipherCmd.Flags().StringVarP(&cipherInput, "input", "i", "", "Input file to encrypt (required)")
	cipherCmd.Flags().StringVarP(&cipherOutput, "output", "o", "", "Output file for encrypted data (required)")

	cipherCmd.MarkFlagRequired("password")
	cipherCmd.MarkFlagRequired("salt")
	cipherCmd.MarkFlagRequired("input")
	cipherCmd.MarkFlagRequired("output")
}
