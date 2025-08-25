package cmd

import (
	"fmt"
	"log"

	"github.com/cristianino/crypto-cli/internal/crypto"

	"github.com/spf13/cobra"
)

var (
	decipherPassword string
	decipherSalt     string
	decipherSize     int
	decipherInput    string
	decipherOutput   string
)

// decipherCmd represents the decipher command
var decipherCmd = &cobra.Command{
	Use:   "decipher",
	Short: "Decrypt a file using AES",
	Long: `Decrypt a file that was encrypted using AES encryption with CBC mode.
The key is derived using scrypt with the provided password and salt.

Examples:
  crypto-cli decipher --password mypass --salt mysalt --size 256 --input encrypted.bin --output decrypted.txt
  crypto-cli decipher -p mypass -s mysalt -z 128 -i encrypted_image.bin -o image.png
`,
	Run: func(cmd *cobra.Command, args []string) {
		if decipherInput == "" {
			log.Fatal("input file is required")
		}
		if decipherOutput == "" {
			log.Fatal("output file is required")
		}
		if decipherPassword == "" {
			log.Fatal("password is required")
		}
		if decipherSalt == "" {
			log.Fatal("salt is required")
		}

		// Validate key size
		if decipherSize != 128 && decipherSize != 192 && decipherSize != 256 {
			log.Fatal("key size must be 128, 192, or 256 bits")
		}

		err := crypto.DecryptFile(decipherPassword, decipherSalt, decipherSize, decipherInput, decipherOutput)
		if err != nil {
			log.Fatalf("decryption failed: %v", err)
		}

		fmt.Printf("File decrypted successfully: %s -> %s\n", decipherInput, decipherOutput)
	},
}

func init() {
	rootCmd.AddCommand(decipherCmd)

	decipherCmd.Flags().StringVarP(&decipherPassword, "password", "p", "", "Password for key derivation (required)")
	decipherCmd.Flags().StringVarP(&decipherSalt, "salt", "s", "", "Salt for key derivation (required)")
	decipherCmd.Flags().IntVarP(&decipherSize, "size", "z", 256, "Key size in bits (128, 192, or 256)")
	decipherCmd.Flags().StringVarP(&decipherInput, "input", "i", "", "Input file to decrypt (required)")
	decipherCmd.Flags().StringVarP(&decipherOutput, "output", "o", "", "Output file for decrypted data (required)")

	decipherCmd.MarkFlagRequired("password")
	decipherCmd.MarkFlagRequired("salt")
	decipherCmd.MarkFlagRequired("input")
	decipherCmd.MarkFlagRequired("output")
}
