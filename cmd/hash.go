package cmd

import (
	"fmt"
	"log"

	"github.com/cristianino/crypto-cli/internal/crypto"

	"github.com/spf13/cobra"
)

var (
	hashAlgorithm string
	hashEncoding  string
	hashFile      string
)

// hashCmd represents the hash command
var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Generate a hash of a file",
	Long: `Generate a hash of a file using different algorithms.

Examples:
  crypto-cli hash --algorithm sha256 --file ./data.txt --encoding hex
  crypto-cli hash -a sha512 -f ./image.png -e base64
`,
	Run: func(cmd *cobra.Command, args []string) {
		output, err := crypto.GenerateHash(hashAlgorithm, hashEncoding, hashFile)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(output)
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)

	hashCmd.Flags().StringVarP(&hashAlgorithm, "algorithm", "a", "sha256", "Hash algorithm: sha256|sha512|sha1|sha3-256|sha3-512")
	hashCmd.Flags().StringVarP(&hashEncoding, "encoding", "e", "hex", "Output encoding: hex|base64")
	hashCmd.Flags().StringVarP(&hashFile, "file", "f", "", "Input file to hash")
	hashCmd.MarkFlagRequired("file")
}
