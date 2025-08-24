package cmd

import (
	"fmt"
	"log"

	"github.com/cristianino/crypto-cli/internal/crypto"

	"github.com/spf13/cobra"
)

var (
	prngType     string
	prngSize     int
	prngEncoding string
	prngMin      int64
	prngMax      int64
)

// prngCmd represents the prng command
var prngCmd = &cobra.Command{
	Use:   "prng",
	Short: "Generate pseudo-random values",
	Long: `Generate pseudo-random values of different types:

Examples:
  crypto-cli prng --type bytes --size 16 --encoding hex
  crypto-cli prng --type uuid
  crypto-cli prng --type int --size 8
`,
	Run: func(cmd *cobra.Command, args []string) {
		output, err := crypto.GeneratePRNG(prngType, prngSize, prngEncoding, prngMin, prngMax)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(output)
	},
}

func init() {
	rootCmd.AddCommand(prngCmd)

	prngCmd.Flags().StringVarP(&prngType, "type", "t", "bytes", "Type of random value: bytes|int|uuid")
	prngCmd.Flags().IntVarP(&prngSize, "size", "s", 16, "Size (for bytes or int)")
	prngCmd.Flags().StringVarP(&prngEncoding, "encoding", "e", "hex", "Encoding for output: hex|base64")
	prngCmd.Flags().Int64Var(&prngMin, "min", 0, "Minimum value (for int type)")
	prngCmd.Flags().Int64Var(&prngMax, "max", 0, "Maximum value (for int type)")
}
