package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "crypto-cli",
	Short: "A CLI for practicing cryptography in Go",
	Long:  "crypto-cli is a command-line tool to explore cryptographic primitives such as PRNG, ciphers, hashes, signatures, and more.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
