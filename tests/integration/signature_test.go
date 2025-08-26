package integration_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLISignAndVerify tests the sign and verify commands together
func TestCLISignAndVerify(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_signature_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// First, generate a key pair for testing
	keyCmd := exec.Command(binaryPath, "keypair",
		"--type", "rsa",
		"--modulus", "2048",
		"--format", "pem",
		"--output", tempDir,
	)

	keyOutput, err := keyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Keypair generation failed: %v, output: %s", err, string(keyOutput))
	}

	// Create test data file
	testFile := filepath.Join(tempDir, "test.txt")
	testData := "This is test data for digital signature CLI testing!"
	err = os.WriteFile(testFile, []byte(testData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")
	signatureFile := filepath.Join(tempDir, "signature.bin")

	tests := []struct {
		name      string
		algorithm string
	}{
		{"RSA-SHA256", "RSA-SHA256"},
		{"RSA-SHA512", "RSA-SHA512"},
		{"RSA-PSS-SHA256", "RSA-PSS-SHA256"},
		{"RSA-PSS-SHA512", "RSA-PSS-SHA512"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Sign the file
			signCmd := exec.Command(binaryPath, "sign",
				"--algorithm", test.algorithm,
				"--input", testFile,
				"--private-key", privateKeyPath,
				"--output", signatureFile,
			)

			signOutput, err := signCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Sign command failed: %v, output: %s", err, string(signOutput))
			}

			// Check sign output
			signOutputStr := string(signOutput)
			if !strings.Contains(signOutputStr, "Signature created successfully") {
				t.Errorf("Expected success message in sign output, got: %s", signOutputStr)
			}

			if !strings.Contains(signOutputStr, test.algorithm) {
				t.Errorf("Expected algorithm %s in sign output, got: %s", test.algorithm, signOutputStr)
			}

			// Verify signature file exists
			if _, err := os.Stat(signatureFile); os.IsNotExist(err) {
				t.Fatalf("Signature file was not created: %s", signatureFile)
			}

			// Verify the signature
			verifyCmd := exec.Command(binaryPath, "verify",
				"--algorithm", test.algorithm,
				"--input", testFile,
				"--public-key", publicKeyPath,
				"--signature", signatureFile,
			)

			verifyOutput, err := verifyCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Verify command failed: %v, output: %s", err, string(verifyOutput))
			}

			// Check verify output
			verifyOutputStr := string(verifyOutput)
			if !strings.Contains(verifyOutputStr, "VERIFICATION SUCCESSFUL") {
				t.Errorf("Expected successful verification, got: %s", verifyOutputStr)
			}

			if !strings.Contains(verifyOutputStr, test.algorithm) {
				t.Errorf("Expected algorithm %s in verify output, got: %s", test.algorithm, verifyOutputStr)
			}

			t.Logf("Successfully signed and verified using %s", test.algorithm)
		})
	}
}

// TestCLISignToStdout tests signing with stdout output
func TestCLISignToStdout(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_sign_stdout_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a key pair
	keyCmd := exec.Command(binaryPath, "keypair",
		"--type", "rsa",
		"--modulus", "2048",
		"--format", "pem",
		"--output", tempDir,
	)

	_, err = keyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Keypair generation failed: %v", err)
	}

	// Create test data file
	testFile := filepath.Join(tempDir, "test.txt")
	testData := "Test data for stdout signature!"
	err = os.WriteFile(testFile, []byte(testData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")

	tests := []struct {
		name     string
		encoding string
	}{
		{"Base64", "base64"},
		{"Hex", "hex"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Sign with stdout output
			signCmd := exec.Command(binaryPath, "sign",
				"--algorithm", "RSA-SHA256",
				"--input", testFile,
				"--private-key", privateKeyPath,
				"--encoding", test.encoding,
			)

			signOutput, err := signCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Sign command failed: %v, output: %s", err, string(signOutput))
			}

			outputStr := string(signOutput)

			// Check for success message
			if !strings.Contains(outputStr, "Signature created successfully") {
				t.Errorf("Expected success message, got: %s", outputStr)
			}

			// Check for signature data
			if !strings.Contains(outputStr, fmt.Sprintf("Signature (%s):", test.encoding)) {
				t.Errorf("Expected signature with %s encoding, got: %s", test.encoding, outputStr)
			}

			t.Logf("Successfully signed with %s encoding to stdout", test.encoding)
		})
	}
}

// TestCLISignFromStdin tests signing from stdin
func TestCLISignFromStdin(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_sign_stdin_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a key pair
	keyCmd := exec.Command(binaryPath, "keypair",
		"--type", "rsa",
		"--modulus", "2048",
		"--format", "pem",
		"--output", tempDir,
	)

	_, err = keyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Keypair generation failed: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	testData := "Test data from stdin for signature!"

	// Sign from stdin
	signCmd := exec.Command(binaryPath, "sign",
		"--algorithm", "RSA-SHA256",
		"--private-key", privateKeyPath,
		"--encoding", "base64",
	)

	signCmd.Stdin = strings.NewReader(testData)
	signOutput, err := signCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Sign command failed: %v, output: %s", err, string(signOutput))
	}

	outputStr := string(signOutput)

	// Check for success message
	if !strings.Contains(outputStr, "Signature created successfully") {
		t.Errorf("Expected success message, got: %s", outputStr)
	}

	// Check that it indicates stdin input
	if !strings.Contains(outputStr, "Input: stdin") {
		t.Errorf("Expected stdin input indication, got: %s", outputStr)
	}

	t.Log("Successfully signed from stdin")
}

// TestCLISignWithEncryptedKey tests signing with encrypted private key
func TestCLISignWithEncryptedKey(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_sign_encrypted_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate an encrypted key pair
	keyCmd := exec.Command(binaryPath, "keypair",
		"--type", "rsa",
		"--modulus", "2048",
		"--format", "pem",
		"--passphrase", "testpass123",
		"--aes-size", "256",
		"--output", tempDir,
	)

	keyOutput, err := keyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Keypair generation failed: %v, output: %s", err, string(keyOutput))
	}

	// Create test data file
	testFile := filepath.Join(tempDir, "test.txt")
	testData := "Test data for encrypted key signature!"
	err = os.WriteFile(testFile, []byte(testData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")
	signatureFile := filepath.Join(tempDir, "signature.bin")

	// Sign with correct passphrase
	signCmd := exec.Command(binaryPath, "sign",
		"--algorithm", "RSA-SHA256",
		"--input", testFile,
		"--private-key", privateKeyPath,
		"--passphrase", "testpass123",
		"--output", signatureFile,
	)

	signOutput, err := signCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Sign command failed: %v, output: %s", err, string(signOutput))
	}

	// Check that it indicates encrypted key
	signOutputStr := string(signOutput)
	if !strings.Contains(signOutputStr, "Private key encrypted: yes") {
		t.Errorf("Expected encrypted key indication, got: %s", signOutputStr)
	}

	// Verify the signature
	verifyCmd := exec.Command(binaryPath, "verify",
		"--algorithm", "RSA-SHA256",
		"--input", testFile,
		"--public-key", publicKeyPath,
		"--signature", signatureFile,
	)

	verifyOutput, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Verify command failed: %v, output: %s", err, string(verifyOutput))
	}

	// Check verification success
	verifyOutputStr := string(verifyOutput)
	if !strings.Contains(verifyOutputStr, "VERIFICATION SUCCESSFUL") {
		t.Errorf("Expected successful verification, got: %s", verifyOutputStr)
	}

	t.Log("Successfully signed with encrypted private key and verified")
}

// TestCLISignValidation tests sign command validation
func TestCLISignValidation(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "MissingPrivateKey",
			args:     []string{"sign", "--algorithm", "RSA-SHA256", "--input", "nonexistent.txt"},
			expected: "required flag(s) \"private-key\" not set",
		},
		{
			name:     "InvalidAlgorithm",
			args:     []string{"sign", "--algorithm", "INVALID", "--private-key", "key.pem"},
			expected: "invalid algorithm",
		},
		{
			name:     "NonexistentPrivateKey",
			args:     []string{"sign", "--algorithm", "RSA-SHA256", "--private-key", "nonexistent.pem"},
			expected: "private key file does not exist",
		},
		{
			name:     "NonexistentInputFile",
			args:     []string{"sign", "--algorithm", "RSA-SHA256", "--private-key", "key.pem", "--input", "nonexistent.txt"},
			expected: "input file does not exist",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, test.args...)
			output, err := cmd.CombinedOutput()

			// We expect these to fail
			if err == nil {
				t.Errorf("Expected command to fail but it succeeded. Output: %s", string(output))
				return
			}

			outputStr := string(output)
			if !strings.Contains(outputStr, test.expected) {
				t.Errorf("Expected error message to contain '%s', got: %s", test.expected, outputStr)
			}
		})
	}
}

// TestCLIVerifyValidation tests verify command validation
func TestCLIVerifyValidation(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "MissingPublicKey",
			args:     []string{"verify", "--algorithm", "RSA-SHA256", "--signature", "sig.bin"},
			expected: "required flag(s) \"public-key\" not set",
		},
		{
			name:     "MissingSignature",
			args:     []string{"verify", "--algorithm", "RSA-SHA256", "--public-key", "key.pem"},
			expected: "either --signature or --signature-text must be provided",
		},
		{
			name:     "BothSignatureOptions",
			args:     []string{"verify", "--algorithm", "RSA-SHA256", "--public-key", "key.pem", "--signature", "sig.bin", "--signature-text", "abcd"},
			expected: "cannot specify both --signature and --signature-text",
		},
		{
			name:     "InvalidAlgorithm",
			args:     []string{"verify", "--algorithm", "INVALID", "--public-key", "key.pem", "--signature", "sig.bin"},
			expected: "invalid algorithm",
		},
		{
			name:     "NonexistentPublicKey",
			args:     []string{"verify", "--algorithm", "RSA-SHA256", "--public-key", "nonexistent.pem", "--signature", "sig.bin"},
			expected: "public key file does not exist",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, test.args...)
			output, err := cmd.CombinedOutput()

			// We expect these to fail
			if err == nil {
				t.Errorf("Expected command to fail but it succeeded. Output: %s", string(output))
				return
			}

			outputStr := string(output)
			if !strings.Contains(outputStr, test.expected) {
				t.Errorf("Expected error message to contain '%s', got: %s", test.expected, outputStr)
			}
		})
	}
}
