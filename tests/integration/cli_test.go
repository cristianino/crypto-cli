package integration_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLIEncryptDecryptE2E tests the complete end-to-end CLI workflow
func TestCLIEncryptDecryptE2E(t *testing.T) {
	// Skip if we don't have the binary
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_e2e_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test data
	testData := "End-to-end test for crypto-cli!"
	inputFile := filepath.Join(tempDir, "input.txt")
	encryptedFile := filepath.Join(tempDir, "encrypted.bin")
	decryptedFile := filepath.Join(tempDir, "decrypted.txt")

	// Create input file
	if err := os.WriteFile(inputFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	// Test encryption
	encryptCmd := exec.Command(binaryPath, "cipher",
		"--password", "e2etest",
		"--salt", "e2esalt",
		"--size", "256",
		"--input", inputFile,
		"--output", encryptedFile,
	)

	encryptOutput, err := encryptCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Encryption command failed: %v, output: %s", err, string(encryptOutput))
	}

	// Verify encryption output message
	if !strings.Contains(string(encryptOutput), "File encrypted successfully") {
		t.Errorf("Expected success message in encrypt output: %s", string(encryptOutput))
	}

	// Verify encrypted file exists and is different
	encryptedData, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	if bytes.Equal([]byte(testData), encryptedData) {
		t.Error("Encrypted file should be different from original")
	}

	// Test decryption
	decryptCmd := exec.Command(binaryPath, "decipher",
		"--password", "e2etest",
		"--salt", "e2esalt",
		"--size", "256",
		"--input", encryptedFile,
		"--output", decryptedFile,
	)

	decryptOutput, err := decryptCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Decryption command failed: %v, output: %s", err, string(decryptOutput))
	}

	// Verify decryption output message
	if !strings.Contains(string(decryptOutput), "File decrypted successfully") {
		t.Errorf("Expected success message in decrypt output: %s", string(decryptOutput))
	}

	// Verify decrypted content
	decryptedData, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedData) != testData {
		t.Errorf("Decrypted data doesn't match original. Expected: %s, Got: %s", testData, string(decryptedData))
	}
}

// TestCLIMultipleKeySizes tests encryption/decryption with different key sizes
func TestCLIMultipleKeySizes(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_keysize_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testData := "Testing different key sizes!"
	inputFile := filepath.Join(tempDir, "input.txt")
	if err := os.WriteFile(inputFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	keySizes := []string{"128", "192", "256"}

	for _, keySize := range keySizes {
		t.Run("KeySize_"+keySize, func(t *testing.T) {
			encryptedFile := filepath.Join(tempDir, "encrypted_"+keySize+".bin")
			decryptedFile := filepath.Join(tempDir, "decrypted_"+keySize+".txt")

			// Encrypt
			encryptCmd := exec.Command(binaryPath, "cipher",
				"-p", "testpass",
				"-s", "testsalt",
				"-z", keySize,
				"-i", inputFile,
				"-o", encryptedFile,
			)

			if err := encryptCmd.Run(); err != nil {
				t.Fatalf("Encryption failed for key size %s: %v", keySize, err)
			}

			// Decrypt
			decryptCmd := exec.Command(binaryPath, "decipher",
				"-p", "testpass",
				"-s", "testsalt",
				"-z", keySize,
				"-i", encryptedFile,
				"-o", decryptedFile,
			)

			if err := decryptCmd.Run(); err != nil {
				t.Fatalf("Decryption failed for key size %s: %v", keySize, err)
			}

			// Verify
			decryptedData, err := os.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			if string(decryptedData) != testData {
				t.Errorf("Data mismatch for key size %s", keySize)
			}
		})
	}
}

// TestCLIErrorHandling tests CLI error conditions
func TestCLIErrorHandling(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_error_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	validFile := filepath.Join(tempDir, "valid.txt")
	if err := os.WriteFile(validFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create valid file: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errText string
	}{
		{
			name:    "Missing required flag",
			args:    []string{"cipher", "--password", "pass"},
			wantErr: true,
			errText: "required",
		},
		{
			name:    "Invalid key size",
			args:    []string{"cipher", "-p", "pass", "-s", "salt", "-z", "64", "-i", validFile, "-o", "out.bin"},
			wantErr: true,
			errText: "key size must be",
		},
		{
			name:    "Non-existent input file",
			args:    []string{"cipher", "-p", "pass", "-s", "salt", "-i", "nonexistent.txt", "-o", "out.bin"},
			wantErr: true,
			errText: "failed to open input file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			output, err := cmd.CombinedOutput()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but command succeeded. Output: %s", string(output))
				} else if !strings.Contains(strings.ToLower(string(output)), strings.ToLower(tt.errText)) {
					t.Errorf("Expected error containing '%s', got: %s", tt.errText, string(output))
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v, output: %s", err, string(output))
			}
		})
	}
}

// TestCLIWithTestData tests CLI with shared test data files
func TestCLIWithTestData(t *testing.T) {
	binaryPath := getBinaryPath(t)

	// Get project root directory
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	projectRoot := filepath.Join(workDir, "..", "..")
	testDataDir := filepath.Join(projectRoot, "tests", "testdata")

	tempDir, err := os.MkdirTemp("", "cli_testdata_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFiles := []string{"small_file.txt", "text_file.txt"}

	for _, testFile := range testFiles {
		t.Run(testFile, func(t *testing.T) {
			inputFile := filepath.Join(testDataDir, testFile)
			encryptedFile := filepath.Join(tempDir, testFile+"_encrypted.bin")
			decryptedFile := filepath.Join(tempDir, testFile+"_decrypted.txt")

			// Skip if test file doesn't exist
			if _, err := os.Stat(inputFile); os.IsNotExist(err) {
				t.Skipf("Test data file not found: %s", inputFile)
				return
			}

			// Read original data
			originalData, err := os.ReadFile(inputFile)
			if err != nil {
				t.Fatalf("Failed to read original file: %v", err)
			}

			// Encrypt
			encryptCmd := exec.Command(binaryPath, "cipher",
				"--password", "testdata_pass",
				"--salt", "testdata_salt",
				"--size", "256",
				"--input", inputFile,
				"--output", encryptedFile,
			)

			if err := encryptCmd.Run(); err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			decryptCmd := exec.Command(binaryPath, "decipher",
				"--password", "testdata_pass",
				"--salt", "testdata_salt",
				"--size", "256",
				"--input", encryptedFile,
				"--output", decryptedFile,
			)

			if err := decryptCmd.Run(); err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify
			decryptedData, err := os.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			if !bytes.Equal(originalData, decryptedData) {
				t.Error("Decrypted data doesn't match original")
			}
		})
	}
}

// TestCLIWrongCredentials tests behavior with wrong password/salt
func TestCLIWrongCredentials(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_wrong_creds_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create and encrypt a file
	inputFile := filepath.Join(tempDir, "secret.txt")
	encryptedFile := filepath.Join(tempDir, "secret_encrypted.bin")
	decryptedFile := filepath.Join(tempDir, "secret_decrypted.txt")

	if err := os.WriteFile(inputFile, []byte("secret data"), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	// Encrypt with correct credentials
	encryptCmd := exec.Command(binaryPath, "cipher",
		"--password", "correct_pass",
		"--salt", "correct_salt",
		"--size", "256",
		"--input", inputFile,
		"--output", encryptedFile,
	)

	if err := encryptCmd.Run(); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong password
	decryptCmd := exec.Command(binaryPath, "decipher",
		"--password", "wrong_pass",
		"--salt", "correct_salt",
		"--size", "256",
		"--input", encryptedFile,
		"--output", decryptedFile,
	)

	output, err := decryptCmd.CombinedOutput()
	if err == nil {
		t.Error("Expected decryption to fail with wrong password")
	}

	if !strings.Contains(string(output), "decryption failed") {
		t.Errorf("Expected 'decryption failed' in error output, got: %s", string(output))
	}
}

// getBinaryPath returns the path to the crypto-cli binary
func getBinaryPath(t *testing.T) string {
	// Try to find the binary in common locations
	possiblePaths := []string{
		"../../crypto-cli",    // From tests/integration
		"../../../crypto-cli", // Alternative path
		"crypto-cli",          // In PATH
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		// Also try with .exe extension for Windows
		if _, err := os.Stat(path + ".exe"); err == nil {
			return path + ".exe"
		}
	}

	// Try to build it
	buildCmd := exec.Command("go", "build", "-o", "crypto-cli", "../../main.go")
	if err := buildCmd.Run(); err != nil {
		t.Skipf("Could not find or build crypto-cli binary: %v", err)
	}

	return "./crypto-cli"
}
