package integration_test

import (
	"bytes"
	"encoding/json"
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

// TestCLIHMACE2E tests HMAC generation via CLI
func TestCLIHMACE2E(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "hmac_e2e_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test data
	testData := "HMAC test data for CLI integration!"
	inputFile := filepath.Join(tempDir, "input.txt")
	if err := os.WriteFile(inputFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	tests := []struct {
		name      string
		algorithm string
		key       string
		encoding  string
		expected  string // We'll validate format instead of exact value
	}{
		{"SHA256-Hex", "sha256", "testkey", "hex", "hex"},
		{"SHA512-Base64", "sha512", "testkey", "base64", "base64"},
		{"SHA1-Hex", "sha1", "testkey", "hex", "hex"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, "hmac",
				"--algorithm", test.algorithm,
				"--key", test.key,
				"--encoding", test.encoding,
				"--file", inputFile,
			)

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("HMAC command failed: %v, output: %s", err, string(output))
			}

			result := strings.TrimSpace(string(output))

			// Validate output format
			if result == "" {
				t.Errorf("HMAC output is empty")
			}

			switch test.expected {
			case "hex":
				if len(result)%2 != 0 {
					t.Errorf("Hex output should have even length, got %d", len(result))
				}
				// Check if it's valid hex (basic check)
				for _, c := range result {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						t.Errorf("Invalid hex character: %c", c)
						break
					}
				}
			case "base64":
				// Basic base64 validation (should not be empty and have reasonable length)
				if len(result) == 0 {
					t.Errorf("Base64 output should not be empty")
				}
			}

			// Test consistency - same command should produce same result
			cmd2 := exec.Command(binaryPath, "hmac",
				"--algorithm", test.algorithm,
				"--key", test.key,
				"--encoding", test.encoding,
				"--file", inputFile,
			)
			output2, err := cmd2.CombinedOutput()
			if err != nil {
				t.Fatalf("Second HMAC command failed: %v", err)
			}
			result2 := strings.TrimSpace(string(output2))

			if result != result2 {
				t.Errorf("HMAC results should be consistent: %s != %s", result, result2)
			}
		})
	}
}

// TestCLIHMACStdin tests HMAC generation from stdin
func TestCLIHMACStdin(t *testing.T) {
	binaryPath := getBinaryPath(t)

	testData := "HMAC stdin test data!"

	cmd := exec.Command(binaryPath, "hmac",
		"--algorithm", "sha256",
		"--key", "stdinkey",
		"--encoding", "hex",
	)
	cmd.Stdin = strings.NewReader(testData)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("HMAC stdin command failed: %v, output: %s", err, string(output))
	}

	result := strings.TrimSpace(string(output))

	// Validate result
	if result == "" {
		t.Errorf("HMAC output is empty")
	}

	if len(result)%2 != 0 {
		t.Errorf("Hex output should have even length, got %d", len(result))
	}
}

// TestCLIHMACShortFlags tests HMAC with short flags
func TestCLIHMACShortFlags(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "hmac_short_flags_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testData := "Short flags test!"
	inputFile := filepath.Join(tempDir, "input.txt")
	if err := os.WriteFile(inputFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	cmd := exec.Command(binaryPath, "hmac",
		"-a", "sha512",
		"-k", "shortkey",
		"-e", "base64",
		"-f", inputFile,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("HMAC short flags command failed: %v, output: %s", err, string(output))
	}

	result := strings.TrimSpace(string(output))
	if result == "" {
		t.Errorf("HMAC output is empty")
	}
}

// TestCLIHMACErrors tests HMAC error cases
func TestCLIHMACErrors(t *testing.T) {
	binaryPath := getBinaryPath(t)

	// Create a temp file for testing
	tempDir, err := os.MkdirTemp("", "hmac_error_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			"Missing Key",
			[]string{"hmac", "--algorithm", "sha256", "--file", testFile},
			"required flag(s) \"key\" not set",
		},
		{
			"Invalid Algorithm",
			[]string{"hmac", "--algorithm", "invalid", "--key", "test", "--file", testFile},
			"unsupported algorithm: invalid",
		},
		{
			"Invalid Encoding",
			[]string{"hmac", "--algorithm", "sha256", "--key", "test", "--encoding", "invalid", "--file", testFile},
			"unsupported encoding: invalid",
		},
		{
			"Nonexistent File",
			[]string{"hmac", "--algorithm", "sha256", "--key", "test", "--file", "nonexistent.txt"},
			"failed to read input",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, test.args...)
			output, err := cmd.CombinedOutput()

			// We expect these to fail
			if err == nil {
				t.Errorf("Expected command to fail, but it succeeded with output: %s", string(output))
				return
			}

			outputStr := string(output)
			if !strings.Contains(outputStr, test.expected) {
				t.Errorf("Expected error message to contain '%s', got: %s", test.expected, outputStr)
			}
		})
	}
}

// TestCLIDiffieHellmanE2E tests Diffie-Hellman key exchange via CLI
func TestCLIDiffieHellmanE2E(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "dh_e2e_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test key generation
	t.Run("KeyGeneration", func(t *testing.T) {
		encodings := []string{"hex", "base64"}

		for _, encoding := range encodings {
			t.Run("Encoding_"+encoding, func(t *testing.T) {
				cmd := exec.Command(binaryPath, "dh",
					"--mode", "generate",
					"--encoding", encoding,
				)

				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("DH key generation failed: %v, output: %s", err, string(output))
				}

				// Verify JSON structure
				var result map[string]interface{}
				if err := json.Unmarshal(output, &result); err != nil {
					t.Fatalf("Failed to parse JSON output: %v", err)
				}

				// Check required fields
				requiredFields := []string{"prime", "generator", "publicKey", "privateKey"}
				for _, field := range requiredFields {
					if _, exists := result[field]; !exists {
						t.Errorf("Missing field: %s", field)
					}
					if result[field] == "" {
						t.Errorf("Empty field: %s", field)
					}
				}

				// Secret should not be present in generation
				if secret, exists := result["secret"]; exists && secret != "" {
					t.Errorf("Secret should not be present in key generation")
				}
			})
		}
	})

	// Test complete key exchange
	t.Run("KeyExchange", func(t *testing.T) {
		// Generate Alice's keys
		aliceCmd := exec.Command(binaryPath, "dh", "--mode", "generate", "--encoding", "hex")
		aliceOutput, err := aliceCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to generate Alice's keys: %v", err)
		}

		var aliceKeys map[string]string
		if err := json.Unmarshal(aliceOutput, &aliceKeys); err != nil {
			t.Fatalf("Failed to parse Alice's keys: %v", err)
		}

		// Generate Bob's keys
		bobCmd := exec.Command(binaryPath, "dh", "--mode", "generate", "--encoding", "hex")
		bobOutput, err := bobCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to generate Bob's keys: %v", err)
		}

		var bobKeys map[string]string
		if err := json.Unmarshal(bobOutput, &bobKeys); err != nil {
			t.Fatalf("Failed to parse Bob's keys: %v", err)
		}

		// Alice computes shared secret
		aliceSecretCmd := exec.Command(binaryPath, "dh",
			"--mode", "compute",
			"--prime", aliceKeys["prime"],
			"--generator", aliceKeys["generator"],
			"--private-key", aliceKeys["privateKey"],
			"--other-public-key", bobKeys["publicKey"],
			"--encoding", "hex",
		)

		aliceSecretOutput, err := aliceSecretCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Alice failed to compute secret: %v, output: %s", err, string(aliceSecretOutput))
		}

		var aliceResult map[string]string
		if err := json.Unmarshal(aliceSecretOutput, &aliceResult); err != nil {
			t.Fatalf("Failed to parse Alice's secret result: %v", err)
		}

		// Bob computes shared secret
		bobSecretCmd := exec.Command(binaryPath, "dh",
			"--mode", "compute",
			"--prime", bobKeys["prime"],
			"--generator", bobKeys["generator"],
			"--private-key", bobKeys["privateKey"],
			"--other-public-key", aliceKeys["publicKey"],
			"--encoding", "hex",
		)

		bobSecretOutput, err := bobSecretCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Bob failed to compute secret: %v, output: %s", err, string(bobSecretOutput))
		}

		var bobResult map[string]string
		if err := json.Unmarshal(bobSecretOutput, &bobResult); err != nil {
			t.Fatalf("Failed to parse Bob's secret result: %v", err)
		}

		// Both should compute the same shared secret
		if aliceResult["secret"] != bobResult["secret"] {
			t.Errorf("Shared secrets don't match:\nAlice: %s\nBob: %s",
				aliceResult["secret"], bobResult["secret"])
		}

		// Verify secret is not empty
		if aliceResult["secret"] == "" {
			t.Errorf("Alice's shared secret is empty")
		}
		if bobResult["secret"] == "" {
			t.Errorf("Bob's shared secret is empty")
		}
	})
}

// TestCLIDiffieHellmanOutputFile tests saving DH results to file
func TestCLIDiffieHellmanOutputFile(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "dh_file_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "keys.json")

	cmd := exec.Command(binaryPath, "dh",
		"--mode", "generate",
		"--encoding", "base64",
		"--output", outputFile,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("DH file output failed: %v, output: %s", err, string(output))
	}

	// Verify success message
	if !strings.Contains(string(output), "Diffie-Hellman keys saved to:") {
		t.Errorf("Expected success message in output: %s", string(output))
	}

	// Verify file exists and has valid JSON
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Invalid JSON in output file: %v", err)
	}

	// Check required fields
	requiredFields := []string{"prime", "generator", "publicKey", "privateKey"}
	for _, field := range requiredFields {
		if _, exists := result[field]; !exists {
			t.Errorf("Missing field in file: %s", field)
		}
	}
}

// TestCLIDiffieHellmanErrors tests DH error cases
func TestCLIDiffieHellmanErrors(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			"Invalid Mode",
			[]string{"dh", "--mode", "invalid"},
			"Invalid mode: invalid",
		},
		{
			"Missing Prime in Compute",
			[]string{"dh", "--mode", "compute", "--generator", "2", "--private-key", "123", "--other-public-key", "456"},
			"--prime is required for compute mode",
		},
		{
			"Missing Generator in Compute",
			[]string{"dh", "--mode", "compute", "--prime", "123", "--private-key", "123", "--other-public-key", "456"},
			"--generator is required for compute mode",
		},
		{
			"Invalid Encoding",
			[]string{"dh", "--mode", "generate", "--encoding", "invalid"},
			"unsupported encoding: invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, test.args...)
			output, err := cmd.CombinedOutput()

			// We expect these to fail
			if err == nil {
				t.Errorf("Expected command to fail, but it succeeded with output: %s", string(output))
				return
			}

			outputStr := string(output)
			if !strings.Contains(outputStr, test.expected) {
				t.Errorf("Expected error message to contain '%s', got: %s", test.expected, outputStr)
			}
		})
	}
}


// TestKDFCommand tests the kdf command functionality
func TestKDFCommand(t *testing.T) {
binPath := getBinaryPath(t)

// Test basic scrypt functionality
cmd := exec.Command(binPath, "kdf", "--algorithm", "scrypt", "--password", "testpassword", "--salt", "testsalt123456", "--keylen", "32")
output, err := cmd.CombinedOutput()
if err != nil {
t.Fatalf("KDF scrypt command failed: %v, output: %s", err, string(output))
}

outputStr := string(output)
if !strings.Contains(outputStr, "Algorithm: scrypt") {
t.Errorf("Expected scrypt algorithm in output, got: %s", outputStr)
}
if !strings.Contains(outputStr, "Derived key (base64):") {
t.Errorf("Expected derived key in output, got: %s", outputStr)
}

// Test PBKDF2
cmd = exec.Command(binPath, "kdf", "--algorithm", "pbkdf2-sha256", "--password", "testpassword", "--salt", "testsalt123456", "--keylen", "32", "--encoding", "hex")
output, err = cmd.CombinedOutput()
if err != nil {
t.Fatalf("KDF PBKDF2 command failed: %v, output: %s", err, string(output))
}

outputStr = string(output)
if !strings.Contains(outputStr, "Algorithm: pbkdf2-sha256") {
t.Errorf("Expected pbkdf2-sha256 algorithm in output, got: %s", outputStr)
}
if !strings.Contains(outputStr, "Derived key (hex):") {
t.Errorf("Expected derived key in hex output, got: %s", outputStr)
}

// Test invalid algorithm
cmd = exec.Command(binPath, "kdf", "--algorithm", "invalid", "--password", "testpassword", "--salt", "testsalt123456", "--keylen", "32")
output, err = cmd.CombinedOutput()
if err == nil {
t.Errorf("Expected command to fail with invalid algorithm, but it succeeded with output: %s", string(output))
}

t.Logf("KDF tests passed successfully")
}

// TestKDFHelpCommand tests the kdf help command
func TestKDFHelpCommand(t *testing.T) {
binPath := getBinaryPath(t)

cmd := exec.Command(binPath, "kdf", "--help")
output, err := cmd.CombinedOutput()
if err != nil {
t.Fatalf("kdf help command failed: %v", err)
}

outputStr := string(output)
expectedStrings := []string{
"--algorithm",
"--password",
"--salt",
"--keylen",
"scrypt",
"pbkdf2-sha256",
"pbkdf2-sha512",
}

for _, expected := range expectedStrings {
if !strings.Contains(outputStr, expected) {
t.Errorf("Help output should contain '%s'\nActual output: %s", expected, outputStr)
}
}
}
