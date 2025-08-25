package crypto_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cristianino/crypto-cli/internal/crypto"
)

// TestEncryptDecryptFile tests the complete encrypt/decrypt cycle
func TestEncryptDecryptFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "crypto_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test data
	originalData := []byte("Hello, this is a test file for encryption and decryption!")
	password := "testpassword123"
	salt := "testsalt456"

	// Create input file
	inputFile := filepath.Join(tempDir, "input.txt")
	if err := os.WriteFile(inputFile, originalData, 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	// Test different key sizes
	keySizes := []int{128, 192, 256}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize), func(t *testing.T) {
			encryptedFile := filepath.Join(tempDir, fmt.Sprintf("encrypted_%d.bin", keySize))
			decryptedFile := filepath.Join(tempDir, fmt.Sprintf("decrypted_%d.txt", keySize))

			// Test encryption
			err := crypto.EncryptFile(password, salt, keySize, inputFile, encryptedFile)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify encrypted file exists and is different from original
			encryptedData, err := os.ReadFile(encryptedFile)
			if err != nil {
				t.Fatalf("Failed to read encrypted file: %v", err)
			}

			if bytes.Equal(originalData, encryptedData) {
				t.Error("Encrypted data should be different from original data")
			}

			// Verify encrypted file is longer (due to IV and padding)
			if len(encryptedData) <= len(originalData) {
				t.Error("Encrypted file should be longer than original due to IV and padding")
			}

			// Test decryption
			err = crypto.DecryptFile(password, salt, keySize, encryptedFile, decryptedFile)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify decrypted data matches original
			decryptedData, err := os.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			if !bytes.Equal(originalData, decryptedData) {
				t.Error("Decrypted data does not match original data")
			}
		})
	}
}

// TestEncryptFileErrors tests error handling in EncryptFile
func TestEncryptFileErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "crypto_error_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	validInputFile := filepath.Join(tempDir, "valid_input.txt")
	if err := os.WriteFile(validInputFile, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to create valid input file: %v", err)
	}

	tests := []struct {
		name       string
		password   string
		salt       string
		keySize    int
		inputPath  string
		outputPath string
		wantError  bool
	}{
		{
			name:       "Invalid key size",
			password:   "password",
			salt:       "salt",
			keySize:    64, // Invalid size
			inputPath:  validInputFile,
			outputPath: filepath.Join(tempDir, "output.bin"),
			wantError:  true,
		},
		{
			name:       "Non-existent input file",
			password:   "password",
			salt:       "salt",
			keySize:    256,
			inputPath:  filepath.Join(tempDir, "nonexistent.txt"),
			outputPath: filepath.Join(tempDir, "output.bin"),
			wantError:  true,
		},
		{
			name:       "Invalid output path",
			password:   "password",
			salt:       "salt",
			keySize:    256,
			inputPath:  validInputFile,
			outputPath: "/invalid/path/output.bin",
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.EncryptFile(tt.password, tt.salt, tt.keySize, tt.inputPath, tt.outputPath)
			if (err != nil) != tt.wantError {
				t.Errorf("EncryptFile() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestDecryptFileErrors tests error handling in DecryptFile
func TestDecryptFileErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "crypto_decrypt_error_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a properly encrypted file for some tests
	validInputFile := filepath.Join(tempDir, "input.txt")
	validEncryptedFile := filepath.Join(tempDir, "encrypted.bin")
	testData := []byte("test data for decryption errors")

	if err := os.WriteFile(validInputFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	if err := crypto.EncryptFile("password", "salt", 256, validInputFile, validEncryptedFile); err != nil {
		t.Fatalf("Failed to create valid encrypted file: %v", err)
	}

	// Create an invalid encrypted file (too short)
	invalidEncryptedFile := filepath.Join(tempDir, "invalid.bin")
	if err := os.WriteFile(invalidEncryptedFile, []byte("too short"), 0644); err != nil {
		t.Fatalf("Failed to create invalid encrypted file: %v", err)
	}

	// Create a file with invalid padding
	invalidPaddingFile := filepath.Join(tempDir, "invalid_padding.bin")
	invalidData := make([]byte, 32) // 16 bytes IV + 16 bytes data
	rand.Read(invalidData)
	if err := os.WriteFile(invalidPaddingFile, invalidData, 0644); err != nil {
		t.Fatalf("Failed to create invalid padding file: %v", err)
	}

	tests := []struct {
		name       string
		password   string
		salt       string
		keySize    int
		inputPath  string
		outputPath string
		wantError  bool
	}{
		{
			name:       "Wrong password",
			password:   "wrongpassword",
			salt:       "salt",
			keySize:    256,
			inputPath:  validEncryptedFile,
			outputPath: filepath.Join(tempDir, "output.txt"),
			wantError:  true,
		},
		{
			name:       "Wrong salt",
			password:   "password",
			salt:       "wrongsalt",
			keySize:    256,
			inputPath:  validEncryptedFile,
			outputPath: filepath.Join(tempDir, "output.txt"),
			wantError:  true,
		},
		{
			name:       "Wrong key size",
			password:   "password",
			salt:       "salt",
			keySize:    128, // Wrong size
			inputPath:  validEncryptedFile,
			outputPath: filepath.Join(tempDir, "output.txt"),
			wantError:  true,
		},
		{
			name:       "Non-existent input file",
			password:   "password",
			salt:       "salt",
			keySize:    256,
			inputPath:  filepath.Join(tempDir, "nonexistent.bin"),
			outputPath: filepath.Join(tempDir, "output.txt"),
			wantError:  true,
		},
		{
			name:       "File too short",
			password:   "password",
			salt:       "salt",
			keySize:    256,
			inputPath:  invalidEncryptedFile,
			outputPath: filepath.Join(tempDir, "output.txt"),
			wantError:  true,
		},
		{
			name:       "Invalid padding",
			password:   "password",
			salt:       "salt",
			keySize:    256,
			inputPath:  invalidPaddingFile,
			outputPath: filepath.Join(tempDir, "output.txt"),
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.DecryptFile(tt.password, tt.salt, tt.keySize, tt.inputPath, tt.outputPath)
			if (err != nil) != tt.wantError {
				t.Errorf("DecryptFile() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestEncryptDecryptEmptyFile tests encryption/decryption of empty files
func TestEncryptDecryptEmptyFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "crypto_empty_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create empty file
	emptyFile := filepath.Join(tempDir, "empty.txt")
	if err := os.WriteFile(emptyFile, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	encryptedFile := filepath.Join(tempDir, "encrypted_empty.bin")
	decryptedFile := filepath.Join(tempDir, "decrypted_empty.txt")

	// Encrypt empty file
	err = crypto.EncryptFile("password", "salt", 256, emptyFile, encryptedFile)
	if err != nil {
		t.Fatalf("Failed to encrypt empty file: %v", err)
	}

	// Verify encrypted file exists and has content (IV + padding)
	encryptedData, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	expectedSize := 16 + 16 // IV + one block of padding
	if len(encryptedData) != expectedSize {
		t.Errorf("Expected encrypted empty file size %d, got %d", expectedSize, len(encryptedData))
	}

	// Decrypt
	err = crypto.DecryptFile("password", "salt", 256, encryptedFile, decryptedFile)
	if err != nil {
		t.Fatalf("Failed to decrypt empty file: %v", err)
	}

	// Verify decrypted file is empty
	decryptedData, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decryptedData) != 0 {
		t.Errorf("Expected decrypted file to be empty, got %d bytes", len(decryptedData))
	}
}

// TestEncryptDecryptWithTestData tests using the shared test data files
func TestEncryptDecryptWithTestData(t *testing.T) {
	// Get the root directory to access testdata
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Find testdata directory (it should be in ../testdata relative to this test file)
	testDataDir := filepath.Join(workDir, "tests", "testdata")
	// If that doesn't exist, try from the test execution directory
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		testDataDir = filepath.Join(workDir, "..", "testdata")
	}

	tempDir, err := os.MkdirTemp("", "crypto_testdata_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFiles := []struct {
		name string
		file string
	}{
		{"small_file", "small_file.txt"},
		{"text_file", "text_file.txt"},
		{"empty_file", "empty_file.txt"},
	}

	for _, tf := range testFiles {
		t.Run(tf.name, func(t *testing.T) {
			inputFile := filepath.Join(testDataDir, tf.file)
			encryptedFile := filepath.Join(tempDir, tf.name+"_encrypted.bin")
			decryptedFile := filepath.Join(tempDir, tf.name+"_decrypted.txt")

			// Skip if testdata file doesn't exist (for CI environments)
			if _, err := os.Stat(inputFile); os.IsNotExist(err) {
				t.Skipf("Test data file not found: %s", inputFile)
				return
			}

			// Read original data
			originalData, err := os.ReadFile(inputFile)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Encrypt
			err = crypto.EncryptFile("testpass", "testsalt", 256, inputFile, encryptedFile)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			err = crypto.DecryptFile("testpass", "testsalt", 256, encryptedFile, decryptedFile)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify
			decryptedData, err := os.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			if !bytes.Equal(originalData, decryptedData) {
				t.Error("Decrypted data does not match original data")
			}
		})
	}
}

// BenchmarkEncryptFile benchmarks the encryption performance
func BenchmarkEncryptFile(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "crypto_bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test file (1KB)
	testData := make([]byte, 1024)
	rand.Read(testData)
	inputFile := filepath.Join(tempDir, "bench_input.txt")
	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputFile := filepath.Join(tempDir, fmt.Sprintf("bench_output_%d.bin", i))
		err := crypto.EncryptFile("password", "salt", 256, inputFile, outputFile)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkDecryptFile benchmarks the decryption performance
func BenchmarkDecryptFile(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "crypto_bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create and encrypt test file (1KB)
	testData := make([]byte, 1024)
	rand.Read(testData)
	inputFile := filepath.Join(tempDir, "bench_input.txt")
	encryptedFile := filepath.Join(tempDir, "bench_encrypted.bin")

	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	if err := crypto.EncryptFile("password", "salt", 256, inputFile, encryptedFile); err != nil {
		b.Fatalf("Failed to encrypt test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputFile := filepath.Join(tempDir, fmt.Sprintf("bench_decrypted_%d.txt", i))
		err := crypto.DecryptFile("password", "salt", 256, encryptedFile, outputFile)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// TestGenerateHMAC tests HMAC generation with different algorithms and encodings
func TestGenerateHMAC(t *testing.T) {
	// Create a temporary test file
	tempDir, err := os.MkdirTemp("", "hmac_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testData := []byte("Hello, this is a test message for HMAC!")
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	testCases := []struct {
		algorithm string
		key       string
		encoding  string
		expected  string // We'll compute expected values
	}{
		{"sha256", "secret", "hex", ""},
		{"sha512", "secret", "hex", ""},
		{"sha1", "secret", "hex", ""},
		{"sha256", "secret", "base64", ""},
		{"sha3-256", "secret", "hex", ""},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_%s", tc.algorithm, tc.encoding), func(t *testing.T) {
			result, err := crypto.GenerateHMAC(tc.algorithm, tc.key, tc.encoding, testFile)
			if err != nil {
				t.Fatalf("GenerateHMAC failed: %v", err)
			}

			// Verify result is not empty
			if result == "" {
				t.Errorf("HMAC result is empty")
			}

			// Verify encoding format
			switch tc.encoding {
			case "hex":
				if len(result)%2 != 0 {
					t.Errorf("Hex encoding should have even length, got %d", len(result))
				}
			case "base64":
				// Base64 should be valid (this is a basic check)
				if len(result) == 0 {
					t.Errorf("Base64 encoding should not be empty")
				}
			}

			// Test consistency - same input should produce same HMAC
			result2, err := crypto.GenerateHMAC(tc.algorithm, tc.key, tc.encoding, testFile)
			if err != nil {
				t.Fatalf("Second GenerateHMAC failed: %v", err)
			}
			if result != result2 {
				t.Errorf("HMAC results should be consistent: %s != %s", result, result2)
			}

			// Test different key produces different HMAC
			result3, err := crypto.GenerateHMAC(tc.algorithm, tc.key+"different", tc.encoding, testFile)
			if err != nil {
				t.Fatalf("Third GenerateHMAC failed: %v", err)
			}
			if result == result3 {
				t.Errorf("Different keys should produce different HMACs")
			}
		})
	}
}

// TestGenerateHMACFromStdin tests HMAC generation from stdin (empty file path)
func TestGenerateHMACFromStdin(t *testing.T) {
	// We can't easily test stdin in unit tests, but we can test the empty filePath case
	// by temporarily redirecting os.Stdin (this is more complex, so we'll skip for now)
	// This would be better tested in integration tests
	t.Skip("Stdin testing requires integration test setup")
}

// TestGenerateHMACErrors tests error cases
func TestGenerateHMACErrors(t *testing.T) {
	// Test unsupported algorithm
	_, err := crypto.GenerateHMAC("unsupported", "key", "hex", "nonexistent.txt")
	if err == nil || err.Error() != "unsupported algorithm: unsupported" {
		t.Errorf("Expected unsupported algorithm error, got: %v", err)
	}

	// Test unsupported encoding
	_, err = crypto.GenerateHMAC("sha256", "key", "unsupported", "nonexistent.txt")
	if err == nil || err.Error() != "unsupported encoding: unsupported" {
		t.Errorf("Expected unsupported encoding error, got: %v", err)
	}

	// Test nonexistent file
	_, err = crypto.GenerateHMAC("sha256", "key", "hex", "nonexistent.txt")
	if err == nil {
		t.Errorf("Expected file not found error")
	}
}

// BenchmarkGenerateHMAC benchmarks HMAC generation performance
func BenchmarkGenerateHMAC(b *testing.B) {
	// Create a temporary test file with 1KB of data
	tempDir, err := os.MkdirTemp("", "hmac_bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testData := make([]byte, 1024)
	rand.Read(testData)
	testFile := filepath.Join(tempDir, "bench_test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	algorithms := []string{"sha256", "sha512", "sha1"}
	for _, alg := range algorithms {
		b.Run(alg, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := crypto.GenerateHMAC(alg, "benchmarkkey", "hex", testFile)
				if err != nil {
					b.Fatalf("HMAC generation failed: %v", err)
				}
			}
		})
	}
}
