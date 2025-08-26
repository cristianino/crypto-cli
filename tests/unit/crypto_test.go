package crypto_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestGenerateDiffieHellmanKeys tests DH key generation
func TestGenerateDiffieHellmanKeys(t *testing.T) {
	encodings := []string{"hex", "base64"}

	for _, encoding := range encodings {
		t.Run(fmt.Sprintf("Encoding_%s", encoding), func(t *testing.T) {
			result, err := crypto.GenerateDiffieHellmanKeys(encoding)
			if err != nil {
				t.Fatalf("GenerateDiffieHellmanKeys failed: %v", err)
			}

			// Verify all fields are present and not empty
			if result.Prime == "" {
				t.Errorf("Prime is empty")
			}
			if result.Generator == "" {
				t.Errorf("Generator is empty")
			}
			if result.PublicKey == "" {
				t.Errorf("PublicKey is empty")
			}
			if result.PrivateKey == "" {
				t.Errorf("PrivateKey is empty")
			}

			// Secret should not be present in key generation
			if result.Secret != "" {
				t.Errorf("Secret should be empty in key generation, got: %s", result.Secret)
			}

			// Test consistency - generating keys twice should produce different results
			result2, err := crypto.GenerateDiffieHellmanKeys(encoding)
			if err != nil {
				t.Fatalf("Second GenerateDiffieHellmanKeys failed: %v", err)
			}

			// Prime and generator should be the same (using same modp group)
			if result.Prime != result2.Prime {
				t.Errorf("Prime should be consistent across generations")
			}
			if result.Generator != result2.Generator {
				t.Errorf("Generator should be consistent across generations")
			}

			// Private and public keys should be different
			if result.PrivateKey == result2.PrivateKey {
				t.Errorf("Private keys should be different")
			}
			if result.PublicKey == result2.PublicKey {
				t.Errorf("Public keys should be different")
			}
		})
	}
}

// TestComputeDiffieHellmanSecret tests DH shared secret computation
func TestComputeDiffieHellmanSecret(t *testing.T) {
	encoding := "hex"

	// Generate keys for Alice
	aliceKeys, err := crypto.GenerateDiffieHellmanKeys(encoding)
	if err != nil {
		t.Fatalf("Failed to generate Alice's keys: %v", err)
	}

	// Generate keys for Bob
	bobKeys, err := crypto.GenerateDiffieHellmanKeys(encoding)
	if err != nil {
		t.Fatalf("Failed to generate Bob's keys: %v", err)
	}

	// Alice computes shared secret using Bob's public key
	aliceParams := crypto.DiffieHellmanParams{
		Prime:                  aliceKeys.Prime,
		PrimeEncoding:          encoding,
		Generator:              aliceKeys.Generator,
		GeneratorEncoding:      encoding,
		PrivateKey:             aliceKeys.PrivateKey,
		PrivateKeyEncoding:     encoding,
		OtherPublicKey:         bobKeys.PublicKey,
		OtherPublicKeyEncoding: encoding,
	}

	aliceResult, err := crypto.ComputeDiffieHellmanSecret(aliceParams, encoding)
	if err != nil {
		t.Fatalf("Alice failed to compute shared secret: %v", err)
	}

	// Bob computes shared secret using Alice's public key
	bobParams := crypto.DiffieHellmanParams{
		Prime:                  bobKeys.Prime,
		PrimeEncoding:          encoding,
		Generator:              bobKeys.Generator,
		GeneratorEncoding:      encoding,
		PrivateKey:             bobKeys.PrivateKey,
		PrivateKeyEncoding:     encoding,
		OtherPublicKey:         aliceKeys.PublicKey,
		OtherPublicKeyEncoding: encoding,
	}

	bobResult, err := crypto.ComputeDiffieHellmanSecret(bobParams, encoding)
	if err != nil {
		t.Fatalf("Bob failed to compute shared secret: %v", err)
	}

	// Both should compute the same shared secret
	if aliceResult.Secret != bobResult.Secret {
		t.Errorf("Shared secrets don't match:\nAlice: %s\nBob: %s", aliceResult.Secret, bobResult.Secret)
	}

	// Verify secret is not empty
	if aliceResult.Secret == "" {
		t.Errorf("Shared secret is empty")
	}
}

// TestDiffieHellmanErrors tests error cases
func TestDiffieHellmanErrors(t *testing.T) {
	// Test invalid encoding for key generation
	_, err := crypto.GenerateDiffieHellmanKeys("invalid")
	if err == nil || !strings.Contains(fmt.Sprintf("%v", err), "unsupported encoding") {
		t.Errorf("Expected unsupported encoding error, got: %v", err)
	}

	// Test invalid params for secret computation
	params := crypto.DiffieHellmanParams{
		Prime:                  "invalid",
		PrimeEncoding:          "hex",
		Generator:              "2",
		GeneratorEncoding:      "hex",
		PrivateKey:             "123",
		PrivateKeyEncoding:     "hex",
		OtherPublicKey:         "456",
		OtherPublicKeyEncoding: "hex",
	}

	_, err = crypto.ComputeDiffieHellmanSecret(params, "hex")
	if err == nil {
		t.Errorf("Expected error with invalid prime")
	}
}

// BenchmarkGenerateDiffieHellmanKeys benchmarks DH key generation
func BenchmarkGenerateDiffieHellmanKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := crypto.GenerateDiffieHellmanKeys("hex")
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

// BenchmarkComputeDiffieHellmanSecret benchmarks DH secret computation
func BenchmarkComputeDiffieHellmanSecret(b *testing.B) {
	// Setup: generate keys once
	aliceKeys, err := crypto.GenerateDiffieHellmanKeys("hex")
	if err != nil {
		b.Fatalf("Failed to generate Alice's keys: %v", err)
	}

	bobKeys, err := crypto.GenerateDiffieHellmanKeys("hex")
	if err != nil {
		b.Fatalf("Failed to generate Bob's keys: %v", err)
	}

	params := crypto.DiffieHellmanParams{
		Prime:                  aliceKeys.Prime,
		PrimeEncoding:          "hex",
		Generator:              aliceKeys.Generator,
		GeneratorEncoding:      "hex",
		PrivateKey:             aliceKeys.PrivateKey,
		PrivateKeyEncoding:     "hex",
		OtherPublicKey:         bobKeys.PublicKey,
		OtherPublicKeyEncoding: "hex",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.ComputeDiffieHellmanSecret(params, "hex")
		if err != nil {
			b.Fatalf("Secret computation failed: %v", err)
		}
	}
}

// TestGenerateKeyPair tests RSA key pair generation
func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name       string
		opts       crypto.KeyPairOptions
		shouldFail bool
	}{
		{
			name: "RSA-2048-PEM-NoPassphrase",
			opts: crypto.KeyPairOptions{
				Type:          crypto.RSA,
				ModulusLength: 2048,
				Passphrase:    "",
				Format:        crypto.PEM,
				AESKeySize:    256,
			},
			shouldFail: false,
		},
		{
			name: "RSA-3072-PEM-WithPassphrase",
			opts: crypto.KeyPairOptions{
				Type:          crypto.RSA,
				ModulusLength: 3072,
				Passphrase:    "secret123",
				Format:        crypto.PEM,
				AESKeySize:    256,
			},
			shouldFail: false,
		},
		{
			name: "RSA-4096-DER-NoPassphrase",
			opts: crypto.KeyPairOptions{
				Type:          crypto.RSA,
				ModulusLength: 4096,
				Passphrase:    "",
				Format:        crypto.DER,
				AESKeySize:    128,
			},
			shouldFail: false,
		},
		{
			name: "RSA-PSS-2048-PEM-WithPassphrase",
			opts: crypto.KeyPairOptions{
				Type:          crypto.RSAPSS,
				ModulusLength: 2048,
				Passphrase:    "mypassword",
				Format:        crypto.PEM,
				AESKeySize:    192,
			},
			shouldFail: false,
		},
		{
			name: "Invalid-ModulusLength",
			opts: crypto.KeyPairOptions{
				Type:          crypto.RSA,
				ModulusLength: 1024, // Invalid
				Passphrase:    "",
				Format:        crypto.PEM,
				AESKeySize:    256,
			},
			shouldFail: true,
		},
		{
			name: "Invalid-AESKeySize",
			opts: crypto.KeyPairOptions{
				Type:          crypto.RSA,
				ModulusLength: 2048,
				Passphrase:    "secret",
				Format:        crypto.PEM,
				AESKeySize:    512, // Invalid
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := crypto.GenerateKeyPair(tt.opts)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if keyPair == nil {
				t.Fatal("Key pair is nil")
			}

			if len(keyPair.PublicKey) == 0 {
				t.Error("Public key is empty")
			}

			if len(keyPair.PrivateKey) == 0 {
				t.Error("Private key is empty")
			}

			// Verify format-specific properties
			if tt.opts.Format == crypto.PEM {
				// PEM keys should start with -----BEGIN
				if !bytes.HasPrefix(keyPair.PublicKey, []byte("-----BEGIN PUBLIC KEY-----")) {
					t.Error("Public key doesn't start with PEM header")
				}
				if !bytes.HasPrefix(keyPair.PrivateKey, []byte("-----BEGIN")) {
					t.Error("Private key doesn't start with PEM header")
				}
			}

			t.Logf("Generated %s key pair with %d-bit modulus in %s format",
				tt.opts.Type, tt.opts.ModulusLength, tt.opts.Format)
		})
	}
}

// TestSaveKeyPairToFiles tests saving key pairs to files
func TestSaveKeyPairToFiles(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "keypair_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a key pair
	opts := crypto.KeyPairOptions{
		Type:          crypto.RSA,
		ModulusLength: 2048,
		Passphrase:    "testpass",
		Format:        crypto.PEM,
		AESKeySize:    256,
	}

	keyPair, err := crypto.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test saving to files
	err = crypto.SaveKeyPairToFiles(keyPair, tempDir, crypto.PEM)
	if err != nil {
		t.Fatalf("Failed to save key pair: %v", err)
	}

	// Verify files exist
	publicKeyPath := filepath.Join(tempDir, "public.pem")
	privateKeyPath := filepath.Join(tempDir, "private.pem")

	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Error("Public key file was not created")
	}

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}

	// Verify file contents match
	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key file: %v", err)
	}

	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}

	if !bytes.Equal(keyPair.PublicKey, publicKeyData) {
		t.Error("Public key file content doesn't match generated key")
	}

	if !bytes.Equal(keyPair.PrivateKey, privateKeyData) {
		t.Error("Private key file content doesn't match generated key")
	}

	t.Logf("Successfully saved key pair to %s", tempDir)
}

// BenchmarkGenerateKeyPair benchmarks key pair generation
func BenchmarkGenerateKeyPair(b *testing.B) {
	opts := crypto.KeyPairOptions{
		Type:          crypto.RSA,
		ModulusLength: 2048,
		Passphrase:    "",
		Format:        crypto.PEM,
		AESKeySize:    256,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.GenerateKeyPair(opts)
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

// TestSignAndVerify tests digital signature functionality
func TestSignAndVerify(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "signature_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a key pair for testing
	keyPairOpts := crypto.KeyPairOptions{
		Type:          crypto.RSA,
		ModulusLength: 2048,
		Passphrase:    "",
		Format:        crypto.PEM,
		AESKeySize:    256,
	}

	keyPair, err := crypto.GenerateKeyPair(keyPairOpts)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Save key pair to files
	err = crypto.SaveKeyPairToFiles(keyPair, tempDir, crypto.PEM)
	if err != nil {
		t.Fatalf("Failed to save key pair: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")

	// Test data
	testData := []byte("This is a test message for digital signature!")

	tests := []struct {
		name      string
		algorithm crypto.SignatureAlgorithm
	}{
		{"RSA-SHA256", crypto.RSASHA256},
		{"RSA-SHA512", crypto.RSASHA512},
		{"RSA-PSS-SHA256", crypto.RSAPSS256},
		{"RSA-PSS-SHA512", crypto.RSAPSS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign the data
			signOpts := crypto.SignOptions{
				Algorithm:      tt.algorithm,
				PrivateKeyFile: privateKeyPath,
				Passphrase:     "",
			}

			signature, err := crypto.SignData(testData, signOpts)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			if len(signature) == 0 {
				t.Error("Signature is empty")
			}

			// Verify the signature
			verifyOpts := crypto.VerifyOptions{
				Algorithm:     tt.algorithm,
				PublicKeyFile: publicKeyPath,
			}

			err = crypto.VerifyData(testData, signature, verifyOpts)
			if err != nil {
				t.Errorf("Verification failed: %v", err)
			}

			// Test verification with wrong data (should fail)
			wrongData := []byte("This is wrong data!")
			err = crypto.VerifyData(wrongData, signature, verifyOpts)
			if err == nil {
				t.Error("Verification should have failed with wrong data")
			}

			// Test verification with wrong signature (should fail)
			wrongSignature := make([]byte, len(signature))
			copy(wrongSignature, signature)
			wrongSignature[0] ^= 0xFF // Flip some bits
			err = crypto.VerifyData(testData, wrongSignature, verifyOpts)
			if err == nil {
				t.Error("Verification should have failed with wrong signature")
			}

			t.Logf("Successfully signed and verified using %s", tt.algorithm)
		})
	}
}

// TestSignAndVerifyWithEncryptedKey tests signature with encrypted private key
func TestSignAndVerifyWithEncryptedKey(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "encrypted_signature_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate an encrypted key pair
	keyPairOpts := crypto.KeyPairOptions{
		Type:          crypto.RSA,
		ModulusLength: 2048,
		Passphrase:    "testpassword123",
		Format:        crypto.PEM,
		AESKeySize:    256,
	}

	keyPair, err := crypto.GenerateKeyPair(keyPairOpts)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Save key pair to files
	err = crypto.SaveKeyPairToFiles(keyPair, tempDir, crypto.PEM)
	if err != nil {
		t.Fatalf("Failed to save key pair: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")

	// Test data
	testData := []byte("Test message with encrypted private key!")

	// Sign with correct passphrase
	signOpts := crypto.SignOptions{
		Algorithm:      crypto.RSASHA256,
		PrivateKeyFile: privateKeyPath,
		Passphrase:     "testpassword123",
	}

	signature, err := crypto.SignData(testData, signOpts)
	if err != nil {
		t.Fatalf("Signing with correct passphrase failed: %v", err)
	}

	// Verify the signature
	verifyOpts := crypto.VerifyOptions{
		Algorithm:     crypto.RSASHA256,
		PublicKeyFile: publicKeyPath,
	}

	err = crypto.VerifyData(testData, signature, verifyOpts)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	// Test signing with wrong passphrase (should fail)
	signOptsWrong := crypto.SignOptions{
		Algorithm:      crypto.RSASHA256,
		PrivateKeyFile: privateKeyPath,
		Passphrase:     "wrongpassword",
	}

	_, err = crypto.SignData(testData, signOptsWrong)
	if err == nil {
		t.Error("Signing should have failed with wrong passphrase")
	}

	// Test signing without passphrase (should fail)
	signOptsNoPass := crypto.SignOptions{
		Algorithm:      crypto.RSASHA256,
		PrivateKeyFile: privateKeyPath,
		Passphrase:     "",
	}

	_, err = crypto.SignData(testData, signOptsNoPass)
	if err == nil {
		t.Error("Signing should have failed without passphrase")
	}

	t.Log("Successfully tested encrypted private key signing")
}

// TestSignFile tests signing files
func TestSignFile(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "file_signature_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a key pair
	keyPairOpts := crypto.KeyPairOptions{
		Type:          crypto.RSA,
		ModulusLength: 2048,
		Passphrase:    "",
		Format:        crypto.PEM,
		AESKeySize:    256,
	}

	keyPair, err := crypto.GenerateKeyPair(keyPairOpts)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Save key pair to files
	err = crypto.SaveKeyPairToFiles(keyPair, tempDir, crypto.PEM)
	if err != nil {
		t.Fatalf("Failed to save key pair: %v", err)
	}

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	testData := "This is test file content for signature testing!"
	err = os.WriteFile(testFile, []byte(testData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")

	// Sign the file
	signOpts := crypto.SignOptions{
		Algorithm:      crypto.RSASHA256,
		InputFile:      testFile,
		PrivateKeyFile: privateKeyPath,
		Passphrase:     "",
	}

	signature, err := crypto.SignFile(signOpts)
	if err != nil {
		t.Fatalf("File signing failed: %v", err)
	}

	// Verify the file signature
	verifyOpts := crypto.VerifyOptions{
		Algorithm:     crypto.RSASHA256,
		InputFile:     testFile,
		PublicKeyFile: publicKeyPath,
	}

	// Save signature to file and test file verification
	signatureFile := filepath.Join(tempDir, "signature.bin")
	err = os.WriteFile(signatureFile, signature, 0644)
	if err != nil {
		t.Fatalf("Failed to write signature file: %v", err)
	}

	verifyOpts.SignatureFile = signatureFile
	err = crypto.VerifyFile(verifyOpts)
	if err != nil {
		t.Errorf("File verification failed: %v", err)
	}

	t.Log("Successfully signed and verified file")
}

// BenchmarkSignData benchmarks signing performance
func BenchmarkSignData(b *testing.B) {
	// Generate a key pair for benchmarking
	keyPairOpts := crypto.KeyPairOptions{
		Type:          crypto.RSA,
		ModulusLength: 2048,
		Passphrase:    "",
		Format:        crypto.PEM,
		AESKeySize:    256,
	}

	keyPair, err := crypto.GenerateKeyPair(keyPairOpts)
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create temporary files
	tempDir, err := os.MkdirTemp("", "benchmark_signature")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	err = crypto.SaveKeyPairToFiles(keyPair, tempDir, crypto.PEM)
	if err != nil {
		b.Fatalf("Failed to save key pair: %v", err)
	}

	privateKeyPath := filepath.Join(tempDir, "private.pem")
	testData := []byte("Benchmark test data for signature performance!")

	signOpts := crypto.SignOptions{
		Algorithm:      crypto.RSASHA256,
		PrivateKeyFile: privateKeyPath,
		Passphrase:     "",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.SignData(testData, signOpts)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}
	}
}

// TestKDFScrypt tests scrypt key derivation
func TestKDFScrypt(t *testing.T) {
	tests := []struct {
		name    string
		opts    crypto.KDFOptions
		wantErr bool
	}{
		{
			name: "Scrypt-Default-Parameters",
			opts: crypto.KDFOptions{
				Algorithm: crypto.Scrypt,
				Password:  "testpassword",
				Salt:      "testsalt",
				KeyLen:    32,
				N:         32768,
				R:         8,
				P:         1,
			},
			wantErr: false,
		},
		{
			name: "Scrypt-Custom-Parameters",
			opts: crypto.KDFOptions{
				Algorithm: crypto.Scrypt,
				Password:  "testpassword",
				Salt:      "testsalt",
				KeyLen:    64,
				N:         16384,
				R:         8,
				P:         1,
			},
			wantErr: false,
		},
		{
			name: "Scrypt-Invalid-N",
			opts: crypto.KDFOptions{
				Algorithm: crypto.Scrypt,
				Password:  "testpassword",
				Salt:      "testsalt",
				KeyLen:    32,
				N:         12345, // Not a power of 2
				R:         8,
				P:         1,
			},
			wantErr: true,
		},
		{
			name: "Scrypt-Empty-Password",
			opts: crypto.KDFOptions{
				Algorithm: crypto.Scrypt,
				Password:  "",
				Salt:      "testsalt",
				KeyLen:    32,
				N:         16384,
				R:         8,
				P:         1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derivedKey, err := crypto.DeriveKey(tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(derivedKey) != tt.opts.KeyLen {
				t.Errorf("Expected key length %d, got %d", tt.opts.KeyLen, len(derivedKey))
			}

			// Test that same parameters produce same key
			derivedKey2, err := crypto.DeriveKey(tt.opts)
			if err != nil {
				t.Errorf("Second derivation failed: %v", err)
				return
			}

			if !bytes.Equal(derivedKey, derivedKey2) {
				t.Error("Same parameters should produce same derived key")
			}

			// Test that different salt produces different key
			optsWithDifferentSalt := tt.opts
			optsWithDifferentSalt.Salt = "differentsalt"
			derivedKey3, err := crypto.DeriveKey(optsWithDifferentSalt)
			if err != nil {
				t.Errorf("Third derivation failed: %v", err)
				return
			}

			if bytes.Equal(derivedKey, derivedKey3) {
				t.Error("Different salt should produce different derived key")
			}

			t.Logf("Successfully derived %d-byte key using scrypt", len(derivedKey))
		})
	}
}

// TestKDFPBKDF2 tests PBKDF2 key derivation
func TestKDFPBKDF2(t *testing.T) {
	tests := []struct {
		name    string
		opts    crypto.KDFOptions
		wantErr bool
	}{
		{
			name: "PBKDF2-SHA256-Default",
			opts: crypto.KDFOptions{
				Algorithm:  crypto.PBKDF2SHA256,
				Password:   "testpassword",
				Salt:       "testsalt",
				KeyLen:     32,
				Iterations: 100000,
				HashFunc:   "sha256",
			},
			wantErr: false,
		},
		{
			name: "PBKDF2-SHA512",
			opts: crypto.KDFOptions{
				Algorithm:  crypto.PBKDF2SHA512,
				Password:   "testpassword",
				Salt:       "testsalt",
				KeyLen:     64,
				Iterations: 50000,
				HashFunc:   "sha512",
			},
			wantErr: false,
		},
		{
			name: "PBKDF2-SHA1",
			opts: crypto.KDFOptions{
				Algorithm:  crypto.PBKDF2SHA1,
				Password:   "testpassword",
				Salt:       "testsalt",
				KeyLen:     20,
				Iterations: 10000,
				HashFunc:   "sha1",
			},
			wantErr: false,
		},
		{
			name: "PBKDF2-Empty-Salt",
			opts: crypto.KDFOptions{
				Algorithm:  crypto.PBKDF2SHA256,
				Password:   "testpassword",
				Salt:       "",
				KeyLen:     32,
				Iterations: 100000,
				HashFunc:   "sha256",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derivedKey, err := crypto.DeriveKey(tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(derivedKey) != tt.opts.KeyLen {
				t.Errorf("Expected key length %d, got %d", tt.opts.KeyLen, len(derivedKey))
			}

			// Test deterministic behavior
			derivedKey2, err := crypto.DeriveKey(tt.opts)
			if err != nil {
				t.Errorf("Second derivation failed: %v", err)
				return
			}

			if !bytes.Equal(derivedKey, derivedKey2) {
				t.Error("Same parameters should produce same derived key")
			}

			t.Logf("Successfully derived %d-byte key using %s", len(derivedKey), tt.opts.Algorithm)
		})
	}
}

// TestGenerateRandomSalt tests random salt generation
func TestGenerateRandomSalt(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "Salt-16-bytes",
			length:  16,
			wantErr: false,
		},
		{
			name:    "Salt-32-bytes",
			length:  32,
			wantErr: false,
		},
		{
			name:    "Salt-Invalid-Length",
			length:  0,
			wantErr: true,
		},
		{
			name:    "Salt-Negative-Length",
			length:  -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt, err := crypto.GenerateRandomSalt(tt.length)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(salt) != tt.length {
				t.Errorf("Expected salt length %d, got %d", tt.length, len(salt))
			}

			// Test that multiple generations produce different salts
			salt2, err := crypto.GenerateRandomSalt(tt.length)
			if err != nil {
				t.Errorf("Second salt generation failed: %v", err)
				return
			}

			if bytes.Equal(salt, salt2) {
				t.Error("Random salt generation should produce different salts")
			}

			t.Logf("Successfully generated %d-byte random salt", len(salt))
		})
	}
}

// TestScryptParameterValidation tests scrypt parameter validation
func TestScryptParameterValidation(t *testing.T) {
	tests := []struct {
		name    string
		N, r, p int
		wantErr bool
	}{
		{
			name:    "Valid-Parameters",
			N:       32768,
			r:       8,
			p:       1,
			wantErr: false,
		},
		{
			name:    "Invalid-N-Not-Power-Of-2",
			N:       12345,
			r:       8,
			p:       1,
			wantErr: true,
		},
		{
			name:    "Invalid-N-Zero",
			N:       0,
			r:       8,
			p:       1,
			wantErr: true,
		},
		{
			name:    "Invalid-r-Zero",
			N:       16384,
			r:       0,
			p:       1,
			wantErr: true,
		},
		{
			name:    "Invalid-p-Zero",
			N:       16384,
			r:       8,
			p:       0,
			wantErr: true,
		},
		{
			name:    "Memory-Limit-Exceeded",
			N:       1048576, // Very high N
			r:       128,     // Very high r
			p:       1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.ValidateScryptParameters(tt.N, tt.r, tt.p)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// BenchmarkKDFScrypt benchmarks scrypt performance
func BenchmarkKDFScrypt(b *testing.B) {
	opts := crypto.KDFOptions{
		Algorithm: crypto.Scrypt,
		Password:  "benchmarkpassword",
		Salt:      "benchmarksalt",
		KeyLen:    32,
		N:         16384, // Lower N for faster benchmark
		R:         8,
		P:         1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.DeriveKey(opts)
		if err != nil {
			b.Fatalf("Scrypt derivation failed: %v", err)
		}
	}
}

// BenchmarkKDFPBKDF2 benchmarks PBKDF2 performance
func BenchmarkKDFPBKDF2(b *testing.B) {
	opts := crypto.KDFOptions{
		Algorithm:  crypto.PBKDF2SHA256,
		Password:   "benchmarkpassword",
		Salt:       "benchmarksalt",
		KeyLen:     32,
		Iterations: 10000, // Lower iterations for faster benchmark
		HashFunc:   "sha256",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.DeriveKey(opts)
		if err != nil {
			b.Fatalf("PBKDF2 derivation failed: %v", err)
		}
	}
}
