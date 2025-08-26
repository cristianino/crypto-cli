package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLIKeypairGeneration tests the keypair command
func TestCLIKeypairGeneration(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tempDir, err := os.MkdirTemp("", "cli_keypair_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name       string
		args       []string
		checkFiles bool
	}{
		{
			name: "RSA-2048-PEM-ToFiles",
			args: []string{"keypair",
				"--type", "rsa",
				"--modulus", "2048",
				"--format", "pem",
				"--output", tempDir,
			},
			checkFiles: true,
		},
		{
			name: "RSA-2048-PEM-WithPassphrase",
			args: []string{"keypair",
				"--type", "rsa",
				"--modulus", "2048",
				"--format", "pem",
				"--passphrase", "secret123",
				"--aes-size", "256",
				"--output", filepath.Join(tempDir, "encrypted"),
			},
			checkFiles: true,
		},
		{
			name: "RSA-3072-DER-ToFiles",
			args: []string{"keypair",
				"--type", "rsa",
				"--modulus", "3072",
				"--format", "der",
				"--output", filepath.Join(tempDir, "der_keys"),
			},
			checkFiles: true,
		},
		{
			name: "RSA-PSS-2048-PEM-ToStdout",
			args: []string{"keypair",
				"--type", "rsa-pss",
				"--modulus", "2048",
				"--format", "pem",
				"--encoding", "base64",
			},
			checkFiles: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, test.args...)
			output, err := cmd.CombinedOutput()

			if err != nil {
				t.Fatalf("Keypair command failed: %v, output: %s", err, string(output))
			}

			outputStr := string(output)

			// Check for success indicators
			if !strings.Contains(outputStr, "Key pair generated successfully") {
				t.Errorf("Expected success message, got: %s", outputStr)
			}

			if test.checkFiles {
				// Extract output directory from args
				var outDir string
				for i, arg := range test.args {
					if arg == "--output" && i+1 < len(test.args) {
						outDir = test.args[i+1]
						break
					}
				}

				if outDir != "" {
					// Determine file extension
					ext := "pem" // default
					for i, arg := range test.args {
						if arg == "--format" && i+1 < len(test.args) {
							ext = test.args[i+1]
							break
						}
					}

					// Check files exist
					publicKeyPath := filepath.Join(outDir, "public."+ext)
					privateKeyPath := filepath.Join(outDir, "private."+ext)

					if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
						t.Errorf("Public key file not found: %s", publicKeyPath)
					}

					if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
						t.Errorf("Private key file not found: %s", privateKeyPath)
					}

					// Verify file permissions
					if info, err := os.Stat(privateKeyPath); err == nil {
						mode := info.Mode()
						if mode.Perm() != 0600 {
							t.Errorf("Private key file has incorrect permissions: %o (expected 0600)", mode.Perm())
						}
					}
				}
			} else {
				// Check stdout output contains keys
				if !strings.Contains(outputStr, "Public Key") {
					t.Error("Expected public key in stdout output")
				}
				if !strings.Contains(outputStr, "Private Key") {
					t.Error("Expected private key in stdout output")
				}
			}

			t.Logf("Keypair test '%s' completed successfully", test.name)
		})
	}
}

// TestCLIKeypairValidation tests keypair command validation
func TestCLIKeypairValidation(t *testing.T) {
	binaryPath := getBinaryPath(t)

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "InvalidKeyType",
			args:     []string{"keypair", "--type", "invalid"},
			expected: "invalid key type",
		},
		{
			name:     "InvalidModulusLength",
			args:     []string{"keypair", "--modulus", "1024"},
			expected: "invalid modulus length",
		},
		{
			name:     "InvalidFormat",
			args:     []string{"keypair", "--format", "invalid"},
			expected: "invalid format",
		},
		{
			name:     "InvalidAESSize",
			args:     []string{"keypair", "--aes-size", "512"},
			expected: "invalid AES size",
		},
		{
			name:     "DERWithPassphrase",
			args:     []string{"keypair", "--format", "der", "--passphrase", "secret"},
			expected: "DER format with passphrase encryption is not supported",
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
