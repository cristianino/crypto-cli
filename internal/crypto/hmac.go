package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/sha3"
)

// GenerateHMAC generates an HMAC for the given input using the specified algorithm, key, and encoding
func GenerateHMAC(algorithm, key, encoding, filePath string) (string, error) {
	// Validate algorithm first
	var h hash.Hash
	switch algorithm {
	case "sha256":
		h = hmac.New(sha256.New, []byte(key))
	case "sha512":
		h = hmac.New(sha512.New, []byte(key))
	case "sha1":
		h = hmac.New(sha1.New, []byte(key))
	case "sha3-256":
		h = hmac.New(sha3.New256, []byte(key))
	case "sha3-512":
		h = hmac.New(sha3.New512, []byte(key))
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Validate encoding
	switch encoding {
	case "hex", "base64":
		// Valid encodings
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}

	var data []byte
	var err error

	if filePath == "" {
		// Read from stdin
		data, err = io.ReadAll(os.Stdin)
	} else {
		// Read from file
		data, err = os.ReadFile(filePath)
	}

	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}

	h.Write(data)
	mac := h.Sum(nil)

	switch encoding {
	case "hex":
		return hex.EncodeToString(mac), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(mac), nil
	default:
		// This should never happen due to earlier validation
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}
