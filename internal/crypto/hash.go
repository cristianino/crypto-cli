package crypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

func GenerateHash(algorithm, encoding, filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	var hash []byte
	switch algorithm {
	case "sha256":
		h := sha256.Sum256(data)
		hash = h[:]
	case "sha512":
		h := sha512.Sum512(data)
		hash = h[:]
	case "sha1":
		h := sha1.Sum(data)
		hash = h[:]
	case "sha3-256":
		h := sha3.Sum256(data)
		hash = h[:]
	case "sha3-512":
		h := sha3.Sum512(data)
		hash = h[:]
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	switch encoding {
	case "hex":
		return hex.EncodeToString(hash), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(hash), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}
