package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

func GeneratePRNG(t string, size int, encoding string) (string, error) {
	switch t {
	case "bytes":
		b := make([]byte, size)
		_, err := rand.Read(b)
		if err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		switch encoding {
		case "hex":
			return hex.EncodeToString(b), nil
		case "base64":
			return base64.StdEncoding.EncodeToString(b), nil
		default:
			return "", fmt.Errorf("unsupported encoding: %s", encoding)
		}

	case "int":
		n, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), uint(size*8)))
		if err != nil {
			return "", fmt.Errorf("failed to generate random int: %w", err)
		}
		return n.String(), nil

	case "uuid":
		u, err := uuid.NewRandom()
		if err != nil {
			return "", fmt.Errorf("failed to generate uuid: %w", err)
		}
		return u.String(), nil

	default:
		return "", fmt.Errorf("unsupported type: %s", t)
	}
}
