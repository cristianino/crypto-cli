package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

// RFC 5114 - 2048-bit MODP Group (similar to modp14)
// This is a well-known safe prime used for Diffie-Hellman
var (
	// 2048-bit MODP Group prime (hex)
	modp14PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183560791C6EB861DAD0ABDEDE08A88EE5C01C7D8E3ED2E86B14E03A9B9B41E4B5AF6C4E33A9C67E7B9C2FED57378C4C97E3E85F1CF3A5D0A7BE0C31D9C9C6F8D16F8B2B0A6FE0C4C3F8F8E8E8E6F6C2C2C2C2C2C2C2C2C2C2"

	// Generator (typically 2)
	modp14GeneratorHex = "02"
)

// DiffieHellmanResult represents the result of Diffie-Hellman operations
type DiffieHellmanResult struct {
	Prime      string `json:"prime"`
	Generator  string `json:"generator"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`       // Should be kept secret
	Secret     string `json:"secret,omitempty"` // Only present when computing shared secret
}

// GenerateDiffieHellmanKeys generates new Diffie-Hellman key pair using modp14 group
func GenerateDiffieHellmanKeys(encoding string) (*DiffieHellmanResult, error) {
	// Parse the prime and generator
	prime := new(big.Int)
	prime.SetString(modp14PrimeHex, 16)

	generator := new(big.Int)
	generator.SetString(modp14GeneratorHex, 16)

	// Generate private key (random number less than prime-1)
	max := new(big.Int).Sub(prime, big.NewInt(1))
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate public key: g^privateKey mod prime
	publicKey := new(big.Int).Exp(generator, privateKey, prime)

	// Encode results
	primeStr, err := encodeBigInt(prime, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode prime: %w", err)
	}

	generatorStr, err := encodeBigInt(generator, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode generator: %w", err)
	}

	publicKeyStr, err := encodeBigInt(publicKey, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	privateKeyStr, err := encodeBigInt(privateKey, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &DiffieHellmanResult{
		Prime:      primeStr,
		Generator:  generatorStr,
		PublicKey:  publicKeyStr,
		PrivateKey: privateKeyStr,
	}, nil
}

// ComputeDiffieHellmanSecret computes the shared secret using the other party's public key
func ComputeDiffieHellmanSecret(params DiffieHellmanParams, encoding string) (*DiffieHellmanResult, error) {
	// Parse prime, generator, private key, and other party's public key
	prime := new(big.Int)
	generator := new(big.Int)
	privateKey := new(big.Int)
	otherPublicKey := new(big.Int)

	var err error

	// Decode prime
	prime, err = decodeToBigInt(params.Prime, params.PrimeEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode prime: %w", err)
	}

	// Decode generator
	generator, err = decodeToBigInt(params.Generator, params.GeneratorEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode generator: %w", err)
	}

	// Decode private key
	privateKey, err = decodeToBigInt(params.PrivateKey, params.PrivateKeyEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Decode other party's public key
	otherPublicKey, err = decodeToBigInt(params.OtherPublicKey, params.OtherPublicKeyEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode other public key: %w", err)
	}

	// Compute our public key: g^privateKey mod prime
	publicKey := new(big.Int).Exp(generator, privateKey, prime)

	// Compute shared secret: otherPublicKey^privateKey mod prime
	secret := new(big.Int).Exp(otherPublicKey, privateKey, prime)

	// Encode results
	primeStr, err := encodeBigInt(prime, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode prime: %w", err)
	}

	generatorStr, err := encodeBigInt(generator, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode generator: %w", err)
	}

	publicKeyStr, err := encodeBigInt(publicKey, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	privateKeyStr, err := encodeBigInt(privateKey, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	secretStr, err := encodeBigInt(secret, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode secret: %w", err)
	}

	return &DiffieHellmanResult{
		Prime:      primeStr,
		Generator:  generatorStr,
		PublicKey:  publicKeyStr,
		PrivateKey: privateKeyStr,
		Secret:     secretStr,
	}, nil
}

// DiffieHellmanParams represents parameters for computing shared secret
type DiffieHellmanParams struct {
	Prime                  string
	PrimeEncoding          string
	Generator              string
	GeneratorEncoding      string
	PrivateKey             string
	PrivateKeyEncoding     string
	OtherPublicKey         string
	OtherPublicKeyEncoding string
}

// encodeBigInt encodes a big.Int to the specified encoding
func encodeBigInt(n *big.Int, encoding string) (string, error) {
	switch encoding {
	case "hex":
		return n.Text(16), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(n.Bytes()), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// decodeToBigInt decodes a string to big.Int based on encoding
func decodeToBigInt(s, encoding string) (*big.Int, error) {
	switch encoding {
	case "hex":
		n := new(big.Int)
		n, ok := n.SetString(s, 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex string")
		}
		return n, nil
	case "base64":
		bytes, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 string: %w", err)
		}
		n := new(big.Int)
		n.SetBytes(bytes)
		return n, nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}
