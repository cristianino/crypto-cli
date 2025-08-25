package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

// EncryptFile encrypts a file using AES encryption with CBC mode
// The key is derived using scrypt from the password and salt
// The IV is randomly generated and prepended to the encrypted data
func EncryptFile(password, salt string, keySize int, inputPath, outputPath string) error {
	// Generate a random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Derive key using scrypt
	key, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, keySize/8)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Write IV to the beginning of the output file
	if _, err := outputFile.Write(iv); err != nil {
		return fmt.Errorf("failed to write IV: %w", err)
	}

	// Create CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Read and encrypt the file in chunks
	buffer := make([]byte, 1024)
	var remainder []byte

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		if n == 0 {
			break
		}

		// Accumulate data
		data := append(remainder, buffer[:n]...)

		// Process complete blocks (16-byte blocks for AES)
		for len(data) >= aes.BlockSize {
			block := data[:aes.BlockSize]
			encrypted := make([]byte, aes.BlockSize)
			mode.CryptBlocks(encrypted, block)

			if _, err := outputFile.Write(encrypted); err != nil {
				return fmt.Errorf("failed to write encrypted data: %w", err)
			}

			data = data[aes.BlockSize:]
		}

		remainder = data

		if err == io.EOF {
			break
		}
	}

	// Handle padding for the last block (PKCS#7 padding)
	if len(remainder) > 0 {
		padSize := aes.BlockSize - len(remainder)
		padding := make([]byte, padSize)
		for i := range padding {
			padding[i] = byte(padSize)
		}
		remainder = append(remainder, padding...)
	} else {
		// If file size is exactly divisible by block size, add a full block of padding
		padding := make([]byte, aes.BlockSize)
		for i := range padding {
			padding[i] = byte(aes.BlockSize)
		}
		remainder = padding
	}

	// Encrypt and write the final padded block
	if len(remainder) > 0 {
		encrypted := make([]byte, len(remainder))
		mode.CryptBlocks(encrypted, remainder)

		if _, err := outputFile.Write(encrypted); err != nil {
			return fmt.Errorf("failed to write final encrypted block: %w", err)
		}
	}

	return nil
}

// DecryptFile decrypts a file that was encrypted with EncryptFile
func DecryptFile(password, salt string, keySize int, inputPath, outputPath string) error {
	// Derive key using scrypt
	key, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, keySize/8)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read IV from the beginning of the file
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inputFile, iv); err != nil {
		return fmt.Errorf("failed to read IV: %w", err)
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Read the encrypted data
	encryptedData, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Check if data length is valid (must be multiple of block size)
	if len(encryptedData)%aes.BlockSize != 0 {
		return fmt.Errorf("invalid encrypted data: length is not multiple of block size")
	}

	// Decrypt the data
	decryptedData := make([]byte, len(encryptedData))
	mode.CryptBlocks(decryptedData, encryptedData)

	// Remove PKCS#7 padding
	if len(decryptedData) == 0 {
		return fmt.Errorf("no data to decrypt")
	}

	paddingSize := int(decryptedData[len(decryptedData)-1])
	if paddingSize > aes.BlockSize || paddingSize == 0 {
		return fmt.Errorf("invalid padding")
	}

	// Verify padding
	for i := len(decryptedData) - paddingSize; i < len(decryptedData); i++ {
		if decryptedData[i] != byte(paddingSize) {
			return fmt.Errorf("invalid padding")
		}
	}

	// Remove padding
	decryptedData = decryptedData[:len(decryptedData)-paddingSize]

	// Write decrypted data to output file
	if _, err := outputFile.Write(decryptedData); err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}

	return nil
}
