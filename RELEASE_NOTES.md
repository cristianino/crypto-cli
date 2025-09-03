# Release Notes - v1.0.0

## 🎉 First Stable Release!

This is the first stable release of **crypto-cli**, a comprehensive command-line tool for learning and practicing modern cryptography. This Go implementation provides a complete cryptographic toolkit with support for multiple platforms.

## ✨ Features

### Core Cryptographic Operations
- **🎲 PRNG (Pseudo-Random Number Generation)**: Generate random bytes, integers, and UUIDs
- **🔐 AES Encryption/Decryption**: Symmetric encryption using AES in CBC mode
- **🏷️ Hashing**: Support for SHA-1, SHA-2, and SHA-3 hash functions
- **🔑 HMAC**: Keyed-hash message authentication codes
- **🤝 Diffie-Hellman**: Secure key exchange implementation
- **🗝️ RSA Key Pairs**: Generate and manage RSA and RSA-PSS key pairs
- **✍️ Digital Signatures**: Create and verify RSA signatures with SHA-256/SHA-512
- **🔗 Key Derivation**: Implement KDFs like scrypt and PBKDF2

### Platform Support
- **Linux**: x86_64 and ARM64
- **macOS**: Intel (x86_64) and Apple Silicon (ARM64)  
- **Windows**: x86_64

### User Experience
- **Intuitive CLI**: Easy-to-use command structure with comprehensive help
- **Flexible I/O**: Support for files, stdin/stdout, and various encodings
- **Educational**: Perfect for learning cryptographic concepts
- **Production Ready**: Robust error handling and validation

## 📦 Installation Options

### Quick Install (Precompiled Binaries)
Download ready-to-use binaries from the [releases page](https://github.com/cristianino/crypto-cli/releases/v1.0.0):

- `crypto-cli-v1.0.0-linux-amd64.tar.gz` - Linux x64
- `crypto-cli-v1.0.0-linux-arm64.tar.gz` - Linux ARM64
- `crypto-cli-v1.0.0-darwin-amd64.tar.gz` - macOS Intel
- `crypto-cli-v1.0.0-darwin-arm64.tar.gz` - macOS Apple Silicon
- `crypto-cli-v1.0.0-windows-amd64.zip` - Windows x64

### Build from Source
```bash
git clone https://github.com/cristianino/crypto-cli.git
cd crypto-cli
make build
```

## 🚀 Quick Start

```bash
# Generate 16 random bytes in base64
crypto-cli prng --type bytes --size 16 --encoding base64

# Hash a file with SHA-256
crypto-cli hash --algorithm sha256 --file document.txt

# Encrypt a file with AES
crypto-cli cipher --password mypassword --input secret.txt --output encrypted.bin

# Generate RSA key pair
crypto-cli keypair --algorithm rsa --size 2048 --format pem
```

## 🔒 Security

All cryptographic operations use industry-standard algorithms and implementations:
- AES-256 for symmetric encryption
- RSA-2048/4096 for asymmetric operations
- SHA-256/SHA-512 for hashing and signatures
- Secure random number generation using crypto/rand

## 📖 Educational Purpose

This tool was specifically designed for educational purposes to help developers and students understand:
- How different cryptographic primitives work
- Practical implementation of cryptographic concepts
- Real-world usage patterns and best practices
- The relationship between different cryptographic operations

## 🛡️ Verification

All release binaries include SHA256 checksums for integrity verification. Download `checksums.txt` and verify your download:

```bash
sha256sum -c checksums.txt --ignore-missing
```

## 🤝 Contributing

We welcome contributions! Please see our [GitHub repository](https://github.com/cristianino/crypto-cli) for more information.

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

---

**Full Changelog**: https://github.com/cristianino/crypto-cli/commits/v1.0.0
