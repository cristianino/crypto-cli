# crypto-cli

A command-line interface (CLI) tool written in Go for learning and practicing modern cryptography.  
This project is a Golang reimplementation of [curso-criptografia](https://github.com/cristianino/curso-criptografia), originally built in Node.js.

## Features

- **✅ Random generation (PRNG)**: bytes, integers, UUIDs
- **✅ Ciphers**: encrypt and decrypt with AES (CBC mode)
- **✅ Hashing**: SHA-1, SHA-2, SHA-3
- **✅ HMAC**: keyed message authentication codes
- **✅ Diffie-Hellman**: key exchange
- **✅ Key pairs**: RSA and RSA-PSS key pair generation and serialization
- **✅ Digital signatures**: RSA sign and verify with SHA-256/SHA-512
- **✅ Key derivation**: KDFs like scrypt and PBKDF2

---

## 📦 Quick Download & Install

> **🚀 Ready to use! No compilation needed.**

### Choose your platform:

<table>
<tr>
<td align="center">
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/linux/linux-original.svg" width="48" height="48"><br>
<strong>Linux x64</strong><br>
<a href="https://github.com/cristianino/crypto-cli/releases/latest/download/crypto-cli-v1.0.1-linux-amd64.tar.gz">
📥 Download
</a>
</td>
<td align="center">
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/linux/linux-original.svg" width="48" height="48"><br>
<strong>Linux ARM64</strong><br>
<a href="https://github.com/cristianino/crypto-cli/releases/latest/download/crypto-cli-v1.0.1-linux-arm64.tar.gz">
📥 Download
</a>
</td>
<td align="center">
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/apple/apple-original.svg" width="48" height="48"><br>
<strong>macOS Intel</strong><br>
<a href="https://github.com/cristianino/crypto-cli/releases/latest/download/crypto-cli-v1.0.1-darwin-amd64.tar.gz">
📥 Download
</a>
</td>
<td align="center">
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/apple/apple-original.svg" width="48" height="48"><br>
<strong>macOS Apple Silicon</strong><br>
<a href="https://github.com/cristianino/crypto-cli/releases/latest/download/crypto-cli-v1.0.1-darwin-arm64.tar.gz">
📥 Download
</a>
</td>
<td align="center">
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/windows8/windows8-original.svg" width="48" height="48"><br>
<strong>Windows x64</strong><br>
<a href="https://github.com/cristianino/crypto-cli/releases/latest/download/crypto-cli-v1.0.1-windows-amd64.zip">
📥 Download
</a>
</td>
</tr>
</table>

### 🔧 Installation Steps:

#### 🐧 **Linux / macOS:**
```bash
# 1. Download and extract (replace URL with your platform)
wget https://github.com/cristianino/crypto-cli/releases/latest/download/crypto-cli-v1.0.1-linux-amd64.tar.gz
tar -xzf crypto-cli-v1.0.1-linux-amd64.tar.gz

# 2. Install system-wide (optional)
sudo mv crypto-cli-v1.0.1-linux-amd64 /usr/local/bin/crypto-cli

# 3. Test installation
crypto-cli --help
```

#### 🪟 **Windows:**
1. **Download** the `.zip` file for Windows
2. **Extract** the archive 
3. **Add to PATH** or move `crypto-cli.exe` to a directory in your PATH
4. **Test** by opening Command Prompt and running `crypto-cli --help`

### ✅ **Verify Download (Optional)**
```bash
# Download checksums
wget https://github.com/cristianino/crypto-cli/releases/latest/download/checksums.txt

# Verify integrity
sha256sum -c checksums.txt --ignore-missing
```

---

## 🚀 Quick Start Examples

Get started immediately with these common tasks:

### 🎲 Generate Random Data
```bash
# Random bytes in base64
crypto-cli prng --type bytes --size 32 --encoding base64

# Random UUID
crypto-cli prng --type uuid
```

### 🔐 Encrypt Files
```bash
# Encrypt a file
crypto-cli cipher --password mypassword --input secret.txt --output encrypted.bin

# Decrypt it back
crypto-cli decipher --password mypassword --input encrypted.bin --output decrypted.txt
```

### 🏷️ Hash Data
```bash
# Hash a file with SHA-256
crypto-cli hash --algorithm sha256 --file document.txt

# Hash from stdin
echo "Hello World" | crypto-cli hash --algorithm sha256
```

### 🔑 Generate Key Pairs
```bash
# Generate RSA key pair
crypto-cli keypair --algorithm rsa --size 2048 --format pem

# Generate with password protection
crypto-cli keypair --algorithm rsa --size 2048 --format pem --passphrase mypassword
```

> 💡 **Tip:** Run `crypto-cli --help` or `crypto-cli <command> --help` to see all available options!

## Project Structure

```bash
crypto-cli/
├── cmd/                # Cobra commands
│   ├── root.go         # Root command (entry point)
│   ├── prng.go         # "prng" command
│   ├── hash.go         # "hash" command
│   ├── cipher.go       # "cipher" command (encrypt)
│   ├── decipher.go     # "decipher" command (decrypt)
│   ├── hmac.go         # "hmac" command
│   ├── dh.go           # "dh" command (Diffie-Hellman)
│   ├── keypair.go      # "keypair" command (RSA key pairs)
│   ├── sign.go         # "sign" command (digital signatures)
│   ├── verify.go       # "verify" command (signature verification)
│   └── ...             # other commands
├── internal/           # Internal packages (not exported outside the module)
│   └── crypto/         # Cryptographic implementations
│       ├── prng.go     # PRNG logic
│       ├── hash.go     # Hashing logic
│       ├── cipher.go   # AES encryption/decryption logic
│       ├── hmac.go     # HMAC logic
│       ├── dh.go       # Diffie-Hellman logic
│       ├── keypair.go  # RSA key pair generation logic
│       ├── signature.go # Digital signature logic
│       └── ...         
├── tests/              # Test suite (see TESTING.md)
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   ├── testdata/       # Test data files
│   └── run_tests.sh    # Test runner script
├── go.mod              # Go module definition
├── go.sum
├── main.go             # Main entry point
├── LICENSE             # MIT License
├── README.md
└── TESTING.md          # Testing documentation
````

---

## 📚 Advanced Usage & Examples

### 🔐 **Encryption & Decryption**
```bash
# Encrypt a file with AES-256
crypto-cli cipher --password mypassword --input secret.txt --output encrypted.bin

# Decrypt the file back
crypto-cli decipher --password mypassword --input encrypted.bin --output decrypted.txt

# Using different key sizes (128, 192, 256)
crypto-cli cipher --password mypassword --key-size 256 --input data.txt --output data.enc
```

### 🏷️ **Hashing**
```bash
# SHA-256 hash of a file
crypto-cli hash --algorithm sha256 --file document.txt

# Hash from stdin with different encodings
echo "Hello World" | crypto-cli hash --algorithm sha512 --encoding base64

# Supported: sha1, sha256, sha512, sha3-256, sha3-512
crypto-cli hash --algorithm sha3-256 --file data.txt --encoding hex
```

### 🔑 **HMAC (Message Authentication)**
```bash
# Generate HMAC for file integrity
crypto-cli hmac --algorithm sha256 --key secretkey --file document.txt

# HMAC from stdin
echo "message" | crypto-cli hmac -a sha256 -k mykey -e base64
```

### 🤝 **Diffie-Hellman Key Exchange**
```bash
# Generate DH parameters and keys
crypto-cli dh --mode generate --encoding hex

# Compute shared secret
crypto-cli dh --mode compute --prime <P> --generator <G> --private-key <priv> --public-key <pub>
```

### 🗝️ **RSA Key Pair Generation**
```bash
# Generate 2048-bit RSA key pair
crypto-cli keypair --algorithm rsa --size 2048 --format pem

# Generate with password protection
crypto-cli keypair --algorithm rsa --size 4096 --format pem --passphrase mypassword

# Save to files
crypto-cli keypair --algorithm rsa --size 2048 --private-key-file private.pem --public-key-file public.pem
```

### ✍️ **Digital Signatures**
```bash
# Sign a document
crypto-cli sign --algorithm rsa --hash-algorithm sha256 --private-key private.pem --input document.txt

# Verify signature
crypto-cli verify --algorithm rsa --hash-algorithm sha256 --public-key public.pem --signature signature.txt --input document.txt
```

### 🔗 **Key Derivation Functions (KDF)**
```bash
# Generate key from password using scrypt
crypto-cli kdf --algorithm scrypt --password mypassword --salt mysalt --key-length 32

# Using PBKDF2
crypto-cli kdf --algorithm pbkdf2 --hash sha256 --password mypassword --salt mysalt --iterations 10000
```

---

## 🛠️ Build from Source

For developers who want to modify or contribute:

```bash
# Clone repository
git clone https://github.com/cristianino/crypto-cli.git
cd crypto-cli

# Install dependencies
go mod tidy

# Build
make build

# Run tests
make test

# Build for all platforms
make build-all
```

---

## 📖 Command Reference

Run `crypto-cli --help` to see all available commands:

- `prng` - Generate pseudo-random values (bytes, integers, UUIDs)
- `hash` - Generate hashes using various algorithms  
- `cipher` - Encrypt files with AES
- `decipher` - Decrypt files encrypted with AES
- `hmac` - Generate HMAC for message authentication
- `dh` - Diffie-Hellman key exchange operations
- `keypair` - Generate RSA key pairs
- `sign` - Create digital signatures
- `verify` - Verify digital signatures
- `kdf` - Key derivation functions (scrypt, PBKDF2)

> 💡 **Tip:** Use `crypto-cli <command> --help` for detailed options on each command.

---

## 🎯 Educational Purpose

This tool is designed for **learning cryptography**. Each command demonstrates real-world cryptographic concepts:

- **Understand** how different algorithms work
- **Practice** with safe, well-tested implementations
- **Experiment** with parameters and see results
- **Learn** best practices in cryptographic operations

---

## 🛡️ Security Notes

- Uses industry-standard algorithms (AES-256, RSA-2048+, SHA-256+)
- Secure random number generation with `crypto/rand`
- Proper key derivation with scrypt/PBKDF2
- No hardcoded secrets or backdoors

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

<div align="center">

**⭐ If you find this tool useful, please give it a star on GitHub! ⭐**

[Report Bug](https://github.com/cristianino/crypto-cli/issues) • [Request Feature](https://github.com/cristianino/crypto-cli/issues) • [Documentation](https://github.com/cristianino/crypto-cli)

</div>
