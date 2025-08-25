# crypto-cli

A command-line interface (CLI) tool written in Go for learning and practicing modern cryptography.  
This project is a Golang reimplementation of [curso-criptografia](https://github.com/cristianino/curso-criptografia), originally built in Node.js.

## Features

- **✅ Random generation (PRNG)**: bytes, integers, UUIDs
- **✅ Ciphers**: encrypt and decrypt with AES (CBC mode)
- **✅ Hashing**: SHA-1, SHA-2, SHA-3
- **✅ HMAC**: keyed message authentication codes
- **✅ Diffie-Hellman**: key exchange
- **Key pairs**: generation and serialization *(planned)*
- **Digital signatures**: sign and verify *(planned)*
- **Key derivation**: KDFs like scrypt and PBKDF2 *(planned)*

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
│   └── ...             # other commands (signatures, etc.)
├── internal/           # Internal packages (not exported outside the module)
│   └── crypto/         # Cryptographic implementations
│       ├── prng.go     # PRNG logic
│       ├── hash.go     # Hashing logic
│       ├── cipher.go   # AES encryption/decryption logic
│       ├── hmac.go     # HMAC logic
│       ├── dh.go       # Diffie-Hellman logic
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

## Installation

### Basic Installation (Local Build)

```bash
# Clone the repository
git clone https://github.com/cristianino/crypto-cli.git
cd crypto-cli

# Install dependencies
go mod tidy

# Build
go build -o crypto-cli

# Run
./crypto-cli --help
```

### Install as System Command (Linux)

To use `crypto-cli` as a global command from anywhere in your system:

#### Option 1: Install to `/usr/local/bin` (Recommended)

```bash
# Clone and build
git clone https://github.com/cristianino/crypto-cli.git
cd crypto-cli
go mod tidy
go build -o crypto-cli

# Install globally (requires sudo)
sudo cp crypto-cli /usr/local/bin/

# Verify installation
crypto-cli --help
```

#### Option 2: Install to `~/.local/bin` (User-only)

```bash
# Create local bin directory if it doesn't exist
mkdir -p ~/.local/bin

# Clone and build
git clone https://github.com/cristianino/crypto-cli.git
cd crypto-cli
go mod tidy
go build -o crypto-cli

# Install for current user
cp crypto-cli ~/.local/bin/

# Add to PATH if not already (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
crypto-cli --help
```

#### Option 3: Direct Go Installation

```bash
# Install directly using go install
go install github.com/cristianino/crypto-cli@latest

# Verify installation (assuming $GOPATH/bin is in your PATH)
crypto-cli --help
```

#### Uninstall

```bash
# If installed to /usr/local/bin
sudo rm /usr/local/bin/crypto-cli

# If installed to ~/.local/bin
rm ~/.local/bin/crypto-cli

# If installed with go install
rm $(go env GOPATH)/bin/crypto-cli
```

## Example Usage

> **Note**: The examples below assume you have installed `crypto-cli` as a system command. If you're running it locally, use `./crypto-cli` instead of `crypto-cli`.

Generate 16 random bytes encoded in base64:

```bash
crypto-cli prng --type bytes --size 16 --encoding base64
```

Generate a random UUID:

```bash
crypto-cli prng --type uuid
```

Generate a random INT:
```bash
# Use size in bits (example: 8 bytes = 64 bits)
crypto-cli prng --type int --size 8

# Number between 1 and 6
crypto-cli prng --type int --min 1 --max 6

# Number between 1000 and 9999
crypto-cli prng --type int --min 1000 --max 9999

# Number between 0 and 100 (default if you only use --type int)
crypto-cli prng --type int
```

Generate hash of a file:

```bash
# Generate SHA256 hash of a file in hexadecimal format
crypto-cli hash --algorithm sha256 --encoding hex --file example.txt

# Generate SHA512 hash of a file in base64 format
crypto-cli hash --algorithm sha512 --encoding base64 --file example.txt

# Generate SHA1 hash (hexadecimal is default encoding)
crypto-cli hash --algorithm sha1 --file example.txt

# Hash from stdin
cat file.txt | crypto-cli hash --algorithm sha256

# Supported algorithms: sha256, sha512, sha1
# Supported encodings: hex, base64
```

Generate HMAC for message authentication:

```bash
# Generate HMAC-SHA256 of a file with a secret key
crypto-cli hmac --algorithm sha256 --key mysecret --encoding hex --file example.txt

# Generate HMAC-SHA512 with base64 encoding
crypto-cli hmac --algorithm sha512 --key mysecret --encoding base64 --file example.txt

# Generate HMAC-SHA256 (hex is default encoding)
crypto-cli hmac --algorithm sha256 --key mysecret --file example.txt

# Generate HMAC from stdin
cat file.txt | crypto-cli hmac --algorithm sha256 --key mysecret

# Using shorter flags
crypto-cli hmac -a sha512 -k mysecret -e base64 -f data.txt

# Supported algorithms: sha256, sha512, sha1, sha3-256, sha3-512
# Supported encodings: hex, base64
```

Diffie-Hellman key exchange:

```bash
# Generate new key pair
crypto-cli dh --mode generate --encoding hex

# Generate key pair with base64 encoding and save to file
crypto-cli dh --mode generate --encoding base64 --output alice_keys.json

# Compute shared secret (Alice computes secret using Bob's public key)
crypto-cli dh --mode compute \
  --prime <prime-from-keygen> --prime-encoding hex \
  --generator <generator-from-keygen> --generator-encoding hex \
  --private-key <alice-private-key> --private-key-encoding hex \
  --other-public-key <bob-public-key> --other-public-key-encoding hex \
  --encoding hex

# Using shorter flags
crypto-cli dh -m compute \
  --prime <prime> \
  --generator <generator> \
  --private-key <your-private-key> \
  --other-public-key <their-public-key> \
  -e base64

# Both parties should get the same shared secret!
# Supported encodings: hex, base64
```

Encrypt and decrypt files:

```bash
# Encrypt a file with AES-256-CBC
crypto-cli cipher --password mypassword --salt mysalt --size 256 --input data.txt --output encrypted.bin

# Encrypt with shorter flags (AES-128-CBC)
crypto-cli cipher -p mypassword -s mysalt -z 128 -i image.png -o encrypted_image.bin

# Decrypt the file
crypto-cli decipher --password mypassword --salt mysalt --size 256 --input encrypted.bin --output decrypted.txt

# Decrypt with shorter flags
crypto-cli decipher -p mypassword -s mysalt -z 128 -i encrypted_image.bin -o image.png

# Supported key sizes: 128, 192, 256 bits
# Uses AES encryption in CBC mode with scrypt key derivation
```

## Testing

This project has comprehensive test coverage including unit tests, integration tests, and benchmarks.

### Quick Testing

```bash
# Run all tests
./tests/run_tests.sh all

# Run only unit tests (fast)
./tests/run_tests.sh unit

# Run with coverage report
./tests/run_tests.sh coverage

# Run benchmarks
./tests/run_tests.sh benchmarks
```

### Test Structure

- **Unit Tests**: Fast tests for core cryptographic functions
- **Integration Tests**: End-to-end CLI testing
- **Test Data**: Shared test files for consistency
- **Coverage**: 55.3% code coverage with HTML reports

For detailed testing documentation, see [TESTING.md](TESTING.md).

## Contributing

Pull requests are welcome! If you want to add new cryptographic commands, feel free to open an issue or PR.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
