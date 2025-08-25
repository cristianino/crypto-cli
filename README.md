# crypto-cli

A command-line interface (CLI) tool written in Go for learning and practicing modern cryptography.  
This project is a Golang reimplementation of [curso-criptografia](https://github.com/cristianino/curso-criptografia), originally built in Node.js.

## Features (planned)

- **Random generation (PRNG)**: bytes, integers, UUIDs
- **Ciphers**: encrypt and decrypt with modern algorithms (AES, ChaCha20, etc.)
- **Hashing**: SHA-2, SHA-3, etc.
- **HMAC**: keyed message authentication codes
- **Diffie-Hellman**: key exchange
- **Key pairs**: generation and serialization
- **Digital signatures**: sign and verify
- **Key derivation**: KDFs like scrypt and PBKDF2

## Project Structure

```bash
crypto-cli/
├── cmd/                # Cobra commands
│   ├── root.go         # Root command (entry point)
│   ├── prng.go         # "prng" command
│   └── ...             # other commands (cipher, hash, dh, etc.)
├── internal/           # Internal packages (not exported outside the module)
│   └── crypto/         # Cryptographic implementations
│       ├── prng.go     # PRNG logic
│       └── ...         
├── go.mod              # Go module definition
├── go.sum
├── main.go             # Main entry point
└── README.md
````

## Installation

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

## Example Usage

Generate 16 random bytes encoded in base64:

```bash
./crypto-cli prng --type bytes --size 16 --encoding base64
```

Generate a random UUID:

```bash
./crypto-cli prng --type uuid
```

Generate a random INT:
```bash
# Use size in bits (example: 8 bytes = 64 bits)
./crypto-cli prng --type int --size 8

# Number between 1 and 6
./crypto-cli prng --type int --min 1 --max 6

# Number between 1000 and 9999
./crypto-cli prng --type int --min 1000 --max 9999

# Number between 0 and 100 (default if you only use --type int)
./crypto-cli prng --type int
```

Generate hash of a file:

```bash
# Generate SHA256 hash of a file in hexadecimal format
./crypto-cli hash --algorithm sha256 --encoding hex --file example.txt

# Generate SHA512 hash of a file in base64 format
./crypto-cli hash --algorithm sha512 --encoding base64 --file example.txt

# Generate SHA1 hash (hexadecimal is default encoding)
./crypto-cli hash --algorithm sha1 --file example.txt

# Supported algorithms: sha256, sha512, sha1
# Supported encodings: hex, base64
```

## Contributing

Pull requests are welcome! If you want to add new cryptographic commands, feel free to open an issue or PR.
