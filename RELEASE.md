# Release Process Documentation

This document explains how to create a new release for crypto-cli with precompiled binaries.

## Prerequisites

1. Go 1.25+ installed
2. Git repository with push access
3. All changes committed and tests passing

## Automated Release Process

We provide several tools to make the release process easy and consistent:

### Quick Release (Recommended)

```bash
# Create and publish a new release
./release.sh v1.0.0
```

This script will:
1. Validate the version format
2. Check for uncommitted changes  
3. Run all tests
4. Build binaries for all platforms
5. Generate SHA256 checksums
6. Create and push a git tag
7. Trigger GitHub Actions to create the release

### Manual Step-by-Step Process

If you prefer to do it manually or need more control:

#### 1. Prepare the Release

```bash
# Clean previous builds
make clean

# Run tests to ensure everything works
make test

# Build binaries for all platforms
./build.sh v1.0.0
```

#### 2. Create Git Tag

```bash
# Create annotated tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push tag to GitHub
git push origin v1.0.0
```

#### 3. Create GitHub Release

The GitHub Actions workflow will automatically:
- Detect the new tag
- Build all binaries
- Generate checksums  
- Create a GitHub release
- Upload all assets

## Manual GitHub Release (if Actions fail)

1. Go to https://github.com/cristianino/crypto-cli/releases
2. Click "Draft a new release"
3. Select the tag you created
4. Fill in the release title: "Release v1.0.0"
5. Copy the description from `RELEASE_NOTES.md`
6. Upload the binary files from the `dist/` directory:
   - `crypto-cli-v1.0.0-linux-amd64.tar.gz`
   - `crypto-cli-v1.0.0-linux-arm64.tar.gz`
   - `crypto-cli-v1.0.0-darwin-amd64.tar.gz`
   - `crypto-cli-v1.0.0-darwin-arm64.tar.gz`
   - `crypto-cli-v1.0.0-windows-amd64.zip`
   - `checksums.txt`
7. Click "Publish release"

## Available Scripts and Tools

### `build.sh`
Builds binaries for all supported platforms:
```bash
./build.sh v1.0.0
```

### `release.sh`
Complete release automation:
```bash
./release.sh v1.0.0          # Full release
./release.sh v1.0.0 --dry-run # Test without changes
```

### `Makefile` Targets
```bash
make build      # Build for current platform
make build-all  # Build for all platforms
make test       # Run all tests
make clean      # Clean build artifacts
make release    # Create release (requires git tag)
```

## Supported Platforms

We build binaries for the following platforms:

- **Linux x86_64**: Most Linux distributions
- **Linux ARM64**: ARM-based Linux systems (Raspberry Pi, etc.)
- **macOS x86_64**: Intel-based Macs
- **macOS ARM64**: Apple Silicon Macs (M1, M2, etc.)
- **Windows x86_64**: 64-bit Windows systems

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., v1.0.0)
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## Security

All release binaries include SHA256 checksums for verification:

```bash
# Verify a downloaded binary
sha256sum -c checksums.txt --ignore-missing
```

## GitHub Actions Workflow

The `.github/workflows/release.yml` workflow automatically:

1. Triggers on git tag push matching `v*`
2. Sets up Go environment
3. Builds binaries for all platforms
4. Generates checksums
5. Creates GitHub release
6. Uploads all binary assets

## Troubleshooting

### Build Fails
- Check Go version (requires 1.25+)
- Ensure all dependencies are available: `go mod tidy`
- Run tests first: `make test`

### GitHub Actions Fails
- Check workflow logs in GitHub Actions tab
- Ensure GITHUB_TOKEN has correct permissions
- Verify tag was pushed correctly

### Binary Size Too Large
- Binaries are built with `-s -w` flags to reduce size
- Use compression (tar.gz/zip) for distribution
- Consider using UPX if needed (not included by default)

## File Structure After Release

```
dist/
├── crypto-cli-v1.0.0-linux-amd64.tar.gz
├── crypto-cli-v1.0.0-linux-arm64.tar.gz
├── crypto-cli-v1.0.0-darwin-amd64.tar.gz
├── crypto-cli-v1.0.0-darwin-arm64.tar.gz
├── crypto-cli-v1.0.0-windows-amd64.zip
└── checksums.txt
```

## Post-Release

After a successful release:

1. Update README.md if needed with new version numbers
2. Announce the release on relevant channels
3. Update any documentation that references version numbers
4. Consider creating a blog post or announcement

## Contributing to Release Process

If you want to improve the release process:

1. Test changes with `--dry-run` first
2. Update this documentation
3. Consider backward compatibility
4. Test on different platforms if possible
