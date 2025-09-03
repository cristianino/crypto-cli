#!/bin/bash

# Release script for crypto-cli
# This script helps create a new release with proper versioning

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if version is provided
if [ $# -eq 0 ]; then
    log_error "Please provide a version number"
    echo "Usage: $0 <version> [--dry-run]"
    echo "Example: $0 v1.0.0"
    exit 1
fi

VERSION=$1
DRY_RUN=false

if [ "$2" = "--dry-run" ]; then
    DRY_RUN=true
    log_warning "DRY RUN MODE - No actual changes will be made"
fi

# Validate version format
if [[ ! $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_error "Version must be in format vX.Y.Z (e.g., v1.0.0)"
    exit 1
fi

log_info "Preparing release $VERSION"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    log_error "This script must be run from the root of the git repository"
    exit 1
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    log_warning "You have uncommitted changes. Please commit or stash them before creating a release."
    git status --short
    if [ "$DRY_RUN" = false ]; then
        exit 1
    fi
fi

# Check if tag already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    log_error "Tag $VERSION already exists"
    exit 1
fi

# Run tests
log_info "Running tests..."
if ! make test > /dev/null 2>&1; then
    log_error "Tests failed. Please fix them before creating a release."
    exit 1
fi
log_success "All tests passed"

# Build binaries
log_info "Building binaries for all platforms..."
if [ "$DRY_RUN" = false ]; then
    make clean
    ./build.sh "$VERSION"
    
    # Generate checksums
    cd dist
    sha256sum * > checksums.txt
    cd ..
    
    log_success "Binaries built successfully"
    log_info "Generated files:"
    ls -la dist/
else
    log_info "Would build binaries for version $VERSION"
fi

# Create git tag and push
if [ "$DRY_RUN" = false ]; then
    log_info "Creating git tag $VERSION"
    git tag -a "$VERSION" -m "Release $VERSION

Release highlights:
- Complete cryptographic toolkit
- Multi-platform support (Linux, macOS, Windows)
- Educational and production-ready

See RELEASE_NOTES.md for detailed changelog."

    log_info "Pushing tag to origin"
    git push origin "$VERSION"
    
    log_success "Tag $VERSION created and pushed"
else
    log_info "Would create and push git tag $VERSION"
fi

# Instructions for GitHub release
echo ""
log_success "Release preparation completed!"
echo ""
log_info "Next steps:"
echo "1. Go to: https://github.com/cristianino/crypto-cli/releases"
echo "2. Click 'Draft a new release'"
echo "3. Select tag: $VERSION"
echo "4. Title: 'Release $VERSION'"
echo "5. Copy description from RELEASE_NOTES.md"
echo "6. Upload the following files from dist/:"
echo "   - crypto-cli-$VERSION-linux-amd64.tar.gz"
echo "   - crypto-cli-$VERSION-linux-arm64.tar.gz"
echo "   - crypto-cli-$VERSION-darwin-amd64.tar.gz"
echo "   - crypto-cli-$VERSION-darwin-arm64.tar.gz"
echo "   - crypto-cli-$VERSION-windows-amd64.zip"
echo "   - checksums.txt"
echo "7. Click 'Publish release'"
echo ""

if [ "$DRY_RUN" = false ]; then
    log_info "Or wait for GitHub Actions to automatically create the release!"
fi

echo ""
log_success "🎉 Release $VERSION is ready!"
