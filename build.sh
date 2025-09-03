#!/bin/bash

# Build script for crypto-cli
# Compiles binaries for multiple platforms

set -e

VERSION=${1:-"v1.0.0"}
APP_NAME="crypto-cli"
DIST_DIR="dist"

echo "Building $APP_NAME $VERSION..."

# Clean previous builds
rm -rf $DIST_DIR
mkdir -p $DIST_DIR

# Build for different platforms
declare -a platforms=(
    "linux/amd64"
    "linux/arm64" 
    "windows/amd64"
    "darwin/amd64"
    "darwin/arm64"
)

for platform in "${platforms[@]}"; do
    IFS='/' read -r -a array <<< "$platform"
    GOOS="${array[0]}"
    GOARCH="${array[1]}"
    
    output_name="$APP_NAME-$VERSION-$GOOS-$GOARCH"
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi
    
    echo "Building for $GOOS/$GOARCH..."
    
    env GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-X main.version=$VERSION -s -w" \
        -o "$DIST_DIR/$output_name" \
        main.go
    
    # Create compressed archives
    cd $DIST_DIR
    if [ $GOOS = "windows" ]; then
        zip "${output_name%.exe}.zip" "$output_name"
        rm "$output_name"
    else
        tar -czf "${output_name}.tar.gz" "$output_name"
        rm "$output_name"
    fi
    cd ..
    
    echo "✅ Built $output_name"
done

echo ""
echo "🎉 Build completed! Binaries available in $DIST_DIR/"
ls -la $DIST_DIR/
