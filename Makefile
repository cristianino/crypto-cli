SHELL := /bin/bash

# Version
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Application name
APP_NAME := crypto-cli

# Directories
DIST_DIR := dist
BIN_DIR := bin

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags
LDFLAGS := -ldflags="-X github.com/cristianino/crypto-cli/cmd.version=$(VERSION) -s -w"

.PHONY: all build clean test deps help install build-all release

# Default target
all: clean deps test build

# Build for current platform
build:
	@echo "Building $(APP_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) main.go
	@echo "✅ Build completed: $(BIN_DIR)/$(APP_NAME)"

# Build for all platforms
build-all:
	@echo "Building for all platforms..."
	@chmod +x build.sh
	@./build.sh $(VERSION)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BIN_DIR) $(DIST_DIR)
	@rm -f $(APP_NAME) $(APP_NAME).exe
	@echo "✅ Clean completed"

# Run tests
test: build
	@echo "Running tests..."
	@echo "Building binary for integration tests..."
	@cp $(BIN_DIR)/$(APP_NAME) $(APP_NAME)
	@chmod +x $(APP_NAME)
	$(GOTEST) -v ./...
	@chmod +x tests/run_tests.sh
	@./tests/run_tests.sh
	@echo "✅ Tests completed"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

# Install binary to GOPATH/bin
install: build
	@echo "Installing $(APP_NAME)..."
	@cp $(BIN_DIR)/$(APP_NAME) $(GOPATH)/bin/
	@echo "✅ $(APP_NAME) installed to $(GOPATH)/bin"

# Create a release (requires git tag)
release:
	@if [ -z "$(shell git tag --points-at HEAD)" ]; then \
		echo "❌ No git tag found. Please create a tag first:"; \
		echo "   git tag -a v1.0.0 -m 'First release'"; \
		echo "   git push origin v1.0.0"; \
		exit 1; \
	fi
	@make build-all
	@echo "🎉 Release ready! Files in $(DIST_DIR)/"

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Clean, install deps, test, and build"
	@echo "  build      - Build for current platform"
	@echo "  build-all  - Build for all platforms" 
	@echo "  clean      - Clean build artifacts"
	@echo "  test       - Run tests"
	@echo "  deps       - Install dependencies"
	@echo "  install    - Install binary to GOPATH/bin"
	@echo "  release    - Create release (requires git tag)"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Example usage:"
	@echo "  make build VERSION=v1.0.0"
	@echo "  make release"
