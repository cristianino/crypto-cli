#!/bin/bash

# Test runner script for crypto-cli
# This script provides convenient ways to run different types of tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Change to project root
cd "$(dirname "$0")/.."

# Build the project first
build_project() {
    log_info "Building crypto-cli..."
    if go build -o crypto-cli ./main.go; then
        log_success "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    if go test ./tests/unit/... -v; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    build_project
    if go test ./tests/integration/... -v; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed"
        return 1
    fi
}

# Run all tests
run_all_tests() {
    log_info "Running all tests..."
    run_unit_tests
    run_integration_tests
    log_success "All tests completed"
}

# Run tests with coverage
run_coverage() {
    log_info "Running tests with coverage..."
    
    # Unit tests coverage - we need to target the actual packages being tested
    go test ./tests/unit/... -coverpkg=./internal/... -coverprofile=unit_coverage.out -covermode=atomic
    
    # Generate HTML coverage report
    go tool cover -html=unit_coverage.out -o coverage.html
    
    # Show coverage summary
    go tool cover -func=unit_coverage.out | tail -1
    
    log_success "Coverage report generated: coverage.html"
}

# Run benchmarks
run_benchmarks() {
    log_info "Running benchmarks..."
    go test ./tests/unit/... -bench=. -benchmem -run=^$
    log_success "Benchmarks completed"
}

# Run specific test
run_specific_test() {
    local test_pattern="$1"
    if [[ -z "$test_pattern" ]]; then
        log_error "Please provide a test pattern"
        echo "Usage: $0 specific <test_pattern>"
        echo "Example: $0 specific TestEncryptDecryptFile"
        exit 1
    fi
    
    log_info "Running tests matching pattern: $test_pattern"
    go test ./tests/unit/... ./tests/integration/... -v -run="$test_pattern"
}

# Clean up test artifacts
clean() {
    log_info "Cleaning up test artifacts..."
    rm -f crypto-cli
    rm -f *.out
    rm -f coverage.html
    log_success "Cleanup completed"
}

# Show help
show_help() {
    echo "crypto-cli Test Runner"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  unit              Run unit tests only"
    echo "  integration       Run integration tests only"
    echo "  all               Run all tests (unit + integration)"
    echo "  coverage          Run tests with coverage report"
    echo "  benchmarks        Run performance benchmarks"
    echo "  specific <pattern> Run tests matching specific pattern"
    echo "  clean             Clean up test artifacts"
    echo "  help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 all"
    echo "  $0 coverage"
    echo "  $0 specific TestEncryptDecrypt"
    echo "  $0 benchmarks"
}

# Main command dispatcher
case "${1:-help}" in
    "unit")
        run_unit_tests
        ;;
    "integration")
        run_integration_tests
        ;;
    "all")
        run_all_tests
        ;;
    "coverage")
        run_coverage
        ;;
    "benchmarks")
        run_benchmarks
        ;;
    "specific")
        run_specific_test "$2"
        ;;
    "clean")
        clean
        ;;
    "help"|*)
        show_help
        ;;
esac
