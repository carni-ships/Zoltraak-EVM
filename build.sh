#!/bin/bash
# EVMetal Build Script
# Usage: ./build.sh [debug|release]

set -e

BUILD_TYPE="${1:-release}"

echo "=== EVMetal Build Script ==="

# Check for required tools
if ! command -v swift &> /dev/null; then
    echo "Error: Swift is required but not installed."
    echo "Install Xcode or Swift from https://swift.org/download/"
    exit 1
fi

# Initialize submodules if needed
if [ -d "foundry" ] && [ ! -f "foundry/foundry.toml" ]; then
    echo "Initializing foundry submodule..."
    git submodule update --init foundry
fi

# Build
echo "Building EVMetal ($BUILD_TYPE)..."
swift build -c "$BUILD_TYPE"

# Verify binary
BINARY=".build/$BUILD_TYPE/EVMetalRunner"
if [ -f "$BINARY" ]; then
    echo "Build successful: $BINARY"

    # Make executable
    chmod +x "$BINARY" 2>/dev/null || true

    # Show size
    SIZE=$(du -h "$BINARY" 2>/dev/null | cut -f1 || echo "unknown")
    echo "Binary size: $SIZE"

    echo ""
    echo "Run with:"
    echo "  ./$BINARY benchmarks"
    echo "  ./$BINARY eth-live 1"
else
    echo "Build failed - binary not found"
    exit 1
fi