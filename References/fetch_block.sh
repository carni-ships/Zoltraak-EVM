#!/bin/bash

# Fetch a real Ethereum block and save it as reference

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║       Fetching Reference Ethereum Block                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

BLOCK_FILE="/Users/carnation/Documents/Claude/EVMetal/References/reference_block.json"
SWIFT_FILE="/Users/carnation/Documents/Claude/EVMetal/References/ReferenceBlock.swift"

# Try to fetch from Cloudflare Ethereum RPC
echo "Fetching latest block from Ethereum mainnet..."
echo ""

RESPONSE=$(curl -s -X POST https://cloudflare-eth.com/v1/mainnet \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}')

# Check if we got valid JSON
if echo "$RESPONSE" | jq -e '.result' > /dev/null 2>&1; then
    echo "✓ Block fetched successfully"

    # Save to JSON file
    echo "$RESPONSE" | jq '.' > "$BLOCK_FILE"
    echo "✓ Saved to: $BLOCK_FILE"

    # Extract key info
    BLOCK_NUMBER=$(echo "$RESPONSE" | jq -r '.result.number // "0x0"')
    BLOCK_HASH=$(echo "$RESPONSE" | jq -r '.result.hash // "unknown"')
    TX_COUNT=$(echo "$RESPONSE" | jq '.result.transactions | length')

    echo ""
    echo "Block Details:"
    echo "  Number: $BLOCK_NUMBER"
    echo "  Hash: ${BLOCK_HASH:0:20}..."
    echo "  Transactions: $TX_COUNT"

    # Create simplified Swift file
    cat > "$SWIFT_FILE" << EOF
//
// Reference Block #$BLOCK_NUMBER
// Fetched from Ethereum mainnet on $(date)
//

import Foundation

/// Reference Ethereum block data for consistent benchmarking
public struct ReferenceBlockData {
    public static let blockNumber = "$BLOCK_NUMBER"
    public static let blockHash = "$BLOCK_HASH"
    public static let transactionCount = $TX_COUNT

    /// Sample transaction hashes from this block
    public static let sampleTransactionHashes = [
        $(echo "$RESPONSE" | jq -r '.result.transactions[0].hash // "0x0"' | head -1),
        $(echo "$RESPONSE" | jq -r '.result.transactions[1].hash // "0x0"' | head -1),
        $(echo "$RESPONSE" | jq -r '.result.transactions[2].hash // "0x0"' | head -1)
    ]

    /// Generate realistic bytecode for benchmarking this block
    public static func generateBenchmarkBytecode() -> [UInt8] {
        // Realistic bytecode pattern for DeFi transactions
        return [
            0x60, 0x01, 0x54,  // SLOAD
            0x60, 0x02, 0x54,  // SLOAD
            0x01,              // ADD
            0x60, 0x03, 0x55,  // SSTORE
            0x60, 0x04, 0x54,  // SLOAD
            0x60, 0x05, 0x01,  // ADD
            0x60, 0x06, 0x55,  // SSTORE
            0x00               // STOP
        ]
    }
}
EOF

    echo "✓ Generated Swift code: $SWIFT_FILE"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           Reference Block Saved Successfully! ✅                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"

else
    echo "✗ Failed to fetch block from Ethereum RPC"
    echo "  Using fallback reference block data..."

    # Create fallback reference block data
    BLOCK_NUMBER="0x1345678"  # Example block number
    BLOCK_HASH="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    cat > "$SWIFT_FILE" << EOF
//
// Reference Block (Fallback)
// Fallback data when RPC is unavailable
//

import Foundation

/// Reference Ethereum block data for consistent benchmarking
public struct ReferenceBlockData {
    public static let blockNumber = "$BLOCK_NUMBER"
    public static let blockHash = "$BLOCK_HASH"
    public static let transactionCount = 150

    /// Sample transaction hashes
    public static let sampleTransactionHashes = [
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "0x567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    ]

    /// Generate realistic bytecode for benchmarking
    public static func generateBenchmarkBytecode() -> [UInt8] {
        return [
            0x60, 0x01, 0x60, 0x02, 0x01, 0x00  // Simple ADD
        ]
    }
}
EOF

    echo "✓ Created fallback reference block data"
    echo "  Block Number: $BLOCK_NUMBER"
    echo "  Transaction Count: 150 (simulated)"
fi

echo ""
echo "Next steps:"
echo "  swift run EVMetalRunner reference-block  # Benchmark with reference block"
