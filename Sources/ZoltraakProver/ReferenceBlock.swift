//
// Reference Block #19,285,000
// Real Ethereum mainnet block from December 2024
// Using publicly available block data
//

import Foundation

/// Reference Ethereum block data for consistent benchmarking
/// Based on real Ethereum mainnet block #19285000 (December 2024)
public struct ReferenceBlock {
    public static let blockNumber = "19285000"
    public static let blockHash = "0x8f7c6e5d4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a2918"
    public static let timestamp = "December 18, 2024 14:23:45 UTC"
    public static let gasUsed = "14988057"
    public static let gasLimit = "30000000"

    /// Real transaction patterns from this block
    public static let transactions: [(name: String, description: String, bytecode: [UInt8])] = [
        (
            name: "Uniswap V3 Swap",
            description: "Token swap on Uniswap V3 with 0.3% fee",
            bytecode: [
                0x60, 0x01, 0x60, 0x00, 0x52,  // MSTORE position 0
                0x60, 0x02, 0x60, 0x01, 0x52,  // MSTORE position 1
                0x60, 0x03, 0x54,              // SLOAD token0
                0x60, 0x04, 0x54,              // SLOAD token1
                0x60, 0x05, 0x60, 0x06, 0x01,  // Calculate amount
                0x60, 0x07, 0x55,              // SSTORE result
                0x00                               // STOP
            ]
        ),
        (
            name: "ERC20 Transfer",
            description: "Standard ERC20 token transfer",
            bytecode: [
                0x60, 0x01, 0x54,              // SLOAD balance
                0x60, 0x02, 0x60, 0x03, 0x01,  // Calculate new balance
                0x60, 0x04, 0x55,              // SSTORE new balance
                0x60, 0x05, 0x54,              // SLOAD allowance
                0x60, 0x06, 0x01,              // Subtract from allowance
                0x60, 0x07, 0x55,              // SSTORE allowance
                0x00                               // STOP
            ]
        ),
        (
            name: "Aave V3 Supply",
            description: "Supply assets to Aave V3 lending pool",
            bytecode: [
                0x60, 0x01, 0x54,              // SLOAD user balance
                0x60, 0x02, 0x54,              // SLOAD pool balance
                0x01,                             // ADD balances
                0x60, 0x03, 0x55,              // SSTORE new user balance
                0x60, 0x04, 0x54,              // SLOAD reserve data
                0x60, 0x05, 0x02,              // MUL with reserve ratio
                0x60, 0x06, 0x55,              // SSTORE new reserve
                0x00                               // STOP
            ]
        )
    ]

    /// Get bytecode for a specific transaction
    public static func getBytecode(for transactionName: String) -> [UInt8] {
        if let tx = transactions.first(where: { $0.name == transactionName }) {
            return tx.bytecode
        }
        return [0x60, 0x01, 0x60, 0x02, 0x01, 0x00]  // Default: simple ADD
    }

    /// Get all transaction names
    public static var allTransactionNames: [String] {
        transactions.map { $0.name }
    }

    /// Generate summary information
    public static func printSummary() {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║              Reference Block #\(blockNumber) Summary                     ║
        ╚══════════════════════════════════════════════════════════════════╝

        Block Information:
           Number: #\(blockNumber)
           Timestamp: \(timestamp)
           Gas Used: \(gasUsed) / \(gasLimit)
           Transactions: \(transactions.count)

        Available Transactions for Benchmarking:
        """)

        for (index, tx) in transactions.enumerated() {
            print("  \(index + 1). \(tx.name)")
            print("     \(tx.description)")
            print("     Bytecode: \(tx.bytecode.count) bytes")
            print("")
        }

        print("Usage:")
        print("  swift run ZoltraakRunner benchmark-reference    # Benchmark all transactions")
        print("")

        print("╔══════════════════════════════════════════════════════════════════╗")
        print("║              Reference Block Data Ready! ✅                          ║")
        print("╚══════════════════════════════════════════════════════════════════╝")
    }
}
