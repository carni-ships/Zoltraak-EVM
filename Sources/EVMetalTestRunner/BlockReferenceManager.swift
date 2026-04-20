import Foundation

/// Utility to fetch and save real Ethereum blocks for reference benchmarking
public struct BlockReferenceManager {

    public static func fetchAndSaveReferenceBlock(config: RealEthereumBlockFetcher.RPCConfig = .cloudflare) {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║       Fetching Reference Ethereum Block for Benchmarking            ║
        ╚══════════════════════════════════════════════════════════════════╝

        Fetching latest block from Ethereum mainnet...

        """)

        do {
            // Fetch the block
            let block = try RealEthereumBlockFetcher.fetchLatestBlock(config: config)

            print("✓ Block fetched: #\(block.number)")
            print("  Hash: \(block.hash)")
            print("  Timestamp: \(block.timestamp)")
            print("  Transactions: \(block.transactions.count)")

            // Save to file
            let savedPath = try saveBlockToFile(block: block)
            print("\n✓ Block saved to: \(savedPath)")

            // Save as Swift code for easy inclusion
            let swiftPath = try saveAsSwiftCode(block: block)
            print("✓ Swift code saved to: \(swiftPath)")

            // Print summary
            printBlockSummary(block: block)

        } catch {
            print("✗ Error: \(error)")
        }
    }

    /// Save block data to JSON file
    private static func saveBlockToFile(block: EthereumBlock) throws -> String {
        let fileName = "reference_block_\(block.number).json"
        let savePath = "/Users/carnation/Documents/Claude/EVMetal/References/\(fileName)"

        // Ensure directory exists
        let dirPath = "/Users/carnation/Documents/Claude/EVMetal/References"
        try FileManager.default.createDirectory(atPath: dirPath, withIntermediateDirectories: true)

        // Convert block to JSON
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(block)

        // Write to file
        try data.write(to: URL(fileURLWithPath: savePath))

        return savePath
    }

    /// Save block as Swift code for easy benchmarking
    private static func saveAsSwiftCode(block: EthereumBlock) throws -> String {
        let fileName = "ReferenceBlock.swift"
        let savePath = "/Users/carnation/Documents/Claude/EVMetal/References/\(fileName)"

        var code = """
//
// Reference Block #\(block.number)
// Auto-generated from Ethereum mainnet
// Generated: \(Date())
//

import Foundation

/// Reference Ethereum block for consistent benchmarking
public struct ReferenceBlock {
    public static let blockNumber = "\(block.number)"
    public static let blockHash = "\(block.hash)"
    public static let timestamp = "\(block.timestamp)"
    public static let gasUsed = "\(block.gasUsed)"
    public static let gasLimit = "\(block.gasLimit)"

    public static let transactions: [(name: String, from: String, to: String?, value: String, gas: String, bytecode: [UInt8])] = [
"""

        // Add transactions
        for (index, tx) in block.transactions.enumerated() {
            let txName = "Transaction_\(index + 1)"
            let txBytecode = tx.input.isEmpty ? "[]" : tx.input.map { "0x" + String(format: "%02x", $0) }.joined(separator: ", ")

            code += """
        // \(txName): \(tx.hash.prefix(20))...
        (
            name: "\(txName)",
            from: "\(tx.from)",
            to: \(tx.to.map { "\"\($0)\"" } ?? "nil"),
            value: "\(tx.value)",
            gas: "\(tx.gas)",
            bytecode: [UInt8](description: "\(txBytecode)")
        ),
"""
        }

        code += """
    ]
}

/// Generate realistic bytecode for transaction type
public func generateBytecode(for transaction: String) -> [UInt8] {
    switch transaction {
    case "Transaction_1":
        return generateTransaction1Bytecode()
    case "Transaction_2":
        return generateTransaction2Bytecode()
    case "Transaction_3":
        return generateTransaction3Bytecode()
    default:
        return [0x60, 0x01, 0x60, 0x02, 0x01, 0x00]  // Default: simple ADD
    }
}

private func generateTransaction1Bytecode() -> [UInt8] {
    return [
        0x60, 0x01, 0x54,  // SLOAD
        0x60, 0x02, 0x54,  // SLOAD
        0x01,              // ADD
        0x60, 0x03, 0x55,  // SSTORE
        0x00               // STOP
    ]
}

private func generateTransaction2Bytecode() -> [UInt8] {
    return [
        0x60, 0x01, 0x60, 0x00, 0x52,  // MSTORE
        0x60, 0x02, 0x60, 0x01, 0x52,  // MSTORE
        0x60, 0x00, 0x51,              // MLOAD
        0x60, 0x01, 0x51,              // MLOAD
        0x01,                          // ADD
        0x00                           // STOP
    ]
}

private func generateTransaction3Bytecode() -> [UInt8] {
    return [
        0x60, 0x01, 0x60, 0x02, 0x01,  // ADD
        0x60, 0x03, 0x02,              // MUL
        0x60, 0x04, 0x60, 0x05, 0x01,  // ADD
        0x00                           // STOP
    ]
}
"""

        try code.write(to: URL(fileURLWithPath: savePath), atomically: true, encoding: .utf8)
        return savePath
    }

    /// Print block summary
    private static func printBlockSummary(block: EthereumBlock) {
        print("""

        ╔══════════════════════════════════════════════════════════════════╗
        ║                    Block Summary                                 ║
        ╚══════════════════════════════════════════════════════════════════╝

        Block #\(block.number):
           Hash: \(block.hash.prefix(20))...
           Parent: \(block.parentHash.prefix(20))...
           Transactions: \(block.transactions.count)
           Gas Used: \(block.gasUsed)
           Gas Limit: \(block.gasLimit)

        Top Transactions:
        """)

        for (index, tx) in block.transactions.prefix(5).enumerated() {
            let txType = identifyTransactionType(tx: tx)
            print("  \(index + 1). \(txType)")
            print("     From: \(tx.from.prefix(20))...")
            print("     To: \(tx.to?.prefix(20) ?? "Contract Creation")")
            print("     Value: \(tx.value)")
            print("     Gas: \(tx.gas)")
            print("")
        }

        print("Usage:")
        print("  swift run EVMetalRunner reference-block    # Benchmark against reference block")
        print("")

        print("╔══════════════════════════════════════════════════════════════════╗")
        print("║           Reference Block Saved Successfully! ✅                  ║")
        print("╚══════════════════════════════════════════════════════════════════╝")
    }

    /// Identify transaction type based on characteristics
    private static func identifyTransactionType(tx: EthereumTransaction) -> String {
        if tx.to == nil {
            return "Contract Creation"
        } else if !tx.input.isEmpty {
            if tx.input.count > 68 {
                return "Contract Call (with calldata)"
            } else {
                return "Function Call"
            }
        } else {
            return "Simple ETH Transfer"
        }
    }
}
