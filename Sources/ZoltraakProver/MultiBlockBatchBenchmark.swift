import Foundation
import zkMetal
import Zoltraak

/// Simple multi-block batch benchmark
public struct MultiBlockBatchBenchmark {

    /// Benchmark proving multiple blocks sequentially with IVC folding
    public static func run(
        startBlock: UInt64 = 21000000,
        blockCount: Int = 3,
        useCompression: Bool = true
    ) async throws {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║       Multi-Block Batch Proving Benchmark                      ║
        ╚══════════════════════════════════════════════════════════════════╝

        Blocks: \(blockCount) consecutive blocks starting at #\(startBlock)
        Mode: \(useCompression ? "Ultra-compressed (16 columns)" : "Standard (32 columns)")
        """)

        let rpcConfig = RealEthereumBlockFetcher.RPCConfig.publicNode

        // Configuration - use default IVC config to avoid internal init issues
        let blockConfig = BlockProvingConfig(
            numQueries: 4,
            logBlowup: 1,
            logTraceLength: 6,
            useGPU: true,
            maxTransactionsPerBlock: 200,
            enableInterTxConstraints: false,
            gpuBatchSize: 512,
            useArchiveNodeWitness: false,
            archiveNodeURL: nil,
            useStateProofs: false,
            stateProofMode: .withoutProofs
        )

        // Use default IVC config
        let ivcConfig = IVCProvingConfig(
            ivcConfig: .default,
            enableCycleFold: false,
            generateFinalProof: false,
            maxBlocksPerAccumulator: blockCount + 10
        )

        // Create prover
        let ivcProver = try ZoltraakIVCBlockProver(
            blockConfig: blockConfig,
            ivcConfig: ivcConfig
        )

        let totalStart = CFAbsoluteTimeGetCurrent()
        var blockTimes: [(blockNum: UInt64, proveMs: Double)] = []

        // Prove each block
        for i in 0..<blockCount {
            let blockNum = startBlock + UInt64(i)
            let blockStart = CFAbsoluteTimeGetCurrent()

            print("\n[Block \(i+1)/\(blockCount)] Fetching block #\(blockNum)...")

            // Fetch block
            let hexBlock = String(format: "0x%llx", blockNum)
            let block = try RealEthereumBlockFetcher.fetchBlock(number: hexBlock, config: rpcConfig)

            print("[Block \(i+1)] Got \(block.transactions.count) transactions")

            // Convert transactions
            var evmTxs: [EVMTransaction] = []
            for tx in block.transactions.prefix(50) {
                let code: [UInt8]
                let calldata: [UInt8]

                if tx.to == nil && !tx.input.isEmpty {
                    code = tx.input
                    calldata = []
                } else if let toAddr = tx.to, !toAddr.isEmpty {
                    code = [0x60, 0x01, 0x00]  // Minimal placeholder
                    calldata = tx.input
                } else {
                    code = []
                    calldata = []
                }

                evmTxs.append(EVMTransaction(
                    code: code,
                    calldata: calldata,
                    value: .zero,
                    gasLimit: 1_000_000,
                    txHash: tx.hash
                ))
            }

            // Create block context - simplified
            let timestampVal = parseHexToUInt64(block.timestamp)
            let gasLimitVal = parseHexToUInt64(block.gasLimit)

            let context = BlockContext(
                beneficiary: M31Word.zero,
                gasLimit: gasLimitVal,
                timestamp: timestampVal,
                number: blockNum,
                difficulty: M31Word.zero,
                prevRandao: M31Word.zero,
                baseFee: M31Word(limbs: [M31(v: 1), M31.zero, M31.zero, M31.zero, M31.zero, M31.zero, M31.zero, M31.zero, M31.zero]),
                chainId: M31Word(low64: 1),
                blockhashes: [M31Word](repeating: .zero, count: 256)
            )

            print("[Block \(i+1)] Proving...")

            // Prove block with IVC
            let ivcResult = try await ivcProver.proveIVC(
                transactions: evmTxs,
                blockContext: context
            )

            let blockTime = (CFAbsoluteTimeGetCurrent() - blockStart) * 1000
            blockTimes.append((blockNum, blockTime))

            print("[Block \(i+1)] Proved in \(String(format: "%.1f", blockTime))ms (accumulated: \(ivcResult.accumulatedBlocks) blocks)")
        }

        let totalTime = (CFAbsoluteTimeGetCurrent() - totalStart) * 1000
        let totalTxs = blockTimes.count * 50  // Approximate

        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║              Multi-Block Batch Results                        ║
        ╚══════════════════════════════════════════════════════════════════╝

        Blocks proven: \(blockCount)
        Total time: \(String(format: "%.1f", totalTime))ms
        Per-block breakdown:
        """)

        for bt in blockTimes {
            print("  Block \(bt.blockNum): \(String(format: "%.1f", bt.proveMs))ms")
        }

        let avgTime = totalTime / Double(blockCount)
        let txPerSec = Double(totalTxs) / (totalTime / 1000.0)
        print("""
        Average per block: \(String(format: "%.1f", avgTime))ms
        Estimated TX/s: \(String(format: "%.1f", txPerSec)) TX/s
        """)
    }

    /// Parse hex string to UInt64
    private static func parseHexToUInt64(_ hex: String) -> UInt64 {
        var cleanHex = hex
        if hex.hasPrefix("0x") || hex.hasPrefix("0X") {
            cleanHex = String(hex.dropFirst(2))
        }
        var result: UInt64 = 0
        for char in cleanHex {
            result = result * 16
            if let digit = char.hexDigitValue {
                result += UInt64(digit)
            }
        }
        return result
    }
}
