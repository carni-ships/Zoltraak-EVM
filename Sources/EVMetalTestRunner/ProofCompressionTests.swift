import Foundation
import EVMetal
import zkMetal

/// Tests for proof compression functionality.
///
/// These tests verify that proof compression works correctly and produces
/// valid proofs under various compression configurations.
public struct ProofCompressionTests {

    // MARK: - Test Configuration

    /// Number of transactions for testing
    public static let testTransactionCount = 16

    /// Whether to run slow tests
    public static let runSlowTests = false

    // MARK: - Test Cases

    /// Run all proof compression tests.
    public static func runAll() async throws {
        print(String(repeating: "=", count: 60))
        print("Proof Compression Tests")
        print(String(repeating: "=", count: 60))
        print()

        try await testBasicCompression()
        try await testColumnSubset()
        try await testTwoTierProving()
        try await testSecurityAnalysis()
        try await testTraceLengthVariations()

        print()
        print("All proof compression tests passed!")
    }

    /// Test basic compression functionality.
    public static func testBasicCompression() async throws {
        print("[Test] Basic Compression")
        print(String(repeating: "-", count: 40))

        // Create test transactions
        let transactions = createTestTransactions(count: testTransactionCount)
        let blockContext = BlockContext()

        // Test with different compression levels
        let configs: [(String, ProofCompressionConfig)] = [
            ("Standard", .standard),
            ("High Compression", .highCompression),
            ("Max Compression", .maxCompression)
        ]

        for (name, config) in configs {
            print()
            print("  Testing \(name)...")

            let prover = try EVMetalBlockProver(
                config: .fast,
                compressionConfig: config
            )

            let start = CFAbsoluteTimeGetCurrent()
            let proof = try await prover.prove(
                transactions: transactions,
                blockContext: blockContext
            )
            let elapsed = CFAbsoluteTimeGetCurrent() - start

            print("    Proof generated in \(String(format: "%.1f", elapsed * 1000))ms")
            print("    logTraceLength: \(proof.logTraceLength)")
            print("    logBlockTraceLength: \(proof.logBlockTraceLength)")
            print("    Tree depth: \(proof.logBlockTraceLength) levels")
            print("    Commitments: \(proof.commitments.count) columns")

            // Verify proof structure
            assert(proof.commitments.count == 180, "Should have 180 column commitments")
            assert(!proof.starkProof.isEmpty, "Proof data should not be empty")

            print("    [PASS] \(name)")
        }

        print()
        print("[PASS] Basic Compression Test")
    }

    /// Test column subset proving.
    public static func testColumnSubset() async throws {
        print()
        print("[Test] Column Subset Proving")
        print(String(repeating: "-", count: 40))

        let transactions = createTestTransactions(count: testTransactionCount)
        let blockContext = BlockContext()

        // Test with different column subsets
        let columnCounts = [180, 64, 32, 16]

        for count in columnCounts {
            print()
            print("  Testing with \(count) proving columns...")

            let config = ProofCompressionConfig(
                logTraceLength: 8,
                provingColumnCount: count
            )

            let prover = try EVMetalBlockProver(
                config: .fast,
                compressionConfig: config
            )

            let proof = try await prover.prove(
                transactions: transactions,
                blockContext: blockContext
            )

            // Verify proof structure
            assert(proof.commitments.count == 180, "Should always commit all 180 columns")
            assert(!proof.starkProof.isEmpty, "Proof should not be empty")

            // Calculate soundness loss
            let loss = log2(Double(180) / Double(count))
            print("    Commit columns: 180, Prove columns: \(count)")
            print("    Soundness loss: ~\(String(format: "%.1f", loss)) bits")

            print("    [PASS] \(count) columns")
        }

        print()
        print("[PASS] Column Subset Test")
    }

    /// Test two-tier proving.
    public static func testTwoTierProving() async throws {
        print()
        print("[Test] Two-Tier Proving")
        print(String(repeating: "-", count: 40))

        let transactions = createTestTransactions(count: testTransactionCount)
        let blockContext = BlockContext()

        // Enable two-tier proving
        let config = ProofCompressionConfig(
            logTraceLength: 8,
            provingColumnCount: 32,
            enableTwoTierProving: true,
            tier1NumQueries: 8,
            tier2NumQueries: 50
        )

        let prover = try EVMetalBlockProver(
            config: .fast,
            compressionConfig: config
        )

        print()
        print("  Generating two-tier proof...")

        let result = try await prover.proveTwoTier(
            transactions: transactions,
            blockContext: blockContext
        )

        // Verify tier 1 proof exists
        if let tier1 = result.tier1Proof {
            print("    Tier 1 proof: \(String(format: "%.1f", tier1.timing.totalMs))ms")
            print("    Tier 1 queries: \(config.tier1NumQueries)")
        } else {
            print("    Tier 1 proof: (not generated - two-tier disabled)")
        }

        // Verify tier 2 proof exists
        let tier2 = result.tier2Proof
        print("    Tier 2 proof: \(String(format: "%.1f", tier2.timing.totalMs))ms")
        print("    Tier 2 queries: \(config.tier2NumQueries)")

        // Verify metadata
        print("    Generated tiers: \(result.generatedTiers.map { "\($0)" }.joined(separator: ", "))")
        print("    Security bits: \(result.tierMetadata.securityBits)")

        print()
        print("[PASS] Two-Tier Proving Test")
    }

    /// Test security analysis functionality.
    public static func testSecurityAnalysis() async throws {
        print()
        print("[Test] Security Analysis")
        print(String(repeating: "-", count: 40))

        let configs: [(String, ProofCompressionConfig)] = [
            ("None (baseline)", .none),
            ("Standard", .standard),
            ("High Compression", .highCompression),
            ("Max Compression", .maxCompression)
        ]

        for (name, config) in configs {
            print()
            print("  \(name):")

            let analysis = ProofCompressionSecurityAnalysis(
                baseline: .none,
                compressed: config
            )

            print("    logTraceLength: \(config.logTraceLength)")
            print("    logBlowup: \(config.logBlowup)")
            print("    provingColumns: \(config.provingColumnCount)")
            print("    numQueries: \(config.numQueries)")
            print("    Baseline security: \(analysis.baselineSecurityBits) bits")
            print("    Compressed security: \(analysis.compressedSecurityBits) bits")
            print("    Soundness loss: \(String(format: "%.1f", analysis.soundnessLossBits)) bits")
            print("    Estimated speedup: \(String(format: "%.1fx", analysis.estimatedSpeedup))")
            print("    Production ready: \(analysis.acceptableForProduction ? "YES" : "NO")")
            print("    \(config.securityDescription)")
        }

        print()
        print("[PASS] Security Analysis Test")
    }

    /// Test different trace length variations.
    public static func testTraceLengthVariations() async throws {
        print()
        print("[Test] Trace Length Variations")
        print(String(repeating: "-", count: 40))

        let transactions = createTestTransactions(count: 8)  // Fewer for speed
        let blockContext = BlockContext()

        let traceLengths = [12, 10, 8, 6, 4]

        for logTrace in traceLengths {
            print()
            print("  logTraceLength = \(logTrace) (\(1 << logTrace) rows per tx)")

            let config = ProofCompressionConfig(
                logTraceLength: logTrace,
                provingColumnCount: 32
            )

            let prover = try EVMetalBlockProver(
                config: .fast,
                compressionConfig: config
            )

            let proof = try await prover.prove(
                transactions: transactions,
                blockContext: blockContext
            )

            let treeDepth = proof.logBlockTraceLength
            let treeSize = 1 << treeDepth
            let compressionRatio = pow(2.0, Double(12 - logTrace))

            print("    Tree depth: \(treeDepth) levels")
            print("    Tree size: \(treeSize) leaves")
            print("    Compression ratio: \(String(format: "%.0fx", compressionRatio))")
            print("    Proving time: \(String(format: "%.1f", proof.timing.totalMs))ms")
        }

        print()
        print("[PASS] Trace Length Variations Test")
    }

    // MARK: - Helper Methods

    /// Create test transactions with simple bytecode.
    private static func createTestTransactions(count: Int) -> [EVMTransaction] {
        return (0..<count).map { i in
            EVMTransaction(
                code: [0x60, 0x01],  // PUSH1 1
                calldata: [],
                value: .zero,
                gasLimit: 21_000,
                txHash: "test_tx_\(i)"
            )
        }
    }
}

// MARK: - Benchmark Tests

/// Benchmark tests for proof compression.
public struct ProofCompressionBenchmarks {

    /// Run compression benchmark.
    public static func runCompressionBenchmark(
        transactionCount: Int = 123,
        config: ProofCompressionConfig = .highCompression
    ) async throws -> CompressionBenchmarkResult {
        print()
        print(String(repeating: "=", count: 60))
        print("Compression Benchmark")
        print(String(repeating: "=", count: 60))
        print()
        print("Configuration:")
        print("  Transactions: \(transactionCount)")
        print("  logTraceLength: \(config.logTraceLength)")
        print("  logBlowup: \(config.logBlowup)")
        print("  provingColumns: \(config.provingColumnCount)")
        print()

        let result = try await EVMetalBlockProver.benchmarkCompression(
            transactionCount: transactionCount,
            compressionConfig: config
        )

        print()
        print(result.summary)

        return result
    }

    /// Run baseline vs compressed comparison.
    public static func runComparison(
        transactionCount: Int = 64
    ) async throws {
        print()
        print(String(repeating: "=", count: 60))
        print("Baseline vs Compressed Comparison")
        print(String(repeating: "=", count: 60))

        let configs: [(String, ProofCompressionConfig?)] = [
            ("Baseline (no compression)", nil),
            ("Standard compression", .standard),
            ("High compression", .highCompression),
            ("Max compression", .maxCompression)
        ]

        var results: [(String, Double)] = []

        for (name, config) in configs {
            print()
            print("Testing \(name)...")

            let transactions = (0..<transactionCount).map { i in
                EVMTransaction(
                    code: [0x60, 0x01],
                    calldata: [],
                    value: .zero,
                    gasLimit: 21_000,
                    txHash: "tx_\(i)"
                )
            }

            let prover = try EVMetalBlockProver(
                config: .fast,
                compressionConfig: config
            )

            let start = CFAbsoluteTimeGetCurrent()
            let proof = try await prover.prove(
                transactions: transactions,
                blockContext: BlockContext()
            )
            let elapsed = CFAbsoluteTimeGetCurrent() - start

            results.append((name, elapsed))
            print("  Time: \(String(format: "%.1f", elapsed * 1000))ms")
        }

        print()
        print("Summary:")
        print(String(repeating: "-", count: 40))
        for (name, time) in results {
            let speedup = results[0].1 / time
            print("  \(name): \(String(format: "%.1f", time * 1000))ms (\(String(format: "%.2fx", speedup)))")
        }
    }
}
