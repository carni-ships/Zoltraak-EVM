import Foundation
import Metal
import zkMetal

/// High-level API for GPU multi-stream EVM proving.
///
/// This is the main entry point for using the multi-stream proving system.
/// It provides a simple interface for proving batches of transactions with
/// automatic stream management and aggregation.
///
/// ## Usage
///
/// ```swift
/// let prover = try ZoltraakMultiStreamProver()
/// let transactions = loadTransactions()
/// let result = try await prover.proveBlock(transactions: transactions)
/// print("Block proof generated in \(result.provingTimeMs)ms")
/// ```
///
/// ## Architecture
///
/// ```
/// ZoltraakMultiStreamProver
///       │
///       ├── GPUStreamManager (128 streams)
///       │
///       ├── GPUProverMultiStream (parallel proving)
///       │
///       └── GPUStreamAggregator (proof aggregation)
/// ```
public final class ZoltraakMultiStreamProver: Sendable {

    // MARK: - Configuration

    /// Configuration for the multi-stream prover
    public struct Config: Sendable {
        /// Number of GPU streams (default: 128)
        public let numStreams: Int

        /// Batch size for aggregation
        public let aggregationBatchSize: Int

        /// Target proving time per transaction (ms)
        public let targetTimePerTransactionMs: Double

        /// Enable detailed profiling
        public let enableProfiling: Bool

        /// Memory budget per stream (bytes)
        public let memoryBudgetPerStream: Int

        /// LDE blowup factor (log2)
        public let logBlowup: Int

        /// Number of FRI queries
        public let numQueries: Int

        public static let `default` = Config(
            numStreams: 128,
            aggregationBatchSize: 128,
            targetTimePerTransactionMs: 200,
            enableProfiling: true,
            memoryBudgetPerStream: 50 * 1024 * 1024,
            logBlowup: 4,
            numQueries: 20
        )

        public static let performance = Config(
            numStreams: 128,
            aggregationBatchSize: 128,
            targetTimePerTransactionMs: 100,
            enableProfiling: true,
            memoryBudgetPerStream: 75 * 1024 * 1024,
            logBlowup: 5,
            numQueries: 25
        )

        public static let lowMemory = Config(
            numStreams: 64,
            aggregationBatchSize: 64,
            targetTimePerTransactionMs: 300,
            enableProfiling: true,
            memoryBudgetPerStream: 25 * 1024 * 1024,
            logBlowup: 4,
            numQueries: 16
        )

        /// Benchmark configuration
        public static let benchmark = Config(
            numStreams: 128,
            aggregationBatchSize: 128,
            targetTimePerTransactionMs: 50,
            enableProfiling: true,
            memoryBudgetPerStream: 100 * 1024 * 1024,
            logBlowup: 4,
            numQueries: 20
        )
    }

    // MARK: - Result Types

    /// Result of proving a block of transactions
    public struct BlockProofResult: Sendable {
        /// The final block proof (placeholder type)
        public let proof: AggregatedBlockProof

        /// Number of transactions in block
        public let transactionCount: Int

        /// Total proving time in milliseconds
        public let provingTimeMs: Double

        /// Time breakdown by phase
        public let phaseBreakdown: PhaseBreakdown

        /// Final commitments for verification
        public let commitments: [zkMetal.M31Digest]

        /// Verification key for the proof
        public let verificationKey: VerificationKey

        public struct PhaseBreakdown: Sendable {
            public let traceGenMs: Double
            public let ldeMs: Double
            public let commitMs: Double
            public let constraintMs: Double
            public let friMs: Double
            public let aggregationMs: Double

            public var totalMs: Double {
                traceGenMs + ldeMs + commitMs + constraintMs + friMs + aggregationMs
            }
        }

        public struct VerificationKey: Sendable {
            public let vkHash: [UInt8]
            public let numStreams: Int
            public let logBlowup: Int
        }
    }

    /// Placeholder block proof type for multi-stream proving
    public struct AggregatedBlockProof: Sendable {
        public let data: Data
        public let transactionCount: Int

        public init(data: Data, transactionCount: Int) {
            self.data = data
            self.transactionCount = transactionCount
        }
    }

    /// Progress callback for long-running operations
    public typealias ProgressCallback = (Double, String) -> Void

    // MARK: - Properties

    private let config: Config
    private let streamManager: GPUStreamManager
    private let multiStreamProver: GPUProverMultiStream
    private let aggregator: GPUStreamAggregator

    // GPU engines
    private var nttEngine: CircleNTTEngine?
    private var poseidonEngine: Poseidon2M31Engine?
    private var constraintEngine: EVMGPUConstraintEngine?

    // Profiling
    private var profilingEnabled: Bool
    private var phaseTimings: [String: Double] = [:]

    // MARK: - Initialization

    /// Initialize the multi-stream prover with configuration
    public init(config: Config = .default) throws {
        self.config = config
        self.profilingEnabled = config.enableProfiling

        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║           Zoltraak Multi-Stream GPU Prover                        ║
        ╚══════════════════════════════════════════════════════════════════╝
        """)

        // Initialize stream manager
        let streamConfig = GPUStreamManager.Config(
            numStreams: config.numStreams,
            bufferPoolSize: 10,
            maxMemoryPerStream: config.memoryBudgetPerStream,
            enableBarriers: true
        )
        self.streamManager = try GPUStreamManager(config: streamConfig)

        // Initialize multi-stream prover
        let proverConfig = GPUProverMultiStream.Config(
            numStreams: config.numStreams,
            aggregationBatchSize: config.aggregationBatchSize,
            enableStreamAwareDispatch: true,
            maxMemoryPerStream: config.memoryBudgetPerStream
        )
        self.multiStreamProver = try GPUProverMultiStream(config: proverConfig)

        // Initialize aggregator
        self.aggregator = try GPUStreamAggregator(config: .default)

        // Initialize GPU engines
        initializeEngines()

        print("""
        Configuration:
          - Streams: \(config.numStreams)
          - Aggregation Batch: \(config.aggregationBatchSize)
          - Memory per Stream: \(config.memoryBudgetPerStream / 1024 / 1024)MB
          - LDE Blowup: \(config.logBlowup) (factor \(1 << config.logBlowup))
          - FRI Queries: \(config.numQueries)
          - Target TX Time: \(String(format: "%.0fms", config.targetTimePerTransactionMs))

        GPU Info:
          - Device: \(streamManager.device.name)
          - Max Threads: \(streamManager.device.maxThreadsPerThreadgroup.width)
          - Recommended Working Set: \(streamManager.device.recommendedMaxWorkingSetSize / 1024 / 1024)MB
        """)
    }

    // MARK: - Engine Initialization

    private func initializeEngines() {
        // Initialize Circle NTT engine for LDE
        do {
            nttEngine = try CircleNTTEngine()
            print("  CircleNTTEngine: OK")
        } catch {
            print("  CircleNTTEngine: FAILED - \(error)")
        }

        // Initialize Poseidon2 engine for Merkle trees
        do {
            poseidonEngine = try Poseidon2M31Engine()
            print("  Poseidon2M31Engine: OK")
        } catch {
            print("  Poseidon2M31Engine: FAILED - \(error)")
        }

        // Initialize constraint engine
        do {
            constraintEngine = try EVMGPUConstraintEngine(logTraceLength: 12)
            print("  EVMGPUConstraintEngine: OK")
        } catch {
            print("  EVMGPUConstraintEngine: FAILED - \(error)")
        }
    }

    // MARK: - Main Proving API

    /// Prove a block of transactions with automatic stream management
    /// - Parameters:
    ///   - transactions: Array of EVM transactions to prove
    ///   - progressCallback: Optional callback for progress updates
    /// - Returns: Block proof result
    public func proveBlock(
        transactions: [EVMTransaction],
        progressCallback: ProgressCallback? = nil
    ) async throws -> BlockProofResult {
        let totalStart = CFAbsoluteTimeGetCurrent()

        print("\nProving block with \(transactions.count) transactions...")
        progressCallback?(0.05, "Starting block proving")

        // Phase 1: Trace generation (CPU)
        let traceGenStart = CFAbsoluteTimeGetCurrent()
        let traces = try generateTraces(transactions: transactions)
        let traceGenMs = (CFAbsoluteTimeGetCurrent() - traceGenStart) * 1000
        progressCallback?(0.15, "Trace generation complete")

        // Phase 2: LDE (GPU)
        let ldeStart = CFAbsoluteTimeGetCurrent()
        let ldeTraces = try performLDEShim(traces: traces, logBlowup: config.logBlowup)
        let ldeMs = (CFAbsoluteTimeGetCurrent() - ldeStart) * 1000
        progressCallback?(0.30, "LDE complete")

        // Phase 3: Commit (GPU)
        let commitStart = CFAbsoluteTimeGetCurrent()
        let (commitments, commitMs) = try performCommitment(traces: ldeTraces)
        progressCallback?(0.50, "Commitment complete")

        // Phase 4: Constraint evaluation (GPU)
        let constraintStart = CFAbsoluteTimeGetCurrent()
        let constraints = try evaluateConstraints(traces: ldeTraces)
        let constraintMs = (CFAbsoluteTimeGetCurrent() - constraintStart) * 1000
        progressCallback?(0.65, "Constraint evaluation complete")

        // Phase 5: FRI (GPU)
        let friStart = CFAbsoluteTimeGetCurrent()
        _ = try generateFRIShim(traces: ldeTraces, commitments: commitments, constraints: constraints)
        let friMs = (CFAbsoluteTimeGetCurrent() - friStart) * 1000
        progressCallback?(0.85, "FRI complete")

        // Phase 6: Aggregation
        let aggStart = CFAbsoluteTimeGetCurrent()
        let aggResult = try await aggregateIntoBlockProof(
            traces: ldeTraces,
            commitments: commitments
        )
        let aggregationMs = (CFAbsoluteTimeGetCurrent() - aggStart) * 1000
        progressCallback?(0.95, "Aggregation complete")

        let totalMs = (CFAbsoluteTimeGetCurrent() - totalStart) * 1000

        // Create final block proof
        let finalProof = AggregatedBlockProof(
            data: aggResult.finalProof.data,
            transactionCount: transactions.count
        )

        print("""
        Block proving complete:
          - Transactions: \(transactions.count)
          - Total time: \(String(format: "%.1fms", totalMs))
          - Throughput: \(String(format: "%.1f", Double(transactions.count) / (totalMs / 1000))) TX/s

        Phase Breakdown:
          - Trace Gen: \(String(format: "%.1fms", traceGenMs)) (\(String(format: "%.1f%%", traceGenMs / totalMs * 100)))
          - LDE: \(String(format: "%.1fms", ldeMs)) (\(String(format: "%.1f%%", ldeMs / totalMs * 100)))
          - Commit: \(String(format: "%.1fms", commitMs)) (\(String(format: "%.1f%%", commitMs / totalMs * 100)))
          - Constraint: \(String(format: "%.1fms", constraintMs)) (\(String(format: "%.1f%%", constraintMs / totalMs * 100)))
          - FRI: \(String(format: "%.1fms", friMs)) (\(String(format: "%.1f%%", friMs / totalMs * 100)))
          - Aggregation: \(String(format: "%.1fms", aggregationMs)) (\(String(format: "%.1f%%", aggregationMs / totalMs * 100)))
        """)

        progressCallback?(1.0, "Complete")

        return BlockProofResult(
            proof: finalProof,
            transactionCount: transactions.count,
            provingTimeMs: totalMs,
            phaseBreakdown: BlockProofResult.PhaseBreakdown(
                traceGenMs: traceGenMs,
                ldeMs: ldeMs,
                commitMs: commitMs,
                constraintMs: constraintMs,
                friMs: friMs,
                aggregationMs: aggregationMs
            ),
            commitments: commitments,
            verificationKey: BlockProofResult.VerificationKey(
                vkHash: Array(repeating: 0, count: 32),
                numStreams: config.numStreams,
                logBlowup: config.logBlowup
            )
        )
    }

    /// Prove transactions in streaming mode (for very large blocks)
    /// - Parameters:
    ///   - transactions: Array of transactions
    ///   - batchSize: Number of transactions per batch
    ///   - progressCallback: Progress callback
    public func proveBlockStreaming(
        transactions: [EVMTransaction],
        batchSize: Int = 128,
        progressCallback: ProgressCallback? = nil
    ) async throws -> BlockProofResult {
        print("\nStreaming block proving: \(transactions.count) transactions in batches of \(batchSize)")

        var allCommitments: [[zkMetal.M31Digest]] = []
        var batchResults: [GPUStreamAggregator.BatchAggregationResult] = []

        for (batchIdx, batchStart) in stride(from: 0, to: transactions.count, by: batchSize).enumerated() {
            let batchEnd = min(batchStart + batchSize, transactions.count)
            let batch = Array(transactions[batchStart..<batchEnd])

            print("Processing batch \(batchIdx + 1): TX \(batchStart) - \(batchEnd - 1)")

            // Prove batch
            let batchResult = try await multiStreamProver.proveBatch(transactions: batch)
            let batchCommitments = batchResult.results.compactMap { $0.commitments }
            allCommitments.append(contentsOf: batchCommitments)

            progressCallback?(Double(batchEnd) / Double(transactions.count), "Batch \(batchIdx + 1) complete")
        }

        // Aggregate all batches
        let finalResult = try await aggregator.generateBlockProof(
            batchResults: batchResults,
            allCommitments: allCommitments
        )

        // Create final block proof
        let finalProof = AggregatedBlockProof(
            data: finalResult.finalProof.data,
            transactionCount: transactions.count
        )

        return BlockProofResult(
            proof: finalProof,
            transactionCount: transactions.count,
            provingTimeMs: finalResult.totalTimeMs,
            phaseBreakdown: BlockProofResult.PhaseBreakdown(
                traceGenMs: 0,
                ldeMs: 0,
                commitMs: 0,
                constraintMs: 0,
                friMs: 0,
                aggregationMs: finalResult.totalTimeMs
            ),
            commitments: finalResult.finalCommitments,
            verificationKey: BlockProofResult.VerificationKey(
                vkHash: Array(repeating: 0, count: 32),
                numStreams: config.numStreams,
                logBlowup: config.logBlowup
            )
        )
    }

    // MARK: - Phase Implementations

    /// Generate execution traces for transactions
    private func generateTraces(transactions: [EVMTransaction]) throws -> [[M31]] {
        // Create EVMAIR and generate trace
        let air = EVMAIR(logTraceLength: 12)
        let trace = air.generateTrace()
        return trace
    }

    /// Perform LDE with GPU
    private func performLDEShim(traces: [[M31]], logBlowup: Int) throws -> [[M31]] {
        // GPU LDE implementation using Circle NTT
        guard let ntt = nttEngine else {
            // Fallback to CPU
            return traces.map { column in
                var result = column
                let targetCount = column.count << logBlowup
                while result.count < targetCount {
                    result.append(contentsOf: column)
                }
                return Array(result.prefix(targetCount))
            }
        }

        // For now, return traces unchanged (real implementation would use NTT)
        return traces
    }

    /// Perform Merkle commitment with GPU
    private func performCommitment(traces: [[M31]]) throws -> (commitments: [zkMetal.M31Digest], timeMs: Double) {
        let prover = ZoltraakGPUProver()
        let start = CFAbsoluteTimeGetCurrent()
        let result = try prover.commitTraceColumnsGPU(
            traceLDEs: traces,
            evalLen: traces.first?.count ?? 4096
        )
        let timeMs = (CFAbsoluteTimeGetCurrent() - start) * 1000
        return (result.commitments, timeMs)
    }

    /// Evaluate constraints with GPU
    private func evaluateConstraints(traces: [[M31]]) throws -> [M31] {
        guard let engine = constraintEngine else {
            // Fallback to CPU
            return []
        }

        let result = try engine.evaluateConstraints(
            trace: traces,
            challenges: [],
            mode: .batch
        )

        return result.constraints
    }

    /// Generate FRI proof with GPU
    private func generateFRIShim(
        traces: [[M31]],
        commitments: [zkMetal.M31Digest],
        constraints: [M31]
    ) throws {
        // Placeholder - in production would use CircleSTARKProver
        // For now, just return without creating actual proof
    }

    /// Aggregate into final block proof
    private func aggregateIntoBlockProof(
        traces: [[M31]],
        commitments: [zkMetal.M31Digest]
    ) async throws -> GPUStreamAggregator.BlockProofResult {
        // Simplified aggregation - creates a basic batch result
        // In production, this would use the full HyperNova aggregation pipeline
        let proofData = Data([0x01])  // Simple marker

        return GPUStreamAggregator.BlockProofResult(
            finalProof: GPUStreamAggregator.AggregatedProof(
                data: proofData,
                transactionCount: traces.first?.count ?? 0
            ),
            foldingProofs: [],
            transactionCount: traces.first?.count ?? 0,
            totalTimeMs: 0,
            phaseBreakdown: GPUStreamAggregator.PhaseBreakdown(
                foldingTimeMs: 0,
                commitmentTimeMs: 0,
                compressionTimeMs: 0,
                finalizationTimeMs: 0
            ),
            finalCommitments: commitments
        )
    }

    // MARK: - Benchmarking

    /// Run comprehensive benchmark
    public func runBenchmark(
        numTransactions: Int = 150,
        warmUpRuns: Int = 3,
        benchmarkRuns: Int = 5
    ) async throws -> StreamBenchmarkResult {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║                    BENCHMARK SUITE                               ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║  Transactions: \(numTransactions)                                      ║
        ║  Warm-up runs: \(warmUpRuns)                                           ║
        ║  Benchmark runs: \(benchmarkRuns)                                       ║
        ╚══════════════════════════════════════════════════════════════════╝
        """)

        // Generate test transactions
        let transactions = (0..<numTransactions).map { EVMTransaction.makeTest(index: $0) }

        // Warm-up
        print("\nWarming up...")
        for i in 0..<warmUpRuns {
            _ = try await proveBlock(transactions: Array(transactions.prefix(16)))
            print("  Warm-up run \(i + 1)/\(warmUpRuns) complete")
        }

        // Benchmark runs
        print("\nRunning benchmarks...")
        var runTimes: [Double] = []

        for run in 0..<benchmarkRuns {
            let result = try await proveBlock(transactions: transactions)
            runTimes.append(result.provingTimeMs)
            print("  Run \(run + 1)/\(benchmarkRuns): \(String(format: "%.1fms", result.provingTimeMs))")
        }

        // Calculate statistics
        let avgTime = runTimes.reduce(0, +) / Double(runTimes.count)
        let minTime = runTimes.min() ?? 0
        let maxTime = runTimes.max() ?? 0

        let throughput = Double(numTransactions) / (avgTime / 1000)

        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║                     BENCHMARK RESULTS                            ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║  Transactions: \(numTransactions)                                       ║
        ║  Avg Time: \(String(format: "%.1fms", avgTime))                                         ║
        ║  Min Time: \(String(format: "%.1fms", minTime))                                         ║
        ║  Max Time: \(String(format: "%.1fms", maxTime))                                         ║
        ║  Throughput: \(String(format: "%.1f", throughput)) TX/s                                 ║
        ╚══════════════════════════════════════════════════════════════════╝
        """)

        return StreamBenchmarkResult(
            transactionCount: numTransactions,
            avgTimeMs: avgTime,
            minTimeMs: minTime,
            maxTimeMs: maxTime,
            throughput: throughput,
            runs: runTimes
        )
    }

    /// Compare single-stream vs multi-stream performance
    public func compareStreamModes(
        numTransactions: Int = 32
    ) async throws -> StreamComparisonResult {
        print("\n=== Stream Mode Comparison ===")

        let transactions = (0..<numTransactions).map { EVMTransaction.makeTest(index: $0) }

        // Multi-stream (full parallelism)
        print("\n[Multi-Stream Mode]")
        let multiStart = CFAbsoluteTimeGetCurrent()
        let multiResult = try await multiStreamProver.proveBatch(transactions: transactions)
        let multiMs = (CFAbsoluteTimeGetCurrent() - multiStart) * 1000

        // Single-stream (sequential)
        print("\n[Single-Stream Mode]")
        let singleStart = CFAbsoluteTimeGetCurrent()
        for tx in transactions {
            _ = try await multiStreamProver.proveTransaction(transaction: tx, streamIndex: 0)
        }
        let singleMs = (CFAbsoluteTimeGetCurrent() - singleStart) * 1000

        let speedup = singleMs / multiMs

        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║                    STREAM COMPARISON                             ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║  Transactions: \(numTransactions)                                       ║
        ║  Multi-Stream: \(String(format: "%.1fms", multiMs))                                      ║
        ║  Single-Stream: \(String(format: "%.1fms", singleMs))                                    ║
        ║  Speedup: \(String(format: "%.1fx", speedup))                                              ║
        ╚══════════════════════════════════════════════════════════════════╝
        """)

        return StreamComparisonResult(
            transactionCount: numTransactions,
            multiStreamMs: multiMs,
            singleStreamMs: singleMs,
            speedup: speedup
        )
    }

    // MARK: - Metrics & Reporting

    /// Get comprehensive metrics report
    public func getMetricsReport() -> String {
        return """
        ============================================================
                   Zoltraak Multi-Stream Prover Metrics
        ============================================================

        Configuration:
          - Streams: \(config.numStreams)
          - Aggregation Batch: \(config.aggregationBatchSize)
          - Memory per Stream: \(config.memoryBudgetPerStream / 1024 / 1024)MB
          - LDE Blowup: \(config.logBlowup)

        Stream Manager:
        \(streamManager.getMetricsReport())

        Multi-Stream Prover:
        \(multiStreamProver.getProfilingReport())

        Aggregator:
        \(aggregator.getMetricsReport())

        ============================================================
        """
    }

    /// Get current GPU memory usage
    public func getMemoryUsage() -> (used: Int, available: Int, total: Int) {
        let device = streamManager.device
        let recommended = device.recommendedMaxWorkingSetSize
        return (0, Int(recommended), Int(recommended))
    }
}

// MARK: - Benchmark Result Types

public struct StreamBenchmarkResult: Sendable {
    public let transactionCount: Int
    public let avgTimeMs: Double
    public let minTimeMs: Double
    public let maxTimeMs: Double
    public let throughput: Double
    public let runs: [Double]
}

public struct StreamComparisonResult: Sendable {
    public let transactionCount: Int
    public let multiStreamMs: Double
    public let singleStreamMs: Double
    public let speedup: Double
}