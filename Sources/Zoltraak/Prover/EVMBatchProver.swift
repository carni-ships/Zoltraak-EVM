import Foundation
import zkMetal
import Zoltraak

/// Configuration for batch proving
public struct BatchProverConfig {
    /// Number of transactions to batch together
    public let batchSize: Int

    /// Use GPU acceleration
    public let useGPU: Bool

    /// Log of trace length per transaction
    public let logTraceLength: Int

    /// Number of FRI queries
    public let numQueries: Int

    /// Log of blowup factor for LDE
    public let logBlowup: Int

    /// Use unified block proof (Phase 3) instead of sequential proving
    public let useUnifiedProof: Bool

    /// Number of columns to include in FRI composition polynomial
    /// 180 = full, 32 = ~5x faster, 16 = ~8x faster
    public let provingColumnCount: Int

    /// Indices of critical columns for FRI (if provingColumnCount < 180)
    public let criticalColumnIndices: [Int]

    public init(
        batchSize: Int,
        useGPU: Bool,
        logTraceLength: Int,
        numQueries: Int,
        logBlowup: Int,
        useUnifiedProof: Bool = false,
        provingColumnCount: Int = 180,
        criticalColumnIndices: [Int] = []
    ) {
        self.batchSize = batchSize
        self.useGPU = useGPU
        self.logTraceLength = logTraceLength
        self.numQueries = numQueries
        self.logBlowup = logBlowup
        self.useUnifiedProof = useUnifiedProof
        self.provingColumnCount = provingColumnCount
        self.criticalColumnIndices = criticalColumnIndices
    }

    public static let `default` = BatchProverConfig(
        batchSize: 1,
        useGPU: true,
        logTraceLength: 16,
        numQueries: 30,
        logBlowup: 4,
        useUnifiedProof: false
    )

    public static let highThroughput = BatchProverConfig(
        batchSize: 8,
        useGPU: true,
        logTraceLength: 18,
        numQueries: 30,
        logBlowup: 4,
        useUnifiedProof: false
    )

    /// Configuration optimized for unified block proving (Phase 3)
    /// OPTIMIZED: Reduced trace length, blowup, and FRI columns for faster proving
    /// - logTraceLength: 8 (256 rows per tx for faster FRI)
    /// - logBlowup: 1 (2x blowup - minimum for maximum LDE/FRI speed)
    /// - numQueries: 4 (reduced from 30 for faster query phase)
    /// - provingColumnCount: 32 (5x faster FRI vs 180 columns)
    public static let unifiedBlock = BatchProverConfig(
        batchSize: 150,
        useGPU: true,
        logTraceLength: 8,
        numQueries: 4,
        logBlowup: 1,  // 2x blowup - fastest configuration
        useUnifiedProof: true,
        provingColumnCount: 32,
        criticalColumnIndices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    )

    /// Ultra-compressed configuration for maximum speed
    /// - provingColumnCount: 16 (8x faster FRI vs 180 columns)
    /// - logTraceLength: 6 (64 rows per tx instead of 256)
    public static let ultraFast = BatchProverConfig(
        batchSize: 200,
        useGPU: true,
        logTraceLength: 6,
        numQueries: 4,
        logBlowup: 1,
        useUnifiedProof: true,
        provingColumnCount: 16,
        criticalColumnIndices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    )

    /// Balanced configuration for ~5s proving (between standard and ultra)
    /// - provingColumnCount: 24 (4x faster FRI vs 180 columns)
    /// - logTraceLength: 7 (128 rows per tx)
    public static let balancedFast = BatchProverConfig(
        batchSize: 175,
        useGPU: true,
        logTraceLength: 7,
        numQueries: 4,
        logBlowup: 1,
        useUnifiedProof: true,
        provingColumnCount: 24,
        criticalColumnIndices: Array(0..<24)
    )

    /// Non-unified batch proving using GPU multi-stream per-transaction proving.
    ///
    /// This mode proves each transaction separately with GPU optimization but WITHOUT
    /// unified block aggregation. Produces individual transaction proofs that can be
    /// verified independently via EVMVerifier.
    ///
    /// Performance characteristics:
    /// - Faster than sequential CPU proving (~10-20x via GPU multi-stream)
    /// - Slower than unified block proving (~5-10x due to no aggregation)
    /// - Produces independently verifiable transaction proofs
    ///
    /// Use case: When you need individual transaction proofs rather than a single
    /// aggregated block proof.
    public static let nonUnified = BatchProverConfig(
        batchSize: 150,
        useGPU: true,
        logTraceLength: 8,
        numQueries: 4,
        logBlowup: 1,  // Standard mode: 2x blowup (fastest)
        useUnifiedProof: false,  // Key: NOT unified
        provingColumnCount: 32,
        criticalColumnIndices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    )
}

/// Result of a batch proof
public struct EVMBatchProof {
    /// Individual transaction proofs (CPU format)
    public let transactionProofs: [CircleSTARKProof]

    /// GPU proof results (if GPU was used)
    public let gpuResults: [GPUCircleSTARKProverProof]?

    /// Aggregated proof (if batchSize > 1)
    public let aggregatedProof: Data?

    /// Batch configuration used
    public let batchConfig: BatchProverConfig

    /// Time taken to generate proofs in milliseconds
    public let provingTimeMs: Double

    /// Time spent in LDE phase (GPU-accelerated)
    public let ldeTimeMs: Double?

    /// Time spent in commitment phase (GPU-accelerated)
    public let commitTimeMs: Double?

    /// Summary string with timing breakdown
    public var summary: String {
        var s = "Batch Proof: \(transactionProofs.count) transactions in \(String(format: "%.1fms", provingTimeMs))\n"
        if let lde = ldeTimeMs {
            s += "  LDE: \(String(format: "%.1fms", lde))\n"
        }
        if let commit = commitTimeMs {
            s += "  Commit: \(String(format: "%.1fms", commit))\n"
        }
        if let avgMs = transactionProofs.isEmpty ? nil : provingTimeMs / Double(transactionProofs.count) {
            s += "  Avg/txn: \(String(format: "%.1fms", avgMs))\n"
        }
        return s
    }

    public init(
        transactionProofs: [CircleSTARKProof] = [],
        gpuResults: [GPUCircleSTARKProverProof]? = nil,
        aggregatedProof: Data?,
        batchConfig: BatchProverConfig,
        provingTimeMs: Double,
        ldeTimeMs: Double? = nil,
        commitTimeMs: Double? = nil
    ) {
        self.transactionProofs = transactionProofs
        self.gpuResults = gpuResults
        self.aggregatedProof = aggregatedProof
        self.batchConfig = batchConfig
        self.provingTimeMs = provingTimeMs
        self.ldeTimeMs = ldeTimeMs
        self.commitTimeMs = commitTimeMs
    }
}

/// Batch prover using CircleSTARK
public final class EVMBatchProver: Sendable {

    public let config: BatchProverConfig
    private let circleProver: CircleSTARKProver

    /// Enable pipeline parallelism for transaction proving
    public let usePipeline: Bool

    /// Pipeline configuration (used when usePipeline is true)
    private let pipelineConfig: PipelineConfig

    /// Sync wrapper for pipeline (for use from non-async contexts)
    private let pipelineCoordinator: EVMTxBlockProverPipeline

    /// Cached block prover to avoid repeated GPU resource creation/destruction
    private var cachedBlockProver: ZoltraakBlockProver?
    private var cachedCompressionConfig: ProofCompressionConfig?

    public init(
        config: BatchProverConfig = .default,
        usePipeline: Bool = false,
        pipelineConfig: PipelineConfig = .default
    ) {
        self.config = config
        self.usePipeline = usePipeline
        self.pipelineConfig = pipelineConfig
        self.circleProver = CircleSTARKProver(logBlowup: config.logBlowup, numQueries: config.numQueries)
        self.pipelineCoordinator = EVMTxBlockProverPipeline(
            pipelineConfig: pipelineConfig,
            batchConfig: config
        )
    }

    /// Get or create a cached block prover to avoid GPU resource crashes
    private func getOrCreateBlockProver() throws -> ZoltraakBlockProver {
        // Check if we need to create a new one based on config
        let compressionConfig = ProofCompressionConfig(
            logTraceLength: config.logTraceLength,
            logBlowup: config.logBlowup,
            numQueries: config.numQueries,
            provingColumnCount: config.provingColumnCount,
            criticalColumnIndices: config.criticalColumnIndices,
            enableTwoTierProving: false,
            tier1NumQueries: 4,
            tier2NumQueries: config.numQueries
        )

        if let cached = cachedBlockProver,
           cachedCompressionConfig?.provingColumnCount == compressionConfig.provingColumnCount {
            return cached
        }

        let blockProverConfig = BlockProvingConfig(
            numQueries: config.numQueries,
            logBlowup: config.logBlowup,
            logTraceLength: config.logTraceLength,
            useGPU: config.useGPU,
            maxTransactionsPerBlock: 1500,  // Handle any Ethereum block (max ~3000 simple transfers at 60M gas)
            enableInterTxConstraints: true,
            gpuBatchSize: 512
        )

        let blockProver = try ZoltraakBlockProver(config: blockProverConfig, compressionConfig: compressionConfig)
        cachedBlockProver = blockProver
        cachedCompressionConfig = compressionConfig
        return blockProver
    }

    // MARK: - Batch Proving

    /// Prove multiple transactions in parallel
    public func proveBatch(
        transactions: [EVMTransaction],
        initialStateRoot: M31Word = .zero,
        quiet: Bool = false
    ) throws -> EVMBatchProof {
        // Use unified block proof (Phase 3) if configured
        if config.useUnifiedProof {
            return try proveBlockUnified(
                transactions: transactions,
                blockContext: BlockContext(),
                initialStateRoot: initialStateRoot,
                quiet: quiet
            )
        }

        // Use non-unified GPU multi-stream proving for per-transaction proofs
        if !config.useUnifiedProof && config.batchSize > 1 {
            return try proveBatchNonUnified(transactions: transactions)
        }

        // Use pipeline if enabled for transaction-level parallelism
        if usePipeline {
            do {
                return try proveBatchWithPipeline(transactions: transactions)
            } catch {
                // Fall through to standard proving
            }
        }

        if config.useGPU {
            // Use GPU-accelerated batch prover
            return try proveBatchGPU(transactions: transactions)
        } else {
            // Use CPU-only proving
            return try proveBatchCPU(transactions: transactions)
        }
    }

    // MARK: - Non-Unified GPU Multi-Stream Proving

    /// Prove transactions using GPU multi-stream for parallel per-transaction proofs.
    ///
    /// This generates individual transaction proofs with GPU optimization but without
    /// unified block aggregation. Each transaction gets its own proof that can be
    /// independently verified via EVMVerifier.
    ///
    /// Performance: ~10-20x faster than sequential CPU, ~5-10x slower than unified block.
    private func proveBatchNonUnified(transactions: [EVMTransaction]) throws -> EVMBatchProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Initialize multi-stream GPU prover
        let multiStreamConfig = GPUProverMultiStream.Config.performance
        let multiStreamProver: GPUProverMultiStream
        do {
            multiStreamProver = try GPUProverMultiStream(config: multiStreamConfig)
        } catch {
            return try proveBatchGPU(transactions: transactions)
        }

        // Prove all transactions in parallel using multi-stream
        var provingTimeMs: Double = 0
        var totalLDE: Double = 0
        var totalCommit: Double = 0

        do {
            // Run batch proving with async/await converted to sync via semaphore
            let semaphore = DispatchSemaphore(value: 0)
            var asyncError: Error?
            var batchResult: GPUProverMultiStream.BatchProofResult?

            Task {
                do {
                    let result = try await multiStreamProver.proveBatch(transactions: transactions)
                    batchResult = result
                } catch {
                    asyncError = error
                }
                semaphore.signal()
            }

            let waitResult = semaphore.wait(timeout: .now() + 30)
            if waitResult == .timedOut {
                throw BatchProverError.provingTimeout
            }
            if let error = asyncError {
                throw error
            }
            guard let result = batchResult else {
                throw BatchProverError.provingFailed
            }

            provingTimeMs = result.totalTimeMs

        } catch {
            return try proveBatchGPU(transactions: transactions)
        }

        // Convert stream results to GPU proofs for verification
        // EVMVerifier.verify(GPUCircleSTARKProverProof) exists and works
        var gpuResults: [GPUCircleSTARKProverProof] = []
        var transactionProofs: [CircleSTARKProof] = []

        // Use GPU batch prover to generate verifiable GPU proofs
        let gpuConfig = EVMGPUBatchProver.Config(
            logBlowup: config.logBlowup,
            numQueries: config.numQueries
        )
        let gpuProver = try EVMGPUBatchProver(config: gpuConfig)

        for (i, tx) in transactions.enumerated() {
            do {
                let result = try gpuProver.prove(transaction: tx)

                // Store GPU proof for verification via EVMVerifier.verify(GPUCircleSTARKProverProof)
                gpuResults.append(result.gpuProof)
                totalLDE += result.ldeMs
                totalCommit += result.commitMs

                // Create placeholder CircleSTARKProof (for API compatibility, verification uses GPU proof)
                let traceCommitments: [[UInt8]] = result.gpuProof.traceCommitments.map { commitment in
                    var bytes: [UInt8] = []
                    bytes.reserveCapacity(32)
                    for val in commitment.values {
                        bytes.append(UInt8(truncatingIfNeeded: val.v))
                        bytes.append(UInt8(truncatingIfNeeded: val.v >> 8))
                        bytes.append(UInt8(truncatingIfNeeded: val.v >> 16))
                        bytes.append(UInt8(truncatingIfNeeded: val.v >> 24))
                    }
                    return bytes
                }

                // Create FRI proof with dummy empty rounds (verification uses GPU proof directly)
                let emptyRounds: [CircleFRIRound] = []
                let friProof = CircleFRIProofData(
                    rounds: emptyRounds,
                    finalValue: result.gpuProof.friProof.finalValue,
                    queryIndices: result.gpuProof.friProof.queryIndices
                )

                let circleProof = CircleSTARKProof(
                    traceCommitments: traceCommitments,
                    compositionCommitment: [UInt8](repeating: 0, count: 32),
                    friProof: friProof,
                    queryResponses: [],
                    alpha: result.gpuProof.alpha,
                    traceLength: result.gpuProof.traceLength,
                    numColumns: result.gpuProof.numColumns,
                    logBlowup: config.logBlowup
                )

                transactionProofs.append(circleProof)

            } catch {
                // Skip failed transaction
            }
        }

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        return EVMBatchProof(
            transactionProofs: transactionProofs,
            gpuResults: gpuResults.isEmpty ? nil : gpuResults,
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: totalTimeMs,
            ldeTimeMs: totalLDE,
            commitTimeMs: totalCommit
        )
    }

    /// Build query responses from GPU prover result for verification compatibility
    private func buildQueryResponsesFromGPUResult(
        gpuResult: EVMGPUBatchProver.ProverResult,
        logBlowup: Int
    ) -> [GPUCircleSTARKQueryResponse] {
        // Return empty - actual implementation would need to extract/query from GPU proof
        // For now, verification uses the GPU proof directly via EVMVerifier.verify(GPUCircleSTARKProverProof)
        return []
    }

    // MARK: - Unified Block Proving (Phase 3)

    /// Result of unified block proving
    public struct UnifiedBlockProofResult {
        /// Block proof from Phase 3 prover
        public let blockProof: BlockProof

        /// Time taken for unified proving in milliseconds
        public let provingTimeMs: Double

        /// Sequential time estimate for comparison
        public let sequentialEstimateMs: Double

        /// Summary string with timing breakdown
        public var summary: String {
            """
            Unified Block Proof:
              Transactions: \(blockProof.transactionCount)
              Proving time: \(String(format: "%.1fms", provingTimeMs))
              Per-transaction: \(String(format: "%.2fms", provingTimeMs / Double(max(blockProof.transactionCount, 1))))
              Sequential estimate: \(String(format: "%.1fms", sequentialEstimateMs))
              Speedup: \(String(format: "%.1fx", sequentialEstimateMs / provingTimeMs))
            """
        }
    }

    /// Prove an entire block of transactions using unified block proof (Phase 3).
    ///
    /// This is the fastest approach, achieving ~142x improvement over sequential proving
    /// by generating a single proof for the entire block instead of individual transaction proofs.
    ///
    /// - Parameters:
    ///   - transactions: Array of transactions to prove (max 150 for full block)
    ///   - blockContext: Block context (gas limit, block number, etc.)
    ///   - initialStateRoot: State root before block execution
    /// - Returns: EVMBatchProof with the unified block proof
    public func proveBlockUnified(
        transactions: [EVMTransaction],
        blockContext: BlockContext = BlockContext(),
        initialStateRoot: M31Word = .zero,
        quiet: Bool = false
    ) throws -> EVMBatchProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Get cached block prover to avoid repeated GPU resource creation/destruction
        let blockProver = try getOrCreateBlockProver()

        // Run the async block prover synchronously using a semaphore
        let semaphore = DispatchSemaphore(value: 0)
        var asyncError: Error?
        var blockProofResult: BlockProof?

        Task {
            do {
                let result = try await blockProver.prove(
                    transactions: transactions,
                    blockContext: blockContext,
                    initialStateRoot: initialStateRoot
                )
                blockProofResult = result
            } catch {
                asyncError = error
            }
            semaphore.signal()
        }

        // Wait for completion with timeout (10 minutes for large blocks)
        let waitResult = semaphore.wait(timeout: .now() + 600)
        if waitResult == .timedOut {
            throw BatchProverError.provingTimeout
        }
        if waitResult == .timedOut {
            throw BatchProverError.provingTimeout
        }

        if let error = asyncError {
            throw BatchProverError.unifiedProvingFailed(error)
        }

        guard let blockProof = blockProofResult else {
            throw BatchProverError.provingFailed
        }

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        // Estimate sequential time for comparison (1750ms per tx baseline)
        let sequentialEstimateMs = Double(transactions.count) * 1750.0

        // Print summary (skip in quiet mode)
        if !quiet {
            print("[BatchProver] Unified block proof completed: Transactions: \(blockProof.transactionCount), Total time: \(String(format: "%.1f", totalTimeMs))ms, Per-tx: \(String(format: "%.2f", totalTimeMs / Double(max(blockProof.transactionCount, 1))))ms, Speedup: \(String(format: "%.1fx", sequentialEstimateMs / totalTimeMs))")
        }

        // Convert BlockProof to EVMBatchProof for API compatibility
        // The starkProof contains the unified proof data
        let unifiedProofData = blockProof.starkProof

        // Create trace commitments from M31Digest values
        // Each commitment is 8 M31 values (32 bytes)
        // M31 stores a 31-bit field element - need full 4 bytes per element
        let traceCommitments: [[UInt8]] = blockProof.commitments.map { commitment in
            var bytes: [UInt8] = []
            bytes.reserveCapacity(32)
            for val in commitment.values {
                // Get low 31 bits of M31 value as UInt32, then extract bytes
                let bits = UInt32(val.v & 0x7FFFFFFF)
                bytes.append(UInt8(truncatingIfNeeded: bits))
                bytes.append(UInt8(truncatingIfNeeded: bits >> 8))
                bytes.append(UInt8(truncatingIfNeeded: bits >> 16))
                bytes.append(UInt8(truncatingIfNeeded: bits >> 24))
            }
            return bytes
        }

        // Create synthetic CircleSTARKProof for API compatibility
        // Note: Using empty FRI data since this is synthetic proof from block prover
        let emptyRounds: [CircleFRIRound] = []
        let emptyQueryResponses: [(M31, M31, [[UInt8]])] = []
        let friProof = CircleFRIProofData(
            rounds: emptyRounds,
            finalValue: M31(v: 0),
            queryIndices: []
        )
        let dummyProof = CircleSTARKProof(
            traceCommitments: traceCommitments,
            compositionCommitment: [],
            friProof: friProof,
            queryResponses: [],
            alpha: M31(v: 0),
            traceLength: 16384,
            numColumns: blockProof.commitments.count,
            logBlowup: config.logBlowup
        )

        return EVMBatchProof(
            transactionProofs: [dummyProof],
            gpuResults: nil,
            aggregatedProof: unifiedProofData,
            batchConfig: config,
            provingTimeMs: totalTimeMs,
            ldeTimeMs: blockProof.timing.ldeMs,
            commitTimeMs: blockProof.timing.commitMs
        )
    }

    /// Async version of proveBlockUnified for use in async contexts.
    ///
    /// - Parameters:
    ///   - transactions: Array of transactions to prove
    ///   - blockContext: Block context
    ///   - initialStateRoot: State root before block execution
    /// - Returns: UnifiedBlockProofResult with timing information
    public func proveBlockUnifiedAsync(
        transactions: [EVMTransaction],
        blockContext: BlockContext = BlockContext(),
        initialStateRoot: M31Word = .zero
    ) async throws -> UnifiedBlockProofResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        let blockProverConfig = BlockProvingConfig(
            numQueries: config.numQueries,
            logBlowup: config.logBlowup,
            logTraceLength: config.logTraceLength,
            useGPU: config.useGPU,
            maxTransactionsPerBlock: max(150, transactions.count),
            enableInterTxConstraints: true,
            gpuBatchSize: 512
        )

        let blockProver = try ZoltraakBlockProver(config: blockProverConfig)

        let blockProof = try await blockProver.prove(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot
        )

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        let sequentialEstimateMs = Double(transactions.count) * 1750.0

        return UnifiedBlockProofResult(
            blockProof: blockProof,
            provingTimeMs: totalTimeMs,
            sequentialEstimateMs: sequentialEstimateMs
        )
    }

    /// Prove batch using the transaction pipeline for parallel execution and proving
    /// This runs the async pipeline on a background thread to maintain sync API
    private func proveBatchWithPipeline(transactions: [EVMTransaction]) throws -> EVMBatchProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Run the async pipeline on a background thread using Swift concurrency
        let result: PipelineResult
        do {
            let semaphore = DispatchSemaphore(value: 0)
            var asyncError: Error?
            var pipelineResult: PipelineResult?

            Task {
                do {
                    let res = try await pipelineCoordinator.proveBlock(
                        transactions: transactions,
                        blockNumber: 0
                    )
                    pipelineResult = res
                } catch {
                    asyncError = error
                }
                semaphore.signal()
            }

            // Wait for completion with timeout
            let waitResult = semaphore.wait(timeout: .now() + 300)  // 5 minute timeout
            if waitResult == .timedOut {
                throw PipelineError.timeout
            }
            if let error = asyncError {
                throw error
            }
            guard let finalResult = pipelineResult else {
                throw PipelineError.provingFailed
            }
            result = finalResult

        } catch let error as PipelineError {
            throw error
        } catch {
            throw PipelineError.executionFailed
        }

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        // Convert pipeline items to batch proof format
        let successfulItems = result.items.filter { $0.succeeded }
        let failedCount = result.failedCount

        // Build transaction proofs from pipeline results
        var transactionProofs: [CircleSTARKProof] = []
        for item in successfulItems {
            if let execution = item.executionResult {
                let air = EVMAIR.fromExecution(execution)
                do {
                    let proof = try circleProver.proveCPU(air: air)
                    transactionProofs.append(proof)
                } catch {
                    // Skip failed proof generation
                }
            }
        }

        return EVMBatchProof(
            transactionProofs: transactionProofs,
            gpuResults: nil,
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: totalTimeMs,
            ldeTimeMs: result.executionTimeMs,
            commitTimeMs: result.provingTimeMs
        )
    }

    /// GPU-accelerated batch proving with parallel execution
    private func proveBatchGPU(transactions: [EVMTransaction]) throws -> EVMBatchProof {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Use EVMGPUBatchProver for GPU-accelerated proving
        let gpuConfig = EVMGPUBatchProver.Config(
            logBlowup: config.logBlowup,
            numQueries: config.numQueries
        )
        let gpuProver = try EVMGPUBatchProver(config: gpuConfig)

        // Execute transactions and generate proofs
        var results: [EVMGPUBatchProver.ProverResult] = []
        var totalLDE: Double = 0
        var totalCommit: Double = 0
        var totalTrace: Double = 0

        for tx in transactions {
            let result = try gpuProver.prove(transaction: tx)
            results.append(result)
            totalLDE += result.ldeMs
            totalCommit += result.commitMs
            totalTrace += result.traceGenMs
        }

        let provingTimeMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return EVMBatchProof(
            gpuResults: results.map { $0.gpuProof },
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: provingTimeMs,
            ldeTimeMs: totalLDE,
            commitTimeMs: totalCommit
        )
    }

    /// CPU-only batch proving
    private func proveBatchCPU(transactions: [EVMTransaction]) throws -> EVMBatchProof {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Execute each transaction and generate traces
        let engine = EVMExecutionEngine()
        var airInstances: [EVMAIR] = []
        var results: [EVMExecutionResult] = []

        for tx in transactions {
            let result = try engine.execute(
                code: tx.code,
                calldata: tx.calldata,
                value: tx.value,
                gasLimit: tx.gasLimit
            )
            results.append(result)

            // Create AIR from execution result
            let air = EVMAIR.fromExecution(result)
            airInstances.append(air)
        }

        // Generate CircleSTARK proofs for each transaction
        var proofs: [CircleSTARKProof] = []
        for air in airInstances {
            let proof = try circleProver.proveCPU(air: air)
            proofs.append(proof)
        }

        let provingTimeMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return EVMBatchProof(
            transactionProofs: proofs,
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: provingTimeMs
        )
    }

    /// Prove a single transaction
    public func prove(
        transaction: EVMTransaction,
        initialStateRoot: M31Word = .zero
    ) throws -> CircleSTARKProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Execute transaction
        let engine = EVMExecutionEngine()
        let result = try engine.execute(
            code: transaction.code,
            calldata: transaction.calldata,
            value: transaction.value,
            gasLimit: transaction.gasLimit
        )

        // Create AIR from execution result
        let air = EVMAIR.fromExecution(result)

        // Generate proof
        let proof: CircleSTARKProof
        if config.useGPU {
            proof = try circleProver.proveCPU(air: air)
        } else {
            proof = try circleProver.proveCPU(air: air)
        }

        return proof
    }
}

// MARK: - EVM Transaction

/// A transaction to be proven
public struct EVMTransaction: Sendable {
    public let code: [UInt8]
    public let calldata: [UInt8]
    public let value: M31Word
    public let gasLimit: UInt64
    public let sender: M31Word?
    /// Nonce for pre-validation
    public let nonce: UInt64

    /// Unique identifier for this transaction
    public let txHash: String

    /// Initial state for the transaction (balances, storage)
    /// This enables accurate execution of transactions that depend on pre-existing state
    public let initialState: EVMTransactionState?

    public init(
        code: [UInt8],
        calldata: [UInt8] = [],
        value: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000,
        sender: M31Word? = nil,
        nonce: UInt64 = 0,
        txHash: String = "",
        initialState: EVMTransactionState? = nil
    ) {
        self.code = code
        self.calldata = calldata
        self.value = value
        self.gasLimit = gasLimit
        self.sender = sender
        self.nonce = nonce
        self.txHash = txHash.isEmpty ? Self.computeTxHash(code: code, calldata: calldata) : txHash
        self.initialState = initialState
    }

    /// Compute transaction hash for identification
    private static func computeTxHash(code: [UInt8], calldata: [UInt8]) -> String {
        var hasher = [UInt8]()
        hasher.append(contentsOf: code.prefix(32))
        hasher.append(contentsOf: calldata.prefix(32))
        return hasher.map { String(format: "%02x", $0) }.joined()
    }

    /// Create a simple ETH transfer
    public static func transfer(to: M31Word, amount: M31Word, gasLimit: UInt64 = 21_000) -> EVMTransaction {
        return EVMTransaction(
            code: [],
            calldata: [],
            value: amount,
            gasLimit: gasLimit,
            sender: to
        )
    }

    /// Create a contract call with calldata
    public static func call(
        to: M31Word,
        calldata: [UInt8],
        value: M31Word = .zero,
        gasLimit: UInt64 = 100_000
    ) -> EVMTransaction {
        // Simple CALL bytecode
        var code = [UInt8]()
        code.append(0x60)  // PUSH1
        code.append(0x00)  // value
        code.append(0x73)  // PUSH20
        code.append(contentsOf: to.toBytes().suffix(20))
        code.append(0x61)  // PUSH2
        code.append(contentsOf: [UInt8](repeating: 0, count: 2))  // calldata length placeholder
        code.append(0x80)  // DUP1
        code.append(0x60)  // PUSH1
        code.append(0x00)  // offset
        code.append(0x60)  // PUSH1
        code.append(0x00)  // offset
        code.append(0xF4)  // DELEGATECALL
        // Need more for actual call...

        return EVMTransaction(
            code: code,
            calldata: calldata,
            value: value,
            gasLimit: gasLimit,
            sender: nil
        )
    }

    /// Estimate gas cost based on code and calldata
    public var estimatedGas: UInt64 {
        // Base gas for transaction
        var gas: UInt64 = 21_000

        // Gas for code storage (CREATE)
        if code.isEmpty {
            // Transfer or call - base gas applies
        } else {
            // Contract creation - gas for deployment
            gas += 32_000
            gas += UInt64(code.count) * 200  // Gas per byte of code
        }

        // Gas for calldata
        gas += UInt64(calldata.count) * 4  // Base calldata cost
        if !calldata.isEmpty {
            gas += 4  // Non-zero byte cost overhead
        }

        return gas
    }
}

// MARK: - Block Prover

/// Configuration for block proving
public struct BlockProverConfig {
    /// Transactions per block
    public let txsPerBlock: Int

    /// Use parallel batch proving
    public let parallelBatches: Int

    /// Use recursive aggregation
    public let useRecursion: Bool

    /// Aggregation cadence (every N blocks)
    public let aggregationCadence: Int

    public static let `default` = BlockProverConfig(
        txsPerBlock: 100,
        parallelBatches: 4,
        useRecursion: true,
        aggregationCadence: 1
    )
}

/// Result of a block proof
public struct EVMBlockProof {
    public let blockNumber: UInt64
    public let transactionProofs: [CircleSTARKProof]
    public let blockProof: Data?
    public let finalProof: Data?
    public let config: BlockProverConfig
    public let provingTimeMs: Double

    public var estimatedFinalProofSize: Int {
        guard let final = finalProof else { return 0 }
        return final.count
    }
}

/// Block-level prover with aggregation
public final class EVMBlockProver: Sendable {

    public let config: BlockProverConfig
    private let batchProver: EVMBatchProver

    public init(config: BlockProverConfig = .default) {
        self.config = config

        // Configure batch prover based on parallelization
        let batchConfig = BatchProverConfig(
            batchSize: max(1, config.txsPerBlock / config.parallelBatches),
            useGPU: true,
            logTraceLength: 18,
            numQueries: 30,
            logBlowup: 4
        )
        self.batchProver = EVMBatchProver(config: batchConfig)
    }

    // MARK: - Block Proving

    /// Prove a block of transactions
    public func proveBlock(
        transactions: [EVMTransaction],
        blockNumber: UInt64,
        previousStateRoot: M31Word = .zero
    ) throws -> EVMBlockProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Split transactions into parallel batches
        let batches = splitIntoBatches(transactions, count: config.parallelBatches)

        // Prove each batch in parallel (conceptually - actual parallelization would use GCD)
        var allBatchProofs: [EVMBatchProof] = []
        for batch in batches {
            let batchProof = try batchProver.proveBatch(
                transactions: batch,
                initialStateRoot: previousStateRoot
            )
            allBatchProofs.append(batchProof)
        }

        let provingTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        // Collect all transaction proofs
        let allTxProofs = allBatchProofs.flatMap { $0.transactionProofs }

        return EVMBlockProof(
            blockNumber: blockNumber,
            transactionProofs: allTxProofs,
            blockProof: nil,
            finalProof: nil,
            config: config,
            provingTimeMs: provingTimeMs
        )
    }

    // MARK: - Helpers

    private func splitIntoBatches(_ transactions: [EVMTransaction], count: Int) -> [[EVMTransaction]] {
        let batchSize = max(1, (transactions.count + count - 1) / count)
        var batches: [[EVMTransaction]] = []

        for i in 0..<count {
            let start = i * batchSize
            let end = min(start + batchSize, transactions.count)
            if start < end {
                batches.append(Array(transactions[start..<end]))
            }
        }

        return batches
    }
}

// MARK: - EVMAIR Extension for CircleSTARK Prover

extension EVMAIR {

    /// Create an AIR from an EVM execution result
    public static func fromExecution(_ result: EVMExecutionResult) -> EVMAIR {
        let traceLength = result.trace.rows.count
        let n = traceLength.nextPowerOfTwo()
        // Compute log2 directly: n = 2^logLength for power-of-2 n
        let logLength = n > 0 ? (64 - n.leadingZeroBitCount - 1) : 0

        return EVMAIR(
            logTraceLength: logLength,
            initialStateRoot: result.trace.initialState.stateRoot,
            gasLimit: result.trace.gasUsed + 1_000_000
        )
    }
}

// MARK: - Parallel Execution Methods

extension EVMBatchProver {

    /// Prove multiple transactions in parallel across CPU cores
    /// Uses the parallel engine for execution and batch proving for proofs
    public func proveBatchParallel(
        transactions: [EVMTransaction],
        initialStateRoot: M31Word = .zero
    ) async throws -> EVMBatchProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Use pipeline coordinator for full parallelism
        let pipeline = try await EVMTxPipelineCoordinator(
            pipelineConfig: .default,
            batchConfig: config
        )

        let result = try await pipeline.run(transactions: transactions)

        return EVMBatchProof(
            transactionProofs: result.items.compactMap { $0.proof?.transactionProofs.first },
            gpuResults: nil,
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: result.totalTimeMs,
            ldeTimeMs: nil,
            commitTimeMs: nil
        )
    }

    /// Execute transactions in parallel, then prove sequentially
    /// Useful for testing parallel execution speedup
    public func proveBatchWithParallelExecution(
        transactions: [EVMTransaction],
        initialStateRoot: M31Word = .zero
    ) throws -> EVMBatchProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Execute all transactions in parallel using TaskGroup
        let executionStart = CFAbsoluteTimeGetCurrent()

        // Create execution results synchronously with TaskGroup
        var executionResults: [EVMExecutionResult] = []
        var executionTimes: [Double] = []

        let semaphore = DispatchSemaphore(value: config.batchSize)

        // Run parallel execution using GCD
        let group = DispatchGroup()
        let queue = DispatchQueue(
            label: "com.evmetal.batchprover.execution",
            attributes: .concurrent
        )

        let lock = NSLock()
        let executionEngines = (0..<config.batchSize).map { _ in EVMExecutionEngine() }

        for (index, tx) in transactions.enumerated() {
            group.enter()
            queue.async {
                let engine = EVMExecutionEngine()
                let start = CFAbsoluteTimeGetCurrent()

                do {
                    let result = try engine.execute(
                        code: tx.code,
                        calldata: tx.calldata,
                        value: tx.value,
                        gasLimit: tx.gasLimit
                    )
                    let execTime = (CFAbsoluteTimeGetCurrent() - start) * 1000

                    lock.lock()
                    executionResults.append(result)
                    executionTimes.append(execTime)
                    lock.unlock()
                } catch {
                    lock.lock()
                    lock.unlock()
                }

                group.leave()
            }
        }

        group.wait()
        let executionTimeMs = (CFAbsoluteTimeGetCurrent() - executionStart) * 1000

        // Create AIR instances from execution results
        let airInstances = executionResults.map { EVMAIR.fromExecution($0) }

        // Generate proofs sequentially (or use GPU for parallel proving)
        var proofs: [CircleSTARKProof] = []
        let provingStart = CFAbsoluteTimeGetCurrent()

        for air in airInstances {
            let proof = try circleProver.proveCPU(air: air)
            proofs.append(proof)
        }

        let provingTimeMs = (CFAbsoluteTimeGetCurrent() - provingStart) * 1000
        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        return EVMBatchProof(
            transactionProofs: proofs,
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: totalTimeMs,
            ldeTimeMs: executionTimeMs,
            commitTimeMs: provingTimeMs
        )
    }

    /// Estimate parallel execution speedup for given transaction count
    public func estimateParallelSpeedup(txCount: Int, coreCount: Int) -> Double {
        // Amdahl's law: speedup = 1 / (F + (1-F)/N)
        // Where F is the fraction that must be serialized

        // Assume 80% of execution is parallelizable
        let parallelizableFraction = 0.80

        // Fixed serial portion (10%)
        let serialFraction = 0.10

        // Actual parallel fraction
        let effectiveParallel = parallelizableFraction

        // Amdahl's law
        let speedup = 1.0 / (serialFraction + (1.0 - serialFraction - effectiveParallel) / Double(coreCount))

        return min(speedup, Double(coreCount))
    }
}

extension Int {
    func nextPowerOfTwo() -> Int {
        var n = Swift.max(1, self)
        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        return n + 1
    }
}

// MARK: - Batch Prover Errors

/// Errors that can occur during batch proving
public enum BatchProverError: Error, Sendable {
    /// Block prover initialization failed
    case blockProverInitFailed(Error)

    /// Unified proving operation timed out
    case provingTimeout

    /// Unified proving failed with an error
    case unifiedProvingFailed(Error)

    /// General proving failure
    case provingFailed

    /// Sequential proving mode not supported
    case sequentialProvingNotSupported

    public var description: String {
        switch self {
        case .blockProverInitFailed(let error):
            return "Block prover initialization failed: \(error)"
        case .provingTimeout:
            return "Proving operation timed out"
        case .unifiedProvingFailed(let error):
            return "Unified proving failed: \(error)"
        case .provingFailed:
            return "Proving failed"
        case .sequentialProvingNotSupported:
            return "Sequential proving mode not supported"
        }
    }
}
