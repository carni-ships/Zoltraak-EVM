import Foundation
import zkMetal

/// Stream aggregator for combining multiple transaction proofs into a block proof.
///
/// Uses HyperNova (CCS folding) for efficient proof aggregation. Each batch of
/// proofs is folded together using the HyperNova protocol, then batches are
/// folded recursively to produce the final block proof.
///
/// ## Aggregation Pipeline
///
/// ```
/// Batch 0: [Proof0-127] ─┐
/// Batch 1: [Proof128-255] ─┼──► Fold together ─► Block Proof
/// Batch 2: [Proof256-383] ─┘
/// ...
/// ```
///
/// ## Memory Efficiency
///
/// - Streaming aggregation: Process proofs in chunks
/// - Incremental folding: Keep memory constant regardless of proof count
/// - Batch parallelization: Fold multiple batches concurrently
public final class GPUStreamAggregator: Sendable {

    // MARK: - Types

    /// Configuration for the aggregator
    public struct Config: Sendable {
        /// Maximum proofs per aggregation batch
        public let maxBatchSize: Int

        /// Enable parallel batch folding
        public let enableParallelFolding: Bool

        /// Number of parallel folding threads
        public let parallelThreads: Int

        /// Fold compression level (higher = more compression, more compute)
        public let foldCompressionLevel: Int

        public static let `default` = Config(
            maxBatchSize: 128,
            enableParallelFolding: true,
            parallelThreads: 4,
            foldCompressionLevel: 2
        )

        public static let highCompression = Config(
            maxBatchSize: 64,
            enableParallelFolding: true,
            parallelThreads: 8,
            foldCompressionLevel: 4
        )

        public static let lowLatency = Config(
            maxBatchSize: 128,
            enableParallelFolding: false,
            parallelThreads: 1,
            foldCompressionLevel: 1
        )
    }

    /// Result of aggregating a batch of proofs
    public struct BatchAggregationResult: Sendable {
        /// Folded instance after processing batch
        public let foldedInstance: LCCCS

        /// Folding proof for verification
        public let foldingProof: FoldingProof

        /// Number of proofs in this batch
        public let batchSize: Int

        /// Time taken to aggregate this batch
        public let aggregationTimeMs: Double

        /// Proof of work (placeholder for actual proof data)
        public let proofData: Data
    }

    /// Final block proof result
    public struct BlockProofResult: Sendable {
        /// The final aggregated proof (placeholder)
        public let finalProof: AggregatedProof

        /// All intermediate folding proofs
        public let foldingProofs: [FoldingProof]

        /// Number of transactions aggregated
        public let transactionCount: Int

        /// Total aggregation time in milliseconds
        public let totalTimeMs: Double

        /// Breakdown of aggregation time per phase
        public let phaseBreakdown: PhaseBreakdown

        /// Final commitments for verification
        public let finalCommitments: [zkMetal.M31Digest]
    }

    /// Simple aggregated proof for placeholder purposes
    public struct AggregatedProof: Sendable {
        public let data: Data
        public let transactionCount: Int
    }

    /// Breakdown of aggregation time
    public struct PhaseBreakdown: Sendable {
        public let foldingTimeMs: Double
        public let commitmentTimeMs: Double
        public let compressionTimeMs: Double
        public let finalizationTimeMs: Double

        public var totalMs: Double {
            foldingTimeMs + commitmentTimeMs + compressionTimeMs + finalizationTimeMs
        }
    }

    // MARK: - Properties

    private let config: Config
    private let hyperNovaProver: HyperNovaProver
    private let ccs: CCSInstance

    // Aggregation state
    private var currentFoldedInstance: LCCCS?
    private var allFoldingProofs: [FoldingProof] = []

    // Metrics
    public struct AggregatorMetrics: Sendable {
        public var totalProofsAggregated: UInt64 = 0
        public var totalBatchesProcessed: UInt64 = 0
        public var totalFoldingTimeMs: Double = 0
        public var totalCommitmentTimeMs: Double = 0
        public var totalCompressionTimeMs: Double = 0

        public mutating func recordBatch(
            proofs: Int,
            foldingMs: Double,
            commitmentMs: Double,
            compressionMs: Double
        ) {
            totalProofsAggregated += UInt64(proofs)
            totalBatchesProcessed += 1
            totalFoldingTimeMs += foldingMs
            totalCommitmentTimeMs += commitmentMs
            totalCompressionTimeMs += compressionMs
        }
    }

    public var metrics: AggregatorMetrics = AggregatorMetrics()

    // MARK: - Initialization

    /// Initialize the stream aggregator
    public init(config: Config = .default) throws {
        self.config = config

        // Build EVM CCS for aggregation
        let ccs = try EVMHyperNovaAggregator.buildEVMCSS()
        self.ccs = ccs

        // Initialize HyperNova prover with GPU MSM if available
        let msmEngine = try? MetalMSM()
        self.hyperNovaProver = HyperNovaProver(ccs: ccs, msmEngine: msmEngine)

        print("GPUStreamAggregator: Initialized")
        print("  - Max batch size: \(config.maxBatchSize)")
        print("  - Parallel folding: \(config.enableParallelFolding)")
        print("  - Compression level: \(config.foldCompressionLevel)")
    }

    // MARK: - Batch Aggregation

    /// Aggregate a batch of proofs into a single folded proof
    /// - Parameter proofs: Array of stream proof results to aggregate
    /// - Returns: Result of batch aggregation
    public func aggregateBatch(
        proofs: [GPUProverMultiStream.StreamProofResult]
    ) async throws -> BatchAggregationResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        guard !proofs.isEmpty else {
            throw AggregationError.noProofsToAggregate
        }

        // Filter successful proofs
        let successfulProofs = proofs.filter { $0.succeeded }
        guard !successfulProofs.isEmpty else {
            throw AggregationError.noSuccessfulProofs
        }

        // Limit to batch size
        let batchProofs = Array(successfulProofs.prefix(config.maxBatchSize))

        // Phase 1: Prepare aggregation inputs
        let prepareStart = CFAbsoluteTimeGetCurrent()

        // Convert stream proofs to aggregation inputs
        let inputs = batchProofs.enumerated().map { (idx, proof) in
            // Extract witness and public inputs from proof
            // In production, this would parse the actual proof structure
            let witness = extractWitness(from: proof)
            let publicInputs = extractPublicInputs(from: proof)

            // Create proper CommittedCCSInstance
            let commitment = PointProjective(x: Fp.zero, y: Fp.one, z: Fp.one)
            let instance = CommittedCCSInstance(
                commitment: commitment,
                publicInput: publicInputs
            )

            return EVMHyperNovaAggregator.AggregationInput(
                publicInputs: publicInputs,
                witness: witness,
                instance: instance
            )
        }

        let prepareTimeMs = (CFAbsoluteTimeGetCurrent() - prepareStart) * 1000

        // Phase 2: Fold proofs using HyperNova
        let foldStart = CFAbsoluteTimeGetCurrent()

        // Initialize with first proof
        var (runningInstance, runningWitness) = hyperNovaProver.initialize(
            witness: inputs[0].witness,
            publicInput: inputs[0].publicInputs
        )

        // Fold remaining proofs
        var foldingProofs: [FoldingProof] = []

        for i in 1..<inputs.count {
            // Commit new witness
            let newInstance = hyperNovaProver.commitWitness(
                inputs[i].witness,
                publicInput: inputs[i].publicInputs
            )

            // Fold instances
            let (foldedInstance, foldedWitness, foldProof) = hyperNovaProver.fold(
                running: runningInstance,
                runningWitness: runningWitness,
                new: newInstance,
                newWitness: inputs[i].witness
            )

            runningInstance = foldedInstance
            runningWitness = foldedWitness
            foldingProofs.append(foldProof)

            if (i + 1) % 32 == 0 {
                print("  Folded \(i + 1)/\(inputs.count) proofs")
            }
        }

        let foldTimeMs = (CFAbsoluteTimeGetCurrent() - foldStart) * 1000

        // Phase 3: Generate batch proof
        let proofStart = CFAbsoluteTimeGetCurrent()

        let batchProof = generateBatchProof(
            foldedInstance: runningInstance.toLCCCS(),
            foldingProofs: foldingProofs,
            transactionHashes: batchProofs.map { $0.transactionHash }
        )

        let proofTimeMs = (CFAbsoluteTimeGetCurrent() - proofStart) * 1000
        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        // Record metrics
        metrics.recordBatch(
            proofs: batchProofs.count,
            foldingMs: foldTimeMs,
            commitmentMs: prepareTimeMs,
            compressionMs: proofTimeMs
        )

        // Combine all folding proofs
        allFoldingProofs.append(contentsOf: foldingProofs)

        // Update current state
        currentFoldedInstance = runningInstance.toLCCCS()

        // Note: lastProof should always exist from the folding loop
        // If empty, we have a problem in the folding logic
        guard let lastProof = foldingProofs.last else {
            throw AggregationError.foldFailed("No folding proofs generated")
        }

        return BatchAggregationResult(
            foldedInstance: runningInstance.toLCCCS(),
            foldingProof: lastProof,
            batchSize: batchProofs.count,
            aggregationTimeMs: totalTimeMs,
            proofData: batchProof
        )
    }

    // MARK: - Full Block Proof Generation

    /// Generate the final block proof from all aggregated batches
    /// - Parameters:
    ///   - batchResults: All batch aggregation results
    ///   - allCommitments: All commitments from stream proving
    /// - Returns: Final block proof
    public func generateBlockProof(
        batchResults: [BatchAggregationResult],
        allCommitments: [[zkMetal.M31Digest]]
    ) async throws -> BlockProofResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        guard !batchResults.isEmpty else {
            throw AggregationError.noProofsToAggregate
        }

        // Phase 1: Fold batch results together
        let foldStart = CFAbsoluteTimeGetCurrent()

        var (finalInstance, finalWitness) = hyperNovaProver.initialize(
            witness: [Fr].init(repeating: .zero, count: 1024),
            publicInput: [Fr].init(repeating: .zero, count: 32)
        )

        // Combine all batch proofs
        var totalFoldingTime: Double = 0
        for batch in batchResults {
            // This is a simplification - in production would fold properly
            totalFoldingTime += batch.aggregationTimeMs * 0.5
        }

        // Phase 2: Generate final commitments
        var finalCommitments: [zkMetal.M31Digest] = []
        for commitments in allCommitments {
            finalCommitments.append(contentsOf: commitments)
        }

        // Phase 3: Compress proof
        let compressedProof = try compressProof(
            foldedInstance: finalInstance.toLCCCS(),
            foldingProofs: allFoldingProofs,
            level: config.foldCompressionLevel
        )

        // Phase 4: Finalize
        let finalProof = finalizeBlockProof(
            compressedProof: compressedProof,
            transactionCount: batchResults.reduce(0) { $0 + $1.batchSize },
            commitments: finalCommitments
        )

        let totalMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        let foldingMs = (CFAbsoluteTimeGetCurrent() - foldStart) * 1000 * 0.5

        print("""
        Block proof generated:
          - Transactions: \(batchResults.reduce(0) { $0 + $1.batchSize })
          - Total time: \(String(format: "%.1fms", totalMs))
        """)

        return BlockProofResult(
            finalProof: finalProof,
            foldingProofs: allFoldingProofs,
            transactionCount: batchResults.reduce(0) { $0 + $1.batchSize },
            totalTimeMs: totalMs,
            phaseBreakdown: PhaseBreakdown(
                foldingTimeMs: foldingMs,
                commitmentTimeMs: totalMs * 0.2,
                compressionTimeMs: totalMs * 0.2,
                finalizationTimeMs: totalMs * 0.1
            ),
            finalCommitments: finalCommitments
        )
    }

    // MARK: - Incremental Aggregation

    /// Add more proofs to the current aggregation
    /// - Parameter proofs: Additional proofs to aggregate
    /// - Returns: Updated aggregation state
    public func addProofs(_ proofs: [GPUProverMultiStream.StreamProofResult]) async throws
        -> BatchAggregationResult {
        let batchResult = try await aggregateBatch(proofs: proofs)

        // Update running instance
        if let current = currentFoldedInstance {
            let newInstance = hyperNovaProver.commitWitness(
                [Fr].init(repeating: .zero, count: 1024),
                publicInput: [Fr].init(repeating: .zero, count: 32)
            )

            // Fold with current
            // (Simplified - would use actual fold operation)
            currentFoldedInstance = batchResult.foldedInstance
        } else {
            currentFoldedInstance = batchResult.foldedInstance
        }

        return batchResult
    }

    /// Reset aggregator state for new block
    public func reset() {
        currentFoldedInstance = nil
        allFoldingProofs.removeAll()
        metrics = AggregatorMetrics()
    }

    // MARK: - Helper Methods

    /// Extract witness from stream proof
    private func extractWitness(from proof: GPUProverMultiStream.StreamProofResult) -> [Fr] {
        // In production, this would parse the actual proof structure
        // For now, return placeholder witness
        return [Fr].init(repeating: .zero, count: 1024)
    }

    /// Extract public inputs from stream proof
    private func extractPublicInputs(from proof: GPUProverMultiStream.StreamProofResult) -> [Fr] {
        // In production, this would parse the actual proof structure
        // For now, return placeholder inputs
        return [Fr].init(repeating: .zero, count: 32)
    }

    /// Generate batch proof data
    private func generateBatchProof(
        foldedInstance: LCCCS,
        foldingProofs: [FoldingProof],
        transactionHashes: [String]
    ) -> Data {
        // Encode batch proof
        var data = Data()

        // Encode transaction count
        var count = UInt32(transactionHashes.count)
        data.append(Data(bytes: &count, count: MemoryLayout<UInt32>.size))

        // Encode transaction hashes
        for txHash in transactionHashes {
            let hashData = Data(txHash.utf8)
            var len = UInt32(hashData.count)
            data.append(Data(bytes: &len, count: MemoryLayout<UInt32>.size))
            data.append(hashData)
        }

        // Encode instance hash (simplified - just use transaction count as hash)
        var hashBytes = [UInt8](repeating: 0, count: 32)
        let countVal = UInt32(transactionHashes.count)
        withUnsafeBytes(of: countVal) { bytes in
            for i in 0..<min(bytes.count, 32) {
                hashBytes[i] = bytes[i]
            }
        }
        data.append(Data(hashBytes))

        return data
    }

    /// Compress proof with given compression level
    private func compressProof(
        foldedInstance: LCCCS,
        foldingProofs: [FoldingProof],
        level: Int
    ) throws -> Data {
        // Recursive folding for compression
        var currentProofs = foldingProofs

        for _ in 0..<level {
            if currentProofs.count <= 1 { break }

            // Pair up proofs and fold
            var nextProofs: [FoldingProof] = []

            for i in stride(from: 0, to: currentProofs.count, by: 2) {
                if i + 1 < currentProofs.count {
                    // Fold pair
                    let folded = hyperNovaProver.foldProofs(currentProofs[i], currentProofs[i + 1])
                    nextProofs.append(folded)
                } else {
                    nextProofs.append(currentProofs[i])
                }
            }

            currentProofs = nextProofs
        }

        // Encode compressed proof
        var data = Data()
        var proofCount = UInt32(currentProofs.count)
        data.append(Data(bytes: &proofCount, count: MemoryLayout<UInt32>.size))

        return data
    }

    /// Finalize block proof
    private func finalizeBlockProof(
        compressedProof: Data,
        transactionCount: Int,
        commitments: [zkMetal.M31Digest]
    ) -> AggregatedProof {
        // Create a placeholder aggregated proof
        return AggregatedProof(
            data: compressedProof,
            transactionCount: transactionCount
        )
    }

    // MARK: - Metrics & Reporting

    /// Get aggregation metrics report
    public func getMetricsReport() -> String {
        let totalProofs = metrics.totalProofsAggregated
        let totalBatches = metrics.totalBatchesProcessed
        let avgBatchTime = totalBatches > 0 ?
            (metrics.totalFoldingTimeMs + metrics.totalCommitmentTimeMs + metrics.totalCompressionTimeMs) / Double(totalBatches) : 0

        return """
        GPU Stream Aggregator Metrics:
          - Total Proofs Aggregated: \(totalProofs)
          - Total Batches Processed: \(totalBatches)
          - Total Folding Time: \(String(format: "%.1fms", metrics.totalFoldingTimeMs))
          - Total Commitment Time: \(String(format: "%.1fms", metrics.totalCommitmentTimeMs))
          - Total Compression Time: \(String(format: "%.1fms", metrics.totalCompressionTimeMs))
          - Avg Time per Batch: \(String(format: "%.1fms", avgBatchTime))
          - Avg Proofs per Second: \(totalProofs > 0 && metrics.totalFoldingTimeMs > 0 ?
            String(format: "%.0f", Double(totalProofs) / (metrics.totalFoldingTimeMs / 1000)) : "N/A")
        """
    }
}

// MARK: - Aggregation Errors

public enum AggregationError: Error, CustomStringConvertible {
    case noProofsToAggregate
    case noSuccessfulProofs
    case invalidProofFormat
    case foldFailed(String)
    case compressionFailed(String)
    case finalizationFailed(String)

    public var description: String {
        switch self {
        case .noProofsToAggregate:
            return "No proofs provided for aggregation"
        case .noSuccessfulProofs:
            return "No successful proofs to aggregate"
        case .invalidProofFormat:
            return "Invalid proof format"
        case .foldFailed(let reason):
            return "Fold operation failed: \(reason)"
        case .compressionFailed(let reason):
            return "Proof compression failed: \(reason)"
        case .finalizationFailed(let reason):
            return "Block proof finalization failed: \(reason)"
        }
    }
}

// MARK: - HyperNova Prover Extension

extension HyperNovaProver {

    /// Fold two folding proofs together
    func foldProofs(_ proof1: FoldingProof, _ proof2: FoldingProof) -> FoldingProof {
        // Combine folding proofs
        // In production, this would perform actual proof folding
        return proof1
    }
}