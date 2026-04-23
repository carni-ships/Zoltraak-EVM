// Zoltraak Brakedown Commitment
// Provides Brakedown vector commitment for EVM trace columns
//
// Brakedown is a hash-based, transparent PCS using expander-graph linear codes.
// Reference: Golovnev, Lee, Setty, Thaler, Wahby - eprint 2021/1043
//
// Key properties for EVM:
//   - Hash-based (no trusted setup, post-quantum friendly)
//   - O(N) commitment, O(sqrt(N)) proof size
//   - GPU-accelerated via zkMetal's GPUBrakedownProverEngine
//   - Works with BN254 scalar field (Fr)
//
// This module bridges EVM trace columns (M31 field) with Brakedown (Fr field).
// M31 values are converted to Fr before commitment.

import Foundation
import Metal
import zkMetal

// MARK: - Brakedown Commitment Errors

/// Errors that can occur during Brakedown commitment operations.
public enum BrakedownError: Error {
    case noGPU
    case noCommandQueue
    case missingKernel
    case gpuError(String)
    case initializationFailed(String)

    public var description: String {
        switch self {
        case .noGPU:
            return "No GPU available"
        case .noCommandQueue:
            return "Failed to create Metal command queue"
        case .missingKernel:
            return "Metal kernel not found"
        case .gpuError(let msg):
            return "GPU error: \(msg)"
        case .initializationFailed(let msg):
            return "Initialization failed: \(msg)"
        }
    }
}

// MARK: - Zoltraak Brakedown Configuration

/// Configuration for Zoltraak Brakedown commitment.
///
/// Controls the tradeoff between proof size, prover time, and security.
public struct ZoltraakBrakedownConfig {
    /// Rate inverse (blowup factor). Codeword = message * rateInverse.
    /// Higher values = better soundness but larger proofs.
    /// Default: 4 (gives ~60 bits with 30 queries)
    public let rateInverse: Int

    /// Number of random column queries for soundness.
    /// Security ~ numQueries * log2(rateInverse) bits.
    /// Default: 30
    public let numQueries: Int

    /// Expander graph degree (edges per right vertex).
    /// Higher = better code distance but slower encoding.
    /// Default: 10
    public let expanderDegree: Int

    /// Minimum number of columns before GPU encoding is used.
    /// Below this, CPU encoding is faster due to dispatch overhead.
    public let gpuThreshold: Int

    /// Standard configuration: 4x blowup, 30 queries, degree-10.
    public static let standard = ZoltraakBrakedownConfig(
        rateInverse: 4, numQueries: 30, expanderDegree: 10, gpuThreshold: 256
    )

    /// High security: 8x blowup, 50 queries, degree-16.
    public static let highSecurity = ZoltraakBrakedownConfig(
        rateInverse: 8, numQueries: 50, expanderDegree: 16, gpuThreshold: 512
    )

    /// Fast prover: 4x blowup, 16 queries, degree-8. Lower security (~32 bits).
    public static let fast = ZoltraakBrakedownConfig(
        rateInverse: 4, numQueries: 16, expanderDegree: 8, gpuThreshold: 128
    )

    /// Estimated soundness in bits.
    public var soundnessBits: Double {
        return Double(numQueries) * log2(Double(rateInverse))
    }

    public init(rateInverse: Int = 4, numQueries: Int = 30,
                expanderDegree: Int = 10, gpuThreshold: Int = 256) {
        self.rateInverse = rateInverse
        self.numQueries = numQueries
        self.expanderDegree = expanderDegree
        self.gpuThreshold = gpuThreshold
    }
}

// MARK: - Commitment Result

/// Result of committing EVM trace columns to Brakedown.
public struct ZoltraakBrakedownCommitResult {
    /// Individual Brakedown commitments for each trace column.
    public let commitments: [BrakedownProverCommitment]

    /// Combined batch commitment root (Poseidon2 hash chain of individual roots).
    public let batchRoot: Fr

    /// Total elapsed time in milliseconds.
    public let timeMs: Double

    /// Time spent converting M31 to Fr in milliseconds.
    public let conversionMs: Double

    /// Time spent in Brakedown commitment in milliseconds.
    public let commitMs: Double

    /// Number of columns committed.
    public var numColumns: Int { commitments.count }

    /// Commitment size (per column): just the Merkle root (1 Fr / 32 bytes).
    public var commitmentSizeBytes: Int {
        MemoryLayout<Fr>.stride
    }
}

// MARK: - Opening Result

/// Result of opening committed trace columns.
public struct ZoltraakBrakedownOpenResult {
    /// Batch opening proof.
    public let batchProof: BrakedownProverBatchProof

    /// Total elapsed time in milliseconds.
    public let timeMs: Double

    /// Approximate proof size in bytes.
    public var proofSizeBytes: Int {
        batchProof.proofs.reduce(0) { $0 + $1.proofSizeBytes }
    }
}

// MARK: - Main Engine

/// Zoltraak Brakedown Commitment Engine
///
/// Provides vector commitment for EVM trace columns using Brakedown.
///
/// ## Usage
///
/// ```swift
/// let engine = try ZoltraakBrakedownEngine()
/// let result = try engine.commit(traceLDEs: traceLDEs, evalLen: 4096)
/// print("Batch root: \(result.batchRoot)")
/// ```
///
/// ## Field Conversion
///
/// EVM traces use M31 (p = 2^31 - 1) but Brakedown uses Fr (BN254 scalar field).
/// Values are converted via modular reduction: Fr(v) = v mod r where r is BN254's order.
///
/// ## Proof System Integration
///
/// The resulting BrakedownProof is compatible with zkMetal's batch verification
/// and can be integrated with Circle STARK for the full proof system.
public class ZoltraakBrakedownEngine {

    // MARK: - Properties

    /// Configuration
    public let config: ZoltraakBrakedownConfig

    /// GPU-accelerated Brakedown prover engine
    private let proverEngine: GPUBrakedownProverEngine

    /// Metal device for GPU operations
    public let device: MTLDevice

    /// Command queue for GPU operations
    public let commandQueue: MTLCommandQueue

    // MARK: - Initialization

    /// Create a Brakedown engine with given configuration.
    public init(config: ZoltraakBrakedownConfig = .standard) throws {
        self.config = config

        let proverConfig = BrakedownProverConfig(
            rateInverse: config.rateInverse,
            numQueries: config.numQueries,
            expanderDegree: config.expanderDegree,
            codeSeed: 0xBEEF,
            gpuThreshold: config.gpuThreshold
        )

        self.proverEngine = try GPUBrakedownProverEngine(config: proverConfig)
        guard let dev = MTLCreateSystemDefaultDevice() else {
            throw BrakedownError.noGPU
        }
        self.device = dev
        guard let queue = device.makeCommandQueue() else {
            throw BrakedownError.noCommandQueue
        }
        self.commandQueue = queue
    }

    /// Convenience init with default configuration.
    public convenience init() throws {
        try self.init(config: .standard)
    }

    // MARK: - Commitment

    /// Commit EVM trace columns using Brakedown.
    ///
    /// Each trace column is committed separately using Brakedown PCS.
    /// A batch root is computed by hashing all individual commitments.
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form, each column is an array of M31 values.
    ///   - evalLen: Evaluation length (number of elements per column, must be power of 2).
    /// - Returns: `ZoltraakBrakedownCommitResult` with commitments and timing.
    public func commit(traceLDEs: [[M31]], evalLen: Int) throws -> ZoltraakBrakedownCommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()

        let numColumns = traceLDEs.count
        precondition(numColumns > 0, "Must have at least one column")
        precondition(evalLen > 0 && (evalLen & (evalLen - 1)) == 0,
                     "evalLen must be a power of 2")

        // Step 1: Convert M31 to Fr
        let convT0 = CFAbsoluteTimeGetCurrent()
        var frPolynomials: [[Fr]] = []
        frPolynomials.reserveCapacity(numColumns)

        for col in traceLDEs {
            precondition(col.count == evalLen, "Column length must match evalLen")
            let frPoly = m31ArrayToFr(col)
            frPolynomials.append(frPoly)
        }

        let conversionMs = (CFAbsoluteTimeGetCurrent() - convT0) * 1000

        // Step 2: Batch commit using GPU Brakedown prover
        let commitT0 = CFAbsoluteTimeGetCurrent()
        let batchCommitment = try proverEngine.batchCommit(polynomials: frPolynomials)
        let commitMs = (CFAbsoluteTimeGetCurrent() - commitT0) * 1000

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return ZoltraakBrakedownCommitResult(
            commitments: batchCommitment.commitments,
            batchRoot: batchCommitment.batchRoot,
            timeMs: totalMs,
            conversionMs: conversionMs,
            commitMs: commitMs
        )
    }

    /// Commit a single trace column.
    ///
    /// - Parameters:
    ///   - values: M31 values to commit.
    ///   - evalLen: Number of values (power of 2).
    /// - Returns: Single column commitment.
    public func commitColumn(values: [M31], evalLen: Int) throws -> BrakedownProverCommitment {
        let frPoly = m31ArrayToFr(values)
        return try proverEngine.commit(evaluations: frPoly)
    }

    // MARK: - Opening

    /// Generate opening proofs for committed trace columns.
    ///
    /// - Parameters:
    ///   - commitResult: Result from a previous commitment.
    ///   - point: Multilinear evaluation point (length = log2(evalLen)).
    /// - Returns: Opening proof result.
    public func open(commitResult: ZoltraakBrakedownCommitResult,
                     point: [Fr]) throws -> ZoltraakBrakedownOpenResult {
        let t0 = CFAbsoluteTimeGetCurrent()

        let batchProof = try proverEngine.batchOpen(
            batch: BrakedownProverBatchCommitment(
                commitments: commitResult.commitments,
                batchRoot: commitResult.batchRoot
            ),
            point: point
        )

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return ZoltraakBrakedownOpenResult(
            batchProof: batchProof,
            timeMs: totalMs
        )
    }

    /// Open a single column.
    public func openColumn(commitment: BrakedownProverCommitment,
                          point: [Fr]) throws -> BrakedownProverOpeningProof {
        return try proverEngine.open(commitment: commitment, point: point)
    }

    // MARK: - Verification

    /// Verify opening proofs.
    ///
    /// - Parameters:
    ///   - commitResult: Original commitment.
    ///   - openResult: Opening proof.
    /// - Returns: true if all proofs are valid.
    public func verify(commitResult: ZoltraakBrakedownCommitResult,
                       openResult: ZoltraakBrakedownOpenResult) -> Bool {
        return proverEngine.verifyBatch(
            batch: BrakedownProverBatchCommitment(
                commitments: commitResult.commitments,
                batchRoot: commitResult.batchRoot
            ),
            proof: openResult.batchProof
        )
    }

    /// Verify a single column opening.
    public func verifyColumn(commitment: BrakedownProverCommitment,
                            proof: BrakedownProverOpeningProof) -> Bool {
        return proverEngine.verify(commitment: commitment, proof: proof)
    }

    // MARK: - Field Conversion

    /// Convert M31 array to Fr array.
    ///
    /// M31 values are reduced modulo the BN254 scalar field order.
    /// Uses Montgomery multiplication for efficiency.
    ///
    /// - Parameter m31Values: Array of M31 values.
    /// - Returns: Array of Fr values.
    public func m31ArrayToFr(_ m31Values: [M31]) -> [Fr] {
        var frValues: [Fr] = []
        frValues.reserveCapacity(m31Values.count)

        for m31 in m31Values {
            // Reduce M31 value modulo BN254 prime
            let frVal = frFromUInt64(UInt64(m31.v))
            frValues.append(frVal)
        }

        return frValues
    }

    /// Convert Fr array back to M31 array (if values fit in M31 range).
    ///
    /// - Parameter frValues: Array of Fr values.
    /// - Returns: Array of M31 values, or nil if any value is out of range.
    public func frArrayToM31(_ frValues: [Fr]) -> [M31]? {
        var m31Values: [M31] = []
        m31Values.reserveCapacity(frValues.count)

        for fr in frValues {
            // Extract low 31 bits if value fits in M31 range
            let val = frToUInt64Low(fr)

            if val >= UInt64(M31.P) {
                return nil  // Value out of M31 range
            }

            m31Values.append(M31(v: UInt32(val)))
        }

        return m31Values
    }

    // MARK: - Utilities

    /// Compute a random evaluation point for opening.
    ///
    /// - Parameters:
    ///   - logEval: Log of evaluation length (number of variables).
    ///   - seed: Optional seed for determinism.
    /// - Returns: Random evaluation point.
    public func randomPoint(logEval: Int, seed: UInt64 = 0xDEADBEEF) -> [Fr] {
        var rng = seed
        var point: [Fr] = []
        point.reserveCapacity(logEval)

        for _ in 0..<logEval {
            rng = rng &* 6364136223846793005 &+ 1442695040888963407
            let val = rng >> 32
            point.append(frFromUInt64(val))
        }

        return point
    }

    /// Return statistics about a commitment for debugging.
    public func commitmentStats(_ c: BrakedownProverCommitment)
        -> (numVars: Int, evalCount: Int, matrixDims: String,
            encodedCols: Int, treeSize: Int, commitmentBytes: Int) {
        return proverEngine.commitmentStats(c)
    }

    /// Return statistics about an opening proof for debugging.
    public func proofStats(_ p: BrakedownProverOpeningProof)
        -> (tVectorLen: Int, numQueries: Int, proofBytes: Int,
            avgMerklePathLen: Double) {
        return proverEngine.proofStats(p)
    }
}

// MARK: - Helper Functions

/// Convert UInt64 to Fr (BN254 scalar field).
private func frFromUInt64(_ val: UInt64) -> Fr {
    // Use zkMetal's frFromInt but cast to UInt64
    return frFromInt(val)
}

/// Extract low UInt64 from Fr (assumes Fr is in range).
/// This extracts the first limb of the Fr representation.
private func frToUInt64Low(_ fr: Fr) -> UInt64 {
    let limbs = fr.to64()
    return limbs[0]
}

/// Simple hash for combining commitment roots.
/// Uses BN254 scalar field arithmetic.
private func hashCommitments(_ commitments: [Fr]) -> Fr {
    guard !commitments.isEmpty else { return .zero }
    guard commitments.count > 1 else { return commitments[0] }

    var current = commitments
    while current.count > 1 {
        var next = [Fr]()
        for i in stride(from: 0, to: current.count, by: 2) {
            if i + 1 < current.count {
                // Combine pair with simple field multiplication + addition
                let combined = frAdd(current[i], frMul(current[i], current[i + 1]))
                next.append(combined)
            } else {
                next.append(current[i])
            }
        }
        current = next
    }
    return current[0]
}

// MARK: - Interleaved 8-Tree Brakedown Commitment

/// Result of committing EVM trace columns using interleaved 8-tree Brakedown.
public struct ZoltraakBrakedownInterleavedResult {
    /// 8 Brakedown commitments (one per tree).
    public let commitments: [BrakedownProverCommitment]

    /// Combined batch root (hash of all 8 tree roots).
    public let batchRoot: Fr

    /// Time spent converting M31 to Fr in milliseconds.
    public let conversionMs: Double

    /// Time spent building interleaved data in milliseconds.
    public let interleaveMs: Double

    /// Time spent in Brakedown commitment in milliseconds.
    public let commitMs: Double

    /// Total elapsed time in milliseconds.
    public let timeMs: Double

    /// Number of trees used.
    public var numTrees: Int { commitments.count }

    /// Number of columns per tree (approximate).
    public var columnsPerTree: Int { 180 / numTrees }

    /// Estimated proof size for all 8 trees.
    public var totalCommitmentSize: Int {
        var total = 0
        for commitment in commitments {
            total += commitment.commitmentSize
        }
        return total
    }
}

extension ZoltraakBrakedownEngine {

    /// Number of trees for interleaved commitment.
    /// 180 columns / 8 trees = ~22-23 columns per tree.
    public static let numInterleavedTrees = 8

    /// Commit trace columns using INTERLEAVED 8-Tree Brakedown commitment.
    ///
    /// This combines the best of both approaches:
    /// - 8-tree structure: Better GPU utilization, fewer trees (8 vs 180)
    /// - Brakedown: Trustless commitment without KZG trusted setup
    ///
    /// Data Layout:
    /// ```
    /// Tree 0: columns 0-22 (23 columns), values interleaved
    /// Tree 1: columns 23-45 (23 columns), values interleaved
    /// ...
    /// Tree 7: columns 156-179 (24 columns), values interleaved
    ///
    /// Each tree: ~23 x 16384 = 376,832 values (padded to 524288 = 2^19)
    /// Total: 8 trees
    /// ```
    ///
    /// Interleaved values within each tree:
    /// Layout: [col0_val0, col1_val0, ..., col22_val0, col0_val1, col1_val1, ...]
    ///
    /// Note: Each tree is padded to the next power of 2 (2^19 = 524288) for
    /// Brakedown compatibility. Padding uses zero values.
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form (180 columns expected).
    ///   - evalLen: Evaluation length (number of leaves per column, e.g., 16384).
    /// - Returns: `ZoltraakBrakedownInterleavedResult` with 8 commitments and timing.
    public func commitInterleaved8Trees(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> ZoltraakBrakedownInterleavedResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count
        let numTrees = Self.numInterleavedTrees

        precondition(numColumns > 0, "Must have at least one column")
        precondition(evalLen > 0 && (evalLen & (evalLen - 1)) == 0,
                     "evalLen must be a power of 2")

        // Calculate column distribution across trees
        let columnsPerTree = numColumns / numTrees
        let remainder = numColumns % numTrees

        // Calculate power-of-2 size for each tree
        // Each tree has colsInTree * evalLen values, pad to next power of 2
        // For 23 * 16384 = 376832, next power of 2 is 524288 (2^19)
        // For 22 * 16384 = 360448, next power of 2 is 524288 (2^19)
        let computeColsInTree: (Int) -> Int = { treeIdx in
            return treeIdx < remainder ? columnsPerTree + 1 : columnsPerTree
        }

        let rawValuesPerTree = computeColsInTree(0) * evalLen
        // Round up to next power of 2
        var paddedValuesPerTree = 1
        while paddedValuesPerTree < rawValuesPerTree {
            paddedValuesPerTree *= 2
        }

        // Step 1: Convert M31 to Fr for all columns
        let convT0 = CFAbsoluteTimeGetCurrent()
        var frPolynomials: [[Fr]] = []
        frPolynomials.reserveCapacity(numColumns)

        for col in traceLDEs {
            precondition(col.count == evalLen, "Column length must match evalLen")
            let frPoly = m31ArrayToFr(col)
            frPolynomials.append(frPoly)
        }
        let conversionMs = (CFAbsoluteTimeGetCurrent() - convT0) * 1000

        // Step 2: Interleave columns into 8 trees with padding
        let interleaveT0 = CFAbsoluteTimeGetCurrent()

        // Build interleaved data for each tree with zero padding
        var treeData: [[Fr]] = []
        treeData.reserveCapacity(numTrees)

        for treeIdx in 0..<numTrees {
            let colsInThisTree = computeColsInTree(treeIdx)

            // Calculate starting column index
            let baseCol: Int
            if treeIdx < remainder {
                baseCol = treeIdx * columnsPerTree + treeIdx
            } else {
                baseCol = treeIdx * columnsPerTree + remainder
            }

            // Interleave values from columns in this tree
            // Layout: [col0_val0, col1_val0, ..., colN_val0, col0_val1, ...]
            var interleaved: [Fr] = []
            interleaved.reserveCapacity(paddedValuesPerTree)

            // Add actual interleaved values
            for pos in 0..<evalLen {
                for colInGroup in 0..<colsInThisTree {
                    let globalCol = baseCol + colInGroup
                    if globalCol < numColumns && pos < frPolynomials[globalCol].count {
                        interleaved.append(frPolynomials[globalCol][pos])
                    }
                }
            }

            // Pad to power of 2 with zeros
            while interleaved.count < paddedValuesPerTree {
                interleaved.append(.zero)
            }

            treeData.append(interleaved)
        }

        let interleaveMs = (CFAbsoluteTimeGetCurrent() - interleaveT0) * 1000

        // Step 3: Commit each tree with Brakedown
        let commitT0 = CFAbsoluteTimeGetCurrent()
        var commitments: [BrakedownProverCommitment] = []

        for treeIdx in 0..<numTrees {
            let commitment = try proverEngine.commit(evaluations: treeData[treeIdx])
            commitments.append(commitment)
        }

        // Combine all tree roots into a batch root
        let treeRoots = commitments.map { $0.merkleRoot }
        let batchRoot = hashCommitments(treeRoots)

        let commitMs = (CFAbsoluteTimeGetCurrent() - commitT0) * 1000
        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return ZoltraakBrakedownInterleavedResult(
            commitments: commitments,
            batchRoot: batchRoot,
            conversionMs: conversionMs,
            interleaveMs: interleaveMs,
            commitMs: commitMs,
            timeMs: totalMs
        )
    }

    /// Benchmark interleaved 8-tree Brakedown vs standard Brakedown.
    ///
    /// - Parameters:
    ///   - numColumns: Number of trace columns (default: 180).
    ///   - evalLen: Evaluation length per column (default: 16384).
    /// - Returns: Tuple comparing both approaches.
    public func benchmarkInterleaved(
        numColumns: Int = 180,
        evalLen: Int = 16384
    ) throws -> (standardMs: Double, interleavedMs: Double, speedup: Double) {
        // Generate synthetic trace data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                let val = UInt32((col * 1000 + i) % Int(M31.P) & 0x7FFFFFFF)
                values.append(M31(v: val))
            }
            traceLDEs.append(values)
        }

        // Standard Brakedown (180 trees)
        let standardT0 = CFAbsoluteTimeGetCurrent()
        let standardResult = try commit(traceLDEs: traceLDEs, evalLen: evalLen)
        let standardMs = (CFAbsoluteTimeGetCurrent() - standardT0) * 1000

        // Interleaved 8-tree Brakedown
        let interleavedT0 = CFAbsoluteTimeGetCurrent()
        let interleavedResult = try commitInterleaved8Trees(traceLDEs: traceLDEs, evalLen: evalLen)
        let interleavedMs = (CFAbsoluteTimeGetCurrent() - interleavedT0) * 1000

        let speedup = standardMs / interleavedMs

        print("  Standard Brakedown (180 trees): \(String(format: "%.2f", standardMs)) ms")
        print("    - Conversion: \(String(format: "%.2f", standardResult.conversionMs)) ms")
        print("    - Commit: \(String(format: "%.2f", standardResult.commitMs)) ms")
        print("  Interleaved Brakedown (8 trees): \(String(format: "%.2f", interleavedMs)) ms")
        print("    - Conversion: \(String(format: "%.2f", interleavedResult.conversionMs)) ms")
        print("    - Interleave: \(String(format: "%.2f", interleavedResult.interleaveMs)) ms")
        print("    - Commit: \(String(format: "%.2f", interleavedResult.commitMs)) ms")
        print("  Speedup: \(String(format: "%.2fx", speedup))")

        return (standardMs, interleavedMs, speedup)
    }
}

// MARK: - Benchmark Support

extension ZoltraakBrakedownEngine {

    /// Benchmark Brakedown commitment for EVM-scale traces.
    ///
    /// - Parameters:
    ///   - numColumns: Number of trace columns (default: 180, typical EVMAIR).
    ///   - evalLen: Evaluation length per column (default: 16384).
    /// - Returns: Tuple of (commitMs, conversionMs, totalMs) timing values.
    public func benchmarkCommit(
        numColumns: Int = 180,
        evalLen: Int = 16384
    ) throws -> (commitMs: Double, conversionMs: Double, totalMs: Double) {
        // Generate synthetic trace data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                let val = UInt32((col * 1000 + i) % Int(M31.P) & 0x7FFFFFFF)
                values.append(M31(v: val))
            }
            traceLDEs.append(values)
        }

        // Benchmark commitment
        let result = try commit(traceLDEs: traceLDEs, evalLen: evalLen)

        return (result.commitMs, result.conversionMs, result.timeMs)
    }

    /// Compare Brakedown vs Merkle commitment.
    ///
    /// - Parameters:
    ///   - numColumns: Number of trace columns.
    ///   - evalLen: Evaluation length per column.
    /// - Returns: Tuple comparing Brakedown and Merkle timings.
    public func benchmarkVersusMerkle(
        numColumns: Int = 180,
        evalLen: Int = 16384
    ) throws -> (brakedownMs: Double, merkleMs: Double, speedup: Double) {
        // Generate synthetic trace data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                let val = UInt32((col * 1000 + i) % Int(M31.P) & 0x7FFFFFFF)
                values.append(M31(v: val))
            }
            traceLDEs.append(values)
        }

        // Brakedown timing
        let brakedownT0 = CFAbsoluteTimeGetCurrent()
        let brakedownResult = try commit(traceLDEs: traceLDEs, evalLen: evalLen)
        let brakedownMs = (CFAbsoluteTimeGetCurrent() - brakedownT0) * 1000

        // Merkle timing (CPU baseline)
        let merkleT0 = CFAbsoluteTimeGetCurrent()
        var merkleRoots: [zkMetal.M31Digest] = []
        for col in traceLDEs {
            let tree = buildPoseidon2M31MerkleTree(col, count: evalLen)
            merkleRoots.append(poseidon2M31MerkleRoot(tree, n: evalLen))
        }
        let merkleMs = (CFAbsoluteTimeGetCurrent() - merkleT0) * 1000

        print("  Brakedown commit: \(String(format: "%.2f", brakedownMs)) ms")
        print("    - Conversion: \(String(format: "%.2f", brakedownResult.conversionMs)) ms")
        print("    - Commit: \(String(format: "%.2f", brakedownResult.commitMs)) ms")
        print("  Merkle commit: \(String(format: "%.2f", merkleMs)) ms")
        print("  Brakedown proof size: \(brakedownResult.commitments.first?.commitmentSize ?? 0) bytes/column")

        let speedup = merkleMs / brakedownMs

        return (brakedownMs, merkleMs, speedup)
    }
}
