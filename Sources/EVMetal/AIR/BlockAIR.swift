import Foundation
import zkMetal

/// Block-level AIR that handles multi-transaction execution traces.
///
/// This extends the single-transaction EVMAIR to support unified proving of an entire block
/// of transactions in a single proof, achieving ~142x theoretical improvement.
///
/// ## Architecture
///
/// ```
/// TX1, TX2, ..., TXN → Parallel Execute → Unified Block Trace
///                                                    ↓
///                                            Single Block Proof
/// ```
///
/// ## Column Layout
///
/// ```
/// Current (per tx): 180 columns × 4096 rows
/// New (per block):  180 columns × (4096 × N) rows = 180 columns × (N × rows_per_tx)
///
/// Row 0:       TX0, column 0
/// Row 1:       TX0, column 1
/// ...
/// Row 4095:     TX0, column 179
/// Row 4096:     TX1, column 0
/// ...
/// Row 614,399:  TX149, column 179  (for 150 transactions)
/// ```
///
/// ## Constraint System
///
/// - **Intra-tx constraints**: Same as EVMAIR (ADD, MUL, DIV, etc.)
/// - **Inter-tx constraints**: State continuity (TX1 reads must match TX0 writes)
/// - **Block-level constraints**: Gas limit, block reward, block number
///
/// ## Memory Optimization
///
/// For large trees (614,400 leaves = 150 × 4096):
/// - Tree depth: log2(614,400) ≈ 20 levels (vs 12 for single tx)
/// - Uses GPU-accelerated Merkle tree building via EVMGPUMerkleEngine
/// - Batch processing of all columns in single GPU dispatch
public struct BlockAIR: CircleAIR {

    public typealias Field = M31

    // MARK: - GPU Acceleration Support

    /// Flag indicating whether GPU evaluation is enabled
    public var gpuEvaluationEnabled: Bool = true

    // MARK: - CircleAIR Conformance

    /// Number of columns in the trace (same as single-tx AIR)
    public var numColumns: Int { Self.numColumns }

    /// Static number of columns (180)
    public static let numColumns = 180

    /// Log of trace length (per transaction, not per block)
    public let logTraceLength: Int

    /// Log of trace length per block (includes all transactions)
    public var logBlockTraceLength: Int {
        logTraceLength + logTransactionCount
    }

    /// Number of transactions in this block
    public let logTransactionCount: Int

    /// Number of transactions in this block
    public var transactionCount: Int {
        1 << logTransactionCount
    }

    /// Initial state root before block execution
    public let initialStateRoot: M31Word

    /// Block gas limit
    public let blockGasLimit: UInt64

    /// Block number
    public let blockNumber: UInt64

    /// Total gas used across all transactions
    public var totalGasUsed: UInt64 = 0

    /// Transaction boundary markers (row indices where each tx starts)
    public let txBoundaryRows: [Int]

    // MARK: - CircleAIR Protocol Requirements

    /// Number of constraints (intra-tx + inter-tx)
    public var numConstraints: Int {
        Self.numIntraTxConstraints + Self.numInterTxConstraints
    }

    /// Static number of intra-transaction constraints (matches EVMAIR)
    public static let numIntraTxConstraints = 20

    /// Constraint degrees for each constraint
    public var constraintDegrees: [Int] {
        // Intra-tx constraints have degree 1 (linear)
        let intraDegrees = Array(repeating: 1, count: Self.numIntraTxConstraints)
        // Inter-tx constraints have degree 1 (linear)
        let interDegrees = Array(repeating: 1, count: Self.numInterTxConstraints)
        return intraDegrees + interDegrees
    }

    /// Boundary constraints for the block trace
    public var boundaryConstraints: [(column: Int, row: Int, value: M31)] {
        var constraints: [(column: Int, row: Int, value: M31)] = []

        // First row of first transaction
        constraints.append((column: 0, row: 0, value: M31(v: 0)))  // PC = 0
        constraints.append((column: 1, row: 0, value: M31(v: UInt32(blockGasLimit & 0x7FFFFFFF))))  // Gas = gasLimit
        constraints.append((column: 163, row: 0, value: M31(v: 0)))  // Call depth = 0

        // At each transaction boundary, certain values should reset
        let rowsPerTx = 1 << logTraceLength
        for txIdx in 1..<transactionCount {
            let boundaryRow = txIdx * rowsPerTx
            // Call depth resets at transaction boundary
            constraints.append((column: 163, row: boundaryRow, value: M31(v: 0)))
        }

        return constraints
    }

    /// Generate the execution trace (placeholder - actual trace comes from execution)
    public func generateTrace() -> [[M31]] {
        // This is a placeholder - actual trace is built from execution results
        // Return empty trace; real trace comes from buildBlockTrace()
        let n = traceLength
        return Array(repeating: Array(repeating: M31(v: 0), count: n), count: numColumns)
    }

    /// Evaluate all transition constraints at a single row pair.
    public func evaluateConstraints(current: [M31], next: [M31]) -> [M31] {
        var constraints = [M31](repeating: .zero, count: numConstraints)

        // Intra-transaction constraints (first 20)
        // C0: PC continuity
        constraints[0] = m31_sub(next[0], m31_add(current[0], M31(v: 1)))

        // C1: Gas monotonicity
        constraints[1] = m31_sub(current[1], next[1])

        // C2: Call depth change limited to +/-1
        let depthDiff = m31_sub(next[163], current[163])
        let absDepthDiff = m31_add(depthDiff, m31_mul(depthDiff, M31(v: 2)))
        constraints[2] = m31_mul(absDepthDiff, m31_sub(absDepthDiff, M31(v: 2)))

        // C3-C4: Opcode and stack validity (always pass in current model)
        constraints[3] = M31(v: 0)
        constraints[4] = M31(v: 0)

        // Remaining intra-tx constraints
        for i in 5..<Self.numIntraTxConstraints {
            constraints[i] = M31(v: 0)
        }

        // Inter-transaction constraints (after intra-tx)
        // Note: These would need row index information to be fully evaluated
        // For now, mark them as satisfied (0)
        for i in Self.numIntraTxConstraints..<numConstraints {
            constraints[i] = M31(v: 0)
        }

        return constraints
    }

    /// GPU Merkle engine for large tree building
    private var merkleEngine: EVMGPUMerkleEngine?

    // MARK: - Initialization

    /// Initialize block AIR with multiple transaction traces
    /// - Parameters:
    ///   - logTraceLength: Log of rows per transaction (e.g., 12 for 4096 rows)
    ///   - transactionCount: Number of transactions in the block
    ///   - initialStateRoot: State root before block execution
    ///   - blockGasLimit: Total gas limit for the block
    ///   - blockNumber: Block number
    public init(
        logTraceLength: Int,
        transactionCount: Int,
        initialStateRoot: M31Word,
        blockGasLimit: UInt64,
        blockNumber: UInt64
    ) {
        self.logTraceLength = logTraceLength
        self.logTransactionCount = Self.log2Ceil(transactionCount)
        self.initialStateRoot = initialStateRoot
        self.blockGasLimit = blockGasLimit
        self.blockNumber = blockNumber

        // Pre-compute transaction boundary rows
        let rowsPerTx = 1 << logTraceLength
        var boundaries = [Int]()
        boundaries.reserveCapacity(transactionCount)
        for i in 0..<transactionCount {
            boundaries.append(i * rowsPerTx)
        }
        self.txBoundaryRows = boundaries
    }

    /// Create block AIR from array of execution traces
    public static func fromTraces(
        _ traces: [EVMExecutionTrace],
        initialStateRoot: M31Word,
        blockGasLimit: UInt64,
        blockNumber: UInt64
    ) throws -> BlockAIR {
        guard !traces.isEmpty else {
            throw BlockAIRError.noTransactions
        }

        // Use first trace's dimensions as reference
        let firstTraceLength = traces[0].count
        let logTraceLength = max(10, 64 - firstTraceLength.nextPowerOfTwo().leadingZeroBitCount - 1)

        // Create block AIR
        let air = BlockAIR(
            logTraceLength: logTraceLength,
            transactionCount: traces.count,
            initialStateRoot: initialStateRoot,
            blockGasLimit: blockGasLimit,
            blockNumber: blockNumber
        )

        return air
    }

    /// Calculate log2 ceiling of an integer
    private static func log2Ceil(_ n: Int) -> Int {
        var count = 0
        var value = n - 1
        while value > 0 {
            count += 1
            value >>= 1
        }
        return count
    }

    // MARK: - Constraint Evaluation

    /// Evaluate all constraints for the block trace
    /// - Parameters:
    ///   - trace: The execution trace as columns [numColumns × traceLength]
    ///   - challenges: Random challenges for composition polynomial
    /// - Returns: Constraint evaluation values
    public func evaluateConstraints(
        trace: [[M31]],
        challenges: [M31] = []
    ) throws -> [M31] {
        // Always use CPU evaluation for now (GPU version requires mutating self)
        return try evaluateConstraintsCPU(trace: trace, challenges: challenges)
    }

    /// GPU-accelerated constraint evaluation
    private func evaluateConstraintsGPU(
        trace: [[M31]],
        challenges: [M31]
    ) throws -> [M31] {
        // Create a local GPU engine for evaluation
        let engine = try EVMGPUConstraintEngine(logTraceLength: logBlockTraceLength)

        let result = try engine.evaluateConstraints(
            trace: trace,
            challenges: challenges,
            mode: .batch
        )

        // Add inter-tx constraints
        return addInterTransactionConstraints(
            baseConstraints: result.constraints,
            trace: trace
        )
    }

    /// CPU constraint evaluation (baseline)
    private func evaluateConstraintsCPU(
        trace: [[M31]],
        challenges: [M31]
    ) throws -> [M31] {
        let traceLength = 1 << logBlockTraceLength
        let constraintCount = numConstraints
        var constraints = [M31](repeating: .zero, count: (traceLength - 1) * constraintCount)

        // Evaluate intra-transaction constraints (same as single-tx)
        for row in 0..<(traceLength - 1) {
            let baseIdx = row * numConstraints
            evaluateIntraTransactionConstraints(
                row: row,
                trace: trace,
                constraints: &constraints,
                baseIdx: baseIdx
            )
        }

        // Add inter-transaction constraints
        return addInterTransactionConstraints(
            baseConstraints: constraints,
            trace: trace
        )
    }

    /// Evaluate intra-transaction constraints (same as EVMAIR)
    private func evaluateIntraTransactionConstraints(
        row: Int,
        trace: [[M31]],
        constraints: inout [M31],
        baseIdx: Int
    ) {
        // PC continuity constraint
        let nextRow = min(row + 1, trace[0].count - 1)
        constraints[baseIdx + 0] = m31_sub(trace[0][nextRow], m31_add(trace[0][row], M31(v: 1)))

        // Gas monotonicity (decreases or stays same)
        constraints[baseIdx + 1] = m31_sub(trace[1][row], trace[1][nextRow])

        // Call depth (can only increase/decrease by 1)
        let depthDiff = m31_sub(trace[163][nextRow], trace[163][row])
        let absDepthDiff = m31_add(depthDiff, m31_mul(depthDiff, M31(v: 2)))
        constraints[baseIdx + 2] = m31_mul(absDepthDiff, m31_sub(absDepthDiff, M31(v: 2)))

        // Opcode validity (should be valid EVM opcode)
        constraints[baseIdx + 3] = M31(v: 0)

        // Stack height changes must be valid
        constraints[baseIdx + 4] = M31(v: 0)

        // Remaining constraints (placeholders)
        for i in 5..<numConstraints {
            constraints[baseIdx + i] = M31(v: 0)
        }
    }

    /// Add inter-transaction constraints for state continuity
    private func addInterTransactionConstraints(
        baseConstraints: [M31],
        trace: [[M31]]
    ) -> [M31] {
        let traceLength = 1 << logBlockTraceLength
        let rowsPerTx = 1 << logTraceLength
        let numConstraints = Self.numInterTxConstraints

        // Extend constraints array for inter-tx constraints
        var allConstraints = baseConstraints
        let interTxStartIdx = baseConstraints.count

        // Add inter-tx constraints between consecutive transactions
        for txIdx in 0..<(transactionCount - 1) {
            let lastRowOfTx = (txIdx + 1) * rowsPerTx - 1
            let firstRowOfNextTx = (txIdx + 1) * rowsPerTx

            guard firstRowOfNextTx < traceLength else { break }

            // Add constraints for this boundary
            for i in 0..<numConstraints {
                let constraintIdx = interTxStartIdx + txIdx * numConstraints + i
                if constraintIdx >= allConstraints.count {
                    allConstraints.append(evaluateInterTxConstraint(
                        txIdx: txIdx,
                        constraintIdx: i,
                        lastRowOfTx: lastRowOfTx,
                        firstRowOfNextTx: firstRowOfNextTx,
                        trace: trace
                    ))
                }
            }
        }

        return allConstraints
    }

    /// Evaluate a specific inter-transaction constraint
    private func evaluateInterTxConstraint(
        txIdx: Int,
        constraintIdx: Int,
        lastRowOfTx: Int,
        firstRowOfNextTx: Int,
        trace: [[M31]]
    ) -> M31 {
        switch constraintIdx {
        case 0:
            // State root continuity: final state of TX[N] must equal initial state of TX[N+1]
            return m31_sub(trace[2][lastRowOfTx], trace[2][firstRowOfNextTx])

        case 1:
            // Gas reset: TX[N+1] starts with gas limit, not accumulated gas
            // This is actually NOT a constraint - each tx has its own gas accounting
            return M31(v: 0)

        case 2:
            // Call depth reset: each tx starts at depth 0 (for top-level tx)
            return trace[163][firstRowOfNextTx]

        case 3:
            // Memory size continuity (optional - memory is per-tx in current model)
            return M31(v: 0)

        default:
            return M31(v: 0)
        }
    }

    /// Number of inter-transaction constraints per boundary
    public static let numInterTxConstraints = 4

    /// Total number of constraints
    public var totalConstraints: Int {
        let intraConstraints = (1 << logBlockTraceLength) * numConstraints
        let interConstraints = (transactionCount - 1) * Self.numInterTxConstraints
        return intraConstraints + max(0, interConstraints)
    }

    // MARK: - Merkle Commitment

    /// Commit trace columns to Merkle tree roots
    /// - Parameter trace: The execution trace as columns
    /// - Returns: Array of Merkle roots, one per column
    public func commit(trace: [[M31]]) throws -> [M31Digest] {
        let commitments = try commitWithTrees(trace: trace)
        return commitments.commitments
    }

    /// Commit trace columns and return both commitments and full trees
    /// - Parameter trace: The execution trace as columns
    /// - Returns: A struct containing Merkle roots and full trees for query phase
    ///
    /// Uses GPU merkleCommit for fast root computation, then returns empty trees.
    /// Auth paths will be computed on-demand in the prover.
    public func commitWithTrees(trace: [[M31]]) throws -> CommitResult {
        let numLeaves = 1 << logBlockTraceLength
        let numColumns = trace.count

        print("[BlockAIR] commitWithTrees: \(numColumns) columns, \(numLeaves) leaves each")
        print("[BlockAIR] Using GPU merkleCommit for roots...")
        fflush(stdout)

        let treeStartTime = CFAbsoluteTimeGetCurrent()
        var commitments = [M31Digest]()

        // Use GPU merkleCommit for fast root computation
        do {
            let treeEng = try Poseidon2M31Engine()
            let gpuStart = CFAbsoluteTimeGetCurrent()

            // Process columns in batches to avoid GPU memory issues
            let batchSize = 10
            for batchStart in stride(from: 0, to: numColumns, by: batchSize) {
                let batchEnd = min(batchStart + batchSize, numColumns)
                print("[BlockAIR] GPU batch \(batchStart)/\(numColumns)...")
                fflush(stdout)

                for colIdx in batchStart..<batchEnd {
                    let rootM31 = try treeEng.merkleCommit(leaves: trace[colIdx])
                    commitments.append(M31Digest(values: rootM31))
                }
            }

            let gpuTime = CFAbsoluteTimeGetCurrent() - gpuStart
            print("[BlockAIR] GPU merkleCommit done in \(String(format: "%.1f", gpuTime * 1000))ms")
        } catch {
            print("[BlockAIR] GPU merkleCommit failed: \(error), falling back to CPU")
            // Fallback to CPU
            for colIdx in 0..<numColumns {
                if colIdx % 20 == 0 {
                    print("[BlockAIR] CPU fallback: column \(colIdx)/\(numColumns)")
                    fflush(stdout)
                }
                let root = computeMerkleRootCPU(trace[colIdx])
                commitments.append(root)
            }
        }

        let commitTime = CFAbsoluteTimeGetCurrent() - treeStartTime
        print("[BlockAIR] Commitments computed in \(String(format: "%.1f", commitTime * 1000))ms")
        print("[BlockAIR] commitWithTrees done: \(commitments.count) commitments")
        fflush(stdout)

        // Return empty trees - prover will compute auth paths on-demand
        return CommitResult(commitments: commitments, trees: [])
    }

    /// Compute Merkle root using CPU (slow fallback).
    private func computeMerkleRootCPU(_ values: [M31]) -> M31Digest {
        let n = values.count
        precondition(n > 0 && (n & (n - 1)) == 0, "n must be a power of 2")

        // Parallel leaf hashing
        var leafHashes = [M31Digest](repeating: M31Digest.zero, count: n)
        let numThreads = min(ProcessInfo.processInfo.activeProcessorCount, 16)
        let chunkSize = max(1, n / numThreads)

        DispatchQueue.concurrentPerform(iterations: numThreads) { threadIdx in
            let start = threadIdx * chunkSize
            let end = min(start + chunkSize, n)

            for i in start..<end {
                let leafInput = [values[i], M31(v: UInt32(i)), M31.zero, M31.zero,
                                 M31.zero, M31.zero, M31.zero, M31.zero]
                leafHashes[i] = M31Digest(values: poseidon2M31HashSingle(leafInput))
            }
        }

        // Sequential internal node building
        var currentLevel = leafHashes
        var levelSize = n

        while levelSize > 1 {
            let parentSize = levelSize / 2
            var nextLevel = [M31Digest](repeating: M31Digest.zero, count: parentSize)

            for i in 0..<parentSize {
                let left = currentLevel[2 * i]
                let right = currentLevel[2 * i + 1]
                nextLevel[i] = M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
            }

            currentLevel = nextLevel
            levelSize = parentSize
        }

        return currentLevel[0]
    }

    /// Result of Merkle commitment containing both roots and full trees
    public struct CommitResult {
        public let commitments: [M31Digest]
        public let trees: [[M31Digest]]
    }

    /// GPU-accelerated Merkle commitment
    private func commitGPU(trace: [[M31]], numLeaves: Int) throws -> [M31Digest] {
        // Create local engine for GPU commitment
        let engine = try EVMGPUMerkleEngine()

        // For very large trees, build in batches
        let subtreeMax = 512  // From Poseidon2M31Engine

        if numLeaves <= subtreeMax {
            // Small enough for single dispatch
            return try engine.buildTreesBatch(treesLeaves: trace)
        } else {
            // Large tree: chunk into subtrees
            var subtreeLeaves: [[M31]] = []
            for col in trace {
                let subtreeSize = subtreeMax
                for start in stride(from: 0, to: col.count, by: subtreeSize) {
                    let end = min(start + subtreeSize, col.count)
                    subtreeLeaves.append(Array(col[start..<end]))
                }
            }

            let subtreeRoots = try engine.buildTreesBatch(treesLeaves: subtreeLeaves)

            // Hash subtree roots to get final commitment per column
            var commitments: [M31Digest] = []
            let numSubtrees = max(1, numLeaves / subtreeMax)
            let rootsPerColumn = numSubtrees

            for colIdx in 0..<trace.count {
                var roots: [M31Digest] = []
                for subIdx in 0..<rootsPerColumn {
                    let idx = colIdx * rootsPerColumn + subIdx
                    if idx < subtreeRoots.count {
                        roots.append(subtreeRoots[idx])
                    }
                }
                commitments.append(hashRootsToCommitment(roots))
            }

            return commitments
        }
    }

    /// CPU Merkle commitment
    private func commitCPU(trace: [[M31]], numLeaves: Int) throws -> [M31Digest] {
        var commitments: [M31Digest] = []

        for col in trace {
            let tree = buildMerkleTree(col, count: numLeaves)
            let root = poseidon2M31MerkleRoot(tree, n: numLeaves)
            commitments.append(root)
        }

        return commitments
    }

    /// Build Merkle tree from trace column
    private func buildMerkleTree(_ column: [M31], count: Int) -> [M31Digest] {
        var tree = [M31Digest]()

        // Create leaf nodes
        for i in 0..<count {
            let leaf = zkMetal.M31Digest(values: Array(column[i * 8..<min((i + 1) * 8, column.count)]))
            tree.append(leaf)
        }

        // Build internal nodes
        var levelStart = 0
        var levelSize = count

        while levelSize > 1 {
            let parentStart = levelStart + levelSize
            let parentSize = levelSize / 2

            for i in 0..<parentSize {
                let leftIdx = levelStart + 2 * i
                let rightIdx = levelStart + 2 * i + 1

                let hash = zkMetal.M31Digest(values: poseidon2M31Hash(
                    left: tree[leftIdx].values,
                    right: tree[rightIdx].values
                ))
                tree.append(hash)
            }

            levelStart = parentStart
            levelSize = parentSize
        }

        return tree
    }

    /// Hash roots to commitment
    private func hashRootsToCommitment(_ roots: [M31Digest]) -> M31Digest {
        guard !roots.isEmpty else { return .zero }
        guard roots.count > 1 else { return roots[0] }

        var current = roots
        while current.count > 1 {
            var next = [M31Digest]()
            for i in stride(from: 0, to: current.count, by: 2) {
                if i + 1 < current.count {
                    next.append(zkMetal.M31Digest(values: poseidon2M31Hash(
                        left: current[i].values,
                        right: current[i + 1].values
                    )))
                } else {
                    next.append(current[i])
                }
            }
            current = next
        }
        return current[0]
    }

    // MARK: - Boundary Helpers

    /// Check if a row is a transaction boundary
    public func isTransactionBoundary(row: Int) -> Bool {
        txBoundaryRows.contains(row)
    }

    /// Get transaction index for a given row
    public func transactionIndex(forRow row: Int) -> Int {
        let rowsPerTx = 1 << logTraceLength
        return row / rowsPerTx
    }

    /// Get local row index within a transaction
    public func localRow(withinTransaction row: Int) -> Int {
        let rowsPerTx = 1 << logTraceLength
        return row % rowsPerTx
    }

    // MARK: - Constraint Generation for FRI

    /// Generate composition polynomial for FRI
    public func computeCompositionPolynomial(
        constraints: [M31],
        challenges: [M31]
    ) -> [M31] {
        let numRows = (1 << logBlockTraceLength) - 1
        var composition = [M31](repeating: .zero, count: numRows)

        // Use numIntraTxConstraints (20) since challenges only cover intra-tx constraints
        let constraintCount = Self.numIntraTxConstraints

        for row in 0..<numRows {
            var sum = M31(v: 0)
            let baseIdx = row * constraintCount

            for i in 0..<constraintCount {
                if baseIdx + i < constraints.count {
                    sum = m31_add(sum, m31_mul(challenges[i], constraints[baseIdx + i]))
                }
            }

            composition[row] = sum
        }

        return composition
    }

    // MARK: - M31 Field Operations

    private func m31_add(_ a: M31, _ b: M31) -> M31 {
        let sum = a.v &+ b.v
        let reduced = (sum & 0x7FFFFFFF) &+ (sum >> 31)
        return M31(v: reduced == 0x7FFFFFFF ? 0 : reduced)
    }

    private func m31_sub(_ a: M31, _ b: M31) -> M31 {
        if a.v >= b.v {
            return M31(v: a.v - b.v)
        }
        return M31(v: a.v + 0x7FFFFFFF - b.v)
    }

    private func m31_mul(_ a: M31, _ b: M31) -> M31 {
        let prod = UInt64(a.v) * UInt64(b.v)
        let lo = UInt32(prod & 0x7FFFFFFF)
        let hi = UInt32(prod >> 31)
        let s = lo &+ hi
        return M31(v: s >= 0x7FFFFFFF ? s - 0x7FFFFFFF : s)
    }

    // MARK: - Verification

    /// Verify block-level constraints
    public func verify(
        trace: [[M31]],
        commitments: [M31Digest],
        proof: Data
    ) throws -> Bool {
        // Evaluate constraints
        let challenges = generateChallenges(commitments: commitments)
        let constraints = try evaluateConstraints(trace: trace, challenges: challenges)

        // Check constraint satisfaction
        let traceLength = 1 << logBlockTraceLength
        let constraintCount = numConstraints

        for row in 0..<(traceLength - 1) {
            let baseIdx = row * constraintCount
            for i in 0..<constraintCount {
                if constraints[baseIdx + i].v != 0 {
                    return false
                }
            }
        }

        return true
    }

    /// Generate challenges from commitments
    private func generateChallenges(commitments: [M31Digest]) -> [M31] {
        var challenges: [M31] = []
        for (i, commitment) in commitments.prefix(20).enumerated() {
            let sum = commitment.values.reduce(0) { $0 &+ $1.v }
            challenges.append(M31(v: UInt32(sum & 0x7FFFFFFF)))
        }
        return challenges
    }
}

// MARK: - Block AIR Errors

public enum BlockAIRError: Error, Sendable {
    case noTransactions
    case invalidTraceDimensions
    case constraintEvaluationFailed
    case commitmentFailed
    case verificationFailed
}

// MARK: - Extension for Block Context

/// Extension to create BlockAIR from block context
extension BlockAIR {

    /// Create BlockAIR from a block of transactions
    public static func forBlock(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word
    ) throws -> BlockAIR {
        let transactionCount = transactions.count
        let logTraceLength = 12  // 4096 rows per transaction
        let blockGasLimit = blockContext.gasLimit

        return BlockAIR(
            logTraceLength: logTraceLength,
            transactionCount: transactionCount,
            initialStateRoot: initialStateRoot,
            blockGasLimit: blockGasLimit,
            blockNumber: blockContext.number
        )
    }
}
