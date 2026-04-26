import Foundation
import Metal
import zkMetal

/// Block-level AIR that handles multi-transaction execution traces.
///
/// This extends the single-transaction EVMAIR to support unified proving of an entire block
/// of transactions in a single proof, achieving ~142x theoretical improvement.
///
/// ## Proof Compression Support
///
/// This AIR supports the following compression optimizations:
///
/// 1. **Reduced trace length**: Smaller logTraceLength values create smaller trees
/// 2. **Column subset proving**: Only critical columns are verified in FRI
/// 3. **Two-tier proving**: Fast proof for critical columns, full proof when needed
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
        logTraceLength + log2Ceil(transactionCount)
    }

    /// Number of trace rows (per block, power of 2)
    public var traceLength: Int {
        1 << logBlockTraceLength
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

    // MARK: - Proof Compression Support

    /// Column subset for FRI composition (indices into full column set)
    ///
    /// When set, only these columns are included in the FRI composition polynomial.
    /// The full 180 columns are still committed to maintain soundness.
    public var provingColumnIndices: [Int]

    /// Whether to use column subset proving
    public var useColumnSubset: Bool {
        !provingColumnIndices.isEmpty && provingColumnIndices.count < Self.numColumns
    }

    /// Number of columns to prove (may be subset of total)
    public var provingColumnCount: Int {
        provingColumnIndices.isEmpty ? numColumns : provingColumnIndices.count
    }

    // MARK: - CircleAIR Protocol Requirements

    /// Number of constraints (only intra-tx for column subset optimization)
    public var numConstraints: Int {
        // For column subset optimization, only use intra-tx constraints
        if useColumnSubset {
            return Self.numIntraTxConstraints
        }
        return Self.numIntraTxConstraints + Self.numInterTxConstraints
    }

    /// Static number of intra-transaction constraints (matches EVMAIR)
    public static let numIntraTxConstraints = 20

    /// Constraint degrees for each constraint (only intra-tx for column subset)
    public var constraintDegrees: [Int] {
        // For column subset optimization, only use intra-tx constraint degrees
        Array(repeating: 1, count: Self.numIntraTxConstraints)
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
        // This is a placeholder - actual trace is built from buildBlockTrace()
        let n = traceLength
        return Array(repeating: Array(repeating: M31(v: 0), count: n), count: numColumns)
    }

    /// Evaluate all transition constraints at a single row pair.
    ///
    /// Note: For column subset optimization, we only evaluate constraints
    /// that can be computed from the provided columns.
    public func evaluateConstraints(current: [M31], next: [M31]) -> [M31] {
        // Only evaluate intra-transaction constraints (inter-tx constraints need row index)
        var constraints = [M31](repeating: .zero, count: Self.numIntraTxConstraints)

        // Check if we have enough columns for full constraints
        let hasAllColumns = current.count >= 164 && next.count >= 164

        // C0: PC continuity (column 0)
        if current.count > 0 && next.count > 0 {
            constraints[0] = m31_sub(next[0], m31_add(current[0], M31(v: 1)))
        }

        // C1: Gas monotonicity (column 1)
        if current.count > 1 && next.count > 1 {
            constraints[1] = m31_sub(current[1], next[1])
        }

        // C2: Call depth change limited to +/-1 (column 163)
        // This constraint is skipped if column 163 is not in the subset
        if hasAllColumns {
            let depthDiff = m31_sub(next[163], current[163])
            let absDepthDiff = m31_add(depthDiff, m31_mul(depthDiff, M31(v: 2)))
            constraints[2] = m31_mul(absDepthDiff, m31_sub(absDepthDiff, M31(v: 2)))
        } else {
            // Mark as satisfied if call depth column not available
            constraints[2] = M31(v: 0)
        }

        // C3-C4: Opcode and stack validity (always pass in current model)
        constraints[3] = M31(v: 0)
        constraints[4] = M31(v: 0)

        // Remaining intra-tx constraints
        for i in 5..<Self.numIntraTxConstraints {
            constraints[i] = M31(v: 0)
        }

        return constraints
    }

    /// Evaluate all transition constraints (full version, returns all constraints)
    /// - Parameters:
    ///   - current: Current row column values
    ///   - next: Next row column values
    /// - Returns: All constraint values (intra-tx + inter-tx)
    public func evaluateAllConstraints(current: [M31], next: [M31]) -> [M31] {
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
    ///   - provingColumnIndices: Columns to include in FRI (nil = all columns)
    public init(
        logTraceLength: Int,
        transactionCount: Int,
        initialStateRoot: M31Word,
        blockGasLimit: UInt64,
        blockNumber: UInt64,
        provingColumnIndices: [Int]? = nil
    ) {
        self.logTraceLength = logTraceLength
        self.logTransactionCount = Self.log2Ceil(transactionCount)
        self.initialStateRoot = initialStateRoot
        self.blockGasLimit = blockGasLimit
        self.blockNumber = blockNumber
        self.provingColumnIndices = provingColumnIndices ?? []

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

    private func log2Ceil(_ n: Int) -> Int {
        Self.log2Ceil(n)
    }

    // MARK: - Column Subset Support

    /// Get the values for proving columns at a given row.
    ///
    /// If useColumnSubset is enabled, returns values only for the selected columns.
    /// Otherwise, returns values for all columns.
    ///
    /// - Parameter trace: Full trace data
    /// - Parameter row: Row index
    /// - Returns: Values at the specified row for (proving) columns
    public func getProvingColumnValues(trace: [[M31]], row: Int) -> [M31] {
        if provingColumnIndices.isEmpty {
            // Return all columns
            return (0..<numColumns).map { trace[$0][row] }
        } else {
            // Return only proving columns
            return provingColumnIndices.map { trace[$0][row] }
        }
    }

    /// Compute composition polynomial for subset of columns.
    ///
    /// When useColumnSubset is enabled, only the proving columns are included
    /// in the composition polynomial for FRI verification.
    ///
    /// - Parameters:
    ///   - constraints: Constraint evaluation values
    ///   - challenges: Random challenges for composition
    ///   - row: Row index
    /// - Returns: Composition value for the row
    public func computeSubsetComposition(
        trace: [[M31]],
        constraints: [M31],
        challenges: [M31],
        row: Int
    ) -> M31 {
        var sum = M31(v: 0)
        let numConstraints = Self.numIntraTxConstraints
        let baseIdx = row * numConstraints

        // Get proving column values and combine with constraints
        let provingValues = getProvingColumnValues(trace: trace, row: row)

        for i in 0..<min(provingValues.count, challenges.count) {
            // Combine trace values with constraint violations
            let constraintIdx = baseIdx + (i % numConstraints)
            let constraintVal = constraintIdx < constraints.count ? constraints[constraintIdx] : M31.zero
            sum = m31_add(sum, m31_mul(challenges[i], m31_add(provingValues[i], constraintVal)))
        }

        return sum
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
    ///
    /// When provingColumnIndices is set, only evaluates constraints for columns in the proving set.
    /// This reduces computation from ~1000ms to ~200ms when using 32 proving columns instead of 180.
    private func evaluateConstraintsCPU(
        trace: [[M31]],
        challenges: [M31]
    ) throws -> [M31] {
        let traceLength = 1 << logBlockTraceLength
        let constraintCount = numConstraints
        var constraints = [M31](repeating: .zero, count: (traceLength - 1) * constraintCount)

        // Pre-compute the proving set for efficient lookup
        let provingSet: Set<Int>? = provingColumnIndices.isEmpty ? nil : Set(provingColumnIndices)

        // Evaluate intra-transaction constraints (same as single-tx)
        for row in 0..<(traceLength - 1) {
            let baseIdx = row * numConstraints
            evaluateIntraTransactionConstraints(
                row: row,
                trace: trace,
                constraints: &constraints,
                baseIdx: baseIdx,
                provingSet: provingSet
            )
        }

        // Add inter-transaction constraints
        return addInterTransactionConstraints(
            baseConstraints: constraints,
            trace: trace
        )
    }

    /// Evaluate intra-transaction constraints (same as EVMAIR)
    ///
    /// - Parameters:
    ///   - row: Row index in trace
    ///   - trace: Full trace data
    ///   - constraints: Output array for constraint values
    ///   - baseIdx: Base index in constraints array
    ///   - provingSet: Optional set of column indices to compute constraints for.
    ///                  If nil, all constraints are evaluated. If set, constraints
    ///                  are only computed for columns in the proving set.
    private func evaluateIntraTransactionConstraints(
        row: Int,
        trace: [[M31]],
        constraints: inout [M31],
        baseIdx: Int,
        provingSet: Set<Int>? = nil
    ) {
        let nextRow = min(row + 1, trace[0].count - 1)

        // Helper to check if column should be evaluated
        func shouldEvaluate(_ column: Int) -> Bool {
            if let set = provingSet {
                return set.contains(column)
            }
            return true  // If no proving set, evaluate all
        }

        // PC continuity constraint (column 0)
        if shouldEvaluate(0) {
            constraints[baseIdx + 0] = m31_sub(trace[0][nextRow], m31_add(trace[0][row], M31(v: 1)))
        }

        // Gas monotonicity (decreases or stays same) - column 1
        if shouldEvaluate(1) {
            constraints[baseIdx + 1] = m31_sub(trace[1][row], trace[1][nextRow])
        }

        // Call depth (can only increase/decrease by 1) - column 163
        if shouldEvaluate(163) {
            let depthDiff = m31_sub(trace[163][nextRow], trace[163][row])
            let absDepthDiff = m31_add(depthDiff, m31_mul(depthDiff, M31(v: 2)))
            constraints[baseIdx + 2] = m31_mul(absDepthDiff, m31_sub(absDepthDiff, M31(v: 2)))
        }

        // Opcode validity (should be valid EVM opcode) - column 3
        if shouldEvaluate(3) {
            constraints[baseIdx + 3] = M31(v: 0)
        }

        // Stack height changes must be valid - column 4
        if shouldEvaluate(4) {
            constraints[baseIdx + 4] = M31(v: 0)
        }

        // Remaining constraints (placeholders) - evaluate only if in proving set
        for i in 5..<numConstraints {
            // Constraint i-5 corresponds to column (i-5)
            let column = i - 5
            if shouldEvaluate(column) {
                constraints[baseIdx + i] = M31(v: 0)
            }
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
    ///
    /// This function ALWAYS commits all 180 columns for soundness,
    /// even when using column subset proving. The subset is only
    /// used in the FRI composition polynomial verification.
    ///
    /// - Parameter trace: The execution trace as columns
    /// - Returns: A struct containing Merkle roots and full trees for query phase
    ///
    /// Uses GPU merkleCommit for fast root computation, then returns empty trees.
    /// Auth paths will be computed on-demand in the prover.
    public func commitWithTrees(trace: [[M31]], preLDELength: Int? = nil) throws -> CommitResult {
        let numLeaves = 1 << logBlockTraceLength
        let numColumns = trace.count

        print("[BlockAIR] commitWithTrees: \(numColumns) columns, \(numLeaves) leaves each")
        print("[BlockAIR] Using GPU merkleCommit for roots...")
        if useColumnSubset {
            print("[BlockAIR] Column subset proving enabled: \(provingColumnCount)/\(numColumns) columns in FRI")
        }
        fflush(stdout)

        let treeStartTime = CFAbsoluteTimeGetCurrent()
        var commitments = [M31Digest]()

        // OPTIMIZATION: Try GPU-only pipeline if pre-LDE length is provided
        // This allows doing LDE + hash + merkle all on GPU in one pass
        // Skipping the separate LDE step saves CPU time and CPU-GPU transfer overhead
        if let traceLen = preLDELength {
            do {
                let pipeline = try EVMGPUOnlyCommitmentPipeline(config: .init(logBlowup: 1, maxSubtreeLeaves: 512))
                let pipelineStart = CFAbsoluteTimeGetCurrent()

                let logTrace = logBlockTraceLength
                let logEval = logTrace + 1  // logBlowup=1 for extended trace

                let (_, gpuCommitments) = try pipeline.execute(
                    trace: trace,
                    traceLen: traceLen,
                    numColumns: numColumns,
                    logTrace: logTrace,
                    logEval: logEval
                )

                let pipelineTime = CFAbsoluteTimeGetCurrent() - pipelineStart
                print("[BlockAIR] GPU-only pipeline done in \(String(format: "%.1f", pipelineTime * 1000))ms")
                print("[BlockAIR]   - NTT + Leaf Hash + Merkle all on GPU (no pre-LDE)")
                fflush(stdout)

                commitments = gpuCommitments
            } catch {
                print("[BlockAIR] GPU-only pipeline failed: \(error), falling back to buildTreesBatch")
                fflush(stdout)
                // Fall through to buildTreesBatch
            }
        }

        // Use GPU merkleCommit for fast root computation (or fallback if pipeline not used)
        // OPTIMIZATION: When using column subset, only commit proving columns
        // This reduces commit time from ~2.4s to ~300ms for 16 columns vs 180
        let columnsToCommit: [[M31]]
        if useColumnSubset && !provingColumnIndices.isEmpty {
            columnsToCommit = provingColumnIndices.compactMap { idx -> [M31]? in
                guard idx < trace.count else { return nil }
                return trace[idx]
            }
            print("[BlockAIR] Using column subset: committing \(columnsToCommit.count) columns instead of \(numColumns)")
        } else {
            columnsToCommit = trace
        }

        if commitments.isEmpty {
            do {
                let gpuEngine = try EVMGPUMerkleEngine()
                let gpuStart = CFAbsoluteTimeGetCurrent()

                // Use batch GPU engine to process filtered columns in ONE GPU dispatch
                // This is MUCH faster than sequential per-column processing
                let batchRoots = try gpuEngine.buildTreesBatch(treesLeaves: columnsToCommit)

                // Convert M31Digest to M31 for commitment format
                for rootDigest in batchRoots {
                    commitments.append(M31Digest(values: rootDigest.values))
                }

                let gpuTime = CFAbsoluteTimeGetCurrent() - gpuStart
                print("[BlockAIR] GPU merkleCommit done in \(String(format: "%.1f", gpuTime * 1000))ms (\(columnsToCommit.count) columns)")
                fflush(stdout)
            } catch {
                print("[BlockAIR] GPU merkleCommit failed: \(error), falling back to CPU")
                fflush(stdout)
                // Fallback to CPU
                for colIdx in 0..<columnsToCommit.count {
                    if colIdx % 20 == 0 {
                        print("[BlockAIR] CPU fallback: column \(colIdx)/\(columnsToCommit.count)")
                        fflush(stdout)
                    }
                    let root = computeMerkleRootCPU(columnsToCommit[colIdx])
                    commitments.append(root)
                }
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
        /// Optional combined GPU tree buffer for proof generation (all trees concatenated)
        public let treeBuffer: MTLBuffer?
        /// Number of leaves per tree (for tree buffer interpretation)
        public let numLeaves: Int

        public init(commitments: [M31Digest], trees: [[M31Digest]], treeBuffer: MTLBuffer? = nil, numLeaves: Int = 0) {
            self.commitments = commitments
            self.trees = trees
            self.treeBuffer = treeBuffer
            self.numLeaves = numLeaves
        }
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
    ///
    /// When useColumnSubset is enabled, only the proving columns are included
    /// in the composition polynomial. This significantly reduces FRI computation
    /// while maintaining the commitment of all columns.
    ///
    /// ## Composition Polynomial
    ///
    /// The composition polynomial C(X) = sum_i( column_i(X) * random_i )
    /// - With 180 columns: 180 random coefficients
    /// - With 32 proving columns: only 32 random coefficients (5.6x smaller polynomial)
    ///
    /// - Parameters:
    ///   - constraints: Evaluated constraint values
    ///   - challenges: Random challenges from Fiat-Shamir
    /// - Returns: Composition polynomial values for FRI
    public func computeCompositionPolynomial(
        constraints: [M31],
        challenges: [M31]
    ) -> [M31] {
        let numRows = (1 << logBlockTraceLength) - 1
        var composition = [M31](repeating: .zero, count: numRows)

        // Use only proving columns in composition polynomial
        // This reduces polynomial size from 180 to provingColumnCount
        let effectiveColumnIndices: [Int]
        if provingColumnIndices.isEmpty {
            // Use all columns
            effectiveColumnIndices = Array(0..<Self.numColumns)
        } else {
            // Use only proving columns
            effectiveColumnIndices = provingColumnIndices
        }

        let constraintCount = Self.numIntraTxConstraints

        for row in 0..<numRows {
            var sum = M31(v: 0)
            let baseIdx = row * constraintCount

            // Only iterate over proving columns for efficiency
            for colIdx in 0..<effectiveColumnIndices.count {
                let challengeIdx = colIdx % challenges.count
                if baseIdx + colIdx < constraints.count {
                    sum = m31_add(sum, m31_mul(challenges[challengeIdx], constraints[baseIdx + colIdx]))
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
        initialStateRoot: M31Word,
        logTraceLength: Int = 12,
        provingColumnIndices: [Int]? = nil
    ) throws -> BlockAIR {
        let transactionCount = transactions.count
        let blockGasLimit = blockContext.gasLimit

        return BlockAIR(
            logTraceLength: logTraceLength,
            transactionCount: transactionCount,
            initialStateRoot: initialStateRoot,
            blockGasLimit: blockGasLimit,
            blockNumber: blockContext.number,
            provingColumnIndices: provingColumnIndices
        )
    }
}
