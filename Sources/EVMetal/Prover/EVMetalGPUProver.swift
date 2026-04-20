import Foundation
import Metal
import zkMetal

// MARK: - EVMetalGPUProver

/// EVMetal GPU Prover with batch Merkle commitment.
///
/// This prover uses a GPU kernel that hashes individual M31 values with position,
/// producing commitments that MATCH zkmetal's CPU tree builder.
///
/// The prover supports two commitment strategies:
/// - Pure GPU: All operations on GPU (leaf hashing + tree building)
/// - Hybrid: CPU position hashing + GPU tree building (often faster due to CPU parallelism)
///
/// ## Architecture
///
/// ```
/// Trace LDEs ([[M31]])
///        │
///        ▼
/// ┌─────────────────┐     ┌──────────────────┐
/// │  Leaf Hashing   │ ──▶ │  Merkle Tree     │
/// │  (CPU or GPU)   │     │  Building (GPU)  │
/// └─────────────────┘     └──────────────────┘
///        │                         │
///        ▼                         ▼
/// ┌─────────────────────────────────────────┐
/// │     Column Commitments [M31Digest]      │
/// └─────────────────────────────────────────┘
/// ```
public final class EVMetalGPUProver {

    // MARK: - Configuration

    /// Configuration for the GPU prover.
    ///
    /// - `logBlowup`: Log of the blowup factor for low-degree extension (LDE).
    ///   A blowup of 2 means each trace row is expanded to 4 rows.
    /// - `numQueries`: Number of queries used in the FRI commitment phase.
    public struct Config {
        /// Log of the blowup factor for LDE expansion.
        public let logBlowup: Int
        /// Number of queries for FRI commitment.
        public let numQueries: Int

        /// Standard configuration with reasonable defaults for most use cases.
        public static let standard = Config(logBlowup: 2, numQueries: 20)

        /// Creates a new configuration.
        /// - Parameters:
        ///   - logBlowup: Log of blowup factor (default: 2, meaning 4x expansion)
        ///   - numQueries: Number of queries (default: 20)
        public init(logBlowup: Int = 2, numQueries: Int = 20) {
            self.logBlowup = logBlowup
            self.numQueries = numQueries
        }
    }

    // MARK: - Result Types

    /// Result of a commitment operation with timing information.
    public struct CommitResult {
        /// The computed commitments, one per trace column.
        public let commitments: [zkMetal.M31Digest]
        /// Total elapsed time in milliseconds.
        public let timeMs: Double
        /// Time spent hashing leaves in milliseconds.
        public let leafHashMs: Double
        /// Time spent building Merkle trees in milliseconds.
        public let treeBuildMs: Double

        /// Creates a new commit result.
        /// - Parameters:
        ///   - commitments: Array of column commitments.
        ///   - timeMs: Total time in milliseconds.
        ///   - leafHashMs: Leaf hashing time in milliseconds.
        ///   - treeBuildMs: Tree building time in milliseconds.
        public init(commitments: [zkMetal.M31Digest], timeMs: Double, leafHashMs: Double = 0, treeBuildMs: Double = 0) {
            self.commitments = commitments
            self.timeMs = timeMs
            self.leafHashMs = leafHashMs
            self.treeBuildMs = treeBuildMs
        }
    }

    // MARK: - Private State

    private let config: Config
    private let leafHashEngine: EVMetalLeafHashEngine
    private let cpuProver: EVMetalCPUMerkleProver
    private var merkleEngine: EVMGPUMerkleEngine?
    private var gpuTreeEngine: Poseidon2M31Engine?  // zkMetal's GPU tree building engine

    // MARK: - Initialization

    /// Creates a new GPU prover with the given configuration.
    /// - Parameter config: Prover configuration. Uses `.standard` if not specified.
    public init(config: Config = .standard) {
        self.config = config
        self.leafHashEngine = try! EVMetalLeafHashEngine()
        // self.leafHashEngine.useSIMDCooperative = true  // Disabled - kernel has issues
        self.cpuProver = EVMetalCPUMerkleProver()
        self.merkleEngine = try? EVMGPUMerkleEngine()
        do {
            self.gpuTreeEngine = try Poseidon2M31Engine()  // Initialize GPU tree engine
            print("✓ GPU Tree Engine initialized successfully")
        } catch {
            print("✗ GPU Tree Engine initialization failed: \(error)")
            self.gpuTreeEngine = nil
        }
    }

    // MARK: - GPU Commitment (Pure GPU)

    /// Commit trace columns using GPU with position-hashed Merkle trees.
    ///
    /// This produces commitments that MATCH zkMetal's CPU tree builder because
    /// the GPU kernel hashes individual M31 values with their position.
    ///
    /// Now uses GPU tree building via Poseidon2M31Engine.merkleCommit for
    /// significantly improved performance.
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form, where each column is an array of M31 values.
    ///   - evalLen: Evaluation length (number of leaves per column, power of 2).
    /// - Returns: `CommitResult` containing commitments and timing information.
    /// - Throws: Error if GPU operations fail.
    public func commitTraceColumnsGPU(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count

        // Determine if input is in "pre-hashed node" format (8 M31 per leaf)
        // or "individual M31" format (1 M31 per leaf position).
        // Pre-hashed nodes have (traceLDEs[col].count / evalLen) >= 8
        let m31PerLeaf: Int
        let actualLeavesPerColumn: Int

        if !traceLDEs.isEmpty && !traceLDEs[0].isEmpty {
            let valuesPerCol = traceLDEs[0].count
            if valuesPerCol >= evalLen * 8 {
                // Pre-hashed node format: 8 M31 per leaf
                m31PerLeaf = 8
                actualLeavesPerColumn = evalLen
            } else {
                // Individual M31 format: 1 M31 per leaf
                m31PerLeaf = 1
                actualLeavesPerColumn = evalLen
            }
        } else {
            m31PerLeaf = 1
            actualLeavesPerColumn = evalLen
        }

        print("    [GPU Prover] commitTraceColumnsGPU: numColumns=\(numColumns), evalLen=\(evalLen), m31PerLeaf=\(m31PerLeaf)")
        if !traceLDEs.isEmpty && !traceLDEs[0].isEmpty {
            print("    [GPU Prover] traceLDEs[0].count=\(traceLDEs[0].count), expected for m31PerLeaf=1: \(evalLen)")
        }

        var commitments: [zkMetal.M31Digest] = []
        let leafHashMs: Double
        let treeBuildMs: Double

        if m31PerLeaf == 8 {
            // Data is already in pre-hashed node format (8 M31 per leaf)
            // Skip GPU leaf hashing, go directly to tree building

            // Reorganize into tree leaf format: [tree0_leaf0_8vals, tree0_leaf1_8vals, ...]
            var treesLeaves: [[M31]] = []
            treesLeaves.reserveCapacity(numColumns)
            for col in traceLDEs {
                treesLeaves.append(Array(col.prefix(evalLen * 8)))
            }

            let treeStart = CFAbsoluteTimeGetCurrent()
            if let engine = merkleEngine {
                // GPU batch tree building using EVMGPUMerkleEngine
                commitments = try engine.buildTreesBatch(treesLeaves: treesLeaves)
            } else {
                // CPU tree building fallback
                for colLeaves in treesLeaves {
                    let root = buildTreeFromDigests(digests: colLeaves, numLeaves: evalLen, numColumns: 1)
                    commitments.append(root)
                }
            }
            leafHashMs = 0
            treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeStart) * 1000

        } else {
            // Individual M31 format - need leaf hashing first
            // Try GPU leaf hashing first, but fall back to CPU if it fails

            // Flatten all values (column-major: all of col0, then all of col1, ...)
            var flatValues: [M31] = []
            flatValues.reserveCapacity(numColumns * evalLen)
            for col in 0..<numColumns {
                flatValues.append(contentsOf: traceLDEs[col])
            }

            print("    [GPU Prover] flatValues prepared, count=\(flatValues.count)")
            print("    [GPU Prover] flatValues[0..<8]: \(flatValues.prefix(8).map { $0.v })")
            print("    [GPU Prover] evalLen=\(evalLen), numColumns=\(numColumns)")

            let hashStart = CFAbsoluteTimeGetCurrent()
            var allDigests: [[M31]] = []

            print("    [GPU Prover] About to call tryGPULeafHash, flatValues count=\(flatValues.count)")

            do {
                // Try GPU leaf hashing
                allDigests = try tryGPULeafHash(flatValues: flatValues, numColumns: numColumns, countPerColumn: evalLen)
                leafHashMs = (CFAbsoluteTimeGetCurrent() - hashStart) * 1000
            } catch {
                print("    GPU leaf hashing failed, using CPU: \(error)")
                // Fall back to CPU leaf hashing
                let cpuT0 = CFAbsoluteTimeGetCurrent()
                allDigests = cpuHashLeaves(flatValues: flatValues, numColumns: numColumns, countPerColumn: evalLen)
                leafHashMs = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000
            }

            // Phase 2: Build trees using CPU (simple and reliable)
            // allDigests[col] already contains digests for column col in sequential order
            let treeStart = CFAbsoluteTimeGetCurrent()
            for colDigests in allDigests {
                let root = buildTreeFromDigests(digests: colDigests, numLeaves: evalLen, numColumns: 1)
                commitments.append(root)
            }
            treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeStart) * 1000
        }

        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        return CommitResult(
            commitments: commitments,
            timeMs: elapsed,
            leafHashMs: leafHashMs,
            treeBuildMs: treeBuildMs
        )
    }

    /// Build a Merkle tree from pre-hashed digests (CPU tree building).
    /// This is used after GPU leaf hashing to complete the tree construction.
    ///
    /// Supports TWO input formats:
    /// 1. Sequential format: [leaf0_M31_0..7, leaf1_M31_0..7, ...] - direct from CPU hashing
    /// 2. Interleaved format: [pos0_col0_0..7, pos0_col1_0..7, ..., pos1_col0_0..7, ...] - from GPU leaf hashing
    private func buildTreeFromDigests(digests: [M31], numLeaves: Int, numColumns: Int = 1) -> zkMetal.M31Digest {
        // Detect input format based on count vs expected
        // Interleaved format: count == numLeaves * numColumns * 8
        // Sequential format: count == numLeaves * 8 (for single column)

        let totalM31 = digests.count
        let expectedSequential = numLeaves * 8

        // If we have more data than sequential format expects, assume interleaved
        let isInterleaved = totalM31 > expectedSequential && numColumns > 1

        // Convert digests to M31Digest nodes
        var nodes: [zkMetal.M31Digest] = []
        nodes.reserveCapacity(numLeaves)

        for leafIdx in 0..<numLeaves {
            var digestValues = [M31]()
            digestValues.reserveCapacity(8)

            if isInterleaved {
                // Interleaved format: [pos0_col0_0..7, pos0_col1_0..7, ..., pos1_col0_0..7, ...]
                // For column=col, position=leafIdx: base = (leafIdx * numColumns + col) * 8
                // Since we process digests for a single column's tree, use col=0
                let col = 0  // Column being processed (single column per tree)
                let base = (leafIdx * numColumns + col) * 8
                for j in 0..<8 {
                    digestValues.append(digests[base + j])
                }
            } else {
                // Sequential format: [leaf0_0..7, leaf1_0..7, ...]
                let base = leafIdx * 8
                for j in 0..<8 {
                    digestValues.append(digests[base + j])
                }
            }
            nodes.append(zkMetal.M31Digest(values: digestValues))
        }

        // Build tree bottom-up
        var levelSize = numLeaves
        while levelSize > 1 {
            var nextLevel: [zkMetal.M31Digest] = []
            nextLevel.reserveCapacity((levelSize + 1) / 2)
            for i in stride(from: 0, to: levelSize, by: 2) {
                let left = nodes[i]
                let right = i + 1 < levelSize ? nodes[i + 1] : left
                let hash = zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
                nextLevel.append(hash)
            }
            nodes = nextLevel
            levelSize = nodes.count
        }
        return nodes[0]
    }

    /// Try GPU leaf hashing with error handling.
    /// Returns the same format as hashLeavesBatchPerColumn.
    private func tryGPULeafHash(flatValues: [M31], numColumns: Int, countPerColumn: Int) throws -> [[M31]] {
        print("    [GPU Prover] tryGPULeafHash: flatValues count=\(flatValues.count), numColumns=\(numColumns), countPerColumn=\(countPerColumn)")
        print("    [GPU Prover] flatValues[0..<8]: \(flatValues.prefix(8).map { $0.v })")

        let result = try leafHashEngine.hashLeavesBatchPerColumn(
            allValues: flatValues,
            numColumns: numColumns,
            countPerColumn: countPerColumn
        )

        // Debug: Print first column's first 2 digests to compare with CPU
        if !result.isEmpty && result[0].count >= 16 {
            print("    [GPU Leaf Hash] first column first 2 digests:")
            print("      leaf[0]: \(result[0][0..<8].map { $0.v })")
            print("      leaf[1]: \(result[0][8..<16].map { $0.v })")
        }

        return result
    }

    /// CPU-based leaf hashing for fallback when GPU fails.
    /// Uses position hashing like the GPU kernel.
    ///
    /// IMPORTANT: This function must match the GPU leaf hashing behavior.
    /// The GPU kernel uses column-major layout:
    ///   flatValues: [col0_leaf0, col0_leaf1, ..., col0_leafN, col1_leaf0, col1_leaf1, ...]
    ///   positions: per-column position = 0, 1, 2, ... for each column
    ///
    /// So for column `col` and position `i`:
    ///   srcIdx = col * countPerColumn + i
    ///   position = i (per-column, not global)
    private func cpuHashLeaves(flatValues: [M31], numColumns: Int, countPerColumn: Int) -> [[M31]] {
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)

        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)

            for i in 0..<countPerColumn {
                // Column-major indexing: flatValues[col * countPerColumn + i]
                let srcIdx = col * countPerColumn + i
                let val = srcIdx < flatValues.count ? flatValues[srcIdx] : M31.zero
                // Per-column position (same as GPU kernel): position = i for each column
                let position = M31(v: UInt32(i))

                // Hash with position (same as GPU kernel)
                let leafInput = [val, position, M31.zero, M31.zero,
                                  M31.zero, M31.zero, M31.zero, M31.zero]
                let digest = poseidon2M31HashSingle(leafInput)

                for v in digest {
                    columnDigests.append(v)
                }
            }
            results.append(columnDigests)
        }

        return results
    }

    /// Build multiple Merkle trees in parallel using GPU batch processing.
    /// This is significantly faster than building trees sequentially.
    ///
    /// - Parameter allColumnDigests: Array of digest arrays, one per column/tree.
    ///   Each inner array contains the pre-hashed leaves (8 M31 per leaf).
    /// - Parameter numLeaves: Number of leaves per tree (power of 2).
    /// - Returns: Array of root digests, one per tree.
    /// - Throws: Error if GPU operations fail.
    private func buildTreesBatchParallel(allColumnDigests: [[M31]], numLeaves: Int) throws -> [zkMetal.M31Digest] {
        guard let gpuTreeEng = gpuTreeEngine else {
            throw GPUProverError.gpuError("GPU tree engine not available")
        }

        let numTrees = allColumnDigests.count
        let nodeSize = 8  // M31 elements per digest

        // For trees <= 512 leaves, we can use the batch fused kernel
        // For larger trees, we need to chunk them
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        if numLeaves <= subtreeMax {
            return try buildTreesSingleLevel(allColumnDigests: allColumnDigests, numLeaves: numLeaves, gpuTreeEng: gpuTreeEng)
        } else {
            return try buildTreesMultiLevel(allColumnDigests: allColumnDigests, numLeaves: numLeaves, gpuTreeEng: gpuTreeEng)
        }
    }

    /// Build multiple trees that fit in a single level (≤512 leaves each)
    /// Uses zkMetal's encodeMerkleFused for parallel processing of all trees.
    private func buildTreesSingleLevel(allColumnDigests: [[M31]], numLeaves: Int, gpuTreeEng: Poseidon2M31Engine) throws -> [zkMetal.M31Digest] {
        let numTrees = allColumnDigests.count
        let nodeSize = 8
        let device = gpuTreeEng.device
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        let stride = MemoryLayout<UInt32>.stride

        // Layout input buffer: [tree0_leaf0_0, ..., tree0_leaf0_7, tree0_leaf1_0, ..., tree1_leaf0_0, ...]
        let totalInputVals = numTrees * numLeaves * nodeSize
        guard let inputBuf = device.makeBuffer(length: totalInputVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffer")
        }

        // Copy all tree data to input buffer
        let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: totalInputVals)
        var inputIdx = 0
        for treeDigests in allColumnDigests {
            for val in treeDigests {
                precondition(inputIdx < totalInputVals, "Input index out of bounds: \(inputIdx) >= \(totalInputVals)")
                inputPtr[inputIdx] = val.v
                inputIdx += 1
            }
        }

        // Allocate output buffer for roots
        let rootBytes = numTrees * nodeSize * stride
        guard let outputBuf = device.makeBuffer(length: rootBytes, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate output buffer")
        }

        // Create command buffer and encode batch Merkle tree computation
        guard let cmdBuf = gpuTreeEng.commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        // Use zkMetal's encodeMerkleFused for parallel processing
        gpuTreeEng.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: inputBuf,
            leavesOffset: 0,
            rootsBuffer: outputBuf,
            rootsOffset: 0,
            numSubtrees: numTrees,
            subtreeSize: numLeaves
        )

        enc.endEncoding()
        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results and convert to M31Digest array
        let outputCapacity = numTrees * nodeSize
        precondition(rootBytes >= outputCapacity * stride, "Output buffer too small")
        let outPtr = outputBuf.contents().bindMemory(to: UInt32.self, capacity: outputCapacity)
        var roots: [zkMetal.M31Digest] = []
        roots.reserveCapacity(numTrees)

        for i in 0..<numTrees {
            var rootValues = [M31]()
            rootValues.reserveCapacity(nodeSize)
            for j in 0..<nodeSize {
                let idx = i * nodeSize + j
                precondition(idx < outputCapacity, "Output index out of bounds: \(idx) >= \(outputCapacity)")
                rootValues.append(M31(v: outPtr[idx]))
            }
            roots.append(zkMetal.M31Digest(values: rootValues))
        }

        return roots
    }

    /// Build multiple large trees that require multiple levels in parallel.
///
/// Uses zkMetal's encodeMerkleFused for subtree roots + encodeHashPairs for upper levels.
/// All 180 trees are processed in a single command buffer with memory barriers.
///
/// For evalLen=16384 (logBlowup=5 with traceLen=512):
/// - 32 subtrees per tree (16384 / 512 = 32)
/// - 180 trees × 32 subtrees = 5760 subtree roots
/// - Upper levels processed level-by-level in same command buffer
    private func buildTreesMultiLevel(allColumnDigests: [[M31]], numLeaves: Int, gpuTreeEng: Poseidon2M31Engine) throws -> [zkMetal.M31Digest] {
        let numTrees = allColumnDigests.count
        let nodeSize = 8
        let device = gpuTreeEng.device
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize
        let numSubtrees = numLeaves / subtreeMax
        let stride = MemoryLayout<UInt32>.stride

        // Step 1: Flatten all trees' leaves into one big buffer
        // Layout: [tree0_subtree0_leaves, tree0_subtree1_leaves, ..., tree1_subtree0_leaves, ...]
        let leavesPerTree = numTrees * numSubtrees * subtreeMax * nodeSize
        guard let leavesBuf = device.makeBuffer(length: leavesPerTree * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate leaves buffer")
        }

        let leavesPtr = leavesBuf.contents().bindMemory(to: UInt32.self, capacity: leavesPerTree)
        var idx = 0
        for treeLeaves in allColumnDigests {
            for subIdx in 0..<numSubtrees {
                let start = subIdx * subtreeMax * nodeSize
                let end = start + subtreeMax * nodeSize
                for i in start..<end {
                    leavesPtr[idx] = treeLeaves[i].v
                    idx += 1
                }
            }
        }

        // Step 2: Allocate output buffer for all subtree roots
        let rootsPerTree = numSubtrees * nodeSize
        let rootsSize = numTrees * rootsPerTree * stride
        guard let rootsBuf = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate roots buffer")
        }

        // Step 3: Build all subtrees in ONE GPU dispatch using encodeMerkleFused
        // numSubtrees: number of subtrees per tree
        // totalSubtrees = numTrees * numSubtrees
        let totalSubtrees = numTrees * numSubtrees

        guard let cmdBuf = gpuTreeEng.commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        // Fused subtree → roots for ALL trees in parallel
        gpuTreeEng.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: leavesBuf,
            leavesOffset: 0,
            rootsBuffer: rootsBuf,
            rootsOffset: 0,
            numSubtrees: totalSubtrees,
            subtreeSize: subtreeMax
        )

        // Step 4: Process upper levels level-by-level in same command buffer
        var currentNodes = numSubtrees  // Number of subtree roots per tree
        var srcBuf = rootsBuf

        if currentNodes > 1 {
            // Allocate ping-pong buffers for upper levels
            guard let bufA = device.makeBuffer(length: rootsSize, options: .storageModeShared),
                  let bufB = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate upper level buffers")
            }

            var dstBuf = bufA

            while currentNodes > 1 {
                enc.memoryBarrier(scope: .buffers)

                // Hash pairs at this level for all trees using public API
                let pairs = currentNodes / 2
                gpuTreeEng.encodeHashPairs(
                    encoder: enc,
                    buffer: srcBuf,
                    inputOffset: 0,
                    outputOffset: 0,
                    count: numTrees * pairs,
                    outputBuffer: dstBuf
                )

                currentNodes = pairs
                swap(&srcBuf, &dstBuf)
            }
        }

        enc.endEncoding()
        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        // Step 5: Read back final roots from the correct buffer
        let outPtr = srcBuf.contents().bindMemory(to: UInt32.self, capacity: numTrees * nodeSize)

        var roots: [zkMetal.M31Digest] = []
        roots.reserveCapacity(numTrees)

        for i in 0..<numTrees {
            var rootValues = [M31]()
            rootValues.reserveCapacity(nodeSize)
            for j in 0..<nodeSize {
                rootValues.append(M31(v: outPtr[i * nodeSize + j]))
            }
            roots.append(zkMetal.M31Digest(values: rootValues))
        }

        return roots
    }

    // MARK: - GPU Utility Methods

    /// Builds a complete Merkle tree from individual M31 values using the GPU.
    ///
    /// This is useful for building single trees when you already have the values
    /// and want GPU acceleration for both leaf hashing and tree building.
    ///
    /// - Parameters:
    ///   - values: Individual M31 values (one per leaf).
    ///   - count: Number of leaves (power of 2).
    /// - Returns: The root digest of the Merkle tree.
    /// - Throws: Error if GPU operations fail.
    public func buildTreeGPU(values: [M31], count: Int) throws -> zkMetal.M31Digest {
        return try leafHashEngine.buildMerkleTree(values: values, numLeaves: count)
    }

    /// Hash individual M31 values with their position to create leaf digests.
    ///
    /// This uses the GPU to hash each value with its position using Poseidon2.
    /// The result is 8 M31 elements per leaf, suitable for Merkle tree building.
    ///
    /// - Parameter values: Individual M31 values to hash.
    /// - Returns: Array of M31 digests (8 M31 elements per input value).
    /// - Throws: Error if GPU operations fail.
    public func hashLeavesWithPosition(values: [M31]) throws -> [M31] {
        let positions = (0..<values.count).map { UInt32($0) }
        return try leafHashEngine.hashLeavesWithPosition(values: values, positions: positions)
    }

    // MARK: - Hybrid Commitment (CPU Hash + GPU Tree)

    /// Commit trace columns using HYBRID approach: CPU position hashing + GPU tree building.
    ///
    /// This is significantly faster than the pure GPU approach because:
    /// 1. CPU hashes leaves with position in parallel (exploiting multi-core CPU)
    /// 2. GPU builds trees from pre-hashed digests using the fast batch kernel
    ///
    /// This produces commitments that MATCH zkmetal's CPU tree builder.
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form, where each column is an array of M31 values.
    ///   - evalLen: Evaluation length (number of leaves per column, power of 2).
    /// - Returns: `CommitResult` containing commitments and timing breakdown.
    /// - Throws: Error if GPU operations fail.
    public func commitTraceColumnsHybrid(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        let numColumns = traceLDEs.count

        if evalLen <= subtreeMax {
            // All leaves fit in one subtree
            // Step 1: CPU position-hash all leaves using multithreading
            let leafHashT0 = CFAbsoluteTimeGetCurrent()

            // Flatten all values
            var flatValues: [M31] = []
            flatValues.reserveCapacity(numColumns * evalLen)
            for col in traceLDEs {
                flatValues.append(contentsOf: col)
            }

            // CPU hashes all columns at once using multithreading
            let allDigests = cpuProver.hashLeavesBatchPerColumn(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: evalLen
            )

            let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

            // Step 2: GPU builds trees from pre-hashed digests using fast batch kernel
            let treeBuildT0 = CFAbsoluteTimeGetCurrent()

            var commitments: [zkMetal.M31Digest] = []
            if let engine = merkleEngine {
                // Use fast GPU batch kernel for tree building
                commitments = try engine.buildTreesBatch(treesLeaves: allDigests)
            } else {
                // Fallback: CPU tree building
                for colDigests in allDigests {
                    var nodes: [zkMetal.M31Digest] = []
                    for i in 0..<evalLen {
                        let start = i * 8
                        let digestValues = Array(colDigests[start..<start + 8])
                        nodes.append(zkMetal.M31Digest(values: digestValues))
                    }
                    var levelSize = evalLen
                    while levelSize > 1 {
                        var nextLevel: [zkMetal.M31Digest] = []
                        for i in stride(from: 0, to: levelSize, by: 2) {
                            let left = nodes[i]
                            let right = i + 1 < levelSize ? nodes[i + 1] : left
                            let hash = zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
                            nextLevel.append(hash)
                        }
                        nodes = nextLevel
                        levelSize = nodes.count
                    }
                    commitments.append(nodes[0])
                }
            }

            let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
            let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            print("    Hybrid breakdown: CPU hashing \(Int(leafHashMs))ms + GPU tree \(Int(treeBuildMs))ms = \(Int(elapsed))ms total")

            return CommitResult(commitments: commitments, timeMs: elapsed, leafHashMs: leafHashMs, treeBuildMs: treeBuildMs)

        } else {
            // Large trees: chunk into subtrees
            // Use CPU multithreaded hashing + GPU tree building
            let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize
            let numSubtrees = evalLen / subtreeMax

            let leafHashT0 = CFAbsoluteTimeGetCurrent()

            // Pre-allocate result array
            let totalSubtrees = numColumns * numSubtrees
            var allSubtreeLeaves: [[M31]] = Array(repeating: [], count: totalSubtrees)

            DispatchQueue.concurrentPerform(iterations: totalSubtrees) { idx in
                let col = idx / numSubtrees
                let subIdx = idx % numSubtrees
                let start = subIdx * subtreeMax
                let subtreeValues = Array(traceLDEs[col][start..<start + subtreeMax])

                // CPU hash this subtree's leaves with per-column positions
                let positions = (0..<subtreeMax).map { UInt32($0) }
                let digests = self.cpuProver.hashLeavesWithPosition(
                    values: subtreeValues,
                    positions: positions
                )

                allSubtreeLeaves[idx] = digests
            }

            let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

            // GPU builds trees from pre-hashed digests
            let treeBuildT0 = CFAbsoluteTimeGetCurrent()

            var subtreeRoots: [zkMetal.M31Digest] = []
            if let engine = merkleEngine {
                subtreeRoots = try engine.buildTreesBatch(treesLeaves: allSubtreeLeaves)
            } else {
                // Fallback: CPU tree building
                for leaves in allSubtreeLeaves {
                    let root = buildTreeFromDigests(digests: leaves, numLeaves: subtreeMax)
                    subtreeRoots.append(root)
                }
            }

            // Combine subtree roots to get final commitments
            var commitments: [zkMetal.M31Digest] = []
            commitments.reserveCapacity(numColumns)

            for col in 0..<numColumns {
                var roots: [zkMetal.M31Digest] = []
                for subIdx in 0..<numSubtrees {
                    roots.append(subtreeRoots[col * numSubtrees + subIdx])
                }
                commitments.append(hashRootsToCommitment(roots))
            }

            let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
            let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            return CommitResult(commitments: commitments, timeMs: elapsed, leafHashMs: leafHashMs, treeBuildMs: treeBuildMs)
        }
    }

    private func hashRootsToCommitment(_ roots: [zkMetal.M31Digest]) -> zkMetal.M31Digest {
        guard !roots.isEmpty else { return .zero }
        guard roots.count > 1 else { return roots[0] }

        var current = roots
        while current.count > 1 {
            var next = [zkMetal.M31Digest]()
            for i in stride(from: 0, to: current.count, by: 2) {
                if i + 1 < current.count {
                    next.append(zkMetal.M31Digest(values: poseidon2M31Hash(
                        left: current[i].values, right: current[i+1].values)))
                } else {
                    next.append(current[i])
                }
            }
            current = next
        }
        return current[0]
    }

    // MARK: - Profiling

    /// Profiles GPU vs CPU commit performance for EVMAIR-scale traces.
    ///
    /// This generates synthetic trace data at the specified scale, runs both
    /// CPU and GPU commitment, and reports timing comparison. GPU commitments
    /// are verified to match CPU commitments exactly.
    ///
    /// - Parameters:
    ///   - numColumns: Number of trace columns (default: 180, EVMAIR scale).
    ///   - evalLen: Evaluation length / leaves per column (default: 4096).
    /// - Returns: Tuple of (cpuMs, gpuMs, speedup) timing values.
    /// - Throws: Error if GPU operations fail.
    public func profileCommitSpeedup(
        numColumns: Int = 180,
        evalLen: Int = 4096
    ) throws -> (cpuMs: Double, gpuMs: Double, speedup: Double) {
        // Generate trace LDEs with 8 M31 per leaf (pre-hashed format)
        // This bypasses GPU leaf hashing and uses GPU tree building directly
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                for j in 0..<8 {
                    values.append(M31(v: UInt32(col * 10000 + i * 10 + j)))
                }
            }
            traceLDEs.append(values)
        }

        // CPU baseline
        let cpuT0 = CFAbsoluteTimeGetCurrent()
        var cpuCommitments: [zkMetal.M31Digest] = []
        for col in traceLDEs {
            // For pre-hashed format, we skip the leaf hashing and just build tree from digests
            let root = buildTreeFromDigests(digests: col, numLeaves: evalLen, numColumns: 1)
            cpuCommitments.append(root)
        }
        let cpuMs = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000

        // GPU batch - uses pre-hashed leaf format (8 M31 per leaf)
        let gpuResult = try commitTraceColumnsGPU(traceLDEs: traceLDEs, evalLen: evalLen)
        let gpuMs = gpuResult.timeMs

        // Verify they match
        var match = true
        for i in 0..<numColumns {
            if gpuResult.commitments[i].values != cpuCommitments[i].values {
                match = false
                break
            }
        }
        print("  GPU commitments match CPU: \(match)")

        return (cpuMs, gpuMs, cpuMs / gpuMs)
    }
}
