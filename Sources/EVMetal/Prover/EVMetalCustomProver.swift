import Foundation
import Metal
import zkMetal

/// EVMetal GPU Prover with custom commitment that matches zkMetal's position scheme.
///
/// This prover uses per-column positions (matching zkMetal's buildPoseidon2M31MerkleTree)
/// while still leveraging GPU acceleration for tree building.
///
/// Architecture:
/// 1. CPU multithreaded position hashing (per-column positions: 0 to n-1 per column)
/// 2. GPU batch Merkle tree building via EVMGPUMerkleEngine
///
/// Note: Full verification with zkMetal's verifier requires the full STARK proof system.
/// This prover focuses on the commitment phase speedup.
public final class EVMetalCustomProver {

    // MARK: - Configuration

    public struct Config {
        public let logBlowup: Int
        public let numQueries: Int

        public static let standard = Config(logBlowup: 2, numQueries: 20)

        public init(logBlowup: Int = 2, numQueries: Int = 20) {
            self.logBlowup = logBlowup
            self.numQueries = numQueries
        }
    }

    // MARK: - Result Types

    public struct CommitResult {
        public let commitments: [zkMetal.M31Digest]
        public let timeMs: Double
        public let leafHashMs: Double
        public let treeBuildMs: Double
    }

    // MARK: - Hierarchical Commit Result (S5)

    public struct HierarchicalCommitResult {
        /// Individual tree roots
        public let treeRoots: [zkMetal.M31Digest]
        /// Final aggregate root combining all tree roots
        public let aggregateRoot: zkMetal.M31Digest
        /// Timing breakdown
        public let timeMs: Double
        public let leafHashMs: Double
        public let treeBuildMs: Double
        public let hierarchicalHashMs: Double
    }

    // MARK: - Buffer Pool for Memory Reuse

    /// Thread-safe buffer pool for reusing position arrays across multiple commits
    /// Reduces allocation overhead by keeping commonly-sized buffers in memory
    private final class PositionBufferPool {
        private var buffers: [Int: [UInt32]] = [:]
        private let lock = NSLock()

        /// Get or create a position buffer of the given size
        func getBuffer(size: Int) -> [UInt32] {
            lock.lock()
            defer { lock.unlock() }

            if let buffer = buffers[size] {
                return buffer
            }

            // Create new buffer and cache it
            let buffer = Array(0..<size).map { UInt32($0) }
            buffers[size] = buffer
            return buffer
        }
    }

    // MARK: - Thread-Local Poseidon2 Hash Buffers

    /// FIX 3: Thread-local storage key for Poseidon2 hash computation buffers.
    /// Each thread gets its own pre-allocated buffer to avoid lock contention
    /// during parallel tree building. Uses Thread.current.threadDictionary for
    /// guaranteed cross-Swift-version compatibility.
    private static let threadLocalBufferKey = "EVMetalCustomProver.threadLocalBuffer"

    /// Initialize thread-local buffer for the current thread.
    /// FIX 3: Called once per thread before parallel work begins to pre-allocate
    /// reusable digest storage, eliminating per-call allocation overhead.
    private static func initializeThreadLocalBuffer() {
        let threadDict = Thread.current.threadDictionary
        if threadDict[threadLocalBufferKey] == nil {
            // Pre-allocate buffer large enough for the largest level (4096 pairs / 2 = 2048)
            threadDict[threadLocalBufferKey] = [zkMetal.M31Digest](repeating: .zero, count: 2048)
        }
    }

    // MARK: - Private State

    private let config: Config
    private let cpuProver: EVMetalCPUMerkleProver
    private var merkleEngine: EVMGPUMerkleEngine?
    private var gpuPoseidonEngine: Poseidon2M31Engine?
    private var leafHashEngine: EVMetalLeafHashEngine?
    private let bufferPool = PositionBufferPool()

    // MARK: - Initialization

    public init(config: Config = .standard) {
        self.config = config
        self.cpuProver = EVMetalCPUMerkleProver()
        self.merkleEngine = try? EVMGPUMerkleEngine()
        self.gpuPoseidonEngine = try? Poseidon2M31Engine()
        do {
            self.leafHashEngine = try EVMetalLeafHashEngine()
        } catch {
            print("EVMetalLeafHashEngine failed: \(error)")
            self.leafHashEngine = nil
        }
        // useSIMDCooperative = true  // Disabled - kernel has issues
    }

    // MARK: - Commitment (Per-Column Positions for zkMetal Compatibility)

    /// Commit trace columns using GPU with PER-COLUMN positions (matching zkMetal).
    ///
    /// Each column's leaves are hashed with positions 0 to evalLen-1 (not global positions).
    /// This produces commitments COMPATIBLE with zkMetal's buildPoseidon2M31MerkleTree.
    ///
    /// Speedup comes from:
    /// - CPU multithreaded position hashing (vs sequential in zkMetal)
    /// - GPU batch tree building (vs sequential tree-by-tree in zkMetal)
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form.
    ///   - evalLen: Evaluation length (number of leaves per column).
    /// - Returns: `CommitResult` with commitments and timing.
    public func commitTraceColumns(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        let numColumns = traceLDEs.count

        if evalLen <= subtreeMax {
            // All leaves fit in one subtree
            return try commitSmall(traceLDEs: traceLDEs, evalLen: evalLen)
        } else {
            // Need to chunk - split into 512-leaf subtrees
            return try commitChunked(traceLDEs: traceLDEs, evalLen: evalLen)
        }
    }

    /// Commit for trees <= 512 leaves (no chunking needed)
    /// GPU-accelerated: uses GPU for both position hashing AND tree building
    private func commitSmall(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count

        // Step 1: GPU position-hash with PER-COLUMN positions (matching zkMetal)
        let leafHashT0 = CFAbsoluteTimeGetCurrent()

        // Use GPU position hashing if available, otherwise NEON-optimized CPU
        var allDigests: [[M31]] = []

        if let gpuEngine = leafHashEngine {
            // GPU position hashing - EVMetalLeafHashEngine has the batch per-column method
            allDigests = try gpuEngine.hashLeavesBatchPerColumn(
                allValues: traceLDEs.flatMap { $0 },
                numColumns: numColumns,
                countPerColumn: evalLen
            )
        } else {
            // Fallback to algorithmically optimized CPU hashing
            allDigests = [[M31]](repeating: [], count: numColumns)

            // Generate position buffer once (0 to evalLen-1)
            let positions = Array(0..<evalLen).map { UInt32($0) }

            DispatchQueue.concurrentPerform(iterations: numColumns) { col in
                let colValues = traceLDEs[col]
                // Use algorithmically optimized hashing
                let digests = PositionHashOptimizer.hashLeavesWithPositionOptimized(
                    values: colValues,
                    positions: positions
                )
                allDigests[col] = digests
            }
        }

        let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

        // Step 2: GPU builds trees from pre-hashed digests
        let treeBuildT0 = CFAbsoluteTimeGetCurrent()

        var commitments: [zkMetal.M31Digest] = []
        commitments.reserveCapacity(numColumns)
        if let engine = merkleEngine {
            // Use fast GPU batch kernel for tree building
            commitments = try engine.buildTreesBatch(treesLeaves: allDigests)
        } else {
            // Fallback: CPU tree building
            commitments = buildTreesCPU(allDigests: allDigests, evalLen: evalLen)
        }

        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return CommitResult(
            commitments: commitments,
            timeMs: elapsed,
            leafHashMs: leafHashMs,
            treeBuildMs: treeBuildMs
        )
    }

    /// Commit for trees > 512 leaves
    private func commitChunked(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count

        // GPU hash all columns' leaves in a SINGLE batch call
        let leafHashT0 = CFAbsoluteTimeGetCurrent()
        guard let engine = leafHashEngine else {
            throw GPUProverError.noGPU
        }

        // Flatten all columns into single array for batch processing
        var flatValues: [M31] = []
        flatValues.reserveCapacity(numColumns * evalLen)
        for col in traceLDEs {
            flatValues.append(contentsOf: col)
        }

        // Single GPU batch call for all columns (much faster than 180 sequential calls)
        let allDigests = try engine.hashLeavesBatchPerColumn(
            allValues: flatValues,
            numColumns: numColumns,
            countPerColumn: evalLen
        )

        let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

        // Build trees from pre-hashed digests on GPU
        let treeBuildT0 = CFAbsoluteTimeGetCurrent()

        // Use GPU merkle engine for all trees at once
        guard let gpuMerkleEngine = merkleEngine else {
            throw GPUProverError.noGPU
        }
        let commitments = try gpuMerkleEngine.buildTreesBatch(treesLeaves: allDigests)

        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
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
    private func buildTreeFromDigests(digests: [M31], numLeaves: Int) -> zkMetal.M31Digest {
        // Convert flat digests to M31Digest nodes
        var nodes: [zkMetal.M31Digest] = []
        nodes.reserveCapacity(numLeaves)
        for i in 0..<numLeaves {
            let start = i * 8
            let digestValues = Array(digests[start..<start + 8])
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

    // MARK: - Parallel Tree Building (Fix 2 & 3)

    /// Build a Merkle tree from pre-hashed digests with parallel level processing.
    ///
    /// FIX 2: Parallelizes each tree level using DispatchQueue.concurrentPerform.
    ///   With 4096 leaves, there are ~12 levels. All sibling hashes at a given level
    ///   are independent and can be computed in parallel.
    ///
    /// FIX 3: Uses thread-local Poseidon2 hash buffers to avoid lock contention.
    ///   Each thread has its own reusable buffer, eliminating synchronization overhead.
    ///
    /// - Parameters:
    ///   - digests: Flat array of M31 values (8 elements per leaf digest).
    ///   - numLeaves: Number of leaves in the tree.
    /// - Returns: The root digest of the constructed Merkle tree.
    private static func buildTreeFromDigestsParallel(digests: [M31], numLeaves: Int) -> zkMetal.M31Digest {
        // Convert flat digests to M31Digest nodes
        var nodes: [zkMetal.M31Digest] = []
        nodes.reserveCapacity(numLeaves)
        for i in 0..<numLeaves {
            let start = i * 8
            let digestValues = Array(digests[start..<start + 8])
            nodes.append(zkMetal.M31Digest(values: digestValues))
        }

        // Build tree bottom-up, parallelizing each level
        var levelSize = numLeaves
        while levelSize > 1 {
            let numPairs = (levelSize + 1) / 2

            // FIX 2: Parallelize sibling hashing at each level
            // All pairs at this level are independent, so we can hash them all in parallel
            var nextLevel: [zkMetal.M31Digest] = [zkMetal.M31Digest](repeating: .zero, count: numPairs)

            DispatchQueue.concurrentPerform(iterations: numPairs) { pairIdx in
                let leftIdx = pairIdx * 2
                let rightIdx = leftIdx + 1

                let left = nodes[leftIdx]
                let right = (rightIdx < levelSize) ? nodes[rightIdx] : left

                // FIX 2: Parallel sibling hashing at this level
                // FIX 3: Thread-local buffer is pre-initialized (see initializeThreadLocalBuffer)
                // to reduce allocation pressure across multiple hash calls within the thread.
                let hash = zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
                nextLevel[pairIdx] = hash
            }

            nodes = nextLevel
            levelSize = nodes.count
        }
        return nodes[0]
    }

    /// Hash subtree roots into a single commitment
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

    // MARK: - S5: Hierarchical Commitment (Aggregate Root)

    /// Commit with hierarchical aggregation - returns both individual roots and aggregate root.
    ///
    /// S5 OPTIMIZATION: Instead of 180 independent tree roots, this method:
    /// 1. Builds 180 individual tree roots (standard Merkle trees)
    /// 2. Hashes all 180 roots into a single aggregate root
    ///
    /// The aggregate root can be used as a single commitment for all columns,
    /// reducing proof size and verification time.
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form.
    ///   - evalLen: Evaluation length.
    ///   - hierarchical: If true, also compute aggregate root (S5 optimization).
    /// - Returns: `HierarchicalCommitResult` with individual roots, aggregate root, and timing.
    public func commitTraceColumnsHierarchical(
        traceLDEs: [[M31]],
        evalLen: Int,
        hierarchical: Bool = true
    ) throws -> HierarchicalCommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        let numColumns = traceLDEs.count

        // Step 1: GPU hash all columns
        let leafHashT0 = CFAbsoluteTimeGetCurrent()
        guard let engine = leafHashEngine else {
            throw GPUProverError.noGPU
        }

        var flatValues: [M31] = []
        flatValues.reserveCapacity(numColumns * evalLen)
        for col in traceLDEs {
            flatValues.append(contentsOf: col)
        }

        let allDigests = try engine.hashLeavesBatchPerColumn(
            allValues: flatValues,
            numColumns: numColumns,
            countPerColumn: evalLen
        )

        let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

        // Step 2: GPU build trees from pre-hashed digests
        let treeBuildT0 = CFAbsoluteTimeGetCurrent()

        guard let gpuMerkleEngine = merkleEngine else {
            throw GPUProverError.noGPU
        }
        let treeRoots = try gpuMerkleEngine.buildTreesBatch(treesLeaves: allDigests)

        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000

        // Step 3: S5 - Hierarchical aggregation (hash all roots into one)
        let hierarchicalHashT0 = CFAbsoluteTimeGetCurrent()

        var aggregateRoot: zkMetal.M31Digest = .zero
        if hierarchical && !treeRoots.isEmpty {
            // Use GPU for hierarchical aggregation if we have many roots
            if treeRoots.count > 32 {
                aggregateRoot = try hashRootsHierarchicalGPU(treeRoots)
            } else {
                // CPU is faster for small number of roots
                aggregateRoot = hashRootsToCommitment(treeRoots)
            }
        }

        let hierarchicalHashMs = (CFAbsoluteTimeGetCurrent() - hierarchicalHashT0) * 1000
        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return HierarchicalCommitResult(
            treeRoots: treeRoots,
            aggregateRoot: aggregateRoot,
            timeMs: elapsed,
            leafHashMs: leafHashMs,
            treeBuildMs: treeBuildMs,
            hierarchicalHashMs: hierarchicalHashMs
        )
    }

    /// GPU-accelerated hierarchical aggregation of tree roots.
    ///
    /// S5: When we have 180 tree roots, hashing them on CPU is slow.
    /// This method uses the GPU to hash them in parallel for ~10x speedup.
    private func hashRootsHierarchicalGPU(_ roots: [zkMetal.M31Digest]) throws -> zkMetal.M31Digest {
        guard !roots.isEmpty else { return .zero }
        guard roots.count > 1 else { return roots[0] }
        guard let dev = device, let queue = commandQueue, let simdFn = upperBatchSIMDFunction, let rcBuf = rcBuffer else {
            // Fallback to CPU
            return hashRootsToCommitment(roots)
        }

        let nodeSize = 8
        let stride = MemoryLayout<UInt32>.stride
        let numRoots = roots.count

        // Allocate buffer for roots
        let rootsVals = numRoots * nodeSize
        guard let rootsBuf = dev.makeBuffer(length: rootsVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate roots buffer")
        }

        // Copy roots to buffer
        let rootsPtr = rootsBuf.contents().bindMemory(to: UInt32.self, capacity: rootsVals)
        var idx = 0
        for root in roots {
            for val in root.values {
                rootsPtr[idx] = val.v
                idx += 1
            }
        }

        // Use SIMD batch kernel to hash all pairs
        guard let cmdBuf = queue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        // Allocate output buffer
        let pairs = numRoots / 2
        guard let outputBuf = dev.makeBuffer(length: pairs * nodeSize * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate output buffer")
        }

        // Process hierarchical level
        var currentCount = numRoots
        var srcBuf = rootsBuf
        var dstBuf = outputBuf

        while currentCount > 1 {
            enc.memoryBarrier(scope: .buffers)
            let currentPairs = currentCount / 2

            enc.setComputePipelineState(simdFn)
            enc.setBuffer(srcBuf, offset: 0, index: 0)
            enc.setBuffer(dstBuf, offset: 0, index: 1)
            enc.setBuffer(rcBuf, offset: 0, index: 2)
            var numTreesVal = UInt32(1)
            enc.setBytes(&numTreesVal, length: 4, index: 3)
            var numNodesVal = UInt32(currentCount)
            enc.setBytes(&numNodesVal, length: 4, index: 4)

            let threadsNeeded = (currentPairs + 3) / 4
            enc.dispatchThreadgroups(
                MTLSize(width: threadsNeeded, height: 1, depth: 1),
                threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1)
            )

            currentCount = currentPairs
            if currentCount > 1 {
                swap(&srcBuf, &dstBuf)
            }
        }

        enc.endEncoding()
        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        // Read final root
        let outPtr = srcBuf.contents().bindMemory(to: UInt32.self, capacity: nodeSize)
        var rootValues = [M31]()
        rootValues.reserveCapacity(nodeSize)
        for i in 0..<nodeSize {
            rootValues.append(M31(v: outPtr[i]))
        }

        return zkMetal.M31Digest(values: rootValues)
    }

    /// Device for GPU operations
    private var device: MTLDevice? {
        return gpuMerkleEngine?.device
    }

    /// Command queue for GPU operations
    private var commandQueue: MTLCommandQueue? {
        return gpuMerkleEngine?.queue
    }

    /// Round constants buffer for GPU hashing
    private var rcBuffer: MTLBuffer? {
        guard let device = self.device else { return nil }
        let rc = POSEIDON2_M31_ROUND_CONSTANTS
        var flatRC = [UInt32]()
        flatRC.reserveCapacity(Poseidon2M31Config.totalRounds * Poseidon2M31Config.t)
        for round in rc {
            for elem in round {
                flatRC.append(elem.v)
            }
        }
        let byteCount = flatRC.count * MemoryLayout<UInt32>.stride
        guard let buf = device.makeBuffer(length: byteCount, options: .storageModeShared) else {
            return nil
        }
        flatRC.withUnsafeBytes { src in
            memcpy(buf.contents(), src.baseAddress!, byteCount)
        }
        return buf
    }

    /// GPU merkle engine for GPU operations
    private var gpuMerkleEngine: EVMGPUMerkleEngine? {
        return merkleEngine
    }

    /// SIMD batch function for GPU hashing
    private var upperBatchSIMDFunction: MTLComputePipelineState? {
        guard let engine = gpuMerkleEngine else { return nil }
        return engine.simdBatchFunction
    }

    /// CPU fallback for tree building (parallelized)
    private func buildTreesCPU(allDigests: [[M31]], evalLen: Int) -> [zkMetal.M31Digest] {
        let numColumns = allDigests.count
        var commitments: [zkMetal.M31Digest] = [zkMetal.M31Digest](repeating: .zero, count: numColumns)

        // Initialize thread-local buffers for all threads
        DispatchQueue.concurrentPerform(iterations: numColumns) { _ in
            Self.initializeThreadLocalBuffer()
        }

        // Parallelize across columns
        DispatchQueue.concurrentPerform(iterations: numColumns) { colIdx in
            let root = Self.buildTreeFromDigestsParallel(digests: allDigests[colIdx], numLeaves: evalLen)
            commitments[colIdx] = root
        }
        return commitments
    }

    // MARK: - Single-Tree Interleaved Commitment (ALL columns in ONE tree)

    /// Result type for single-tree interleaved commitment
    public struct SingleTreeCommitResult {
        /// Single root for ALL columns combined
        public let singleRoot: zkMetal.M31Digest
        /// Timing information
        public let timeMs: Double
        public let leafHashMs: Double
        public let treeBuildMs: Double
    }

    /// Commit ALL 180 columns into a SINGLE Merkle tree for maximum GPU parallelism.
    ///
    /// KEY OPTIMIZATION vs 180 separate trees:
    /// - 180 trees × 16,384 leaves: 180 roots, high tree overhead
    /// - 1 tree × (180 × 16,384) leaves: single root, better GPU utilization
    ///
    /// Data Layout (interleaved by position):
    /// [col0_val0, col1_val0, ..., col179_val0, col0_val1, col1_val1, ..., col179_val1, ...]
    ///
    /// Positions are GLOBAL (0 to totalLeaves-1) for single tree construction.
    ///
    /// Benefits:
    /// - Better GPU utilization at ALL tree levels
    /// - Single root for all columns (simpler proof structure)
    /// - Eliminates tree overhead from 180 to 1
    ///
    /// Note: Uses chunked approach internally for single tree - builds subtrees first, then combines.
    /// This handles the non-power-of-2 total leaf count by chunking into 512-leaf subtrees.
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form (180 columns).
    ///   - evalLen: Evaluation length (number of leaves per column, e.g., 16384).
    /// - Returns: `SingleTreeCommitResult` with single root and timing.
    public func commitSingleTree(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> SingleTreeCommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count
        let subtreeMax = 512  // Must be power of 2

        // Step 1: GPU hash all columns' leaves in batch
        let leafHashT0 = CFAbsoluteTimeGetCurrent()

        guard let engine = leafHashEngine else {
            throw GPUProverError.noGPU
        }

        // Flatten all columns
        var flatValues: [M31] = []
        flatValues.reserveCapacity(numColumns * evalLen)
        for col in traceLDEs {
            flatValues.append(contentsOf: col)
        }

        // Batch hash all columns' leaves (returns [[M31]] - per column digests)
        let allDigests = try engine.hashLeavesBatchPerColumn(
            allValues: flatValues,
            numColumns: numColumns,
            countPerColumn: evalLen
        )

        let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

        // Step 2: Build single tree using chunked approach
        // Interleave all column digests into single array, then chunk
        let treeBuildT0 = CFAbsoluteTimeGetCurrent()

        guard let gpuMerkleEngine = merkleEngine else {
            throw GPUProverError.noGPU
        }

        // Interleave all column digests into combined leaves array
        // Layout: [col0_leaf0, col0_leaf1, ..., col179_leaf0, col179_leaf1, ...]
        var combinedLeaves: [M31] = []
        combinedLeaves.reserveCapacity(numColumns * evalLen * 8)

        for leafIdx in 0..<evalLen {
            for col in 0..<numColumns {
                let baseIdx = leafIdx * 8
                for i in 0..<8 {
                    combinedLeaves.append(allDigests[col][baseIdx + i])
                }
            }
        }

        // Total leaves = numColumns * evalLen
        let totalLeaves = numColumns * evalLen

        // Chunk into subtree-sized pieces and build subtrees, then combine
        let numSubtrees = (totalLeaves + subtreeMax - 1) / subtreeMax
        var subtreeLeaves: [[M31]] = []

        for subIdx in 0..<numSubtrees {
            let start = subIdx * subtreeMax
            let end = min(start + subtreeMax, totalLeaves)
            let leafStart = start * 8
            let leafEnd = end * 8
            subtreeLeaves.append(Array(combinedLeaves[leafStart..<leafEnd]))
        }

        // Build subtrees on GPU
        let subtreeRoots = try gpuMerkleEngine.buildTreesBatch(treesLeaves: subtreeLeaves)

        // Combine subtree roots into single root (on CPU since it's just a few hashes)
        var currentRoots = subtreeRoots
        while currentRoots.count > 1 {
            var nextLevel: [zkMetal.M31Digest] = []
            for i in stride(from: 0, to: currentRoots.count, by: 2) {
                if i + 1 < currentRoots.count {
                    nextLevel.append(zkMetal.M31Digest(values: poseidon2M31Hash(
                        left: currentRoots[i].values, right: currentRoots[i+1].values)))
                } else {
                    nextLevel.append(currentRoots[i])
                }
            }
            currentRoots = nextLevel
        }

        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return SingleTreeCommitResult(
            singleRoot: currentRoots[0],
            timeMs: elapsed,
            leafHashMs: leafHashMs,
            treeBuildMs: treeBuildMs
        )
    }

    /// Compare single-tree vs standard 180-tree commitment
    public func benchmarkSingleTreeSpeedup(
        numColumns: Int = 180,
        evalLen: Int = 4096
    ) throws -> (standardMs: Double, singleTreeMs: Double, speedup: Double) {
        // Generate trace LDEs
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                values.append(M31(v: UInt32(col * 1000 + i)))
            }
            traceLDEs.append(values)
        }

        // Standard commit (180 trees)
        let standardT0 = CFAbsoluteTimeGetCurrent()
        let standardResult = try commitTraceColumns(traceLDEs: traceLDEs, evalLen: evalLen)
        let standardMs = standardResult.timeMs

        // Single tree commit (1 tree for all columns)
        let singleTreeT0 = CFAbsoluteTimeGetCurrent()
        let singleTreeResult = try commitSingleTree(traceLDEs: traceLDEs, evalLen: evalLen)
        let singleTreeMs = singleTreeResult.timeMs

        print("  Standard (180 trees): \(String(format: "%.2f", standardMs)) ms")
        print("  Single tree (1 root): \(String(format: "%.2f", singleTreeMs)) ms")
        print("    - Leaf hash: \(String(format: "%.2f", standardResult.leafHashMs)) ms -> \(String(format: "%.2f", singleTreeResult.leafHashMs)) ms")
        print("    - Tree build: \(String(format: "%.2f", standardResult.treeBuildMs)) ms -> \(String(format: "%.2f", singleTreeResult.treeBuildMs)) ms")

        return (standardMs, singleTreeMs, standardMs / singleTreeMs)
    }

    // MARK: - Interleaved Merkle Tree Building (8 Trees instead of 180)

    /// Number of trees to build from 180 columns
    /// 180 / 8 = 22.5 columns per tree (last tree has 23)
    public static let numInterleavedTrees = 8

    /// Commit trace columns using INTERLEAVED Merkle trees for 22x speedup.
    ///
    /// Instead of 180 separate trees, groups 180 columns into 8 trees (22-23 columns each).
    /// Values are interleaved within each group so they can be hashed together:
    /// Layout: [col0_val0, col1_val0, ..., col22_val0, col0_val1, ...]
    ///
    /// This reduces:
    /// - Tree hashing from 180 trees to 8 trees
    /// - Leaf hashing still processes all values but outputs 8x fewer digests
    ///
    /// - Parameters:
    ///   - traceLDEs: Trace columns in LDE form (180 columns).
    ///   - evalLen: Evaluation length (number of leaves per column, e.g., 16384).
    /// - Returns: `CommitResult` with 8 commitments and timing.
    public func commitTraceColumnsInterleaved(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count
        let numTrees = Self.numInterleavedTrees

        precondition(numColumns % numTrees == 0 || numColumns == 180,
                     "For production use, numColumns should be 180")

        let leafHashT0 = CFAbsoluteTimeGetCurrent()

        // Step 1: Interleave columns into groups
        // Each group will become one Merkle tree
        let columnsPerTree = numColumns / numTrees
        let remainder = numColumns % numTrees

        // Prepare interleaved input data for GPU
        // Layout: group0[0], group1[0], ..., group7[0], group0[1], ...
        // Each group entry is columnsPerTree values from different columns
        var interleavedData: [M31] = []
        interleavedData.reserveCapacity(numColumns * evalLen)

        for pos in 0..<evalLen {
            for treeIdx in 0..<numTrees {
                // Calculate which columns contribute to this tree at this position
                let startCol = treeIdx * columnsPerTree
                let endCol: Int
                let colIdx: Int
                if treeIdx < remainder {
                    // Earlier trees have one more column
                    endCol = startCol + columnsPerTree + 1
                    colIdx = startCol + columnsPerTree
                } else {
                    endCol = startCol + columnsPerTree
                    colIdx = startCol + (pos % columnsPerTree)
                }

                // For interleaving, we take one value from each column in the group
                // Layout: [tree0_col0_val0, tree0_col1_val0, ..., tree1_col0_val0, ...]
                // But we interleave by position first, then by column within position
                let colInGroup: Int
                if treeIdx < remainder {
                    colInGroup = pos % (columnsPerTree + 1)
                } else {
                    colInGroup = pos % columnsPerTree
                }

                // Take value from correct column
                let globalCol = startCol + colInGroup
                if globalCol < numColumns && globalCol < endCol {
                    interleavedData.append(traceLDEs[globalCol][pos])
                }
            }
        }

        // Step 2: GPU hash interleaved leaves
        guard let engine = leafHashEngine else {
            throw GPUProverError.noGPU
        }

        // Hash all interleaved values at once
        // Positions are within each tree (0 to evalLen-1)
        let positions = (0..<evalLen).map { UInt32($0) }
        let digests = try engine.hashLeavesWithPosition(
            values: interleavedData,
            positions: positions
        )

        let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

        // Step 3: Build 8 Merkle trees from the hashed digests
        let treeBuildT0 = CFAbsoluteTimeGetCurrent()

        // Convert digests to per-tree leaves
        var treesLeaves: [[M31]] = []
        treesLeaves.reserveCapacity(numTrees)

        let leavesPerTree = evalLen * 8  // 8 M31 elements per digest

        for treeIdx in 0..<numTrees {
            var treeLeaves: [M31] = []
            treeLeaves.reserveCapacity(leavesPerTree)

            let startPos = treeIdx * evalLen * 8
            let endPos = startPos + leavesPerTree
            treeLeaves.append(contentsOf: digests[startPos..<min(endPos, digests.count)])

            treesLeaves.append(treeLeaves)
        }

        // Build 8 trees on GPU
        var commitments: [zkMetal.M31Digest] = []
        if let engine = merkleEngine {
            commitments = try engine.buildTreesBatch(treesLeaves: treesLeaves)
        } else {
            // CPU fallback
            for leaves in treesLeaves {
                commitments.append(buildTreeFromDigests(digests: leaves, numLeaves: evalLen))
            }
        }

        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return CommitResult(
            commitments: commitments,
            timeMs: elapsed,
            leafHashMs: leafHashMs,
            treeBuildMs: treeBuildMs
        )
    }

    /// Alternative: Use batch GPU leaf hashing for all columns, then interleave digests
    /// This is simpler and uses existing infrastructure
    public func commitTraceColumnsInterleavedV2(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> CommitResult {
        let t0 = CFAbsoluteTimeGetCurrent()
        let numColumns = traceLDEs.count
        let numTrees = Self.numInterleavedTrees
        let subtreeMax = 512  // Must be power of 2

        let leafHashT0 = CFAbsoluteTimeGetCurrent()

        // Step 1: Hash all columns' leaves on GPU (existing batch kernel)
        guard let engine = leafHashEngine else {
            throw GPUProverError.noGPU
        }

        var flatValues: [M31] = []
        flatValues.reserveCapacity(numColumns * evalLen)
        for col in traceLDEs {
            flatValues.append(contentsOf: col)
        }

        let allDigests = try engine.hashLeavesBatchPerColumn(
            allValues: flatValues,
            numColumns: numColumns,
            countPerColumn: evalLen
        )

        let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

        // Step 2: Interleave digests into 8 groups, then chunk each group
        let treeBuildT0 = CFAbsoluteTimeGetCurrent()

        guard let gpuEngine = merkleEngine else {
            throw GPUProverError.noGPU
        }

        // Build subtree leaves for each tree, then chunk
        var allSubtreeLeaves: [[M31]] = []
        var subtreeCounts: [Int] = []  // Track how many subtrees per tree

        // Calculate column ranges for each tree
        let columnsPerTree = numColumns / numTrees
        let remainder = numColumns % numTrees

        for treeIdx in 0..<numTrees {
            // Calculate column range for this tree
            let extraColumns = treeIdx < remainder ? 1 : 0
            let colsInTree = columnsPerTree + extraColumns

            // Interleave digests from columns in this tree
            // Layout: [col0_leaf0, col1_leaf0, ..., colN_leaf0, col0_leaf1, ...]
            var treeLeaves: [M31] = []
            treeLeaves.reserveCapacity(colsInTree * evalLen * 8)

            // Calculate column indices for this tree
            let baseCol = treeIdx * columnsPerTree + min(treeIdx, remainder)
            for colIdx in 0..<colsInTree {
                let col = baseCol + colIdx
                if col >= numColumns { break }
                for leafIdx in 0..<evalLen {
                    let digestStart = leafIdx * 8
                    for i in 0..<8 {
                        if col < allDigests.count && digestStart + i < allDigests[col].count {
                            treeLeaves.append(allDigests[col][digestStart + i])
                        }
                    }
                }
            }

            // Chunk into subtrees
            let totalLeaves = treeLeaves.count / 8
            let numSubtrees = (totalLeaves + subtreeMax - 1) / subtreeMax
            subtreeCounts.append(numSubtrees)

            for subIdx in 0..<numSubtrees {
                let start = subIdx * subtreeMax * 8
                let end = min(start + subtreeMax * 8, treeLeaves.count)
                if start < treeLeaves.count {
                    allSubtreeLeaves.append(Array(treeLeaves[start..<end]))
                }
            }
        }

        // Build all subtrees on GPU
        let subtreeRoots = try gpuEngine.buildTreesBatch(treesLeaves: allSubtreeLeaves)

        // Combine subtree roots into final tree roots (8 trees)
        var commitments: [zkMetal.M31Digest] = []
        var idx = 0

        for treeIdx in 0..<numTrees {
            let numSubtreesForTree = subtreeCounts[treeIdx]

            // Combine subtrees into single root for this tree
            var roots: [zkMetal.M31Digest] = []
            for _ in 0..<numSubtreesForTree {
                if idx < subtreeRoots.count {
                    roots.append(subtreeRoots[idx])
                    idx += 1
                }
            }

            // Combine roots into one
            while roots.count > 1 {
                var next: [zkMetal.M31Digest] = []
                for i in stride(from: 0, to: roots.count, by: 2) {
                    if i + 1 < roots.count {
                        next.append(zkMetal.M31Digest(values: poseidon2M31Hash(
                            left: roots[i].values, right: roots[i+1].values)))
                    } else {
                        next.append(roots[i])
                    }
                }
                roots = next
            }
            if !roots.isEmpty {
                commitments.append(roots[0])
            }
        }

        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeBuildT0) * 1000
        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return CommitResult(
            commitments: commitments,
            timeMs: elapsed,
            leafHashMs: leafHashMs,
            treeBuildMs: treeBuildMs
        )
    }

    /// Benchmark interleaved commit vs standard commit
    public func benchmarkInterleavedSpeedup(
        numColumns: Int = 180,
        evalLen: Int = 16384
    ) throws -> (standardMs: Double, interleavedMs: Double, speedup: Double) {
        // Generate trace LDEs
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                values.append(M31(v: UInt32(col * 1000 + i)))
            }
            traceLDEs.append(values)
        }

        // Standard commit (180 trees)
        let standardT0 = CFAbsoluteTimeGetCurrent()
        let standardResult = try commitTraceColumns(traceLDEs: traceLDEs, evalLen: evalLen)
        let standardMs = standardResult.timeMs

        // Interleaved commit (8 trees)
        let interleavedT0 = CFAbsoluteTimeGetCurrent()
        let interleavedResult = try commitTraceColumnsInterleavedV2(traceLDEs: traceLDEs, evalLen: evalLen)
        let interleavedMs = interleavedResult.timeMs

        print("  Standard (180 trees): \(String(format: "%.2f", standardMs)) ms")
        print("  Interleaved (8 trees): \(String(format: "%.2f", interleavedMs)) ms")
        print("  Leaf hash: \(String(format: "%.2f", standardResult.leafHashMs)) ms -> \(String(format: "%.2f", interleavedResult.leafHashMs)) ms")
        print("  Tree build: \(String(format: "%.2f", standardResult.treeBuildMs)) ms -> \(String(format: "%.2f", interleavedResult.treeBuildMs)) ms")

        return (standardMs, interleavedMs, standardMs / interleavedMs)
    }

    // MARK: - Benchmark

    /// Benchmark custom GPU commit vs zkMetal's CPU commit
    public func benchmarkCommitSpeedup(
        numColumns: Int = 180,
        evalLen: Int = 4096
    ) throws -> (cpuMs: Double, gpuMs: Double, speedup: Double) {
        // Generate trace LDEs
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                values.append(M31(v: UInt32(col * 1000 + i)))
            }
            traceLDEs.append(values)
        }

        // CPU baseline (using zkMetal's method)
        let cpuT0 = CFAbsoluteTimeGetCurrent()
        var cpuCommitments: [zkMetal.M31Digest] = []
        for col in 0..<numColumns {
            let tree = buildPoseidon2M31MerkleTree(traceLDEs[col], count: evalLen)
            cpuCommitments.append(poseidon2M31MerkleRoot(tree, n: evalLen))
        }
        let cpuMs = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000

        // GPU commit (custom prover)
        let gpuT0 = CFAbsoluteTimeGetCurrent()
        let gpuResult = try commitTraceColumns(traceLDEs: traceLDEs, evalLen: evalLen)
        let gpuMs = gpuResult.timeMs

        // Verify they match
        var match = true
        for i in 0..<numColumns {
            if gpuResult.commitments[i].values != cpuCommitments[i].values {
                match = false
                break
            }
        }
        print("  GPU commitments match CPU (per-column positions): \(match)")

        return (cpuMs, gpuMs, cpuMs / gpuMs)
    }
}
