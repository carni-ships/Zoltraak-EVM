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

    // MARK: - Initialization

    /// Creates a new GPU prover with the given configuration.
    /// - Parameter config: Prover configuration. Uses `.standard` if not specified.
    public init(config: Config = .standard) {
        self.config = config
        self.leafHashEngine = try! EVMetalLeafHashEngine()
        self.cpuProver = EVMetalCPUMerkleProver()
        self.merkleEngine = try? EVMGPUMerkleEngine()
    }

    // MARK: - GPU Commitment (Pure GPU)

    /// Commit trace columns using GPU with position-hashed Merkle trees.
    ///
    /// This produces commitments that MATCH zkmetal's CPU tree builder because
    /// the GPU kernel hashes individual M31 values with their position.
    ///
    /// For trees larger than `Poseidon2M31Engine.merkleSubtreeSize` (512 leaves),
    /// the tree is automatically chunked into subtrees, with roots combined
    /// using a binary hash to produce the final commitment.
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
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        var commitments: [zkMetal.M31Digest] = []

        if evalLen <= subtreeMax {
            // All leaves fit in one subtree - batch hash all columns at once
            let numColumns = traceLDEs.count

            // Flatten all values
            var flatValues: [M31] = []
            flatValues.reserveCapacity(numColumns * evalLen)
            for col in traceLDEs {
                flatValues.append(contentsOf: col)
            }

            // GPU batch hash all columns at once
            let allDigests = try leafHashEngine.hashLeavesBatchPerColumn(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: evalLen
            )

            // Build trees from pre-hashed digests
            for colDigests in allDigests {
                var nodes: [zkMetal.M31Digest] = []
                for i in 0..<evalLen {
                    let start = i * 8
                    let digestValues = Array(colDigests[start..<start + 8])
                    nodes.append(zkMetal.M31Digest(values: digestValues))
                }

                // Build tree bottom-up
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
        } else {
            // Need to chunk - split into 512-leaf subtrees
            let numSubtrees = evalLen / subtreeMax
            let numColumns = traceLDEs.count

            for col in traceLDEs {
                var subtreeRoots: [zkMetal.M31Digest] = []
                for subIdx in 0..<numSubtrees {
                    let start = subIdx * subtreeMax
                    let subtreeValues = Array(col[start..<start + subtreeMax])
                    let root = try leafHashEngine.buildMerkleTree(values: subtreeValues, numLeaves: subtreeMax)
                    subtreeRoots.append(root)
                }
                let commitment = hashRootsToCommitment(subtreeRoots)
                commitments.append(commitment)
            }
        }

        let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        return CommitResult(commitments: commitments, timeMs: elapsed)
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

            return CommitResult(commitments: commitments, timeMs: elapsed, leafHashMs: leafHashMs, treeBuildMs: treeBuildMs)

        } else {
            // Need to chunk - split into 512-leaf subtrees
            let numSubtrees = evalLen / subtreeMax
            let leafHashT0 = CFAbsoluteTimeGetCurrent()

            // Process each column using CPU
            var columnRoots: [[zkMetal.M31Digest]] = []

            for col in traceLDEs {
                var subtreeRoots: [zkMetal.M31Digest] = []

                for subIdx in 0..<numSubtrees {
                    let start = subIdx * subtreeMax
                    let subtreeValues = Array(col[start..<start + subtreeMax])

                    // Hash this subtree's leaves using CPU
                    let subtreeDigests = cpuProver.hashLeavesBatchPerColumn(
                        allValues: subtreeValues,
                        numColumns: 1,
                        countPerColumn: subtreeMax
                    )

                    // Build tree for this subtree
                    var nodes: [zkMetal.M31Digest] = []
                    for i in 0..<subtreeMax {
                        let digestStart = i * 8
                        let digestValues = Array(subtreeDigests[0][digestStart..<digestStart + 8])
                        nodes.append(zkMetal.M31Digest(values: digestValues))
                    }
                    var levelSize = subtreeMax
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
                    subtreeRoots.append(nodes[0])
                }

                columnRoots.append(subtreeRoots)
            }

            let leafHashMs = (CFAbsoluteTimeGetCurrent() - leafHashT0) * 1000

            // Hash subtree roots to get final commitment
            var commitments: [zkMetal.M31Digest] = []
            for roots in columnRoots {
                commitments.append(hashRootsToCommitment(roots))
            }

            let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000
            return CommitResult(commitments: commitments, timeMs: elapsed, leafHashMs: leafHashMs, treeBuildMs: 0)
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
        // Generate trace LDEs with individual M31 values (one per leaf position)
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var values: [M31] = []
            for i in 0..<evalLen {
                values.append(M31(v: UInt32(col * 1000 + i)))
            }
            traceLDEs.append(values)
        }

        // CPU baseline
        let cpuT0 = CFAbsoluteTimeGetCurrent()
        var cpuCommitments: [zkMetal.M31Digest] = []
        for col in traceLDEs {
            let tree = buildPoseidon2M31MerkleTree(col, count: evalLen)
            cpuCommitments.append(poseidon2M31MerkleRoot(tree, n: evalLen))
        }
        let cpuMs = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000

        // GPU batch
        let gpuT0 = CFAbsoluteTimeGetCurrent()
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
