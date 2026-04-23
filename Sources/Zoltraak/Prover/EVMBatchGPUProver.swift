import Foundation
import Metal
import zkMetal

/// GPU-accelerated batch Merkle commitment profiler.
///
/// This profiles the batch commit phase to measure the speedup from using
/// `EVMGPUMerkleEngine.buildTreesBatch()` vs CPU sequential tree building.
///
/// Usage:
/// - Call `profileCommit()` to benchmark GPU batch vs CPU for given trace dimensions
/// - Use results to determine optimal configuration for production
public struct EVMBatchGPUProfiler {

    // MARK: - Types

    public struct ProfileResult {
        public let numColumns: Int
        public let evalLen: Int
        public let cpuCommitMs: Double
        public let gpuCommitMs: Double
        public let speedup: Double

        public var description: String {
            """
            Batch Commit Profile:
              Columns: \(numColumns)
              Eval length: \(evalLen)
              CPU: \(String(format: "%.1f ms", cpuCommitMs))
              GPU: \(String(format: "%.1f ms", gpuCommitMs))
              Speedup: \(String(format: "%.1fx", speedup))
            """
        }
    }

    // MARK: - Profiling

    /// Profile CPU vs GPU batch Merkle commitment for given trace layout.
    ///
    /// The trace LDEs should contain individual M31 elements (not pre-hashed leaves).
    /// For trees ≤ 512 leaves, GPU batch can build all trees in one dispatch.
    /// For larger trees, they are chunked into 512-leaf subtrees.
    public static func profileCommit(
        traceLDEs: [[M31]],
        evalLen: Int,
        preHashed: Bool = false
    ) throws -> ProfileResult {
        let numColumns = traceLDEs.count
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        // CPU baseline
        let cpuT0 = CFAbsoluteTimeGetCurrent()
        var cpuCommitments: [zkMetal.M31Digest] = []
        for col in traceLDEs {
            if preHashed {
                // For pre-hashed leaves (8 M31 each), build tree directly
                let tree = buildPoseidon2M31MerkleTreeFromHashedLeaves(col, count: evalLen)
                cpuCommitments.append(poseidon2M31MerkleRoot(tree, n: evalLen))
            } else {
                // Standard case: individual M31 elements
                let tree = buildPoseidon2M31MerkleTree(col, count: evalLen)
                cpuCommitments.append(poseidon2M31MerkleRoot(tree, n: evalLen))
            }
        }
        let cpuMs = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000

        // GPU batch
        let engine = try EVMGPUMerkleEngine()
        let gpuT0 = CFAbsoluteTimeGetCurrent()

        var gpuCommitments: [zkMetal.M31Digest] = []

        if evalLen <= subtreeMax {
            // All trees fit in batch kernel
            gpuCommitments = try engine.buildTreesBatch(treesLeaves: traceLDEs)
        } else {
            // Chunk into subtrees
            let numSubtrees = evalLen / subtreeMax
            var allSubtreeLeaves: [[M31]] = []
            for col in traceLDEs {
                for subIdx in 0..<numSubtrees {
                    let start = subIdx * subtreeMax
                    allSubtreeLeaves.append(Array(col[start..<start + subtreeMax]))
                }
            }

            let subtreeRoots = try engine.buildTreesBatch(treesLeaves: allSubtreeLeaves)

            // Hash subtree roots per column
            var idx = 0
            for _ in 0..<numColumns {
                var roots: [zkMetal.M31Digest] = []
                for _ in 0..<numSubtrees {
                    roots.append(subtreeRoots[idx])
                    idx += 1
                }
                gpuCommitments.append(hashRootsToCommitment(roots))
            }
        }

        let gpuMs = (CFAbsoluteTimeGetCurrent() - gpuT0) * 1000

        return ProfileResult(
            numColumns: numColumns,
            evalLen: evalLen,
            cpuCommitMs: cpuMs,
            gpuCommitMs: gpuMs,
            speedup: cpuMs / gpuMs
        )
    }

    // MARK: - Helpers

    /// Build Merkle tree from pre-hashed 8-M31 leaf nodes (no position hashing)
    private static func buildPoseidon2M31MerkleTreeFromHashedLeaves(
        _ elements: [M31],
        count: Int
    ) -> [zkMetal.M31Digest] {
        // Each 8 M31 elements is already a leaf digest
        let nodeSize = 8
        precondition(elements.count == count * nodeSize)

        var tree = [zkMetal.M31Digest]()
        tree.reserveCapacity(2 * count)

        // Leaves
        for i in 0..<count {
            let start = i * nodeSize
            let leafData = Array(elements[start..<start + nodeSize])
            tree.append(zkMetal.M31Digest(values: leafData))
        }

        // Build internal nodes
        var levelStart = 0
        var levelSize = count
        while levelSize > 1 {
            let parentStart = levelStart + levelSize
            let parentSize = levelSize / 2
            for i in 0..<parentSize {
                let left = tree[levelStart + 2 * i]
                let right = tree[levelStart + 2 * i + 1]
                tree.append(zkMetal.M31Digest(values: poseidon2M31Hash(
                    left: left.values, right: right.values)))
            }
            levelStart = parentStart
            levelSize = parentSize
        }

        return tree
    }

    /// Hash an array of digests into a single commitment
    private static func hashRootsToCommitment(_ roots: [zkMetal.M31Digest]) -> zkMetal.M31Digest {
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
}
