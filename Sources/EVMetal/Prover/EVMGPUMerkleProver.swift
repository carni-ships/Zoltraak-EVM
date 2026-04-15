import Foundation
import Metal
import zkMetal

/// GPU-accelerated batch Merkle tree builder using Poseidon2-M31
///
/// Note: GPU batch tree building for M31 is not yet available. This engine
/// currently uses CPU tree building but is structured to support GPU kernels
/// once they are implemented.
public final class EVMGPUMerkleEngine {
    public let device: MTLDevice
    public let commandQueue: MTLCommandQueue

    public init() throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUProverError.noGPU
        }
        self.device = device

        guard let queue = device.makeCommandQueue() else {
            throw GPUProverError.noCommandQueue
        }
        self.commandQueue = queue
    }

    /// Build multiple Merkle trees from pre-hashed leaves
    /// Each tree is built from its leaves; all trees must have power-of-2 leaves.
    ///
    /// - Parameter treesLeaves: Array of leaf arrays, one per tree (8 M31 elements per leaf node)
    /// - Returns: Array of zkMetal.M31Digest roots, one per tree
    public func buildTreesBatch(treesLeaves: [[M31]]) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8

        // Validate input
        for leaves in treesLeaves {
            precondition(leaves.count % nodeSize == 0, "Leaves must be multiple of 8 M31 elements")
            let numLeaves = leaves.count / nodeSize
            precondition(numLeaves > 0 && (numLeaves & (numLeaves - 1)) == 0, "Number of leaves must be power of 2")
            precondition(numLeaves <= 512, "Tree too large")
        }

        // Build each tree using CPU tree building
        return try treesLeaves.map { leaves in
            try buildTreeFromLeaves(leaves)
        }
    }

    /// Build a single Merkle tree from pre-hashed leaves
    private func buildTreeFromLeaves(_ leaves: [M31]) throws -> zkMetal.M31Digest {
        let numLeaves = leaves.count / 8
        precondition(numLeaves > 0 && (numLeaves & (numLeaves - 1)) == 0, "numLeaves must be power of 2")

        // Convert to M31Digest nodes
        var nodes: [zkMetal.M31Digest] = []
        nodes.reserveCapacity(numLeaves)
        for i in 0..<numLeaves {
            let start = i * 8
            let digestValues = Array(leaves[start..<start + 8])
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

    /// Build a single Merkle tree on GPU (placeholder - uses CPU)
    public func buildTree(leaves: [M31]) throws -> zkMetal.M31Digest {
        return try buildTreesBatch(treesLeaves: [leaves])[0]
    }

    /// Generate Merkle proof for a leaf index in a pre-built tree
    public func generateProof(tree: [zkMetal.M31Digest], n: Int, index: Int) -> [zkMetal.M31Digest] {
        var path = [zkMetal.M31Digest]()
        var levelStart = 0
        var levelSize = n
        var idx = index
        while levelSize > 1 {
            let sibIdx = idx ^ 1
            path.append(tree[levelStart + sibIdx])
            levelStart += levelSize
            levelSize /= 2
            idx /= 2
        }
        return path
    }
}

// MARK: - GPU Prover Errors

public enum GPUProverError: Error {
    case noGPU
    case noCommandQueue
    case noCommandBuffer
    case missingKernel
    case gpuError(String)

    public var description: String {
        switch self {
        case .noGPU:
            return "No GPU available"
        case .noCommandQueue:
            return "Failed to create command queue"
        case .noCommandBuffer:
            return "Failed to create command buffer"
        case .missingKernel:
            return "Metal kernel not found"
        case .gpuError(let msg):
            return "GPU error: \(msg)"
        }
    }
}