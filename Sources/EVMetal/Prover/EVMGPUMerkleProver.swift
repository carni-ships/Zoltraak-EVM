import Foundation
import Metal
import zkMetal

/// GPU-accelerated batch Merkle tree builder using Poseidon2-M31 via zkMetal
///
/// This engine uses zkMetal's Poseidon2M31Engine which provides:
/// - GPU-accelerated Poseidon2 permutation
/// - Fused Merkle tree kernel using GPU shared memory for trees up to 512 leaves
/// - Level-by-level GPU processing for larger trees
///
/// For upper levels (after subtree roots), uses a custom batch kernel that
/// processes multiple pairs per thread for better throughput.
public final class EVMGPUMerkleEngine {
    public let device: MTLDevice
    public let commandQueue: MTLCommandQueue

    /// Public accessor for command queue (used by hierarchical commit)
    public var queue: MTLCommandQueue {
        return commandQueue
    }

    /// zkMetal's GPU Poseidon2-M31 engine for Merkle tree building
    private let gpuEngine: Poseidon2M31Engine

    /// Custom upper-level batch kernel for processing multiple pairs per thread
    private let upperBatchFunction: MTLComputePipelineState

    /// SIMD-optimized batch kernel with multiple pairs per thread
    private let upperBatchSIMDFunction: MTLComputePipelineState

    /// Public accessor for SIMD batch function (used by hierarchical commit)
    public var simdBatchFunction: MTLComputePipelineState {
        return upperBatchSIMDFunction
    }

    /// SIMD-group cooperative hashing kernel
    private let simdGroupFunction: MTLComputePipelineState

    /// Optimized batch kernel with better grid mapping (S2)
    private let optimizedBatchFunction: MTLComputePipelineState

    /// Interleaved memory access kernel (S4)
    private let interleavedFunction: MTLComputePipelineState

    /// Round constants buffer for the custom kernel
    private let rcBuffer: MTLBuffer

    public init() throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUProverError.noGPU
        }
        self.device = device

        guard let queue = device.makeCommandQueue() else {
            throw GPUProverError.noCommandQueue
        }
        self.commandQueue = queue

        // Use zkMetal's GPU engine for Poseidon2-M31
        self.gpuEngine = try Poseidon2M31Engine()

        // Compile custom upper-level batch kernels
        let upperBatchLibrary = try Self.compileUpperBatchShaders(device: device)

        // Standard batch kernel (one thread per pair)
        guard let fn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_upper_batch") else {
            throw GPUProverError.missingKernel
        }
        self.upperBatchFunction = try device.makeComputePipelineState(function: fn)

        // SIMD-optimized batch kernel (multiple pairs per thread)
        if let simdFn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_upper_batch_simd") {
            self.upperBatchSIMDFunction = try device.makeComputePipelineState(function: simdFn)
        } else {
            // Fallback to standard kernel
            self.upperBatchSIMDFunction = self.upperBatchFunction
        }

        // SIMD-group cooperative hashing kernel (S3)
        if let sgFn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_simd_group") {
            self.simdGroupFunction = try device.makeComputePipelineState(function: sgFn)
        } else {
            // Fallback to SIMD batch kernel
            self.simdGroupFunction = self.upperBatchSIMDFunction
        }

        // Optimized batch kernel with better grid mapping (S2)
        if let optFn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_upper_batch_optimized") {
            self.optimizedBatchFunction = try device.makeComputePipelineState(function: optFn)
        } else {
            // Fallback to SIMD batch kernel
            self.optimizedBatchFunction = self.upperBatchSIMDFunction
        }

        // Interleaved memory access kernel (S4)
        if let intFn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_interleaved") {
            self.interleavedFunction = try device.makeComputePipelineState(function: intFn)
        } else {
            // Fallback to optimized batch
            self.interleavedFunction = self.optimizedBatchFunction
        }

        // Create round constants buffer for custom kernel
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
            throw GPUProverError.gpuError("Failed to allocate RC buffer")
        }
        flatRC.withUnsafeBytes { src in
            memcpy(buf.contents(), src.baseAddress!, byteCount)
        }
        self.rcBuffer = buf
    }

    private static func compileUpperBatchShaders(device: MTLDevice) throws -> MTLLibrary {
        let shaderDir = Self.findShaderDir()
        let shaderPath = shaderDir + "/poseidon2_m31_merkle_tree.metal"
        guard FileManager.default.fileExists(atPath: shaderPath) else {
            throw GPUProverError.missingKernel
        }
        let source = try String(contentsOfFile: shaderPath, encoding: .utf8)
        let options = MTLCompileOptions()
        options.fastMathEnabled = true
        options.languageVersion = .version2_0
        return try device.makeLibrary(source: source, options: options)
    }

    /// Find the shader directory by searching standard locations.
    private static func findShaderDir() -> String {
        let execPath = CommandLine.arguments[0]
        let execDir = (execPath as NSString).deletingLastPathComponent
        for bundle in Bundle.allBundles {
            if let url = bundle.url(forResource: "Shaders", withExtension: nil) {
                let path = url.appendingPathComponent("hash").path
                if FileManager.default.fileExists(atPath: path + "/poseidon2_m31_merkle_tree.metal") {
                    return path
                }
            }
        }
        let candidates = [
            "\(execDir)/../Sources/EVMetal/Shaders",
            execDir + "/../Sources/EVMetal/Shaders",
            "./Sources/EVMetal/Shaders",
        ]
        for path in candidates {
            if FileManager.default.fileExists(atPath: "\(path)/hash/poseidon2_m31_merkle_tree.metal") {
                return path + "/hash"
            }
        }
        return execDir + "/../Sources/EVMetal/Shaders"
    }

    /// Build multiple Merkle trees from pre-hashed leaves on GPU
    ///
    /// Each tree is built from its leaves; all trees must have power-of-2 leaves.
    /// Each leaf is 8 M31 elements (a Poseidon2 digest from leaf hashing).
    ///
    /// OPTIMIZED: For trees <= 512 leaves (subtreeMax), ALL trees are processed
    /// in a SINGLE GPU dispatch using encodeMerkleFused. This is 100-500x faster
    /// than processing trees sequentially.
    ///
    /// For larger trees, subtrees are processed in batch, then upper levels
    /// are combined level-by-level in the same command buffer.
    ///
    /// - Parameter treesLeaves: Array of leaf arrays, one per tree (8 M31 elements per leaf node)
    /// - Returns: Array of zkMetal.M31Digest roots, one per tree
    public func buildTreesBatch(treesLeaves: [[M31]]) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        // Validate input
        for leaves in treesLeaves {
            precondition(leaves.count % nodeSize == 0, "Leaves must be multiple of 8 M31 elements")
            let numLeaves = leaves.count / nodeSize
            precondition(numLeaves > 0 && (numLeaves & (numLeaves - 1)) == 0, "Number of leaves must be power of 2")
        }

        guard !treesLeaves.isEmpty else { return [] }

        let numTrees = treesLeaves.count
        let numLeaves = treesLeaves[0].count / nodeSize
        let stride = MemoryLayout<UInt32>.stride

        // OPTIMIZATION: For trees <= subtreeMax, use batch fused kernel
        if numLeaves <= subtreeMax {
            return try buildTreesBatchSmall(treesLeaves: treesLeaves, numLeaves: numLeaves, numTrees: numTrees, stride: stride)
        } else {
            // Large trees: batch subtree processing + GPU upper levels
            return try buildTreesBatchLarge(treesLeaves: treesLeaves, numLeaves: numLeaves, numTrees: numTrees, stride: stride)
        }
    }

    /// Build all trees <= 512 leaves in ONE GPU dispatch.
    private func buildTreesBatchSmall(treesLeaves: [[M31]], numLeaves: Int, numTrees: Int, stride: Int) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8

        // Allocate input buffer: [tree0_all_leaves, tree1_all_leaves, ...]
        let totalInputVals = numTrees * numLeaves * nodeSize
        guard let inputBuf = device.makeBuffer(length: totalInputVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffer")
        }

        // Copy all tree data to input buffer
        let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: totalInputVals)
        var idx = 0
        for treeLeaves in treesLeaves {
            for val in treeLeaves {
                inputPtr[idx] = val.v
                idx += 1
            }
        }

        // Allocate output buffer for roots
        let rootBytes = numTrees * nodeSize * stride
        guard let outputBuf = device.makeBuffer(length: rootBytes, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate output buffer")
        }

        // ONE GPU dispatch for ALL trees
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
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
        try waitAndCheckError(cmdBuf, operation: "buildTreesBatch: fuse")

        // Read results
        let outPtr = outputBuf.contents().bindMemory(to: UInt32.self, capacity: numTrees * nodeSize)
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

    /// Build trees > 512 leaves using batch subtree processing + GPU upper levels.
    private func buildTreesBatchLarge(treesLeaves: [[M31]], numLeaves: Int, numTrees: Int, stride: Int) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize
        let numSubtrees = numLeaves / subtreeMax

        // Step 1: Flatten all trees' leaves into one buffer
        // Layout: [tree0_subtree0, tree0_subtree1, ..., tree1_subtree0, ...]
        let leavesPerTree = numSubtrees * subtreeMax * nodeSize
        let totalLeavesVals = numTrees * leavesPerTree

        guard let leavesBuf = device.makeBuffer(length: totalLeavesVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate leaves buffer")
        }

        let leavesPtr = leavesBuf.contents().bindMemory(to: UInt32.self, capacity: totalLeavesVals)
        var idx = 0
        for treeLeaves in treesLeaves {
            for subIdx in 0..<numSubtrees {
                let start = subIdx * subtreeMax * nodeSize
                for i in 0..<(subtreeMax * nodeSize) {
                    leavesPtr[idx] = treeLeaves[start + i].v
                    idx += 1
                }
            }
        }

        // Step 2: Allocate output buffer for subtree roots
        let rootsPerTree = numSubtrees * nodeSize
        let rootsSize = numTrees * rootsPerTree * stride

        guard let rootsBuf = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate roots buffer")
        }

        // Step 3: ONE GPU dispatch for ALL subtrees
        let totalSubtrees = numTrees * numSubtrees

        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: leavesBuf,
            leavesOffset: 0,
            rootsBuffer: rootsBuf,
            rootsOffset: 0,
            numSubtrees: totalSubtrees,
            subtreeSize: subtreeMax
        )

        // Step 4: Process upper levels using OPTIMIZED batch kernel (S2, S3, S4)
        var currentNodes = numSubtrees
        var srcBuf = rootsBuf

        if currentNodes > 1 {
            guard let bufA = device.makeBuffer(length: rootsSize, options: .storageModeShared),
                  let bufB = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate upper level buffers")
            }

            var dstBuf = bufA

            // S2: Use threadgroup size of 256 for better GPU occupancy
            // This allows the GPU to schedule more threadgroups simultaneously
            let threadsPerThreadgroup = min(256, upperBatchSIMDFunction.maxTotalThreadsPerThreadgroup)

            while currentNodes > 1 {
                enc.memoryBarrier(scope: .buffers)
                let pairs = currentNodes / 2

                // S2: Use optimized batch kernel with better grid mapping
                // Each threadgroup processes one tree for better locality
                enc.setComputePipelineState(optimizedBatchFunction)
                enc.setBuffer(srcBuf, offset: 0, index: 0)
                enc.setBuffer(dstBuf, offset: 0, index: 1)
                enc.setBuffer(rcBuffer, offset: 0, index: 2)
                var numTreesVal = UInt32(numTrees)
                enc.setBytes(&numTreesVal, length: 4, index: 3)
                var numNodesVal = UInt32(currentNodes)
                enc.setBytes(&numNodesVal, length: 4, index: 4)
                var pairsPerTreeVal = UInt32(pairs)
                enc.setBytes(&pairsPerTreeVal, length: 4, index: 5)

                // S2: Better grid mapping - one threadgroup per tree
                // Each threadgroup processes all pairs for its tree
                let threadgroupSize = min(threadsPerThreadgroup, (pairs + 3) / 4)
                enc.dispatchThreadgroups(
                    MTLSize(width: numTrees, height: 1, depth: 1),
                    threadsPerThreadgroup: MTLSize(width: threadgroupSize, height: 1, depth: 1)
                )

                currentNodes = pairs
                swap(&srcBuf, &dstBuf)
            }
        }

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildTreesBatchLarge: loop")

        // Step 5: Read final roots
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

    /// Build multiple trees from pre-hashed leaves on GPU
    public func buildTree(leaves: [M31]) throws -> zkMetal.M31Digest {
        return try buildTreesBatch(treesLeaves: [leaves])[0]
    }

    /// Build trees from GPU buffers directly (no CPU readback).
    ///
    /// This is the KEY OPTIMIZATION for the GPU-only commitment pipeline.
    /// Takes hashed GPU buffers and builds Merkle trees without reading data back to CPU.
    ///
    /// - Parameters:
    ///   - gpuBuffers: GPU buffers with hashed digests (8 M31 per leaf)
    ///   - numColumns: Number of columns (one tree per buffer)
    ///   - evalLen: Number of elements per buffer (leaves per column)
    /// - Returns: Array of M31Digest roots
    public func buildTreesFromGPUBuffers(
        gpuBuffers: [MTLBuffer],
        numColumns: Int,
        evalLen: Int
    ) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        guard gpuBuffers.count == numColumns else {
            throw GPUProverError.gpuError("Buffer count mismatch: \(gpuBuffers.count) vs \(numColumns)")
        }

        // Small trees: All fit in one dispatch via buildTreesBatchSmall
        if evalLen <= subtreeMax {
            return try buildTreesBatchFromGPUBuffers(
                gpuBuffers: gpuBuffers,
                numColumns: numColumns,
                evalLen: evalLen,
                nodeSize: nodeSize
            )
        } else {
            // Large trees: Chunk into subtrees, build with buildTreesWithSubtrees
            let numSubtrees = evalLen / subtreeMax
            return try buildTreesWithSubtreesFromGPUBuffers(
                gpuBuffers: gpuBuffers,
                numColumns: numColumns,
                numSubtreesPerTree: numSubtrees,
                subtreeSize: subtreeMax,
                nodeSize: nodeSize
            )
        }
    }

    /// Build all small trees (<= subtreeMax) from GPU buffers in ONE dispatch.
    private func buildTreesBatchFromGPUBuffers(
        gpuBuffers: [MTLBuffer],
        numColumns: Int,
        evalLen: Int,
        nodeSize: Int
    ) throws -> [zkMetal.M31Digest] {
        let stride = MemoryLayout<UInt32>.stride
        let numLeaves = evalLen

        // Concatenate all GPU buffers into one input buffer
        let totalVals = numColumns * numLeaves * nodeSize
        guard let inputBuf = device.makeBuffer(length: totalVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffer")
        }

        // Copy all buffers to one input buffer
        let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: totalVals)
        var offset = 0
        for buf in gpuBuffers {
            let count = numLeaves * nodeSize
            let srcPtr = buf.contents().bindMemory(to: UInt32.self, capacity: count)
            for i in 0..<count {
                inputPtr[offset + i] = srcPtr[i]
            }
            offset += count
        }

        // Allocate output buffer
        let rootBytes = numColumns * nodeSize * stride
        guard let outputBuf = device.makeBuffer(length: rootBytes, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate output buffer")
        }

        // ONE GPU dispatch for ALL trees
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: inputBuf,
            leavesOffset: 0,
            rootsBuffer: outputBuf,
            rootsOffset: 0,
            numSubtrees: numColumns,
            subtreeSize: numLeaves
        )

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildTreesBatchFromGPUBuffers")

        // Read results
        let outPtr = outputBuf.contents().bindMemory(to: UInt32.self, capacity: numColumns * nodeSize)
        var roots: [zkMetal.M31Digest] = []
        roots.reserveCapacity(numColumns)

        for i in 0..<numColumns {
            var rootValues = [M31]()
            rootValues.reserveCapacity(nodeSize)
            for j in 0..<nodeSize {
                rootValues.append(M31(v: outPtr[i * nodeSize + j]))
            }
            roots.append(zkMetal.M31Digest(values: rootValues))
        }

        return roots
    }

    /// Build trees from GPU buffers with subtrees (for trees > subtreeMax).
    private func buildTreesWithSubtreesFromGPUBuffers(
        gpuBuffers: [MTLBuffer],
        numColumns: Int,
        numSubtreesPerTree: Int,
        subtreeSize: Int,
        nodeSize: Int
    ) throws -> [zkMetal.M31Digest] {
        let stride = MemoryLayout<UInt32>.stride
        let totalSubtrees = numColumns * numSubtreesPerTree

        // Layout: [col0_sub0, col0_sub1, ..., col1_sub0, ...]
        let leavesPerTree = numSubtreesPerTree * subtreeSize * nodeSize
        let totalLeavesVals = numColumns * leavesPerTree

        // Flatten all buffers into one input buffer
        guard let leavesBuf = device.makeBuffer(length: totalLeavesVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate leaves buffer")
        }

        let leavesPtr = leavesBuf.contents().bindMemory(to: UInt32.self, capacity: totalLeavesVals)
        var idx = 0
        for buf in gpuBuffers {
            let subtreeVals = subtreeSize * nodeSize
            let srcPtr = buf.contents().bindMemory(to: UInt32.self, capacity: subtreeVals * numSubtreesPerTree)
            for subIdx in 0..<numSubtreesPerTree {
                for i in 0..<subtreeVals {
                    leavesPtr[idx] = srcPtr[subIdx * subtreeVals + i]
                    idx += 1
                }
            }
        }

        // Allocate roots buffer
        let rootsPerTree = numSubtreesPerTree * nodeSize
        let rootsSize = numColumns * rootsPerTree * stride

        guard let rootsBuf = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate roots buffer")
        }

        // ONE GPU dispatch for ALL subtree roots
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: leavesBuf,
            leavesOffset: 0,
            rootsBuffer: rootsBuf,
            rootsOffset: 0,
            numSubtrees: totalSubtrees,
            subtreeSize: subtreeSize
        )

        // Process upper levels
        var currentNodes = numSubtreesPerTree
        var srcBuf = rootsBuf

        if currentNodes > 1 {
            guard let bufA = device.makeBuffer(length: rootsSize, options: .storageModeShared),
                  let bufB = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate upper level buffers")
            }

            var dstBuf = bufA
            let threadsPerThreadgroup = min(256, upperBatchSIMDFunction.maxTotalThreadsPerThreadgroup)

            while currentNodes > 1 {
                enc.memoryBarrier(scope: .buffers)
                let pairs = currentNodes / 2

                enc.setComputePipelineState(optimizedBatchFunction)
                enc.setBuffer(srcBuf, offset: 0, index: 0)
                enc.setBuffer(dstBuf, offset: 0, index: 1)
                enc.setBuffer(rcBuffer, offset: 0, index: 2)
                var numTreesVal = UInt32(numColumns)
                enc.setBytes(&numTreesVal, length: 4, index: 3)
                var numNodesVal = UInt32(currentNodes)
                enc.setBytes(&numNodesVal, length: 4, index: 4)
                var pairsPerTreeVal = UInt32(pairs)
                enc.setBytes(&pairsPerTreeVal, length: 4, index: 5)

                let threadgroupSize = min(threadsPerThreadgroup, (pairs + 3) / 4)
                enc.dispatchThreadgroups(
                    MTLSize(width: numColumns, height: 1, depth: 1),
                    threadsPerThreadgroup: MTLSize(width: threadgroupSize, height: 1, depth: 1)
                )

                currentNodes = pairs
                swap(&srcBuf, &dstBuf)
            }
        }

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildTreesWithSubtreesFromGPUBuffers")

        // Read final roots
        let outPtr = srcBuf.contents().bindMemory(to: UInt32.self, capacity: numColumns * nodeSize)
        var roots: [zkMetal.M31Digest] = []
        roots.reserveCapacity(numColumns)

        for i in 0..<numColumns {
            var rootValues = [M31]()
            rootValues.reserveCapacity(nodeSize)
            for j in 0..<nodeSize {
                rootValues.append(M31(v: outPtr[i * nodeSize + j]))
            }
            roots.append(zkMetal.M31Digest(values: rootValues))
        }

        return roots
    }

    /// Build multiple trees with chunked subtrees, returning final roots.
    ///
    /// This is the KEY OPTIMIZATION for large trees (e.g., 180 trees with 8 subtrees each).
    /// ALL processing happens on GPU:
    ///   1. Subtree roots via encodeMerkleFused (batch)
    ///   2. Upper levels via optimized batch kernel (batch)
    ///   3. Final root extraction from GPU buffer
    ///
    /// - Parameters:
    ///   - allSubtreeLeaves: Array of subtree leaf arrays. Layout is: [tree0_sub0, tree0_sub1, ..., tree1_sub0, ...]
    ///   - numSubtreesPerTree: Number of subtrees per tree
    ///   - subtreeSize: Number of leaves per subtree (must be <= subtreeMax = 512)
    /// - Returns: Array of root digests, one per tree
    public func buildTreesWithSubtrees(
        allSubtreeLeaves: [[M31]],
        numSubtreesPerTree: Int,
        subtreeSize: Int
    ) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8
        let numTrees = allSubtreeLeaves.count / numSubtreesPerTree
        let stride = MemoryLayout<UInt32>.stride
        let totalSubtrees = allSubtreeLeaves.count

        // Step 1: Flatten all subtree leaves into one GPU buffer
        let leavesPerTree = numSubtreesPerTree * subtreeSize * nodeSize
        let totalLeavesVals = numTrees * leavesPerTree

        guard let leavesBuf = device.makeBuffer(length: totalLeavesVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate leaves buffer")
        }

        let leavesPtr = leavesBuf.contents().bindMemory(to: UInt32.self, capacity: totalLeavesVals)
        var idx = 0
        for treeLeaves in allSubtreeLeaves {
            for val in treeLeaves {
                leavesPtr[idx] = val.v
                idx += 1
            }
        }

        // Step 2: Allocate roots buffer for subtree roots
        let rootsPerTree = numSubtreesPerTree * nodeSize
        let rootsSize = numTrees * rootsPerTree * stride

        guard let rootsBuf = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate roots buffer")
        }

        // Step 3: ONE GPU dispatch for ALL subtree roots
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: leavesBuf,
            leavesOffset: 0,
            rootsBuffer: rootsBuf,
            rootsOffset: 0,
            numSubtrees: totalSubtrees,
            subtreeSize: subtreeSize
        )

        // Step 4: Process upper levels (combine subtree roots per tree) in SAME command buffer
        // S2: Optimized dispatch with better grid mapping
        var currentNodes = numSubtreesPerTree
        var srcBuf = rootsBuf

        if currentNodes > 1 {
            guard let bufA = device.makeBuffer(length: rootsSize, options: .storageModeShared),
                  let bufB = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate upper level buffers")
            }

            var dstBuf = bufA

            // S2: Use larger threadgroup for better GPU occupancy
            let threadsPerThreadgroup = min(256, upperBatchSIMDFunction.maxTotalThreadsPerThreadgroup)

            while currentNodes > 1 {
                enc.memoryBarrier(scope: .buffers)
                let pairs = currentNodes / 2

                // S2: Use optimized batch kernel with better grid mapping
                // S3: SIMD group operations for reduced divergence
                enc.setComputePipelineState(optimizedBatchFunction)
                enc.setBuffer(srcBuf, offset: 0, index: 0)
                enc.setBuffer(dstBuf, offset: 0, index: 1)
                enc.setBuffer(rcBuffer, offset: 0, index: 2)
                var numTreesVal = UInt32(numTrees)
                enc.setBytes(&numTreesVal, length: 4, index: 3)
                var numNodesVal = UInt32(currentNodes)
                enc.setBytes(&numNodesVal, length: 4, index: 4)
                var pairsPerTreeVal = UInt32(pairs)
                enc.setBytes(&pairsPerTreeVal, length: 4, index: 5)

                // S2: Better grid mapping - one threadgroup per tree
                let threadgroupSize = min(threadsPerThreadgroup, (pairs + 3) / 4)
                enc.dispatchThreadgroups(
                    MTLSize(width: numTrees, height: 1, depth: 1),
                    threadsPerThreadgroup: MTLSize(width: threadgroupSize, height: 1, depth: 1)
                )

                currentNodes = pairs
                swap(&srcBuf, &dstBuf)
            }
        }

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildTreesWithSubtrees: upper levels")

        // Step 5: Read final roots from GPU buffer
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
    case commandBufferError(String)
    case invalidDimensions(String)

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
        case .commandBufferError(let msg):
            return "GPU command buffer error: \(msg)"
        case .invalidDimensions(let msg):
            return "Invalid dimensions: \(msg)"
        }
    }
}

// MARK: - GPU Command Buffer Helpers

/// Waits for a command buffer to complete and checks for errors.
/// - Throws: GPUProverError.commandBufferError if the GPU operation failed
private func waitAndCheckError(_ commandBuffer: MTLCommandBuffer, operation: String) throws {
    commandBuffer.waitUntilCompleted()
    if let error = commandBuffer.error {
        let errorDescription: String
        if let gpuError = error as? NSError,
           let underlying = gpuError.userInfo["NSErrorUnderlyingErrorKey"] as? String {
            errorDescription = underlying
        } else {
            errorDescription = error.localizedDescription
        }
        throw GPUProverError.commandBufferError("\(operation): \(errorDescription)")
    }
}
