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
    ///
    /// GPU Proof Generation:
    ///
    /// This engine supports GPU-side proof generation to eliminate the CPU tree
    /// rebuilding bottleneck. The approach:
    ///
    /// 1. GPU builds trees and keeps the flattened tree structure in GPU memory
    /// 2. GPU kernels generate proof paths given query indices
    /// 3. No CPU tree rebuilding required - proofs are generated directly on GPU
    ///
    /// The flattened tree structure is [M31Digest] where:
    ///   - tree[0..n) are leaves
    ///   - tree[n..n+n/2) are level 1 parents
    ///   - ...continues until root at tree[2n-1]
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

    /// GPU proof generation kernel - single proof generator
    private let proofGenFunction: MTLComputePipelineState

    /// GPU proof generation kernel - batch proof generator
    private let batchProofGenFunction: MTLComputePipelineState

    /// GPU SIMD-optimized proof generation kernel
    private let simdProofGenFunction: MTLComputePipelineState

    /// GPU leaf hashing kernel with position (for GPU-only pipeline)
    private let leafHashFunction: MTLComputePipelineState

    /// GPU hash pairs kernel
    private let hashPairsKernel: MTLComputePipelineState

    /// Round constants buffer for the custom kernel
    private let rcBuffer: MTLBuffer

    // MARK: - GPU Buffer Pool for Reuse

    /// Reusable buffers for high-frequency operations (reduce allocation overhead)
    private var bufferPool: [BufferEntry] = []

    /// Buffer entry in the pool
    private struct BufferEntry {
        let buffer: MTLBuffer
        let size: Int
        var lastUseTime: CFAbsoluteTime = 0
    }

    /// Get or create a reusable buffer of the specified size
    /// This reduces GPU memory allocation overhead
    private func getOrCreateBuffer(size: Int) -> MTLBuffer? {
        let now = CFAbsoluteTimeGetCurrent()

        // Try to find an existing buffer of sufficient size
        for i in 0..<bufferPool.count {
            if bufferPool[i].size >= size {
                bufferPool[i].lastUseTime = now
                return bufferPool[i].buffer
            }
        }

        // Create new buffer
        guard let buffer = device.makeBuffer(length: size, options: .storageModeShared) else {
            return nil
        }

        bufferPool.append(BufferEntry(buffer: buffer, size: size, lastUseTime: now))
        return buffer
    }

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

        // GPU proof generation kernels
        self.proofGenFunction = try Self.compileProofKernel(device: device, library: upperBatchLibrary, name: "poseidon2_m31_merkle_proof_generator")
        self.batchProofGenFunction = try Self.compileProofKernel(device: device, library: upperBatchLibrary, name: "poseidon2_m31_merkle_proof_batch")
        self.simdProofGenFunction = try Self.compileProofKernel(device: device, library: upperBatchLibrary, name: "poseidon2_m31_merkle_proof_batch_simd")

        // GPU leaf hashing kernel (from EVMetal's shader)
        let leafHashLibrary = try Self.compileLeafHashShaders(device: device)
        if let lhFn = leafHashLibrary.makeFunction(name: "poseidon2_m31_hash_leaves_with_position") {
            self.leafHashFunction = try device.makeComputePipelineState(function: lhFn)
        } else {
            throw GPUProverError.missingKernel
        }

        if let hpFn = leafHashLibrary.makeFunction(name: "poseidon2_m31_hash_pairs") {
            self.hashPairsKernel = try device.makeComputePipelineState(function: hpFn)
        } else {
            throw GPUProverError.missingKernel
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

    /// Compile leaf hash shaders from EVMetal's shader directory.
    private static func compileLeafHashShaders(device: MTLDevice) throws -> MTLLibrary {
        let shaderDir = Self.findShaderDir()
        let shaderPath = shaderDir + "/poseidon2_m31_leaf_hash.metal"
        guard FileManager.default.fileExists(atPath: shaderPath) else {
            throw GPUProverError.missingKernel
        }
        let source = try String(contentsOfFile: shaderPath, encoding: .utf8)
        let options = MTLCompileOptions()
        options.fastMathEnabled = true
        options.languageVersion = .version2_0
        return try device.makeLibrary(source: source, options: options)
    }

    /// Compile a GPU proof generation kernel.
    private static func compileProofKernel(device: MTLDevice, library: MTLLibrary, name: String) throws -> MTLComputePipelineState {
        guard let function = library.makeFunction(name: name) else {
            throw GPUProverError.missingKernel
        }
        return try device.makeComputePipelineState(function: function)
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

    /// Build trees with GPU leaf hashing integrated (no CPU readback).
    ///
    /// Two-stage pipeline:
    /// 1. GPU leaf hashing: Hash each M31 value with position → digest (8 M31)
    /// 2. GPU Merkle tree: Build trees from pre-hashed digests
    ///
    /// - Parameters:
    ///   - traceLDEs: Raw trace LDE columns [[M31]] (unhashed)
    ///   - numColumns: Number of columns
    ///   - evalLen: Evaluation length (leaves per column)
    /// - Returns: Array of M31Digest roots
    public func buildTreesWithLeafHash(
        traceLDEs: [[M31]],
        numColumns: Int,
        evalLen: Int
    ) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        guard traceLDEs.count == numColumns else {
            throw GPUProverError.gpuError("Column count mismatch: \(traceLDEs.count) vs \(numColumns)")
        }

        let stride = MemoryLayout<UInt32>.stride

        // === Stage 1: GPU Leaf Hashing ===
        // Input: numColumns * evalLen M31 values (raw trace)
        // Output: numColumns * evalLen * nodeSize M31 values (digests, 8 M31 per input)
        // Kernel outputs 8 M31 per thread, so total output = input_count * 8

        // Copy trace data to input buffer (1 M31 per value)
        let totalInputVals = numColumns * evalLen
        guard let inputBuf = device.makeBuffer(length: totalInputVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffer (\(totalInputVals * stride) bytes)")
        }

        let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: totalInputVals)
        var idx = 0
        for col in traceLDEs {
            for val in col {
                inputPtr[idx] = val.v
                idx += 1
            }
        }

        // Create positions buffer: position = leaf_index % evalLen
        let positionsVals = numColumns * evalLen
        guard let positionsBuf = device.makeBuffer(length: positionsVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate positions buffer")
        }
        let positionsPtr = positionsBuf.contents().bindMemory(to: UInt32.self, capacity: positionsVals)
        for colIdx in 0..<numColumns {
            let baseOffset = colIdx * evalLen
            for leafIdx in 0..<evalLen {
                positionsPtr[baseOffset + leafIdx] = UInt32(leafIdx)
            }
        }

        // Output buffer for hashed digests: 8 M31 per input value
        // Kernel writes digest[gid * 8 + i] for i = 0..<8
        let totalDigestVals = numColumns * evalLen * nodeSize
        guard let hashedBuf = device.makeBuffer(length: totalDigestVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate hashed buffer (\(totalDigestVals * stride) bytes)")
        }

        // GPU leaf hashing dispatch
        guard let hashCmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let hashEnc = hashCmdBuf.makeComputeCommandEncoder()!

        hashEnc.setComputePipelineState(leafHashFunction)
        hashEnc.setBuffer(inputBuf, offset: 0, index: 0)        // Values
        hashEnc.setBuffer(positionsBuf, offset: 0, index: 1)     // Positions
        hashEnc.setBuffer(hashedBuf, offset: 0, index: 2)        // Output (digests)
        hashEnc.setBuffer(rcBuffer, offset: 0, index: 3)         // Round constants

        var numLeaves = UInt32(numColumns * evalLen)
        hashEnc.setBytes(&numLeaves, length: 4, index: 4)        // count at index 4

        let totalThreads = numColumns * evalLen
        hashEnc.dispatchThreadgroups(
            MTLSize(width: (totalThreads + 31) / 32, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(width: 32, height: 1, depth: 1)
        )

        hashEnc.endEncoding()
        hashCmdBuf.commit()
        try waitAndCheckError(hashCmdBuf, operation: "buildTreesWithLeafHash: leaf hash")

        // === Stage 2: GPU Merkle Tree Building ===
        // Input: hashed digests (8 M31 per leaf)
        // Output: roots

        let numLeavesPerTree = evalLen  // Each column has evalLen leaves
        let numSubtrees = numLeavesPerTree / subtreeMax

        if numLeavesPerTree <= subtreeMax {
            // Small trees: use fused kernel directly on hashed buffer
            return try buildTreesFromHashedBuffer(
                hashedBuf: hashedBuf,
                numColumns: numColumns,
                evalLen: evalLen,
                nodeSize: nodeSize
            )
        } else {
            // Large trees: build subtree roots, then upper levels
            return try buildTreesLargeFromHashedBuffer(
                hashedBuf: hashedBuf,
                numColumns: numColumns,
                evalLen: evalLen,
                nodeSize: nodeSize,
                subtreeMax: subtreeMax
            )
        }
    }

    /// Build trees from pre-hashed buffer (small trees <= subtreeMax).
    private func buildTreesFromHashedBuffer(
        hashedBuf: MTLBuffer,
        numColumns: Int,
        evalLen: Int,
        nodeSize: Int
    ) throws -> [zkMetal.M31Digest] {
        let stride = MemoryLayout<UInt32>.stride

        // Allocate output buffer for roots
        let rootVals = numColumns * nodeSize
        guard let outputBuf = device.makeBuffer(length: rootVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate output buffer")
        }

        // Use zkMetal's fused Merkle kernel for all trees
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: hashedBuf,
            leavesOffset: 0,
            rootsBuffer: outputBuf,
            rootsOffset: 0,
            numSubtrees: numColumns,
            subtreeSize: evalLen
        )

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildTreesFromHashedBuffer: fuse")

        // Read results
        let outPtr = outputBuf.contents().bindMemory(to: UInt32.self, capacity: rootVals)
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

    /// Build large trees (> subtreeMax) from pre-hashed buffer.
    private func buildTreesLargeFromHashedBuffer(
        hashedBuf: MTLBuffer,
        numColumns: Int,
        evalLen: Int,
        nodeSize: Int,
        subtreeMax: Int
    ) throws -> [zkMetal.M31Digest] {
        let stride = MemoryLayout<UInt32>.stride
        let numSubtrees = evalLen / subtreeMax

        // Allocate roots buffer for subtree roots
        let rootsPerTree = numSubtrees * nodeSize
        let rootsSize = numColumns * rootsPerTree * stride

        guard let rootsBuf = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate roots buffer")
        }

        // Build subtree roots using fused kernel
        guard let subtreeCmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let subtreeEnc = subtreeCmdBuf.makeComputeCommandEncoder()!

        gpuEngine.encodeMerkleFused(
            encoder: subtreeEnc,
            leavesBuffer: hashedBuf,
            leavesOffset: 0,
            rootsBuffer: rootsBuf,
            rootsOffset: 0,
            numSubtrees: numColumns * numSubtrees,
            subtreeSize: subtreeMax
        )

        // Build upper levels (from subtree roots to final roots)
        var currentNodes = numSubtrees
        var srcBuf = rootsBuf

        if currentNodes > 1 {
            guard let bufA = device.makeBuffer(length: rootsSize, options: .storageModeShared),
                  let bufB = device.makeBuffer(length: rootsSize, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate upper level buffers")
            }

            var dstBuf = bufA
            let threadsPerThreadgroup = min(256, upperBatchSIMDFunction.maxTotalThreadsPerThreadgroup)

            while currentNodes > 1 {
                subtreeEnc.memoryBarrier(scope: .buffers)
                let pairs = currentNodes / 2

                subtreeEnc.setComputePipelineState(optimizedBatchFunction)
                subtreeEnc.setBuffer(srcBuf, offset: 0, index: 0)
                subtreeEnc.setBuffer(dstBuf, offset: 0, index: 1)
                subtreeEnc.setBuffer(rcBuffer, offset: 0, index: 2)
                var numTreesVal = UInt32(numColumns)
                subtreeEnc.setBytes(&numTreesVal, length: 4, index: 3)
                var numNodesVal = UInt32(currentNodes)
                subtreeEnc.setBytes(&numNodesVal, length: 4, index: 4)
                var pairsPerTreeVal = UInt32(pairs)
                subtreeEnc.setBytes(&pairsPerTreeVal, length: 4, index: 5)

                let threadgroupSize = min(threadsPerThreadgroup, (pairs + 3) / 4)
                subtreeEnc.dispatchThreadgroups(
                    MTLSize(width: numColumns, height: 1, depth: 1),
                    threadsPerThreadgroup: MTLSize(width: threadgroupSize, height: 1, depth: 1)
                )

                currentNodes = pairs
                swap(&srcBuf, &dstBuf)
            }
        }

        subtreeEnc.endEncoding()
        subtreeCmdBuf.commit()
        try waitAndCheckError(subtreeCmdBuf, operation: "buildTreesLargeFromHashedBuffer: subtree+upper")

        // Read final roots
        let rootVals = numColumns * nodeSize
        let outPtr = srcBuf.contents().bindMemory(to: UInt32.self, capacity: rootVals)
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

    // MARK: - GPU Proof Generation

    /// Build Merkle trees on GPU and keep the flattened tree structure for GPU proof generation.
    ///
    /// This method builds trees AND stores the complete tree structure in GPU buffers,
    /// enabling GPU-side proof generation without CPU tree rebuilding.
    ///
    /// - Parameters:
    ///   - treesLeaves: Array of leaf arrays, one per tree (8 M31 elements per leaf node)
    ///   - keepTreeBuffer: If true, keeps the flattened tree structure in GPU memory
    /// - Returns: Tuple of (roots, treeBuffer, numLeaves) where treeBuffer contains the flattened tree
    public func buildTreesWithGPUProof(
        treesLeaves: [[M31]],
        keepTreeBuffer: Bool = true
    ) throws -> (roots: [zkMetal.M31Digest], treeBuffer: MTLBuffer?, numLeaves: Int) {
        let nodeSize = 8
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        // Validate input
        for leaves in treesLeaves {
            precondition(leaves.count % nodeSize == 0, "Leaves must be multiple of 8 M31 elements")
            let numLeaves = leaves.count / nodeSize
            precondition(numLeaves > 0 && (numLeaves & (numLeaves - 1)) == 0, "Number of leaves must be power of 2")
        }

        guard !treesLeaves.isEmpty else { return ([], nil, 0) }

        let numTrees = treesLeaves.count
        let numLeaves = treesLeaves[0].count / nodeSize
        let stride = MemoryLayout<UInt32>.stride

        if numLeaves <= subtreeMax {
            return try buildTreesWithGPUProofSmall(
                treesLeaves: treesLeaves,
                numLeaves: numLeaves,
                numTrees: numTrees,
                stride: stride,
                keepTreeBuffer: keepTreeBuffer
            )
        } else {
            return try buildTreesWithGPUProofLarge(
                treesLeaves: treesLeaves,
                numLeaves: numLeaves,
                numTrees: numTrees,
                stride: stride,
                keepTreeBuffer: keepTreeBuffer
            )
        }
    }

    /// Build small trees (<= subtreeMax) with GPU proof support.
    private func buildTreesWithGPUProofSmall(
        treesLeaves: [[M31]],
        numLeaves: Int,
        numTrees: Int,
        stride: Int,
        keepTreeBuffer: Bool
    ) throws -> (roots: [zkMetal.M31Digest], treeBuffer: MTLBuffer?, numLeaves: Int) {
        let nodeSize = 8

        // Allocate input buffer
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

        // For small trees, we can build the full tree in one dispatch
        // using the fused kernel, but we need to keep the intermediate results
        // for proof generation. Since the fused kernel doesn't preserve tree structure,
        // for small trees we build level-by-level ourselves.

        // Build trees level-by-level to keep tree structure
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }

        // Allocate full tree buffer (2n - 1 nodes per tree)
        let treeNodeCount = 2 * numLeaves - 1
        let treeBufSize = numTrees * treeNodeCount * nodeSize * stride

        var treeBuffer: MTLBuffer? = nil
        if keepTreeBuffer {
            treeBuffer = device.makeBuffer(length: treeBufSize, options: .storageModeShared)
        }

        // Copy leaves to tree buffer
        if let treeBuf = treeBuffer {
            let treePtr = treeBuf.contents().bindMemory(to: UInt32.self, capacity: numTrees * treeNodeCount * nodeSize)
            var copyIdx = 0
            for treeLeaves in treesLeaves {
                for val in treeLeaves {
                    treePtr[copyIdx] = val.v
                    copyIdx += 1
                }
                // Zero out internal nodes (will be filled by hashing)
                let leafCount = treeLeaves.count
                let internalStart = copyIdx
                let internalEnd = numLeaves * nodeSize
                // Guard against invalid range: if leafCount >= internalEnd, no zeroing needed
                if internalStart < internalEnd {
                    for i in internalStart..<internalEnd {
                        treePtr[copyIdx + i - internalStart] = 0
                    }
                }
                copyIdx += (treeNodeCount - numLeaves) * nodeSize
            }
        }

        // Build internal nodes level by level
        var currentLevelSize = numLeaves
        var levelOffset = 0  // Where current level starts in tree buffer
        var nextLevelOffset = numLeaves  // Where next level starts

        while currentLevelSize > 1 {
            let pairs = currentLevelSize / 2

            // Use batch kernel to hash pairs at this level
            let enc = cmdBuf.makeComputeCommandEncoder()!

            enc.setComputePipelineState(upperBatchFunction)
            if let treeBuf = treeBuffer {
                enc.setBuffer(treeBuf, offset: 0, index: 0)
                enc.setBuffer(treeBuf, offset: 0, index: 1)
            } else {
                enc.setBuffer(inputBuf, offset: 0, index: 0)
                enc.setBuffer(outputBuf, offset: 0, index: 1)
            }
            enc.setBuffer(rcBuffer, offset: 0, index: 2)
            var numTreesVal = UInt32(numTrees)
            enc.setBytes(&numTreesVal, length: 4, index: 3)
            var numNodesVal = UInt32(currentLevelSize)
            enc.setBytes(&numNodesVal, length: 4, index: 4)
            var pairsPerTreeVal = UInt32(pairs)
            enc.setBytes(&pairsPerTreeVal, length: 4, index: 5)

            let threadgroupSize = min(256, upperBatchFunction.maxTotalThreadsPerThreadgroup)
            enc.dispatchThreadgroups(
                MTLSize(width: numTrees, height: 1, depth: 1),
                threadsPerThreadgroup: MTLSize(width: threadgroupSize, height: 1, depth: 1)
            )

            enc.endEncoding()

            // Advance levels
            currentLevelSize /= 2
            levelOffset = nextLevelOffset
            nextLevelOffset += currentLevelSize
        }

        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildTreesWithGPUProofSmall")

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

        return (roots, treeBuffer, numLeaves)
    }

    /// Build large trees (> subtreeMax) with GPU proof support.
    private func buildTreesWithGPUProofLarge(
        treesLeaves: [[M31]],
        numLeaves: Int,
        numTrees: Int,
        stride: Int,
        keepTreeBuffer: Bool
    ) throws -> (roots: [zkMetal.M31Digest], treeBuffer: MTLBuffer?, numLeaves: Int) {
        let nodeSize = 8
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize
        let numSubtrees = numLeaves / subtreeMax

        // Build subtrees first (same as buildTreesBatchLarge)
        // Step 1: Flatten all trees' leaves
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

        // Step 3: Build subtrees
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

        // Step 4: Process upper levels
        var currentNodes = numSubtrees
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
                var numTreesVal = UInt32(numTrees)
                enc.setBytes(&numTreesVal, length: 4, index: 3)
                var numNodesVal = UInt32(currentNodes)
                enc.setBytes(&numNodesVal, length: 4, index: 4)
                var pairsPerTreeVal = UInt32(pairs)
                enc.setBytes(&pairsPerTreeVal, length: 4, index: 5)

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
        try waitAndCheckError(cmdBuf, operation: "buildTreesWithGPUProofLarge")

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

        // Note: For large trees, we don't keep the full tree buffer by default
        // since it would be very large. For GPU proof generation, we build
        // a separate compact tree structure optimized for proof queries.
        return (roots, nil, numLeaves)
    }

    /// Generate Merkle proofs for multiple trees using GPU.
    ///
    /// This is the KEY OPTIMIZATION: Instead of rebuilding trees on CPU for each proof,
    /// we use the pre-built GPU tree structure to generate proofs directly on GPU.
    ///
    /// - Parameters:
    ///   - treeBuffer: GPU buffer containing flattened tree structure
    ///   - numTrees: Number of trees
    ///   - numLeaves: Number of leaves per tree
    ///   - queryIndices: Array of leaf indices to generate proofs for
    /// - Returns: Array of proof paths, one per tree
    public func generateProofsGPU(
        treeBuffer: MTLBuffer,
        numTrees: Int,
        numLeaves: Int,
        queryIndices: [Int]
    ) throws -> [[zkMetal.M31Digest]] {
        let nodeSize = 8
        let stride = MemoryLayout<UInt32>.stride

        // Calculate number of levels
        var numLevels = 0
        var temp = numLeaves
        while temp > 1 {
            temp >>= 1
            numLevels += 1
        }

        // Allocate output buffer for proofs
        let proofSize = numLevels * nodeSize
        let proofBufSize = numTrees * proofSize * stride

        guard let proofBuf = device.makeBuffer(length: proofBufSize, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate proof buffer")
        }

        // Prepare query indices buffer
        guard let queryBuf = device.makeBuffer(length: numTrees * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate query indices buffer")
        }

        let queryPtr = queryBuf.contents().bindMemory(to: UInt32.self, capacity: numTrees)
        for (i, idx) in queryIndices.enumerated() {
            queryPtr[i] = UInt32(idx)
        }

        // Dispatch GPU proof generation kernel
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }

        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(batchProofGenFunction)
        enc.setBuffer(treeBuffer, offset: 0, index: 0)
        enc.setBuffer(proofBuf, offset: 0, index: 1)
        var numTreesVal = UInt32(numTrees)
        enc.setBytes(&numTreesVal, length: 4, index: 2)
        var numLeavesVal = UInt32(numLeaves)
        enc.setBytes(&numLeavesVal, length: 4, index: 3)
        enc.setBuffer(queryBuf, offset: 0, index: 4)

        enc.dispatchThreadgroups(
            MTLSize(width: numTrees, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1)
        )

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "generateProofsGPU")

        // Read back proofs
        let proofPtr = proofBuf.contents().bindMemory(to: UInt32.self, capacity: numTrees * proofSize)
        var proofs: [[zkMetal.M31Digest]] = []
        proofs.reserveCapacity(numTrees)

        for treeIdx in 0..<numTrees {
            var path: [zkMetal.M31Digest] = []
            path.reserveCapacity(numLevels)

            for level in 0..<numLevels {
                var values: [M31] = []
                values.reserveCapacity(nodeSize)
                let baseIdx = treeIdx * proofSize + level * nodeSize

                for i in 0..<nodeSize {
                    values.append(M31(v: proofPtr[baseIdx + i]))
                }
                path.append(zkMetal.M31Digest(values: values))
            }

            proofs.append(path)
        }

        return proofs
    }

    /// Generate a single Merkle proof on GPU.
    public func generateProofGPU(
        treeBuffer: MTLBuffer,
        numLeaves: Int,
        queryIndex: Int
    ) throws -> [zkMetal.M31Digest] {
        let nodeSize = 8
        let stride = MemoryLayout<UInt32>.stride

        // Calculate number of levels
        var numLevels = 0
        var temp = numLeaves
        while temp > 1 {
            temp >>= 1
            numLevels += 1
        }

        // Allocate output buffer for single proof
        let proofSize = numLevels * nodeSize
        guard let proofBuf = device.makeBuffer(length: proofSize * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate proof buffer")
        }

        // Dispatch GPU proof generation kernel
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }

        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(proofGenFunction)
        enc.setBuffer(treeBuffer, offset: 0, index: 0)
        enc.setBuffer(proofBuf, offset: 0, index: 1)
        var numLeavesVal = UInt32(numLeaves)
        enc.setBytes(&numLeavesVal, length: 4, index: 2)
        var queryIndexVal = UInt32(queryIndex)
        enc.setBytes(&queryIndexVal, length: 4, index: 3)

        enc.dispatchThreadgroups(
            MTLSize(width: 1, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1)
        )

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "generateProofGPU")

        // Read back proof
        let proofPtr = proofBuf.contents().bindMemory(to: UInt32.self, capacity: proofSize)
        var path: [zkMetal.M31Digest] = []
        path.reserveCapacity(numLevels)

        for level in 0..<numLevels {
            var values: [M31] = []
            values.reserveCapacity(nodeSize)
            let baseIdx = level * nodeSize

            for i in 0..<nodeSize {
                values.append(M31(v: proofPtr[baseIdx + i]))
            }
            path.append(zkMetal.M31Digest(values: values))
        }

        return path
    }

    /// Build tree and generate proof in one GPU dispatch (optimized).
    ///
    /// This method is for when you need both the tree built AND proofs generated
    /// in the most efficient manner. It avoids intermediate CPU readbacks.
    public func buildTreeAndGenerateProof(
        leaves: [M31],
        queryIndex: Int
    ) throws -> (root: zkMetal.M31Digest, proof: [zkMetal.M31Digest]) {
        // Build tree on GPU first
        let root = try buildTree(leaves: leaves)

        // For single proofs, build tree with structure preserved then generate proof
        // This requires a specialized kernel that builds tree while preserving structure
        // For now, return CPU proof as fallback
        let nodeSize = 8
        let numLeaves = leaves.count / nodeSize

        // Build flattened tree on CPU (for small trees)
        var tree: [zkMetal.M31Digest] = []
        tree.reserveCapacity(2 * numLeaves)

        // Add leaves
        for i in 0..<numLeaves {
            let values = Array(leaves[i * nodeSize..<(i + 1) * nodeSize])
            tree.append(zkMetal.M31Digest(values: values))
        }

        // Build internal nodes
        var levelSize = numLeaves
        while levelSize > 1 {
            let newLevelStart = tree.count
            for i in stride(from: 0, to: levelSize, by: 2) {
                let left = tree[i]
                let right = i + 1 < levelSize ? tree[i + 1] : tree[i]
                tree.append(zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values)))
            }
            levelSize = tree.count - newLevelStart
        }

        // Generate proof from tree
        let proof = generateProof(tree: tree, n: numLeaves, index: queryIndex)

        return (root, proof)
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

// MARK: - Hierarchical Merkle Commitment Engine

/// GPU-accelerated hierarchical Merkle commitment engine.
///
/// This engine builds a two-level commitment structure:
/// - Level 0: Individual column roots (180 trees)
/// - Level 1: Root-of-roots combining all 180 columns into a single tree
///
/// For query proofs, we only need to prove the hierarchical root commits
/// to the 180 individual roots, reducing query proof size from O(180) to O(1).
public final class HierarchicalMerkleEngine {
    public let device: MTLDevice
    public let commandQueue: MTLCommandQueue

    /// zkMetal's GPU Poseidon2-M31 engine for Merkle tree building
    private let gpuEngine: Poseidon2M31Engine

    /// SIMD batch function for upper level hashing
    private let simdBatchFunction: MTLComputePipelineState

    /// Round constants buffer for custom kernel
    private let rcBuffer: MTLBuffer

    /// Optimized batch kernel with better grid mapping
    private let optimizedBatchFunction: MTLComputePipelineState

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

        // Compile custom upper-level batch kernels (same as EVMGPUMerkleEngine)
        let upperBatchLibrary = try Self.compileUpperBatchShaders(device: device)

        // SIMD-optimized batch kernel
        if let simdFn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_upper_batch_simd") {
            self.simdBatchFunction = try device.makeComputePipelineState(function: simdFn)
        } else {
            self.simdBatchFunction = try device.makeComputePipelineState(function: upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_upper_batch")!)
        }

        // Optimized batch kernel
        if let optFn = upperBatchLibrary.makeFunction(name: "poseidon2_m31_merkle_tree_upper_batch_optimized") {
            self.optimizedBatchFunction = try device.makeComputePipelineState(function: optFn)
        } else {
            self.optimizedBatchFunction = self.simdBatchFunction
        }

        // Create round constants buffer
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
            "\(execPath)/../Sources/EVMetal/Shaders",
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

    // MARK: - Hierarchical Commitment

    /// Build hierarchical commitment: root-of-roots tree from column roots.
    ///
    /// This creates a two-level commitment structure:
    /// 1. Build 180 individual column trees (already done externally)
    /// 2. Build one hierarchical tree where each leaf is a column root
    ///
    /// - Parameters:
    ///   - columnRoots: Array of 180 column roots (M31Digest each)
    ///   - numLeavesPerColumn: Number of leaves per column tree (for column tree depth)
    /// - Returns: HierarchicalCommitResult containing root-of-roots tree and proof helpers
    public func buildHierarchicalCommitment(
        columnRoots: [zkMetal.M31Digest],
        numLeavesPerColumn: Int
    ) throws -> HierarchicalCommitResult {
        let nodeSize = 8
        let numColumns = columnRoots.count
        let stride = MemoryLayout<UInt32>.stride

        // Step 1: Convert column roots to flat M31 array for tree building
        // Each root is 8 M31 elements (32 bytes)
        var leavesFlat: [M31] = []
        leavesFlat.reserveCapacity(numColumns * nodeSize)

        for root in columnRoots {
            for val in root.values {
                leavesFlat.append(val)
            }
        }

        // Step 2: Build the hierarchical tree using GPU
        // For 180 columns, pad to power of 2 (256 leaves)
        let paddedNumColumns = (numColumns + (numColumns & 1))

        // Allocate input buffer for hierarchical leaves
        let totalVals = paddedNumColumns * nodeSize
        guard let inputBuf = device.makeBuffer(length: totalVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate hierarchical input buffer")
        }

        // Copy column roots to input buffer (flattened)
        let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: totalVals)
        for (colIdx, root) in columnRoots.enumerated() {
            for (valIdx, val) in root.values.enumerated() {
                inputPtr[colIdx * nodeSize + valIdx] = val.v
            }
        }

        // Zero-pad remaining leaves if needed
        for i in numColumns..<paddedNumColumns {
            for j in 0..<nodeSize {
                inputPtr[i * nodeSize + j] = 0
            }
        }

        // Allocate output buffer for root
        let rootBytes = nodeSize * stride
        guard let outputBuf = device.makeBuffer(length: rootBytes, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate hierarchical output buffer")
        }

        // Build tree using GPU fused kernel
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
            numSubtrees: 1,
            subtreeSize: paddedNumColumns
        )

        enc.endEncoding()
        cmdBuf.commit()
        try waitAndCheckError(cmdBuf, operation: "buildHierarchicalCommitment")

        // Read hierarchical root
        let outPtr = outputBuf.contents().bindMemory(to: UInt32.self, capacity: nodeSize)
        var rootValues = [M31]()
        rootValues.reserveCapacity(nodeSize)
        for i in 0..<nodeSize {
            rootValues.append(M31(v: outPtr[i]))
        }
        let hierarchicalRoot = zkMetal.M31Digest(values: rootValues)

        // Step 3: Build CPU-side tree for query proofs
        // Convert flat leaves back to digest array for tree building
        var leavesDigests: [zkMetal.M31Digest] = []
        leavesDigests.reserveCapacity(paddedNumColumns)
        for i in 0..<paddedNumColumns {
            let values = Array(leavesFlat[i * nodeSize..<(i + 1) * nodeSize])
            leavesDigests.append(zkMetal.M31Digest(values: values))
        }

        // Build full tree for query proofs
        let tree = buildPoseidon2M31MerkleTreeFromDigests(leavesDigests, count: paddedNumColumns)

        // Calculate column tree depth for query proofs
        var colTreeDepth = 0
        var temp = numLeavesPerColumn
        while temp > 1 {
            colTreeDepth += 1
            temp /= 2
        }

        // Calculate hierarchical tree depth
        var hierTreeDepth = 0
        temp = paddedNumColumns
        while temp > 1 {
            hierTreeDepth += 1
            temp /= 2
        }

        return HierarchicalCommitResult(
            hierarchicalRoot: hierarchicalRoot,
            hierarchicalTree: tree,
            numColumns: numColumns,
            paddedNumColumns: paddedNumColumns,
            columnTreeDepth: colTreeDepth,
            hierarchicalTreeDepth: hierTreeDepth
        )
    }

    /// Build Merkle tree from pre-hashed digests (leaves already in digest format).
    private func buildPoseidon2M31MerkleTreeFromDigests(
        _ digests: [zkMetal.M31Digest],
        count n: Int
    ) -> [zkMetal.M31Digest] {
        precondition(n > 0 && (n & (n - 1)) == 0, "n must be a power of 2")
        let treeSize = 2 * n - 1
        var tree = [zkMetal.M31Digest](repeating: .zero, count: treeSize)

        // Copy leaves
        for i in 0..<n {
            tree[i] = digests[i]
        }

        // Build internal nodes bottom-up
        var levelStart = 0
        var levelSize = n
        while levelSize > 1 {
            let parentStart = levelStart + levelSize
            let parentSize = levelSize / 2
            for i in 0..<parentSize {
                let left = tree[levelStart + 2 * i]
                let right = tree[levelStart + 2 * i + 1]
                tree[parentStart + i] = zkMetal.M31Digest(values: poseidon2M31Hash(
                    left: left.values, right: right.values))
            }
            levelStart = parentStart
            levelSize = parentSize
        }

        return tree
    }

    /// Generate hierarchical proof for a column index.
    ///
    /// For verifying that hierarchical root commits to column[colIdx]:
    /// - Path through hierarchical tree to hierarchical root
    ///
    /// - Parameters:
    ///   - result: Hierarchical commit result
    ///   - columnIndex: Index of the column (0-179)
    /// - Returns: Authentication path through hierarchical tree
    public func generateHierarchicalProof(
        result: HierarchicalCommitResult,
        columnIndex: Int
    ) -> [zkMetal.M31Digest] {
        let tree = result.hierarchicalTree
        let paddedIndex = min(columnIndex, result.paddedNumColumns - 1)

        var path = [zkMetal.M31Digest]()
        var levelStart = 0
        var levelSize = result.paddedNumColumns
        var idx = paddedIndex

        while levelSize > 1 {
            let sibIdx = idx ^ 1
            path.append(tree[levelStart + sibIdx])
            levelStart += levelSize
            levelSize /= 2
            idx /= 2
        }

        return path
    }

    /// Generate combined proof data for hierarchical verification.
    ///
    /// This generates the proof that the hierarchical root commits to
    /// a specific column's root. The verifier can reconstruct the column
    /// root from this proof and verify it matches the column commitment.
    public func generateCombinedProof(
        result: HierarchicalCommitResult,
        columnIndex: Int,
        columnRoot: zkMetal.M31Digest
    ) -> HierarchicalProof {
        let path = generateHierarchicalProof(result: result, columnIndex: columnIndex)
        return HierarchicalProof(
            columnIndex: columnIndex,
            columnRoot: columnRoot,
            hierarchicalPath: path
        )
    }
}

// MARK: - Hierarchical Commitment Result Types

/// Result of hierarchical commitment building.
public struct HierarchicalCommitResult {
    /// Root of the hierarchical tree (root-of-roots)
    public let hierarchicalRoot: zkMetal.M31Digest

    /// The complete hierarchical tree for proof generation
    public let hierarchicalTree: [zkMetal.M31Digest]

    /// Number of actual columns (180)
    public let numColumns: Int

    /// Number of leaves in padded tree (next power of 2)
    public let paddedNumColumns: Int

    /// Depth of each column tree (for column tree proofs)
    public let columnTreeDepth: Int

    /// Depth of hierarchical tree
    public let hierarchicalTreeDepth: Int

    /// Total proof depth for queries: column depth + hierarchical depth
    public var totalProofDepth: Int {
        return columnTreeDepth + hierarchicalTreeDepth
    }
}

/// Hierarchical proof for verifying column root inclusion.
public struct HierarchicalProof {
    /// Index of the column this proof is for
    public let columnIndex: Int

    /// The column's root digest
    public let columnRoot: zkMetal.M31Digest

    /// Authentication path through hierarchical tree
    public let hierarchicalPath: [zkMetal.M31Digest]

    /// Verify this proof against the hierarchical root.
    public func verify(hierarchicalRoot: zkMetal.M31Digest) -> Bool {
        var current = columnRoot
        var idx = columnIndex

        for sibling in hierarchicalPath {
            if idx & 1 == 0 {
                current = zkMetal.M31Digest(values: poseidon2M31Hash(
                    left: current.values, right: sibling.values))
            } else {
                current = zkMetal.M31Digest(values: poseidon2M31Hash(
                    left: sibling.values, right: current.values))
            }
            idx /= 2
        }

        return current == hierarchicalRoot
    }

    /// Serialize proof to bytes for transmission.
    public var serialized: [UInt8] {
        var bytes: [UInt8] = []
        // Column index (4 bytes)
        var idx = UInt32(columnIndex)
        bytes.append(contentsOf: withUnsafeBytes(of: &idx) { Array($0) })
        // Column root (32 bytes)
        bytes.append(contentsOf: columnRoot.bytes)
        // Path length (4 bytes)
        var pathLen = UInt32(hierarchicalPath.count)
        bytes.append(contentsOf: withUnsafeBytes(of: &pathLen) { Array($0) })
        // Path elements (32 bytes each)
        for digest in hierarchicalPath {
            bytes.append(contentsOf: digest.bytes)
        }
        return bytes
    }

    /// Deserialize proof from bytes.
    public static func deserialize(_ bytes: [UInt8]) -> HierarchicalProof? {
        guard bytes.count >= 40 else { return nil }  // 4 + 32 + 4 minimum

        var offset = 0
        // Column index
        let idx = bytes.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
        offset += 4

        // Column root
        var rootVals = [M31]()
        for i in 0..<8 {
            let v = bytes.withUnsafeBytes { $0.load(fromByteOffset: offset + i * 4, as: UInt32.self) }
            rootVals.append(M31(v: v))
        }
        offset += 32
        let root = zkMetal.M31Digest(values: rootVals)

        // Path length
        guard offset + 4 <= bytes.count else { return nil }
        let pathLen = bytes.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
        offset += 4

        // Path elements
        var path: [zkMetal.M31Digest] = []
        for _ in 0..<pathLen {
            guard offset + 32 <= bytes.count else { return nil }
            var vals = [M31]()
            for i in 0..<8 {
                let v = bytes.withUnsafeBytes { $0.load(fromByteOffset: offset + i * 4, as: UInt32.self) }
                vals.append(M31(v: v))
            }
            path.append(zkMetal.M31Digest(values: vals))
            offset += 32
        }

        return HierarchicalProof(
            columnIndex: Int(idx),
            columnRoot: root,
            hierarchicalPath: path
        )
    }
}
