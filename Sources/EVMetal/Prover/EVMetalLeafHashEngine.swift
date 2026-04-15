import Foundation
import Metal
import zkMetal

/// GPU engine for Poseidon2-M31 leaf hashing with position.
/// This matches the CPU tree builder's leaf hashing scheme.
public final class EVMetalLeafHashEngine {

    public let device: MTLDevice
    public let commandQueue: MTLCommandQueue

    private let hashLeavesFunction: MTLComputePipelineState
    private let hashPairsFunction: MTLComputePipelineState
    private let rcBuffer: MTLBuffer

    public static let nodeSize = 8  // M31 elements per digest

    public init() throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUProverError.noGPU
        }
        self.device = device

        guard let queue = device.makeCommandQueue() else {
            throw GPUProverError.noCommandQueue
        }
        self.commandQueue = queue

        // Compile shaders
        let library = try Self.compileShaders(device: device)

        guard let hashFn = library.makeFunction(name: "poseidon2_m31_hash_leaves_with_position"),
              let pairsFn = library.makeFunction(name: "poseidon2_m31_hash_pairs") else {
            throw GPUProverError.missingKernel
        }

        self.hashLeavesFunction = try device.makeComputePipelineState(function: hashFn)
        self.hashPairsFunction = try device.makeComputePipelineState(function: pairsFn)

        // Create round constants buffer (same as Poseidon2M31Engine)
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

    private static func compileShaders(device: MTLDevice) throws -> MTLLibrary {
        let shaderPath = "/Users/carnation/Documents/Claude/EVMetal/Sources/EVMetal/Shaders/hash/poseidon2_m31_leaf_hash.metal"

        guard FileManager.default.fileExists(atPath: shaderPath) else {
            throw GPUProverError.missingKernel
        }

        let source = try String(contentsOfFile: shaderPath, encoding: .utf8)
        let options = MTLCompileOptions()
        options.fastMathEnabled = true
        options.languageVersion = .version2_0

        return try device.makeLibrary(source: source, options: options)
    }

    /// Number of leaves processed per thread in the SIMD kernel
    private static let leavesPerThread = 4

    /// Hash individual M31 values with position to create leaf digests.
    /// Uses SIMD-optimized kernel processing multiple leaves per thread.
    /// Output: array of digests, each digest is 8 M31 elements.
    public func hashLeavesWithPosition(
        values: [M31],
        positions: [UInt32]
    ) throws -> [M31] {
        let count = values.count
        precondition(count == positions.count, "values and positions must have same count")

        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride

        // Allocate buffers
        guard let valuesBuf = device.makeBuffer(length: count * stride, options: .storageModeShared),
              let positionsBuf = device.makeBuffer(length: count * stride, options: .storageModeShared),
              let digestsBuf = device.makeBuffer(length: count * digestStride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate buffers")
        }

        // Copy values
        values.withUnsafeBytes { src in
            memcpy(valuesBuf.contents(), src.baseAddress!, count * stride)
        }

        // Copy positions
        positions.withUnsafeBytes { src in
            memcpy(positionsBuf.contents(), src.baseAddress!, count * stride)
        }

        // GPU dispatch with SIMD optimization (multiple leaves per thread)
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(hashLeavesFunction)
        enc.setBuffer(valuesBuf, offset: 0, index: 0)
        enc.setBuffer(positionsBuf, offset: 0, index: 1)
        enc.setBuffer(digestsBuf, offset: 0, index: 2)
        enc.setBuffer(rcBuffer, offset: 0, index: 3)
        var cnt = UInt32(count)
        enc.setBytes(&cnt, length: 4, index: 4)

        // SIMD kernel processes multiple leaves per thread
        let leavesPerThread = Self.leavesPerThread
        let threadsPerTG = min(hashLeavesFunction.maxTotalThreadsPerThreadgroup, 256)
        let leavesPerTG = threadsPerTG * leavesPerThread
        let numThreadgroups = (count + leavesPerTG - 1) / leavesPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: count * 8)
        var digests = [M31]()
        digests.reserveCapacity(count * 8)
        for i in 0..<(count * 8) {
            digests.append(M31(v: ptr[i]))
        }

        return digests
    }

    /// Hash all leaves from multiple columns in a single GPU dispatch.
    /// This is much faster than calling hashLeavesWithPosition for each column separately.
    /// Uses SIMD-optimized kernel processing multiple leaves per thread.
    /// Each column's leaves are at positions [colOffset, colOffset + countPerColumn).
    public func hashLeavesBatchPerColumn(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        let totalCount = numColumns * countPerColumn

        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride

        // Allocate buffers
        guard let valuesBuf = device.makeBuffer(length: totalCount * stride, options: .storageModeShared),
              let positionsBuf = device.makeBuffer(length: totalCount * stride, options: .storageModeShared),
              let digestsBuf = device.makeBuffer(length: totalCount * digestStride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate buffers")
        }

        // Copy values and create positions
        var flatValues = [UInt32]()
        var flatPositions = [UInt32]()
        flatValues.reserveCapacity(totalCount)
        flatPositions.reserveCapacity(totalCount)

        for col in 0..<numColumns {
            let colOffset = col * countPerColumn
            for i in 0..<countPerColumn {
                flatValues.append(allValues[colOffset + i].v)
                flatPositions.append(UInt32(colOffset + i))
            }
        }

        // Copy to buffers
        flatValues.withUnsafeBytes { src in
            memcpy(valuesBuf.contents(), src.baseAddress!, totalCount * stride)
        }
        flatPositions.withUnsafeBytes { src in
            memcpy(positionsBuf.contents(), src.baseAddress!, totalCount * stride)
        }

        // GPU dispatch with SIMD optimization
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(hashLeavesFunction)
        enc.setBuffer(valuesBuf, offset: 0, index: 0)
        enc.setBuffer(positionsBuf, offset: 0, index: 1)
        enc.setBuffer(digestsBuf, offset: 0, index: 2)
        enc.setBuffer(rcBuffer, offset: 0, index: 3)
        var totalCnt = UInt32(totalCount)
        enc.setBytes(&totalCnt, length: 4, index: 4)

        // SIMD kernel processes multiple leaves per thread
        let leavesPerThread = Self.leavesPerThread
        let threadsPerTG = min(hashLeavesFunction.maxTotalThreadsPerThreadgroup, 256)
        let leavesPerTG = threadsPerTG * leavesPerThread
        let numThreadgroups = (totalCount + leavesPerTG - 1) / leavesPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results and split by column
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount * 8)
        var results: [[M31]] = []
        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)
            for i in 0..<(countPerColumn * 8) {
                let idx = (col * countPerColumn * 8) + i
                columnDigests.append(M31(v: ptr[idx]))
            }
            results.append(columnDigests)
        }

        return results
    }

    /// Build complete Merkle tree from individual M31 values using GPU + CPU.
    /// GPU hashes leaves with position, CPU builds tree from digests.
    ///
    /// - Parameters:
    ///   - values: Individual M31 values (one per leaf)
    ///   - numLeaves: Number of leaves (power of 2)
    /// - Returns: Root digest (8 M31 elements)
    public func buildMerkleTree(
        values: [M31],
        numLeaves: Int
    ) throws -> zkMetal.M31Digest {
        precondition(numLeaves > 0 && (numLeaves & (numLeaves - 1)) == 0, "numLeaves must be power of 2")
        precondition(values.count >= numLeaves, "Not enough values for numLeaves")

        // Step 1: GPU hashes leaves with position
        let leafValues = Array(values.prefix(numLeaves))
        let positions = (0..<numLeaves).map { UInt32($0) }
        let digests = try hashLeavesWithPosition(values: leafValues, positions: positions)

        // Step 2: CPU builds tree from digests
        // Each digest is 8 M31 elements
        var nodes: [zkMetal.M31Digest] = []
        for i in 0..<numLeaves {
            let start = i * 8
            let digestValues = Array(digests[start..<start + 8])
            nodes.append(zkMetal.M31Digest(values: digestValues))
        }

        // Build tree bottom-up
        var levelSize = numLeaves
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

        return nodes[0]
    }
}
