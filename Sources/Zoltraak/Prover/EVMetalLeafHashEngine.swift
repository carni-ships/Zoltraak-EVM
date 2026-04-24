import Foundation
import Metal
import zkMetal

/// GPU engine for Poseidon2-M31 leaf hashing with position.
/// This matches the CPU tree builder's leaf hashing scheme.
///
/// Memory optimizations H2-H5:
/// - H2: Memory Coalescing - restructured data layout for better GPU memory access
/// - H3: Shared Memory Usage - cache position lookups in GPU shared memory
/// - H4: Pre-compute Position Hashes - reuse position hash inputs across columns
/// - H5: Half-Precision - 16-bit storage for M31 values where possible
///
/// Buffer pooling for reusable GPU buffers
/// Pre-allocated temporary buffers to avoid per-call allocations
/// Efficient buffer reuse across multiple hashing operations
public final class ZoltraakLeafHashEngine {

    public let device: MTLDevice
    public let commandQueue: MTLCommandQueue

    private let hashLeavesFunction: MTLComputePipelineState
    private let hashPairsFunction: MTLComputePipelineState
    private let rcBuffer: MTLBuffer

    // H2-H5: Additional optimized kernels
    private let hashLeavesOptimizedFunction: MTLComputePipelineState?
    private let hashLeavesHalfFunction: MTLComputePipelineState?
    private let hashLeavesTransposedFunction: MTLComputePipelineState?
    private let hashLeavesCombinedFunction: MTLComputePipelineState?
    private let precomputePositionsFunction: MTLComputePipelineState?
    private let hashLeavesPrecomputedFunction: MTLComputePipelineState?

    // Shared memory pool for position caching (H3)
    private var sharedPositionCachePool: [MTLBuffer] = []

    // H4: Precomputed position hash states (P2M31_T=16 values per position)
    private var precomputedPositionStates: [MTLBuffer] = []
    private static let poseidonT = 16  // P2M31_T from shader

    /// Use SIMD group cooperative kernel (faster but requires threadgroup sync)
    /// Note: Currently disabled - SIMD kernel had Metal compilation issues
    public var useSIMDCooperative: Bool = false { didSet { _ = useSIMDCooperative } }

    // MARK: - Buffer Pool for Memory Optimization

    /// Simple buffer pool to reuse GPU buffers across operations
    private struct BufferPool {
        private var buffers: [MTLBuffer] = []
        private let maxSize: Int

        init(maxSize: Int = 10) {
            self.maxSize = maxSize
        }

        mutating func obtain(device: MTLDevice, length: Int, options: MTLResourceOptions) -> MTLBuffer? {
            // Try to find a suitable buffer in the pool
            for i in 0..<buffers.count {
                if buffers[i].length >= length {
                    let buffer = buffers.remove(at: i)
                    return buffer
                }
            }
            // No suitable buffer found, create new one
            return device.makeBuffer(length: length, options: options)
        }

        mutating func returnBuffer(_ buffer: MTLBuffer) {
            if buffers.count < maxSize {
                buffers.append(buffer)
            }
            // Otherwise, let it be deallocated
        }
    }

    private var inputBufferPool = BufferPool(maxSize: 5)
    private var outputBufferPool = BufferPool(maxSize: 5)
    private var positionStatesBufferPool = BufferPool(maxSize: 3)  // Pool for H4 precomputed states

    public static let nodeSize = 8  // M31 elements per digest

    // MARK: - Optimization Level

    /// Optimization level for leaf hashing
    public enum OptimizationLevel: Int {
        case basic = 0      // Original kernel
        case coalesced = 1  // H2: Memory coalescing
        case sharedMem = 2  // H2+H3: Memory coalescing + shared memory
        case precomputed = 3 // H2+H3+H4: Add position precomputation
        case halfPrecision = 4 // H2+H3+H5: Half precision storage
        case combined = 5   // H2+H3+H4+H5: All optimizations combined
    }

    /// Current optimization level (default: sharedMem for best balance)
    public var optimizationLevel: OptimizationLevel = .sharedMem

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

        // H2-H5: Try to compile optimized kernels (may fail on some GPUs)
        self.hashLeavesOptimizedFunction = try? Self.createKernel(library: library, device: device, name: "poseidon2_m31_hash_leaves_optimized")
        self.hashLeavesHalfFunction = try? Self.createKernel(library: library, device: device, name: "poseidon2_m31_hash_leaves_half")
        self.hashLeavesTransposedFunction = try? Self.createKernel(library: library, device: device, name: "poseidon2_m31_hash_leaves_transposed")
        self.hashLeavesCombinedFunction = try? Self.createKernel(library: library, device: device, name: "poseidon2_m31_hash_leaves_combined")
        self.precomputePositionsFunction = try? Self.createKernel(library: library, device: device, name: "poseidon2_m31_precompute_positions")
        self.hashLeavesPrecomputedFunction = try? Self.createKernel(library: library, device: device, name: "poseidon2_m31_hash_leaves_precomputed")

        // Pre-allocate shared memory pools for position caching (H3)
        let cacheSize = 1024 * MemoryLayout<UInt32>.stride  // 1024 positions
        for _ in 0..<4 {
            if let cache = device.makeBuffer(length: cacheSize, options: .storageModeShared) {
                sharedPositionCachePool.append(cache)
            }
        }

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

    private static func createKernel(library: MTLLibrary, device: MTLDevice, name: String) throws -> MTLComputePipelineState {
        guard let fn = library.makeFunction(name: name) else {
            throw GPUProverError.missingKernel
        }
        return try device.makeComputePipelineState(function: fn)
    }

    private static func compileShaders(device: MTLDevice) throws -> MTLLibrary {
        let shaderPath = "/Users/carnation/Documents/Claude/EVMetal/Sources/Zoltraak/Shaders/hash/poseidon2_m31_leaf_hash.metal"

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
    /// Set to 1 since the kernel now processes 1 leaf per thread with position= gid
    private static let leavesPerThread = 1

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

        // Convert values to UInt32 array for efficient buffer transfer
        var valuesUInt32 = [UInt32](repeating: 0, count: count)
        for i in 0..<count {
            valuesUInt32[i] = values[i].v
        }

        var positionsUInt32 = [UInt32](repeating: 0, count: count)
        for i in 0..<count {
            positionsUInt32[i] = positions[i]
        }

        // Allocate buffers with optimized storage mode
        // Using makeBuffer(bytes:) is more efficient than allocate + memcpy
        guard let valuesBuf = device.makeBuffer(bytes: valuesUInt32,
                                                      length: count * stride,
                                                      options: .storageModeShared),
              let positionsBuf = device.makeBuffer(bytes: positionsUInt32,
                                                          length: count * stride,
                                                          options: .storageModeShared),
              let digestsBuf = device.makeBuffer(length: count * digestStride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate buffers")
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
        let maxThreads = hashLeavesFunction.maxTotalThreadsPerThreadgroup
        let threadsPerTG = min(maxThreads, 256)
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

    /// Hash all leaves from multiple columns in a single GPU dispatch with buffer pooling.
    /// This is much faster than calling hashLeavesWithPosition for each column separately.
    /// Uses SIMD-optimized kernel processing multiple leaves per thread.
    ///
    /// Memory optimizations:
    /// - Buffer pooling reduces allocation overhead
    /// - Pre-sized arrays avoid dynamic growth
    /// - Efficient data layout for GPU access
    ///
    /// Data layout: interleaved by position (not by column).
    /// For 4 columns x 16 leaves: [col0_pos0, col1_pos0, col2_pos0, col3_pos0, col0_pos1, ...]
    /// Each column's leaves are at positions [0, countPerColumn).
    public func hashLeavesBatchPerColumn(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        let totalCount = numColumns * countPerColumn

        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride

        // Pre-allocate flat arrays for efficient memory layout
        var flatValues = [UInt32](repeating: 0, count: totalCount)
        var flatPositions = [UInt32](repeating: 0, count: totalCount)

        // Build flat arrays in column-major layout
        // Layout: [col0_pos0, col0_pos1, ..., col0_posN, col1_pos0, col1_pos1, ...]
        // Position for each value is its index within its column (0, 1, 2, ... countPerColumn-1)
        for col in 0..<numColumns {
            let srcBase = col * countPerColumn
            for i in 0..<countPerColumn {
                flatValues[srcBase + i] = allValues[srcBase + i].v
                flatPositions[srcBase + i] = UInt32(i)  // Per-column position (0, 1, 2, ...)
            }
        }

        // Allocate ALL buffers directly (not from pool) to avoid size mismatch issues
        let valuesBufLength = totalCount * stride
        let positionsBufLength = totalCount * stride
        let digestsBufLength = totalCount * digestStride

        guard let valuesBuf = device.makeBuffer(length: valuesBufLength, options: .storageModeShared),
              let positionsBuf = device.makeBuffer(length: positionsBufLength, options: .storageModeShared),
              let digestsBuf = device.makeBuffer(length: digestsBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate buffers")
        }

        // Copy data to buffers
        memcpy(valuesBuf.contents(), flatValues, valuesBufLength)
        memcpy(positionsBuf.contents(), flatPositions, positionsBufLength)

        // Debug: verify buffer contents
        let vPtr = valuesBuf.contents().bindMemory(to: UInt32.self, capacity: 8)
        let pPtr = positionsBuf.contents().bindMemory(to: UInt32.self, capacity: 8)
        print("    [GPU Leaf Hash] values buffer: [\(vPtr[0]), \(vPtr[1]), \(vPtr[2]), \(vPtr[3])]")
        print("    [GPU Leaf Hash] positions buffer: [\(pPtr[0]), \(pPtr[1]), \(pPtr[2]), \(pPtr[3])]")

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

        // Kernel processes 1 leaf per thread
        let threadsPerTG = min(hashLeavesFunction.maxTotalThreadsPerThreadgroup, 256)
        let numThreadgroups = (totalCount + threadsPerTG - 1) / threadsPerTG
        print("    [GPU dispatch] threadsPerTG=\(threadsPerTG), numThreadgroups=\(numThreadgroups)")
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results and split by column
        // GPU output is in column-major layout: [col0_pos0_0..7, col0_pos1_0..7, ..., col1_pos0_0..7, ...]
        // For column=col and position=i: base = (col * countPerColumn + i) * 8
        let resultsCount = totalCount * 8

        // Verify buffer size before binding (critical for safety)
        guard digestsBuf.length >= resultsCount * stride else {
            throw GPUProverError.gpuError("Digest buffer too small: buffer=\(digestsBuf.length), need=\(resultsCount * stride)")
        }

        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: resultsCount)
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)

        // Extract digests by column from column-major GPU output
        // For column=col and position=i: base = (col * countPerColumn + i) * 8
        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)
            for i in 0..<countPerColumn {
                let baseIdx = (col * countPerColumn + i) * 8
                // Bounds check for safety (in case GPU didn't write all data)
                if baseIdx + 8 > resultsCount {
                    throw GPUProverError.gpuError("Index out of bounds: baseIdx=\(baseIdx), resultsCount=\(resultsCount)")
                }
                for j in 0..<8 {
                    columnDigests.append(M31(v: ptr[baseIdx + j]))
                }
            }
            results.append(columnDigests)
        }

        // Return input buffers to pool for reuse (output buffer is not pooled)
        inputBufferPool.returnBuffer(valuesBuf)
        inputBufferPool.returnBuffer(positionsBuf)
        // Note: digestsBuf is not returned to pool since it's created directly
        // and has variable size requirements

        return results
    }

    /// Hash all leaves from multiple columns in interleaved layout for SINGLE tree building.
    ///
    /// This is the KEY OPTIMIZATION for maximizing GPU parallelism:
    /// - Instead of 180 trees × 16,384 leaves (180 separate trees)
    /// - We use 1 tree × (180 × 16,384) leaves (single combined tree)
    ///
    /// Data layout: interleaved by column position.
    /// For 180 columns × 16,384 leaves:
    ///   [col0_leaf0, col1_leaf0, ..., col179_leaf0, col0_leaf1, col1_leaf1, ...]
    ///
    /// Positions are GLOBAL (0 to totalLeaves-1) for single tree compatibility.
    /// Each digest is 8 M31 elements.
    ///
    /// - Parameters:
    ///   - allValues: All column values interleaved: [col0_v0, col1_v0, ..., colN_v0, col0_v1, ...]
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of values per column
    /// - Returns: Flat array of digests (8 M31 elements per leaf), suitable for single tree
    public func hashLeavesInterleaved(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [M31] {
        let totalCount = numColumns * countPerColumn
        precondition(allValues.count == totalCount, "allValues must contain numColumns * countPerColumn elements")

        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride

        // Pre-allocate flat arrays
        var flatValues = [UInt32](repeating: 0, count: totalCount)
        var flatPositions = [UInt32](repeating: 0, count: totalCount)

        // Interleave by column: [col0_v0, col1_v0, ..., colN_v0, col0_v1, ...]
        // Positions are GLOBAL: 0, 1, 2, ..., totalCount-1
        for col in 0..<numColumns {
            let srcBase = col * countPerColumn
            for i in 0..<countPerColumn {
                let dst = i * numColumns + col
                flatValues[dst] = allValues[srcBase + i].v
                // Global position for single tree
                flatPositions[dst] = UInt32(srcBase + i)
            }
        }

        // Allocate buffers using pool for efficiency
        let valuesBufLength = totalCount * stride
        let positionsBufLength = totalCount * stride
        let digestsBufLength = totalCount * digestStride

        guard let valuesBuf = inputBufferPool.obtain(device: device, length: valuesBufLength, options: .storageModeShared),
              let positionsBuf = inputBufferPool.obtain(device: device, length: positionsBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffers")
        }

        // Create digest buffer directly (avoid pool reuse issues)
        guard let digestsBuf = device.makeBuffer(length: digestsBufLength, options: .storageModeShared) else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to allocate digest buffer")
        }

        // Copy data to buffers
        memcpy(valuesBuf.contents(), flatValues, valuesBufLength)
        memcpy(positionsBuf.contents(), flatPositions, positionsBufLength)

        // GPU dispatch
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

        // Read results as flat array (no per-column splitting needed)
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount * 8)
        var results = [M31]()
        results.reserveCapacity(totalCount * 8)

        for i in 0..<(totalCount * 8) {
            results.append(M31(v: ptr[i]))
        }

        // Return input buffers to pool for reuse
        inputBufferPool.returnBuffer(valuesBuf)
        inputBufferPool.returnBuffer(positionsBuf)
        // Note: digestsBuf is not pooled due to variable size requirements

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

    // MARK: - H2-H5 Optimized Hashing Methods

    /// Hash leaves with H2+H3 optimization (memory coalescing + shared memory)
    /// Uses the optimized kernel with position caching in shared memory
    ///
    /// - Parameters:
    ///   - allValues: All column values in transposed layout
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of leaves per column
    /// - Returns: Array of digests per column
    public func hashLeavesOptimizedH2H3(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        let totalCount = numColumns * countPerColumn
        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride

        // Allocate buffers - input buffers use pool, output buffer is allocated directly
        let valuesBufLength = totalCount * stride
        let positionsBufLength = countPerColumn * stride  // Positions are shared across columns
        let digestsBufLength = totalCount * digestStride

        guard let valuesBuf = inputBufferPool.obtain(device: device, length: valuesBufLength, options: .storageModeShared),
              let positionsBuf = inputBufferPool.obtain(device: device, length: positionsBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffers")
        }

        // Create digest buffer directly (avoid pool reuse issues)
        guard let digestsBuf = device.makeBuffer(length: digestsBufLength, options: .storageModeShared) else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to allocate digest buffer")
        }

        guard let cacheBuf = sharedPositionCachePool.popLast() else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to pop cache buffer")
        }

        // Fill positions buffer (0 to countPerColumn-1, shared across all columns)
        let positionsPtr = positionsBuf.contents().bindMemory(to: UInt32.self, capacity: countPerColumn)
        for i in 0..<countPerColumn {
            positionsPtr[i] = UInt32(i)
        }

        // Copy values in transposed layout (contiguous by column)
        let valuesPtr = valuesBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount)
        for col in 0..<numColumns {
            let srcBase = col * countPerColumn
            let dstBase = col * countPerColumn
            for i in 0..<countPerColumn {
                valuesPtr[dstBase + i] = allValues[srcBase + i].v
            }
        }

        // GPU dispatch with optimized kernel
        guard let kernel = hashLeavesOptimizedFunction else {
            // Fallback to basic kernel if optimized not available
            return try hashLeavesBatchPerColumn(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        }

        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(kernel)
        enc.setBuffer(valuesBuf, offset: 0, index: 0)
        enc.setBuffer(positionsBuf, offset: 0, index: 1)
        enc.setBuffer(digestsBuf, offset: 0, index: 2)
        enc.setBuffer(rcBuffer, offset: 0, index: 3)
        var totalCnt = UInt32(totalCount)
        enc.setBytes(&totalCnt, length: 4, index: 4)
        var numCol = UInt32(numColumns)
        enc.setBytes(&numCol, length: 4, index: 5)
        var leavesPerCol = UInt32(countPerColumn)
        enc.setBytes(&leavesPerCol, length: 4, index: 6)
        enc.setBuffer(cacheBuf, offset: 0, index: 7)

        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let leavesPerTG = threadsPerTG
        let numThreadgroups = (totalCount + leavesPerTG - 1) / leavesPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount * 8)
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)

        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)
            let colBase = col * countPerColumn
            for i in 0..<countPerColumn {
                let baseIdx = (colBase + i) * 8
                for j in 0..<8 {
                    columnDigests.append(M31(v: ptr[baseIdx + j]))
                }
            }
            results.append(columnDigests)
        }

        // Return input buffers to pools (output buffer is not pooled due to variable sizes)
        inputBufferPool.returnBuffer(valuesBuf)
        inputBufferPool.returnBuffer(positionsBuf)
        // Note: digestsBuf is not returned to pool since it has variable size requirements
        sharedPositionCachePool.append(cacheBuf)

        return results
    }

    /// Hash leaves with H2+H3+H5 optimization (coalescing + shared memory + half precision)
    /// Uses 16-bit storage for M31 values where possible
    ///
    /// - Parameters:
    ///   - allValues: All column values in transposed layout
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of leaves per column
    /// - Returns: Array of digests per column
    public func hashLeavesOptimizedH2H3H5(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        let totalCount = numColumns * countPerColumn
        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride
        let halfStride = MemoryLayout<UInt16>.stride

        // Allocate buffers with half-precision input
        let valuesBufLength = totalCount * halfStride
        let positionsBufLength = countPerColumn * stride
        let digestsBufLength = totalCount * digestStride

        guard let valuesBuf = inputBufferPool.obtain(device: device, length: valuesBufLength, options: .storageModeShared),
              let positionsBuf = inputBufferPool.obtain(device: device, length: positionsBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffers")
        }

        // Create digest buffer directly (avoid pool reuse issues)
        guard let digestsBuf = device.makeBuffer(length: digestsBufLength, options: .storageModeShared) else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to allocate digest buffer")
        }

        guard let cacheBuf = sharedPositionCachePool.popLast() else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to pop cache buffer")
        }

        // Fill positions buffer
        let positionsPtr = positionsBuf.contents().bindMemory(to: UInt32.self, capacity: countPerColumn)
        for i in 0..<countPerColumn {
            positionsPtr[i] = UInt32(i)
        }

        // Copy values in half-precision
        let valuesPtr = valuesBuf.contents().bindMemory(to: UInt16.self, capacity: totalCount)
        for i in 0..<totalCount {
            valuesPtr[i] = UInt16(allValues[i].v)
        }

        // GPU dispatch with half-precision kernel
        guard let kernel = hashLeavesHalfFunction else {
            // Fallback to H2H3 kernel
            return try hashLeavesOptimizedH2H3(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        }

        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(kernel)
        enc.setBuffer(valuesBuf, offset: 0, index: 0)
        enc.setBuffer(positionsBuf, offset: 0, index: 1)
        enc.setBuffer(digestsBuf, offset: 0, index: 2)
        enc.setBuffer(rcBuffer, offset: 0, index: 3)
        var totalCnt = UInt32(totalCount)
        enc.setBytes(&totalCnt, length: 4, index: 4)
        enc.setBuffer(cacheBuf, offset: 0, index: 5)

        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let leavesPerTG = threadsPerTG
        let numThreadgroups = (totalCount + leavesPerTG - 1) / leavesPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount * 8)
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)

        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)
            let colBase = col * countPerColumn
            for i in 0..<countPerColumn {
                let baseIdx = (colBase + i) * 8
                for j in 0..<8 {
                    columnDigests.append(M31(v: ptr[baseIdx + j]))
                }
            }
            results.append(columnDigests)
        }

        // Return input buffers to pools (output buffer is not pooled due to variable sizes)
        inputBufferPool.returnBuffer(valuesBuf)
        inputBufferPool.returnBuffer(positionsBuf)
        // Note: digestsBuf is not returned to pool since it has variable size requirements
        sharedPositionCachePool.append(cacheBuf)

        return results
    }

    /// Hash leaves with ALL optimizations H2+H3+H4+H5 combined
    /// This is the maximum optimization level
    ///
    /// - Parameters:
    ///   - allValues: All column values
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of leaves per column
    /// - Returns: Array of digests per column
    public func hashLeavesFullyOptimized(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        let totalCount = numColumns * countPerColumn
        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride
        let halfStride = MemoryLayout<UInt16>.stride

        // Allocate buffers - input buffers use pool, output buffer is allocated directly
        let valuesBufLength = totalCount * halfStride  // Half-precision
        let positionsBufLength = countPerColumn * stride
        let digestsBufLength = totalCount * digestStride

        guard let valuesBuf = inputBufferPool.obtain(device: device, length: valuesBufLength, options: .storageModeShared),
              let positionsBuf = inputBufferPool.obtain(device: device, length: positionsBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffers")
        }

        // Create digest buffer directly (avoid pool reuse issues)
        guard let digestsBuf = device.makeBuffer(length: digestsBufLength, options: .storageModeShared) else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to allocate digest buffer")
        }

        guard let cacheBuf = sharedPositionCachePool.popLast() else {
            inputBufferPool.returnBuffer(valuesBuf)
            inputBufferPool.returnBuffer(positionsBuf)
            throw GPUProverError.gpuError("Failed to pop cache buffer")
        }

        // Fill positions buffer
        let positionsPtr = positionsBuf.contents().bindMemory(to: UInt32.self, capacity: countPerColumn)
        for i in 0..<countPerColumn {
            positionsPtr[i] = UInt32(i)
        }

        // Copy values in half-precision transposed layout
        let valuesPtr = valuesBuf.contents().bindMemory(to: UInt16.self, capacity: totalCount)
        for col in 0..<numColumns {
            let srcBase = col * countPerColumn
            let dstBase = col * countPerColumn
            for i in 0..<countPerColumn {
                valuesPtr[dstBase + i] = UInt16(allValues[srcBase + i].v)
            }
        }

        // GPU dispatch with combined optimization kernel
        guard let kernel = hashLeavesCombinedFunction else {
            // Fallback to H2H3H5
            return try hashLeavesOptimizedH2H3H5(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        }

        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(kernel)
        enc.setBuffer(valuesBuf, offset: 0, index: 0)
        enc.setBuffer(positionsBuf, offset: 0, index: 1)
        enc.setBuffer(digestsBuf, offset: 0, index: 2)
        enc.setBuffer(rcBuffer, offset: 0, index: 3)
        var totalCnt = UInt32(totalCount)
        enc.setBytes(&totalCnt, length: 4, index: 4)
        var numCol = UInt32(numColumns)
        enc.setBytes(&numCol, length: 4, index: 5)
        var leavesPerCol = UInt32(countPerColumn)
        enc.setBytes(&leavesPerCol, length: 4, index: 6)
        enc.setBuffer(cacheBuf, offset: 0, index: 7)

        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let leavesPerTG = threadsPerTG
        let numThreadgroups = (totalCount + leavesPerTG - 1) / leavesPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount * 8)
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)

        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)
            let colBase = col * countPerColumn
            for i in 0..<countPerColumn {
                let baseIdx = (colBase + i) * 8
                for j in 0..<8 {
                    columnDigests.append(M31(v: ptr[baseIdx + j]))
                }
            }
            results.append(columnDigests)
        }

        // Return input buffers to pools (output buffer is not pooled due to variable sizes)
        inputBufferPool.returnBuffer(valuesBuf)
        inputBufferPool.returnBuffer(positionsBuf)
        // Note: digestsBuf is not returned to pool since it has variable size requirements
        sharedPositionCachePool.append(cacheBuf)

        return results
    }

    /// H4: Pre-compute Poseidon2 hash states for all positions (0..countPerColumn-1)
    /// This runs once on CPU/GPU before leaf hashing to eliminate position hashing from critical path.
    ///
    /// Key insight: Instead of hashing (position, value) for each leaf, pre-hash the position
    /// once to get state S_pos, then for each leaf just do S_pos + value and permute.
    ///
    /// - Parameters:
    ///   - countPerColumn: Number of unique positions to pre-compute (e.g., 1024 for 1024 leaves)
    /// - Throws: GPUProverError if precomputation fails
    public func precomputePositionHashes(countPerColumn: Int) throws {
        guard let kernel = precomputePositionsFunction else {
            throw GPUProverError.missingKernel
        }

        let stride = MemoryLayout<UInt32>.stride
        let statesBufLength = countPerColumn * Self.poseidonT * stride

        // Create positions array: [0, 1, 2, ..., countPerColumn-1]
        var flatPositions = [UInt32](repeating: 0, count: countPerColumn)
        for i in 0..<countPerColumn {
            flatPositions[i] = UInt32(i)
        }

        // Allocate buffers using pool
        guard let positionsBuf = positionStatesBufferPool.obtain(device: device, length: countPerColumn * stride, options: .storageModeShared),
              let statesBuf = positionStatesBufferPool.obtain(device: device, length: statesBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate buffers for position precomputation")
        }

        // Copy positions to buffer
        memcpy(positionsBuf.contents(), flatPositions, countPerColumn * stride)

        // GPU dispatch for position precomputation
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(kernel)
        enc.setBuffer(positionsBuf, offset: 0, index: 0)
        enc.setBuffer(statesBuf, offset: 0, index: 1)
        enc.setBuffer(rcBuffer, offset: 0, index: 2)
        var cnt = UInt32(countPerColumn)
        enc.setBytes(&cnt, length: 4, index: 3)

        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let numThreadgroups = (countPerColumn + threadsPerTG - 1) / threadsPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            positionStatesBufferPool.returnBuffer(positionsBuf)
            positionStatesBufferPool.returnBuffer(statesBuf)
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Return buffers to pool for later use
        positionStatesBufferPool.returnBuffer(positionsBuf)
        positionStatesBufferPool.returnBuffer(statesBuf)
    }

    /// H4: Hash leaves using pre-computed position hash states
    /// Must call precomputePositionHashes(countPerColumn:) first.
    ///
    /// - Parameters:
    ///   - allValues: All column values in transposed layout
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of leaves per column
    /// - Returns: Array of digests per column
    public func hashLeavesWithPrecomputedPositions(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int,
        precomputedStates: MTLBuffer  // Pre-computed position hash states
    ) throws -> [[M31]] {
        guard let kernel = hashLeavesPrecomputedFunction else {
            throw GPUProverError.missingKernel
        }

        let totalCount = numColumns * countPerColumn
        let stride = MemoryLayout<UInt32>.stride
        let digestStride = 8 * stride

        // Allocate buffers
        let valuesBufLength = totalCount * stride
        let digestsBufLength = totalCount * digestStride

        guard let valuesBuf = inputBufferPool.obtain(device: device, length: valuesBufLength, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate values buffer")
        }

        guard let digestsBuf = device.makeBuffer(length: digestsBufLength, options: .storageModeShared) else {
            inputBufferPool.returnBuffer(valuesBuf)
            throw GPUProverError.gpuError("Failed to allocate digest buffer")
        }

        // Copy values in transposed layout (contiguous by column)
        let valuesPtr = valuesBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount)
        for col in 0..<numColumns {
            let srcBase = col * countPerColumn
            let dstBase = col * countPerColumn
            for i in 0..<countPerColumn {
                valuesPtr[dstBase + i] = allValues[srcBase + i].v
            }
        }

        // GPU dispatch with precomputed positions kernel
        guard let cmdBuf = commandQueue.makeCommandBuffer() else {
            inputBufferPool.returnBuffer(valuesBuf)
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        enc.setComputePipelineState(kernel)
        enc.setBuffer(valuesBuf, offset: 0, index: 0)
        enc.setBuffer(precomputedStates, offset: 0, index: 1)
        enc.setBuffer(digestsBuf, offset: 0, index: 2)
        enc.setBuffer(rcBuffer, offset: 0, index: 3)
        var cnt = UInt32(totalCount)
        enc.setBytes(&cnt, length: 4, index: 4)

        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let numThreadgroups = (totalCount + threadsPerTG - 1) / threadsPerTG
        enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                               threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            inputBufferPool.returnBuffer(valuesBuf)
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        // Read results
        let ptr = digestsBuf.contents().bindMemory(to: UInt32.self, capacity: totalCount * 8)
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)

        for col in 0..<numColumns {
            var columnDigests: [M31] = []
            columnDigests.reserveCapacity(countPerColumn * 8)
            let colBase = col * countPerColumn
            for i in 0..<countPerColumn {
                let baseIdx = (colBase + i) * 8
                for j in 0..<8 {
                    columnDigests.append(M31(v: ptr[baseIdx + j]))
                }
            }
            results.append(columnDigests)
        }

        // Return input buffers to pools
        inputBufferPool.returnBuffer(valuesBuf)
        // Note: digestsBuf is not pooled due to variable size requirements

        return results
    }

    // H4: Cached precomputed position states (reused across multiple calls)
    private var cachedPositionStates: MTLBuffer?
    private var cachedCountPerColumn: Int = 0

    /// Hash all leaves using the best available optimization level
    /// Automatically selects the optimal kernel based on availability
    ///
    /// - Parameters:
    ///   - allValues: All column values
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of leaves per column
    /// - Returns: Array of digests per column
    public func hashLeavesAutoOptimized(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        switch optimizationLevel {
        case .basic:
            return try hashLeavesBatchPerColumn(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        case .coalesced, .sharedMem:
            return try hashLeavesOptimizedH2H3(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        case .precomputed:
            // H4: Use pre-computed position hashes
            return try hashLeavesWithPrecomputedPositionsH4(
                allValues: allValues,
                numColumns: numColumns,
                countPerColumn: countPerColumn
            )
        case .halfPrecision:
            return try hashLeavesOptimizedH2H3H5(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        case .combined:
            return try hashLeavesFullyOptimized(allValues: allValues, numColumns: numColumns, countPerColumn: countPerColumn)
        }
    }

    /// H4: Hash leaves with pre-computed position hash states
    /// Uses cached position states if countPerColumn matches, otherwise recomputes
    private func hashLeavesWithPrecomputedPositionsH4(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) throws -> [[M31]] {
        // Check if we need to recompute position hashes
        if cachedPositionStates == nil || cachedCountPerColumn != countPerColumn {
            // Recompute position hashes
            try precomputePositionHashes(countPerColumn: countPerColumn)

            // Allocate and fill the states buffer
            let stride = MemoryLayout<UInt32>.stride
            let statesBufLength = countPerColumn * Self.poseidonT * stride

            guard let statesBuf = device.makeBuffer(length: statesBufLength, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate states buffer")
            }

            // Create positions array and run precomputation kernel
            var flatPositions = [UInt32](repeating: 0, count: countPerColumn)
            for i in 0..<countPerColumn {
                flatPositions[i] = UInt32(i)
            }

            guard let kernel = precomputePositionsFunction else {
                throw GPUProverError.missingKernel
            }

            guard let positionsBuf = device.makeBuffer(bytes: flatPositions, length: countPerColumn * stride, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate positions buffer")
            }

            guard let cmdBuf = commandQueue.makeCommandBuffer() else {
                throw GPUProverError.noCommandBuffer
            }
            let enc = cmdBuf.makeComputeCommandEncoder()!

            enc.setComputePipelineState(kernel)
            enc.setBuffer(positionsBuf, offset: 0, index: 0)
            enc.setBuffer(statesBuf, offset: 0, index: 1)
            enc.setBuffer(rcBuffer, offset: 0, index: 2)
            var cnt = UInt32(countPerColumn)
            enc.setBytes(&cnt, length: 4, index: 3)

            let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
            let numThreadgroups = (countPerColumn + threadsPerTG - 1) / threadsPerTG
            enc.dispatchThreadgroups(MTLSize(width: numThreadgroups, height: 1, depth: 1),
                                   threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1))
            enc.endEncoding()

            cmdBuf.commit()
            cmdBuf.waitUntilCompleted()

            if let error = cmdBuf.error {
                throw GPUProverError.gpuError(error.localizedDescription)
            }

            cachedPositionStates = statesBuf
            cachedCountPerColumn = countPerColumn
        }

        // Use cached precomputed states
        guard let states = cachedPositionStates else {
            throw GPUProverError.gpuError("No cached position states available")
        }

        return try hashLeavesWithPrecomputedPositions(
            allValues: allValues,
            numColumns: numColumns,
            countPerColumn: countPerColumn,
            precomputedStates: states
        )
    }

    /// Get available optimization features
    public func getAvailableOptimizations() -> [String: Bool] {
        return [
            "H2_memory_coalescing": hashLeavesOptimizedFunction != nil,
            "H3_shared_memory": hashLeavesOptimizedFunction != nil,
            "H4_precomputation": precomputePositionsFunction != nil,
            "H5_half_precision": hashLeavesHalfFunction != nil,
            "combined_kernel": hashLeavesCombinedFunction != nil
        ]
    }
}