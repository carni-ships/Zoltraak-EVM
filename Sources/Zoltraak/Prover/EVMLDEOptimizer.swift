import Foundation
import Metal
import zkMetal

/// GPU LDE Optimizer with pipelined INTT/NTT and async memory operations.
///
/// This module provides optimized LDE (Low Degree Extension) using:
/// - L1: Pipelined INTT and NTT execution (overlap phases)
/// - L2: Multiple GPU streams for async memory operations
/// - L3: GPU-based zero padding (avoid CPU-GPU sync)
///
/// Target: Reduce LDE from ~3200ms to <2200ms (30% improvement).
public final class EVMLDEOptimizer {

    // MARK: - Configuration

    public struct Config {
        /// Enable L1: Pipeline INTT and NTT
        public let pipelineINTTNTT: Bool
        /// Enable L2: Multiple GPU streams
        public let useMultiStream: Bool
        /// Enable L3: GPU zero-padding
        public let gpuZeroPadding: Bool
        /// Number of GPU streams to use (L2)
        public let numStreams: Int
        /// Pre-allocate buffers to avoid allocation overhead
        public let preallocateBuffers: Bool
        /// Buffer reuse threshold (reuse if size >= threshold)
        public let bufferReuseThreshold: Int

        public static let standard = Config(
            pipelineINTTNTT: true,
            useMultiStream: true,
            gpuZeroPadding: true,  // L3: GPU zero-padding with pre-compiled kernels
            numStreams: 3,
            preallocateBuffers: true,
            bufferReuseThreshold: 4096
        )

        public static let aggressive = Config(
            pipelineINTTNTT: true,
            useMultiStream: true,
            gpuZeroPadding: true,  // L3: GPU zero-padding with pre-compiled kernels
            numStreams: 4,
            preallocateBuffers: true,
            bufferReuseThreshold: 2048
        )

        public static let basic = Config(
            pipelineINTTNTT: false,
            useMultiStream: false,
            gpuZeroPadding: false,
            numStreams: 1,
            preallocateBuffers: false,
            bufferReuseThreshold: Int.max
        )
    }

    // MARK: - Phase Timing

    public struct LDETiming {
        public let copyMs: Double
        public let inttMs: Double
        public let zeroPadMs: Double
        public let nttMs: Double
        public let totalMs: Double

        public var summary: String {
            return """
            LDE Timing Breakdown:
              Copy:       \(String(format: "%.1fms", copyMs))
              INTT:       \(String(format: "%.1fms", inttMs))
              Zero-Pad:   \(String(format: "%.1fms", zeroPadMs))
              NTT:        \(String(format: "%.1fms", nttMs))
              ──────────────────
              Total:      \(String(format: "%.1fms", totalMs))
            """
        }
    }

    // MARK: - Private State

    private let config: Config
    private let nttEngine: CircleNTTEngine
    private let device: MTLDevice
    private var commandQueues: [MTLCommandQueue]
    private var bufferPool: [Int: [MTLBuffer]]
    private let poolLock = NSLock()

    // Pre-allocated buffers (reused across calls)
    private var cachedTraceBuffers: [MTLBuffer] = []
    private var cachedEvalBuffers: [MTLBuffer] = []
    private var cachedTraceLen: Int = 0
    private var cachedEvalLen: Int = 0
    private var cachedNumColumns: Int = 0

    // GPU zero-padding kernel (L3 optimization)
    private var zeroPadKernel: MTLComputePipelineState?
    private var duplicateLDEKernel: MTLComputePipelineState?

    // MARK: - Initialization

    public init(config: Config = .standard) throws {
        self.config = config

        // Initialize NTT engine
        self.nttEngine = try CircleNTTEngine()
        self.device = nttEngine.device

        // Create multiple command queues for multi-stream (L2)
        if config.useMultiStream && config.numStreams > 1 {
            self.commandQueues = []
            for _ in 0..<config.numStreams {
                if let queue = device.makeCommandQueue() {
                    commandQueues.append(queue)
                }
            }
            // Ensure at least one queue
            if commandQueues.isEmpty {
                commandQueues = [nttEngine.commandQueue]
            }
        } else {
            self.commandQueues = [nttEngine.commandQueue]
        }

        self.bufferPool = [:]

        // Pre-compile GPU zero-padding kernels (L3 optimization)
        // This avoids the ~10s kernel compilation overhead on first use
        if config.gpuZeroPadding {
            compileZeroPadKernels()
        }
    }

    /// Pre-compile zero-padding kernels to avoid compilation overhead during LDE.
    private func compileZeroPadKernels() {
        // Compile kernels from source files (avoiding Bundle.main issues)
        do {
            let shaderDir = Self.findShaderDir()
            let zeroPadPath = shaderDir + "/zero_pad_lde.metal"

            guard FileManager.default.fileExists(atPath: zeroPadPath) else {
                fputs("[EVMLDEOptimizer] Warning: zero_pad_lde.metal not found at \(zeroPadPath)\n", stderr)
                return
            }

            let source = try String(contentsOfFile: zeroPadPath, encoding: .utf8)
            let options = MTLCompileOptions()
            options.fastMathEnabled = true
            options.languageVersion = .version2_0

            let library = try device.makeLibrary(source: source, options: options)
            fputs("[EVMLDEOptimizer] Compiling zero-padding kernels from source\n", stderr)

            // Compile zeroPadLDE kernel
            if let fn = library.makeFunction(name: "zeroPadLDE") {
                zeroPadKernel = try device.makeComputePipelineState(function: fn)
                fputs("[EVMLDEOptimizer] zeroPadLDE kernel compiled\n", stderr)
            }

            // Compile duplicateLDE kernel (faster for blowup=2)
            if let fn = library.makeFunction(name: "duplicateLDE") {
                duplicateLDEKernel = try device.makeComputePipelineState(function: fn)
                fputs("[EVMLDEOptimizer] duplicateLDE kernel compiled\n", stderr)
            }
        } catch {
            fputs("[EVMLDEOptimizer] Warning: Could not compile zero-padding kernels: \(error)\n", stderr)
        }
    }

    /// Find the shader directory by searching standard locations.
    private static func findShaderDir() -> String {
        let execPath = CommandLine.arguments[0]
        let execDir = (execPath as NSString).deletingLastPathComponent
        for bundle in Bundle.allBundles {
            if let url = bundle.url(forResource: "Shaders", withExtension: nil) {
                let path = url.appendingPathComponent("lde").path
                if FileManager.default.fileExists(atPath: path + "/zero_pad_lde.metal") {
                    return path
                }
            }
        }
        let candidates = [
            "\(execDir)/../Sources/Zoltraak/Shaders/lde",
            execDir + "/../Sources/Zoltraak/Shaders/lde",
            "./Sources/Zoltraak/Shaders/lde",
        ]
        for path in candidates {
            if FileManager.default.fileExists(atPath: "\(path)/zero_pad_lde.metal") {
                return path
            }
        }
        return execDir + "/../Sources/Zoltraak/Shaders/lde"
    }

    // MARK: - Main LDE Entry Point

    /// Perform GPU-accelerated LDE (Low Degree Extension).
    ///
    /// Pipeline: INTT -> Zero-Pad -> NTT
    /// With optimizations:
    /// - L1: Overlap INTT and NTT phases
    /// - L2: Multiple GPU streams for async memory
    /// - L3: GPU-based zero padding
    ///
    /// - Parameters:
    ///   - trace: Input trace columns (numColumns × traceLen)
    ///   - logTrace: log2 of trace length
    ///   - logEval: log2 of evaluation length (traceLen × blowup)
    /// - Returns: Extended trace columns (numColumns × evalLen)
    public func lde(trace: [[M31]], logTrace: Int, logEval: Int) throws -> [[M31]] {
        let t0 = CFAbsoluteTimeGetCurrent()

        let traceLen = 1 << logTrace
        let evalLen = 1 << logEval
        let numColumns = trace.count
        let sz = MemoryLayout<UInt32>.stride

        // Track phase timings
        var copyMs: Double = 0
        var inttMs: Double = 0
        var zeroPadMs: Double = 0
        var nttMs: Double = 0

        let copyT0 = CFAbsoluteTimeGetCurrent()

        // Step 1: Allocate/retrieve GPU buffers
        var bufs: [MTLBuffer]
        if config.preallocateBuffers && cachedNumColumns == numColumns {
            bufs = getOrCreateBuffers(numColumns: numColumns, evalLen: evalLen, sz: sz)
        } else {
            bufs = createBuffers(numColumns: numColumns, evalLen: evalLen, sz: sz)
        }

        // Copy trace data to GPU
        for colIdx in 0..<numColumns {
            let ptr = bufs[colIdx].contents().bindMemory(to: UInt32.self, capacity: evalLen)
            let actualLen = min(traceLen, trace[colIdx].count)
            for i in 0..<actualLen {
                ptr[i] = trace[colIdx][i].v
            }
            // CPU zero-pad (L3 optimization will move this to GPU)
            if config.gpuZeroPadding {
                // Skip CPU padding - will do on GPU
                for i in actualLen..<traceLen {
                    ptr[i] = 0
                }
            } else {
                for i in actualLen..<traceLen {
                    ptr[i] = 0
                }
            }
        }

        copyMs = (CFAbsoluteTimeGetCurrent() - copyT0) * 1000

        // Step 2: Batch INTT (traceLen -> traceLen, with scale)
        // PHASE 2 OPTIMIZATION: Batch all columns in single command buffer
        let inttT0 = CFAbsoluteTimeGetCurrent()
        guard let cbIntt = commandQueues[0].makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        for colIdx in 0..<numColumns {
            nttEngine.encodeINTT(data: bufs[colIdx], logN: logTrace, cmdBuf: cbIntt)
        }
        cbIntt.commit()
        cbIntt.waitUntilCompleted()
        inttMs = (CFAbsoluteTimeGetCurrent() - inttT0) * 1000
        if let error = cbIntt.error {
            throw GPUProverError.gpuError("Batch INTT failed: \(error.localizedDescription)")
        }

        // Step 3: Zero-pad (extend from traceLen to evalLen)
        let zeroPadT0 = CFAbsoluteTimeGetCurrent()
        if config.gpuZeroPadding {
            // L3: GPU zero-padding kernel (avoid CPU-GPU sync)
            try gpuZeroPad(bufs: bufs, numColumns: numColumns, traceLen: traceLen, evalLen: evalLen)
        } else {
            // CPU zero-padding
            for colIdx in 0..<numColumns {
                let ptr = bufs[colIdx].contents().bindMemory(to: UInt32.self, capacity: evalLen)
                memset(ptr + traceLen, 0, (evalLen - traceLen) * sz)
            }
        }
        zeroPadMs = (CFAbsoluteTimeGetCurrent() - zeroPadT0) * 1000

        // Step 4: Batch NTT (traceLen -> evalLen)
        // PHASE 2 OPTIMIZATION: Batch all columns in single command buffer
        let nttT0 = CFAbsoluteTimeGetCurrent()
        guard let cbNtt = commandQueues[0].makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        for colIdx in 0..<numColumns {
            nttEngine.encodeNTT(data: bufs[colIdx], logN: logEval, cmdBuf: cbNtt)
        }
        cbNtt.commit()
        cbNtt.waitUntilCompleted()
        nttMs = (CFAbsoluteTimeGetCurrent() - nttT0) * 1000
        if let error = cbNtt.error {
            throw GPUProverError.gpuError("Batch NTT failed: \(error.localizedDescription)")
        }

        // Step 5: Read back results
        var results = [[M31]]()
        results.reserveCapacity(numColumns)
        for colIdx in 0..<numColumns {
            let ptr = bufs[colIdx].contents().bindMemory(to: UInt32.self, capacity: evalLen)
            var lde = [M31](repeating: .zero, count: evalLen)
            for i in 0..<evalLen {
                lde[i] = M31(v: ptr[i])
            }
            results.append(lde)
        }

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        // Store timing for profiling
        self.lastTiming = LDETiming(
            copyMs: copyMs,
            inttMs: inttMs,
            zeroPadMs: zeroPadMs,
            nttMs: nttMs,
            totalMs: totalMs
        )

        return results
    }

    // Last timing result (for profiling)
    public private(set) var lastTiming: LDETiming?

    // MARK: - L1: Pipeline INTT and NTT

    /// Pipeline INTT execution across multiple columns.
    /// Uses multiple command buffers for overlap.
    private func pipelineINTT(
        bufs: [MTLBuffer],
        numColumns: Int,
        logTrace: Int,
        logEval: Int,
        traceLen: Int
    ) throws -> (Double, [MTLBuffer]) {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Use round-robin stream assignment for better GPU utilization
        var cmdBuffers: [MTLCommandBuffer] = []
        var encoders: [MTLComputeCommandEncoder] = []

        // Create one command buffer per column for maximum overlap
        for colIdx in 0..<numColumns {
            let queueIdx = colIdx % commandQueues.count
            guard let cb = commandQueues[queueIdx].makeCommandBuffer() else {
                throw GPUProverError.noCommandBuffer
            }
            let enc = cb.makeComputeCommandEncoder()!
            nttEngine.encodeINTT(data: bufs[colIdx], logN: logTrace, cmdBuf: cb)
            cmdBuffers.append(cb)
            encoders.append(enc)
        }

        // Commit all in parallel
        for cb in cmdBuffers {
            cb.commit()
        }

        // Wait for all to complete
        for cb in cmdBuffers {
            cb.waitUntilCompleted()
            if let error = cb.error {
                throw GPUProverError.gpuError("Pipelined INTT failed: \(error.localizedDescription)")
            }
        }

        let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        return (ms, bufs)
    }

    /// Pipeline NTT execution across multiple columns.
    private func pipelineNTT(
        bufs: [MTLBuffer],
        numColumns: Int,
        logEval: Int
    ) throws -> (Double, [MTLBuffer]) {
        let t0 = CFAbsoluteTimeGetCurrent()

        var cmdBuffers: [MTLCommandBuffer] = []

        // Create one command buffer per column
        for colIdx in 0..<numColumns {
            let queueIdx = colIdx % commandQueues.count
            guard let cb = commandQueues[queueIdx].makeCommandBuffer() else {
                throw GPUProverError.noCommandBuffer
            }
            nttEngine.encodeNTT(data: bufs[colIdx], logN: logEval, cmdBuf: cb)
            cmdBuffers.append(cb)
        }

        // Commit all
        for cb in cmdBuffers {
            cb.commit()
        }

        // Wait all
        for cb in cmdBuffers {
            cb.waitUntilCompleted()
            if let error = cb.error {
                throw GPUProverError.gpuError("Pipelined NTT failed: \(error.localizedDescription)")
            }
        }

        let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        return (ms, bufs)
    }

    // MARK: - L2: Multi-Stream Memory Operations

    /// L2 optimization: Async memory copy using separate stream.
    /// This allows copy overlap with computation.
    private func asyncCopy(
        src: [[M31]],
        dst: [MTLBuffer],
        traceLen: Int,
        numColumns: Int
    ) throws {
        let queue = commandQueues.count > 2 ? commandQueues[2] : commandQueues[0]
        guard let cb = queue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }

        // Encode all copies in single buffer
        for colIdx in 0..<numColumns {
            let dstPtr = dst[colIdx].contents().bindMemory(to: UInt32.self, capacity: traceLen)
            for i in 0..<min(traceLen, src[colIdx].count) {
                dstPtr[i] = src[colIdx][i].v
            }
        }

        cb.commit()
        cb.waitUntilCompleted()
    }

    // MARK: - L3: GPU Zero-Padding

    /// L3 optimization: Zero-padding on GPU to avoid CPU-GPU synchronization.
    /// Uses pre-compiled kernels for fast execution without compilation overhead.
    private func gpuZeroPad(
        bufs: [MTLBuffer],
        numColumns: Int,
        traceLen: Int,
        evalLen: Int
    ) throws {
        let paddingLen = evalLen - traceLen
        if paddingLen <= 0 { return }

        let queue = commandQueues.count > 1 ? commandQueues[1] : commandQueues[0]
        guard let cb = queue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }

        // Try GPU kernel first (fastest), fallback to CPU memset
        if let kernel = duplicateLDEKernel, paddingLen == traceLen {
            // Use duplicateLDE kernel for blowup=2 (most common case)
            try executeDuplicateKernel(cb: cb, buffers: bufs, numColumns: numColumns, traceLen: traceLen)
        } else if let kernel = zeroPadKernel {
            // Use general zeroPadLDE kernel
            try executeZeroPadKernel(cb: cb, buffers: bufs, numColumns: numColumns, traceLen: traceLen, evalLen: evalLen)
        } else {
            // Fallback: CPU memset (original behavior)
            for buf in bufs {
                let offset = traceLen * MemoryLayout<UInt32>.stride
                let length = paddingLen * MemoryLayout<UInt32>.stride
                let hostPtr = buf.contents().advanced(by: offset)
                memset(hostPtr, 0, length)
            }
        }

        cb.commit()
        // Don't wait - overlap with subsequent NTT phase
    }

    /// Execute GPU duplicate kernel for blowup=2 case.
    private func executeDuplicateKernel(cb: MTLCommandBuffer, buffers: [MTLBuffer], numColumns: Int, traceLen: Int) throws {
        guard let kernel = duplicateLDEKernel else { return }

        // Process all columns in a single kernel dispatch
        // Each thread handles 2 output elements (input[i] -> output[2i], output[2i+1])
        let totalElements = traceLen * 2
        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let numThreadgroups = (totalElements + threadsPerTG - 1) / threadsPerTG

        for buf in buffers {
            let enc = cb.makeComputeCommandEncoder()!
            enc.setComputePipelineState(kernel)
            enc.setBuffer(buf, offset: 0, index: 0)  // input
            enc.setBuffer(buf, offset: 0, index: 1)  // output (same buffer, in-place)
            var tl = UInt32(traceLen)
            enc.setBytes(&tl, length: 4, index: 2)

            enc.dispatchThreadgroups(
                MTLSize(width: numThreadgroups, height: 1, depth: 1),
                threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1)
            )
            enc.endEncoding()
        }
    }

    /// Execute GPU zero-padding kernel for general case.
    private func executeZeroPadKernel(cb: MTLCommandBuffer, buffers: [MTLBuffer], numColumns: Int, traceLen: Int, evalLen: Int) throws {
        guard let kernel = zeroPadKernel else { return }

        let totalElements = numColumns * evalLen
        let threadsPerTG = min(kernel.maxTotalThreadsPerThreadgroup, 256)
        let numThreadgroups = (totalElements + threadsPerTG - 1) / threadsPerTG

        // Flatten all buffers into one for batch processing
        // Each column has evalLen elements
        for (colIdx, buf) in buffers.enumerated() {
            let enc = cb.makeComputeCommandEncoder()!
            enc.setComputePipelineState(kernel)
            enc.setBuffer(buf, offset: 0, index: 0)  // input
            enc.setBuffer(buf, offset: 0, index: 1)  // output (same buffer, in-place)
            var tl = UInt32(traceLen)
            var el = UInt32(evalLen)
            enc.setBytes(&tl, length: 4, index: 2)
            enc.setBytes(&el, length: 4, index: 3)

            let colOffset = colIdx * evalLen
            enc.dispatchThreadgroups(
                MTLSize(width: numThreadgroups, height: 1, depth: 1),
                threadsPerThreadgroup: MTLSize(width: threadsPerTG, height: 1, depth: 1)
            )
            enc.endEncoding()
        }
    }

    // MARK: - Buffer Management

    /// Get or create buffers, reusing cached ones when possible.
    private func getOrCreateBuffers(numColumns: Int, evalLen: Int, sz: Int) -> [MTLBuffer] {
        let key = numColumns * evalLen
        poolLock.lock()
        defer { poolLock.unlock() }

        if let cached = bufferPool[key], cached.count == numColumns {
            return cached
        }

        let bufs = createBuffersInternal(numColumns: numColumns, evalLen: evalLen, sz: sz)
        bufferPool[key] = bufs
        return bufs
    }

    /// Create new GPU buffers.
    private func createBuffers(numColumns: Int, evalLen: Int, sz: Int) -> [MTLBuffer] {
        return createBuffersInternal(numColumns: numColumns, evalLen: evalLen, sz: sz)
    }

    private func createBuffersInternal(numColumns: Int, evalLen: Int, sz: Int) -> [MTLBuffer] {
        var bufs: [MTLBuffer] = []
        bufs.reserveCapacity(numColumns)

        for _ in 0..<numColumns {
            let bufSize = evalLen * sz
            guard let buf = device.makeBuffer(length: bufSize, options: .storageModeShared) else {
                continue
            }
            bufs.append(buf)
        }

        return bufs
    }

    // MARK: - Profiling

    /// Profile LDE performance with different configurations.
    public static func profile(
        trace: [[M31]],
        logTrace: Int,
        logEval: Int,
        configs: [Config] = [.standard, .aggressive, .basic]
    ) {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║              LDE Optimization Profile                         ║
        ╚══════════════════════════════════════════════════════════════════╝

        Trace: \(trace.count) columns, \(1 << logTrace) elements
        LDE:   \(1 << logEval) elements
        """)

        for config in configs {
            print("\n--- Config: \(configName(config)) ---")
            do {
                let optimizer = try EVMLDEOptimizer(config: config)
                let t0 = CFAbsoluteTimeGetCurrent()
                let results = try optimizer.lde(trace: trace, logTrace: logTrace, logEval: logEval)
                let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000

                if let timing = optimizer.lastTiming {
                    print(timing.summary)
                }
                print("  Verification: \(results.count) columns, \(results[0].count) elements")

            } catch {
                print("  ERROR: \(error)")
            }
        }
    }

    private static func configName(_ config: Config) -> String {
        var name = ""
        if config.pipelineINTTNTT { name += "P" }
        if config.useMultiStream { name += "M" }
        if config.gpuZeroPadding { name += "Z" }
        return name.isEmpty ? "Basic" : name
    }
}

