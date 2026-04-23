import Foundation
import Metal
import zkMetal

/// Batch Keccak-256 processor for EVM execution traces.
///
/// This processor collects all KECCAK256 opcode inputs from an execution trace
/// and processes them in a single GPU batch operation for maximum throughput.
///
/// ## Usage
///
/// 1. Create the processor: `let batchProcessor = try BatchKeccakProcessor()`
/// 2. Before execution, enable collection: `batchProcessor.startCollecting()`
/// 3. Execute transactions normally
/// 4. After execution, batch process: `let results = try batchProcessor.processBatch()`
/// 5. Inject results back into trace
public final class BatchKeccakProcessor: Sendable {

    // MARK: - Types

    /// A collected Keccak input from KECCAK256 opcode execution
    public struct KeccakCall: Sendable {
        /// Memory bytes to hash
        public let input: [UInt8]

        /// Position in trace (row index) for result mapping
        public let traceIndex: Int

        /// Stack offset value (memory offset)
        public let memoryOffset: UInt64

        /// Size in bytes
        public let size: Int

        public init(input: [UInt8], traceIndex: Int, memoryOffset: UInt64, size: Int) {
            self.input = input
            self.traceIndex = traceIndex
            self.memoryOffset = memoryOffset
            self.size = size
        }
    }

    /// Result of batch processing
    public struct BatchResult: Sendable {
        /// Hashes indexed by trace position
        public let hashes: [Int: [UInt8]]

        /// Number of hashes computed
        public let count: Int

        /// Total time in milliseconds
        public let totalTimeMs: Double

        /// GPU compute time in milliseconds
        public let gpuTimeMs: Double

        /// Data transfer time in milliseconds
        public let transferTimeMs: Double
    }

    // MARK: - GPU Resources

    private let gpuEngine: GPUKeccakEngine?
    private let device: MTLDevice?
    private let commandQueue: MTLCommandQueue?

    // MARK: - Collection State

    private var isCollecting = false
    private var collectedCalls: [KeccakCall] = []
    private let callsLock = NSLock()

    // MARK: - Performance Metrics

    public var totalBatchesProcessed: UInt64 = 0
    public var totalHashesProcessed: UInt64 = 0

    // MARK: - Initialization

    public init() throws {
        self.device = MTLCreateSystemDefaultDevice()
        self.commandQueue = device?.makeCommandQueue()

        if device != nil {
            self.gpuEngine = try GPUKeccakEngine()
        } else {
            self.gpuEngine = nil
        }
    }

    // MARK: - Collection API

    /// Start collecting KECCAK256 calls from execution traces
    public func startCollecting() {
        callsLock.lock()
        defer { callsLock.unlock() }

        isCollecting = true
        collectedCalls = []
    }

    /// Stop collecting and return collected calls
    public func stopCollecting() -> [KeccakCall] {
        callsLock.lock()
        defer { callsLock.unlock() }

        isCollecting = false
        let calls = collectedCalls
        collectedCalls = []
        return calls
    }

    /// Record a KECCAK256 call during execution
    ///
    /// This should be called from the EVM execution engine when a KECCAK256
    /// opcode is encountered (before the actual hash computation).
    ///
    /// - Parameters:
    ///   - input: Memory bytes to hash
    ///   - traceIndex: Position in trace
    ///   - memoryOffset: Stack value for memory offset
    ///   - size: Number of bytes to hash
    public func recordCall(input: [UInt8], traceIndex: Int, memoryOffset: UInt64, size: Int) {
        callsLock.lock()
        defer { callsLock.unlock() }

        guard isCollecting else { return }

        collectedCalls.append(KeccakCall(
            input: input,
            traceIndex: traceIndex,
            memoryOffset: memoryOffset,
            size: size
        ))
    }

    // MARK: - Batch Processing

    /// Process all collected calls on GPU
    ///
    /// This is the main entry point for batch GPU processing.
    /// All collected KECCAK256 calls are processed in a single GPU dispatch.
    ///
    /// - Returns: Batch result with hashes indexed by trace position
    public func processBatch() throws -> BatchResult {
        let calls = stopCollecting()
        guard !calls.isEmpty else {
            return BatchResult(
                hashes: [:],
                count: 0,
                totalTimeMs: 0,
                gpuTimeMs: 0,
                transferTimeMs: 0
            )
        }

        let startTime = CFAbsoluteTimeGetCurrent()

        // Convert to GPUKeccakEngine input format
        let inputs = calls.map { call in
            GPUKeccakEngine.KeccakInput(memory: call.input, traceIndex: call.traceIndex)
        }

        // Process on GPU
        let gpuResult: GPUKeccakEngine.BatchResult
        if let engine = gpuEngine {
            gpuResult = try engine.hashBatch(inputs)
        } else {
            // CPU fallback
            let (hashes, timeMs) = processOnCPU(inputs)
            gpuResult = GPUKeccakEngine.BatchResult(
                hashes: hashes,
                indices: inputs.map { $0.traceIndex },
                gpuTimeMs: timeMs,
                transferTimeMs: 0
            )
        }

        // Map hashes back to trace positions
        var traceHashes: [Int: [UInt8]] = [:]
        for (i, hash) in gpuResult.hashes.enumerated() {
            let traceIndex = gpuResult.indices[i]
            traceHashes[traceIndex] = hash
        }

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        // Update metrics
        totalBatchesProcessed += 1
        totalHashesProcessed += UInt64(calls.count)

        return BatchResult(
            hashes: traceHashes,
            count: calls.count,
            totalTimeMs: totalTimeMs,
            gpuTimeMs: gpuResult.gpuTimeMs,
            transferTimeMs: gpuResult.transferTimeMs
        )
    }

    /// Process batch with CPU fallback
    private func processOnCPU(_ inputs: [GPUKeccakEngine.KeccakInput]) -> ([[UInt8]], Double) {
        let startTime = CFAbsoluteTimeGetCurrent()

        var hashes: [[UInt8]] = []
        for input in inputs {
            let hash = zkMetal.keccak256(input.memory)
            hashes.append(Array(hash))
        }

        let timeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        return (hashes, timeMs)
    }

    // MARK: - Single Call Processing

    /// Process a single Keccak call (used when batch is not available)
    public func processSingle(input: [UInt8]) -> [UInt8] {
        return Array(zkMetal.keccak256(input))
    }

    // MARK: - GPU Availability

    /// Check if GPU processing is available
    public var isGPUAvailable: Bool {
        return gpuEngine != nil
    }

    /// Average time per hash in microseconds
    public var averageTimePerHashUs: Double {
        guard let engine = gpuEngine else { return 0 }
        return engine.averageTimePerHashUs
    }

    /// Reset performance metrics
    public func resetMetrics() {
        totalBatchesProcessed = 0
        totalHashesProcessed = 0
        gpuEngine?.resetMetrics()
    }
}

// MARK: - EVM Integration

/// Extension to EVMExecutionEngine for batch Keccak support
public extension EVMExecutionEngine {

    /// Batch Keccak processor for this engine
    private static var batchKeccakProcessor: BatchKeccakProcessor? = nil

    /// Initialize the batch Keccak processor
    public static func initializeBatchKeccak() throws {
        batchKeccakProcessor = try BatchKeccakProcessor()
    }

    /// Get the batch Keccak processor
    public static var keccakProcessor: BatchKeccakProcessor? {
        return batchKeccakProcessor
    }

    /// Enable batch Keccak collection for upcoming execution
    public func enableBatchKeccakCollection() throws {
        if Self.batchKeccakProcessor == nil {
            try Self.initializeBatchKeccak()
        }
        Self.batchKeccakProcessor?.startCollecting()
    }

    /// Process all collected Keccak calls and return results
    public func processBatchKeccak() throws -> BatchKeccakProcessor.BatchResult {
        guard let processor = Self.batchKeccakProcessor else {
            throw BatchKeccakError.notInitialized
        }
        return try processor.processBatch()
    }

    /// Record a Keccak call during execution
    func recordKeccakCall(input: [UInt8], traceIndex: Int, memoryOffset: UInt64, size: Int) {
        Self.batchKeccakProcessor?.recordCall(
            input: input,
            traceIndex: traceIndex,
            memoryOffset: memoryOffset,
            size: size
        )
    }
}

// MARK: - Error Types

public enum BatchKeccakError: Error, CustomStringConvertible {
    case notInitialized
    case collectionFailed
    case processingFailed
    case gpuNotAvailable

    public var description: String {
        switch self {
        case .notInitialized:
            return "Batch Keccak processor not initialized"
        case .collectionFailed:
            return "Failed to collect Keccak calls"
        case .processingFailed:
            return "Failed to process Keccak batch"
        case .gpuNotAvailable:
            return "GPU not available for batch processing"
        }
    }
}

// MARK: - Batch Keccak Result Injection

/// Inject batch Keccak results back into EVM state
///
/// After processing a batch of Keccak operations on GPU, the results need to be
/// injected back into the appropriate positions in the trace or state.
public struct BatchKeccakResultInjector {

    /// Inject hash results into the execution trace
    ///
    /// - Parameters:
    ///   - trace: Original execution trace
    ///   - hashes: Map of trace index to hash result
    ///   - memory: Memory state at time of execution
    /// - Returns: Updated trace with Keccak results filled in
    public static func injectIntoTrace(
        trace: EVMExecutionTrace,
        hashes: [Int: [UInt8]],
        memory: EVMMemory
    ) -> EVMExecutionTrace {
        // For each KECCAK256 opcode in the trace, if we have a computed hash,
        // inject it into the appropriate position
        //
        // Note: In a full implementation, this would modify the trace rows
        // to include the computed hash values. The current implementation
        // provides the framework for this integration.

        // This is a placeholder - real implementation would:
        // 1. For each KECCAK256 row, look up the corresponding hash
        // 2. Modify the row's stack snapshot to include the hash
        // 3. Return the modified trace

        return trace
    }

    /// Compute Keccak hash directly from memory for a single position
    ///
    /// - Parameters:
    ///   - offset: Memory offset
    ///   - size: Number of bytes to hash
    ///   - memory: Memory state
    /// - Returns: 32-byte Keccak-256 hash
    public static func computeDirect(
        offset: UInt64,
        size: Int,
        memory: EVMMemory
    ) -> [UInt8] {
        var bytes = [UInt8]()
        for i in 0..<size {
            bytes.append(memory.loadByte(offset: Int(offset) + i))
        }
        return Array(zkMetal.keccak256(bytes))
    }
}
