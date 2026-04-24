import Foundation
import Metal
import zkMetal

/// GPU Stream Manager for concurrent proof generation.
///
/// Manages multiple Metal command streams for parallel transaction proving.
/// Each stream operates independently until aggregation phase.
///
/// ## Architecture
///
/// ```
/// GPU Stream 0: [TX1] LDE→Commit→Constraint→FRI
/// GPU Stream 1: [TX2] LDE→Commit→Constraint→FRI
/// ...
/// GPU Stream 127: [TX127] LDE→Commit→Constraint→FRI
/// → Aggregate 128 proofs
/// ```
///
/// ## Memory Management
///
/// Each stream requires dedicated buffer pools. With 128 streams:
/// - Total memory: 128 × ~50MB = ~6.4GB
/// - Per-stream buffer pools to avoid allocation overhead
public final class GPUStreamManager: Sendable {

    // MARK: - Configuration

    /// Configuration for stream manager
    public struct Config: Sendable {
        /// Number of streams (default: 128)
        public let numStreams: Int

        /// Buffer pool size per stream
        public let bufferPoolSize: Int

        /// Maximum memory per stream in bytes (default: 50MB)
        public let maxMemoryPerStream: Int

        /// Enable stream synchronization barriers
        public let enableBarriers: Bool

        public static let `default` = Config(
            numStreams: 128,
            bufferPoolSize: 10,
            maxMemoryPerStream: 50 * 1024 * 1024,
            enableBarriers: false
        )

        /// High memory configuration for large traces
        public static let highMemory = Config(
            numStreams: 64,
            bufferPoolSize: 15,
            maxMemoryPerStream: 100 * 1024 * 1024,
            enableBarriers: false
        )

        /// Low memory configuration for limited GPU memory
        public static let lowMemory = Config(
            numStreams: 64,
            bufferPoolSize: 5,
            maxMemoryPerStream: 25 * 1024 * 1024,
            enableBarriers: false
        )
    }

    // MARK: - Stream State

    /// Per-stream command queue and buffer pools
    public struct StreamState: Sendable {
        public let streamIndex: Int
        public let commandQueue: MTLCommandQueue
        public var bufferPool: StreamBufferPool
        public var isBusy: Bool
        public var currentTransactionId: Int?

        init(streamIndex: Int, commandQueue: MTLCommandQueue, poolSize: Int) {
            self.streamIndex = streamIndex
            self.commandQueue = commandQueue
            self.bufferPool = StreamBufferPool(maxSize: poolSize)
            self.isBusy = false
            self.currentTransactionId = nil
        }
    }

    /// Thread-safe buffer pool for a single stream
    public struct StreamBufferPool: Sendable {
        private var buffers: [MTLBuffer] = []
        private let maxSize: Int

        init(maxSize: Int) {
            self.maxSize = maxSize
        }

        mutating func obtain(device: MTLDevice, length: Int, options: MTLResourceOptions) -> MTLBuffer? {
            for i in 0..<buffers.count {
                if buffers[i].length >= length {
                    return buffers.remove(at: i)
                }
            }
            return device.makeBuffer(length: length, options: options)
        }

        mutating func returnBuffer(_ buffer: MTLBuffer) {
            if buffers.count < maxSize {
                buffers.append(buffer)
            }
        }

        mutating func releaseAll() {
            buffers.removeAll()
        }

        mutating func size() -> Int {
            return buffers.count
        }
    }

    // MARK: - Properties

    public let config: Config
    public let device: MTLDevice

    /// All command streams (one per transaction slot)
    private var streams: [StreamState]

    /// Stream allocation lock for thread-safe access
    private let streamLock = NSLock()

    /// Metrics
    public struct Metrics: Sendable {
        public var totalDispatches: UInt64 = 0
        public var totalBytesAllocated: Int = 0
        public var peakConcurrentStreams: Int = 0
        public var currentActiveStreams: Int = 0

        public mutating func recordDispatch() {
            totalDispatches += 1
            currentActiveStreams += 1
            peakConcurrentStreams = max(peakConcurrentStreams, currentActiveStreams)
        }

        public mutating func recordCompletion() {
            currentActiveStreams = max(0, currentActiveStreams - 1)
        }

        public mutating func recordAllocation(bytes: Int) {
            totalBytesAllocated += bytes
        }
    }

    public var metrics: Metrics = Metrics()

    // MARK: - Initialization

    /// Initialize stream manager with configured number of streams
    public init(config: Config = .default) throws {
        print("[GPUStreamManager] init called with config.numStreams=\(config.numStreams)")
        self.config = config

        // Get Metal device
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUStreamError.noGPU
        }
        self.device = device

        // Create command queues for each stream
        var createdStreams: [StreamState] = []
        for i in 0..<config.numStreams {
            if let queue = device.makeCommandQueue() {
                let state = StreamState(
                    streamIndex: i,
                    commandQueue: queue,
                    poolSize: config.bufferPoolSize
                )
                createdStreams.append(state)
            } else {
                print("Warning: Could not create command queue for stream \(i)")
            }
        }

        guard !createdStreams.isEmpty else {
            throw GPUStreamError.noCommandQueue
        }

        self.streams = createdStreams
        print("GPUStreamManager: Initialized \(streams.count) streams")
    }

    // MARK: - Stream Management

    /// Acquire a free stream for transaction processing
    /// Returns nil if no streams available
    public func acquireStream() -> Int? {
        streamLock.lock()
        defer { streamLock.unlock() }

        for i in 0..<streams.count {
            if !streams[i].isBusy {
                streams[i].isBusy = true
                metrics.recordDispatch()
                return i
            }
        }
        return nil
    }

    /// Release a stream back to the pool
    public func releaseStream(_ streamIndex: Int) {
        streamLock.lock()
        defer { streamLock.unlock() }

        guard streamIndex < streams.count else { return }

        // Release all buffers in the stream's pool
        streams[streamIndex].bufferPool.releaseAll()
        streams[streamIndex].isBusy = false
        streams[streamIndex].currentTransactionId = nil

        metrics.recordCompletion()
    }

    /// Get stream state by index
    public func getStream(_ index: Int) -> StreamState? {
        guard index < streams.count else { return nil }
        return streams[index]
    }

    /// Get all free stream indices
    public func getFreeStreams() -> [Int] {
        streamLock.lock()
        defer { streamLock.unlock() }

        return (0..<streams.count).filter { !streams[$0].isBusy }
    }

    /// Get count of free streams
    public var freeStreamCount: Int {
        streamLock.lock()
        defer { streamLock.unlock() }
        return streams.filter { !$0.isBusy }.count
    }

    /// Total number of streams
    public var totalStreamCount: Int {
        return streams.count
    }

    /// Check if all streams are free
    public var allStreamsFree: Bool {
        streamLock.lock()
        defer { streamLock.unlock() }
        return streams.allSatisfy { !$0.isBusy }
    }

    // MARK: - Buffer Management

    /// Allocate buffer from stream's pool
    public func allocateBuffer(
        forStream streamIndex: Int,
        length: Int,
        options: MTLResourceOptions = .storageModeShared
    ) -> MTLBuffer? {
        guard streamIndex < streams.count else { return nil }

        let buffer = streams[streamIndex].bufferPool.obtain(
            device: device,
            length: length,
            options: options
        )

        if let buf = buffer {
            metrics.recordAllocation(bytes: length)
        }

        return buffer
    }

    /// Return buffer to stream's pool
    public func returnBuffer(_ buffer: MTLBuffer, toStream streamIndex: Int) {
        guard streamIndex < streams.count else { return }
        streams[streamIndex].bufferPool.returnBuffer(buffer)
    }

    /// Get available memory for a stream
    public func availableMemory(forStream streamIndex: Int) -> Int {
        guard streamIndex < streams.count else { return 0 }

        let poolSize = streams[streamIndex].bufferPool.size()
        // Estimate based on pool usage
        return config.maxMemoryPerStream - (poolSize * 10 * 1024 * 1024) // ~10MB per buffer
    }

    // MARK: - Command Buffer Creation

    /// Create a new command buffer for a stream
    public func makeCommandBuffer(forStream streamIndex: Int) -> MTLCommandBuffer? {
        guard streamIndex < streams.count else { return nil }
        return streams[streamIndex].commandQueue.makeCommandBuffer()
    }

    /// Create multiple command buffers for batch processing
    public func makeCommandBuffers(forStreams streamIndices: [Int]) -> [MTLCommandBuffer?] {
        return streamIndices.map { makeCommandBuffer(forStream: $0) }
    }

    // MARK: - Synchronization

    /// Wait for all streams to complete
    public func synchronizeAll() {
        for stream in streams {
            stream.commandQueue.makeCommandBuffer()?.waitUntilCompleted()
        }
    }

    /// Wait for specific streams to complete
    public func synchronize(streams streamIndices: [Int]) {
        for idx in streamIndices {
            guard idx < streams.count else { continue }
            streams[idx].commandQueue.makeCommandBuffer()?.waitUntilCompleted()
        }
    }

    // MARK: - Profiling

    /// Get current utilization as percentage
    public var utilization: Double {
        streamLock.lock()
        defer { streamLock.unlock() }
        let busy = streams.filter { $0.isBusy }.count
        return Double(busy) / Double(streams.count) * 100
    }

    /// Get detailed metrics report
    public func getMetricsReport() -> String {
        return """
        GPU Stream Manager Metrics:
          - Total Streams: \(totalStreamCount)
          - Free Streams: \(freeStreamCount)
          - Current Active: \(metrics.currentActiveStreams)
          - Peak Concurrent: \(metrics.peakConcurrentStreams)
          - Total Dispatches: \(metrics.totalDispatches)
          - Total Bytes Allocated: \(metrics.totalBytesAllocated / 1024 / 1024)MB
          - Utilization: \(String(format: "%.1f%%", utilization))
        """
    }
}

// MARK: - Stream Allocation Context

/// RAII-style stream guard for automatic release
public struct StreamGuard {
    let manager: GPUStreamManager
    let streamIndex: Int

    init(manager: GPUStreamManager, streamIndex: Int) {
        self.manager = manager
        self.streamIndex = streamIndex
    }

    public func release() {
        manager.releaseStream(streamIndex)
    }
}

extension GPUStreamManager {

    /// Acquire stream with automatic cleanup
    public func acquireStreamWithGuard() -> (streamIndex: Int, streamGuard: StreamGuard)? {
        guard let idx = acquireStream() else { return nil }
        let streamGuard = StreamGuard(manager: self, streamIndex: idx)
        return (idx, streamGuard)
    }
}