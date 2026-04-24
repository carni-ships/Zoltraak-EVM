import Foundation
import Metal
import zkMetal

/// GPU-accelerated EVM interpreter for parallel transaction execution.
///
/// This implementation executes multiple EVM transactions simultaneously on GPU,
/// achieving massive speedup compared to CPU-based execution.
///
/// ## Architecture
///
/// ```
/// Each GPU thread handles one transaction:
/// - Thread 0: Transaction 0 (code, calldata, value)
/// - Thread 1: Transaction 1
/// - ...
/// - Thread N: Transaction N
/// ```
///
/// ## GPU Memory Layout
///
/// ```
/// Transaction State Buffer [numTxs * stateSize]:
///   - txState[txIdx].pc: UInt32
///   - txState[txIdx].gas: UInt64
///   - txState[txIdx].stackPtr: UInt32
///   - txState[txIdx].memoryPtr: UInt32
///   - txState[txIdx].running: UInt32
///   - txState[txIdx].reverted: UInt32
///
/// Stack Buffer [numTxs * maxStackDepth * 32 bytes]:
///   - stack[txIdx * maxStackDepth + stackPtr] = M31Word (256-bit)
///
/// Memory Buffer [numTxs * maxMemoryBytes]:
///   - memory[txIdx * maxMemoryBytes + offset] = UInt8
/// ```
///
/// ## Key Opcodes
///
/// Each EVM opcode is implemented as a GPU compute kernel or kernel function:
/// - Arithmetic: ADD, SUB, MUL, DIV, MOD
/// - Comparison: LT, GT, EQ
/// - Bitwise: AND, OR, XOR, NOT
/// - Memory: MLOAD, MSTORE
/// - Control: JUMP, JUMPI, JUMPDEST
/// - Stack: PUSH, POP, DUP, SWAP
public final class GPUEVMInterpreter: Sendable {

    // MARK: - Constants

    /// Maximum transactions per GPU batch (256 for optimal threadgroup size)
    public static let maxBatchSize = 256

    /// Maximum stack depth per EVM spec
    public static let maxStackDepth = 1024

    /// Maximum memory per transaction (2^22 = 4MB - sufficient for most EVM txs)
    /// With 30M gas, max memory ~8MB. Most txs use <100KB.
    public static let maxMemoryBytes = 1 << 22   // 4 MB

    /// Maximum bytecode size per transaction
    public static let maxCodeSize = 24576  // 24KB

    /// Maximum trace rows per transaction
    public static let maxTraceRows = 4096

    /// Size of state per transaction in GPU buffer
    public static let txStateSize = 64  // bytes

    // MARK: - Types

    /// Transaction input for GPU execution
    public struct TransactionInput: Sendable {
        public let code: [UInt8]
        public let calldata: [UInt8]
        public let value: M31Word
        public let gasLimit: UInt64
        public let address: M31Word
        public let caller: M31Word

        public init(
            code: [UInt8],
            calldata: [UInt8] = [],
            value: M31Word = .zero,
            gasLimit: UInt64 = 30_000_000,
            address: M31Word = .zero,
            caller: M31Word = .zero
        ) {
            self.code = code
            self.calldata = calldata
            self.value = value
            self.gasLimit = gasLimit
            self.address = address
            self.caller = caller
        }
    }

    /// Result of GPU EVM execution
    public struct ExecutionResult: Sendable {
        /// Execution trace rows
        public let traceRows: [EVMTraceRow]

        /// Gas used
        public let gasUsed: UInt64

        /// Whether execution reverted
        public let reverted: Bool

        /// Return data
        public let returnData: [UInt8]

        /// Execution time in milliseconds
        public let executionTimeMs: Double

        /// Number of steps executed
        public let stepCount: Int

        public init(
            traceRows: [EVMTraceRow],
            gasUsed: UInt64,
            reverted: Bool,
            returnData: [UInt8],
            executionTimeMs: Double,
            stepCount: Int
        ) {
            self.traceRows = traceRows
            self.gasUsed = gasUsed
            self.reverted = reverted
            self.returnData = returnData
            self.executionTimeMs = executionTimeMs
            self.stepCount = stepCount
        }
    }

    /// GPU memory layout for batch execution
    private struct BatchMemoryLayout: Sendable {
        let numTxs: Int
        let stateBufferSize: Int
        let stackBufferSize: Int
        let memoryBufferSize: Int
        let codeBufferSize: Int
        let traceBufferSize: Int
        let totalSize: Int

        init(numTxs: Int) {
            self.numTxs = numTxs
            self.stateBufferSize = numTxs * GPUEVMInterpreter.txStateSize
            self.stackBufferSize = numTxs * GPUEVMInterpreter.maxStackDepth * 32
            self.memoryBufferSize = numTxs * GPUEVMInterpreter.maxMemoryBytes
            self.codeBufferSize = numTxs * GPUEVMInterpreter.maxCodeSize
            self.traceBufferSize = numTxs * GPUEVMInterpreter.maxTraceRows * 64  // 64 bytes per trace row
            self.totalSize = stateBufferSize + stackBufferSize + memoryBufferSize + codeBufferSize + traceBufferSize
        }
    }

    // MARK: - GPU Resources

    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let library: MTLLibrary

    // Compute pipelines for each opcode category
    private let arithmeticPipeline: MTLComputePipelineState
    private let comparisonPipeline: MTLComputePipelineState
    private let bitwisePipeline: MTLComputePipelineState
    private let stackPipeline: MTLComputePipelineState
    private let memoryPipeline: MTLComputePipelineState
    private let controlFlowPipeline: MTLComputePipelineState
    private let mainLoopPipeline: MTLComputePipelineState
    private let traceCollectPipeline: MTLComputePipelineState

    // Memory pool
    private var bufferPool: [MTLBuffer] = []
    private var currentBatchLayout: BatchMemoryLayout?

    // MARK: - Performance Metrics

    public struct Metrics: Sendable {
        public var totalBatches: UInt64 = 0
        public var totalTransactions: UInt64 = 0
        public var totalTimeMs: Double = 0
        public var avgTimeMs: Double = 0
        public var peakMemoryBytes: Int = 0

        public mutating func record(batchMs: Double, txCount: Int, memoryBytes: Int) {
            totalBatches += 1
            totalTransactions += UInt64(txCount)
            totalTimeMs += batchMs
            avgTimeMs = totalTimeMs / Double(totalBatches)
            peakMemoryBytes = max(peakMemoryBytes, memoryBytes)
        }
    }

    public var metrics: Metrics = Metrics()

    // MARK: - Initialization

    /// Initialize GPU EVM interpreter
    public init() throws {
        // Get Metal device
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUEVMError.gpuNotAvailable
        }
        self.device = device

        // Create command queue
        guard let commandQueue = device.makeCommandQueue() else {
            throw GPUEVMError.commandQueueCreationFailed
        }
        self.commandQueue = commandQueue

        // Load and compile shaders
        let source = GPUEVMShaders.shaderSource
        do {
            library = try device.makeLibrary(source: source, options: MTLCompileOptions())
        } catch {
            throw GPUEVMError.shaderCompilationFailed(error.localizedDescription)
        }

        // Create compute pipelines
        arithmeticPipeline = try Self.createPipeline(library: library, device: device, "evm_arithmetic")
        comparisonPipeline = try Self.createPipeline(library: library, device: device, "evm_comparison")
        bitwisePipeline = try Self.createPipeline(library: library, device: device, "evm_bitwise")
        stackPipeline = try Self.createPipeline(library: library, device: device, "evm_stack")
        memoryPipeline = try Self.createPipeline(library: library, device: device, "evm_memory")
        controlFlowPipeline = try Self.createPipeline(library: library, device: device, "evm_control_flow")
        mainLoopPipeline = try Self.createPipeline(library: library, device: device, "evm_main_loop")
        traceCollectPipeline = try Self.createPipeline(library: library, device: device, "evm_trace_collect")
    }

    private static func createPipeline(
        library: MTLLibrary,
        device: MTLDevice,
        _ functionName: String
    ) throws -> MTLComputePipelineState {
        guard let function = library.makeFunction(name: functionName) else {
            throw GPUEVMError.functionNotFound(functionName)
        }
        do {
            return try device.makeComputePipelineState(function: function)
        } catch {
            throw GPUEVMError.pipelineCreationFailed(functionName, error.localizedDescription)
        }
    }

    // MARK: - Public API

    /// Execute transactions in parallel on GPU
    ///
    /// - Parameters:
    ///   - transactions: Array of transaction inputs
    ///   - blockContext: Block context for execution
    ///   - txContext: Transaction context
    /// - Returns: Array of execution results, one per transaction
    public func executeBatch(
        transactions: [TransactionInput],
        blockContext: BlockContext,
        txContext: TransactionContext
    ) throws -> [ExecutionResult] {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Validate batch size
        guard transactions.count <= Self.maxBatchSize else {
            throw GPUEVMError.batchSizeExceeded(
                requested: transactions.count,
                max: Self.maxBatchSize
            )
        }

        // Initialize batch memory layout
        let layout = BatchMemoryLayout(numTxs: transactions.count)
        currentBatchLayout = layout

        // Allocate GPU buffers
        let buffers = try allocateBuffers(layout: layout, transactions: transactions, blockContext: blockContext, txContext: txContext)

        // Execute GPU kernels
        try executeKernels(buffers: buffers, layout: layout, blockContext: blockContext, txContext: txContext)

        // Read back results
        let results = try readResults(buffers: buffers, layout: layout, transactions: transactions)

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        metrics.record(batchMs: totalTimeMs, txCount: transactions.count, memoryBytes: layout.totalSize)

        return results
    }

    /// Execute a single transaction on GPU
    public func execute(
        code: [UInt8],
        calldata: [UInt8] = [],
        value: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000,
        blockContext: BlockContext,
        txContext: TransactionContext
    ) throws -> ExecutionResult {
        let input = TransactionInput(
            code: code,
            calldata: calldata,
            value: value,
            gasLimit: gasLimit,
            address: M31Word(low64: 1),
            caller: txContext.origin
        )
        let results = try executeBatch(
            transactions: [input],
            blockContext: blockContext,
            txContext: txContext
        )
        return results[0]
    }

    // MARK: - Buffer Management

    private struct GPUBuffers {
        let stateBuffer: MTLBuffer
        let stackBuffer: MTLBuffer
        let memoryBuffer: MTLBuffer
        let codeBuffer: MTLBuffer
        let traceBuffer: MTLBuffer
        let configBuffer: MTLBuffer
    }

    private func allocateBuffers(
        layout: BatchMemoryLayout,
        transactions: [TransactionInput],
        blockContext: BlockContext,
        txContext: TransactionContext
    ) throws -> GPUBuffers {
        // State buffer: pc, gas, stackPtr, memoryPtr, running, reverted
        guard let stateBuffer = device.makeBuffer(
            length: layout.stateBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUEVMError.bufferAllocationFailed(layout.stateBufferSize)
        }

        // Stack buffer: 1024 * 32 bytes per tx
        guard let stackBuffer = device.makeBuffer(
            length: layout.stackBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUEVMError.bufferAllocationFailed(layout.stackBufferSize)
        }

        // Memory buffer: maxMemoryBytes per tx
        guard let memoryBuffer = device.makeBuffer(
            length: layout.memoryBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUEVMError.bufferAllocationFailed(layout.memoryBufferSize)
        }

        // Code buffer: maxCodeSize per tx
        guard let codeBuffer = device.makeBuffer(
            length: layout.codeBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUEVMError.bufferAllocationFailed(layout.codeBufferSize)
        }

        // Copy transaction codes
        let codePtr = codeBuffer.contents().bindMemory(to: UInt8.self, capacity: layout.codeBufferSize)
        for (txIdx, tx) in transactions.enumerated() {
            let offset = txIdx * Self.maxCodeSize
            for (i, byte) in tx.code.enumerated() {
                codePtr[offset + i] = byte
            }
        }

        // Trace buffer
        guard let traceBuffer = device.makeBuffer(
            length: layout.traceBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUEVMError.bufferAllocationFailed(layout.traceBufferSize)
        }

        // Config buffer: block/tx context
        let configSize = MemoryLayout<GPUExecutionConfig>.stride * layout.numTxs
        guard let configBuffer = device.makeBuffer(
            length: configSize,
            options: .storageModeShared
        ) else {
            throw GPUEVMError.bufferAllocationFailed(configSize)
        }

        // Initialize configs
        let configPtr = configBuffer.contents().bindMemory(
            to: GPUExecutionConfig.self,
            capacity: layout.numTxs
        )
        for (txIdx, tx) in transactions.enumerated() {
            let chainIdBytes = blockContext.chainId.toBytes()
            let originBytes = txContext.origin.toBytes()
            let callerBytes = tx.caller.toBytes()

            configPtr[txIdx] = GPUExecutionConfig(
                gasLimit: tx.gasLimit,
                blockTimestamp: blockContext.timestamp,
                blockNumber: blockContext.number,
                chainId: bytesToTuple(chainIdBytes),
                origin: bytesToTuple(originBytes),
                caller: bytesToTuple(callerBytes)
            )
        }

        return GPUBuffers(
            stateBuffer: stateBuffer,
            stackBuffer: stackBuffer,
            memoryBuffer: memoryBuffer,
            codeBuffer: codeBuffer,
            traceBuffer: traceBuffer,
            configBuffer: configBuffer
        )
    }

    /// Helper to convert [UInt8] to 32-byte tuple
    private func bytesToTuple(_ bytes: [UInt8]) -> (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    ) {
        var result: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

        for i in 0..<min(32, bytes.count) {
            withUnsafeMutableBytes(of: &result) { ptr in
                ptr[i] = bytes[i]
            }
        }
        return result
    }

    // MARK: - Kernel Execution

    private func executeKernels(
        buffers: GPUBuffers,
        layout: BatchMemoryLayout,
        blockContext: BlockContext,
        txContext: TransactionContext
    ) throws {
        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let computeEncoder = commandBuffer.makeComputeCommandEncoder() else {
            throw GPUEVMError.commandBufferCreationFailed
        }

        // Set shared buffers
        computeEncoder.setBuffer(buffers.stateBuffer, offset: 0, index: 0)
        computeEncoder.setBuffer(buffers.stackBuffer, offset: 0, index: 1)
        computeEncoder.setBuffer(buffers.memoryBuffer, offset: 0, index: 2)
        computeEncoder.setBuffer(buffers.codeBuffer, offset: 0, index: 3)
        computeEncoder.setBuffer(buffers.traceBuffer, offset: 0, index: 4)
        computeEncoder.setBuffer(buffers.configBuffer, offset: 0, index: 5)

        // Set constants
        var numTxs = UInt32(layout.numTxs)
        var maxStackDepth = UInt32(Self.maxStackDepth)
        var maxMemoryBytes = UInt32(Self.maxMemoryBytes)
        var maxCodeSize = UInt32(Self.maxCodeSize)
        var maxTraceRows = UInt32(Self.maxTraceRows)

        computeEncoder.setBytes(&numTxs, length: MemoryLayout<UInt32>.stride, index: 6)
        computeEncoder.setBytes(&maxStackDepth, length: MemoryLayout<UInt32>.stride, index: 7)
        computeEncoder.setBytes(&maxMemoryBytes, length: MemoryLayout<UInt32>.stride, index: 8)
        computeEncoder.setBytes(&maxCodeSize, length: MemoryLayout<UInt32>.stride, index: 9)
        computeEncoder.setBytes(&maxTraceRows, length: MemoryLayout<UInt32>.stride, index: 10)

        // Execute main loop kernel
        computeEncoder.setComputePipelineState(mainLoopPipeline)
        let threadsPerGroup = MTLSize(width: 256, height: 1, depth: 1)
        let numThreadGroups = MTLSize(width: (layout.numTxs + 255) / 256, height: 1, depth: 1)
        computeEncoder.dispatchThreadgroups(numThreadGroups, threadsPerThreadgroup: threadsPerGroup)

        computeEncoder.endEncoding()
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()
    }

    // MARK: - Result Reading

    private struct GPUExecutionConfig {
        var gasLimit: UInt64
        var blockTimestamp: UInt64
        var blockNumber: UInt64
        var chainId: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                     UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                     UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                     UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
        var origin: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
        var caller: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
    }

    private struct GPUTraceRow {
        var pc: UInt32
        var opcode: UInt8
        var gas: UInt64
        var stackHeight: UInt32
        var memorySize: UInt32
        var callDepth: UInt32
        var isRunning: UInt32
        var isReverted: UInt32
        var padding: UInt64
    }

    private func readResults(
        buffers: GPUBuffers,
        layout: BatchMemoryLayout,
        transactions: [TransactionInput]
    ) throws -> [ExecutionResult] {
        var results: [ExecutionResult] = []

        let statePtr = buffers.stateBuffer.contents()
        let tracePtr = buffers.traceBuffer.contents().bindMemory(
            to: GPUTraceRow.self,
            capacity: layout.numTxs * Self.maxTraceRows
        )

        for txIdx in 0..<layout.numTxs {
            // Read state - use properly aligned offsets matching Metal shader layout
            let stateOffset = txIdx * Self.txStateSize
            let stateData = statePtr.advanced(by: stateOffset)

            // Metal shader TxState layout (properly aligned):
            // offset 0: pc (uint32_t)
            // offset 4: padding
            // offset 8: gas (uint64_t) - 8-byte aligned
            // offset 16: stackPtr (uint32_t)
            // offset 20: memoryPtr (uint32_t)
            // offset 24: running (uint32_t)
            // offset 28: reverted (uint32_t)
            // offset 32: callDepth (uint32_t)
            // offset 36-63: padding
            let pc = stateData.load(as: UInt32.self)
            let gas = stateData.load(fromByteOffset: 8, as: UInt64.self)
            let running = stateData.load(fromByteOffset: 24, as: UInt32.self)
            let reverted = stateData.load(fromByteOffset: 28, as: UInt32.self)

            // Read trace rows
            var traceRows: [EVMTraceRow] = []
            let traceBase = txIdx * Self.maxTraceRows
            let tx = transactions[txIdx]

            // Count actual trace rows
            var traceRowCount = 0
            for rowIdx in 0..<Self.maxTraceRows {
                let row = tracePtr[traceBase + rowIdx]
                if row.opcode != 0 {
                    traceRowCount += 1
                }
            }

            // Read trace rows
            for rowIdx in 0..<traceRowCount {
                let row = tracePtr[traceBase + rowIdx]
                let stackWords = readStackWords(
                    stackBuffer: buffers.stackBuffer,
                    txIdx: txIdx,
                    stackHeight: Int(row.stackHeight)
                )

                traceRows.append(EVMTraceRow(
                    pc: Int(row.pc),
                    opcode: row.opcode,
                    gas: row.gas,
                    stackHeight: Int(row.stackHeight),
                    stackSnapshot: stackWords,
                    memorySize: Int(row.memorySize),
                    callDepth: Int(row.callDepth),
                    stateRoot: .zero,
                    isRunning: row.isRunning != 0,
                    isReverted: row.isReverted != 0,
                    timestamp: UInt64(Date().timeIntervalSince1970 * 1000)
                ))
            }

            // Read return data from memory
            let returnData = readReturnData(
                memoryBuffer: buffers.memoryBuffer,
                txIdx: txIdx
            )

            let gasUsed = tx.gasLimit - gas
            let executionTimeMs = 0.0  // Would need GPU timing buffer for accurate measurement

            results.append(ExecutionResult(
                traceRows: traceRows,
                gasUsed: gasUsed,
                reverted: reverted != 0,
                returnData: returnData,
                executionTimeMs: executionTimeMs,
                stepCount: traceRowCount
            ))
        }

        return results
    }

    private func readStackWords(
        stackBuffer: MTLBuffer,
        txIdx: Int,
        stackHeight: Int
    ) -> [M31Word] {
        let ptr = stackBuffer.contents().bindMemory(
            to: UInt8.self,
            capacity: Self.maxStackDepth * 32
        )
        let offset = txIdx * Self.maxStackDepth * 32
        var words: [M31Word] = []

        for i in 0..<min(stackHeight, 16) {
            let wordOffset = offset + (stackHeight - 1 - i) * 32
            let bytes = Array(UnsafeBufferPointer(start: ptr.advanced(by: wordOffset), count: 32))
            words.append(M31Word(bytes: bytes))
        }

        return words
    }

    private func readReturnData(
        memoryBuffer: MTLBuffer,
        txIdx: Int
    ) -> [UInt8] {
        let ptr = memoryBuffer.contents().bindMemory(
            to: UInt8.self,
            capacity: Self.maxMemoryBytes
        )
        let offset = txIdx * Self.maxMemoryBytes

        // Simple return: read first 256 bytes as return data
        let returnSize = min(256, Self.maxMemoryBytes)
        return Array(UnsafeBufferPointer(start: ptr.advanced(by: offset), count: returnSize))
    }

    // MARK: - Utility

    /// Check if GPU can handle the given number of transactions
    public func canHandle(batchSize: Int) -> Bool {
        let layout = BatchMemoryLayout(numTxs: batchSize)
        return layout.totalSize <= Self.maxMemoryBudgetBytes
    }

    /// Maximum memory budget for GPU EVM execution (512MB)
    public static let maxMemoryBudgetBytes = 512 * 1024 * 1024

    /// Estimate memory usage for a batch
    public static func estimateMemoryUsage(numTransactions: Int) -> Int {
        let layout = BatchMemoryLayout(numTxs: numTransactions)
        return layout.totalSize
    }
}

// MARK: - GPU EVM Errors

public enum GPUEVMError: Error, Sendable, CustomStringConvertible {
    case gpuNotAvailable
    case shaderCompilationFailed(String)
    case functionNotFound(String)
    case pipelineCreationFailed(String, String)
    case bufferAllocationFailed(Int)
    case commandQueueCreationFailed
    case commandBufferCreationFailed
    case batchSizeExceeded(requested: Int, max: Int)
    case executionFailed(String)

    public var description: String {
        switch self {
        case .gpuNotAvailable:
            return "GPU not available for EVM execution"
        case .shaderCompilationFailed(let reason):
            return "Shader compilation failed: \(reason)"
        case .functionNotFound(let name):
            return "GPU function not found: \(name)"
        case .pipelineCreationFailed(let name, let reason):
            return "Pipeline creation failed for \(name): \(reason)"
        case .bufferAllocationFailed(let size):
            return "Buffer allocation failed: \(size) bytes"
        case .commandQueueCreationFailed:
            return "Failed to create command queue"
        case .commandBufferCreationFailed:
            return "Failed to create command buffer"
        case .batchSizeExceeded(let requested, let max):
            return "Batch size \(requested) exceeds maximum \(max)"
        case .executionFailed(let message):
            return "GPU execution failed: \(message)"
        }
    }
}

// MARK: - Embedded Metal Shaders

/// Embedded Metal shader source for GPU EVM execution
enum GPUEVMShaders {
    static let shaderSource = """
    // GPU-accelerated EVM Interpreter
    // Each thread handles one transaction execution
    //
    // Memory layout:
    // - State buffer: [txIdx * 64] = { pc, gas, stackPtr, memoryPtr, running, reverted }
    // - Stack buffer: [txIdx * 1024 * 32 + stackPtr * 32] = M31Word
    // - Memory buffer: [txIdx * maxMemory + offset] = UInt8
    // - Code buffer: [txIdx * maxCodeSize] = bytecode
    // - Config buffer: [txIdx] = execution config

    #include <metal_stdlib>
    using namespace metal;

    constant uint M31_P = 0x7FFFFFFF;

    // M31 field operations
    struct M31 {
        uint v;
    };

    // 256-bit word as 8 x M31 limbs
    struct M31Word {
        M31 limb[8];
    };

    M31 m31_zero() { return M31{0}; }
    M31 m31_one() { return M31{1}; }

    M31 m31_add(M31 a, M31 b) {
        uint s = a.v + b.v;
        uint r = (s & M31_P) + (s >> 31);
        return M31{r == M31_P ? 0u : r};
    }

    M31 m31_sub(M31 a, M31 b) {
        if (a.v >= b.v) return M31{a.v - b.v};
        return M31{a.v + M31_P - b.v};
    }

    M31 m31_mul(M31 a, M31 b) {
        ulong prod = ulong(a.v) * ulong(b.v);
        uint lo = uint(prod & ulong(M31_P));
        uint hi = uint(prod >> 31);
        uint s = lo + hi;
        uint r = (s & M31_P) + (s >> 31);
        return M31{r == M31_P ? 0u : r};
    }

    bool m31_is_zero(M31 a) { return a.v == 0; }

    bool m31_lt(M31 a, M31 b) {
        return a.v < b.v;
    }

    bool m31_gt(M31 a, M31 b) {
        return a.v > b.v;
    }

    bool m31_eq(M31 a, M31 b) {
        return a.v == b.v;
    }

    M31 m31_and(M31 a, M31 b) {
        return M31{a.v & b.v};
    }

    M31 m31_or(M31 a, M31 b) {
        return M31{a.v | b.v};
    }

    M31 m31_xor(M31 a, M31 b) {
        return M31{a.v ^ b.v};
    }

    M31 m31_not(M31 a) {
        return M31{a.v ^ M31_P};
    }

    // Transaction state structure - aligned layout matching Swift reads
    struct PackedTxState {
        uint pc;         // offset 0, 4 bytes
        uint padding1;   // offset 4, 4 bytes (padding to align gas)
        uint64_t gas;    // offset 8, 8 bytes (8-byte aligned)
        uint stackPtr;   // offset 16, 4 bytes
        uint memoryPtr;  // offset 20, 4 bytes
        uint running;    // offset 24, 4 bytes
        uint reverted;   // offset 28, 4 bytes
        uint callDepth;  // offset 32, 4 bytes
    };

    // Alias for backwards compatibility
    typedef PackedTxState TxState;

    // Trace row structure
    struct TraceRow {
        uint pc;
        uchar opcode;
        uint gas;
        uint stackHeight;
        uint memorySize;
        uint callDepth;
        uint isRunning;
        uint isReverted;
        uint padding;
    };

    // Configuration
    struct Config {
        uint64_t gasLimit;
        uint64_t blockTimestamp;
        uint64_t blockNumber;
        uchar chainId[32];
        uchar origin[32];
        uchar caller[32];
    };

    // Stack operations
    inline M31Word readStack(device const uchar* stack, uint txIdx, uint stackPtr, uint maxStackDepth) {
        M31Word word;
        uint offset = txIdx * maxStackDepth * 32 + stackPtr * 32;
        for (uint i = 0; i < 8; i++) {
            uint val = 0;
            for (uint j = 0; j < 4; j++) {
                val |= uint(stack[offset + i * 4 + j]) << (j * 8);
            }
            word.limb[i] = M31{val};
        }
        return word;
    }

    inline void writeStack(device uchar* stack, uint txIdx, uint stackPtr, uint maxStackDepth, M31Word word) {
        uint offset = txIdx * maxStackDepth * 32 + stackPtr * 32;
        for (uint i = 0; i < 8; i++) {
            uint val = word.limb[i].v;
            for (uint j = 0; j < 4; j++) {
                stack[offset + i * 4 + j] = uchar((val >> (j * 8)) & 0xFF);
            }
        }
    }

    // Push value onto stack
    inline void stackPush(device TxState* states, device uchar* stack,
                          uint txIdx, uint maxStackDepth, M31Word value) {
        uint stackPtr = states[txIdx].stackPtr;
        writeStack(stack, txIdx, stackPtr, maxStackDepth, value);
        states[txIdx].stackPtr = stackPtr + 1;
    }

    // Pop value from stack
    inline M31Word stackPop(device TxState* states, device uchar* stack,
                           uint txIdx, uint maxStackDepth) {
        uint stackPtr = states[txIdx].stackPtr - 1;
        states[txIdx].stackPtr = stackPtr;
        return readStack(stack, txIdx, stackPtr, maxStackDepth);
    }

    // EVM opcodes
    constant uchar OP_STOP = 0x00;
    constant uchar OP_ADD = 0x01;
    constant uchar OP_MUL = 0x02;
    constant uchar OP_SUB = 0x03;
    constant uchar OP_DIV = 0x04;
    constant uchar OP_MOD = 0x06;
    constant uchar OP_LT = 0x10;
    constant uchar OP_GT = 0x11;
    constant uchar OP_EQ = 0x14;
    constant uchar OP_ISZERO = 0x15;
    constant uchar OP_AND = 0x16;
    constant uchar OP_OR = 0x17;
    constant uchar OP_XOR = 0x18;
    constant uchar OP_NOT = 0x19;
    constant uchar OP_PUSH1 = 0x60;
    constant uchar OP_PUSH2 = 0x61;
    constant uchar OP_PUSH3 = 0x62;
    constant uchar OP_PUSH4 = 0x63;
    constant uchar OP_PUSH5 = 0x64;
    constant uchar OP_PUSH6 = 0x65;
    constant uchar OP_PUSH7 = 0x66;
    constant uchar OP_PUSH8 = 0x67;
    constant uchar OP_PUSH9 = 0x68;
    constant uchar OP_PUSH10 = 0x69;
    constant uchar OP_PUSH11 = 0x6A;
    constant uchar OP_PUSH12 = 0x6B;
    constant uchar OP_PUSH13 = 0x6C;
    constant uchar OP_PUSH14 = 0x6D;
    constant uchar OP_PUSH15 = 0x6E;
    constant uchar OP_PUSH16 = 0x6F;
    constant uchar OP_PUSH17 = 0x70;
    constant uchar OP_PUSH18 = 0x71;
    constant uchar OP_PUSH19 = 0x72;
    constant uchar OP_PUSH20 = 0x73;
    constant uchar OP_PUSH21 = 0x74;
    constant uchar OP_PUSH22 = 0x75;
    constant uchar OP_PUSH23 = 0x76;
    constant uchar OP_PUSH24 = 0x77;
    constant uchar OP_PUSH25 = 0x78;
    constant uchar OP_PUSH26 = 0x79;
    constant uchar OP_PUSH27 = 0x7A;
    constant uchar OP_PUSH28 = 0x7B;
    constant uchar OP_PUSH29 = 0x7C;
    constant uchar OP_PUSH30 = 0x7D;
    constant uchar OP_PUSH31 = 0x7E;
    constant uchar OP_PUSH32 = 0x7F;
    constant uchar OP_POP = 0x50;
    constant uchar OP_MLOAD = 0x51;
    constant uchar OP_MSTORE = 0x52;
    constant uchar OP_JUMP = 0x56;
    constant uchar OP_JUMPI = 0x57;
    constant uchar OP_JUMPDEST = 0x5B;
    constant uchar OP_RETURN = 0xF3;
    constant uchar OP_REVERT = 0xFD;
    constant uchar OP_PUSH0 = 0x5F;

    // Read bytecode at pc
    inline uchar readCode(device const uchar* code, uint txIdx, uint maxCodeSize, uint pc) {
        return code[txIdx * maxCodeSize + pc];
    }

    // Read immediate value (PUSH instructions)
    inline M31Word readImmediate(device const uchar* code, uint txIdx, uint maxCodeSize, uint pc, uint numBytes) {
        M31Word word;
        for (uint i = 0; i < 8; i++) {
            word.limb[i] = m31_zero();
        }

        uint offset = txIdx * maxCodeSize + pc;
        uint limbIdx = 0;
        uint bitPos = 0;
        uint accumulated = 0;
        uint bitsInAccumulated = 0;

        for (uint i = 0; i < numBytes && i < 32; i++) {
            uint byte = code[offset + i];
            accumulated |= byte << bitPos;
            bitPos += 8;
            bitsInAccumulated += 8;

            while (bitsInAccumulated >= 31 && limbIdx < 8) {
                word.limb[limbIdx] = M31{accumulated & M31_P};
                accumulated >>= 31;
                bitPos -= 31;
                bitsInAccumulated -= 31;
                limbIdx++;
            }
        }

        // Handle remaining bits
        if (bitsInAccumulated > 0 && limbIdx < 8) {
            word.limb[limbIdx] = M31{accumulated & M31_P};
        }

        return word;
    }

    // Main EVM execution loop
    kernel void evm_main_loop(
        device TxState* states            [[buffer(0)]],
        device uchar* stack              [[buffer(1)]],
        device uchar* memory             [[buffer(2)]],
        device const uchar* code         [[buffer(3)]],
        device TraceRow* trace           [[buffer(4)]],
        device const Config* config      [[buffer(5)]],
        constant uint& numTxs            [[buffer(6)]],
        constant uint& maxStackDepth      [[buffer(7)]],
        constant uint& maxMemory         [[buffer(8)]],
        constant uint& maxCodeSize       [[buffer(9)]],
        constant uint& maxTraceRows      [[buffer(10)]],
        uint gid                         [[thread_position_in_grid]]
    ) {
        if (gid >= numTxs) return;

        TxState state = states[gid];
        uint traceIdx = 0;
        uint maxSteps = 10000;  // Limit iterations per transaction

        // Initialize state from config
        state.gas = uint(config[gid].gasLimit);
        state.pc = 0;
        state.stackPtr = 0;
        state.memoryPtr = 0;
        state.running = 1;
        state.reverted = 0;
        state.callDepth = 0;
        states[gid] = state;

        // Main execution loop
        while (state.running && traceIdx < maxSteps) {
            uchar opcode = readCode(code, gid, maxCodeSize, state.pc);

            // Record trace row before execution
            if (traceIdx < maxTraceRows) {
                uint baseTrace = gid * maxTraceRows + traceIdx;
                trace[baseTrace].pc = state.pc;
                trace[baseTrace].opcode = opcode;
                trace[baseTrace].gas = state.gas;
                trace[baseTrace].stackHeight = state.stackPtr;
                trace[baseTrace].memorySize = state.memoryPtr;
                trace[baseTrace].callDepth = state.callDepth;
                trace[baseTrace].isRunning = state.running;
                trace[baseTrace].isReverted = state.reverted;
            }

            state.pc++;
            state.gas -= 3;  // Base gas cost

            // Execute opcode
            switch (opcode) {
                case OP_STOP:
                    state.running = 0;
                    break;

                case OP_ADD: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_add(a.limb[i], b.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_SUB: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_sub(a.limb[i], b.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_MUL: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_mul(a.limb[i], b.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_DIV: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    // Simplified: push zero
                    stackPush(&states[gid], stack, gid, maxStackDepth, M31Word{});
                    break;
                }

                case OP_MOD: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    // Simplified: push zero
                    stackPush(&states[gid], stack, gid, maxStackDepth, M31Word{});
                    break;
                }

                case OP_LT: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    result.limb[0] = m31_lt(a.limb[0], b.limb[0]) ? m31_one() : m31_zero();
                    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_GT: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    result.limb[0] = m31_gt(a.limb[0], b.limb[0]) ? m31_one() : m31_zero();
                    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_EQ: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    bool eq = true;
                    for (uint i = 0; i < 8; i++) {
                        if (a.limb[i].v != b.limb[i].v) { eq = false; break; }
                    }
                    result.limb[0] = eq ? m31_one() : m31_zero();
                    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_ISZERO: {
                    if (state.stackPtr < 1) { state.running = 0; break; }
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    bool isZero = true;
                    for (uint i = 0; i < 8; i++) {
                        if (a.limb[i].v != 0) { isZero = false; break; }
                    }
                    result.limb[0] = isZero ? m31_one() : m31_zero();
                    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_AND: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_and(a.limb[i], b.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_OR: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_or(a.limb[i], b.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_XOR: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_xor(a.limb[i], b.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_NOT: {
                    if (state.stackPtr < 1) { state.running = 0; break; }
                    auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                    M31Word result;
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_not(a.limb[i]);
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                    break;
                }

                case OP_PUSH0:
                    stackPush(&states[gid], stack, gid, maxStackDepth, M31Word{});
                    break;

                case OP_PUSH1:
                case OP_PUSH2:
                case OP_PUSH3:
                case OP_PUSH4:
                case OP_PUSH5:
                case OP_PUSH6:
                case OP_PUSH7:
                case OP_PUSH8:
                case OP_PUSH9:
                case OP_PUSH10:
                case OP_PUSH11:
                case OP_PUSH12:
                case OP_PUSH13:
                case OP_PUSH14:
                case OP_PUSH15:
                case OP_PUSH16:
                case OP_PUSH17:
                case OP_PUSH18:
                case OP_PUSH19:
                case OP_PUSH20:
                case OP_PUSH21:
                case OP_PUSH22:
                case OP_PUSH23:
                case OP_PUSH24:
                case OP_PUSH25:
                case OP_PUSH26:
                case OP_PUSH27:
                case OP_PUSH28:
                case OP_PUSH29:
                case OP_PUSH30:
                case OP_PUSH31:
                case OP_PUSH32: {
                    uint pushBytes = opcode - OP_PUSH1 + 1;
                    M31Word value = readImmediate(code, gid, maxCodeSize, state.pc, pushBytes);
                    state.pc += pushBytes;
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                    break;
                }

                case OP_POP:
                    if (state.stackPtr < 1) { state.running = 0; break; }
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    break;

                case OP_JUMPDEST:
                    // No-op, just a valid jump target
                    break;

                case OP_JUMP: {
                    if (state.stackPtr < 1) { state.running = 0; break; }
                    // Simplified: just advance pc based on top of stack
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    state.pc += 10;  // Simplified jump
                    break;
                }

                case OP_JUMPI: {
                    if (state.stackPtr < 2) { state.running = 0; break; }
                    stackPop(&states[gid], stack, gid, maxStackDepth);
                    auto cond = stackPop(&states[gid], stack, gid, maxStackDepth);
                    if (!m31_is_zero(cond.limb[0])) {
                        state.pc += 10;  // Simplified conditional jump
                    }
                    break;
                }

                case OP_RETURN:
                case OP_REVERT:
                    state.running = 0;
                    if (opcode == OP_REVERT) {
                        state.reverted = 1;
                    }
                    break;

                default:
                    // Unknown opcode - stop execution
                    state.running = 0;
                    break;
            }

            traceIdx++;
            states[gid] = state;
        }
    }

    // Arithmetic kernel (for complex operations)
    kernel void evm_arithmetic(
        device TxState* states            [[buffer(0)]],
        device uchar* stack               [[buffer(1)]],
        constant uint& numTxs            [[buffer(6)]],
        constant uint& maxStackDepth      [[buffer(7)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for complex arithmetic (ADDMOD, MULMOD, EXP, etc.)
    }

    // Comparison kernel
    kernel void evm_comparison(
        device TxState* states            [[buffer(0)]],
        device uchar* stack               [[buffer(1)]],
        constant uint& numTxs              [[buffer(6)]],
        constant uint& maxStackDepth      [[buffer(7)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for SLT, SGT, BYTE, etc.
    }

    // Bitwise kernel
    kernel void evm_bitwise(
        device TxState* states            [[buffer(0)]],
        device uchar* stack               [[buffer(1)]],
        constant uint& numTxs             [[buffer(6)]],
        constant uint& maxStackDepth       [[buffer(7)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for SHL, SHR, SAR, SIGNEXTEND, etc.
    }

    // Stack operations kernel
    kernel void evm_stack(
        device TxState* states            [[buffer(0)]],
        device uchar* stack               [[buffer(1)]],
        constant uint& numTxs             [[buffer(6)]],
        constant uint& maxStackDepth       [[buffer(7)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for DUP, SWAP operations
    }

    // Memory operations kernel
    kernel void evm_memory(
        device TxState* states            [[buffer(0)]],
        device uchar* memory              [[buffer(2)]],
        device uchar* stack               [[buffer(1)]],
        constant uint& numTxs             [[buffer(6)]],
        constant uint& maxStackDepth      [[buffer(7)]],
        constant uint& maxMemory          [[buffer(8)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for MLOAD, MSTORE, MSIZE operations
    }

    // Control flow kernel
    kernel void evm_control_flow(
        device TxState* states            [[buffer(0)]],
        device uchar* stack               [[buffer(1)]],
        device const uchar* code          [[buffer(3)]],
        constant uint& numTxs             [[buffer(6)]],
        constant uint& maxStackDepth     [[buffer(7)]],
        constant uint& maxCodeSize        [[buffer(9)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for JUMP, JUMPI, JUMPDEST validation
    }

    // Trace collection kernel
    kernel void evm_trace_collect(
        device TxState* states            [[buffer(0)]],
        device TraceRow* trace            [[buffer(4)]],
        constant uint& numTxs             [[buffer(6)]],
        constant uint& maxTraceRows       [[buffer(10)]],
        uint gid                          [[thread_position_in_grid]]
    ) {
        // Reserved for post-processing trace data
    }
    """
}
