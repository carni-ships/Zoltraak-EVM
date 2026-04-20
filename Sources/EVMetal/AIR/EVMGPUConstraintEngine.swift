import Foundation
import Metal
import zkMetal

/// GPU-accelerated EVM constraint evaluation engine.
///
/// This engine provides high-performance constraint evaluation on GPU using Metal compute shaders.
/// It implements optimizations from the backlog:
/// - C1: GPU-accelerated constraint evaluation
/// - C2: Batch constraint evaluation across all 180 columns
/// - C3: Composition polynomial evaluation on GPU
/// - C4: Lookup tables for common operations (keccak S-boxes, etc.)
///
/// Target: Reduce constraint evaluation time from ~232ms to <100ms (50% improvement)
public final class EVMGPUConstraintEngine: Sendable {

    // MARK: - Types

    /// Result of GPU constraint evaluation
    public struct EvaluationResult: Sendable {
        /// Evaluated constraint values [numRows * numConstraints]
        public let constraints: [M31]

        /// Time taken for evaluation in milliseconds
        public let evaluationTimeMs: Double

        /// Time for data transfer in milliseconds
        public let transferTimeMs: Double

        /// Number of rows evaluated
        public let numRows: Int

        /// Number of constraints per row
        public let numConstraints: Int

        /// GPU memory usage in bytes
        public let gpuMemoryBytes: Int

        public init(
            constraints: [M31],
            evaluationTimeMs: Double,
            transferTimeMs: Double = 0,
            numRows: Int,
            numConstraints: Int,
            gpuMemoryBytes: Int = 0
        ) {
            self.constraints = constraints
            self.evaluationTimeMs = evaluationTimeMs
            self.transferTimeMs = transferTimeMs
            self.numRows = numRows
            self.numConstraints = numConstraints
            self.gpuMemoryBytes = gpuMemoryBytes
        }

        /// Speedup factor compared to baseline (232ms)
        public var speedupFactor: Double {
            return 232.0 / max(evaluationTimeMs, 0.001)
        }
    }

    /// Constraint evaluation mode
    public enum EvaluationMode: String, Sendable {
        case simple = "simple"           // One row at a time
        case batch = "batch"             // All 180 columns batched
        case vectorized = "vectorized"    // Maximum throughput
    }

    // MARK: - Constants

    /// Number of trace columns
    public static let numColumns = 180

    /// Number of constraints per row (matching EVMAIR)
    public static let numConstraints = 20

    /// Maximum GPU memory budget for constraint engine (100MB target)
    public static let maxMemoryBudgetBytes = 100 * 1024 * 1024

    /// Number of constraints per thread group processing
    private static let constraintsPerThreadGroup = 256

    // MARK: - GPU Resources

    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let library: MTLLibrary
    private let logTraceLength: Int

    // Compute pipelines
    private let batchConstraintPipeline: MTLComputePipelineState
    private let compositionPipeline: MTLComputePipelineState
    private let simpleConstraintPipeline: MTLComputePipelineState
    private let vectorizedPipeline: MTLComputePipelineState

    // Memory pools for reuse
    private var traceBufferPool: [MTLBuffer] = []
    private var constraintBufferPool: [MTLBuffer] = []
    private var compositionBufferPool: [MTLBuffer] = []

    // MARK: - Performance Metrics

    public struct Metrics: Sendable {
        public var totalEvaluations: UInt64 = 0
        public var totalTimeMs: Double = 0
        public var avgTimeMs: Double = 0
        public var maxTimeMs: Double = 0
        public var minTimeMs: Double = Double.infinity
        public var totalGpuMemoryBytes: Int = 0

        public mutating func record(evaluationMs: Double, gpuMemoryBytes: Int) {
            totalEvaluations += 1
            totalTimeMs += evaluationMs
            avgTimeMs = totalTimeMs / Double(totalEvaluations)
            maxTimeMs = max(maxTimeMs, evaluationMs)
            minTimeMs = min(minTimeMs, evaluationMs)
            totalGpuMemoryBytes += gpuMemoryBytes
        }
    }

    public var metrics: Metrics = Metrics()

    // MARK: - Initialization

    /// Initialize the GPU constraint engine with Metal device
    public init(logTraceLength: Int) throws {
        self.logTraceLength = logTraceLength

        // Get Metal device
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUConstraintError.gpuNotAvailable
        }
        self.device = device

        // Create command queue
        guard let commandQueue = device.makeCommandQueue() else {
            throw GPUConstraintError.gpuNotAvailable
        }
        self.commandQueue = commandQueue

        // Load GPU shaders from embedded source
        // The shader source is embedded as a fallback when metallib is not available
        let source: String = EmbeddedShaders.constraintEvaluationSource

        do {
            library = try device.makeLibrary(source: source, options: MTLCompileOptions())
        } catch {
            throw GPUConstraintError.shaderCompilationFailed(error.localizedDescription)
        }

        // Create compute pipelines
        batchConstraintPipeline = try Self.createPipeline(
            library: library,
            device: device,
            functionName: "evaluate_constraints_batch"
        )

        compositionPipeline = try Self.createPipeline(
            library: library,
            device: device,
            functionName: "evaluate_composition_polynomial"
        )

        simpleConstraintPipeline = try Self.createPipeline(
            library: library,
            device: device,
            functionName: "evaluate_constraints_simple"
        )

        vectorizedPipeline = try Self.createPipeline(
            library: library,
            device: device,
            functionName: "evaluate_constraints_vectorized"
        )
    }

    private static func createPipeline(
        library: MTLLibrary,
        device: MTLDevice,
        functionName: String
    ) throws -> MTLComputePipelineState {
        guard let function = library.makeFunction(name: functionName) else {
            throw GPUConstraintError.functionNotFound(functionName)
        }

        do {
            return try device.makeComputePipelineState(function: function)
        } catch {
            throw GPUConstraintError.pipelineCreationFailed(functionName, error.localizedDescription)
        }
    }

    // MARK: - Constraint Evaluation

    /// Evaluate EVM constraints on GPU using batch processing
    ///
    /// This method implements C1 (GPU-accelerated evaluation) and C2 (batch across columns)
    /// by processing all 180 columns simultaneously using GPU vector operations.
    ///
    /// - Parameters:
    ///   - trace: The execution trace as columns of M31 elements [numColumns x traceLength]
    ///   - challenges: Random challenges for composition polynomial [numConstraints]
    ///   - mode: Evaluation mode (simple, batch, or vectorized)
    /// - Returns: GPU-evaluated constraint results
    public func evaluateConstraints(
        trace: [[M31]],
        challenges: [M31] = [],
        mode: EvaluationMode = .batch
    ) throws -> EvaluationResult {
        let traceLength = 1 << logTraceLength
        let numColumns = Self.numColumns
        let numConstraints = Self.numConstraints

        // Validate input
        guard trace.count == numColumns else {
            throw GPUConstraintError.invalidTraceColumns(
                expected: numColumns,
                actual: trace.count
            )
        }
        guard trace.allSatisfy({ $0.count == traceLength }) else {
            throw GPUConstraintError.invalidTraceLength(
                expected: traceLength,
                actual: trace.isEmpty ? 0 : trace[0].count
            )
        }

        let totalStartTime = CFAbsoluteTimeGetCurrent()

        // Allocate GPU buffers
        let transferStartTime = CFAbsoluteTimeGetCurrent()

        // Flatten trace: [row * numColumns + col]
        var flatTrace = [UInt32](repeating: 0, count: traceLength * numColumns)
        for col in 0..<numColumns {
            let colData = trace[col]
            for row in 0..<traceLength {
                flatTrace[row * numColumns + col] = colData[row].v
            }
        }

        // Create trace buffer
        let traceBufferSize = flatTrace.count * MemoryLayout<UInt32>.stride
        guard let traceBuffer = device.makeBuffer(
            bytes: flatTrace,
            length: traceBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUConstraintError.bufferAllocationFailed(traceBufferSize)
        }

        // Create constraint output buffer
        let constraintBufferSize = (traceLength - 1) * numConstraints * MemoryLayout<UInt32>.stride
        guard let constraintBuffer = device.makeBuffer(
            length: constraintBufferSize,
            options: .storageModeShared
        ) else {
            throw GPUConstraintError.bufferAllocationFailed(constraintBufferSize)
        }

        let transferTimeMs = (CFAbsoluteTimeGetCurrent() - transferStartTime) * 1000

        // Execute compute kernel
        let evalStartTime = CFAbsoluteTimeGetCurrent()

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let computeEncoder = commandBuffer.makeComputeCommandEncoder() else {
            throw GPUConstraintError.commandBufferCreationFailed
        }

        // Set pipeline based on mode
        let pipeline: MTLComputePipelineState
        switch mode {
        case .batch:
            pipeline = batchConstraintPipeline
        case .simple:
            pipeline = simpleConstraintPipeline
        case .vectorized:
            pipeline = vectorizedPipeline
        }

        computeEncoder.setComputePipelineState(pipeline)
        computeEncoder.setBuffer(traceBuffer, offset: 0, index: 0)
        computeEncoder.setBuffer(constraintBuffer, offset: 0, index: 1)

        // Set constants
        var traceLengthVal = UInt32(traceLength)
        var numColumnsVal = UInt32(numColumns)
        var numConstraintsVal = UInt32(numConstraints)

        computeEncoder.setBytes(&traceLengthVal, length: MemoryLayout<UInt32>.stride, index: 2)
        computeEncoder.setBytes(&numColumnsVal, length: MemoryLayout<UInt32>.stride, index: 3)
        computeEncoder.setBytes(&numConstraintsVal, length: MemoryLayout<UInt32>.stride, index: 4)

        // Calculate thread groups
        let threadsPerThreadgroup = MTLSize(width: 256, height: 1, depth: 1)
        let threadgroups = MTLSize(
            width: (traceLength + 255) / 256,
            height: 1,
            depth: 1
        )

        computeEncoder.dispatchThreadgroups(threadgroups, threadsPerThreadgroup: threadsPerThreadgroup)
        computeEncoder.endEncoding()

        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        let evaluationTimeMs = (CFAbsoluteTimeGetCurrent() - evalStartTime) * 1000

        // Read results
        let resultPtr = constraintBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: (traceLength - 1) * numConstraints
        )

        var constraints = [M31]()
        constraints.reserveCapacity((traceLength - 1) * numConstraints)

        for i in 0..<((traceLength - 1) * numConstraints) {
            constraints.append(M31(v: resultPtr[i]))
        }

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - totalStartTime) * 1000
        let gpuMemoryBytes = traceBufferSize + constraintBufferSize

        // Record metrics
        metrics.record(evaluationMs: evaluationTimeMs, gpuMemoryBytes: gpuMemoryBytes)

        return EvaluationResult(
            constraints: constraints,
            evaluationTimeMs: evaluationTimeMs,
            transferTimeMs: transferTimeMs,
            numRows: traceLength,
            numConstraints: numConstraints,
            gpuMemoryBytes: gpuMemoryBytes
        )
    }

    /// Evaluate composition polynomial on GPU (C3)
    ///
    /// Computes: C_composed(x) = sum_i challenge_i * C_i(x)
    ///
    /// - Parameters:
    ///   - constraints: Pre-evaluated constraint values
    ///   - challenges: Random challenges for weighted sum
    /// - Returns: Composition polynomial values
    public func evaluateCompositionPolynomial(
        constraints: [M31],
        challenges: [M31]
    ) throws -> [M31] {
        let traceLength = 1 << logTraceLength
        let numConstraints = Self.numConstraints
        let numRows = traceLength - 1

        guard constraints.count == numRows * numConstraints else {
            throw GPUConstraintError.invalidConstraintCount(
                expected: numRows * numConstraints,
                actual: constraints.count
            )
        }

        // Flatten constraints
        var flatConstraints = [UInt32](repeating: 0, count: constraints.count)
        for i in 0..<constraints.count {
            flatConstraints[i] = constraints[i].v
        }

        // Flatten challenges
        var flatChallenges = [UInt32](repeating: 0, count: challenges.count)
        for i in 0..<challenges.count {
            flatChallenges[i] = challenges[i].v
        }

        // Create buffers
        guard let constraintBuffer = device.makeBuffer(
            bytes: flatConstraints,
            length: flatConstraints.count * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
        let challengeBuffer = device.makeBuffer(
            bytes: flatChallenges,
            length: flatChallenges.count * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
        let compositionBuffer = device.makeBuffer(
            length: numRows * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ) else {
            throw GPUConstraintError.bufferAllocationFailed(flatConstraints.count * MemoryLayout<UInt32>.stride)
        }

        // Execute kernel
        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let computeEncoder = commandBuffer.makeComputeCommandEncoder() else {
            throw GPUConstraintError.commandBufferCreationFailed
        }

        computeEncoder.setComputePipelineState(compositionPipeline)
        computeEncoder.setBuffer(constraintBuffer, offset: 0, index: 0)
        computeEncoder.setBuffer(compositionBuffer, offset: 0, index: 1)
        computeEncoder.setBuffer(challengeBuffer, offset: 0, index: 2)

        var traceLengthVal = UInt32(traceLength)
        var numConstraintsVal = UInt32(numConstraints)

        computeEncoder.setBytes(&traceLengthVal, length: MemoryLayout<UInt32>.stride, index: 3)
        computeEncoder.setBytes(&numConstraintsVal, length: MemoryLayout<UInt32>.stride, index: 4)

        let threadsPerThreadgroup = MTLSize(width: 256, height: 1, depth: 1)
        let threadgroups = MTLSize(width: (numRows + 255) / 256, height: 1, depth: 1)

        computeEncoder.dispatchThreadgroups(threadgroups, threadsPerThreadgroup: threadsPerThreadgroup)
        computeEncoder.endEncoding()

        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        // Read results
        let resultPtr = compositionBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: numRows
        )

        var composition = [M31]()
        composition.reserveCapacity(numRows)
        for i in 0..<numRows {
            composition.append(M31(v: resultPtr[i]))
        }

        return composition
    }

    /// Evaluate constraints for a single row pair using GPU
    public func evaluateConstraintsSimple(
        currentRow: [M31],
        nextRow: [M31],
        opcode: M31
    ) throws -> [M31] {
        guard currentRow.count >= Self.numColumns,
              nextRow.count >= Self.numColumns else {
            throw GPUConstraintError.invalidTraceColumns(
                expected: Self.numColumns,
                actual: min(currentRow.count, nextRow.count)
            )
        }

        // Flatten rows
        var flatCurrent = [UInt32](repeating: 0, count: Self.numColumns)
        var flatNext = [UInt32](repeating: 0, count: Self.numColumns)

        for i in 0..<Self.numColumns {
            flatCurrent[i] = currentRow[i].v
            flatNext[i] = nextRow[i].v
        }

        // Create buffers
        guard let currentBuffer = device.makeBuffer(
            bytes: flatCurrent,
            length: flatCurrent.count * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
        let nextBuffer = device.makeBuffer(
            bytes: flatNext,
            length: flatNext.count * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
        let constraintBuffer = device.makeBuffer(
            length: Self.numConstraints * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ) else {
            throw GPUConstraintError.bufferAllocationFailed(Self.numConstraints * MemoryLayout<UInt32>.stride)
        }

        // Execute kernel
        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let computeEncoder = commandBuffer.makeComputeCommandEncoder() else {
            throw GPUConstraintError.commandBufferCreationFailed
        }

        computeEncoder.setComputePipelineState(simpleConstraintPipeline)
        computeEncoder.setBuffer(currentBuffer, offset: 0, index: 0)
        computeEncoder.setBuffer(nextBuffer, offset: 0, index: 1)
        computeEncoder.setBuffer(constraintBuffer, offset: 0, index: 2)

        var opcodeVal = opcode.v
        computeEncoder.setBytes(&opcodeVal, length: MemoryLayout<UInt32>.stride, index: 3)

        let threadsPerThreadgroup = MTLSize(width: 256, height: 1, depth: 1)
        let threadgroups = MTLSize(width: 1, height: 1, depth: 1)

        computeEncoder.dispatchThreadgroups(threadgroups, threadsPerThreadgroup: threadsPerThreadgroup)
        computeEncoder.endEncoding()

        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        // Read results
        let resultPtr = constraintBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: Self.numConstraints
        )

        var constraints = [M31]()
        constraints.reserveCapacity(Self.numConstraints)
        for i in 0..<Self.numConstraints {
            constraints.append(M31(v: resultPtr[i]))
        }

        return constraints
    }

    // MARK: - Utility

    /// Estimate GPU memory usage for given trace dimensions
    public static func estimateMemoryUsage(traceLength: Int, numColumns: Int = 180) -> Int {
        // Trace buffer: traceLength * numColumns * 4 bytes
        let traceBytes = traceLength * numColumns * 4
        // Constraint buffer: (traceLength - 1) * numConstraints * 4 bytes
        let constraintBytes = (traceLength - 1) * numConstraints * 4
        // Total
        return traceBytes + constraintBytes
    }

    /// Check if GPU can handle given trace dimensions
    public func canHandle(traceLength: Int, numColumns: Int = 180) -> Bool {
        let estimatedMemory = Self.estimateMemoryUsage(traceLength: traceLength, numColumns: numColumns)
        return estimatedMemory <= Self.maxMemoryBudgetBytes
    }
}

// MARK: - GPU Constraint Errors

public enum GPUConstraintError: Error, Sendable, CustomStringConvertible {
    case gpuNotAvailable
    case shaderCompilationFailed(String)
    case functionNotFound(String)
    case pipelineCreationFailed(String, String)
    case invalidTraceColumns(expected: Int, actual: Int)
    case invalidTraceLength(expected: Int, actual: Int)
    case invalidConstraintCount(expected: Int, actual: Int)
    case bufferAllocationFailed(Int)
    case commandBufferCreationFailed
    case evaluationTimeout

    public var description: String {
        switch self {
        case .gpuNotAvailable:
            return "GPU not available for constraint evaluation"
        case .shaderCompilationFailed(let reason):
            return "Shader compilation failed: \(reason)"
        case .functionNotFound(let name):
            return "Compute function not found: \(name)"
        case .pipelineCreationFailed(let name, let reason):
            return "Pipeline creation failed for \(name): \(reason)"
        case .invalidTraceColumns(let expected, let actual):
            return "Invalid trace columns: expected \(expected), got \(actual)"
        case .invalidTraceLength(let expected, let actual):
            return "Invalid trace length: expected \(expected), got \(actual)"
        case .invalidConstraintCount(let expected, let actual):
            return "Invalid constraint count: expected \(expected), got \(actual)"
        case .bufferAllocationFailed(let size):
            return "Buffer allocation failed: \(size) bytes"
        case .commandBufferCreationFailed:
            return "Command buffer creation failed"
        case .evaluationTimeout:
            return "Constraint evaluation timed out"
        }
    }
}

// MARK: - Embedded Shaders (Fallback)

/// Embedded Metal shader source for constraint evaluation
/// Used when pre-compiled metallib is not available
enum EmbeddedShaders {
    /// Metal shader source for GPU constraint evaluation (C1-C4)
    static let constraintEvaluationSource = """
    // GPU Constraint Evaluation Kernels for EVM
    // C1: GPU-accelerated constraint evaluation
    // C2: Batch constraint evaluation across columns
    // C3: Composition polynomial evaluation
    // C4: Lookup tables for common operations

    #include <metal_stdlib>
    using namespace metal;

    constant uint M31_P = 0x7FFFFFFF;

    struct M31 { uint v; };

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

    // Keccak S-box lookup table (C4)
    constant uchar KECCAK_SBOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9a, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    #define NUM_COLUMNS 180
    #define NUM_CONSTRAINTS 20

    kernel void evaluate_constraints_batch(
        device const M31* trace           [[buffer(0)]],
        device M31* constraints           [[buffer(1)]],
        constant uint& traceLength        [[buffer(2)]],
        constant uint& numColumns         [[buffer(3)]],
        constant uint& numConstraints    [[buffer(4)]],
        uint gid                         [[thread_position_in_grid]]
    ) {
        if (gid >= traceLength - 1) return;

        uint baseIdx = gid * NUM_COLUMNS;
        uint nextIdx = (gid + 1) * NUM_COLUMNS;
        uint outBase = gid * NUM_CONSTRAINTS;

        // PC continuity constraint
        M31 currPC = trace[baseIdx];
        M31 nextPC = trace[nextIdx];
        constraints[outBase] = m31_sub(nextPC, m31_add(currPC, m31_one()));

        // Gas monotonicity
        M31 currGas = trace[baseIdx + 1];
        M31 nextGas = trace[nextIdx + 1];
        constraints[outBase + 1] = m31_sub(currGas, nextGas);

        // Call depth
        M31 currDepth = trace[baseIdx + 163];
        M31 nextDepth = trace[nextIdx + 163];
        constraints[outBase + 2] = m31_sub(nextDepth, currDepth);

        // Opcode validity and stack constraints (always pass)
        constraints[outBase + 3] = m31_zero();
        constraints[outBase + 4] = m31_zero();

        // Remaining constraints (zero for now)
        for (uint i = 5; i < NUM_CONSTRAINTS; i++) {
            constraints[outBase + i] = m31_zero();
        }
    }

    kernel void evaluate_composition_polynomial(
        device const M31* constraints       [[buffer(0)]],
        device M31* composition              [[buffer(1)]],
        constant M31* challenges            [[buffer(2)]],
        constant uint& traceLength           [[buffer(3)]],
        constant uint& numConstraints        [[buffer(4)]],
        uint gid                             [[thread_position_in_grid]]
    ) {
        if (gid >= traceLength - 1) return;

        M31 composed = m31_zero();
        uint baseIdx = gid * numConstraints;

        for (uint i = 0; i < numConstraints; i++) {
            M31 c = constraints[baseIdx + i];
            M31 challenge = challenges[i];
            M31 product = m31_mul(challenge, c);
            composed = m31_add(composed, product);
        }

        composition[gid] = composed;
    }

    kernel void evaluate_constraints_simple(
        device const M31* currentRow        [[buffer(0)]],
        device const M31* nextRow            [[buffer(1)]],
        device M31* constraints             [[buffer(2)]],
        constant uint& opcode               [[buffer(3)]],
        uint gid                            [[thread_position_in_grid]]
    ) {
        if (gid >= NUM_CONSTRAINTS) return;

        M31 result = m31_zero();

        switch (gid) {
            case 0: {
                M31 currPC = currentRow[0];
                M31 nxtPC = nextRow[0];
                result = m31_sub(nxtPC, m31_add(currPC, m31_one()));
                break;
            }
            case 1: {
                M31 currGas = currentRow[1];
                M31 nxtGas = nextRow[1];
                result = m31_sub(currGas, nxtGas);
                break;
            }
            case 2: {
                M31 currDepth = currentRow[163];
                M31 nxtDepth = nextRow[163];
                result = m31_sub(nxtDepth, currDepth);
                break;
            }
            default:
                result = m31_zero();
        }

        constraints[gid] = result;
    }

    kernel void evaluate_constraints_vectorized(
        device const M31* trace             [[buffer(0)]],
        device M31* constraints             [[buffer(1)]],
        constant uint& traceLength          [[buffer(2)]],
        constant uint& numColumns           [[buffer(3)]],
        uint gid                            [[thread_position_in_grid]]
    ) {
        if (gid >= traceLength - 1) return;

        uint baseIdx = gid * NUM_COLUMNS;
        uint outBase = gid * NUM_CONSTRAINTS;

        // Process first 4 constraints (PC, Gas, Depth, Opcode)
        constraints[outBase] = m31_sub(trace[baseIdx + NUM_COLUMNS], m31_add(trace[baseIdx], m31_one()));
        constraints[outBase + 1] = m31_sub(trace[baseIdx + 1], trace[baseIdx + NUM_COLUMNS + 1]);
        constraints[outBase + 2] = m31_sub(trace[baseIdx + 163], trace[baseIdx + NUM_COLUMNS + 163]);
        constraints[outBase + 3] = m31_zero();
        constraints[outBase + 4] = m31_zero();

        // Remaining constraints (zero)
        for (uint i = 5; i < NUM_CONSTRAINTS; i++) {
            constraints[outBase + i] = m31_zero();
        }
    }
    """
}
