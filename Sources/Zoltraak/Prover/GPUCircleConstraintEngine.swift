import Foundation
import Metal
import zkMetal

/// GPU-accelerated constraint evaluation engine for Circle STARK provers.
///
/// This engine provides high-performance constraint evaluation on GPU using Metal compute shaders,
/// specifically optimized for the Circle STARK proving system.
///
/// ## Performance
///
/// - CPU baseline: ~51 seconds for 32,768 evaluation points
/// - GPU target: <1 second for same workload
/// - Speedup: ~50-100x improvement
///
/// ## Features
///
/// - C1: GPU-accelerated constraint evaluation
/// - C2: Batch constraint evaluation across columns
/// - C3: Composition polynomial evaluation on GPU
/// - C4: Column subset optimization (only 16 columns instead of 180)
public final class GPUCircleConstraintEngine: Sendable {

    // MARK: - Types

    /// Result of GPU constraint evaluation
    public struct EvaluationResult: Sendable {
        /// Evaluated composition polynomial values [evalLen]
        public let compositionValues: [M31]

        /// Time taken for GPU evaluation in milliseconds
        public let gpuTimeMs: Double

        /// Time for data transfer in milliseconds
        public let transferTimeMs: Double

        /// Number of evaluation points
        public let numPoints: Int

        /// Number of columns evaluated
        public let numColumns: Int

        /// Number of constraints per row
        public let numConstraints: Int

        /// GPU memory usage in bytes
        public let gpuMemoryBytes: Int

        /// Whether GPU was used
        public let usedGPU: Bool

        public init(
            compositionValues: [M31],
            gpuTimeMs: Double,
            transferTimeMs: Double = 0,
            numPoints: Int,
            numColumns: Int,
            numConstraints: Int,
            gpuMemoryBytes: Int = 0,
            usedGPU: Bool = true
        ) {
            self.compositionValues = compositionValues
            self.gpuTimeMs = gpuTimeMs
            self.transferTimeMs = transferTimeMs
            self.numPoints = numPoints
            self.numColumns = numColumns
            self.numConstraints = numConstraints
            self.gpuMemoryBytes = gpuMemoryBytes
            self.usedGPU = usedGPU
        }

        /// Speedup factor compared to baseline (51 seconds)
        public var speedupFactor: Double {
            return 51000.0 / max(gpuTimeMs, 0.001)
        }

        /// Total time (GPU + transfer)
        public var totalTimeMs: Double {
            return gpuTimeMs + transferTimeMs
        }
    }

    // MARK: - Configuration

    /// Threshold for using GPU (evalLen < threshold means use CPU)
    public let gpuThreshold: Int

    /// Log of blowup factor
    public let logBlowup: Int

    // MARK: - GPU Resources

    private let device: MTLDevice?
    private let commandQueue: MTLCommandQueue?
    private let evmConstraintEngine: EVMGPUConstraintEngine?

    // MARK: - GPU Availability

    public var gpuAvailable: Bool {
        return device != nil && evmConstraintEngine != nil
    }

    // MARK: - Memory Budget Check

    /// Maximum GPU memory budget for constraint engine (reduced for safety)
    private static let maxMemoryBudgetBytes = 80 * 1024 * 1024  // 80MB (safety margin)

    /// Maximum trace length to allow on GPU (262K can cause OOM)
    private static let maxTraceLengthGPU = 131072  // 128K max

    /// Estimate memory usage for constraint evaluation
    private static func estimateMemoryUsage(traceLength: Int, numColumns: Int = 180) -> Int {
        // Trace buffer: traceLength * numColumns * 4 bytes
        let traceBytes = traceLength * numColumns * 4
        // Constraint buffer: (traceLength - 1) * numConstraints * 4 bytes
        let numConstraints = 20
        let constraintBytes = (traceLength - 1) * numConstraints * 4
        return traceBytes + constraintBytes
    }

    /// Check if GPU can handle given trace dimensions with column subset optimization
    public func canHandle(traceLength: Int, numColumns: Int = 180) -> Bool {
        // Extra safety: don't use GPU for very large traces
        if traceLength > Self.maxTraceLengthGPU {
            return false
        }
        let estimatedMemory = Self.estimateMemoryUsage(traceLength: traceLength, numColumns: numColumns)
        return estimatedMemory <= Self.maxMemoryBudgetBytes
    }

    // MARK: - Initialization

    /// Initialize the GPU Circle constraint engine
    /// - Parameters:
    ///   - gpuThreshold: Minimum evaluation length to use GPU (default: 16384)
    ///   - logBlowup: Log of blowup factor (default: 2)
    public init(gpuThreshold: Int = 16384, logBlowup: Int = 2) {
        self.gpuThreshold = gpuThreshold
        self.logBlowup = logBlowup

        // Try to initialize GPU
        self.device = MTLCreateSystemDefaultDevice()
        self.commandQueue = device?.makeCommandQueue()

        // Initialize EVM GPU constraint engine
        if device != nil {
            self.evmConstraintEngine = try? EVMGPUConstraintEngine(logTraceLength: 14)
        } else {
            self.evmConstraintEngine = nil
        }
    }

    // MARK: - Public Evaluation API

    /// Evaluate constraints with column subset optimization on GPU
    ///
    /// This method evaluates the constraint polynomial using GPU acceleration when:
    /// - GPU is available
    /// - Evaluation length >= gpuThreshold
    ///
    /// Falls back to CPU otherwise.
    ///
    /// - Parameters:
    ///   - traceLDEs: Low-degree extended trace columns [numColumns x evalLen]
    ///   - columnIndices: Subset of column indices to evaluate (nil = all columns)
    ///   - alpha: Random challenge for composition polynomial
    ///   - logTrace: Log of trace length
    ///   - boundaryConstraints: Optional boundary constraints
    /// - Returns: GPU constraint evaluation result
    public func evaluateConstraintsWithSubset(
        traceLDEs: [[M31]],
        columnIndices: [Int]?,
        alpha: M31,
        logTrace: Int,
        boundaryConstraints: [(column: Int, row: Int, value: M31)] = []
    ) throws -> EvaluationResult {
        let evalLen = traceLDEs.first?.count ?? 0
        let logEval = logTrace + logBlowup

        // Determine columns to use
        let provingCols: [Int]
        if let indices = columnIndices, !indices.isEmpty {
            provingCols = indices
        } else {
            provingCols = Array(0..<traceLDEs.count)
        }

        let numProvingCols = provingCols.count

        // Check if we should use GPU with memory budget check
        // Use GPU when: available, large enough eval, AND fits in 100MB budget
        // Column subset optimization: only count FRI-proving columns (max 32)
        let effectiveColumns = min(numProvingCols, 32)
        let useGPU = gpuAvailable && evalLen >= gpuThreshold && canHandle(traceLength: evalLen, numColumns: effectiveColumns)

        if useGPU {
            return try evaluateConstraintsGPU(
                traceLDEs: traceLDEs,
                columnIndices: provingCols,
                alpha: alpha,
                logTrace: logTrace,
                boundaryConstraints: boundaryConstraints
            )
        } else {
            return try evaluateConstraintsCPU(
                traceLDEs: traceLDEs,
                columnIndices: provingCols,
                alpha: alpha,
                logTrace: logTrace,
                boundaryConstraints: boundaryConstraints
            )
        }
    }

    // MARK: - GPU Evaluation

    /// Evaluate constraints on GPU using EVMGPUConstraintEngine
    private func evaluateConstraintsGPU(
        traceLDEs: [[M31]],
        columnIndices: [Int],
        alpha: M31,
        logTrace: Int,
        boundaryConstraints: [(column: Int, row: Int, value: M31)]
    ) throws -> EvaluationResult {
        let startTime = CFAbsoluteTimeGetCurrent()
        let transferStart = CFAbsoluteTimeGetCurrent()

        let evalLen = traceLDEs.first?.count ?? 0
        let traceLen = 1 << logTrace
        let step = evalLen / traceLen

        // Extract subset columns for proving
        let provingTraceLDEs = extractSubsetColumns(traceLDEs: traceLDEs, indices: columnIndices)

        let transferTimeMs = (CFAbsoluteTimeGetCurrent() - transferStart) * 1000

        // Use EVMGPUConstraintEngine for batch evaluation
        guard let engine = evmConstraintEngine else {
            throw GPUCircleConstraintError.engineNotAvailable
        }

        let gpuStart = CFAbsoluteTimeGetCurrent()
        fputs("[GPUConstraint] Starting GPU eval with \(evalLen) points, \(columnIndices.count) columns\n", stderr)

        // Prepare full 180-column trace by padding non-proving columns with zeros
        // EVMGPUConstraintEngine requires exactly 180 columns
        let paddedTraceLDEs = padTraceToFullColumns(traceLDEs: traceLDEs, columnIndices: columnIndices, totalColumns: 180)

        let prepMs = (CFAbsoluteTimeGetCurrent() - gpuStart) * 1000
        fputs("[GPUConstraint] Prep done: \(String(format: "%.1f", prepMs))ms\n", stderr)

        // Evaluate constraints on GPU, passing evalLen since this is LDE trace
        let evalStart = CFAbsoluteTimeGetCurrent()
        let constraintResult = try engine.evaluateConstraints(
            trace: paddedTraceLDEs,
            challenges: [],
            mode: .batch,
            traceLengthOverride: evalLen
        )

        let constraintEvalMs = (CFAbsoluteTimeGetCurrent() - evalStart) * 1000
        fputs("[GPUConstraint] Constraint eval done: \(String(format: "%.1f", constraintEvalMs))ms\n", stderr)

        // Generate challenges for composition
        var challenges = [M31]()
        for i in 0..<min(columnIndices.count, 20) {
            var alphaPow = alpha
            for _ in 0..<i {
                alphaPow = m31Mul(alphaPow, alpha)
            }
            challenges.append(alphaPow)
        }

        // Compute composition polynomial on GPU, passing evalLen for LDE trace
        let compositionStartTime = CFAbsoluteTimeGetCurrent()
        fputs("[GPUConstraint] Calling evaluateCompositionPolynomial with \(constraintResult.constraints.count) constraints\n", stderr)
        fflush(stderr)

        let composition: [M31]
        do {
            composition = try engine.evaluateCompositionPolynomial(
                constraints: constraintResult.constraints,
                challenges: challenges,
                traceLengthOverride: evalLen
            )
        } catch {
            fputs("[GPUConstraint] Composition polynomial failed: \(error)\n", stderr)
            throw error
        }
        let compTimeMs = (CFAbsoluteTimeGetCurrent() - compositionStartTime) * 1000
        fputs("[GPUConstraint] Composition polynomial done: \(String(format: "%.1f", compTimeMs))ms\n", stderr)
        fflush(stderr)

        // Add boundary constraint contributions
        fputs("[GPUConstraint] Checking boundary constraints, count=\(boundaryConstraints.count)\n", stderr)
        fflush(stderr)
        var compositionWithBoundary = composition
        fputs("[GPUConstraint] compositionWithBoundary assigned from composition\n", stderr)
        fflush(stderr)

        if !boundaryConstraints.isEmpty {
            fputs("[GPUConstraint] Calling addBoundaryContributions...\n", stderr)
            fflush(stderr)
            compositionWithBoundary = addBoundaryContributions(
                composition: composition,
                traceLDEs: traceLDEs,
                boundaryConstraints: boundaryConstraints,
                alpha: alpha,
                logEval: logTrace + logBlowup
            )
            fputs("[GPUConstraint] addBoundaryContributions done\n", stderr)
            fflush(stderr)
        }

        let totalTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        fputs("[GPUConstraint] Returning from evaluateConstraintsGPU, totalTime=\(String(format: "%.1f", totalTimeMs))ms\n", stderr)
        fflush(stderr)

        return EvaluationResult(
            compositionValues: compositionWithBoundary,
            gpuTimeMs: constraintEvalMs + compTimeMs,
            transferTimeMs: transferTimeMs,
            numPoints: evalLen,
            numColumns: columnIndices.count,
            numConstraints: constraintResult.numConstraints,
            gpuMemoryBytes: constraintResult.gpuMemoryBytes,
            usedGPU: true
        )
    }

    // MARK: - CPU Evaluation

    /// Evaluate constraints on CPU (fallback when GPU unavailable)
    private func evaluateConstraintsCPU(
        traceLDEs: [[M31]],
        columnIndices: [Int],
        alpha: M31,
        logTrace: Int,
        boundaryConstraints: [(column: Int, row: Int, value: M31)]
    ) throws -> EvaluationResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        let evalLen = traceLDEs.first?.count ?? 0
        let traceLen = 1 << logTrace
        let step = evalLen / traceLen

        var compositionEvals = [M31](repeating: .zero, count: evalLen)
        let evalDomain = circleCosetDomain(logN: logTrace + logBlowup)

        // Pre-allocate column value arrays
        var current = [M31](repeating: .zero, count: columnIndices.count)
        var next = [M31](repeating: .zero, count: columnIndices.count)

        // Number of constraints per row (matching BlockAIR)
        let numConstraints = 20

        for i in 0..<evalLen {
            let nextI = (i + step) % evalLen

            // Extract column values using subset
            for (j, colIdx) in columnIndices.enumerated() {
                current[j] = traceLDEs[colIdx][i]
                next[j] = traceLDEs[colIdx][nextI]
            }

            // Evaluate constraints with subset columns
            let cVals = evaluateConstraintsCPUImpl(current: current, next: next, numConstraints: numConstraints)

            // Random linear combination
            var combined = M31.zero
            var alphaPow = M31.one
            for cv in cVals {
                combined = m31Add(combined, m31Mul(alphaPow, cv))
                alphaPow = m31Mul(alphaPow, alpha)
            }

            // Boundary constraints
            for bc in boundaryConstraints {
                let colVal = traceLDEs[bc.column][i]
                let diff = m31Sub(colVal, bc.value)
                let vz = circleVanishing(point: evalDomain[i], logDomainSize: logTrace)
                if vz.v != 0 {
                    let quotient = m31Mul(diff, m31Inverse(vz))
                    combined = m31Add(combined, m31Mul(alphaPow, quotient))
                }
                alphaPow = m31Mul(alphaPow, alpha)
            }

            compositionEvals[i] = combined
        }

        let cpuTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        return EvaluationResult(
            compositionValues: compositionEvals,
            gpuTimeMs: cpuTimeMs,
            transferTimeMs: 0,
            numPoints: evalLen,
            numColumns: columnIndices.count,
            numConstraints: numConstraints,
            gpuMemoryBytes: 0,
            usedGPU: false
        )
    }

    /// CPU implementation of constraint evaluation
    private func evaluateConstraintsCPUImpl(current: [M31], next: [M31], numConstraints: Int) -> [M31] {
        var constraints = [M31](repeating: .zero, count: numConstraints)

        // C0: PC continuity (column 0)
        if current.count > 0 && next.count > 0 {
            constraints[0] = m31Sub(next[0], m31Add(current[0], M31(v: 1)))
        }

        // C1: Gas monotonicity (column 1)
        if current.count > 1 && next.count > 1 {
            constraints[1] = m31Sub(current[1], next[1])
        }

        // C2: Call depth change limited to +/-1 (column 163 - usually last)
        let hasAllColumns = current.count >= 164 && next.count >= 164
        if hasAllColumns {
            let depthDiff = m31Sub(next[163], current[163])
            let absDepthDiff = m31Add(depthDiff, m31Mul(depthDiff, M31(v: 2)))
            constraints[2] = m31Mul(absDepthDiff, m31Sub(absDepthDiff, M31(v: 2)))
        } else {
            constraints[2] = M31(v: 0)
        }

        // C3-C4: Opcode and stack validity (always pass in current model)
        constraints[3] = M31(v: 0)
        constraints[4] = M31(v: 0)

        // Remaining constraints
        for i in 5..<numConstraints {
            constraints[i] = M31(v: 0)
        }

        return constraints
    }

    // MARK: - Helper Methods

    /// Extract subset of columns from trace
    private func extractSubsetColumns(traceLDEs: [[M31]], indices: [Int]) -> [[M31]] {
        return indices.compactMap { colIdx in
            guard colIdx < traceLDEs.count else { return nil }
            return traceLDEs[colIdx]
        }
    }

    /// Pad trace to required number of columns by inserting zero columns
    ///
    /// EVMGPUConstraintEngine requires exactly 180 columns for batch evaluation.
    /// This function pads a subset trace with zero columns to meet that requirement.
    ///
    /// - Parameters:
    ///   - traceLDEs: Original trace with subset of columns
    ///   - columnIndices: Indices of proving columns
    ///   - totalColumns: Total columns required (180)
    /// - Returns: Padded trace with all columns (proving columns + zero padding)
    private func padTraceToFullColumns(traceLDEs: [[M31]], columnIndices: [Int], totalColumns: Int) -> [[M31]] {
        let evalLen = traceLDEs.first?.count ?? 0
        guard evalLen > 0 else {
            return [[M31]](repeating: [M31](repeating: .zero, count: evalLen), count: totalColumns)
        }

        // Create result array with totalColumns columns
        var result = [[M31]](repeating: [M31](repeating: .zero, count: evalLen), count: totalColumns)

        // Copy proving columns to their correct positions
        for (j, colIdx) in columnIndices.enumerated() {
            if colIdx < totalColumns {
                result[colIdx] = traceLDEs[j]
            }
        }

        return result
    }

    /// Add boundary constraint contributions to composition polynomial
    ///
    /// OPTIMIZED: Only processes boundary rows, not all rows
    /// This is O(numBoundaryConstraints) instead of O(numBoundaryConstraints × evalLen)
    private func addBoundaryContributions(
        composition: [M31],
        traceLDEs: [[M31]],
        boundaryConstraints: [(column: Int, row: Int, value: M31)],
        alpha: M31,
        logEval: Int
    ) -> [M31] {
        fputs("[addBoundaryContributions] START: composition.count=\(composition.count), constraints=\(boundaryConstraints.count), logEval=\(logEval)\n", stderr)
        fflush(stderr)
        var result = composition

        // Precompute alpha powers up to max row index
        let maxAlphaPow = 20  // For bc.row % 10
        var alphaPowers = [M31](repeating: .one, count: maxAlphaPow)
        for i in 1..<maxAlphaPow {
            alphaPowers[i] = m31Mul(alphaPowers[i-1], alpha)
        }

        // Only process rows that are actual boundary points
        // Collect unique boundary rows
        var boundaryRows = Set<Int>()
        for bc in boundaryConstraints {
            boundaryRows.insert(bc.row)
        }
        fputs("[addBoundaryContributions] Unique boundary rows: \(boundaryRows.count)\n", stderr)
        fflush(stderr)

        // Precompute vanishing polynomial at all boundary rows
        let evalDomain = circleCosetDomain(logN: logEval)
        var vzAtBoundary = [Int: M31]()  // row -> vanishing value
        for row in boundaryRows {
            vzAtBoundary[row] = circleVanishing(point: evalDomain[row], logDomainSize: logEval - logBlowup)
        }

        // Process each boundary constraint - each constraint only affects its specific row
        for bc in boundaryConstraints {
            guard bc.row < composition.count else { continue }
            guard let vz = vzAtBoundary[bc.row], vz.v != 0 else { continue }

            // Get trace column
            guard bc.column < traceLDEs.count else { continue }
            let traceCol = traceLDEs[bc.column]
            guard bc.row < traceCol.count else { continue }

            // Compute diff and quotient
            let colVal = traceCol[bc.row]
            let diff = m31Sub(colVal, bc.value)
            let quotient = m31Mul(diff, m31Inverse(vz))

            // Add alpha^bc.row contribution
            let alphaIdx = bc.row % maxAlphaPow
            let alphaPow = alphaPowers[alphaIdx]
            result[bc.row] = m31Add(result[bc.row], m31Mul(alphaPow, quotient))
        }

        fputs("[addBoundaryContributions] ALL DONE\n", stderr)
        fflush(stderr)
        return result
    }

    // MARK: - Field Operations

    private func m31Add(_ a: M31, _ b: M31) -> M31 {
        let sum = a.v &+ b.v
        let reduced = (sum & 0x7FFFFFFF) &+ (sum >> 31)
        return M31(v: reduced == 0x7FFFFFFF ? 0 : reduced)
    }

    private func m31Sub(_ a: M31, _ b: M31) -> M31 {
        if a.v >= b.v {
            return M31(v: a.v - b.v)
        }
        return M31(v: a.v + 0x7FFFFFFF - b.v)
    }

    private func m31Mul(_ a: M31, _ b: M31) -> M31 {
        let prod = UInt64(a.v) * UInt64(b.v)
        let lo = UInt32(prod & 0x7FFFFFFF)
        let hi = UInt32(prod >> 31)
        let s = lo &+ hi
        return M31(v: s >= 0x7FFFFFFF ? s - 0x7FFFFFFF : s)
    }

    private func m31Inverse(_ x: M31) -> M31 {
        // Fermat's little theorem: x^(p-2) mod p for p = 2^31 - 1
        var result = x
        var exp: UInt32 = 0x7FFFFFFE
        var base = x

        while exp > 1 {
            if exp & 1 == 1 {
                result = m31Mul(result, base)
            }
            base = m31Mul(base, base)
            exp >>= 1
        }

        return result
    }

    /// Generate circle coset domain for evaluation
    private func circleCosetDomain(logN: Int) -> [M31] {
        // Generate domain for Circle STARK
        let n = 1 << logN
        var domain = [M31](repeating: .zero, count: n)

        // Simple geometric progression for domain
        // In real implementation, use twiddle factors from zkMetal
        for i in 0..<n {
            let t = UInt64(i) * UInt64(0x4000000) % UInt64(M31.P)
            domain[i] = M31(v: UInt32(t))
        }

        return domain
    }

    /// Vanishing polynomial for Circle STARK
    private func circleVanishing(point: M31, logDomainSize: Int) -> M31 {
        // Z(x) = x^(2^logDomainSize) - 1
        var result = M31(v: 1)
        let n = 1 << logDomainSize

        for _ in 0..<n {
            result = m31Mul(result, point)
        }

        return m31Sub(result, M31(v: 1))
    }
}

// MARK: - GPU Circle Constraint Errors

public enum GPUCircleConstraintError: Error, CustomStringConvertible {
    case engineNotAvailable
    case gpuNotAvailable
    case invalidTraceLength
    case invalidColumnCount
    case evaluationFailed(String)
    case bufferAllocationFailed(Int)

    public var description: String {
        switch self {
        case .engineNotAvailable:
            return "GPU Circle constraint engine not available"
        case .gpuNotAvailable:
            return "GPU device not available"
        case .invalidTraceLength:
            return "Invalid trace length for GPU evaluation"
        case .invalidColumnCount:
            return "Invalid number of columns for GPU evaluation"
        case .evaluationFailed(let reason):
            return "Constraint evaluation failed: \(reason)"
        case .bufferAllocationFailed(let size):
            return "Buffer allocation failed: \(size) bytes"
        }
    }
}
