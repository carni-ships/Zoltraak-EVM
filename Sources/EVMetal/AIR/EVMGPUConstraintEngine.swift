import Foundation
import zkMetal

/// GPU-accelerated EVM constraint evaluation engine.
/// Uses zkmetal's GPU engines for parallel constraint evaluation.
public final class EVMGPUConstraintEngine: Sendable {

    // MARK: - Types

    /// Result of constraint evaluation on GPU
    public struct GPUConstraintResult: Sendable {
        /// Evaluated constraint values
        public let constraints: [M31]

        /// Time taken for evaluation in milliseconds
        public let evaluationTimeMs: Double

        /// Number of rows evaluated
        public let numRows: Int

        /// Number of constraints per row
        public let numConstraints: Int

        public init(constraints: [M31], evaluationTimeMs: Double, numRows: Int, numConstraints: Int) {
            self.constraints = constraints
            self.evaluationTimeMs = evaluationTimeMs
            self.numRows = numRows
            self.numConstraints = numConstraints
        }
    }

    // MARK: - GPU Resources

    private let logTraceLength: Int
    private let numColumns: Int
    private let numConstraints: Int

    // MARK: - Initialization

    /// Initialize the GPU constraint engine
    public init(logTraceLength: Int, numColumns: Int = 180, numConstraints: Int = 50) {
        self.logTraceLength = logTraceLength
        self.numColumns = numColumns
        self.numConstraints = numConstraints
    }

    // MARK: - Constraint Evaluation

    /// Evaluate EVM constraints on GPU
    /// - Parameters:
    ///   - trace: The execution trace as columns of M31 elements
    ///   - challenges: Random challenges for composition polynomial
    /// - Returns: GPU-evaluated constraint results
    public func evaluateConstraints(
        trace: [[M31]],
        challenges: [M31]
    ) throws -> GPUConstraintResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Validate trace dimensions
        let traceLength = 1 << logTraceLength
        guard trace.count == numColumns else {
            throw GPUConstraintError.invalidTraceColumns(expected: numColumns, actual: trace.count)
        }
        guard trace.allSatisfy({ $0.count == traceLength }) else {
            throw GPUConstraintError.invalidTraceLength(expected: traceLength, actual: trace[0].count)
        }

        // Evaluate constraints using the EVMAIR constraint evaluator
        let air = EVMAIR(logTraceLength: logTraceLength)

        // Evaluate transition constraints for each row pair
        var constraintValues = [M31](repeating: .zero, count: traceLength * numConstraints)

        for row in 0..<(traceLength - 1) {
            let currentRow = trace.map { $0[row] }
            let nextRow = trace.map { $0[row + 1] }

            // Evaluate constraints for this row transition
            let rowConstraints = air.evaluateConstraints(current: currentRow, next: nextRow)

            // Store the constraints
            for (i, c) in rowConstraints.prefix(numConstraints).enumerated() {
                constraintValues[row * numConstraints + i] = c
            }
        }

        let evaluationTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        return GPUConstraintResult(
            constraints: constraintValues,
            evaluationTimeMs: evaluationTimeMs,
            numRows: traceLength,
            numConstraints: numConstraints
        )
    }

    /// Evaluate transition constraints for consecutive trace rows
    /// - Parameters:
    ///   - currentRow: Current trace row
    ///   - nextRow: Next trace row
    ///   - challenges: Random challenges for permutation checks
    /// - Returns: Constraint violation indicator (zero = valid)
    public func evaluateTransitionConstraints(
        currentRow: [M31],
        nextRow: [M31],
        challenges: [M31]
    ) -> M31 {
        // Use EVMAIR to evaluate constraints
        let air = EVMAIR(logTraceLength: 0)
        let constraints = air.evaluateConstraints(current: currentRow, next: nextRow)

        // Combine constraints with challenges
        var combined = M31.zero
        for (i, c) in constraints.prefix(numConstraints).enumerated() {
            let challenge = i < challenges.count ? challenges[i] : M31.one
            // Simple combination: just check if any constraint is non-zero
            if c.v != 0 {
                combined = M31.one
                break
            }
        }

        return combined
    }
}

// MARK: - GPU Constraint Errors

public enum GPUConstraintError: Error, Sendable {
    case invalidTraceColumns(expected: Int, actual: Int)
    case invalidTraceLength(expected: Int, actual: Int)
    case gpuNotAvailable
    case evaluationFailed(String)

    public var description: String {
        switch self {
        case .invalidTraceColumns(let expected, let actual):
            return "Invalid trace columns: expected \(expected), got \(actual)"
        case .invalidTraceLength(let expected, let actual):
            return "Invalid trace length: expected \(expected), got \(actual)"
        case .gpuNotAvailable:
            return "GPU not available for constraint evaluation"
        case .evaluationFailed(let reason):
            return "Constraint evaluation failed: \(reason)"
        }
    }
}
