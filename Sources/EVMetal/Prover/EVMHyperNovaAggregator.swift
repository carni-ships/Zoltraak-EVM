import Foundation
import zkMetal

/// EVM HyperNova aggregation for folding multiple transaction proofs into a block proof.
/// Uses HyperNova (CCS folding) from zkmetal to aggregate CircleSTARK proofs.
public final class EVMHyperNovaAggregator: Sendable {

    // MARK: - Types

    /// Aggregated proof result (in-memory)
    public struct AggregationResult: Sendable {
        /// The folded LCCCS (lightweight committed CCS)
        public let foldedInstance: LCCCS

        /// Folding proofs for verification
        public let foldingProofs: [FoldingProof]

        /// Time taken for aggregation in milliseconds
        public let aggregationTimeMs: Double

        /// Number of proofs aggregated
        public let numProofs: Int
    }

    /// Input for aggregation - a single transaction proof
    public struct AggregationInput: Sendable {
        /// Public inputs to the circuit
        public let publicInputs: [Fr]

        /// Witness elements
        public let witness: [Fr]

        /// Instance parameters
        public let instance: CommittedCCSInstance
    }

    // MARK: - HyperNova Prover

    private let hyperNovaProver: HyperNovaProver
    private let ccs: CCSInstance
    private let gpuEnabled: Bool

    // MARK: - Initialization

    /// Initialize the HyperNova aggregator
    public init(ccs: CCSInstance, gpuEnabled: Bool = true) throws {
        self.ccs = ccs
        self.gpuEnabled = gpuEnabled

        // Initialize HyperNova prover with CCS
        if gpuEnabled {
            // Use GPU MSM engine if available
            let msmEngine = try? MetalMSM()
            self.hyperNovaProver = HyperNovaProver(ccs: ccs, msmEngine: msmEngine)
        } else {
            self.hyperNovaProver = HyperNovaProver(ccs: ccs, msmEngine: nil)
        }
    }

    // MARK: - Aggregation

    /// Aggregate multiple transaction proofs using HyperNova folding
    /// - Parameter inputs: Array of transaction proofs to aggregate
    /// - Returns: Aggregation result with folded proof
    public func aggregate(inputs: [AggregationInput]) throws -> AggregationResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        guard !inputs.isEmpty else {
            throw HyperNovaError.noInputs
        }

        // Initialize with first proof
        guard let first = inputs.first else {
            throw HyperNovaError.noInputs
        }

        var (runningInstance, runningWitness) = hyperNovaProver.initialize(
            witness: first.witness,
            publicInput: first.publicInputs
        )

        // Collect folding proofs
        var foldingProofs: [FoldingProof] = []

        // Fold remaining proofs one by one
        for (i, input) in inputs.dropFirst().enumerated() {
            // Commit the new witness
            let newInstance = hyperNovaProver.commitWitness(
                input.witness,
                publicInput: input.publicInputs
            )

            // Fold current running instance with new instance
            let (foldedInstance, foldedWitness, foldProof) = hyperNovaProver.fold(
                running: runningInstance,
                runningWitness: runningWitness,
                new: newInstance,
                newWitness: input.witness
            )

            // Update running instance with fold
            runningInstance = foldedInstance
            runningWitness = foldedWitness

            // Store the folding proof
            foldingProofs.append(foldProof)

            print("  Folded proof \(i + 2)/\(inputs.count)")
        }

        let aggregationTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        return AggregationResult(
            foldedInstance: runningInstance.toLCCCS(),
            foldingProofs: foldingProofs,
            aggregationTimeMs: aggregationTimeMs,
            numProofs: inputs.count
        )
    }

    /// Fold a new proof into an existing aggregation
    /// - Parameters:
    ///   - currentResult: Current aggregation result
    ///   - newProof: New proof to fold in
    /// - Returns: Updated aggregation result
    public func foldInto(
        currentResult: AggregationResult,
        newProof: AggregationInput
    ) throws -> AggregationResult {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Convert LCCCS to CommittedCCSInstance for fold operation
        let currentInstance = CommittedCCSInstance(from: currentResult.foldedInstance)

        // Commit the new witness
        let newInstance = hyperNovaProver.commitWitness(
            newProof.witness,
            publicInput: newProof.publicInputs
        )

        // Fold with the new proof
        let (foldedInstance, _, foldProof) = hyperNovaProver.fold(
            running: currentInstance,
            runningWitness: [Fr](repeating: .zero, count: newProof.witness.count),
            new: newInstance,
            newWitness: newProof.witness
        )

        let aggregationTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        var newFoldingProofs = currentResult.foldingProofs
        newFoldingProofs.append(foldProof)

        return AggregationResult(
            foldedInstance: foldedInstance.toLCCCS(),
            foldingProofs: newFoldingProofs,
            aggregationTimeMs: aggregationTimeMs,
            numProofs: currentResult.numProofs + 1
        )
    }

    // MARK: - Verification

    /// Verify an aggregated proof using the decider
    /// - Parameters:
    ///   - result: The aggregation result to verify
    ///   - expectedPublicInputs: Expected public inputs (ignored in current impl)
    /// - Returns: True if verification succeeds
    public func verify(
        result: AggregationResult,
        expectedPublicInputs: [Fr]
    ) throws -> Bool {
        // The decider checks the final folded instance
        return hyperNovaProver.engine.decide(
            lcccs: result.foldedInstance,
            witness: [Fr](repeating: .zero, count: ccs.n - 1 - ccs.numPublicInputs)
        )
    }
}

// MARK: - HyperNova Errors

public enum HyperNovaError: Error, Sendable {
    case noInputs
    case invalidCCS(String)
    case foldFailed(String)
    case verificationFailed

    public var description: String {
        switch self {
        case .noInputs:
            return "No inputs provided for aggregation"
        case .invalidCCS(let reason):
            return "Invalid CCS: \(reason)"
        case .foldFailed(let reason):
            return "Fold failed: \(reason)"
        case .verificationFailed:
            return "Proof verification failed"
        }
    }
}

// MARK: - EVM-specific CCS Builder

extension EVMHyperNovaAggregator {

    /// Build a CCS instance for EVM execution
    /// - Parameters:
    ///   - numConstraints: Number of constraints
    ///   - numWitnessElements: Number of witness elements
    ///   - numPublicInputs: Number of public inputs
    /// - Returns: CCS instance for HyperNova
    public static func buildEVMCSS(
        numConstraints: Int,
        numWitnessElements: Int,
        numPublicInputs: Int
    ) -> CCSInstance {
        // Build identity matrices for EVM constraints
        let m = numConstraints
        let n = numWitnessElements + numPublicInputs + 1  // +1 for constant term

        // Create simple identity-based CCS for EVM
        // In production, this would use actual EVM constraint matrices
        var rowPtr = [Int](repeating: 0, count: m + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<m {
            let col = row % n
            colIdx.append(col)
            values.append(Fr(v: (UInt32(row + 1), 0, 0, 0, 0, 0, 0, 0)))
        }
        for row in 0...m {
            rowPtr[row] = colIdx.count
        }

        let matrix = SparseMatrix(
            rows: m,
            cols: n,
            rowPtr: rowPtr,
            colIdx: colIdx,
            values: values
        )

        // Single matrix with identity-like structure
        // CCS requires multisets and coefficients for the constraint equations
        let multisets = [[0]]  // Use first matrix
        let coefficients = [Fr.one]

        return CCSInstance(
            m: m,
            n: n,
            matrices: [matrix],
            multisets: multisets,
            coefficients: coefficients,
            numPublicInputs: numPublicInputs
        )
    }
}
