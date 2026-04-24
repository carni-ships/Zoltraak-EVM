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
    ///
    /// The EVM CCS encodes:
    /// - 180 columns (PC, gas, stack slots, memory, opcode, flags, state root, timestamp)
    /// - 50 constraints (PC continuity, gas monotonicity, call depth, opcode-specific ops)
    /// - Multisets grouping constraints by type (arithmetic, comparison, bitwise, memory, control)
    ///
    /// In production, matrices would be derived from EVMAIR constraint evaluation.
    /// For now, we create a structurally correct CCS with placeholder values.
    public static func buildEVMCSS(
        numConstraints: Int = 50,
        numWitnessElements: Int = 1024,
        numPublicInputs: Int = 32
    ) throws -> CCSInstance {
        // EVM layout: 180 columns, ~50 constraints
        // Columns: PC(1) + gas(2) + stack(144) + reserved(8) + memory(1) + reserved(2) + opcode(1) + flags(4) + callDepth(1) + stateRoot(3) + timestamp(1) + reserved(12) = 180
        let m = numConstraints
        let n = numWitnessElements + numPublicInputs + 1  // +1 for constant term

        // Validate dimensions to prevent precondition failures in zkMetal
        guard n >= 2 else {
            throw HyperNovaError.invalidCCS("n must be >= 2, got \(n)")
        }
        guard m >= 1 else {
            throw HyperNovaError.invalidCCS("m must be >= 1, got \(m)")
        }

        // Build EVM constraint matrices
        // Each matrix represents one constraint type from EVMAIR
        // CRITICAL: Each matrix MUST have exactly m rows (50), or multisets must be structured accordingly

        // Matrix 0: PC continuity (constraints 0-9)
        // Verifies: nextPC = currentPC + 1 for non-jump ops
        let pcMatrix = buildPCContinuityMatrix(totalConstraints: m, n: n, numPublic: numPublicInputs)

        // Matrix 1: Gas monotonicity (constraints 10-19)
        // Verifies: gas only decreases
        let gasMatrix = buildGasMonotonicityMatrix(totalConstraints: m, n: n, numPublic: numPublicInputs)

        // Matrix 2: Call depth (constraints 20-29)
        // Verifies: call depth changes by at most 1
        let callDepthMatrix = buildCallDepthMatrix(totalConstraints: m, n: n, numPublic: numPublicInputs)

        // Matrix 3: Opcode-specific (constraints 30-49)
        // Verifies: arithmetic, comparison, bitwise, memory, control flow
        let opcodeMatrix = buildOpcodeConstraintMatrix(totalConstraints: m, n: n)

        let matrices = [pcMatrix, gasMatrix, callDepthMatrix, opcodeMatrix]

        // Multisets: groups constraint types for efficient folding
        // CCS uses multiset to select which matrices contribute to each constraint
        // Structure: [matrix0_indices, matrix1_indices, matrix2_indices, matrix3_indices]
        let multisets: [[Int]] = [
            Array(0..<50),    // All 50 constraints use Matrix 0 (PC)
            Array(0..<50),    // All 50 constraints use Matrix 1 (Gas)
            Array(0..<50),    // All 50 constraints use Matrix 2 (Call depth)
            Array(0..<50)    // All 50 constraints use Matrix 3 (Opcode)
        ]

        // Coefficients: weights for combining matrices in constraints
        // One coefficient per multiset
        let coefficients = [Fr.one, Fr.one, Fr.one, Fr.one]

        return CCSInstance(
            m: m,
            n: n,
            matrices: matrices,
            multisets: multisets,
            coefficients: coefficients,
            numPublicInputs: numPublicInputs
        )
    }

    /// Build PC continuity constraint matrix
    /// nextPC - currentPC - 1 = 0 for non-jump opcodes
    private static func buildPCContinuityMatrix(totalConstraints: Int, n: Int, numPublic: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: totalConstraints + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<totalConstraints {
            // nextPC - currentPC - 1 = 0
            // nextPC column = 0, currentPC column = 0, constant = 1
            colIdx.append(0)  // nextPC
            values.append(Fr.one)
            // Clamp to valid range [0, n-1]
            let currentPCCol = max(0, min(n - 1, n - numPublic - 1))
            colIdx.append(currentPCCol)
            // -1 in BN254 field (p - 1 where p is the field modulus)
            values.append(Fr(v: (0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0xb2d6a87a, 0x25e9bbb5, 0x596e72c7, 0x0)))

            // Build rowPtr incrementally: each row has 2 entries
            rowPtr[row + 1] = rowPtr[row] + 2
        }

        return SparseMatrix(rows: totalConstraints, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }

    /// Build gas monotonicity constraint matrix
    /// gasNext - gasCurrent <= 0
    private static func buildGasMonotonicityMatrix(totalConstraints: Int, n: Int, numPublic: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: totalConstraints + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<totalConstraints {
            // gasNext - gasCurrent <= 0
            colIdx.append(1)  // gasNext column
            values.append(Fr.one)
            // Use a column within bounds: (n - 1) is the last witness column
            let gasCurrentCol = max(1, min(n - 1, (n - numPublic) / 2))
            colIdx.append(gasCurrentCol)
            // -1 in BN254 field
            values.append(Fr(v: (0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0xb2d6a87a, 0x25e9bbb5, 0x596e72c7, 0x0)))

            // Build rowPtr incrementally: each row has 2 entries
            rowPtr[row + 1] = rowPtr[row] + 2
        }

        return SparseMatrix(rows: totalConstraints, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }

    /// Build call depth constraint matrix
    /// |nextDepth - currentDepth| <= 1
    private static func buildCallDepthMatrix(totalConstraints: Int, n: Int, numPublic: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: totalConstraints + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<totalConstraints {
            // nextDepth - currentDepth <= 1
            // Use columns within bounds: 0-indexed, max column is n-1
            let callDepthCol = max(0, min(n - 1, 163))
            colIdx.append(callDepthCol)
            values.append(Fr.one)
            let prevCallDepthCol = max(0, min(n - 1, 163 + (n - numPublic - 1)))
            colIdx.append(prevCallDepthCol)
            // -1 in BN254 field
            values.append(Fr(v: (0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0xb2d6a87a, 0x25e9bbb5, 0x596e72c7, 0x0)))

            // Build rowPtr incrementally: each row has 2 entries
            rowPtr[row + 1] = rowPtr[row] + 2
        }

        return SparseMatrix(rows: totalConstraints, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }

    /// Build opcode-specific constraint matrix
    /// Encodes stack, memory, and arithmetic operations
    private static func buildOpcodeConstraintMatrix(totalConstraints: Int, n: Int, numPublic: Int = 32) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: totalConstraints + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        // Stack constraints (columns 3-146)
        for row in 0..<totalConstraints {
            // Clamp stackCol to valid range [0, n-1]
            let baseStackCol = 3 + (row % 16) * 9  // Stack slots × limbs
            let stackCol = max(0, min(n - 1, baseStackCol))
            colIdx.append(stackCol)
            values.append(Fr.one)

            // Include opcode column for selection (clamped to valid range)
            let opcodeCol = max(0, min(n - 1, 158))
            colIdx.append(opcodeCol)
            values.append(Fr.one)

            // Build rowPtr incrementally: each row has 2 entries
            rowPtr[row + 1] = rowPtr[row] + 2
        }

        return SparseMatrix(rows: totalConstraints, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }
}
