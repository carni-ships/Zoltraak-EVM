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
    ) -> CCSInstance {
        // EVM layout: 180 columns, ~50 constraints
        // Columns: PC(1) + gas(2) + stack(144) + reserved(8) + memory(1) + reserved(2) + opcode(1) + flags(4) + callDepth(1) + stateRoot(3) + timestamp(1) + reserved(12) = 180
        let m = numConstraints
        let n = numWitnessElements + numPublicInputs + 1  // +1 for constant term

        // Build EVM constraint matrices
        // Each matrix represents one constraint type from EVMAIR

        // Matrix 0: PC continuity (constraint 0-9)
        // Verifies: nextPC = currentPC + 1 for non-jump ops
        let pcMatrix = buildPCContinuityMatrix(m: 10, n: n, numPublic: numPublicInputs)

        // Matrix 1: Gas monotonicity (constraint 10-19)
        // Verifies: gas only decreases
        let gasMatrix = buildGasMonotonicityMatrix(m: 10, n: n, numPublic: numPublicInputs)

        // Matrix 2: Call depth (constraint 20-29)
        // Verifies: call depth changes by at most 1
        let callDepthMatrix = buildCallDepthMatrix(m: 10, n: n, numPublic: numPublicInputs)

        // Matrix 3: Opcode-specific (constraint 30-49)
        // Verifies: arithmetic, comparison, bitwise, memory, control flow
        let opcodeMatrix = buildOpcodeConstraintMatrix(m: 20, n: n)

        let matrices = [pcMatrix, gasMatrix, callDepthMatrix, opcodeMatrix]

        // Multisets: groups constraint types for efficient folding
        // CCS uses multiset to select which matrices contribute to each constraint
        let multisets = [
            Array(0..<10),    // PC constraints use Matrix 0
            Array(10..<20),   // Gas constraints use Matrix 1
            Array(20..<30),   // Call depth constraints use Matrix 2
            Array(30..<50)    // Opcode constraints use Matrix 3
        ]

        // Coefficients: weights for combining matrices in constraints
        let coefficients = [
            Fr.one,   // PC matrix weight
            Fr.one,   // Gas matrix weight
            Fr.one,   // Call depth matrix weight
            Fr.one    // Opcode matrix weight
        ]

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
    private static func buildPCContinuityMatrix(m: Int, n: Int, numPublic: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: m + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<m {
            // nextPC - currentPC - 1 = 0
            // nextPC column = 0, currentPC column = 0, constant = 1
            colIdx.append(0)  // nextPC
            values.append(Fr.one)
            colIdx.append(n - numPublic - 1)  // currentPC
            // -1 in BN254 field (p - 1 where p is the field modulus)
            values.append(Fr(v: (0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0xb2d6a87a, 0x25e9bbb5, 0x596e72c7, 0x0)))
        }
        for row in 0...m {
            rowPtr[row] = colIdx.count
        }

        return SparseMatrix(rows: m, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }

    /// Build gas monotonicity constraint matrix
    /// gasNext - gasCurrent <= 0
    private static func buildGasMonotonicityMatrix(m: Int, n: Int, numPublic: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: m + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<m {
            // gasNext - gasCurrent <= 0
            colIdx.append(1)  // gasNext column
            values.append(Fr.one)
            colIdx.append(1 + (n - numPublic - 1) / 2)  // gasCurrent (high part)
            // -1 in BN254 field
            values.append(Fr(v: (0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0xb2d6a87a, 0x25e9bbb5, 0x596e72c7, 0x0)))
        }
        for row in 0...m {
            rowPtr[row] = colIdx.count
        }

        return SparseMatrix(rows: m, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }

    /// Build call depth constraint matrix
    /// |nextDepth - currentDepth| <= 1
    private static func buildCallDepthMatrix(m: Int, n: Int, numPublic: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: m + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        for row in 0..<m {
            // nextDepth - currentDepth <= 1
            colIdx.append(163)  // call depth column
            values.append(Fr.one)
            colIdx.append(163 + (n - numPublic - 1))  // previous call depth
            // -1 in BN254 field
            values.append(Fr(v: (0x4ffffffa, 0xac96341c, 0x9f60cd29, 0x36fc7695, 0xb2d6a87a, 0x25e9bbb5, 0x596e72c7, 0x0)))
        }
        for row in 0...m {
            rowPtr[row] = colIdx.count
        }

        return SparseMatrix(rows: m, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }

    /// Build opcode-specific constraint matrix
    /// Encodes stack, memory, and arithmetic operations
    private static func buildOpcodeConstraintMatrix(m: Int, n: Int) -> SparseMatrix {
        var rowPtr = [Int](repeating: 0, count: m + 1)
        var colIdx = [Int]()
        var values = [Fr]()

        // Stack constraints (columns 3-146)
        for row in 0..<min(m, 20) {
            let stackCol = 3 + (row % 16) * 9  // Stack slots × limbs
            colIdx.append(stackCol)
            values.append(Fr.one)

            // Include opcode column for selection
            colIdx.append(158)
            values.append(Fr.one)
        }
        for row in 0...m {
            rowPtr[row] = colIdx.count
        }

        return SparseMatrix(rows: m, cols: n, rowPtr: rowPtr, colIdx: colIdx, values: values)
    }
}
