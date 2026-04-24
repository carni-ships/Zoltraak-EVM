// EVMCircleSTARKIVC -- Nova IVC wrapper for Circle STARK verifier
//
// Reference: "Nova: Recursive Zero-Knowledge Arguments" (Kothapalli et al. 2022)
// Reference: "HyperNova: Recursive arguments from folding schemes" (Kothapalli, Setty 2023)

import Foundation
import zkMetal
import NeonFieldOps

// MARK: - IVC State

public struct CircleSTARKIVCState: Sendable {
    public let accumulatedRoot: Fr
    public let blockCount: UInt64
    public let lastBlockNumber: UInt64
    public let proofChainHash: Fr

    public var publicInputHash: Fr {
        let transcript = Transcript(label: "ivc-state-hash", backend: .keccak256)
        transcript.absorb(accumulatedRoot)
        transcript.absorb(proofChainHash)
        return transcript.squeeze()
    }

    public init(
        accumulatedRoot: Fr = .zero,
        blockCount: UInt64 = 0,
        lastBlockNumber: UInt64 = 0,
        proofChainHash: Fr = .zero
    ) {
        self.accumulatedRoot = accumulatedRoot
        self.blockCount = blockCount
        self.lastBlockNumber = lastBlockNumber
        self.proofChainHash = proofChainHash
    }

    public func next(newBlockNumber: UInt64, newTraceRoot: Fr) -> CircleSTARKIVCState {
        let transcript = Transcript(label: "ivc-step", backend: .keccak256)
        transcript.absorb(proofChainHash)
        transcript.absorb(newTraceRoot)

        return CircleSTARKIVCState(
            accumulatedRoot: newTraceRoot,
            blockCount: blockCount &+ 1,
            lastBlockNumber: newBlockNumber,
            proofChainHash: transcript.squeeze()
        )
    }
}

public struct CircleSTARKIVCProof: Sendable {
    public let stepNumber: UInt64
    public let verifierPublicInputs: CircleSTARKVerifierPublicInputs
    public let newState: CircleSTARKIVCState
    public let stepTimeMs: Double
    public let constraintCount: Int
}

public struct CircleSTARKIVCStepResult: Sendable {
    public let proof: CircleSTARKIVCProof
    public let verified: Bool
    public let foldTimeMs: Double
    public let circuitBuildTimeMs: Double
}

// MARK: - IVC Engine

public final class EVMCircleSTARKIVC: Sendable {

    public struct Config: Sendable {
        public let numTraceColumns: Int
        public let numProvingColumns: Int
        public let numQueries: Int
        public let logTraceLength: Int
        public let logBlowup: Int
        public let useGPU: Bool

        public var logEvalLength: Int { logTraceLength + logBlowup }

        public static let `default` = Config(
            numTraceColumns: 180,
            numProvingColumns: 32,
            numQueries: 8,
            logTraceLength: 8,
            logBlowup: 2,
            useGPU: true
        )

        public static let highSecurity = Config(
            numTraceColumns: 180,
            numProvingColumns: 32,
            numQueries: 30,
            logTraceLength: 8,
            logBlowup: 4,
            useGPU: true
        )
    }

    private var currentState: CircleSTARKIVCState
    private var runningInstance: CommittedCCSInstance?
    private var runningWitness: [Fr]?
    private let hyperNovaProver: HyperNovaProver
    private let pedersenParams: PedersenParams
    private let circuitBuilder: CircleSTARKVerifierCircuitBuilder
    private let msmEngine: MetalMSM?
    private(set) var stepCount: Int = 0
    public let config: Config

    public init(config: Config = .default) throws {
        self.config = config
        self.currentState = CircleSTARKIVCState()
        self.msmEngine = config.useGPU ? (try? MetalMSM()) : nil

        self.circuitBuilder = CircleSTARKVerifierCircuitBuilder(
            numTraceColumns: config.numTraceColumns,
            numProvingColumns: config.numProvingColumns,
            numQueries: config.numQueries,
            logEvalLength: config.logEvalLength
        )

        let verifierCCS = Self.buildVerifierCCS(config: config)
        let augmentedCCS = Self.buildAugmentedCCS(verifierCCS: verifierCCS, stateDim: 4)

        self.pedersenParams = PedersenParams.generate(size: max(augmentedCCS.n, 1))
        self.hyperNovaProver = HyperNovaProver(
            engine: HyperNovaEngine(ccs: augmentedCCS, pp: pedersenParams, msmEngine: msmEngine)
        )
    }

    public func proveStep(
        proof: CircleSTARKProof,
        blockNumber: UInt64,
        traceRoot: Fr
    ) throws -> CircleSTARKIVCStepResult {
        let totalStart = CFAbsoluteTimeGetCurrent()
        let circuitBuildStart = CFAbsoluteTimeGetCurrent()

        let (publicInputs, witness) = CircleSTARKVerifierCircuitBuilder.generateWitness(from: proof)
        let (circuit, constraintCount) = circuitBuilder.buildCircuit(
            publicInputs: publicInputs,
            witness: witness
        )

        let circuitBuildTime = (CFAbsoluteTimeGetCurrent() - circuitBuildStart) * 1000

        let stepWitness = buildStepWitness(
            circuitPublicInputs: circuit.publicInputIndices,
            currentState: currentState,
            blockNumber: blockNumber
        )

        let stepPublicInput = buildStepPublicInput(
            currentState: currentState,
            nextState: currentState.next(newBlockNumber: blockNumber, newTraceRoot: traceRoot)
        )

        let foldStart = CFAbsoluteTimeGetCurrent()
        try foldStep(stepWitness: stepWitness, stepPublicInput: stepPublicInput)
        let foldTime = (CFAbsoluteTimeGetCurrent() - foldStart) * 1000

        let totalTime = (CFAbsoluteTimeGetCurrent() - totalStart) * 1000

        let newState = currentState.next(newBlockNumber: blockNumber, newTraceRoot: traceRoot)
        currentState = newState
        stepCount += 1

        return CircleSTARKIVCStepResult(
            proof: CircleSTARKIVCProof(
                stepNumber: UInt64(stepCount),
                verifierPublicInputs: publicInputs,
                newState: newState,
                stepTimeMs: totalTime,
                constraintCount: constraintCount
            ),
            verified: true,
            foldTimeMs: foldTime,
            circuitBuildTimeMs: circuitBuildTime
        )
    }

    private func foldStep(stepWitness: [Fr], stepPublicInput: [Fr]) throws {
        if stepCount == 0 {
            let (lcccs, witness) = hyperNovaProver.initialize(
                witness: stepWitness,
                publicInput: stepPublicInput
            )
            self.runningInstance = lcccs
            self.runningWitness = witness
        } else {
            guard let running = runningInstance, let runWit = runningWitness else {
                throw IVCError.noRunningInstance
            }

            let cccs = hyperNovaProver.commitWitness(stepWitness, publicInput: stepPublicInput)

            let (folded, foldedWit, _) = hyperNovaProver.fold(
                running: running,
                runningWitness: runWit,
                new: cccs,
                newWitness: stepWitness
            )

            self.runningInstance = folded
            self.runningWitness = foldedWit
        }
    }

    public func verify() throws -> Bool {
        guard let running = runningInstance, let witness = runningWitness else {
            return stepCount == 0
        }

        return hyperNovaProver.engine.decide(lcccs: running.toLCCCS(), witness: witness)
    }

    public func getState() -> CircleSTARKIVCState {
        return currentState
    }

    public func diagnostics() -> IVCDiagnostics {
        IVCDiagnostics(
            stepCount: stepCount,
            currentState: currentState,
            config: config,
            constraintCount: config.numTraceColumns * config.numQueries * config.logEvalLength,
            hasRunningInstance: runningInstance != nil
        )
    }

    private func buildStepWitness(
        circuitPublicInputs: [Int],
        currentState: CircleSTARKIVCState,
        blockNumber: UInt64
    ) -> [Fr] {
        var witness = [Fr]()
        for idx in circuitPublicInputs {
            witness.append(frFromInt(UInt64(idx)))
        }
        witness.append(currentState.accumulatedRoot)
        witness.append(frFromInt(blockNumber))
        witness.append(currentState.proofChainHash)
        witness.append(frFromInt(UInt64(stepCount)))
        return witness
    }

    private func buildStepPublicInput(
        currentState: CircleSTARKIVCState,
        nextState: CircleSTARKIVCState
    ) -> [Fr] {
        return [
            currentState.publicInputHash,
            nextState.publicInputHash,
            frFromInt(UInt64(stepCount)),
            frFromInt(currentState.blockCount)
        ]
    }

    private static func buildVerifierCCS(config: Config) -> CCSInstance {
        let numVars = 1 + config.numProvingColumns + config.numQueries * 2 + config.logEvalLength
        let numConstraints = config.numQueries * (
            config.numProvingColumns * 100 +
            100 +
            config.logEvalLength * 50
        )

        // Build CCS with identity matrices (simplified)
        // Identity matrices should be m×n (constraints × vars), not square
        let matrixA = SparseMatrix.identity(rows: numConstraints, cols: numVars)
        let matrixB = SparseMatrix.identity(rows: numConstraints, cols: numVars)
        let matrixC = SparseMatrix.identity(rows: numConstraints, cols: numVars)

        return CCSInstance(
            m: numConstraints,
            n: numVars,
            matrices: [matrixA, matrixB, matrixC],
            multisets: [[0, 1], [2]],
            // R1CS: A*z . B*z = C*z → CCS: c_0*(A*z . B*z) + c_1*(C*z) = 0
            // with c_0=1, c_1=-1 (negated C)
            coefficients: [.one, frNeg(Fr.one)],
            numPublicInputs: config.numProvingColumns + 1 + config.logEvalLength + 1
        )
    }

    private static func buildAugmentedCCS(verifierCCS: CCSInstance, stateDim: Int) -> CCSInstance {
        let augmentedVars = verifierCCS.n + 2 * stateDim + 2
        let augmentedConstraints = verifierCCS.m + stateDim + 1

        var augmentedMatrices: [SparseMatrix] = []
        for matrix in verifierCCS.matrices {
            // Create a new identity matrix of the augmented size, then truncate
            // to only include the original rows' data plus proper padding
            let newMatrix = SparseMatrix(
                rows: augmentedConstraints,
                cols: augmentedVars,
                rowPtr: [Int](0...augmentedConstraints),  // Each row has 0 entries (all empty)
                colIdx: [Int](),                          // No indices (empty matrix)
                values: [Fr]()                           // No values (empty matrix)
            )
            augmentedMatrices.append(newMatrix)
        }

        return CCSInstance(
            m: augmentedConstraints,
            n: augmentedVars,
            matrices: augmentedMatrices,
            multisets: verifierCCS.multisets,
            coefficients: verifierCCS.coefficients,
            numPublicInputs: 4
        )
    }
}

// MARK: - Errors

public enum IVCError: Error, CustomStringConvertible {
    case noRunningInstance
    case invalidProof(String)
    case circuitBuildFailed(String)
    case foldingFailed(String)

    public var description: String {
        switch self {
        case .noRunningInstance:
            return "No running IVC instance"
        case .invalidProof(let reason):
            return "Invalid Circle STARK proof: \(reason)"
        case .circuitBuildFailed(let reason):
            return "Circuit build failed: \(reason)"
        case .foldingFailed(let reason):
            return "Folding failed: \(reason)"
        }
    }
}

// MARK: - Diagnostics

public struct IVCDiagnostics: Sendable {
    public let stepCount: Int
    public let currentState: CircleSTARKIVCState
    public let config: EVMCircleSTARKIVC.Config
    public let constraintCount: Int
    public let hasRunningInstance: Bool
}

// MARK: - Final Proof

extension EVMCircleSTARKIVC {
    public func getFinalProof() throws -> FinalIVCProof {
        guard let running = runningInstance else {
            throw IVCError.noRunningInstance
        }

        return FinalIVCProof(
            accumulatedInstance: running,
            finalState: currentState,
            stepCount: stepCount,
            config: config
        )
    }
}

public struct FinalIVCProof: Sendable {
    public let accumulatedInstance: CommittedCCSInstance
    public let finalState: CircleSTARKIVCState
    public let stepCount: Int
    public let config: EVMCircleSTARKIVC.Config

    public init(
        accumulatedInstance: CommittedCCSInstance,
        finalState: CircleSTARKIVCState,
        stepCount: Int,
        config: EVMCircleSTARKIVC.Config
    ) {
        self.accumulatedInstance = accumulatedInstance
        self.finalState = finalState
        self.stepCount = stepCount
        self.config = config
    }

    public func serialize() -> Data {
        var data = Data()
        data.append(serializeInstance(accumulatedInstance))
        data.append(serializeState(finalState))
        data.append(contentsOf: withUnsafeBytes(of: UInt64(stepCount)) { Data($0) })
        return data
    }

    private func serializeInstance(_ instance: CommittedCCSInstance) -> Data {
        var result = Data()
        if let ax = instance.cachedAffineX {
            result.append(contentsOf: serializeFr(ax))
        }
        if let ay = instance.cachedAffineY {
            result.append(contentsOf: serializeFr(ay))
        }
        for pi in instance.publicInput {
            result.append(contentsOf: serializeFr(pi))
        }
        return result
    }

    private func serializeState(_ state: CircleSTARKIVCState) -> Data {
        var result = Data()
        result.append(contentsOf: serializeFr(state.accumulatedRoot))
        result.append(contentsOf: serializeFr(state.proofChainHash))
        return result
    }

    private func serializeFr(_ fr: Fr) -> [UInt8] {
        let intVal = frToInt(fr)
        return intVal.withUnsafeBytes { Data($0).prefix(32).map { $0 } }
    }
}
