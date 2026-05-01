// ZoltraakBlockProver+IVC -- Integration of IVC with block prover
//
// Reference: "Nova: Recursive Zero-Knowledge Arguments" (Kothapalli et al. 2022)

import Foundation
import zkMetal

// MARK: - IVC Configuration

public struct IVCProvingConfig: Sendable {
    public let ivcConfig: EVMCircleSTARKIVC.Config
    public let enableCycleFold: Bool
    public let generateFinalProof: Bool
    public let maxBlocksPerAccumulator: Int

    public init(
        ivcConfig: EVMCircleSTARKIVC.Config = .default,
        enableCycleFold: Bool = true,
        generateFinalProof: Bool = true,
        maxBlocksPerAccumulator: Int = 1000
    ) {
        self.ivcConfig = ivcConfig
        self.enableCycleFold = enableCycleFold
        self.generateFinalProof = generateFinalProof
        self.maxBlocksPerAccumulator = maxBlocksPerAccumulator
    }

    public static let `default` = IVCProvingConfig()
    public static let highSecurity = IVCProvingConfig(
        ivcConfig: .highSecurity,
        enableCycleFold: true,
        generateFinalProof: true,
        maxBlocksPerAccumulator: 100
    )
}

public struct IVCBlockProof: Sendable {
    public let starkProof: BlockProof
    public let ivcProof: CircleSTARKIVCProof
    public let isBaseCase: Bool
    public let accumulatedBlocks: Int
    public let accumulatorReset: Bool
}

public struct AggregatedProof: Sendable {
    public let ivcProof: FinalIVCProof
    public let cycleFoldProof: CycleFoldFinalProof?
    public let serialized: Data
    public let verificationKey: TransparentVerificationKey

    public var estimatedVerificationGas: UInt64 {
        let baseGas: UInt64 = 70_000  // Transparent verification (no pairing)
        let perInputGas: UInt64 = 10_000
        let cycleFoldGas: UInt64 = 15_000

        let inputCount = UInt64(ivcProof.finalState.blockCount)
        var total = baseGas + (inputCount * perInputGas)

        if cycleFoldProof != nil {
            total += cycleFoldGas
        }

        return total
    }
}

// MARK: - IVC Errors

public enum IVCProverError: Error, Sendable {
    case ivcNotEnabled
    case proofParsingFailed
    case noBlocksAccumulated
    case foldingFailed(String)
    case finalizationFailed(String)
}

// MARK: - IVC Block Prover

public final class ZoltraakIVCBlockProver: Sendable {

    private let blockProver: ZoltraakBlockProver
    private var ivcEngine: EVMCircleSTARKIVC?
    private var cycleFoldFinalizer: EVMCycleFoldFinalizer?
    private var bn254Verifier: EVMBN254Verifier?
    private var ivcConfig: IVCProvingConfig?
    private var accumulatedBlockCount: Int = 0
    private var accumulatedTraceRoot: Fr = .zero

    public init(
        blockConfig: BlockProvingConfig = .default,
        ivcConfig: IVCProvingConfig = .default
    ) throws {
        self.blockProver = try ZoltraakBlockProver(config: blockConfig)
        self.ivcConfig = ivcConfig
        try self.enableIVC(config: ivcConfig)
    }

    public var isIVCEnabled: Bool {
        return ivcEngine != nil
    }

    public func enableIVC(config: IVCProvingConfig) throws {
        self.ivcConfig = config
        self.ivcEngine = try EVMCircleSTARKIVC(config: config.ivcConfig)

        if config.enableCycleFold {
            self.cycleFoldFinalizer = EVMCycleFoldFinalizer(config: .default)
        }

        self.bn254Verifier = try EVMBN254Verifier(config: config.generateFinalProof ? .full : .default)

        self.accumulatedBlockCount = 0
        self.accumulatedTraceRoot = .zero

        print("[IVCBlockProver] IVC enabled")
        print("[IVCBlockProver]   - CycleFold: \(config.enableCycleFold)")
        print("[IVCBlockProver]   - Final proof: \(config.generateFinalProof)")
        print("[IVCBlockProver]   - Max blocks: \(config.maxBlocksPerAccumulator)")
    }

    public func disableIVC() {
        ivcEngine = nil
        cycleFoldFinalizer = nil
        bn254Verifier = nil
        ivcConfig = nil
        accumulatedBlockCount = 0
        accumulatedTraceRoot = .zero

        print("[IVCBlockProver] IVC disabled")
    }

    public func proveIVC(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word = .zero
    ) async throws -> IVCBlockProof {
        guard let engine = ivcEngine else {
            throw IVCProverError.ivcNotEnabled
        }

        let shouldReset = accumulatedBlockCount >= (ivcConfig?.maxBlocksPerAccumulator ?? 1000)
        if shouldReset {
            print("[IVCBlockProver] Resetting accumulator after \(accumulatedBlockCount) blocks")
            disableIVC()
            try enableIVC(config: ivcConfig ?? .default)
        }

        print("[IVCBlockProver] Generating Circle STARK proof for block \(blockContext.number)")
        let blockProof = try await blockProver.prove(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot
        )

        // Parse the proof
        guard let circleProof = try? parseCircleSTARKProof(from: blockProof.starkProof) else {
            throw IVCProverError.proofParsingFailed
        }

        let traceRoot = computeTraceRoot(from: blockProof.commitments)
        let isBaseCase = accumulatedBlockCount == 0

        print("[IVCBlockProver] Folding block \(blockContext.number) into IVC (step \(accumulatedBlockCount + 1))")

        let ivcResult = try engine.proveStep(
            proof: circleProof,
            blockNumber: blockContext.number,
            traceRoot: traceRoot
        )

        accumulatedBlockCount += 1
        accumulatedTraceRoot = traceRoot

        print("[IVCBlockProver] Folded successfully. Total blocks: \(accumulatedBlockCount)")

        return IVCBlockProof(
            starkProof: blockProof,
            ivcProof: ivcResult.proof,
            isBaseCase: isBaseCase,
            accumulatedBlocks: accumulatedBlockCount,
            accumulatorReset: shouldReset
        )
    }

    public func proveBlocksIVC(
        blocks: [(transactions: [EVMTransaction], blockContext: BlockContext)],
        initialStateRoot: M31Word = .zero
    ) async throws -> [IVCBlockProof] {
        var proofs = [IVCBlockProof]()

        for (transactions, blockContext) in blocks {
            let proof = try await proveIVC(
                transactions: transactions,
                blockContext: blockContext,
                initialStateRoot: initialStateRoot
            )
            proofs.append(proof)
        }

        return proofs
    }

    public func getFinalProof() throws -> AggregatedProof {
        guard let engine = ivcEngine else {
            throw IVCProverError.ivcNotEnabled
        }

        guard accumulatedBlockCount > 0 else {
            throw IVCProverError.noBlocksAccumulated
        }

        let ivcProof = try engine.getFinalProof()

        var cycleFoldProof: CycleFoldFinalProof? = nil
        if let finalizer = cycleFoldFinalizer {
            print("[IVCBlockProver] Applying CycleFold finalization")
            cycleFoldProof = finalizer.finalize(ivcProof: ivcProof)
        }

        if let verifier = bn254Verifier {
            print("[IVCBlockProver] Verifying final proof...")
            let result = verifier.verify(finalProof: ivcProof)
            if case .invalid(let reason) = result {
                print("[IVCBlockProver] Warning: Final verification failed: \(reason)")
            }
        }

        let serialized = serializeAggregatedProof(ivcProof: ivcProof, cycleFoldProof: cycleFoldProof)
        let vk = generateVerificationKey(ivcProof: ivcProof)

        return AggregatedProof(
            ivcProof: ivcProof,
            cycleFoldProof: cycleFoldProof,
            serialized: serialized,
            verificationKey: vk
        )
    }

    public func serializeFinalProof() throws -> Data {
        let proof = try getFinalProof()
        return proof.serialized
    }

    public func getIVCDiagnostics() throws -> IVCDiagnostics {
        guard let engine = ivcEngine else {
            throw IVCProverError.ivcNotEnabled
        }
        return engine.diagnostics()
    }

    // MARK: - Private Helpers

    /// Parse CircleSTARKProof from block proof data.
    ///
    /// The block prover serializes GPU proofs using serializeGPUSTARKProof(),
    /// which stores GPUCircleSTARKProverProof data. We need to deserialize this
    /// and adapt it to CircleSTARKProof format for the IVC verifier circuit.
    ///
    /// CPU proofs are serialized using CircleSTARKProof.serialize() and start
    /// with "CSTK" magic bytes. GPU proofs start with trace commitment count.
    private func parseCircleSTARKProof(from data: Data) throws -> CircleSTARKProof {
        // Detect format: "CSTK" (0x43 0x53 0x54 0x4B) for CPU proofs, otherwise GPU
        let isCPUFormat = data.count >= 4 &&
            data[0] == 0x43 && data[1] == 0x53 && data[2] == 0x54 && data[3] == 0x4B

        if isCPUFormat {
            // CPU proof format - use standard deserialization
            return try deserializeCircleSTARKProof(from: data)
        } else {
            // GPU proof format - GPU proofs require internal zkMetal types for full IVC
            // For now, throw an error since GPU proving uses a different proof format
            // that requires zkMetal SDK changes to support properly
            throw IVCProverError.proofParsingFailed
        }
    }

    private func computeTraceRoot(from commitments: [M31Digest]) -> Fr {
        let transcript = Transcript(label: "trace-root", backend: .keccak256)

        for commitment in commitments {
            // Absorb commitment bytes
            transcript.absorbBytes(commitment.bytes)
        }

        return transcript.squeeze()
    }

    private func serializeAggregatedProof(
        ivcProof: FinalIVCProof,
        cycleFoldProof: CycleFoldFinalProof?
    ) -> Data {
        var data = Data()
        data.append(ivcProof.serialize())

        if let cfProof = cycleFoldProof {
            data.append(cfProof.serialize())
        }

        return data
    }

    private func generateVerificationKey(ivcProof: FinalIVCProof) -> TransparentVerificationKey {
        return TransparentVerificationKey(
            numPublicInputs: Int(ivcProof.finalState.blockCount) + 1,
            logCircuitSize: 10  // Estimated circuit size
        )
    }
}
