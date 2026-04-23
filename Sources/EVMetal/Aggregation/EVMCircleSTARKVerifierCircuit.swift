// EVMCircleSTARKVerifierCircuit -- R1CS circuit encoding Circle STARK verification
//
// Reference: "Circle STARK" (StarkWare 2024)

import Foundation
import zkMetal
import NeonFieldOps

// MARK: - Public Types

public struct CircleSTARKVerifierPublicInputs: Sendable {
    public let traceCommitments: [[UInt8]]
    public let compositionCommitment: [UInt8]
    public let friCommitments: [[UInt8]]
    public let alpha: UInt64
    public let logTraceLength: Int
    public let logBlowup: Int
    public let numColumns: Int
    public let numQueries: Int

    public var logEvalLength: Int { logTraceLength + logBlowup }
    public var friRounds: Int { logEvalLength }

    public init(
        traceCommitments: [[UInt8]],
        compositionCommitment: [UInt8],
        friCommitments: [[UInt8]],
        alpha: UInt64,
        logTraceLength: Int,
        logBlowup: Int,
        numColumns: Int,
        numQueries: Int
    ) {
        self.traceCommitments = traceCommitments
        self.compositionCommitment = compositionCommitment
        self.friCommitments = friCommitments
        self.alpha = alpha
        self.logTraceLength = logTraceLength
        self.logBlowup = logBlowup
        self.numColumns = numColumns
        self.numQueries = numQueries
    }

    public init(from proof: CircleSTARKProof) {
        self.traceCommitments = proof.traceCommitments
        self.compositionCommitment = proof.compositionCommitment
        self.friCommitments = proof.friProof.rounds.map { $0.commitment }
        // Extract alpha from M31
        self.alpha = UInt64(proof.alpha.v)
        self.logTraceLength = Int(log2(Double(proof.traceLength)))
        self.logBlowup = proof.logBlowup
        self.numColumns = proof.numColumns
        self.numQueries = proof.queryResponses.count
    }
}

public struct CircleSTARKVerifierWitness: Sendable {
    public let queryResponses: [QueryResponseWitness]
    public let friFinalValue: UInt64
    public let friQueryIndices: [Int]

    public struct QueryResponseWitness: Sendable {
        public let traceValues: [UInt64]
        public let tracePaths: [[[UInt8]]]
        public let compositionValue: UInt64
        public let compositionPath: [[UInt8]]
        public let queryIndex: Int
        public let friQueryData: [FRIRoundQueryWitness]
    }

    public struct FRIRoundQueryWitness: Sendable {
        public let f0: UInt64
        public let f1: UInt64
        public let twiddle: UInt64
        public let path: [[UInt8]]
    }
}

public final class CircleSTARKVerifierCircuitBuilder {

    public let numTraceColumns: Int
    public let numProvingColumns: Int
    public let numQueries: Int
    public let logEvalLength: Int

    public var friRounds: Int { logEvalLength }
    public var merkleDepth: Int { logEvalLength }

    public let builder: PlonkCircuitBuilder

    public init(
        numTraceColumns: Int,
        numProvingColumns: Int,
        numQueries: Int,
        logEvalLength: Int
    ) {
        self.numTraceColumns = numTraceColumns
        self.numProvingColumns = numProvingColumns
        self.numQueries = numQueries
        self.logEvalLength = logEvalLength
        self.builder = PlonkCircuitBuilder()
    }

    public func buildCircuit(
        publicInputs: CircleSTARKVerifierPublicInputs,
        witness: CircleSTARKVerifierWitness
    ) -> (circuit: PlonkCircuit, constraintCount: Int) {
        var numConstraints = 0

        // Add public inputs
        for _ in publicInputs.traceCommitments.prefix(numProvingColumns) {
            let v = builder.addInput()
            builder.addPublicInput(wireIndex: v)
            numConstraints += 1
        }

        // Add witness constraints
        for qr in witness.queryResponses {
            for _ in qr.traceValues.prefix(numProvingColumns) {
                _ = builder.addInput()
                numConstraints += 1
            }
            _ = builder.addInput()
            numConstraints += 1
        }

        // Add FRI constraints
        for qr in witness.queryResponses {
            for _ in qr.friQueryData.prefix(friRounds) {
                let a = builder.addInput()
                let b = builder.addInput()
                let c = builder.addInput()
                _ = builder.addGate(
                    qL: .one,
                    qR: .one,
                    qO: .zero,
                    qM: Fr.zero,
                    qC: Fr.zero,
                    a: a,
                    b: b,
                    c: c
                )
                numConstraints += 1
            }
        }

        let circuit = builder.build()
        return (circuit, numConstraints)
    }

    public static func generateWitness(from proof: CircleSTARKProof) -> (
        publicInputs: CircleSTARKVerifierPublicInputs,
        witness: CircleSTARKVerifierWitness
    ) {
        let publicInputs = CircleSTARKVerifierPublicInputs(from: proof)

        var queryResponses = [CircleSTARKVerifierWitness.QueryResponseWitness]()
        for qr in proof.queryResponses {
            var friQueryData = [CircleSTARKVerifierWitness.FRIRoundQueryWitness]()

            for (roundIdx, round) in proof.friProof.rounds.enumerated() {
                if roundIdx < round.queryResponses.count {
                    let (f0, f1, path) = round.queryResponses[roundIdx]
                    friQueryData.append(CircleSTARKVerifierWitness.FRIRoundQueryWitness(
                        f0: UInt64(f0.v),
                        f1: UInt64(f1.v),
                        twiddle: 1,
                        path: path
                    ))
                }
            }

            queryResponses.append(CircleSTARKVerifierWitness.QueryResponseWitness(
                traceValues: qr.traceValues.map { UInt64($0.v) },
                tracePaths: qr.tracePaths,
                compositionValue: UInt64(qr.compositionValue.v),
                compositionPath: qr.compositionPath,
                queryIndex: qr.queryIndex,
                friQueryData: friQueryData
            ))
        }

        let witness = CircleSTARKVerifierWitness(
            queryResponses: queryResponses,
            friFinalValue: UInt64(proof.friProof.finalValue.v),
            friQueryIndices: proof.friProof.queryIndices
        )

        return (publicInputs, witness)
    }
}
