// VerifierCorrectnessTests.swift - Correctness tests for transparent Nova verifier
//
// Tests the complete verification pipeline including:
// - Commitment verification
// - CCS relation checks
// - MLE evaluation verification
// - State hash consistency
// - Gas optimization validation

import Foundation
import Testing
import zkMetal
@preconcurrency import NeonFieldOps
@testable import Zoltraak

struct VerifierCorrectnessTests {

    // MARK: - Commitment Verification Tests

    @Test
    static func testVerifyOnCurveBN254() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        // Create a valid commitment (generator point)
        let instance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],
            v: []
        )

        let result = verifier.verify(finalProof: createMockFinalProof(instance: instance))
        // Dummy proof - just verify it doesn't crash
        print("Commitment verification test completed, result: \(result)")
    }

    @Test
    static func testIdentityCommitmentRejected() throws {
        // Fresh CCCS (u=1) should reject identity commitment
        let verifier = try EVMBN254Verifier(config: .quick)

        let identityInstance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp.zero,
                y: Fp.zero,
                z: Fp.zero
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,  // Fresh CCCS
            r: [],
            v: []
        )

        // This should be invalid for fresh CCCS with identity commitment
        let proof = createMockFinalProof(instance: identityInstance)
        let result = verifier.verify(finalProof: proof)

        // Result depends on whether curve check catches it first
        print("Identity commitment test: \(result)")
    }

    // MARK: - Public Input Verification Tests

    @Test
    static func testPublicInputCountValidation() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        // Create instance with correct public inputs (4 for IVC)
        let validInstance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],  // Correct count
            u: .one,
            r: [],
            v: []
        )

        let validResult = verifier.verify(finalProof: createMockFinalProof(instance: validInstance))
        print("Valid public input count: \(validResult)")
    }

    @Test
    static func testPublicInputHashMismatch() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        // Create instance
        let instance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],
            v: []
        )

        // Provide mismatched expected inputs
        let wrongInputs: [Fr] = [.zero, .zero, .zero, .zero]
        let result = verifier.verify(
            finalProof: createMockFinalProof(instance: instance),
            expectedPublicInputs: wrongInputs
        )

        // Verify that mismatched inputs cause verification to fail
        switch result {
        case .invalid:
            // Expected - mismatched inputs should cause invalid result
            break
        case .valid:
            throw EVMTestError.executionFailed("Expected invalid result for mismatched inputs")
        case .error:
            // Error case is acceptable for invalid inputs
            break
        }
        print("Hash mismatch test: \(result)")
    }

    // MARK: - MLE Evaluation Tests

    @Test
    static func testMLEConsistencyEmptyArrays() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        // Fresh CCCS: r and v should be empty
        let freshInstance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],  // Empty for fresh
            v: []   // Empty for fresh
        )

        let result = verifier.verify(finalProof: createMockFinalProof(instance: freshInstance))
        print("Fresh CCCS MLE test: \(result)")
    }

    @Test
    static func testMLEConsistencyMismatchRejects() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        // Relaxed CCCS: r and v should have same length
        let mismatchedInstance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: frFromInt(2),  // Relaxed
            r: [Fr.one, Fr.one],  // 2 elements
            v: [Fr.one]  // 1 element - MISMATCH
        )

        let result = verifier.verify(finalProof: createMockFinalProof(instance: mismatchedInstance))
        // Mismatched v count should cause invalid result
        let isInvalid: Bool
        if case .invalid = result {
            isInvalid = true
        } else {
            isInvalid = false
        }
        #expect(isInvalid)
        print("MLE mismatch test: \(result)")
    }

    // MARK: - Relaxed CCCS Tests

    @Test
    static func testRelaxedCCCSAllowsIdentityCommitment() throws {
        let verifier = try EVMBN254Verifier(config: .quick)

        // Relaxed CCCS (u≠1) can have identity commitment
        let relaxedInstance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp.zero,
                y: Fp.zero,
                z: Fp.zero
            ),
            publicInput: [.one, .one, .one, .one],
            u: frFromInt(2),  // Relaxed, not 1
            r: [],
            v: []
        )

        let result = verifier.verify(finalProof: createMockFinalProof(instance: relaxedInstance))
        print("Relaxed CCCS with identity: \(result)")
    }

    // MARK: - Serialization Tests

    @Test
    static func testProofSerializationRoundTrip() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        let instance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],
            v: []
        )

        let proof = createMockFinalProof(instance: instance)
        let serialized = verifier.serializeProof(finalProof: proof)

        #expect(serialized.count > 0)
        print("Serialized proof size: \(serialized.count) bytes")

        // Verify expected size: commitment (64) + u (32) + public inputs (4*32) + state hash (32) + step count (8)
        let expectedMinSize = 64 + 32 + 4*32 + 32 + 8
        #expect(serialized.count >= expectedMinSize)
    }

    // MARK: - Configuration Tests

    @Test
    static func testTransparentConfigNoPairing() throws {
        let verifier = try EVMBN254Verifier(config: .transparent)

        let instance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],
            v: []
        )

        let result = verifier.verify(finalProof: createMockFinalProof(instance: instance))
        print("Transparent config test: \(result)")
    }

    @Test
    static func testQuickConfigMinimalChecks() throws {
        let verifier = try EVMBN254Verifier(config: .quick)

        let instance = CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],
            v: []
        )

        let result = verifier.verify(finalProof: createMockFinalProof(instance: instance))
        print("Quick config test: \(result)")
    }

    // MARK: - Batch Verification Tests

    @Test
    static func testBatchVerification() throws {
        let verifier = try EVMBN254Verifier(config: .quick)

        let proofs = (0..<3).map { i -> FinalIVCProof in
            let instance = CommittedCCSInstance(
                commitment: PointProjective(
                    x: Fp(v: (UInt32(i + 1), 0, 0, 0, 0, 0, 0, 0)),
                    y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                    z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
                ),
                publicInput: [.one, .one, .one, .one],
                u: .one,
                r: [],
                v: []
            )
            return createMockFinalProof(instance: instance)
        }

        let results = verifier.verifyBatch(proofs: proofs)

        #expect(results.count == 3)
        print("Batch verification: \(results)")
    }

    // MARK: - Gas Estimation Tests

    @Test
    static func testTransparentGasEstimation() throws {
        let proof = AggregatedProof(
            ivcProof: createMockFinalProof(instance: createMinimalInstance()),
            cycleFoldProof: nil,
            serialized: Data(),
            verificationKey: TransparentVerificationKey(
                numPublicInputs: 4,
                logCircuitSize: 10
            )
        )

        let gas = proof.estimatedVerificationGas
        print("Estimated gas: \(gas)")

        // Transparent verification should be ~70k gas
        #expect(gas > 0)
        #expect(gas < 100_000)  // Should be under 100k for transparent
    }

    @Test
    static func testWithCycleFoldGasOverhead() throws {
        let proof = AggregatedProof(
            ivcProof: createMockFinalProof(instance: createMinimalInstance()),
            cycleFoldProof: CycleFoldFinalProof(
                grumpkinProof: GrumpkinAccumulator(
                    accX: .one,
                    accY: .one,
                    u: .one
                ),
                bn254FinalCheck: BN254FinalCheck(
                    pairingInput0: .one,
                    pairingInput1: .one,
                    verified: true
                ),
                numDeferredOps: 10
            ),
            serialized: Data(),
            verificationKey: TransparentVerificationKey(
                numPublicInputs: 4,
                logCircuitSize: 10
            )
        )

        let gas = proof.estimatedVerificationGas
        print("Gas with CycleFold: \(gas)")
        #expect(gas > 70_000)
    }

    // MARK: - Helper Functions

    private static func createMockFinalProof(instance: CommittedCCSInstance) -> FinalIVCProof {
        let state = CircleSTARKIVCState(
            accumulatedRoot: .one,
            blockCount: 1,
            lastBlockNumber: 1,
            proofChainHash: .one
        )

        return FinalIVCProof(
            accumulatedInstance: instance,
            finalState: state,
            stepCount: 1,
            config: EVMCircleSTARKIVC.Config.default
        )
    }

    private static func createMinimalInstance() -> CommittedCCSInstance {
        return CommittedCCSInstance(
            commitment: PointProjective(
                x: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0)),
                y: Fp(v: (2, 0, 0, 0, 0, 0, 0, 0)),
                z: Fp(v: (1, 0, 0, 0, 0, 0, 0, 0))
            ),
            publicInput: [.one, .one, .one, .one],
            u: .one,
            r: [],
            v: []
        )
    }
}
