// IVCIntegrationTests.swift - Integration tests for IVC recursive proving
//
// Tests the complete IVC pipeline from Circle STARK proof generation
// through Nova folding and CycleFold finalization.

import Foundation
import Testing
import zkMetal
@preconcurrency import NeonFieldOps
@testable import EVMetal

struct IVCIntegrationTests {

    // MARK: - IVC State Tests

    @Test
    func testIVCStateInitialization() throws {
        let state = CircleSTARKIVCState()

        #expect(frIsZero(state.accumulatedRoot))
        #expect(state.blockCount == 0)
        #expect(state.lastBlockNumber == 0)
        #expect(frIsZero(state.proofChainHash))

        print("Initial IVC state:")
        print("  - Accumulated root: \(frToInt(state.accumulatedRoot))")
        print("  - Block count: \(state.blockCount)")
    }

    @Test
    func testIVCStateNext() throws {
        var state = CircleSTARKIVCState()

        let traceRoot = frFromInt(12345)
        let newState = state.next(newBlockNumber: 1, newTraceRoot: traceRoot)

        #expect(newState.blockCount == 1)
        #expect(newState.lastBlockNumber == 1)
        #expect(!frIsZero(newState.accumulatedRoot))
        #expect(!frIsZero(newState.proofChainHash))

        print("IVC state after first step:")
        print("  - Block count: \(newState.blockCount)")
        print("  - Public input hash: \(frToInt(newState.publicInputHash))")
    }

    @Test
    func testIVCStateChaining() throws {
        var state = CircleSTARKIVCState()

        // Chain several steps
        for i in 1...5 {
            let traceRoot = frFromInt(UInt64(i * 1000))
            state = state.next(newBlockNumber: UInt64(i), newTraceRoot: traceRoot)
        }

        #expect(state.blockCount == 5)
        #expect(state.lastBlockNumber == 5)
        #expect(!frIsZero(state.proofChainHash))

        print("IVC state after 5 steps: block count = \(state.blockCount)")
    }

    // MARK: - IVC Engine Tests

    @Test
    func testIVCEngineInitialization() throws {
        let config = EVMCircleSTARKIVC.Config(
            numTraceColumns: 180,
            numProvingColumns: 32,
            numQueries: 8,
            logTraceLength: 8,
            logBlowup: 2,
            useGPU: false
        )

        let engine = try EVMCircleSTARKIVC(config: config)

        #expect(engine.config.numTraceColumns == 180)
        #expect(engine.config.numQueries == 8)

        let diagnostics = engine.diagnostics()
        print("IVC diagnostics after init:")
        print("  - Step count: \(diagnostics.stepCount)")
        print("  - Has running instance: \(diagnostics.hasRunningInstance)")
    }

    @Test
    func testIVCEngineStepFolding() throws {
        let engine = try EVMCircleSTARKIVC(config: .default)

        // Create a mock proof (simplified for testing)
        let mockProof = createMockCircleSTARKProof()

        // Prove a step
        let traceRoot = frFromInt(42)
        let result = try engine.proveStep(
            proof: mockProof,
            blockNumber: 1,
            traceRoot: traceRoot
        )

        #expect(result.verified)
        #expect(result.proof.stepNumber == 1)

        print("IVC step result:")
        print("  - Step number: \(result.proof.stepNumber)")
        print("  - Circuit build time: \(result.circuitBuildTimeMs)ms")
        print("  - Fold time: \(result.foldTimeMs)ms")
        print("  - Constraint count: \(result.proof.constraintCount)")
    }

    @Test
    func testIVCMultipleStepFolding() throws {
        let engine = try EVMCircleSTARKIVC(config: .default)

        // Chain several steps
        for i in 1...3 {
            let mockProof = createMockCircleSTARKProof()
            let traceRoot = frFromInt(UInt64(i * 100))

            let result = try engine.proveStep(
                proof: mockProof,
                blockNumber: UInt64(i),
                traceRoot: traceRoot
            )

            #expect(result.verified)
            print("Step \(i) completed in \(result.proof.stepTimeMs)ms")
        }

        let finalState = engine.getState()
        #expect(finalState.blockCount == 3)
    }

    @Test
    func testIVCVerify() throws {
        let engine = try EVMCircleSTARKIVC(config: .default)

        // Before any steps
        let verifiedBeforeSteps = try engine.verify()
        #expect(verifiedBeforeSteps)  // Base case: 0 steps is valid

        // Add a step
        let mockProof = createMockCircleSTARKProof()
        _ = try engine.proveStep(
            proof: mockProof,
            blockNumber: 1,
            traceRoot: frFromInt(1)
        )

        // After step
        let verifiedAfterStep = try engine.verify()
        #expect(verifiedAfterStep)
    }

    @Test
    func testIVCDiagnostics() throws {
        let engine = try EVMCircleSTARKIVC(config: .highSecurity)

        // Add a few steps
        for i in 1...2 {
            let mockProof = createMockCircleSTARKProof()
            _ = try engine.proveStep(
                proof: mockProof,
                blockNumber: UInt64(i),
                traceRoot: frFromInt(UInt64(i))
            )
        }

        let diagnostics = engine.diagnostics()

        #expect(diagnostics.stepCount == 2)
        #expect(diagnostics.hasRunningInstance)
        #expect(diagnostics.config.numQueries == 30)  // highSecurity config

        print("IVC diagnostics:")
        print("  - Step count: \(diagnostics.stepCount)")
        print("  - Constraint count: \(diagnostics.constraintCount)")
        print("  - Num queries: \(diagnostics.config.numQueries)")
    }

    // MARK: - CycleFold Tests

    @Test
    func testCycleFoldFinalizerInitialization() throws {
        let finalizer = EVMCycleFoldFinalizer(config: .default)

        #expect(finalizer != nil)
        print("CycleFold finalizer initialized")
    }

    @Test
    func testCycleFoldDeferOperation() throws {
        let finalizer = EVMCycleFoldFinalizer(config: .default)

        // Defer some operations
        finalizer.deferOperation(
            pointX: frFromInt(100),
            pointY: frFromInt(200),
            challenge: frFromInt(42)
        )

        finalizer.deferOperation(
            pointX: frFromInt(300),
            pointY: frFromInt(400),
            challenge: frFromInt(43)
        )

        print("Deferred operations added")
    }

    @Test
    func testCycleFoldAccumulate() throws {
        let finalizer = EVMCycleFoldFinalizer(config: .default)

        // Add operations
        finalizer.deferOperation(
            pointX: frFromInt(100),
            pointY: frFromInt(200),
            challenge: frFromInt(42)
        )

        finalizer.deferOperation(
            pointX: frFromInt(50),
            pointY: frFromInt(75),
            challenge: frFromInt(43)
        )

        // Accumulate
        finalizer.accumulate()

        print("Operations accumulated")
    }

    @Test
    func testCycleFoldFinalize() throws {
        let finalizer = EVMCycleFoldFinalizer(config: .default)
        let ivcEngine = try EVMCircleSTARKIVC(config: .default)

        // Create a mock final IVC proof
        let mockProof = createMockCircleSTARKProof()
        _ = try ivcEngine.proveStep(
            proof: mockProof,
            blockNumber: 1,
            traceRoot: frFromInt(1)
        )

        let ivcFinalProof = try ivcEngine.getFinalProof()

        // Finalize with CycleFold
        finalizer.deferOperation(
            pointX: frFromInt(100),
            pointY: frFromInt(200),
            challenge: frFromInt(42)
        )

        let cycleFoldProof = finalizer.finalize(ivcProof: ivcFinalProof)

        #expect(cycleFoldProof.numDeferredOps == 1)
        #expect(!frIsZero(cycleFoldProof.grumpkinProof.accX))
        #expect(cycleFoldProof.bn254FinalCheck.verified)

        print("CycleFold finalization:")
        print("  - Deferred ops: \(cycleFoldProof.numDeferredOps)")
        print("  - Grumpkin accX: \(frToInt(cycleFoldProof.grumpkinProof.accX))")
    }

    // MARK: - Field Arithmetic Tests

    @Test
    func testFrAdd() throws {
        let a = frFromInt(100)
        let b = frFromInt(200)

        let result = frAdd(a, b)

        print("frAdd(100, 200) = \(frToInt(result))")
    }

    @Test
    func testFrNeg() throws {
        let a = frFromInt(100)
        let result = frNeg(a)

        print("frNeg(100) = \(frToInt(result))")
    }

    @Test
    func testFrSub() throws {
        let a = frFromInt(200)
        let b = frFromInt(100)

        let result = frSub(a, b)

        print("frSub(200, 100) = \(frToInt(result))")
    }

    @Test
    func testFrIsZero() throws {
        let zero = Fr.zero
        let nonZero = frFromInt(42)

        #expect(frIsZero(zero))
        #expect(!frIsZero(nonZero))

        print("frIsZero tests passed")
    }

    @Test
    func testFrIsOdd() throws {
        let even = frFromInt(100)
        let odd = frFromInt(101)

        #expect(!frIsOdd(even))
        #expect(frIsOdd(odd))

        print("frIsOdd tests passed")
    }

    // MARK: - Helper Functions

    private func createMockCircleSTARKProof() -> CircleSTARKProof {
        // Create a minimal mock proof for testing
        // In production, this would come from the actual prover
        let traceCommitments: [[UInt8]] = [[UInt8](repeating: 0, count: 32)]
        let compositionCommitment = [UInt8](repeating: 0, count: 32)
        let friProof = CircleFRIProofData(rounds: [], finalValue: M31.zero, queryIndices: [])
        let queryResponses: [CircleSTARKQueryResponse] = []
        let alpha = M31(v: 42)

        return CircleSTARKProof(
            traceCommitments: traceCommitments,
            compositionCommitment: compositionCommitment,
            friProof: friProof,
            queryResponses: queryResponses,
            alpha: alpha,
            traceLength: 256,
            numColumns: 180,
            logBlowup: 2
        )
    }
}
