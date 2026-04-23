import Foundation
import zkMetal
import Zoltraak

/// Minimal E2E test to isolate the crash
public struct MinimalE2ETest {

    public static func runMinimalTest() {
        print("=== Minimal E2E Test ===")
        fflush(stdout)

        // Test 1: Fibonacci AIR (simple test to verify prover works)
        print("\n--- Test 1: Fibonacci AIR ---")
        fflush(stdout)
        do {
            let fibProver = CircleSTARKProver(logBlowup: 4, numQueries: 30)
            print("  Fibonacci prover created")
            fflush(stdout)
            // FibonacciAIR is defined in zkMetal
            let fibAir = FibonacciAIR(logTraceLength: 10)
            print("  FibonacciAIR created")
            fflush(stdout)
            print("  Generating Fibonacci trace...")
            fflush(stdout)
            let fibTrace = fibAir.generateTrace()
            print("  Fibonacci trace: \(fibTrace.count) columns x \(fibTrace[0].count) rows")
            fflush(stdout)
            print("  Starting Fibonacci proof generation...")
            fflush(stdout)
            let fibProof = try fibProver.proveCPU(air: fibAir)
            print("  Fibonacci proof generated successfully!")
            print("    Commitments: \(fibProof.traceCommitments.count)")
        } catch {
            print("  Fibonacci test failed: \(error)")
        }
        fflush(stdout)

        // Test 2: EVM AIR
        print("\n--- Test 2: EVM AIR ---")
        fflush(stdout)
        let evmEngine = EVMExecutionEngine()
        let code: [UInt8] = [0x00]  // Simple STOP
        let executionResult = try! evmEngine.execute(
            code: code,
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )
        print("  Execution complete, rows: \(executionResult.trace.rows.count)")

        let air = EVMAIR(from: executionResult)
        print("  AIR created: logTraceLength=\(air.logTraceLength), numColumns=\(EVMAIR.numColumns)")

        let prover = CircleSTARKProver(logBlowup: 4, numQueries: 30)
        print("  Prover created")

        do {
            print("  Starting EVM proof generation...")
            fflush(stdout)
            let proof = try prover.proveCPU(air: air)
            print("  EVM proof generated: \(proof.traceCommitments.count) commitments")
        } catch {
            print("  EVM proof generation failed: \(error)")
        }

        print("\n=== Minimal E2E Test Complete ===")
    }
}
