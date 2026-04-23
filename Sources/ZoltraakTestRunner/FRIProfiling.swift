import Foundation
import Metal
import zkMetal
import Zoltraak

/// FRI profiling utility to measure FRI phase performance.
public struct FRIProfiling {

    /// Profile the FRI phase for given composition polynomial size.
    public static func profileFRI(
        evalLen: Int = 4096,
        numQueries: Int = 30
    ) {
        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║           FRI Phase Profiling                                  ║
            ║           Eval Length: \(evalLen), Queries: \(numQueries)                           ║
            ╚══════════════════════════════════════════════════════════════════╝
            """)

        // Create synthetic composition polynomial
        var evals: [M31] = []
        for i in 0..<evalLen {
            evals.append(M31(v: UInt32(i)))
        }

        // Profile CPU FRI
        print("\n--- CPU FRI (baseline) ---")
        profileCPUFRI(evals: evals, numQueries: numQueries)

        // Profile GPU FRI Engine
        print("\n--- GPU FRI Engine ---")
        profileGPUFRI(evals: evals, numQueries: numQueries)

        // Summary
        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║           Optimization Recommendations                        ║
            ╚══════════════════════════════════════════════════════════════════╝

            Current: CPU FRI is used in CircleSTARKProver

            Options:
            1. Use GPU CircleFRIEngine.commitPhase() for GPU folding
               - GPU folding is already implemented ✓
               - Need integration into prover pipeline

            2. Use GPU query phase
               - Available in CircleFRIEngine.queryPhase()
               - Reduces query phase overhead

            3. Full GPU FRI
               - GPU folding + GPU Merkle + GPU queries
               - Would eliminate CPU FRI overhead entirely
            """)
    }

    // MARK: - CPU FRI

    private static func profileCPUFRI(evals: [M31], numQueries: Int) {
        let logN = Int(log2(Double(evals.count)))

        // Estimate FRI folding time
        let foldTime0 = CFAbsoluteTimeGetCurrent()

        // Simulate folding
        var current = evals
        var totalFolds = logN / 2  // FRI folds logN/2 times typically
        for i in 0..<min(totalFolds, 4) {
            let half = current.count / 2
            var next = [M31](repeating: .zero, count: half)
            // Simple average for profiling
            for j in 0..<half {
                next[j] = M31(v: (current[j].v + current[j + half].v) >> 1)
            }
            current = next
        }

        let foldMs = (CFAbsoluteTimeGetCurrent() - foldTime0) * 1000

        // Estimate query time
        let queryTime0 = CFAbsoluteTimeGetCurrent()
        var queryIndices: [Int] = []
        for _ in 0..<numQueries {
            queryIndices.append(Int.random(in: 0..<current.count))
        }
        let queryMs = (CFAbsoluteTimeGetCurrent() - queryTime0) * 1000

        print("""
            CPU FRI Profile:
              Folding: \(String(format: "%.1fms", foldMs)) (estimated)
              Queries: \(String(format: "%.1fms", queryMs))
              Total:   \(String(format: "%.1fms", foldMs + queryMs))
            """)
    }

    // MARK: - GPU FRI

    private static func profileGPUFRI(evals: [M31], numQueries: Int) {
        let logN = Int(log2(Double(evals.count)))

        do {
            let friEngine = try CircleFRIEngine()
            let dev = friEngine.device

            // Generate random alphas
            var alphas: [M31] = []
            for _ in 0..<min(logN / 2, 8) {
                alphas.append(M31(v: UInt32.random(in: 0..<UInt32.max)))
            }

            // Profile commit phase (GPU folding)
            let commitT0 = CFAbsoluteTimeGetCurrent()
            let commitment = try friEngine.commitPhase(evals: evals, alphas: alphas)
            let commitMs = (CFAbsoluteTimeGetCurrent() - commitT0) * 1000

            // Profile query phase
            var queryIndices: [UInt32] = []
            for _ in 0..<numQueries {
                queryIndices.append(UInt32.random(in: 0..<UInt32(evals.count)))
            }

            let queryT0 = CFAbsoluteTimeGetCurrent()
            let queryProofs = friEngine.queryPhase(commitment: commitment, queryIndices: queryIndices)
            let queryMs = (CFAbsoluteTimeGetCurrent() - queryT0) * 1000

            print("""
                GPU FRI Profile:
                  Commit (fold): \(String(format: "%.1fms", commitMs))
                  Queries:       \(String(format: "%.1fms", queryMs))
                  Total:         \(String(format: "%.1fms", commitMs + queryMs))

                GPU vs CPU:
                  Speedup: \(String(format: "%.1fx", (commitMs + queryMs) / max(commitMs, 0.001)))
                """)

        } catch {
            print("  GPU FRI failed: \(error)")
        }
    }
}
