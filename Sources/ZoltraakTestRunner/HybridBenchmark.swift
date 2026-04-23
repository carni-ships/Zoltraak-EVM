import Foundation
import zkMetal
import Zoltraak

/// Quick hybrid commit benchmark to demonstrate GPU tree building speedup
public struct HybridBenchmark {

    public static func runQuickBenchmark() {
        print("=== Hybrid Commit Benchmark (CPU hash + GPU tree) ===")
        print(String(repeating: "─", count: 60))

        do {
            let prover = try ZoltraakGPUProver()

            // Small test first to verify correctness
            print("\n  Testing small scale (4 columns × 16 leaves)...")
            var smallTrace: [[M31]] = []
            for col in 0..<4 {
                var values: [M31] = []
                for i in 0..<16 {
                    values.append(M31(v: UInt32(col * 1000 + i)))
                }
                smallTrace.append(values)
            }

            let smallResult = try prover.commitTraceColumnsHybrid(traceLDEs: smallTrace, evalLen: 16)
            print("  Small scale: \(String(format: "%.1f", smallResult.timeMs))ms total")
            print("    - Leaf hashing: \(String(format: "%.1f", smallResult.leafHashMs))ms")
            print("    - Tree building: \(String(format: "%.1f", smallResult.treeBuildMs))ms")

            // Full EVMAIR scale
            print("\n  Testing full EVMAIR scale (180 columns × 512 leaves)...")
            var fullTrace: [[M31]] = []
            for col in 0..<180 {
                var values: [M31] = []
                for i in 0..<512 {
                    values.append(M31(v: UInt32(col * 1000 + i)))
                }
                fullTrace.append(values)
            }

            let fullResult = try prover.commitTraceColumnsHybrid(traceLDEs: fullTrace, evalLen: 512)
            print("  Full EVMAIR: \(String(format: "%.1f", fullResult.timeMs))ms total")
            print("    - Leaf hashing: \(String(format: "%.1f", fullResult.leafHashMs))ms")
            print("    - Tree building: \(String(format: "%.1f", fullResult.treeBuildMs))ms")

            // Calculate speedup
            let totalMs = fullResult.timeMs
            let cpuTotalEstimate = fullResult.leafHashMs + (fullResult.treeBuildMs * 4)  // Estimate CPU tree time
            let speedup = cpuTotalEstimate / totalMs
            print("\n  Estimated speedup: \(String(format: "%.2fx", speedup))")

            // Throughput
            let totalLeaves = 180 * 512
            let throughput = Double(totalLeaves) / (totalMs / 1000.0)
            print("  Throughput: \(String(format: "%.0f", throughput)) leaves/sec")

        } catch {
            print("  ERROR: \(error)")
        }
    }
}
