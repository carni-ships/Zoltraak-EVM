import Foundation
import zkMetal
import EVMetal

/// Benchmark suite for testing H2-H5 leaf hashing optimizations
public struct LeafHashOptimizations {

    // MARK: - Run All Optimization Tests

    /// Run all optimization benchmarks and report results
    public static func runAll() {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║       Leaf Hashing Optimization Benchmark (H2-H5)              ║
        ╚══════════════════════════════════════════════════════════════════╝

        """)

        // Check available optimizations first
        print("Checking available kernels...")
        do {
            let engine = try EVMetalLeafHashEngine()
            let opts = engine.getAvailableOptimizations()
            print("  Available kernels:")
            for (k, v) in opts.sorted(by: { $0.key < $1.key }) {
                print("    \(k): \(v ? "YES" : "NO")")
            }
        } catch {
            print("  Engine init failed: \(error)")
            return
        }
        print("")

        // Run a single simple benchmark
        runSingleBenchmark(numColumns: 180, numLeaves: 512)
    }

    // MARK: - Single Benchmark

    private static func runSingleBenchmark(numColumns: Int, numLeaves: Int) {
        let totalCount = numColumns * numLeaves

        print("[Test] \(numColumns) columns x \(numLeaves) leaves = \(totalCount) total")
        print(String(repeating: "-", count: 60))

        // Generate test data
        var flatValues: [M31] = []
        flatValues.reserveCapacity(totalCount)
        for col in 0..<numColumns {
            for i in 0..<numLeaves {
                flatValues.append(M31(v: UInt32(col * 1000 + i)))
            }
        }

        // Test baseline (original kernel)
        print("\n  Running benchmarks...")

        do {
            let engine = try EVMetalLeafHashEngine()
            engine.optimizationLevel = .basic

            let t0 = CFAbsoluteTimeGetCurrent()
            _ = try engine.hashLeavesAutoOptimized(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: numLeaves
            )
            let baselineTime = (CFAbsoluteTimeGetCurrent() - t0) * 1000
            print("  Baseline (original):    \(String(format: "%8.2fms", baselineTime))")

            // Test H2H3 optimization
            engine.optimizationLevel = .sharedMem
            let t1 = CFAbsoluteTimeGetCurrent()
            _ = try engine.hashLeavesAutoOptimized(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: numLeaves
            )
            let h2h3Time = (CFAbsoluteTimeGetCurrent() - t1) * 1000
            let h2h3Speedup = baselineTime / h2h3Time
            print("  H2+H3 (coalesced+SM):   \(String(format: "%8.2fms", h2h3Time)) (\(String(format: "%.2fx", h2h3Speedup)))")

            // Test H4 precomputation optimization
            engine.optimizationLevel = .precomputed
            let t1b = CFAbsoluteTimeGetCurrent()
            _ = try engine.hashLeavesAutoOptimized(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: numLeaves
            )
            let h4Time = (CFAbsoluteTimeGetCurrent() - t1b) * 1000
            let h4Speedup = baselineTime / h4Time
            print("  H2+H3+H4 (precomputed): \(String(format: "%8.2fms", h4Time)) (\(String(format: "%.2fx", h4Speedup)))")

            // Test combined
            engine.optimizationLevel = .combined
            let t2 = CFAbsoluteTimeGetCurrent()
            _ = try engine.hashLeavesAutoOptimized(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: numLeaves
            )
            let combinedTime = (CFAbsoluteTimeGetCurrent() - t2) * 1000
            let combinedSpeedup = baselineTime / combinedTime
            print("  Combined (H2+H3+H4+H5): \(String(format: "%8.2fms", combinedTime)) (\(String(format: "%.2fx", combinedSpeedup)))")

        } catch {
            print("  Benchmark failed: \(error)")
        }

        print("""

        ═══════════════════════════════════════════════════════════════════
        Optimization Summary:
        ─────────────────────────────────────────────────────────────────────
        H2: Memory Coalescing - Restructured data layout for GPU access
        H3: Shared Memory - Position caching in threadgroup shared memory
        H4: Pre-computation - Position hash inputs pre-computed once
        H5: Half-Precision - 16-bit storage for M31 values
        ═══════════════════════════════════════════════════════════════════
        """)
    }
}
