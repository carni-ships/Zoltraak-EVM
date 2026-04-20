import Foundation
import zkMetal
import EVMetal

/// Performance profiling for GPU commitment pipeline
public struct PerformanceProfile {

    public struct ProfilingResult {
        public let name: String
        public let numColumns: Int
        public let evalLen: Int
        public let totalLeaves: Int
        public let leafHashMs: Double
        public let treeBuildMs: Double
        public let totalMs: Double
        public let throughputLeavesPerSec: Double
        public let throughputBytesPerSec: Double

        public func printSummary() {
            print("  \(name):")
            print("    Size: \(numColumns) cols × \(evalLen) leaves = \(totalLeaves) total leaves")
            print("    Time: \(String(format: "%.1f", totalMs))ms total")
            print("      - Leaf hashing: \(String(format: "%.1f", leafHashMs))ms")
            print("      - Tree building: \(String(format: "%.1f", treeBuildMs))ms")
            print("    Throughput: \(String(format: "%.0f", throughputLeavesPerSec)) leaves/sec")
            print("              \(String(format: "%.1f", throughputBytesPerSec / 1024 / 1024)) MB/sec")
        }

        public func tableRow() -> String {
            return String(format: "| %-7d | %-6d | %-7d | %-8.1f | %-8.1f | %-6.1f | %-6.0f leaves/s |",
                          numColumns, evalLen, totalLeaves, leafHashMs, treeBuildMs, totalMs, throughputLeavesPerSec)
        }
    }

    /// Profile hybrid commitment performance (CPU hashing + GPU tree building)
    public static func profileHybridCommit(numColumns: Int, evalLen: Int) throws -> ProfilingResult {
        print("\n=== Profiling Hybrid Commit (CPU Hash + GPU Tree) ===")
        print("Configuration: \(numColumns) columns × \(evalLen) leaves")

        // Generate test data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var leaves: [M31] = []
            for i in 0..<evalLen {
                leaves.append(M31(v: UInt32(col * 10000 + i)))
            }
            traceLDEs.append(leaves)
        }

        let totalLeaves = numColumns * evalLen
        let totalBytes = totalLeaves * 4  // 4 bytes per M31

        // Use hybrid approach via EVMetalGPUProver
        let prover = try EVMetalGPUProver()

        // Warmup
        _ = try prover.commitTraceColumnsHybrid(traceLDEs: traceLDEs, evalLen: evalLen)

        // Measure hybrid approach
        let result = try prover.commitTraceColumnsHybrid(traceLDEs: traceLDEs, evalLen: evalLen)

        let totalTime = result.timeMs
        let hashTime = result.leafHashMs
        let treeTime = result.treeBuildMs

        let throughputLeaves = Double(totalLeaves) / (totalTime / 1000)
        let throughputBytes = Double(totalBytes) / (totalTime / 1000)

        let profileResult = ProfilingResult(
            name: "Hybrid (CPU Hash + GPU Tree)",
            numColumns: numColumns,
            evalLen: evalLen,
            totalLeaves: totalLeaves,
            leafHashMs: hashTime,
            treeBuildMs: treeTime,
            totalMs: totalTime,
            throughputLeavesPerSec: throughputLeaves,
            throughputBytesPerSec: throughputBytes
        )

        profileResult.printSummary()
        return profileResult
    }

    /// Profile CPU baseline
    public static func profileCPUBaseline(numColumns: Int, evalLen: Int) -> ProfilingResult {
        print("\n=== Profiling CPU Baseline ===")
        print("Configuration: \(numColumns) columns × \(evalLen) leaves")

        // Generate test data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var leaves: [M31] = []
            for i in 0..<evalLen {
                leaves.append(M31(v: UInt32(col * 10000 + i)))
            }
            traceLDEs.append(leaves)
        }

        let totalLeaves = numColumns * evalLen
        let totalBytes = totalLeaves * 4

        let cpuProver = EVMetalCPUMerkleProver()

        // Warmup
        _ = cpuProver.hashLeavesBatchPerColumn(allValues: traceLDEs.flatMap { $0 }, numColumns: numColumns, countPerColumn: evalLen)

        // Measure full CPU pipeline
        let start = CFAbsoluteTimeGetCurrent()
        var commitments: [zkMetal.M31Digest] = []

        // Hashing
        let hashStart = CFAbsoluteTimeGetCurrent()
        let flatValues = traceLDEs.flatMap { $0 }
        let allDigests = cpuProver.hashLeavesBatchPerColumn(allValues: flatValues, numColumns: numColumns, countPerColumn: evalLen)
        let hashTime = (CFAbsoluteTimeGetCurrent() - hashStart) * 1000

        // Tree building
        let treeStart = CFAbsoluteTimeGetCurrent()
        for colDigests in allDigests {
            var nodes: [zkMetal.M31Digest] = []
            for i in 0..<evalLen {
                let start = i * 8
                let digestValues = Array(colDigests[start..<start + 8])
                nodes.append(zkMetal.M31Digest(values: digestValues))
            }
            var levelSize = evalLen
            while levelSize > 1 {
                var nextLevel: [zkMetal.M31Digest] = []
                for i in stride(from: 0, to: levelSize, by: 2) {
                    let left = nodes[i]
                    let right = i + 1 < levelSize ? nodes[i + 1] : left
                    let hash = zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
                    nextLevel.append(hash)
                }
                nodes = nextLevel
                levelSize = nodes.count
            }
            commitments.append(nodes[0])
        }
        let treeTime = (CFAbsoluteTimeGetCurrent() - treeStart) * 1000

        let totalTime = (CFAbsoluteTimeGetCurrent() - start) * 1000
        let throughputLeaves = Double(totalLeaves) / (totalTime / 1000)
        let throughputBytes = Double(totalBytes) / (totalTime / 1000)

        let result = ProfilingResult(
            name: "CPU Baseline",
            numColumns: numColumns,
            evalLen: evalLen,
            totalLeaves: totalLeaves,
            leafHashMs: hashTime,
            treeBuildMs: treeTime,
            totalMs: totalTime,
            throughputLeavesPerSec: throughputLeaves,
            throughputBytesPerSec: throughputBytes
        )

        result.printSummary()
        return result
    }

    /// Profile GPU vs CPU with detailed breakdown
    public static func profileComparison(numColumns: Int, evalLen: Int) {
        print("\n" + String(repeating: "=", count: 60))
        print("Hybrid vs CPU Performance Comparison")
        print(String(repeating: "=", count: 60))

        do {
            let hybridResult = try profileHybridCommit(numColumns: numColumns, evalLen: evalLen)
            let cpuResult = profileCPUBaseline(numColumns: numColumns, evalLen: evalLen)

            print("\n--- Comparison ---")
            let speedup = cpuResult.totalMs / hybridResult.totalMs
            let treeSpeedup = cpuResult.treeBuildMs / hybridResult.treeBuildMs

            print("  Total time speedup: \(String(format: "%.2f", speedup))x")
            print("  Tree building speedup: \(String(format: "%.2f", treeSpeedup))x")
            print("  Hash time:")
            print("    Hybrid (CPU): \(String(format: "%.1f", hybridResult.leafHashMs))ms")
            print("    CPU: \(String(format: "%.1f", cpuResult.leafHashMs))ms")
            print("  Tree time:")
            print("    Hybrid (GPU): \(String(format: "%.1f", hybridResult.treeBuildMs))ms")
            print("    CPU: \(String(format: "%.1f", cpuResult.treeBuildMs))ms")

        } catch {
            print("  Error: \(error)")
        }
    }

    /// Profile scaling behavior
    public static func profileScaling() {
        print("\n" + String(repeating: "=", count: 60))
        print("Scaling Analysis")
        print(String(repeating: "=", count: 60))

        let configs = [
            (4, 16),      // Small
            (16, 64),     // Medium
            (64, 256),    // Large
            (180, 512),   // EVMAIR single subtree
        ]

        print("\n| Columns | Leaves | Total   | CPU Hash | GPU Tree | Total  | Throughput    |")
        print("|---------|--------|---------|----------|----------|--------|---------------|")

        for (cols, leaves) in configs {
            do {
                let result = try profileHybridCommit(numColumns: cols, evalLen: leaves)
                print(String(format: "| %-7d | %-6d | %-7d | %-8.1f | %-8.1f | %-6.1f | %-6.0f leaves/s |",
                              cols, leaves, result.totalLeaves,
                              result.leafHashMs, result.treeBuildMs, result.totalMs,
                              result.throughputLeavesPerSec))
            } catch {
                print(String(format: "| %-7d | %-6d | ERROR   |", cols, leaves))
            }
        }
    }

    /// Profile detailed phases of hybrid approach
    public static func profileDetailedPhases() {
        print("\n" + String(repeating: "=", count: 60))
        print("Detailed Phase Analysis - Hybrid Approach")
        print(String(repeating: "=", count: 60))

        let numColumns = 180
        let evalLen = 512

        print("\nConfiguration: \(numColumns) columns × \(evalLen) leaves")
        print("Total leaves: \(numColumns * evalLen)")

        // Generate test data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var leaves: [M31] = []
            for i in 0..<evalLen {
                leaves.append(M31(v: UInt32(col * 10000 + i)))
            }
            traceLDEs.append(leaves)
        }

        do {
            let prover = try EVMetalGPUProver()

            // Warmup
            _ = try prover.commitTraceColumnsHybrid(traceLDEs: traceLDEs, evalLen: evalLen)

            // Measure hybrid approach
            let result = try prover.commitTraceColumnsHybrid(traceLDEs: traceLDEs, evalLen: evalLen)

            print("\nPhase Breakdown:")
            print("  1. CPU position hashing:  \(String(format: "%.1f", result.leafHashMs))ms")
            print("  2. GPU tree building:     \(String(format: "%.1f", result.treeBuildMs))ms")
            print("  Total:                   \(String(format: "%.1f", result.timeMs))ms")

            let totalTime = result.timeMs
            print("\nBottleneck Analysis:")
            let hashPercent = (result.leafHashMs / totalTime) * 100
            let treePercent = (result.treeBuildMs / totalTime) * 100
            print("  CPU hashing:  \(String(format: "%.1f", hashPercent))% of total time")
            print("  GPU tree:     \(String(format: "%.1f", treePercent))% of total time")

            let bottleneck = result.leafHashMs > result.treeBuildMs ? "CPU position hashing" : "GPU tree building"
            print("  Primary bottleneck: \(bottleneck)")

        } catch {
            print("  Error: \(error)")
        }
    }

    /// Run full performance profile
    public static func runFullProfile() {
        print("\n" + String(repeating: "=", count: 60))
        print("EVMetal GPU Performance Profile")
        print(String(repeating: "=", count: 60))

        // Quick comparison
        profileComparison(numColumns: 16, evalLen: 64)

        // Scaling analysis
        profileScaling()

        // Detailed phases
        profileDetailedPhases()

        print("\n" + String(repeating: "=", count: 60))
        print("Profile Complete")
        print(String(repeating: "=", count: 60))
    }
}
