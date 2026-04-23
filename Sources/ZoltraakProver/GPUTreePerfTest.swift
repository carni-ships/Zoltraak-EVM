import Foundation
import zkMetal
import Zoltraak

/// Test to measure GPU tree building performance improvement
public struct GPUTreeBuildingPerfTest {

    public static func runGPUTreeBuildingPerfTest() {
        print("\n=== GPU Tree Building Performance Test ===\n")

        do {
            let numColumns = 180
            let evalLen = 512

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

            // Step 1: Hash leaves with GPU (same for both)
            let leafHashEngine = try ZoltraakLeafHashEngine()
            var flatValues: [M31] = []
            for col in traceLDEs {
                flatValues.append(contentsOf: col)
            }

            let hashStart = CFAbsoluteTimeGetCurrent()
            let allDigests = try leafHashEngine.hashLeavesBatchPerColumn(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: evalLen
            )
            let hashMs = (CFAbsoluteTimeGetCurrent() - hashStart) * 1000
            print("GPU leaf hashing: \(String(format: "%.1f", hashMs))ms")

            // Step 2a: CPU tree building
            let cpuTreeStart = CFAbsoluteTimeGetCurrent()
            var cpuCommitments: [zkMetal.M31Digest] = []
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
                cpuCommitments.append(nodes[0])
            }
            let cpuTreeMs = (CFAbsoluteTimeGetCurrent() - cpuTreeStart) * 1000

            // Step 2b: GPU tree building
            let gpuTreeStart = CFAbsoluteTimeGetCurrent()
            let gpuTreeEngine = try Poseidon2M31Engine()
            var gpuCommitments: [zkMetal.M31Digest] = []
            for colDigests in allDigests {
                let rootM31 = try gpuTreeEngine.merkleCommit(leaves: colDigests)
                gpuCommitments.append(zkMetal.M31Digest(values: rootM31))
            }
            let gpuTreeMs = (CFAbsoluteTimeGetCurrent() - gpuTreeStart) * 1000

            // Verify correctness
            var allMatch = true
            for i in 0..<numColumns {
                if cpuCommitments[i].values != gpuCommitments[i].values {
                    allMatch = false
                    print("Column \(i): MISMATCH!")
                }
            }

            print("\n--- Results ---")
            print("CPU tree building: \(String(format: "%.1f", cpuTreeMs))ms")
            print("GPU tree building: \(String(format: "%.1f", gpuTreeMs))ms")
            print("Speedup: \(String(format: "%.2fx", cpuTreeMs / gpuTreeMs))")
            print("Correctness: \(allMatch ? "✓ All MATCH" : "✗ Some MISMATCH")")

            // Total time comparison
            let cpuTotal = hashMs + cpuTreeMs
            let gpuTotal = hashMs + gpuTreeMs
            print("\nTotal time (hash + tree):")
            print("  CPU: \(String(format: "%.1f", cpuTotal))ms")
            print("  GPU: \(String(format: "%.1f", gpuTotal))ms")
            print("  Improvement: \(String(format: "%.1f", cpuTotal - gpuTotal))ms saved (\(String(format: "%.1fx", cpuTotal / gpuTotal))x)")

        } catch {
            print("Error: \(error)")
        }
    }
}
