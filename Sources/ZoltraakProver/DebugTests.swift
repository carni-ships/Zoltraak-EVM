import Foundation
import zkMetal
import Zoltraak

/// Debugging test for GPU commitment generation
public struct DebugTests {

    /// Detailed test for GPU vs CPU commitment matching
    public static func testGPUCPUCommitmentDetailed() {
        print("=== Debug: GPU vs CPU Commitment Detailed Test ===\n")

        let numColumns = 4
        let evalLen = 16

        // Create test data
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var leaves: [M31] = []
            for i in 0..<evalLen {
                leaves.append(M31(v: UInt32(col * 1000 + i)))
            }
            traceLDEs.append(leaves)
        }

        print("Test data: \(numColumns) columns x \(evalLen) leaves")
        print("Column 0 first 5 values: \(traceLDEs[0].prefix(5).map { $0.v })")

        // Step 1: CPU baseline - full pipeline
        print("\n--- Step 1: CPU Baseline ---")
        let cpuProver = ZoltraakCPUMerkleProver()
        var cpuCommitments: [zkMetal.M31Digest] = []

        for col in 0..<numColumns {
            let positions = (0..<evalLen).map { UInt32($0) }
            let digests = cpuProver.hashLeavesWithPosition(
                values: traceLDEs[col],
                positions: positions
            )

            // Show first leaf digest
            print("  Column \(col) - First leaf digest (8 values):")
            print("    \(digests.prefix(8).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))")

            // Build tree
            var nodes: [zkMetal.M31Digest] = []
            for i in 0..<evalLen {
                let start = i * 8
                let digestValues = Array(digests[start..<start + 8])
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

        // Step 2: GPU leaf hashing
        print("\n--- Step 2: GPU Leaf Hashing ---")
        do {
            let leafHashEngine = try ZoltraakLeafHashEngine()

            // Test single column first
            let col0Digests = try leafHashEngine.hashLeavesWithPosition(
                values: traceLDEs[0],
                positions: (0..<evalLen).map { UInt32($0) }
            )

            print("  Column 0 GPU - First leaf digest (8 values):")
            print("    \(col0Digests.prefix(8).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))")

            // Compare with CPU
            let cpuCol0Digests = cpuProver.hashLeavesWithPosition(
                values: traceLDEs[0],
                positions: (0..<evalLen).map { UInt32($0) }
            )

            var leafHashMatch = true
            for i in 0..<min(col0Digests.count, cpuCol0Digests.count) {
                if col0Digests[i].v != cpuCol0Digests[i].v {
                    leafHashMatch = false
                    print("  MISMATCH at digest index \(i)")
                }
            }
            print("  GPU leaf hashes match CPU: \(leafHashMatch)")

            // Step 3: GPU batch hashing
            print("\n--- Step 3: GPU Batch Hashing (all columns) ---")

            // Flatten values for batch processing
            var flatValues: [M31] = []
            for col in traceLDEs {
                flatValues.append(contentsOf: col)
            }

            let batchDigests = try leafHashEngine.hashLeavesBatchPerColumn(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: evalLen
            )

            print("  Batch returned \(batchDigests.count) column digest arrays")
            for col in 0..<numColumns {
                print("  Column \(col) - First leaf digest:")
                print("    \(batchDigests[col].prefix(8).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))")
            }

            // Step 4: Compare CPU vs GPU commitments
            print("\n--- Step 4: Compare Full Commitments ---")

            let gpuProver = ZoltraakGPUProver()
            let gpuResult = try gpuProver.commitTraceColumnsGPU(traceLDEs: traceLDEs, evalLen: evalLen)

            for col in 0..<numColumns {
                let cpuRoot = cpuCommitments[col].values
                let gpuRoot = gpuResult.commitments[col].values

                print("  Column \(col):")
                print("    CPU root: \(cpuRoot.prefix(4).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))...")
                print("    GPU root: \(gpuRoot.prefix(4).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))...")

                if cpuRoot == gpuRoot {
                    print("    ✓ MATCH")
                } else {
                    print("    ✗ MISMATCH")
                    for i in 0..<8 {
                        if cpuRoot[i].v != gpuRoot[i].v {
                            print("      Element \(i): CPU=0x\(String(format: "%08X", cpuRoot[i].v)) GPU=0x\(String(format: "%08X", gpuRoot[i].v))")
                        }
                    }
                }
            }

        } catch {
            print("  Error: \(error)")
        }

        print("\n=== Debug Test Complete ===")
    }

    /// Test that isolates the tree building phase
    public static func testTreeBuildingIsolation() {
        print("\n=== Debug: Tree Building Isolation ===\n")

        // Create identical digests
        let numLeaves = 16
        var digests: [M31] = []
        for i in 0..<numLeaves {
            // Create predictable digest values
            for j in 0..<8 {
                digests.append(M31(v: UInt32(i * 10 + j)))
            }
        }

        print("Test digest array: \(numLeaves) leaves x 8 values = \(digests.count) total")
        print("First 16 values: \(digests.prefix(16).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))")

        // Build tree using CPU method 1 (inline in ZoltraakGPUProver)
        var nodes1: [zkMetal.M31Digest] = []
        for i in 0..<numLeaves {
            let start = i * 8
            let digestValues = Array(digests[start..<start + 8])
            nodes1.append(zkMetal.M31Digest(values: digestValues))
        }

        var levelSize = numLeaves
        while levelSize > 1 {
            var nextLevel: [zkMetal.M31Digest] = []
            for i in stride(from: 0, to: levelSize, by: 2) {
                let left = nodes1[i]
                let right = i + 1 < levelSize ? nodes1[i + 1] : left
                let hash = zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
                nextLevel.append(hash)
            }
            nodes1 = nextLevel
            levelSize = nodes1.count
        }

        // Build tree using CPU method 2 (zkmetal's buildPoseidon2M31MerkleTree if available)
        let cpuProver = ZoltraakCPUMerkleProver()
        let tree = cpuProver.buildMerkleTree(values: digests, numLeaves: numLeaves)

        print("\nTree root comparison:")
        print("  Method 1 (inline): \(nodes1[0].values.prefix(4).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))...")
        print("  Method 2 (zkmetal): \(tree.values.prefix(4).map { String(format: "0x%08X", $0.v) }.joined(separator: ", "))...")

        if nodes1[0].values == tree.values {
            print("  ✓ Both methods produce same root")
        } else {
            print("  ✗ Methods differ!")
            for i in 0..<8 {
                print("    Element \(i): \(String(format: "0x%08X", nodes1[0].values[i].v)) vs \(String(format: "0x%08X", tree.values[i].v))")
            }
        }

        print("\n=== Tree Building Isolation Complete ===")
    }
}
