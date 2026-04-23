import Foundation
import Metal
import zkMetal
import Zoltraak

/// Profiler for Merkle tree building phase
/// Identifies bottlenecks and optimization opportunities
public struct MerkleTreeProfiling {

    // MARK: - Configuration

    public struct Config {
        public let numColumns: Int
        public let numLeaves: Int  // Per column
        public let subtreeSize: Int

        public static let standard = Config(
            numColumns: 180,
            numLeaves: 4096,
            subtreeSize: 512
        )
    }

    // MARK: - Profile Results

    public struct ProfileResult {
        public let config: Config
        public let totalTimeMs: Double
        public let leafHashMs: Double
        public let subtreeHashMs: Double
        public let upperLevelMs: Double
        public let numSubtrees: Int
        public let numLevels: Int
    }

    // MARK: - Run Profile

    public static func profile(config: Config = .standard) {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║         Merkle Tree Building Profiler                           ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║  Columns: \(config.numColumns)                                               ║
        ║  Leaves per column: \(config.numLeaves)                                       ║
        ║  Subtree size: \(config.subtreeSize)                                          ║
        ╚══════════════════════════════════════════════════════════════════╝

        """)

        // Generate test data
        let leaves = generateLeaves(columns: config.numColumns, leaves: config.numLeaves)
        let numSubtrees = config.numLeaves / config.subtreeSize

        print("Generated \(config.numColumns) trees with \(config.numLeaves) leaves each")
        print("Each tree has \(numSubtrees) subtrees of size \(config.subtreeSize)")
        print("Total leaf elements: \(config.numColumns * config.numLeaves)\n")

        // Profile GPU leaf hashing
        print("=== Phase 1: GPU Leaf Hashing ===")
        let leafHashTime = profileLeafHashing(leaves: leaves, numSubtrees: numSubtrees)

        // Profile subtree hashing
        print("\n=== Phase 2: GPU Subtree Hashing ===")
        let subtreeHashTime = profileSubtreeHashing(leaves: leaves, config: config)

        // Profile upper levels
        print("\n=== Phase 3: GPU Upper Levels ===")
        let upperLevelTime = profileUpperLevels(numSubtrees: numSubtrees, numColumns: config.numColumns)

        let totalTime = leafHashTime + subtreeHashTime + upperLevelTime

        print("""

        ╔══════════════════════════════════════════════════════════════════╗
        ║                    PROFILING RESULTS                           ║
        ╚══════════════════════════════════════════════════════════════════╝

        Phase Breakdown:
        ─────────────────────────────────────────────────────────────────────
        1. Leaf Hashing    : \(String(format: "%8.2fms", leafHashTime)) (\(String(format: "%5.1f", (leafHashTime/totalTime)*100))%)
        2. Subtree Hash   : \(String(format: "%8.2fms", subtreeHashTime)) (\(String(format: "%5.1f", (subtreeHashTime/totalTime)*100))%)
        3. Upper Levels   : \(String(format: "%8.2fms", upperLevelTime)) (\(String(format: "%5.1f", (upperLevelTime/totalTime)*100))%)
        ─────────────────────────────────────────────────────────────────────
        TOTAL             : \(String(format: "%8.2fms", totalTime))

        ╔══════════════════════════════════════════════════════════════════╗
        ║                    BOTTLENECK ANALYSIS                          ║
        ╚══════════════════════════════════════════════════════════════════╝
        """)

        analyzeBottleneck(
            leafHashMs: leafHashTime,
            subtreeHashMs: subtreeHashTime,
            upperLevelMs: upperLevelTime
        )

        print("\n" + String(repeating: "═", count: 65))
    }

    // MARK: - Generate Test Data

    private static func generateLeaves(columns: Int, leaves: Int) -> [[M31]] {
        var result: [[M31]] = []
        for col in 0..<columns {
            var column: [M31] = []
            for i in 0..<leaves {
                column.append(M31(v: UInt32((col * 1000 + i) % Int(UInt32.max))))
            }
            result.append(column)
        }
        return result
    }

    // MARK: - Profile Leaf Hashing

    private static func profileLeafHashing(leaves: [[M31]], numSubtrees: Int) -> Double {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Flatten leaves for batch hashing
        var flatValues: [M31] = []
        for col in leaves {
            flatValues.append(contentsOf: col)
        }

        // Time the GPU batch hashing
        do {
            let leafEngine = try ZoltraakLeafHashEngine()
            let countPerColumn = leaves[0].count
            let _ = try leafEngine.hashLeavesBatchPerColumn(
                allValues: flatValues,
                numColumns: leaves.count,
                countPerColumn: countPerColumn
            )
        } catch {
            print("  GPU leaf hashing failed: \(error)")
        }

        return (CFAbsoluteTimeGetCurrent() - t0) * 1000
    }

    // MARK: - Profile Subtree Hashing

    private static func profileSubtreeHashing(leaves: [[M31]], config: Config) -> Double {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Convert to digest format (8 M31 per digest)
        var treeLeaves: [[M31]] = []
        for col in leaves {
            var digests: [M31] = []
            for val in col {
                digests.append(val)
                digests.append(val)
                digests.append(val)
                digests.append(val)
                digests.append(val)
                digests.append(val)
                digests.append(val)
                digests.append(val)
            }
            treeLeaves.append(digests)
        }

        // Time the GPU subtree hashing
        do {
            let merkleEngine = try EVMGPUMerkleEngine()
            let _ = try merkleEngine.buildTreesBatch(treesLeaves: treeLeaves)
        } catch {
            print("  GPU subtree hashing failed: \(error)")
        }

        return (CFAbsoluteTimeGetCurrent() - t0) * 1000
    }

    // MARK: - Profile Upper Levels

    private static func profileUpperLevels(numSubtrees: Int, numColumns: Int) -> Double {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Upper levels are part of buildTreesBatch, so estimate based on tree depth
        let numLevels = Int(log2(Double(numSubtrees)))
        let pairsPerLevel = numColumns * (numSubtrees / 2)

        print("  Number of upper levels: \(numLevels)")
        print("  Pairs per level: \(pairsPerLevel)")
        print("  Total pair hashes: \(pairsPerLevel * numLevels)")

        // Upper levels are already included in subtree hashing time
        // Return 0 as separate measurement
        return 0  // Included in subtreeHashing
    }

    // MARK: - Analyze Bottleneck

    private static func analyzeBottleneck(leafHashMs: Double, subtreeHashMs: Double, upperLevelMs: Double) {
        let total = leafHashMs + subtreeHashMs

        if leafHashMs > subtreeHashMs * 0.5 {
            print("""
            PRIMARY BOTTLENECK: Leaf Hashing (\(String(format: "%.1f", (leafHashMs/total)*100))% of time)
            ─────────────────────────────────────────────────────────────────────
            Recommendation: Optimize GPU kernel throughput
            - Increase batch size
            - Reduce memory bandwidth pressure
            - Consider pre-computing position hashes
            """)
        } else if subtreeHashMs > leafHashMs * 2 {
            print("""
            PRIMARY BOTTLENECK: Merkle Tree Building (\(String(format: "%.1f", (subtreeHashMs/total)*100))% of time)
            ─────────────────────────────────────────────────────────────────────
            Recommendation: Optimize tree kernel
            - Use fused kernel for smaller trees
            - Batch multiple trees in single dispatch
            - Consider hierarchical commitment
            """)
        } else {
            print("""
            BALANCED: No single bottleneck dominates
            ─────────────────────────────────────────────────────────────────────
            Further optimization requires:
            - Pipelined execution (overlap GPU/CPU)
            - Parallel transaction processing
            - Optimized FRI implementation
            """)
        }
    }
}