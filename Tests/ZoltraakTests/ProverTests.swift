import Foundation
import Testing
import zkMetal
@testable import Zoltraak

struct ProverTests {

    // MARK: - GPU vs CPU Leaf Hashing Correctness

    @Test
    static func testGPUvsCPULoadDigestCorrectness() throws {
        // Test that GPU leaf hashing matches CPU leaf hashing
        // This is the core correctness check for ZoltraakLeafHashEngine

        let count = 64  // Test with 64 leaves

        // Generate test values and positions
        var values = [M31]()
        var positions = [UInt32]()
        for i in 0..<count {
            values.append(M31(v: UInt32(i + 1) % M31.P))
            positions.append(UInt32(i * 2))
        }

        // CPU path
        let cpuProver = ZoltraakCPUMerkleProver()
        let cpuDigests = cpuProver.hashLeavesWithPosition(values: values, positions: positions)

        // GPU path
        let gpuEngine = try ZoltraakLeafHashEngine()
        let gpuDigests = try gpuEngine.hashLeavesWithPosition(values: values, positions: positions)

        // Compare
        #expect(cpuDigests.count == gpuDigests.count)

        var allMatch = true
        var firstMismatchIdx: Int?
        for i in 0..<cpuDigests.count {
            if cpuDigests[i].v != gpuDigests[i].v {
                allMatch = false
                if firstMismatchIdx == nil {
                    firstMismatchIdx = i
                }
                print("Mismatch at index \(i): CPU=\(String(format:"0x%08X", cpuDigests[i].v)) GPU=\(String(format:"0x%08X", gpuDigests[i].v))")
            }
        }

        if let idx = firstMismatchIdx {
            let leafIdx = idx / 8
            let elemIdx = idx % 8
            print("First mismatch: leaf=\(leafIdx), element=\(elemIdx), value=\(values[leafIdx].v), position=\(positions[leafIdx])")
        }

        #expect(allMatch)
    }

    @Test
    static func testGPUvsCPULoadDigestBatchPerColumnCorrectness() throws {
        // Test batch per-column hashing

        let numColumns = 8
        let countPerColumn = 16
        let totalCount = numColumns * countPerColumn

        // Generate test values
        var allValues = [M31]()
        for i in 0..<totalCount {
            allValues.append(M31(v: UInt32(i * 3 + 7) % M31.P))
        }

        // CPU path
        let cpuProver = ZoltraakCPUMerkleProver()
        let cpuResults = cpuProver.hashLeavesBatchPerColumn(
            allValues: allValues,
            numColumns: numColumns,
            countPerColumn: countPerColumn
        )

        // GPU path
        let gpuEngine = try ZoltraakLeafHashEngine()
        let gpuResults = try gpuEngine.hashLeavesBatchPerColumn(
            allValues: allValues,
            numColumns: numColumns,
            countPerColumn: countPerColumn
        )

        // Compare
        #expect(cpuResults.count == gpuResults.count)

        for col in 0..<numColumns {
            #expect(cpuResults[col].count == gpuResults[col].count)

            for i in 0..<cpuResults[col].count {
                if cpuResults[col][i].v != gpuResults[col][i].v {
                    print("Mismatch at column \(col), index \(i): CPU=\(String(format:"0x%08X", cpuResults[col][i].v)) GPU=\(String(format:"0x%08X", gpuResults[col][i].v))")
                    Issue.record("GPU and CPU digests must match for column \(col)")
                }
            }
        }
    }

    @Test
    static func testGPUvsCPUMerkleTreeRoot() throws {
        // Test that GPU and CPU produce the same Merkle tree root

        let numLeaves = 256
        var values = [M31]()
        for i in 0..<numLeaves {
            values.append(M31(v: UInt32(i * 7 + 13) % M31.P))
        }

        // CPU path
        let cpuProver = ZoltraakCPUMerkleProver()
        let cpuRoot = cpuProver.buildMerkleTree(values: values, numLeaves: numLeaves)

        // GPU path
        let gpuEngine = try ZoltraakLeafHashEngine()
        let gpuRoot = try gpuEngine.buildMerkleTree(values: values, numLeaves: numLeaves)

        // Compare root values
        for i in 0..<8 {
            #expect(cpuRoot.values[i].v == gpuRoot.values[i].v)
        }

        print("CPU Root: \(cpuRoot.values.map { String(format:"0x%08X", $0.v) }.joined(separator: ", "))")
        print("GPU Root: \(gpuRoot.values.map { String(format:"0x%08X", $0.v) }.joined(separator: ", "))")
    }

    // MARK: - GPU Prover Tests

    @Test
    static func testEVMGPUMerkleEngineBasic() throws {
        let engine = try EVMGPUMerkleEngine()

        // Build a simple tree
        var leaves = [M31](repeating: .zero, count: 64)  // 8 leaves of 8 M31 each
        for i in 0..<64 {
            leaves[i] = M31(v: UInt32(i + 1))
        }

        let root = try engine.buildTree(leaves: leaves)

        #expect(root.values.count == 8)
        print("GPU Merkle root: \(root.values.map { String(format:"0x%08X", $0.v) }.joined(separator: ", "))")
    }

    @Test
    static func testEVMGPUMerkleEngineBatch() throws {
        let engine = try EVMGPUMerkleEngine()

        // Build multiple trees
        let numTrees = 4
        let leavesPerTree = 64
        var treesLeaves: [[M31]] = []

        for t in 0..<numTrees {
            var leaves = [M31]()
            for i in 0..<leavesPerTree {
                leaves.append(M31(v: UInt32(t * 1000 + i + 1)))
            }
            treesLeaves.append(leaves)
        }

        let roots = try engine.buildTreesBatch(treesLeaves: treesLeaves)

        #expect(roots.count == numTrees)
        for (i, root) in roots.enumerated() {
            print("Tree \(i) root: \(root.values.map { String(format:"0x%08X", $0.v) }.joined(separator: ", "))")
        }
    }

    // MARK: - CPU Prover Tests

    @Test
    static func testCPUMerkleProverBasic() throws {
        let prover = ZoltraakCPUMerkleProver()

        var values = [M31]()
        for i in 0..<256 {
            values.append(M31(v: UInt32(i * 3 + 1) % M31.P))
        }

        let root = prover.buildMerkleTree(values: values, numLeaves: 256)

        #expect(root.values.count == 8)
        print("CPU Merkle root: \(root.values.map { String(format:"0x%08X", $0.v) }.joined(separator: ", "))")
    }

    @Test
    static func testCPUMerkleProverBatchPerColumn() throws {
        let prover = ZoltraakCPUMerkleProver()

        let numColumns = 16
        let countPerColumn = 32
        let totalCount = numColumns * countPerColumn

        var allValues = [M31]()
        for i in 0..<totalCount {
            allValues.append(M31(v: UInt32(i * 7 + 5) % M31.P))
        }

        let results = prover.hashLeavesBatchPerColumn(
            allValues: allValues,
            numColumns: numColumns,
            countPerColumn: countPerColumn
        )

        #expect(results.count == numColumns)
        for col in 0..<numColumns {
            #expect(results[col].count == countPerColumn * 8)
        }
    }
}
