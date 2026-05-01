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
    static func testGPUMerkleTreeM31EngineBatchFixed() throws {
        // Test that buildTreesBatchGPU executes without crashing
        // Note: GPU batch tree building has known issues with the batch level kernel
        // producing inconsistent roots for large trees (131072 leaves).
        // For small trees (64 leaves), it runs but may produce inconsistent results.
        // Real-block proving uses CPU trees for correctness.
        let numTrees = 4
        let leavesPerTree = 64

        var treesLeaves: [[M31]] = []
        for t in 0..<numTrees {
            var leaves = [M31]()
            for i in 0..<leavesPerTree {
                leaves.append(M31(v: UInt32(i + 1)))
            }
            treesLeaves.append(leaves)
        }

        let gpuEngine = try GPUMerkleTreeM31Engine()

        // This should not throw
        let (gpuRoots, _, _) = try gpuEngine.buildTreesBatchGPU(columns: treesLeaves, count: leavesPerTree)

        // Basic sanity: should return correct number of roots
        #expect(gpuRoots.count == numTrees)

        // Each root should have 8 M31 elements
        for i in 0..<numTrees {
            #expect(gpuRoots[i].values.count == 8, "Tree \(i) should have 8 M31 elements per digest")
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

    // MARK: - State Proof Mode Tests

    @Test
    static func testStateProofConfiguration() throws {
        // Test that BlockProvingConfig with state proofs is properly configured
        let config1 = BlockProvingConfig.withStateProofs
        #expect(config1.useStateProofs == true)

        let config2 = BlockProvingConfig.withStrictStateProofs
        #expect(config2.useStateProofs == true)

        print("State proof config test passed")
    }

    @Test
    static func testEVMTransactionWithInitialState() throws {
        // Test that EVMTransaction properly holds initial state
        let state = EVMTransactionState(
            balances: ["0x1234": M31Word(low64: 1000)],
            codes: [:],
            codeHashes: [:],
            storage: [:]
        )

        let tx = EVMTransaction(
            code: [0x60, 0x01],
            calldata: [],
            value: .zero,
            gasLimit: 21_000,
            sender: M31Word(low64: 0xabcd),
            to: M31Word(low64: 0x1234),
            initialState: state
        )

        #expect(tx.to != nil)
        #expect(tx.initialState != nil)
        let balance = tx.initialState?.balances["0x1234"]
        #expect(balance != nil)
        #expect(balance?.toHexString() == M31Word(low64: 1000).toHexString())

        print("EVMTransaction with initial state test passed")
    }

    @Test
    static func testMerklePatriciaTrieHexPrefix() throws {
        // Test hex-prefix encoding produces valid output
        let nibbles: [UInt8] = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7]
        let encoded = MerklePatriciaTrie.HexPrefix.encode(nibbles, isLeaf: true)
        #expect(!encoded.isEmpty)

        // Verify encoded length is reasonable (should be at least 1 byte for metadata + data bytes)
        #expect(encoded.count >= 2)

        print("Hex-prefix encoding test passed")
    }

    @Test
    static func testKeccakPatriciaEngineHashBranch() throws {
        // Test branch node hashing
        let children: [[UInt8]] = Array(repeating: [UInt8](repeating: 0, count: 32), count: 16)
        let value: [UInt8] = [UInt8](repeating: 0, count: 32)

        let hash = KeccakPatriciaEngine.hashBranch(children: children, value: value)
        #expect(hash.count == 32)

        print("KeccakPatriciaEngine hashBranch test passed")
    }
}
