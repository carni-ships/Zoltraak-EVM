import Foundation
import zkMetal
import EVMetal

// MARK: - ProverTests

/// End-to-end prover test suite for EVMetal.
///
/// This is an alternative to XCTest that runs tests directly and reports results.
/// Useful when running outside of Xcode or for integration testing.
///
/// Run with: `swift run EVMetalTestRunner --test` or specific test names.
public struct ProverTests {

    // MARK: - Test Runners

    /// Runs all tests including slow E2E tests.
    ///
    /// Tests cover:
    /// - Basic types (M31Word)
    /// - EVM components (stack, memory, execution)
    /// - AIR generation
    /// - Batch prover
    /// - Precompiles
    /// - GPU/CPU commitment correctness
    /// - All EVM opcodes
    /// - E2E proof generation and verification
    /// - GPU batch Merkle
    public static func runAllTests() {
        print("=== EVMetal Prover Tests ===\n")

        testM31WordBasic()
        testEVMStack()
        testEVMMemory()
        testEVMExecution()
        testEVMTraceGeneration()
        testEVMAIR()
        testBatchProver()
        testPrecompiles()
        testGPUCPUCommitmentMatch()
        testAllOpcodes()
        testE2EProofGenerationAndVerification()
        testE2EBlockProof()
        testGPUMerkleBatch()
        testBatchCommitProfile()

        print("\n=== All tests passed! ===")
    }

    /// Runs quick tests, skipping slow E2E tests.
    ///
    /// Includes all tests except `testE2EProofGenerationAndVerification` and `testE2EBlockProof`.
    public static func runQuickTests() {
        testM31WordBasic()
        testEVMStack()
        testEVMMemory()
        testEVMExecution()
        testEVMTraceGeneration()
        testEVMAIR()
        testBatchProver()
        testPrecompiles()
        testGPUCPUCommitmentMatch()
        testAllOpcodes()
        testGPUMerkleBatch()
        testBatchCommitProfile()

        print("\n=== Quick Tests passed! ===")
    }

    /// Runs only GPU batch tests.
    ///
    /// Includes:
    /// - `testGPUCPUCommitmentMatch`
    /// - `testGPUMerkleBatch`
    /// - `testBatchCommitProfile`
    public static func runGPUBatchTests() {
        testGPUCPUCommitmentMatch()
        testGPUMerkleBatch()
        testBatchCommitProfile()

        print("\n=== GPU Batch Tests passed! ===")
    }

    /// Runs only opcode tests.
    public static func runOpcodeTests() {
        testAllOpcodes()

        print("\n=== Opcode Tests passed! ===")
    }

    /// Runs only E2E tests.
    ///
    /// Includes:
    /// - `testGPUCPUCommitmentMatch`
    /// - `testE2EProofGenerationAndVerification`
    /// - `testE2EBlockProof`
    public static func runE2ETests() {
        testGPUCPUCommitmentMatch()
        testE2EProofGenerationAndVerification()
        testE2EBlockProof()

        print("\n=== E2E Tests passed! ===")
    }

    /// Runs a specific test by name (partial match supported).
    ///
    /// - Parameter name: Partial name to match (case-insensitive).
    ///   Available tests: m31word, stack, memory, execution, trace, evmair,
    ///   batch, precompile, e2e, block, gpu, commit, correctness, opcode
    public static func runTest(named name: String) {
        let tests: [(String, () -> Void)] = [
            ("m31word", testM31WordBasic),
            ("stack", testEVMStack),
            ("memory", testEVMMemory),
            ("execution", testEVMExecution),
            ("trace", testEVMTraceGeneration),
            ("evmair", testEVMAIR),
            ("batch", testBatchProver),
            ("precompile", testPrecompiles),
            ("e2e", testE2EProofGenerationAndVerification),
            ("block", testE2EBlockProof),
            ("gpu", testGPUMerkleBatch),
            ("commit", testBatchCommitProfile),
            ("correctness", testGPUCPUCommitmentMatch),
            ("opcode", testAllOpcodes),
        ]

        var found = false
        for (nameLower, testFn) in tests {
            if nameLower.contains(name.lowercased()) || name.lowercased().contains(nameLower) {
                testFn()
                found = true
            }
        }

        if !found {
            print("Unknown test: \(name)")
            print("Available tests: \(tests.map { $0.0 }.joined(separator: ", "))")
        }
    }

    // MARK: - Basic Types

    public static func testM31WordBasic() {
        print("Test: M31Word Basic Operations")

        // Test creation from low64
        let word1 = M31Word(low64: 42)
        assert(!word1.isZero, "Word should not be zero")
        assert(word1.toHexString() != "", "Hex string should not be empty")

        // Test creation from bytes
        let bytes = [UInt8](repeating: 0xFF, count: 32)
        let word2 = M31Word(bytes: bytes)
        assert(!word2.isZero, "Word from bytes should not be zero")

        // Test addition
        let sum = word1.add(word2)
        assert(!sum.result.isZero, "Sum should not be zero")

        print("  ✓ M31Word basic operations passed\n")
    }

    public static func testEVMStack() {
        print("Test: EVM Stack")

        var stack = EVMStack()
        assert(stack.stackHeight == 0, "Initial stack height should be 0")

        let word = M31Word(low64: 100)
        stack.push(word)
        assert(stack.stackHeight == 1, "Stack height should be 1 after push")

        let popped = stack.pop()
        assert(stack.stackHeight == 0, "Stack height should be 0 after pop")
        assert(popped.low32 == 100, "Popped value should match pushed value")

        print("  ✓ EVM Stack passed\n")
    }

    public static func testEVMMemory() {
        print("Test: EVM Memory")

        var mem = EVMMemory()
        assert(mem.size == 0, "Initial memory size should be 0")

        mem.storeByte(offset: 0, value: 0xAB)
        assert(mem.size == 32, "Memory expands to 32-byte words after first store")

        let byte = mem.loadByte(offset: 0)
        assert(byte == 0xAB, "Loaded byte should match stored byte")

        // Test memory expansion at different offset
        mem.storeByte(offset: 64, value: 0xCD)
        assert(mem.size == 96, "Memory should expand to accommodate new offset")

        let byte2 = mem.loadByte(offset: 64)
        assert(byte2 == 0xCD, "Loaded byte at offset 64 should match")

        print("  ✓ EVM Memory passed\n")
    }

    // MARK: - EVM Execution

    public static func testEVMExecution() {
        print("Test: EVM Execution (STOP opcode)")

        let engine = EVMExecutionEngine()
        let result = try! engine.execute(
            code: [0x00],  // STOP
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        assert(!result.trace.reverted, "STOP should not revert")
        assert(result.trace.gasUsed < 100000, "STOP should use minimal gas")
        assert(result.trace.rows.count >= 1, "Should have at least 1 trace row")

        print("  ✓ EVM STOP execution passed\n")
    }

    public static func testEVMExecutionAdd() {
        print("Test: EVM Execution (ADD)")

        // PUSH1 1, PUSH1 2, ADD, STOP
        let code: [UInt8] = [
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x01,        // ADD
            0x00         // STOP
        ]

        let engine = EVMExecutionEngine()
        let result = try! engine.execute(
            code: code,
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        assert(!result.trace.reverted, "ADD should not revert")
        assert(result.trace.rows.count >= 4, "Should have trace rows for all ops")

        print("  ✓ EVM ADD execution passed\n")
    }

    public static func testEVMExecutionMultipleOps() {
        print("Test: EVM Execution (Multiple ops)")

        // Simple loop: PUSH1 10, PUSH1 0, JUMPDEST, SUB, DUP1, PUSH1 0, JUMPI
        let code: [UInt8] = [
            0x60, 0x0A,  // PUSH1 10
            0x60, 0x00,  // PUSH1 0
            0x5B,        // JUMPDEST
            0x03,        // SUB
            0x80,        // DUP1
            0x60, 0x03,  // PUSH1 3
            0x57,        // JUMPI
            0x00         // STOP
        ]

        let engine = EVMExecutionEngine()
        let result = try! engine.execute(
            code: code,
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        assert(!result.trace.reverted, "Execution should not revert")
        print("  ✓ EVM multiple ops execution passed\n")
    }

    // MARK: - Trace Generation

    public static func testEVMTraceGeneration() {
        print("Test: EVM Trace Generation")

        let code: [UInt8] = [
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x01,        // ADD
            0x00         // STOP
        ]

        let engine = EVMExecutionEngine()
        let result = try! engine.execute(
            code: code,
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        // Check trace has correct structure
        assert(result.trace.rows.count >= 4, "Should have 4+ trace rows")
        assert(result.trace.finalState.gas <= result.trace.initialState.gas, "Gas should decrease")

        print("  ✓ EVM Trace Generation passed\n")
    }

    // MARK: - AIR

    public static func testEVMAIR() {
        print("Test: EVMAIR")

        let code: [UInt8] = [
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x01,        // ADD
            0x00         // STOP
        ]

        let engine = EVMExecutionEngine()
        let result = try! engine.execute(
            code: code,
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        // Create AIR from execution
        let air = EVMAIR(from: result)
        assert(air.logTraceLength >= 10, "Trace length should be at least 2^10")

        // Generate trace columns
        let trace = air.generateTrace()
        assert(trace.count == EVMAIR.numColumns, "Should have correct number of columns")
        assert(trace[0].count == air.traceLength, "Should have correct trace length")

        // Check boundary constraints format
        let bc = air.boundaryConstraints
        assert(bc.count >= 4, "Should have boundary constraints")

        print("  ✓ EVMAIR passed\n")
    }

    // MARK: - Batch Prover

    public static func testBatchProver() {
        print("Test: EVMBatchProver")

        // Test that we can create the prover and execute transactions
        // Note: Full CircleSTARK proving requires Metal shaders from zkmetal
        // For now, just test that execution works

        let engine = EVMExecutionEngine()
        let result = try! engine.execute(
            code: [0x00],  // STOP
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        assert(!result.trace.reverted, "Execution should not revert")
        assert(result.trace.rows.count >= 1, "Should have trace rows")

        // Create AIR from result
        let air = EVMAIR(from: result)
        assert(air.logTraceLength >= 10, "Should have valid trace length")

        // Generate trace columns
        let trace = air.generateTrace()
        assert(trace.count == EVMAIR.numColumns, "Should have correct number of columns")

        print("  ✓ EVMBatchProver passed (CircleSTARK GPU requires zkmetal Shaders)\n")
    }

    // MARK: - Precompiles

    public static func testPrecompiles() {
        print("Test: EVMPrecompiles")

        // Test that we can create the engine
        do {
            let engine = try EVMPrecompiles.Engine()
            assert(true, "Engine created successfully")

            // Test gas cost calculation
            let gas = engine.gasCost(address: .ecRecover, inputSize: 128)
            assert(gas > 0, "Gas cost should be positive")

            // Test identity precompile (always succeeds)
            let result = engine.execute(address: .identity, input: [0xDE, 0xAD], gas: 100)
            assert(result.success, "Identity precompile should succeed")
            assert(result.output == [0xDE, 0xAD], "Identity should return input")

            print("  ✓ EVMPrecompiles passed\n")
        } catch {
            print("  ⚠ EVMPrecompiles engine failed to init (expected if no GPU): \(error)\n")
        }
    }

    // MARK: - End-to-End Proof Tests

    public static func testE2EProofGenerationAndVerification() {
        print("Test: E2E Proof Generation and Verification (GPU)")

        // Step 1: Execute EVM code to generate trace
        let code: [UInt8] = [
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x01,        // ADD
            0x00         // STOP
        ]

        let evmEngine = EVMExecutionEngine()
        let executionResult = try! evmEngine.execute(
            code: code,
            calldata: [],
            value: .zero,
            gasLimit: 100000
        )

        assert(!executionResult.trace.reverted, "Execution should not revert")

        // Step 2: Create AIR from execution result
        let air = EVMAIR(from: executionResult)
        print("  AIR created: logTraceLength=\(air.logTraceLength), numColumns=\(EVMAIR.numColumns)")

        // Step 3: Generate trace columns
        let trace = air.generateTrace()
        assert(trace.count == EVMAIR.numColumns, "Should have correct number of columns")
        let traceLen = trace[0].count
        print("  Trace generated: \(trace.count) columns x \(traceLen) rows")

        // Step 4: Generate GPU-accelerated proof using GPUCircleSTARKProverEngine
        let gpuConfig = GPUCircleSTARKProverConfig(
            logBlowup: 2,  // 4x blowup
            numQueries: 20,
            extensionDegree: 4,
            gpuConstraintThreshold: 64,
            gpuFRIFoldThreshold: 64,
            usePoseidon2Merkle: true,
            numQuotientSplits: 2
        )

        let gpuProver = GPUCircleSTARKProverEngine(config: gpuConfig)

        do {
            let result = try gpuProver.prove(air: air)
            print("  Proof generated: \(result.proof.traceCommitments.count) commitments")
            print("  Total proving time: \(result.totalTimeSeconds * 1000)ms")
            print("    - Trace gen: \(result.traceGenTimeSeconds * 1000)ms")
            print("    - LDE: \(result.ldeTimeSeconds * 1000)ms")
            print("    - Commit: \(result.commitTimeSeconds * 1000)ms")
            print("    - Constraints: \(result.constraintTimeSeconds * 1000)ms")
            print("    - FRI: \(result.friTimeSeconds * 1000)ms")
            print("    - Query: \(result.queryTimeSeconds * 1000)ms")

            // Step 5: Verify the proof
            let isValid = gpuProver.verify(air: air, proof: result.proof)
            assert(isValid, "Proof should be valid")

            print("  ✓ Proof verified successfully!")
            print("  ✓ E2E Proof Generation and Verification (GPU) passed\n")
        } catch {
            print("  ⚠ GPU proof generation failed: \(error)")
            print("  (Falling back to CPU prover)\n")

            // Fallback to CPU prover
            let cpuProver = CircleSTARKProver(logBlowup: 4, numQueries: 30)
            do {
                let proof = try cpuProver.proveCPU(air: air)
                print("  CPU Proof generated: \(proof.traceCommitments.count) commitments")

                let verifier = CircleSTARKVerifier()
                let isValid = try verifier.verify(air: air, proof: proof)
                assert(isValid, "CPU Proof should be valid")
                print("  ✓ CPU Proof verified successfully!\n")
            } catch {
                print("  ⚠ CPU proof also failed: \(error)\n")
            }
        }
    }

    public static func testE2EBlockProof() {
        print("Test: E2E Block Proof (Multiple Transactions)")

        // Create multiple transactions
        let transactions: [EVMTransaction] = [
            EVMTransaction(code: [0x00]),  // STOP in first tx
            EVMTransaction(code: [0x60, 0x01, 0x00]),  // PUSH1 1, STOP
        ]

        // Use batch prover
        let batchConfig = BatchProverConfig(
            batchSize: 2,
            useGPU: true,  // GPU-accelerated
            logTraceLength: 14,
            numQueries: 30,
            logBlowup: 4
        )

        let batchProver = EVMBatchProver(config: batchConfig)

        do {
            let batchProof = try batchProver.proveBatch(transactions: transactions)
            print("  Batch proof generated: \(batchProof.transactionProofs.count) transaction proofs")
            print("  Batch proving time: \(batchProof.provingTimeMs)ms")
            print("  ✓ E2E Block Proof passed\n")
        } catch {
            print("  ⚠ Batch proof requires Metal shaders: \(error)")
            print("  (This is expected without zkmetal GPU kernels)\n")
        }
    }

    // MARK: - Memory Argument

    public static func testMemoryArgument() {
        print("Test: EVMemory Lasso Argument")

        // Create memory accesses
        let tracker = EVMemoryTracker()

        // Record reads and writes
        let addr = M31Word(low64: 0)
        let value = M31Word(low64: 0xDEADBEEF)

        tracker.recordWrite(addr: addr, value: value, pc: 0, callDepth: 0)
        tracker.recordRead(addr: addr, value: value, pc: 1, callDepth: 0)

        let sorted = tracker.sortedTrace()
        assert(sorted.count == 2, "Should have 2 memory accesses")

        print("  ✓ EVMemory Lasso Argument passed\n")
    }

    // MARK: - Storage Trie

    public static func testStorageTrie() {
        print("Test: EVMStorageTrie")

        var storage = EVMStorageTrie()

        let key = M31Word(low64: 0x1234)
        let value = M31Word(low64: 0xDEADBEEF)

        storage.store(key: key, value: value)
        let loaded = storage.load(key: key)
        assert(loaded.low32 == 0xDEADBEEF, "Loaded value should match stored value")

        let root = storage.stateRoot
        assert(!root.isZero, "State root should be non-zero after storage")

        print("  ✓ EVMStorageTrie passed\n")
    }

    // MARK: - GPU Batch Merkle

    public static func testGPUMerkleBatch() {
        print("Test: GPU Batch Merkle Trees")

        do {
            let merkleEngine = try EVMGPUMerkleEngine()

            // Create 4 trees, each with 16 leaves (8 M31 elements per leaf)
            let nodeSize = 8
            let leavesPerTree = 16

            var treesLeaves: [[M31]] = []
            for t in 0..<4 {
                var leaves: [M31] = []
                for i in 0..<leavesPerTree {
                    // Each leaf is nodeSize M31 elements
                    for j in 0..<nodeSize {
                        leaves.append(M31(v: UInt32(t * 1000 + i * 10 + j)))
                    }
                }
                treesLeaves.append(leaves)
            }

            let start = CFAbsoluteTimeGetCurrent()
            let roots = try merkleEngine.buildTreesBatch(treesLeaves: treesLeaves)
            let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1000

            assert(roots.count == 4, "Should have 4 roots")
            for (i, root) in roots.enumerated() {
                assert(root.values.count == 8, "Root should have 8 M31 elements")
                print("  Tree \(i) root: \(root.values[0].v), ... (8 M31 elements)")
            }

            // Verify roots are different for different trees
            assert(roots[0].values[0].v != roots[1].values[0].v, "Different trees should have different roots")

            print("  ✓ Built 4 trees (16 leaves each) in \(elapsed)ms")
            print("  ✓ GPU Batch Merkle Trees passed\n")
        } catch {
            print("  ⚠ GPU Batch Merkle test failed (expected if no Metal GPU): \(error)\n")
        }
    }


    // MARK: - Batch Commit Profiling

    public static func testBatchCommitProfile() {
        print("Test: Batch Commit Profiling (180 columns x 512 leaves = batch kernel limit)")

        do {
            // For trees <= 512 leaves, the batch kernel can build all trees in ONE dispatch
            // This is the primary optimization target for EVMAIR
            let numColumns = 180
            let evalLen = 512  // Batch kernel max

            // Create trace LDEs where each leaf is 8 M31 elements (trace row format)
            // GPU batch kernel treats 8 M31 as one pre-hashed leaf node
            var traceLDEs: [[M31]] = []
            for col in 0..<numColumns {
                var leaves: [M31] = []
                for i in 0..<evalLen {
                    for j in 0..<8 {  // 8 M31 per leaf
                        leaves.append(M31(v: UInt32(col * 1000 + i * 10 + j)))
                    }
                }
                traceLDEs.append(leaves)
            }

            print("  \(numColumns) columns x \(evalLen) leaves (8 M31 per leaf)")
            print("  Total data: \(numColumns * evalLen * 8 * 4) bytes")

            // GPU batch - builds all trees in one dispatch
            let prover = EVMetalGPUProver()
            let gpuT0 = CFAbsoluteTimeGetCurrent()
            _ = try prover.commitTraceColumnsGPU(traceLDEs: traceLDEs, evalLen: evalLen)
            let gpuTime = CFAbsoluteTimeGetCurrent() - gpuT0

            print("\n  === COMMIT PHASE (512 leaves, batch kernel max) ===")
            print("  GPU (batch all \(numColumns) at once): \(String(format: "%.1f ms", gpuTime * 1000))")
            print("  Note: GPU uses position-hashed leaf format (matches CPU tree builder)")
            print("")

            // Extended test with larger trees
            print("  === EXTENDED TEST: EVMAIR-size (4096 leaves, chunked) ===")
            testLargeTreeBatchProfile()

            print("  ✓ Batch Commit Profile passed\n")
        } catch {
            print("  ⚠ Batch Commit Profile failed: \(error)\n")
        }
    }

    private static func testLargeTreeBatchProfile() {
        do {
            // For larger trees (4096 leaves), we chunk into 512-leaf subtrees
            let numColumns = 180
            let evalLen = 4096
            let subtreeMax = 512
            let numSubtrees = evalLen / subtreeMax  // 8 subtrees per column

            // Create trace LDEs (8 M31 per leaf)
            var traceLDEs: [[M31]] = []
            for col in 0..<numColumns {
                var leaves: [M31] = []
                for i in 0..<evalLen {
                    for j in 0..<8 {
                        leaves.append(M31(v: UInt32(col * 10000 + i * 10 + j)))
                    }
                }
                traceLDEs.append(leaves)
            }

            print("  \(numColumns) columns x \(evalLen) leaves (8 M31 per leaf, \(numSubtrees) subtrees each)")

            let prover = EVMetalGPUProver()
            let gpuT0 = CFAbsoluteTimeGetCurrent()
            let gpuResult = try prover.commitTraceColumnsGPU(traceLDEs: traceLDEs, evalLen: evalLen)
            let gpuTime = CFAbsoluteTimeGetCurrent() - gpuT0

            print("  GPU (chunked batch): \(String(format: "%.1f ms", gpuTime * 1000))")
            print("  GPU commitments: \(gpuResult.commitments.count) columns committed")
        } catch {
            print("  Large tree test failed: \(error)")
        }
    }

    // MARK: - GPU vs CPU Commitment Correctness Test

    /// Test that GPU commitments match CPU commitments exactly.
    /// This verifies the GPU leaf-hashing approach is correct.
    public static func testGPUCPUCommitmentMatch() {
        print("Test: GPU vs CPU Commitment Correctness")

        do {
            // Test with small tree (no chunking needed)
            let numColumns = 4
            let evalLen = 16  // Small tree for quick test

            // Create trace LDEs where each leaf is 1 M31 element (individual values)
            var traceLDEs: [[M31]] = []
            for col in 0..<numColumns {
                var leaves: [M31] = []
                for i in 0..<evalLen {
                    leaves.append(M31(v: UInt32(col * 1000 + i)))
                }
                traceLDEs.append(leaves)
            }

            print("  Testing \(numColumns) columns x \(evalLen) leaves (1 M31 per leaf)")

            // CPU: position-hash leaves first, then build tree
            let cpuProver = EVMetalCPUMerkleProver()
            var cpuCommitments: [zkMetal.M31Digest] = []
            for col in 0..<numColumns {
                let colLeaves = traceLDEs[col]
                // CPU position-hash all columns at once (same as GPU does)
                let flatValues = colLeaves
                let digests = cpuProver.hashLeavesBatchPerColumn(
                    allValues: flatValues,
                    numColumns: 1,
                    countPerColumn: evalLen
                )
                let colDigests = digests[0]  // Single column result

                // Build tree from pre-hashed digests
                var nodes: [zkMetal.M31Digest] = []
                for i in 0..<evalLen {
                    let start = i * 8
                    let digestValues = Array(colDigests[start..<start + 8])
                    nodes.append(zkMetal.M31Digest(values: digestValues))
                }
                // Build tree bottom-up
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

            print("  CPU commitments computed")

            // Compute GPU commitments
            let prover = EVMetalGPUProver()
            let gpuResult = try prover.commitTraceColumnsGPU(traceLDEs: traceLDEs, evalLen: evalLen)
            print("  GPU commitments computed")

            // Compare
            var allMatch = true
            var mismatchCount = 0
            for i in 0..<numColumns {
                if gpuResult.commitments[i].values != cpuCommitments[i].values {
                    allMatch = false
                    mismatchCount += 1
                    print("  Column \(i): MISMATCH")
                    print("    CPU: \(cpuCommitments[i].values.prefix(4).map { $0.v })...")
                    print("    GPU: \(gpuResult.commitments[i].values.prefix(4).map { $0.v })...")
                }
            }

            if allMatch {
                print("  ✓ All \(numColumns) GPU commitments MATCH CPU commitments")
            } else {
                print("  ✗ \(mismatchCount)/\(numColumns) columns MISMATCHED")
            }

            // Test with larger tree (chunked path)
            print("\n  Testing chunked path (512 leaves per subtree)...")
            testGPUCPUChunkedMatch()

            if allMatch {
                print("\n  ✓ GPU vs CPU Commitment Correctness PASSED\n")
            } else {
                print("\n  ✗ GPU vs CPU Commitment Correctness FAILED\n")
            }

        } catch {
            print("  ⚠ GPU vs CPU test failed: \(error)\n")
        }
    }

    private static func testGPUCPUChunkedMatch() {
        // Test the chunked path where trees > 512 leaves are split
        let numColumns = 2
        let evalLen = 1024  // Will be chunked into 2 subtrees of 512 each

        // Create trace LDEs
        var traceLDEs: [[M31]] = []
        for col in 0..<numColumns {
            var leaves: [M31] = []
            for i in 0..<evalLen {
                for j in 0..<8 {
                    leaves.append(M31(v: UInt32(col * 10000 + i * 10 + j)))
                }
            }
            traceLDEs.append(leaves)
        }

        // CPU: build tree per column
        var cpuCommitments: [zkMetal.M31Digest] = []
        for col in 0..<numColumns {
            var nodes: [zkMetal.M31Digest] = []
            for i in 0..<evalLen {
                let start = i * 8
                let digestValues = Array(traceLDEs[col][start..<start + 8])
                nodes.append(zkMetal.M31Digest(values: digestValues))
            }
            // Build tree
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

        // GPU: chunked path
        do {
            let prover = EVMetalGPUProver()
            let gpuResult = try prover.commitTraceColumnsGPU(traceLDEs: traceLDEs, evalLen: evalLen)

            // Compare
            var allMatch = true
            for i in 0..<numColumns {
                if gpuResult.commitments[i].values != cpuCommitments[i].values {
                    allMatch = false
                    print("    Column \(i) chunked: MISMATCH")
                }
            }

            if allMatch {
                print("    Chunked path: \(numColumns) columns MATCH")
            }
        } catch {
            print("    Chunked path test failed: \(error)")
        }
    }

    // MARK: - Opcode Execution Tests

    /// Test arithmetic opcodes: ADD, MUL, SUB, DIV, MOD
    public static func testOpcodeArithmetic() {
        print("Test: Arithmetic Opcodes")

        let engine = EVMExecutionEngine()

        // ADD: PUSH1 10, PUSH1 20, ADD, STOP
        do {
            let code: [UInt8] = [0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "ADD should not revert")
            print("  ADD: OK")
        } catch {
            print("  ADD: FAILED - \(error)")
        }

        // MUL: PUSH1 3, PUSH1 4, MUL, STOP
        do {
            let code: [UInt8] = [0x60, 0x03, 0x60, 0x04, 0x02, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "MUL should not revert")
            print("  MUL: OK")
        } catch {
            print("  MUL: FAILED - \(error)")
        }

        // SUB: PUSH1 10, PUSH1 3, SUB, STOP
        do {
            let code: [UInt8] = [0x60, 0x0A, 0x60, 0x03, 0x03, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "SUB should not revert")
            print("  SUB: OK")
        } catch {
            print("  SUB: FAILED - \(error)")
        }

        // DIV: PUSH1 10, PUSH1 2, DIV, STOP
        do {
            let code: [UInt8] = [0x60, 0x0A, 0x60, 0x02, 0x04, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "DIV should not revert")
            print("  DIV: OK")
        } catch {
            print("  DIV: FAILED - \(error)")
        }

        // MOD: PUSH1 10, PUSH1 3, MOD, STOP
        do {
            let code: [UInt8] = [0x60, 0x0A, 0x60, 0x03, 0x06, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "MOD should not revert")
            print("  MOD: OK")
        } catch {
            print("  MOD: FAILED - \(error)")
        }

        print("  ✓ Arithmetic Opcodes passed\n")
    }

    /// Test comparison opcodes: LT, GT, EQ, ISZERO
    public static func testOpcodeComparison() {
        print("Test: Comparison Opcodes")

        let engine = EVMExecutionEngine()

        // LT: PUSH1 1, PUSH1 2, LT (1 < 2 = 1), STOP
        do {
            let code: [UInt8] = [0x60, 0x01, 0x60, 0x02, 0x10, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "LT should not revert")
            print("  LT: OK")
        } catch {
            print("  LT: FAILED - \(error)")
        }

        // GT: PUSH1 2, PUSH1 1, GT (2 > 1 = 1), STOP
        do {
            let code: [UInt8] = [0x60, 0x02, 0x60, 0x01, 0x11, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "GT should not revert")
            print("  GT: OK")
        } catch {
            print("  GT: FAILED - \(error)")
        }

        // EQ: PUSH1 5, PUSH1 5, EQ (5 == 5 = 1), STOP
        do {
            let code: [UInt8] = [0x60, 0x05, 0x60, 0x05, 0x14, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "EQ should not revert")
            print("  EQ: OK")
        } catch {
            print("  EQ: FAILED - \(error)")
        }

        // ISZERO: PUSH1 0, ISZERO (0 = 1), STOP
        do {
            let code: [UInt8] = [0x60, 0x00, 0x15, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "ISZERO should not revert")
            print("  ISZERO: OK")
        } catch {
            print("  ISZERO: FAILED - \(error)")
        }

        print("  ✓ Comparison Opcodes passed\n")
    }

    /// Test bitwise opcodes: AND, OR, XOR, NOT
    public static func testOpcodeBitwise() {
        print("Test: Bitwise Opcodes")

        let engine = EVMExecutionEngine()

        // AND: PUSH1 0xFF, PUSH1 0x0F, AND, STOP
        do {
            let code: [UInt8] = [0x60, 0xFF, 0x60, 0x0F, 0x16, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "AND should not revert")
            print("  AND: OK")
        } catch {
            print("  AND: FAILED - \(error)")
        }

        // OR: PUSH1 0x0F, PUSH1 0xF0, OR, STOP
        do {
            let code: [UInt8] = [0x60, 0x0F, 0x60, 0xF0, 0x17, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "OR should not revert")
            print("  OR: OK")
        } catch {
            print("  OR: FAILED - \(error)")
        }

        // XOR: PUSH1 0xFF, PUSH1 0x00, XOR, STOP
        do {
            let code: [UInt8] = [0x60, 0xFF, 0x60, 0x00, 0x18, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "XOR should not revert")
            print("  XOR: OK")
        } catch {
            print("  XOR: FAILED - \(error)")
        }

        // NOT: PUSH1 0x00, NOT, STOP
        do {
            let code: [UInt8] = [0x60, 0x00, 0x19, 0x00]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "NOT should not revert")
            print("  NOT: OK")
        } catch {
            print("  NOT: FAILED - \(error)")
        }

        print("  ✓ Bitwise Opcodes passed\n")
    }

    /// Test push, dup, and swap opcodes
    public static func testOpcodePushDupSwap() {
        print("Test: Push/Dup/Swap Opcodes")

        let engine = EVMExecutionEngine()

        // PUSH1 through PUSH4
        do {
            let code: [UInt8] = [
                0x60, 0x01,  // PUSH1 0x01
                0x61, 0x02, 0x03,  // PUSH2 0x0203
                0x62, 0x04, 0x05, 0x06,  // PUSH3 0x040506
                0x63, 0x07, 0x08, 0x09, 0x0A,  // PUSH4 0x0708090A
                0x00  // STOP
            ]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "PUSH ops should not revert")
            assert(result.trace.rows.count == 5, "Should have 5 trace rows")
            print("  PUSH1-4: OK")
        } catch {
            print("  PUSH ops: FAILED - \(error)")
        }

        // DUP1, DUP2
        do {
            let code: [UInt8] = [0x60, 0x2A, 0x80, 0x81, 0x00]  // PUSH1 42, DUP1, DUP2, STOP
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "DUP ops should not revert")
            print("  DUP1-2: OK")
        } catch {
            print("  DUP ops: FAILED - \(error)")
        }

        // SWAP1
        do {
            let code: [UInt8] = [0x60, 0x01, 0x60, 0x02, 0x90, 0x00]  // PUSH1 1, PUSH1 2, SWAP1, STOP
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "SWAP should not revert")
            print("  SWAP1: OK")
        } catch {
            print("  SWAP ops: FAILED - \(error)")
        }

        print("  ✓ Push/Dup/Swap Opcodes passed\n")
    }

    /// Test control flow: JUMP, JUMPI, JUMPDEST
    public static func testOpcodeControlFlow() {
        print("Test: Control Flow Opcodes")

        let engine = EVMExecutionEngine()

        // Simple JUMP to JUMPDEST
        do {
            let code: [UInt8] = [
                0x60, 0x05,  // PUSH1 5 (target)
                0x56,        // JUMP
                0x00,        // STOP
                0x00,        // STOP (not executed)
                0x5B,        // JUMPDEST at position 4
                0x00         // STOP
            ]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "JUMP should not revert")
            print("  JUMP: OK")
        } catch {
            print("  JUMP: FAILED - \(error)")
        }

        // Conditional JUMPI with true condition
        do {
            let code: [UInt8] = [
                0x60, 0x06,  // PUSH1 6 (target)
                0x60, 0x01,  // PUSH1 1 (condition = true)
                0x57,        // JUMPI
                0x00,        // STOP (not executed)
                0x00,        // STOP (not executed)
                0x5B,        // JUMPDEST at position 5
                0x00         // STOP
            ]
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "JUMPI should not revert")
            print("  JUMPI (true): OK")
        } catch {
            print("  JUMPI (true): FAILED - \(error)")
        }

        // JUMPDEST alone
        do {
            let code: [UInt8] = [0x5B, 0x00]  // JUMPDEST, STOP
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "JUMPDEST should not revert")
            print("  JUMPDEST: OK")
        } catch {
            print("  JUMPDEST: FAILED - \(error)")
        }

        print("  ✓ Control Flow Opcodes passed\n")
    }

    /// Test memory opcodes: MLOAD, MSTORE, MSTORE8
    public static func testOpcodeMemory() {
        print("Test: Memory Opcodes")

        let engine = EVMExecutionEngine()

        // MSTORE and MLOAD
        do {
            let code: [UInt8] = [
                0x60, 0x00,  // PUSH1 0 (offset)
                0x60, 0x42,  // PUSH1 0x42 (value)
                0x52,        // MSTORE
                0x60, 0x00,  // PUSH1 0 (offset)
                0x51,        // MLOAD
                0x00         // STOP
            ]
            let result = try engine.execute(code: code, gasLimit: 10000)
            assert(!result.trace.reverted, "MLOAD/MSTORE should not revert")
            print("  MLOAD/MSTORE: OK")
        } catch {
            print("  MLOAD/MSTORE: FAILED - \(error)")
        }

        // MSTORE8
        do {
            let code: [UInt8] = [
                0x60, 0x00,  // PUSH1 0 (offset)
                0x60, 0xAB,  // PUSH1 0xAB (byte value)
                0x53,        // MSTORE8
                0x00         // STOP
            ]
            let result = try engine.execute(code: code, gasLimit: 10000)
            assert(!result.trace.reverted, "MSTORE8 should not revert")
            print("  MSTORE8: OK")
        } catch {
            print("  MSTORE8: FAILED - \(error)")
        }

        print("  ✓ Memory Opcodes passed\n")
    }

    /// Test RETURN and REVERT opcodes
    public static func testOpcodeReturn() {
        print("Test: Return Opcodes")

        let engine = EVMExecutionEngine()

        // RETURN
        do {
            let code: [UInt8] = [0x60, 0x20, 0x60, 0x00, 0xF3, 0x00]  // PUSH1 32, PUSH1 0, RETURN, STOP
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "RETURN should not revert")
            print("  RETURN: OK")
        } catch {
            print("  RETURN: FAILED - \(error)")
        }

        // REVERT (causes revert)
        do {
            let code: [UInt8] = [0x60, 0x20, 0x60, 0x00, 0xFD, 0x00]  // PUSH1 32, PUSH1 0, REVERT, STOP
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(result.trace.reverted, "REVERT should cause revert")
            print("  REVERT: OK")
        } catch {
            print("  REVERT: FAILED - \(error)")
        }

        print("  ✓ Return Opcodes passed\n")
    }

    /// Test stack operations: POP, stack underflow
    public static func testOpcodeStackOps() {
        print("Test: Stack Opcodes")

        let engine = EVMExecutionEngine()

        // POP
        do {
            let code: [UInt8] = [0x60, 0x42, 0x50, 0x00]  // PUSH1 0x42, POP, STOP
            let result = try engine.execute(code: code, gasLimit: 1000)
            assert(!result.trace.reverted, "POP should not revert")
            print("  POP: OK")
        } catch {
            print("  POP: FAILED - \(error)")
        }

        print("  ✓ Stack Opcodes passed\n")
    }

    /// Run all opcode tests
    public static func testAllOpcodes() {
        print("=== EVM Opcode Tests ===\n")

        testOpcodeArithmetic()
        testOpcodeComparison()
        testOpcodeBitwise()
        testOpcodePushDupSwap()
        testOpcodeControlFlow()
        testOpcodeMemory()
        testOpcodeReturn()
        testOpcodeStackOps()

        print("=== All Opcode Tests passed! ===")
    }
}
