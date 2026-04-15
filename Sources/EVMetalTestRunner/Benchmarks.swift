import Foundation
import zkMetal
import EVMetal

// MARK: - Benchmarks

/// Comprehensive benchmarking suite for EVMetal prover components.
///
/// This suite measures performance of various prover operations including:
/// - GPU batch Merkle tree building at different scales
/// - EVMAIR trace commitment performance
/// - Hybrid commitment (CPU hash + GPU tree)
/// - End-to-end proof generation
/// - Batch transaction proving
///
/// Run with: `swift run EVMetalTestRunner --benchmark`
public struct Benchmarks {

    // MARK: - Running Benchmarks

    /// Runs all benchmark suites in sequence.
    ///
    /// Includes:
    /// - Batch Merkle tree benchmarks at multiple scales
    /// - EVMAIR commit benchmark
    /// - Hybrid commit benchmark
    /// - End-to-end proof benchmark
    /// - Batch transaction benchmark
    public static func runAll() {
        print("""
        ═══════════════════════════════════════════════════════════
        ║           EVMetal Prover Benchmark Suite                 ║
        ═══════════════════════════════════════════════════════════
        """)

        benchmarkBatchMerkleTrees()
        benchmarkEVMAIRCommit()
        benchmarkHybridCommit()
        benchmarkEndToEnd()
        benchmarkBatchTransactions()

        print("""
        ═══════════════════════════════════════════════════════════
        ║                    Benchmarks Complete                    ║
        ═══════════════════════════════════════════════════════════
        """)
    }

    // MARK: - Batch Merkle Trees

    /// Benchmarks GPU batch Merkle tree building at various scales.
    ///
    /// Tests configurations ranging from 16 columns to 180 columns, with varying
    /// leaf counts. Also tests large trees that require chunking into 512-leaf subtrees.
    ///
    /// Timing is compared against estimated sequential CPU time to show speedup.
    public static func benchmarkBatchMerkleTrees() {
        print("\n[1] GPU Batch Merkle Tree Benchmark")
        print(String(repeating: "─", count: 60))

        let configs: [(columns: Int, leaves: Int)] = [
            (16, 256),
            (64, 256),
            (180, 256),
            (180, 512),    // batch kernel limit
        ]

        for config in configs {
            do {
                let engine = try EVMGPUMerkleEngine()
                let nodeSize = 8

                // Create trace data
                var treesLeaves: [[M31]] = []
                for col in 0..<config.columns {
                    var leaves: [M31] = []
                    for i in 0..<config.leaves {
                        for j in 0..<nodeSize {
                            leaves.append(M31(v: UInt32(col * 1000 + i * 10 + j)))
                        }
                    }
                    treesLeaves.append(leaves)
                }

                // Benchmark GPU batch
                let gpuT0 = CFAbsoluteTimeGetCurrent()
                let gpuRoots = try engine.buildTreesBatch(treesLeaves: treesLeaves)
                let gpuMs = (CFAbsoluteTimeGetCurrent() - gpuT0) * 1000

                // CPU baseline (single tree as reference)
                let cpuT0 = CFAbsoluteTimeGetCurrent()
                var cpuRoot = zkMetal.M31Digest.zero
                for col in 0..<1 {  // Just one column for CPU reference
                    let tree = buildPoseidon2M31MerkleTree(treesLeaves[col], count: config.leaves)
                    cpuRoot = poseidon2M31MerkleRoot(tree, n: config.leaves)
                }
                let cpuMs = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000

                // Estimate sequential CPU time for all columns
                let estimatedCpuMs = cpuMs * Double(config.columns)

                print("  \(config.columns) cols × \(config.leaves) leaves: GPU \(String(format: "%.1f", gpuMs))ms | Est. CPU \(String(format: "%.0f", estimatedCpuMs))ms | Speedup \(String(format: "%.0fx", estimatedCpuMs / gpuMs))")

                _ = gpuRoots  // suppress unused
            } catch {
                print("  \(config.columns)×\(config.leaves): ERROR - \(error)")
            }
        }

        // Test larger trees with chunking
        print("\n  [Large trees with chunking]")
        let largeConfigs: [(columns: Int, leaves: Int)] = [
            (64, 1024),
            (180, 1024),
            (180, 2048),
        ]

        for config in largeConfigs {
            do {
                let engine = try EVMGPUMerkleEngine()
                let nodeSize = 8
                let subtreeMax = 512

                // Create trace data
                var treesLeaves: [[M31]] = []
                for col in 0..<config.columns {
                    var leaves: [M31] = []
                    for i in 0..<config.leaves {
                        for j in 0..<nodeSize {
                            leaves.append(M31(v: UInt32(col * 1000 + i * 10 + j)))
                        }
                    }
                    treesLeaves.append(leaves)
                }

                // Chunk into subtrees
                let numSubtrees = config.leaves / subtreeMax
                var allSubtreeLeaves: [[M31]] = []
                for col in treesLeaves {
                    for subIdx in 0..<numSubtrees {
                        let start = subIdx * subtreeMax
                        allSubtreeLeaves.append(Array(col[start..<start + subtreeMax]))
                    }
                }

                // Benchmark GPU batch with chunking
                let gpuT0 = CFAbsoluteTimeGetCurrent()
                let subtreeRoots = try engine.buildTreesBatch(treesLeaves: allSubtreeLeaves)

                // Hash subtree roots to final commitments
                var commitments: [zkMetal.M31Digest] = []
                var idx = 0
                for _ in 0..<config.columns {
                    var roots: [zkMetal.M31Digest] = []
                    for _ in 0..<numSubtrees {
                        roots.append(subtreeRoots[idx])
                        idx += 1
                    }
                    // Hash into commitment
                    while roots.count > 1 {
                        var next: [zkMetal.M31Digest] = []
                        for i in stride(from: 0, to: roots.count, by: 2) {
                            if i + 1 < roots.count {
                                next.append(zkMetal.M31Digest(values: poseidon2M31Hash(
                                    left: roots[i].values, right: roots[i+1].values)))
                            } else {
                                next.append(roots[i])
                            }
                        }
                        roots = next
                    }
                    commitments.append(roots[0])
                }
                let gpuMs = (CFAbsoluteTimeGetCurrent() - gpuT0) * 1000

                print("  \(config.columns) cols × \(config.leaves) leaves (\(numSubtrees) subtrees): GPU \(String(format: "%.1f", gpuMs))ms")

                _ = commitments
            } catch {
                print("  \(config.columns)×\(config.leaves): ERROR - \(error)")
            }
        }
    }

    // MARK: - EVMAIR Commit

    /// Benchmarks EVMAIR trace commitment using EVMetalGPUProver.
    ///
    /// Tests at full EVMAIR scale: 180 columns × 4096 leaves.
    /// Reports CPU (sequential) vs GPU (batch Merkle) timing and speedup.
    public static func benchmarkEVMAIRCommit() {
        print("\n[2] EVMAIR Commit Benchmark")
        print(String(repeating: "─", count: 60))

        do {
            let prover = try EVMetalGPUProver()

            // Profile at EVMAIR scale
            let (cpuMs, gpuMs, speedup) = try prover.profileCommitSpeedup(
                numColumns: 180,
                evalLen: 4096
            )

            print("  EVMAIR-scale: 180 columns × 4096 leaves")
            print("  CPU (sequential): \(String(format: "%.0f", cpuMs))ms")
            print("  GPU (batch Merkle): \(String(format: "%.1f", gpuMs))ms")
            print("  Speedup: \(String(format: "%.0fx", speedup))")

        } catch {
            print("  ERROR: \(error)")
        }
    }

    // MARK: - Hybrid Commit Benchmark

    /// Benchmarks hybrid approach: CPU position hashing + GPU tree building.
    ///
    /// Tests at three scales:
    /// - Small: 4 columns × 16 leaves
    /// - Medium: 32 columns × 512 leaves
    /// - Full EVMAIR: 180 columns × 512 leaves
    ///
    /// Reports timing breakdown between leaf hashing (CPU) and tree building (GPU).
    public static func benchmarkHybridCommit() {
        print("\n[2b] Hybrid Commit Benchmark (CPU hash + GPU tree)")
        print(String(repeating: "─", count: 60))

        do {
            let prover = try EVMetalGPUProver()

            // Small test first to verify correctness
            print("  Testing correctness with small scale (4 columns × 16 leaves)...")
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

            // Medium test
            print("\n  Testing medium scale (32 columns × 512 leaves)...")
            var mediumTrace: [[M31]] = []
            for col in 0..<32 {
                var values: [M31] = []
                for i in 0..<512 {
                    values.append(M31(v: UInt32(col * 1000 + i)))
                }
                mediumTrace.append(values)
            }

            let mediumResult = try prover.commitTraceColumnsHybrid(traceLDEs: mediumTrace, evalLen: 512)
            print("  Medium scale: \(String(format: "%.1f", mediumResult.timeMs))ms total")
            print("    - Leaf hashing: \(String(format: "%.1f", mediumResult.leafHashMs))ms")
            print("    - Tree building: \(String(format: "%.1f", mediumResult.treeBuildMs))ms")

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

        } catch {
            print("  ERROR: \(error)")
        }
    }

    // MARK: - End-to-End

    /// Full end-to-end proof generation benchmark.
    ///
    /// Executes simple EVM bytecode (PUSH1, PUSH1, ADD, STOP), generates
    /// the AIR, runs the CircleSTARK prover, and verifies the proof.
    ///
    /// Reports timing for each phase:
    /// - Trace generation
    /// - LDE (low-degree extension)
    /// - Commitment (Merkle tree building)
    /// - Constraint checking
    /// - FRI (Fast Reed-Solomon IOP)
    /// - Query phase
    public static func benchmarkEndToEnd() {
        print("\n[3] End-to-End Proof Benchmark")
        print(String(repeating: "─", count: 60))

        let code: [UInt8] = [
            0x60, 0x01,
            0x60, 0x02,
            0x01,
            0x00
        ]

        let config = GPUCircleSTARKProverConfig(
            logBlowup: 2,
            numQueries: 20,
            extensionDegree: 4,
            gpuConstraintThreshold: 64,
            gpuFRIFoldThreshold: 64,
            usePoseidon2Merkle: true,
            numQuotientSplits: 2
        )

        let prover = GPUCircleSTARKProverEngine(config: config)

        do {
            let engine = EVMExecutionEngine()
            let result = try engine.execute(code: code, calldata: [], value: .zero, gasLimit: 100000)
            let air = EVMAIR(from: result)

            print("  AIR: \(EVMAIR.numColumns) columns, logTrace=\(air.logTraceLength)")
            print("  Running prover...")

            let t0 = CFAbsoluteTimeGetCurrent()
            let proofResult = try prover.prove(air: air)
            let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            print("""
              Total: \(String(format: "%.0f", totalMs))ms
                - Trace gen:  \(String(format: "%.1f", proofResult.traceGenTimeSeconds * 1000))ms
                - LDE:        \(String(format: "%.1f", proofResult.ldeTimeSeconds * 1000))ms
                - Commit:     \(String(format: "%.0f", proofResult.commitTimeSeconds * 1000))ms  <-- bottleneck
                - Constraints:\(String(format: "%.1f", proofResult.constraintTimeSeconds * 1000))ms
                - FRI:        \(String(format: "%.1f", proofResult.friTimeSeconds * 1000))ms
                - Query:      \(String(format: "%.1f", proofResult.queryTimeSeconds * 1000))ms
            """)

            // Verify
            let isValid = prover.verify(air: air, proof: proofResult.proof)
            print("  Verification: \(isValid ? "✓ PASS" : "✗ FAIL")")

        } catch {
            print("  ERROR: \(error)")
        }
    }

    // MARK: - Batch Transactions

    /// Benchmarks batch transaction proving.
    ///
    /// Tests proving multiple EVM transactions in a single batch proof.
    /// Uses 3 sample transactions with varying complexity.
    ///
    /// Reports per-transaction timing and total proof size.
    public static func benchmarkBatchTransactions() {
        print("\n[4] Batch Transaction Benchmark")
        print(String(repeating: "─", count: 60))

        let transactions: [EVMTransaction] = [
            EVMTransaction(code: [0x00]),  // STOP
            EVMTransaction(code: [0x60, 0x01, 0x00]),
            EVMTransaction(code: [0x60, 0x01, 0x60, 0x02, 0x01, 0x00]),
        ]

        let batchConfig = BatchProverConfig(
            batchSize: transactions.count,
            useGPU: true,
            logTraceLength: 16,
            numQueries: 30,
            logBlowup: 4
        )

        let batchProver = EVMBatchProver(config: batchConfig)

        do {
            let t0 = CFAbsoluteTimeGetCurrent()
            let batchProof = try batchProver.proveBatch(transactions: transactions)
            let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            print("  \(transactions.count) transactions")
            print("  Total time: \(String(format: "%.0f", totalMs))ms")
            print("  Per transaction: \(String(format: "%.0f", totalMs / Double(transactions.count)))ms")
            print("  Proof size: \(batchProof.transactionProofs.count) proofs")

        } catch {
            print("  ERROR: \(error)")
        }
    }
}
