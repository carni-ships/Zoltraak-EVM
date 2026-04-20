import Foundation
import zkMetal
import EVMetal

// MARK: - Brakedown Commitment Benchmark

/// Benchmark suite for EVMetal Brakedown commitment.
///
/// This tests the Brakedown polynomial commitment scheme as an alternative
/// to the traditional Merkle tree commitment for EVM trace columns.
///
/// Run with: `swift run EVMetalTestRunner --brakedown-benchmark`
public struct BrakedownBenchmark {

    // MARK: - Run All

    /// Run all Brakedown benchmarks.
    public static func runAll() {
        print("""
        ═══════════════════════════════════════════════════════════
        ║        EVMetal Brakedown Commitment Benchmark           ║
        ═══════════════════════════════════════════════════════════
        """)

        benchmarkBasicCommit()
        benchmarkEVMScale()
        benchmarkVersusMerkle()
        benchmarkProofGeneration()

        print("""
        ═══════════════════════════════════════════════════════════
        ║               Brakedown Benchmarks Complete              ║
        ═══════════════════════════════════════════════════════════
        """)
    }

    // MARK: - Basic Commit Benchmark

    /// Benchmark basic Brakedown commitment at various scales.
    public static func benchmarkBasicCommit() {
        print("\n[1] Basic Brakedown Commitment")
        print(String(repeating: "─", count: 60))

        let configs: [(columns: Int, evalLen: Int)] = [
            (1, 256),
            (8, 256),
            (16, 256),
            (32, 512),
            (64, 512),
        ]

        for config in configs {
            do {
                let engine = try EVMetalBrakedownEngine(config: .fast)

                // Generate trace data
                var traceLDEs: [[M31]] = []
                for col in 0..<config.columns {
                    var values: [M31] = []
                    for i in 0..<config.evalLen {
                        values.append(M31(v: UInt32((col * 1000 + i) & 0x7FFFFFFF)))
                    }
                    traceLDEs.append(values)
                }

                // Benchmark
                let result = try engine.commit(traceLDEs: traceLDEs, evalLen: config.evalLen)

                print("  \(config.columns) columns x \(config.evalLen) values:")
                print("    Total time: \(String(format: "%.2f", result.timeMs)) ms")
                print("    Conversion: \(String(format: "%.2f", result.conversionMs)) ms")
                print("    Commit:     \(String(format: "%.2f", result.commitMs)) ms")
                print("    Throughput: \(String(format: "%.0f", Double(config.columns * config.evalLen) / result.timeMs * 1000)) vals/sec")

            } catch {
                print("  Error: \(error)")
            }
        }
    }

    // MARK: - EVM Scale Benchmark

    /// Benchmark at EVM production scale (180 columns, large eval len).
    public static func benchmarkEVMScale() {
        print("\n[2] EVM Production Scale (180 columns)")
        print(String(repeating: "─", count: 60))

        let configs: [(columns: Int, evalLen: Int, name: String)] = [
            (180, 2048, "small"),
            (180, 4096, "medium"),
            (180, 8192, "large"),
            (180, 16384, "xlarge"),
        ]

        for config in configs {
            do {
                let engine = try EVMetalBrakedownEngine(config: .standard)

                // Generate trace data
                var traceLDEs: [[M31]] = []
                for col in 0..<config.columns {
                    var values: [M31] = []
                    for i in 0..<config.evalLen {
                        values.append(M31(v: UInt32((col * 1000 + i) & 0x7FFFFFFF)))
                    }
                    traceLDEs.append(values)
                }

                // Benchmark
                let t0 = CFAbsoluteTimeGetCurrent()
                let result = try engine.commit(traceLDEs: traceLDEs, evalLen: config.evalLen)
                let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

                print("  \(config.name) (180 columns x \(config.evalLen) values):")
                print("    Total time: \(String(format: "%.2f", totalMs)) ms")
                print("    Conversion: \(String(format: "%.2f", result.conversionMs)) ms")
                print("    Commit:     \(String(format: "%.2f", result.commitMs)) ms")
                print("    Proof size: \(result.commitments.first?.commitmentSize ?? 0) bytes/column")

            } catch {
                print("  Error: \(error)")
            }
        }
    }

    // MARK: - Versus Merkle

    /// Compare Brakedown vs Merkle commitment performance.
    public static func benchmarkVersusMerkle() {
        print("\n[3] Brakedown vs Merkle Comparison")
        print(String(repeating: "─", count: 60))

        do {
            let engine = try EVMetalBrakedownEngine(config: .standard)
            let numColumns = 180
            let evalLen = 4096

            // Generate trace data
            var traceLDEs: [[M31]] = []
            for col in 0..<numColumns {
                var values: [M31] = []
                for i in 0..<evalLen {
                    values.append(M31(v: UInt32((col * 1000 + i) & 0x7FFFFFFF)))
                }
                traceLDEs.append(values)
            }

            // Brakedown timing
            let brakedownT0 = CFAbsoluteTimeGetCurrent()
            let brakedownResult = try engine.commit(traceLDEs: traceLDEs, evalLen: evalLen)
            let brakedownMs = (CFAbsoluteTimeGetCurrent() - brakedownT0) * 1000

            // Merkle timing (CPU baseline)
            let merkleT0 = CFAbsoluteTimeGetCurrent()
            var merkleRoots: [zkMetal.M31Digest] = []
            for col in traceLDEs {
                let tree = buildPoseidon2M31MerkleTree(col, count: evalLen)
                merkleRoots.append(poseidon2M31MerkleRoot(tree, n: evalLen))
            }
            let merkleMs = (CFAbsoluteTimeGetCurrent() - merkleT0) * 1000

            print("  \(numColumns) columns x \(evalLen) values:")
            print("    Brakedown: \(String(format: "%.2f", brakedownMs)) ms")
            print("      - Conversion: \(String(format: "%.2f", brakedownResult.conversionMs)) ms")
            print("      - Commit:     \(String(format: "%.2f", brakedownResult.commitMs)) ms")
            print("    Merkle:    \(String(format: "%.2f", merkleMs)) ms")
            print("    Proof size (Brakedown): \(brakedownResult.commitments.first?.commitmentSize ?? 0) bytes/column")
            print("    Proof size (Merkle):     32 bytes/column")
            print("    Speedup vs Merkle: \(String(format: "%.2fx", merkleMs / brakedownMs))")

        } catch {
            print("  Error: \(error)")
        }
    }

    // MARK: - Proof Generation

    /// Benchmark opening proof generation.
    public static func benchmarkProofGeneration() {
        print("\n[4] Proof Generation")
        print(String(repeating: "─", count: 60))

        do {
            let engine = try EVMetalBrakedownEngine(config: .standard)
            let numColumns = 16
            let evalLen = 256
            let logEval = Int(log2(Double(evalLen)))

            // Generate trace data
            var traceLDEs: [[M31]] = []
            for col in 0..<numColumns {
                var values: [M31] = []
                for i in 0..<evalLen {
                    values.append(M31(v: UInt32((col * 1000 + i) & 0x7FFFFFFF)))
                }
                traceLDEs.append(values)
            }

            // Commit
            let commitResult = try engine.commit(traceLDEs: traceLDEs, evalLen: evalLen)

            // Generate random point
            let point = engine.randomPoint(logEval: logEval)

            // Open
            let openT0 = CFAbsoluteTimeGetCurrent()
            let openResult = try engine.open(commitResult: commitResult, point: point)
            let openMs = (CFAbsoluteTimeGetCurrent() - openT0) * 1000

            // Verify
            let verifyT0 = CFAbsoluteTimeGetCurrent()
            let valid = engine.verify(commitResult: commitResult, openResult: openResult)
            let verifyMs = (CFAbsoluteTimeGetCurrent() - verifyT0) * 1000

            print("  \(numColumns) columns x \(evalLen) values:")
            print("    Commit: \(String(format: "%.2f", commitResult.timeMs)) ms")
            print("    Open:   \(String(format: "%.2f", openMs)) ms")
            print("    Verify: \(String(format: "%.2f", verifyMs)) ms (result: \(valid))")
            print("    Proof size: \(openResult.proofSizeBytes) bytes")

        } catch {
            print("  Error: \(error)")
        }
    }
}
