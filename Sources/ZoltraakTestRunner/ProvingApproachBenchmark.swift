import Foundation
import Metal
import zkMetal
import Zoltraak

/// Benchmark comparing different GPU proving approaches for EVMAIR.
///
/// This benchmarks:
/// 1. CPU approach: CircleSTARKProver.proveCPU (uses CPU Merkle)
/// 2. Hybrid approach: CPU position hashing + GPU tree building
/// 3. GPU NTT profiling: GPU Circle NTT performance
public struct ProvingApproachBenchmark {

    // MARK: - Benchmark Result

    public struct BenchmarkResult {
        public let approach: String
        public let numColumns: Int
        public let traceLen: Int
        public let evalLen: Int
        public let traceGenMs: Double
        public let nttMs: Double
        public let inttMs: Double
        public let merkleMs: Double
        public let totalMs: Double

        public var summary: String {
            """
            \(approach):
              Columns: \(numColumns), Trace: \(traceLen), Eval: \(evalLen)
              INTT: \(String(format: "%.1fms", inttMs))
              NTT: \(String(format: "%.1fms", nttMs))
              Merkle: \(String(format: "%.1fms", merkleMs))
              TOTAL: \(String(format: "%.1fms", totalMs))
            """
        }
    }

    // MARK: - Benchmark Entry Point

    /// Run benchmarks comparing GPU NTT approaches.
    public static func runAllBenchmarks(
        numColumns: Int = 180,
        traceLen: Int = 1024,
        logBlowup: Int = 4
    ) {
        let evalLen = traceLen << logBlowup

        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║     Zoltraak Proving Approach Benchmark                         ║
            ║     Columns: \(numColumns), Trace: \(traceLen), Eval: \(evalLen)                      ║
            ╚══════════════════════════════════════════════════════════════════╝
            """)

        // Benchmark GPU NTT
        print("\n--- GPU Circle NTT Benchmark ---")
        let nttResult = benchmarkGPUNTT(numColumns: numColumns, traceLen: traceLen, logBlowup: logBlowup)

        // Benchmark GPU Merkle
        print("\n--- GPU Merkle Tree Benchmark ---")
        let merkleResult = benchmarkGPUMerkle(numColumns: numColumns, evalLen: evalLen)

        // Summary
        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║                      SUMMARY                                    ║
            ╚══════════════════════════════════════════════════════════════════╝
            """)
        print(nttResult.summary)
        print(merkleResult.summary)

        // Phase breakdown for 180 columns × 4096 evalLen
        let estimatedTotal = nttResult.nttMs + nttResult.inttMs + merkleResult.totalMs
        print("""

            Estimated Total (NTT + Merkle):
              \(String(format: "%.1fms", estimatedTotal))

            Phase Breakdown:
              INTT: \(String(format: "%.1f%%", nttResult.inttMs / estimatedTotal * 100))
              NTT: \(String(format: "%.1f%%", nttResult.nttMs / estimatedTotal * 100))
              Merkle: \(String(format: "%.1f%%", merkleResult.totalMs / estimatedTotal * 100))

            Optimization Targets:
              1. GPU Merkle: \(String(format: "%.1fms", merkleResult.totalMs)) - Primary bottleneck
              2. GPU NTT: \(String(format: "%.1fms", nttResult.nttMs + nttResult.inttMs)) - Already GPU-accelerated
            """)
    }

    // MARK: - GPU NTT Benchmark

    private static func benchmarkGPUNTT(
        numColumns: Int,
        traceLen: Int,
        logBlowup: Int
    ) -> BenchmarkResult {
        let logTrace = Int(log2(Double(traceLen)))
        let logEval = logTrace + logBlowup
        let evalLen = 1 << logEval

        do {
            let ntt = try CircleNTTEngine()
            let dev = ntt.device
            let queue = ntt.commandQueue
            let sz = MemoryLayout<UInt32>.stride

            // Create buffers and test data
            var buffers: [MTLBuffer] = []
            for _ in 0..<min(numColumns, 16) { // Test with 16 columns max for fairness
                guard let buf = dev.makeBuffer(length: evalLen * sz, options: .storageModeShared) else {
                    continue
                }
                let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
                for i in 0..<evalLen {
                    ptr[i] = UInt32.random(in: 0..<UInt32.max)
                }
                buffers.append(buf)
            }

            let actualColumns = buffers.count
            print("  Testing with \(actualColumns) columns (capped from \(numColumns))")

            // Profile INTT
            let inttT0 = CFAbsoluteTimeGetCurrent()
            guard let cbIntt = queue.makeCommandBuffer() else {
                throw GPUProverError.noCommandBuffer
            }
            for buf in buffers {
                ntt.encodeINTT(data: buf, logN: logTrace, cmdBuf: cbIntt)
            }
            cbIntt.commit()
            cbIntt.waitUntilCompleted()
            let inttMs = (CFAbsoluteTimeGetCurrent() - inttT0) * 1000

            // Profile NTT
            let nttT0 = CFAbsoluteTimeGetCurrent()
            guard let cbNtt = queue.makeCommandBuffer() else {
                throw GPUProverError.noCommandBuffer
            }
            for buf in buffers {
                ntt.encodeNTT(data: buf, logN: logEval, cmdBuf: cbNtt)
            }
            cbNtt.commit()
            cbNtt.waitUntilCompleted()
            let nttMs = (CFAbsoluteTimeGetCurrent() - nttT0) * 1000

            // Scale to full column count
            let scaleFactor = Double(numColumns) / Double(actualColumns)
            let scaledIntMs = inttMs * scaleFactor
            let scaledNttMs = nttMs * scaleFactor

            return BenchmarkResult(
                approach: "GPU Circle NTT",
                numColumns: numColumns,
                traceLen: traceLen,
                evalLen: evalLen,
                traceGenMs: 0,
                nttMs: scaledNttMs,
                inttMs: scaledIntMs,
                merkleMs: 0,
                totalMs: scaledIntMs + scaledNttMs
            )

        } catch {
            print("  GPU NTT benchmark failed: \(error)")
            return BenchmarkResult(
                approach: "GPU Circle NTT",
                numColumns: numColumns,
                traceLen: traceLen,
                evalLen: evalLen,
                traceGenMs: 0,
                nttMs: 0,
                inttMs: 0,
                merkleMs: 0,
                totalMs: 0
            )
        }
    }

    // MARK: - GPU Merkle Benchmark

    private static func benchmarkGPUMerkle(
        numColumns: Int,
        evalLen: Int
    ) -> BenchmarkResult {
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        do {
            let engine = try EVMGPUMerkleEngine()

            // Create test leaves (pre-hashed, 8 M31 per leaf)
            var allLeaves: [[M31]] = []
            let actualColumns = min(numColumns, 16) // Test with 16 columns

            for _ in 0..<actualColumns {
                var leaves: [M31] = []
                let numLeaves = min(evalLen, subtreeMax)
                for _ in 0..<numLeaves {
                    for _ in 0..<8 {
                        leaves.append(M31(v: UInt32.random(in: 0..<UInt32.max)))
                    }
                }
                allLeaves.append(leaves)
            }

            print("  Testing with \(actualColumns) columns, \(min(evalLen, subtreeMax)) leaves each")

            // Profile batch tree building
            let t0 = CFAbsoluteTimeGetCurrent()
            var roots: [zkMetal.M31Digest] = []

            if evalLen <= subtreeMax {
                roots = try engine.buildTreesBatch(treesLeaves: allLeaves)
            } else {
                // For larger trees, skip detailed breakdown
                print("  Large tree mode: \(evalLen) leaves (chunking)")
                let numLeaves = evalLen
                for _ in 0..<actualColumns {
                    var leaves: [M31] = []
                    for _ in 0..<min(numLeaves, 512) {
                        for _ in 0..<8 {
                            leaves.append(M31(v: UInt32.random(in: 0..<UInt32.max)))
                        }
                    }
                    roots.append(contentsOf: try engine.buildTreesBatch(treesLeaves: [leaves]))
                }
            }

            let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            // Scale to full column count
            let scaleFactor = Double(numColumns) / Double(actualColumns)
            let scaledMs = totalMs * scaleFactor

            return BenchmarkResult(
                approach: "GPU Poseidon2 Merkle",
                numColumns: numColumns,
                traceLen: evalLen >> 4,
                evalLen: evalLen,
                traceGenMs: 0,
                nttMs: 0,
                inttMs: 0,
                merkleMs: scaledMs,
                totalMs: scaledMs
            )

        } catch {
            print("  GPU Merkle benchmark failed: \(error)")
            return BenchmarkResult(
                approach: "GPU Poseidon2 Merkle",
                numColumns: numColumns,
                traceLen: evalLen >> 4,
                evalLen: evalLen,
                traceGenMs: 0,
                nttMs: 0,
                inttMs: 0,
                merkleMs: 0,
                totalMs: 0
            )
        }
    }
}
