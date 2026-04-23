import Foundation
import Metal
import zkMetal
import Zoltraak

/// Benchmark comparing GPU pipeline approaches.
public struct GPUPipelineBenchmark {

    public struct BenchmarkResult {
        public let approach: String
        public let copyMs: Double
        public let nttMs: Double
        public let hashMs: Double
        public let treeMs: Double
        public let totalMs: Double
    }

    /// Run comparison between old and new GPU pipeline.
    public static func runComparison(
        numColumns: Int = 180,
        traceLen: Int = 512,  // Use 512 to match GPU Merkle limit
        logBlowup: Int = 4
    ) {
        let evalLen = traceLen << logBlowup

        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║       GPU Pipeline Comparison Benchmark                       ║
            ║       Columns: \(numColumns), Trace: \(traceLen), Eval: \(evalLen)                      ║
            ╚══════════════════════════════════════════════════════════════════╝
            """)

        // Create synthetic trace
        print("Generating synthetic trace...")
        var trace: [[M31]] = []
        for _ in 0..<numColumns {
            var col: [M31] = []
            for i in 0..<traceLen {
                col.append(M31(v: UInt32(i)))
            }
            trace.append(col)
        }

        // Benchmark 1: Old approach (CPU hashing)
        print("\n--- Old Approach (CPU hashing) ---")
        let oldResult = benchmarkOldApproach(
            trace: trace,
            traceLen: traceLen,
            numColumns: numColumns,
            logBlowup: logBlowup
        )

        // Benchmark 2: New approach (GPU-only hashing)
        print("\n--- New Approach (GPU-only hashing) ---")
        let newResult = benchmarkGPUOnlyApproach(
            trace: trace,
            traceLen: traceLen,
            numColumns: numColumns,
            logBlowup: logBlowup
        )

        // Summary
        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║                      RESULTS                                   ║
            ╚══════════════════════════════════════════════════════════════════╝
            """)

        print("""
            Old Approach (CPU hashing + GPU tree):
              Copy:  \(String(format: "%8.1fms", oldResult.copyMs))
              NTT:   \(String(format: "%8.1fms", oldResult.nttMs))
              Hash:  \(String(format: "%8.1fms", oldResult.hashMs))  <-- CPU bottleneck
              Tree:  \(String(format: "%8.1fms", oldResult.treeMs))
              ──────────────────────────
              Total: \(String(format: "%8.1fms", oldResult.totalMs))

            New Approach (GPU-only hashing):
              Copy:  \(String(format: "%8.1fms", newResult.copyMs))
              NTT:   \(String(format: "%8.1fms", newResult.nttMs))
              Hash:  \(String(format: "%8.1fms", newResult.hashMs))  <-- GPU accelerated!
              Tree:  \(String(format: "%8.1fms", newResult.treeMs))
              ──────────────────────────
              Total: \(String(format: "%8.1fms", newResult.totalMs))

            Speedup: \(String(format: "%.2fx", oldResult.totalMs / newResult.totalMs))
            Hash phase speedup: \(String(format: "%.2fx", oldResult.hashMs / max(newResult.hashMs, 0.001)))
            """)

        // Breakdown
        let newTotal = newResult.totalMs
        print("""
            New Approach Breakdown:
              Copy:  \(String(format: "%6.1f%%", newResult.copyMs / newTotal * 100))
              NTT:   \(String(format: "%6.1f%%", newResult.nttMs / newTotal * 100))
              Hash:  \(String(format: "%6.1f%%", newResult.hashMs / newTotal * 100))
              Tree:  \(String(format: "%6.1f%%", newResult.treeMs / newTotal * 100))
            """)
    }

    // MARK: - Old Approach (CPU hashing)

    private static func benchmarkOldApproach(
        trace: [[M31]],
        traceLen: Int,
        numColumns: Int,
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

            // Copy to GPU
            let copyT0 = CFAbsoluteTimeGetCurrent()
            var gpuBuffers: [MTLBuffer] = []
            for col in trace {
                guard let buf = dev.makeBuffer(length: evalLen * sz, options: .storageModeShared) else {
                    continue
                }
                let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
                for i in 0..<min(col.count, traceLen) {
                    ptr[i] = col[i].v
                }
                for i in traceLen..<evalLen { ptr[i] = 0 }
                gpuBuffers.append(buf)
            }
            let copyMs = (CFAbsoluteTimeGetCurrent() - copyT0) * 1000

            // NTT
            let nttT0 = CFAbsoluteTimeGetCurrent()
            guard let cbIntt = queue.makeCommandBuffer() else { return emptyResult() }
            for buf in gpuBuffers { ntt.encodeINTT(data: buf, logN: logTrace, cmdBuf: cbIntt) }
            cbIntt.commit(); cbIntt.waitUntilCompleted()

            guard let cbNtt = queue.makeCommandBuffer() else { return emptyResult() }
            for buf in gpuBuffers { ntt.encodeNTT(data: buf, logN: logEval, cmdBuf: cbNtt) }
            cbNtt.commit(); cbNtt.waitUntilCompleted()
            let nttMs = (CFAbsoluteTimeGetCurrent() - nttT0) * 1000

            // CPU hashing (bottleneck!)
            let hashT0 = CFAbsoluteTimeGetCurrent()
            var allValues: [M31] = []
            for buf in gpuBuffers {
                let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
                for i in 0..<evalLen {
                    allValues.append(M31(v: ptr[i]))
                }
            }

            let cpuProver = ZoltraakCPUMerkleProver()
            let hashedLeaves = cpuProver.hashLeavesBatchPerColumn(
                allValues: allValues,
                numColumns: numColumns,
                countPerColumn: evalLen
            )
            let hashMs = (CFAbsoluteTimeGetCurrent() - hashT0) * 1000

            // GPU tree
            let treeT0 = CFAbsoluteTimeGetCurrent()
            let engine = try EVMGPUMerkleEngine()
            let commitments = try engine.buildTreesBatch(treesLeaves: hashedLeaves)
            let treeMs = (CFAbsoluteTimeGetCurrent() - treeT0) * 1000

            let totalMs = copyMs + nttMs + hashMs + treeMs

            print("  Old approach completed: \(commitments.count) commitments")

            return BenchmarkResult(
                approach: "CPU Hashing",
                copyMs: copyMs,
                nttMs: nttMs,
                hashMs: hashMs,
                treeMs: treeMs,
                totalMs: totalMs
            )
        } catch {
            print("  Old approach failed: \(error)")
            return emptyResult()
        }
    }

    // MARK: - New Approach (GPU-only hashing)

    private static func benchmarkGPUOnlyApproach(
        trace: [[M31]],
        traceLen: Int,
        numColumns: Int,
        logBlowup: Int
    ) -> BenchmarkResult {
        let logTrace = Int(log2(Double(traceLen)))
        let logEval = logTrace + logBlowup
        let evalLen = 1 << logEval

        do {
            let pipeline = try EVMGPUOnlyCommitmentPipeline()

            let t0 = CFAbsoluteTimeGetCurrent()
            let (timings, commitments) = try pipeline.execute(
                trace: trace,
                traceLen: traceLen,
                numColumns: numColumns,
                logTrace: logTrace,
                logEval: logEval
            )
            let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            print("  GPU-only approach completed: \(commitments.count) commitments")

            return BenchmarkResult(
                approach: "GPU-Only",
                copyMs: timings.traceGenMs,
                nttMs: timings.nttMs,
                hashMs: timings.leafHashMs,
                treeMs: timings.treeBuildMs,
                totalMs: totalMs
            )
        } catch {
            print("  New approach failed: \(error)")
            return emptyResult()
        }
    }

    private static func emptyResult() -> BenchmarkResult {
        return BenchmarkResult(
            approach: "Failed",
            copyMs: 0,
            nttMs: 0,
            hashMs: 0,
            treeMs: 0,
            totalMs: 0
        )
    }
}
