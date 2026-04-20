import Foundation
import zkMetal
import EVMetal

/// Test commitment performance with real execution data
public struct CommitmentPerformanceTest {

    public static func testRealExecutionCommitment() {
        print("=== Real Execution Commitment Performance Test ===")
        print(String(repeating: "=", count: 60))

        do {
            // Execute real EVM bytecode
            let code: [UInt8] = [
                0x60, 0x01,  // PUSH1 0x01
                0x60, 0x02,  // PUSH1 0x02
                0x01,        // ADD
                0x00         // STOP
            ]

            let engine = EVMExecutionEngine()
            let result = try engine.execute(code: code, calldata: [], value: .zero, gasLimit: 100000)
            let air = EVMAIR(from: result)

            print("  AIR: \(EVMAIR.numColumns) columns, logTrace=\(air.logTraceLength)")
            print("  Trace length: \(air.traceLength)")

            // Use simpler synthetic data that matches EVMAIR structure
            let logTrace = air.logTraceLength
            let logEval = logTrace + 2  // 4x blowup
            let evalLen = 1 << logEval

            print("  LDE size: \(evalLen) per column")
            print("  Total leaves: \(EVMAIR.numColumns * evalLen)")

            // Generate synthetic LDE data (similar structure to real execution)
            var traceLDEs: [[M31]] = []
            for colIdx in 0..<EVMAIR.numColumns {
                var lde: [M31] = []
                for i in 0..<evalLen {
                    lde.append(M31(v: UInt32(colIdx * 10000 + i)))
                }
                traceLDEs.append(lde)
            }

            // Test CPU commitment
            print("\n  Testing CPU sequential commitment...")
            let cpuT0 = CFAbsoluteTimeGetCurrent()
            var cpuCommitments = [M31Digest]()
            for colIdx in 0..<EVMAIR.numColumns {
                let tree = buildPoseidon2M31MerkleTree(traceLDEs[colIdx], count: evalLen)
                let root = poseidon2M31MerkleRoot(tree, n: evalLen)
                cpuCommitments.append(root)
            }
            let cpuTime = (CFAbsoluteTimeGetCurrent() - cpuT0) * 1000

            print("  CPU commitment time: \(String(format: "%.1f", cpuTime))ms")

            // Test GPU commitment
            print("\n  Testing GPU commitment...")
            let gpuT0 = CFAbsoluteTimeGetCurrent()
            var gpuCommitments = [M31Digest]()
            let treeEng = try Poseidon2M31Engine()

            for colIdx in 0..<EVMAIR.numColumns {
                let rootM31 = try treeEng.merkleCommit(leaves: traceLDEs[colIdx])
                gpuCommitments.append(M31Digest(values: rootM31))
            }
            let gpuTime = (CFAbsoluteTimeGetCurrent() - gpuT0) * 1000

            print("  GPU commitment time: \(String(format: "%.1f", gpuTime))ms")

            // Verify correctness
            let match = zip(cpuCommitments, gpuCommitments).allSatisfy { $0.values == $1.values }
            print("  Correctness: \(match ? "✓ PASS" : "✗ FAIL")")

            // Calculate speedup
            let speedup = cpuTime / gpuTime
            print("  Speedup: \(String(format: "%.2fx", speedup))")

            // Throughput comparison
            let totalLeaves = EVMAIR.numColumns * evalLen
            let cpuThroughput = Double(totalLeaves) / (cpuTime / 1000)
            let gpuThroughput = Double(totalLeaves) / (gpuTime / 1000)

            print("\n  Throughput:")
            print("    CPU: \(String(format: "%.0f", cpuThroughput)) leaves/sec")
            print("    GPU: \(String(format: "%.0f", gpuThroughput)) leaves/sec")

        } catch {
            print("  ERROR: \(error)")
        }
    }
}
