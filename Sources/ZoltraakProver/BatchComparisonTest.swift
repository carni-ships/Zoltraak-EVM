import Foundation
import zkMetal
import Zoltraak

/// Test to measure batch vs sequential GPU tree building
public struct BatchVsSequentialTest {

    public static func runBatchComparison() {
        print("\n=== Batch vs Sequential GPU Tree Building ===\n")

        do {
            let numColumns = 180
            let evalLen = 512

            print("Configuration: \(numColumns) columns × \(evalLen) leaves")

            // Generate and hash leaves once
            let leafHashEngine = try ZoltraakLeafHashEngine()
            var traceLDEs: [[M31]] = []
            for col in 0..<numColumns {
                var leaves: [M31] = []
                for i in 0..<evalLen {
                    leaves.append(M31(v: UInt32(col * 10000 + i)))
                }
                traceLDEs.append(leaves)
            }

            var flatValues: [M31] = []
            for col in traceLDEs {
                flatValues.append(contentsOf: col)
            }

            let allDigests = try leafHashEngine.hashLeavesBatchPerColumn(
                allValues: flatValues,
                numColumns: numColumns,
                countPerColumn: evalLen
            )

            let gpuTreeEngine = try Poseidon2M31Engine()

            // Sequential approach (current Phase 1)
            print("\n--- Sequential GPU (one tree at a time) ---")
            let seqStart = CFAbsoluteTimeGetCurrent()
            var seqRoots: [zkMetal.M31Digest] = []
            for colDigests in allDigests {
                let rootM31 = try gpuTreeEngine.merkleCommit(leaves: colDigests)
                seqRoots.append(zkMetal.M31Digest(values: rootM31))
            }
            let seqMs = (CFAbsoluteTimeGetCurrent() - seqStart) * 1000
            print("Sequential: \(String(format: "%.1f", seqMs))ms")

            // Warmup
            _ = try gpuTreeEngine.merkleCommit(leaves: allDigests[0])

            // Batch approach (Phase 2)
            print("\n--- Batch GPU (all trees in parallel) ---")
            let batchStart = CFAbsoluteTimeGetCurrent()
            let batchRoots = try buildBatchParallel(allColumnDigests: allDigests, numLeaves: evalLen)
            let batchMs = (CFAbsoluteTimeGetCurrent() - batchStart) * 1000
            print("Batch: \(String(format: "%.1f", batchMs))ms")

            // Verify correctness
            var allMatch = true
            for i in 0..<numColumns {
                if seqRoots[i].values != batchRoots[i].values {
                    allMatch = false
                    print("Column \(i): MISMATCH!")
                }
            }

            print("\n--- Results ---")
            print("Speedup: \(String(format: "%.2fx", seqMs / batchMs))")
            print("Time saved: \(String(format: "%.1f", seqMs - batchMs))ms")
            print("Correctness: \(allMatch ? "✓ All MATCH" : "✗ Some MISMATCH")")

        } catch {
            print("Error: \(error)")
        }
    }

    private static func buildBatchParallel(allColumnDigests: [[M31]], numLeaves: Int) throws -> [zkMetal.M31Digest] {
        let numTrees = allColumnDigests.count
        let nodeSize = 8
        let gpuTreeEngine = try Poseidon2M31Engine()
        let device = gpuTreeEngine.device

        let stride = MemoryLayout<UInt32>.stride
        let totalInputVals = numTrees * numLeaves * nodeSize

        guard let inputBuf = device.makeBuffer(length: totalInputVals * stride, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate input buffer")
        }

        let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: totalInputVals)
        var inputIdx = 0
        for treeDigests in allColumnDigests {
            for val in treeDigests {
                inputPtr[inputIdx] = val.v
                inputIdx += 1
            }
        }

        let rootBytes = numTrees * nodeSize * stride
        guard let outputBuf = device.makeBuffer(length: rootBytes, options: .storageModeShared) else {
            throw GPUProverError.gpuError("Failed to allocate output buffer")
        }

        guard let cmdBuf = gpuTreeEngine.commandQueue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        let enc = cmdBuf.makeComputeCommandEncoder()!

        gpuTreeEngine.encodeMerkleFused(
            encoder: enc,
            leavesBuffer: inputBuf,
            leavesOffset: 0,
            rootsBuffer: outputBuf,
            rootsOffset: 0,
            numSubtrees: numTrees,
            subtreeSize: numLeaves
        )

        enc.endEncoding()
        cmdBuf.commit()
        cmdBuf.waitUntilCompleted()

        if let error = cmdBuf.error {
            throw GPUProverError.gpuError(error.localizedDescription)
        }

        let outPtr = outputBuf.contents().bindMemory(to: UInt32.self, capacity: numTrees * nodeSize)
        var roots: [zkMetal.M31Digest] = []
        roots.reserveCapacity(numTrees)

        for i in 0..<numTrees {
            var rootValues = [M31]()
            rootValues.reserveCapacity(nodeSize)
            for j in 0..<nodeSize {
                rootValues.append(M31(v: outPtr[i * nodeSize + j]))
            }
            roots.append(zkMetal.M31Digest(values: rootValues))
        }

        return roots
    }
}
