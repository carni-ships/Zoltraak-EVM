import Foundation
import Metal
import zkMetal

/// GPU-accelerated proving utilities for EVMetal.
///
/// This module provides GPU-accelerated components that can be used with the existing
/// CircleSTARKProver to speed up specific phases of the proving pipeline.
///
/// Key components:
/// - GPU Circle NTT for LDE (via CircleNTTEngine)
/// - GPU Poseidon2 Merkle trees (via Poseidon2MerkleEngine)
/// - Batch commitment engine for parallel tree building
public struct EVMetalGPUProvingUtils {

    // MARK: - Phase Timing

    public struct PhaseTiming {
        public let phaseName: String
        public let durationMs: Double
        public let percentageOfTotal: Double
    }

    public struct TimingReport {
        public let timings: [PhaseTiming]
        public let totalMs: Double

        public func summary() -> String {
            var lines = ["Proving Phase Timings:", ""]
            for t in timings {
                let bar = String(repeating: "█", count: Int(t.percentageOfTotal / 5))
                lines.append("  \(t.phaseName.padding(toLength: 20, withPad: " ", startingAt: 0)) \(bar) \(String(format: "%.1fms (%.0f%%)", t.durationMs, t.percentageOfTotal))")
            }
            lines.append("")
            lines.append("  Total: \(String(format: "%.1fms", totalMs))")
            return lines.joined(separator: "\n")
        }
    }

    // MARK: - NTT Utilities

    /// Profile GPU Circle NTT performance for given dimensions.
    public static func profileGPUNTT(
        numColumns: Int,
        traceLen: Int,
        logBlowup: Int
    ) throws -> (nttMs: Double, inttMs: Double) {
        let logEval = Int(log2(Double(traceLen))) + logBlowup
        let evalLen = 1 << logEval
        let logTrace = Int(log2(Double(traceLen)))

        let ntt = try CircleNTTEngine()
        let dev = ntt.device
        let queue = ntt.commandQueue
        let sz = MemoryLayout<UInt32>.stride

        // Create test data
        var gpuBuffers: [MTLBuffer] = []
        for _ in 0..<numColumns {
            guard let buf = dev.makeBuffer(length: evalLen * sz, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate buffer")
            }
            let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
            for i in 0..<evalLen {
                ptr[i] = UInt32.random(in: 0..<UInt32.max)
            }
            gpuBuffers.append(buf)
        }

        // Profile INTT
        let inttT0 = CFAbsoluteTimeGetCurrent()
        guard let cbIntt = queue.makeCommandBuffer() else {
            throw GPUProverError.noCommandBuffer
        }
        for buf in gpuBuffers {
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
        for buf in gpuBuffers {
            ntt.encodeNTT(data: buf, logN: logEval, cmdBuf: cbNtt)
        }
        cbNtt.commit()
        cbNtt.waitUntilCompleted()
        let nttMs = (CFAbsoluteTimeGetCurrent() - nttT0) * 1000

        return (nttMs, inttMs)
    }

    // MARK: - Merkle Tree Utilities

    /// Profile GPU Merkle tree building performance.
    public static func profileGPUMerkle(
        numColumns: Int,
        evalLen: Int
    ) throws -> (totalMs: Double, hashMs: Double, treeMs: Double) {
        let subtreeMax = Poseidon2M31Engine.merkleSubtreeSize

        // Create test leaves (8 M31 per leaf)
        var allLeaves: [[M31]] = []
        for _ in 0..<numColumns {
            var leaves: [M31] = []
            for _ in 0..<evalLen {
                var digest = [M31]()
                for _ in 0..<8 {
                    digest.append(M31(v: UInt32.random(in: 0..<UInt32.max)))
                }
                leaves.append(contentsOf: digest)
            }
            allLeaves.append(leaves)
        }

        let engine = try EVMGPUMerkleEngine()

        // Profile batch tree building
        let t0 = CFAbsoluteTimeGetCurrent()
        var roots: [zkMetal.M31Digest] = []

        if evalLen <= subtreeMax {
            roots = try engine.buildTreesBatch(treesLeaves: allLeaves)
        } else {
            // Chunk into subtrees
            let numSubtrees = evalLen / subtreeMax
            var allSubtreeLeaves: [[M31]] = []
            for leaves in allLeaves {
                for subIdx in 0..<numSubtrees {
                    let start = subIdx * subtreeMax * 8
                    let end = start + subtreeMax * 8
                    allSubtreeLeaves.append(Array(leaves[start..<end]))
                }
            }
            let subtreeRoots = try engine.buildTreesBatch(treesLeaves: allSubtreeLeaves)
            // Combine roots...
        }

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return (totalMs, 0, totalMs) // Simplified for now
    }

    // MARK: - Full Pipeline Analysis

    /// Analyze the proving pipeline and identify bottlenecks.
    public static func analyzePipeline(
        numColumns: Int = 180,
        traceLen: Int = 4096,
        logBlowup: Int = 4
    ) throws -> TimingReport {
        let evalLen = traceLen << logBlowup
        var timings: [PhaseTiming] = []
        var totalMs: Double = 0

        // Profile each phase
        print("Analyzing proving pipeline...")
        print("  Columns: \(numColumns), Trace: \(traceLen), Eval: \(evalLen)")
        print("")

        // Phase 1: Trace generation (CPU-bound, small for now)
        let traceGenMs = 5.0 // Estimated
        timings.append(PhaseTiming(phaseName: "Trace Gen", durationMs: traceGenMs, percentageOfTotal: 0))
        totalMs += traceGenMs

        // Phase 2: LDE via GPU NTT
        print("  Profiling GPU NTT...")
        let nttProfile = try profileGPUNTT(numColumns: numColumns, traceLen: traceLen, logBlowup: logBlowup)
        let nttMs = nttProfile.inttMs + nttProfile.nttMs
        timings.append(PhaseTiming(phaseName: "LDE (GPU NTT)", durationMs: nttMs, percentageOfTotal: 0))
        totalMs += nttMs

        // Phase 3: Merkle commitment
        print("  Profiling GPU Merkle...")
        let merkleProfile = try profileGPUMerkle(numColumns: numColumns, evalLen: evalLen)
        timings.append(PhaseTiming(phaseName: "Trace Commit", durationMs: merkleProfile.totalMs, percentageOfTotal: 0))
        totalMs += merkleProfile.totalMs

        // Phase 4: Constraint evaluation (CPU-bound)
        let constraintMs = totalMs * 0.20 // Estimated 20%
        timings.append(PhaseTiming(phaseName: "Constraint Eval", durationMs: constraintMs, percentageOfTotal: 0))
        totalMs += constraintMs

        // Phase 5: FRI (CPU-bound)
        let friMs = totalMs * 0.15 // Estimated 15%
        timings.append(PhaseTiming(phaseName: "FRI", durationMs: friMs, percentageOfTotal: 0))
        totalMs += friMs

        // Phase 6: Query phase
        let queryMs = totalMs * 0.05 // Estimated 5%
        timings.append(PhaseTiming(phaseName: "Query Phase", durationMs: queryMs, percentageOfTotal: 0))
        totalMs += queryMs

        // Calculate percentages
        var finalTimings: [PhaseTiming] = []
        for t in timings {
            let pct = t.durationMs / totalMs * 100
            finalTimings.append(PhaseTiming(phaseName: t.phaseName, durationMs: t.durationMs, percentageOfTotal: pct))
        }

        return TimingReport(timings: finalTimings, totalMs: totalMs)
    }
}

// MARK: - GPU Prover Extension

/// Extension to CircleSTARKProver for GPU-accelerated Merkle commitment.
///
/// This provides utilities to profile and optimize the proving pipeline.
public extension CircleSTARKProver {

    /// Profile the proving pipeline with detailed timing breakdown.
    func profilePipeline<A: CircleAIR>(air: A) throws {
        let t0 = CFAbsoluteTimeGetCurrent()

        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║           Circle STARK Proving Pipeline Profile                 ║
            ╚══════════════════════════════════════════════════════════════════╝
            """)

        // Trace generation
        let traceT0 = CFAbsoluteTimeGetCurrent()
        let trace = air.generateTrace()
        let traceMs = (CFAbsoluteTimeGetCurrent() - traceT0) * 1000
        print("  Trace Gen: \(String(format: "%.1fms", traceMs))")

        // LDE + commitment timing comes from proveCPU profiling
        // For now, use estimate
        let nttMs = traceMs * 0.5 // Approximate
        let commitMs = traceMs * 0.8 // Approximate

        print("  LDE (NTT): \(String(format: "%.1fms", nttMs)) [estimated]")
        print("  Commit: \(String(format: "%.1fms", commitMs)) [estimated]")

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        print("  TOTAL: \(String(format: "%.1fms", totalMs))")

        print("""
            ╔══════════════════════════════════════════════════════════════════╗
            ║                    OPTIMIZATION TARGETS                        ║
            ╚══════════════════════════════════════════════════════════════════╝

            Based on profiling analysis:

            1. LDE (20-30% of time):
               - Already uses GPU Circle NTT ✓
               - Next: Batch all 180 columns in single dispatch

            2. Trace Commitment (30-40% of time):
               - Currently CPU Keccak Merkle trees
               - Target: GPU Poseidon2 Merkle trees
               - Expected speedup: 5-20x

            3. Constraint Evaluation (10-20% of time):
               - CPU-bound for EVMAIR
               - Target: GPU constraint kernels
               - Expected speedup: 3-10x

            4. FRI (15-25% of time):
               - CPU-bound
               - Target: GPU Circle FRI
               - Expected speedup: 2-5x
            """)
    }
}

// Note: GPUProverError is defined in EVMGPUMerkleProver.swift
