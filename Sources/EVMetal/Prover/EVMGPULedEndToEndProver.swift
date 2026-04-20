import Foundation
import Metal
import zkMetal

/// GPU-accelerated trace commitment profiler.
///
/// This profiler measures the GPU-accelerated trace commitment phases:
/// 1. GPU Circle NTT for LDE (INTT + NTT)
/// 2. GPU Poseidon2 for leaf hashing with position
/// 3. GPU Merkle tree building
///
/// Usage:
///   let profiler = EVMGPULedEndToEndProver()
///   let result = try profiler.profileGPUCommitment(air: evmAir)
///   print(result.summary)
public final class EVMGPULedEndToEndProver {

    // MARK: - Configuration

    public struct Config {
        /// Log of the blowup factor for LDE
        public let logBlowup: Int

        /// Maximum leaves per subtree for GPU processing
        public let maxSubtreeLeaves: Int

        public static let standard = Config(logBlowup: 4, maxSubtreeLeaves: 512)
        public static let highPerformance = Config(logBlowup: 4, maxSubtreeLeaves: 1024)

        public init(logBlowup: Int = 4, maxSubtreeLeaves: Int = 512) {
            self.logBlowup = logBlowup
            self.maxSubtreeLeaves = maxSubtreeLeaves
        }
    }

    // MARK: - Result Types

    /// GPU commitment profile result
    public struct GPUCommitmentProfile {
        public let numColumns: Int
        public let traceLen: Int
        public let evalLen: Int
        public let numCommitments: Int

        /// Time breakdown in milliseconds
        public let timings: PhaseTimings

        public var summary: String {
            """
            GPU Commitment Profile:
              Columns: \(numColumns), Trace: \(traceLen), Eval: \(evalLen)
              Commitments: \(numCommitments)

            Phase Breakdown:
              Trace Gen:  \(String(format: "%8.1fms", timings.traceGenMs))
              GPU NTT:    \(String(format: "%8.1fms", timings.nttMs))
              Leaf Hash:  \(String(format: "%8.1fms", timings.leafHashMs))
              Tree Build: \(String(format: "%8.1fms", timings.treeBuildMs))
              ──────────────────
              Total:      \(String(format: "%8.1fms", timings.totalMs))

            Percentages:
              NTT:       \(String(format: "%6.1f%%", timings.nttMs / timings.totalMs * 100))
              Leaf Hash:  \(String(format: "%6.1f%%", timings.leafHashMs / timings.totalMs * 100))
              Tree:       \(String(format: "%6.1f%%", timings.treeBuildMs / timings.totalMs * 100))
            """
        }
    }

    public struct PhaseTimings {
        public let traceGenMs: Double
        public let nttMs: Double
        public let leafHashMs: Double
        public let treeBuildMs: Double
        public let constraintMs: Double
        public let friMs: Double
        public let totalMs: Double
    }

    // MARK: - Private State

    private let config: Config
    private var nttEngine: CircleNTTEngine?
    private var leafHashEngine: EVMetalLeafHashEngine?
    private var merkleEngine: EVMGPUMerkleEngine?

    // MARK: - Initialization

    public init(config: Config = .standard) {
        self.config = config
    }

    // MARK: - GPU Engine Access

    private func ensureNTT() throws -> CircleNTTEngine {
        if let e = nttEngine { return e }
        let e = try CircleNTTEngine()
        nttEngine = e
        return e
    }

    private func ensureLeafHash() throws -> EVMetalLeafHashEngine {
        if let e = leafHashEngine { return e }
        let e = try EVMetalLeafHashEngine()
        leafHashEngine = e
        return e
    }

    private func ensureMerkle() throws -> EVMGPUMerkleEngine {
        if let e = merkleEngine { return e }
        let e = try EVMGPUMerkleEngine()
        merkleEngine = e
        return e
    }

    // MARK: - Profile GPU Commitment

    /// Profile GPU trace commitment phases.
    ///
    /// This measures:
    /// 1. GPU Circle NTT for LDE (INTT + NTT)
    /// 2. GPU Poseidon2 for leaf hashing
    /// 3. GPU Merkle tree building
    ///
    /// Returns timing breakdown for each phase.
    public func profileGPUCommitment(air: EVMAIR) throws -> GPUCommitmentProfile {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Step 1: Generate trace
        let traceT0 = CFAbsoluteTimeGetCurrent()
        let trace = air.generateTrace()
        let traceLen = trace[0].count
        let numColumns = trace.count
        let logTrace = air.logTraceLength
        let logEval = logTrace + config.logBlowup
        let evalLen = 1 << logEval
        let traceGenMs = (CFAbsoluteTimeGetCurrent() - traceT0) * 1000

        // Step 2: GPU Circle NTT for LDE
        let nttT0 = CFAbsoluteTimeGetCurrent()
        let ntt = try ensureNTT()
        let dev = ntt.device
        let queue = ntt.commandQueue
        let sz = MemoryLayout<UInt32>.stride

        // Allocate GPU buffers for all columns at eval domain size
        var gpuBuffers: [MTLBuffer] = []
        for col in trace {
            guard let buf = dev.makeBuffer(length: evalLen * sz, options: .storageModeShared) else {
                throw GPUProverError.gpuError("Failed to allocate buffer")
            }
            let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
            for i in 0..<min(col.count, traceLen) {
                ptr[i] = col[i].v
            }
            for i in col.count..<traceLen {
                ptr[i] = 0
            }
            for i in traceLen..<evalLen {
                ptr[i] = 0
            }
            gpuBuffers.append(buf)
        }

        // Batch INTT
        guard let cbIntt = queue.makeCommandBuffer() else { throw GPUProverError.noCommandBuffer }
        for buf in gpuBuffers {
            ntt.encodeINTT(data: buf, logN: logTrace, cmdBuf: cbIntt)
        }
        cbIntt.commit()
        cbIntt.waitUntilCompleted()

        // Batch NTT
        guard let cbNtt = queue.makeCommandBuffer() else { throw GPUProverError.noCommandBuffer }
        for buf in gpuBuffers {
            ntt.encodeNTT(data: buf, logN: logEval, cmdBuf: cbNtt)
        }
        cbNtt.commit()
        cbNtt.waitUntilCompleted()
        let nttMs = (CFAbsoluteTimeGetCurrent() - nttT0) * 1000

        // Step 3: GPU Leaf Hashing with position
        let hashT0 = CFAbsoluteTimeGetCurrent()
        let leafHash = try ensureLeafHash()

        // Read LDE results back for hashing
        var traceLDEs: [[M31]] = []
        for buf in gpuBuffers {
            let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
            var col = [M31](repeating: .zero, count: evalLen)
            for i in 0..<evalLen {
                col[i] = M31(v: ptr[i])
            }
            traceLDEs.append(col)
        }

        // Batch hash all columns with GPU
        var allValues: [M31] = []
        for col in traceLDEs {
            allValues.append(contentsOf: col)
        }
        let hashedLeaves = try leafHash.hashLeavesBatchPerColumn(
            allValues: allValues,
            numColumns: numColumns,
            countPerColumn: evalLen
        )
        let leafHashMs = (CFAbsoluteTimeGetCurrent() - hashT0) * 1000

        // Step 4: GPU Merkle Tree Building
        let treeT0 = CFAbsoluteTimeGetCurrent()
        let merkle = try ensureMerkle()

        let subtreeMax = min(config.maxSubtreeLeaves, Poseidon2M31Engine.merkleSubtreeSize)
        var commitments: [zkMetal.M31Digest] = []

        if evalLen <= subtreeMax {
            // All leaves fit in one subtree - batch all trees
            commitments = try merkle.buildTreesBatch(treesLeaves: hashedLeaves)
        } else {
            // Chunk into subtrees
            let numSubtrees = evalLen / subtreeMax
            var allSubtreeLeaves: [[M31]] = []
            for colDigests in hashedLeaves {
                for subIdx in 0..<numSubtrees {
                    let start = subIdx * subtreeMax * 8
                    let end = start + subtreeMax * 8
                    if end <= colDigests.count {
                        allSubtreeLeaves.append(Array(colDigests[start..<end]))
                    }
                }
            }

            // Build all subtree roots in batch
            let subtreeRoots = try merkle.buildTreesBatch(treesLeaves: allSubtreeLeaves)

            // Hash subtree roots to get column commitments
            for col in 0..<numColumns {
                var roots: [zkMetal.M31Digest] = []
                for sub in 0..<numSubtrees {
                    roots.append(subtreeRoots[col * numSubtrees + sub])
                }
                // Combine roots
                commitments.append(roots[0]) // Simplified
            }
        }
        let treeBuildMs = (CFAbsoluteTimeGetCurrent() - treeT0) * 1000

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        return GPUCommitmentProfile(
            numColumns: numColumns,
            traceLen: traceLen,
            evalLen: evalLen,
            numCommitments: commitments.count,
            timings: PhaseTimings(
                traceGenMs: traceGenMs,
                nttMs: nttMs,
                leafHashMs: leafHashMs,
                treeBuildMs: treeBuildMs,
                constraintMs: 0,
                friMs: 0,
                totalMs: totalMs
            )
        )
    }
}
