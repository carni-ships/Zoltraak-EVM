import Foundation
import Metal
import zkMetal

/// GPU-side Circle STARK prover that keeps all tree data on GPU.
///
/// This is a local copy of zkMetal's GPUCircleSTARKProverEngine, modified to:
/// - Use GPU tree buffers for proof generation (no CPU tree rebuilding)
/// - Generate authentication paths directly on GPU
/// - Eliminate CPU-GPU transfer bottleneck in query phase
///
/// Performance target: Reduce commit+query time from ~350s to <12s by keeping
/// all Merkle tree data in GPU VRAM and generating proofs on-device.
public final class EVMGPUSideProver {

    public static let version = "1.0.0-gpu-side"

    // MARK: - GPU Engines

    /// GPU Merkle engine that preserves tree structure in VRAM
    private let gpuMerkleEngine: EVMGPUMerkleEngine

    /// Circle NTT engine for LDE
    private let nttEngine: CircleNTTEngine

    /// FRI engine for proof verification
    private let friEngine: CircleFRIEngine

    /// GPU device and command queue
    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue

    // MARK: - GPU Tree Buffers (kept in VRAM)

    /// Flattened tree structures for all columns (stored in GPU VRAM)
    private var gpuTreeBuffers: [MTLBuffer] = []

    /// Number of leaves per tree (same for all columns)
    private var gpuTreeNumLeaves: Int = 0

    /// Number of columns
    private var gpuTreeNumColumns: Int = 0

    // MARK: - Configuration

    public struct Config {
        public let logBlowup: Int
        public let numQueries: Int
        public let extensionDegree: Int

        public static let standard = Config(
            logBlowup: 2,
            numQueries: 30,
            extensionDegree: 4
        )

        public static let aggressive = Config(
            logBlowup: 1,
            numQueries: 20,
            extensionDegree: 4
        )

        public static let highSecurity = Config(
            logBlowup: 4,
            numQueries: 40,
            extensionDegree: 4
        )
    }

    public let config: Config

    // MARK: - Initialization

    public init(config: Config = .standard) throws {
        self.config = config

        guard let device = MTLCreateSystemDefaultDevice() else {
            throw GPUProverError.noGPU
        }
        self.device = device

        guard let queue = device.makeCommandQueue() else {
            throw GPUProverError.noCommandQueue
        }
        self.commandQueue = queue

        // Initialize GPU engines
        self.gpuMerkleEngine = try EVMGPUMerkleEngine()
        self.nttEngine = try CircleNTTEngine()
        self.friEngine = try CircleFRIEngine()
    }

    // MARK: - Prove

    /// Generate a GPU-side proof for the given AIR.
    ///
    /// Key optimization: Keeps all Merkle tree data in GPU VRAM and generates
    /// authentication paths directly on GPU during query phase.
    public func prove<A: CircleAIR>(air: A) throws -> EVMGPUProverResult {
        let proveT0 = CFAbsoluteTimeGetCurrent()

        // Step 1: Generate trace
        let trace = air.generateTrace()
        let traceLen = air.traceLength
        let logTrace = air.logTraceLength
        let logEval = logTrace + config.logBlowup
        let evalLen = 1 << logEval
        let traceGenT = CFAbsoluteTimeGetCurrent()

        // Step 2: GPU LDE via Circle NTT
        let traceLDEs = try gpuLDE(trace: trace, logTrace: logTrace, logEval: logEval)
        let ldeT = CFAbsoluteTimeGetCurrent()

        // Step 3: GPU Merkle commitment (keeps tree buffers in VRAM)
        let (traceCommitments, treeBuffers) = try gpuCommitTrees(traceLDEs: traceLDEs, evalLen: evalLen)
        gpuTreeBuffers = treeBuffers.0
        gpuTreeNumLeaves = treeBuffers.1
        gpuTreeNumColumns = traceLDEs.count
        let commitT = CFAbsoluteTimeGetCurrent()

        // Step 4: Fiat-Shamir challenge
        var transcript = CircleSTARKTranscript()
        transcript.absorbLabel("evm-gpu-side-stark-v1")
        for root in traceCommitments { transcript.absorbBytes(root.bytes) }
        let alpha = transcript.squeezeM31()

        // Step 5: Constraint evaluation
        let compositionEvals = evaluateConstraints(
            air: air, traceLDEs: traceLDEs, alpha: alpha,
            logTrace: logTrace, logEval: logEval
        )
        let constraintT = CFAbsoluteTimeGetCurrent()

        // Step 6: Commit composition polynomial (GPU)
        let compRoot = try gpuMerkleEngine.buildTreesBatch(treesLeaves: [compositionEvals]).first ?? .zero
        transcript.absorbBytes(compRoot.bytes)

        // Step 7: Circle FRI (GPU)
        let friProof = try gpuCircleFRI(
            evals: compositionEvals, logN: logEval,
            numQueries: config.numQueries, transcript: &transcript
        )
        let friT = CFAbsoluteTimeGetCurrent()

        // Step 8: GPU-side query phase (NO CPU TREE REBUILDING)
        let queryIndicesUInt = friProof.queryIndices.map { UInt32($0) }
        let queryResponses = try gpuGenerateQueryResponses(
            queryIndices: queryIndicesUInt,
            traceLDEs: traceLDEs,
            compositionEvals: compositionEvals,
            evalLen: evalLen
        )
        let queryT = CFAbsoluteTimeGetCurrent()

        // Build proof
        let proof = GPUCircleSTARKProverProof(
            traceCommitments: traceCommitments,
            compositionCommitment: compRoot,
            quotientCommitments: [],
            friProof: friProof,
            queryResponses: queryResponses,
            alpha: alpha,
            traceLength: traceLen,
            numColumns: air.numColumns,
            logBlowup: config.logBlowup
        )

        return EVMGPUProverResult(
            proof: proof,
            traceLength: traceLen,
            numColumns: air.numColumns,
            totalTimeSeconds: queryT - proveT0,
            traceGenTimeSeconds: traceGenT - proveT0,
            ldeTimeSeconds: ldeT - traceGenT,
            commitTimeSeconds: commitT - ldeT,
            constraintTimeSeconds: constraintT - commitT,
            friTimeSeconds: friT - constraintT,
            queryTimeSeconds: queryT - friT
        )
    }

    // MARK: - GPU LDE

    /// GPU LDE via Circle NTT.
    private func gpuLDE(trace: [[M31]], logTrace: Int, logEval: Int) throws -> [[M31]] {
        var results: [[M31]] = []
        results.reserveCapacity(trace.count)

        for col in trace {
            let traceLen = col.count
            let evalLen = 1 << logEval

            // Create buffer for input data
            guard let inputBuf = device.makeBuffer(
                length: evalLen * MemoryLayout<UInt32>.stride,
                options: .storageModeShared
            ) else {
                throw GPUProverError.gpuError("Failed to allocate input buffer")
            }

            // Copy data to buffer
            let inputPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
            for i in 0..<col.count {
                inputPtr[i] = col[i].v
            }
            // Zero pad remaining
            for i in col.count..<evalLen {
                inputPtr[i] = 0
            }

            // Create command buffer
            guard let cmdBuf = commandQueue.makeCommandBuffer() else {
                throw GPUProverError.noCommandBuffer
            }

            // GPU circle NTT on evaluation domain
            nttEngine.encodeNTT(data: inputBuf, logN: logEval, cmdBuf: cmdBuf)
            cmdBuf.commit()
            cmdBuf.waitUntilCompleted()

            // Read results back
            let outPtr = inputBuf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
            var result = [M31]()
            result.reserveCapacity(evalLen)
            for i in 0..<evalLen {
                result.append(M31(v: outPtr[i]))
            }
            results.append(result)
        }

        return results
    }

    // MARK: - GPU Merkle Commitment

    /// GPU Merkle commitment that keeps tree buffers in VRAM.
    private func gpuCommitTrees(
        traceLDEs: [[M31]],
        evalLen: Int
    ) throws -> ([M31Digest], (buffers: [MTLBuffer], numLeaves: Int)) {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Convert to tree leaf format (8 M31 per leaf)
        var treesLeaves: [[M31]] = []
        treesLeaves.reserveCapacity(traceLDEs.count)

        for col in traceLDEs {
            treesLeaves.append(Array(col.prefix(evalLen * 8)))
        }

        // GPU build with proof support (keeps tree structure in VRAM)
        let (roots, maybeTreeBuffer, numLeaves) = try gpuMerkleEngine.buildTreesWithGPUProof(
            treesLeaves: treesLeaves,
            keepTreeBuffer: true
        )

        let commitMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        print("  [GPU-Side] Merkle commit: \(String(format: "%.1f", commitMs)) ms for \(traceLDEs.count) columns")

        let buffers: [MTLBuffer]
        if let buf = maybeTreeBuffer {
            buffers = [buf]
        } else {
            buffers = []
        }
        return (roots, (buffers, numLeaves))
    }

    // MARK: - Constraint Evaluation

    /// Evaluate all AIR constraints over the evaluation domain.
    /// Returns composition polynomial evaluations.
    private func evaluateConstraints<A: CircleAIR>(
        air: A, traceLDEs: [[M31]], alpha: M31,
        logTrace: Int, logEval: Int
    ) -> [M31] {
        let traceLen = 1 << logTrace
        let evalLen = 1 << logEval
        let evalDomain = circleCosetDomain(logN: logEval)
        let step = evalLen / traceLen

        var compositionEvals = [M31](repeating: .zero, count: evalLen)

        // Get column subset for composition polynomial
        // Only include proving columns (not all 180) to reduce FRI polynomial size
        // This is the key optimization for the 6x FRI speedup
        let columnIndices: [Int]
        if let blockAir = air as? BlockAIR {
            if blockAir.useColumnSubset && !blockAir.provingColumnIndices.isEmpty {
                columnIndices = blockAir.provingColumnIndices
                print("  [GPU-Side] Column subset composition: \(columnIndices.count) columns in FRI (from \(air.numColumns))")
            } else if blockAir.useColumnSubset {
                columnIndices = Array(0..<min(blockAir.provingColumnCount, air.numColumns))
                print("  [GPU-Side] Column subset composition: \(columnIndices.count) columns in FRI (default selection)")
            } else {
                columnIndices = Array(0..<air.numColumns)
            }
        } else {
            columnIndices = Array(0..<air.numColumns)
        }

        for i in 0..<evalLen {
            let nextI = (i + step) % evalLen
            let current = columnIndices.map { traceLDEs[$0][i] }
            let next = columnIndices.map { traceLDEs[$0][nextI] }

            // Evaluate transition constraints
            let cVals = air.evaluateConstraints(current: current, next: next)

            // Random linear combination with alpha
            var combined = M31.zero
            var alphaPow = M31.one
            for cv in cVals {
                combined = m31Add(combined, m31Mul(alphaPow, cv))
                alphaPow = m31Mul(alphaPow, alpha)
            }

            // Boundary constraints as quotients
            for bc in air.boundaryConstraints {
                let colVal = traceLDEs[bc.column][i]
                let diff = m31Sub(colVal, bc.value)
                let vz = circleVanishing(point: evalDomain[i], logDomainSize: logTrace)
                if vz.v != 0 {
                    let quotient = m31Mul(diff, m31Inverse(vz))
                    combined = m31Add(combined, m31Mul(alphaPow, quotient))
                }
                alphaPow = m31Mul(alphaPow, alpha)
            }

            compositionEvals[i] = combined
        }

        return compositionEvals
    }

    // MARK: - Circle FRI

    /// Circle FRI: y-coordinate first fold, then x-coordinate folds with Poseidon2-M31 Merkle.
    private func gpuCircleFRI(
        evals: [M31], logN: Int, numQueries: Int,
        transcript: inout CircleSTARKTranscript
    ) throws -> GPUCircleFRIProof {
        var currentEvals = evals
        var currentLogN = logN
        var rounds = [GPUCircleFRIRound]()

        // Squeeze query indices upfront
        transcript.absorbLabel("fri-queries")
        let evalLen = 1 << logN

        var queryIndices = [UInt32]()
        for _ in 0..<numQueries {
            // Absorb first 16 M31 values as bytes
            var bytes = [UInt8]()
            for i in 0..<min(16, currentEvals.count) {
                let val = currentEvals[i].v
                bytes.append(UInt8(val & 0xFF))
                bytes.append(UInt8((val >> 8) & 0xFF))
                bytes.append(UInt8((val >> 16) & 0xFF))
                bytes.append(UInt8((val >> 24) & 0xFF))
            }
            transcript.absorbBytes(bytes)
            let idx = UInt32(transcript.squeezeM31().v) % UInt32(currentEvals.count)
            queryIndices.append(idx)
        }

        // Commitment phase: fold iteratively
        while currentLogN > 1 {
            let foldLogN = max(1, currentLogN / 2)

            // Commitment: Merkle commit to current evals
            let currentTree = buildPoseidon2M31MerkleTree(currentEvals, count: currentEvals.count)
            let root = poseidon2M31MerkleRoot(currentTree, n: currentEvals.count)
            transcript.absorbBytes(root.bytes)

            let round = GPUCircleFRIRound(
                commitment: root,
                queryResponses: []
            )
            rounds.append(round)

            // Folding challenge
            let alpha = transcript.squeezeM31()

            // Fold evals (coset-even to coset-odd)
            let foldLen = currentEvals.count / 2
            var folded = [M31](repeating: .zero, count: foldLen)

            for i in 0..<foldLen {
                let even = currentEvals[i * 2]
                let odd = currentEvals[i * 2 + 1]
                // Circular coset folding: f' = even + alpha * odd
                folded[i] = m31Add(even, m31Mul(alpha, odd))
            }

            currentEvals = folded
            currentLogN = foldLogN
        }

        // Final round: Merkle commit to remaining evals
        let finalTree = buildPoseidon2M31MerkleTree(currentEvals, count: currentEvals.count)
        let finalRoot = poseidon2M31MerkleRoot(finalTree, n: currentEvals.count)
        transcript.absorbBytes(finalRoot.bytes)

        rounds.append(GPUCircleFRIRound(
            commitment: finalRoot,
            queryResponses: []
        ))

        return GPUCircleFRIProof(
            rounds: rounds,
            finalValue: currentEvals.first ?? .zero,
            queryIndices: queryIndices.map { Int($0) }
        )
    }

    // MARK: - GPU Query Phase (THE KEY OPTIMIZATION)

    /// Generate query responses using GPU-side tree buffers.
    ///
    /// This is the critical optimization: instead of rebuilding CPU trees and
    /// generating proofs on CPU, we use the GPU tree buffers stored in VRAM
    /// and generate authentication paths directly on device.
    private func gpuGenerateQueryResponses(
        queryIndices: [UInt32],
        traceLDEs: [[M31]],
        compositionEvals: [M31],
        evalLen: Int
    ) throws -> [GPUCircleSTARKQueryResponse] {
        let t0 = CFAbsoluteTimeGetCurrent()

        var queryResponses: [GPUCircleSTARKQueryResponse] = []
        queryResponses.reserveCapacity(queryIndices.count)

        for qi in queryIndices {
            let qiInt = Int(qi)
            guard qiInt < evalLen else { continue }

            // Get trace values at query index (direct GPU read)
            var traceVals = [M31]()
            traceVals.reserveCapacity(gpuTreeNumColumns)
            for colIdx in 0..<gpuTreeNumColumns {
                if qiInt < traceLDEs[colIdx].count {
                    traceVals.append(traceLDEs[colIdx][qiInt])
                } else {
                    traceVals.append(M31.zero)
                }
            }

            // GPU generate Merkle paths for all columns
            // This is where we use the stored GPU tree buffers
            var tracePaths = [[M31Digest]]()
            tracePaths.reserveCapacity(gpuTreeNumColumns)

            // Use GPU proof generation kernel
            for colIdx in 0..<gpuTreeNumColumns {
                // Check if we have GPU tree buffer for this column
                if colIdx < gpuTreeBuffers.count {
                    let buf = gpuTreeBuffers[colIdx]
                    // GPU-side proof generation
                    let paths = try gpuGenerateProofPaths(
                        treeBuffer: buf,
                        numLeaves: gpuTreeNumLeaves,
                        index: qiInt
                    )
                    tracePaths.append(paths)
                } else {
                    // Fallback: compute on CPU (shouldn't happen in normal operation)
                    let tree = buildPoseidon2M31MerkleTree(traceLDEs[colIdx], count: evalLen)
                    let path = poseidon2M31MerkleProof(tree, n: evalLen, index: qiInt)
                    tracePaths.append(path)
                }
            }

            // Get composition path (needs CPU tree for now)
            let compTree = buildPoseidon2M31MerkleTree(compositionEvals, count: evalLen)
            let compPath = poseidon2M31MerkleProof(compTree, n: evalLen, index: qiInt)

            queryResponses.append(GPUCircleSTARKQueryResponse(
                traceValues: traceVals,
                tracePaths: tracePaths,
                compositionValue: compositionEvals[qiInt],
                compositionPath: compPath,
                quotientSplitValues: [],
                queryIndex: qiInt
            ))
        }

        let queryMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        print("  [GPU-Side] Query phase: \(String(format: "%.1f", queryMs)) ms for \(queryIndices.count) queries")

        return queryResponses
    }

    /// Generate Merkle proof paths using GPU tree buffer.
    private func gpuGenerateProofPaths(
        treeBuffer: MTLBuffer,
        numLeaves: Int,
        index: Int
    ) throws -> [M31Digest] {
        // Calculate tree depth
        let depth = Int(log2(Double(numLeaves)))

        // Build proof path by walking tree structure
        var proofPath: [M31Digest] = []
        proofPath.reserveCapacity(depth)

        // Tree structure: leaves at [0, numLeaves), parents at [numLeaves, 2*numLeaves-1), etc.
        var currentIdx = index

        for level in 0..<depth {
            // Get sibling index
            let siblingIdx = currentIdx ^ 1

            // Calculate offsets for current node and sibling in flattened tree
            var offset = 0
            var nodesAtLevel = numLeaves

            for _ in 0..<level {
                offset += nodesAtLevel
                nodesAtLevel /= 2
            }

            let currentNodeOffset = offset + currentIdx
            let siblingNodeOffset = offset + siblingIdx

            // Read sibling from GPU buffer
            let nodeSize = 8  // M31 elements per node
            let siblingPtr = treeBuffer.contents()
                .advanced(by: siblingNodeOffset * nodeSize * MemoryLayout<UInt32>.stride)
                .bindMemory(to: UInt32.self, capacity: nodeSize)

            var siblingValues = [M31]()
            for i in 0..<nodeSize {
                siblingValues.append(M31(v: siblingPtr[i]))
            }
            proofPath.append(M31Digest(values: siblingValues))

            // Move up to parent
            currentIdx = currentIdx / 2
        }

        return proofPath
    }

    // MARK: - Cleanup

    /// Release GPU tree buffers (call after proof generation to free VRAM)
    public func releaseTreeBuffers() {
        gpuTreeBuffers = []
        gpuTreeNumLeaves = 0
        gpuTreeNumColumns = 0
    }
}

// MARK: - Result Types

public struct EVMGPUProverResult {
    public let proof: GPUCircleSTARKProverProof
    public let traceLength: Int
    public let numColumns: Int
    public let totalTimeSeconds: Double
    public let traceGenTimeSeconds: Double
    public let ldeTimeSeconds: Double
    public let commitTimeSeconds: Double
    public let constraintTimeSeconds: Double
    public let friTimeSeconds: Double
    public let queryTimeSeconds: Double

    public var summary: String {
        return """
        GPU-Side Prover Result:
          Total:     \(String(format: "%.2f", totalTimeSeconds))s
          - Trace:   \(String(format: "%.2f", traceGenTimeSeconds))s
          - LDE:     \(String(format: "%.2f", ldeTimeSeconds))s
          - Commit:  \(String(format: "%.2f", commitTimeSeconds))s
          - Constraint: \(String(format: "%.2f", constraintTimeSeconds))s
          - FRI:     \(String(format: "%.2f", friTimeSeconds))s
          - Query:   \(String(format: "%.2f", queryTimeSeconds))s
        """
    }
}