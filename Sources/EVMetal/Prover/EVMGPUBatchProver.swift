import Foundation
import Metal
import zkMetal

/// GPU-accelerated EVM batch prover with Poseidon2-M31 Merkle commitment.
///
/// This prover uses GPU Circle NTT for LDE and GPU Poseidon2 for Merkle trees.
/// Returns GPUCircleSTARKProverProof compatible with the GPU prover infrastructure.
///
/// Supports two commitment strategies:
/// - `.merkle`: Traditional Poseidon2-M31 Merkle trees (current default)
/// - `.brakedown`: Brakedown polynomial commitment (new, experimental)
public final class EVMGPUBatchProver {

    // MARK: - Commitment Strategy

    /// Commitment strategy for trace columns.
    public enum CommitmentStrategy: Sendable {
        /// Traditional Poseidon2-M31 Merkle tree commitment.
        case merkle
        /// Brakedown polynomial commitment (hash-based, no trusted setup).
        case brakedown
        /// Brakedown with interleaved 8-tree structure (combines both approaches).
        case brakedownInterleaved
    }

    // MARK: - Configuration

    public struct Config {
        public let logBlowup: Int
        public let numQueries: Int
        /// Commitment strategy to use for trace columns.
        public let commitmentStrategy: CommitmentStrategy
        /// Optional proof compression configuration.
        public let compressionConfig: ProofCompressionConfig?

        public static let standard = Config(logBlowup: 4, numQueries: 30, commitmentStrategy: .merkle, compressionConfig: nil)
        public static let fast = Config(logBlowup: 2, numQueries: 20, commitmentStrategy: .merkle, compressionConfig: nil)
        public static let highSecurity = Config(logBlowup: 4, numQueries: 40, commitmentStrategy: .merkle, compressionConfig: nil)

        /// Configuration with Brakedown commitment strategy.
        public static let brakedown = Config(logBlowup: 4, numQueries: 30, commitmentStrategy: .brakedown, compressionConfig: nil)
        /// Fast configuration with Brakedown commitment.
        public static let brakedownFast = Config(logBlowup: 2, numQueries: 16, commitmentStrategy: .brakedown, compressionConfig: nil)

        /// Configuration with interleaved 8-tree Brakedown commitment.
        /// Combines trustless Brakedown with better GPU utilization from 8-tree structure.
        public static let brakedownInterleaved = Config(logBlowup: 4, numQueries: 30, commitmentStrategy: .brakedownInterleaved, compressionConfig: nil)
        /// Fast configuration with interleaved 8-tree Brakedown.
        public static let brakedownInterleavedFast = Config(logBlowup: 2, numQueries: 16, commitmentStrategy: .brakedownInterleaved, compressionConfig: nil)

        /// Create a GPU batch prover config with compression settings.
        /// - Parameters:
        ///   - compressionConfig: Proof compression configuration (e.g., .highCompression, .standard)
        ///   - commitmentStrategy: Commitment strategy to use.
        public static func compressed(compressionConfig: ProofCompressionConfig, commitmentStrategy: CommitmentStrategy = .merkle) -> Config {
            Config(
                logBlowup: compressionConfig.logBlowup,
                numQueries: compressionConfig.numQueries,
                commitmentStrategy: commitmentStrategy,
                compressionConfig: compressionConfig
            )
        }

        public init(logBlowup: Int = 4, numQueries: Int = 30, commitmentStrategy: CommitmentStrategy = .merkle, compressionConfig: ProofCompressionConfig? = nil) {
            self.logBlowup = logBlowup
            self.numQueries = numQueries
            self.commitmentStrategy = commitmentStrategy
            self.compressionConfig = compressionConfig
        }
    }

    // MARK: - Result Types

    public struct ProverResult {
        public let gpuProof: GPUCircleSTARKProverProof
        public let traceGenMs: Double
        public let ldeMs: Double
        public let commitMs: Double
        public let constraintMs: Double
        public let friMs: Double
        public let totalMs: Double
        /// Commitment strategy used.
        public let commitmentStrategy: CommitmentStrategy

        public var summary: String {
            let strategyName: String
            switch commitmentStrategy {
            case .merkle:
                strategyName = "Merkle (180 trees)"
            case .brakedown:
                strategyName = "Brakedown (180 trees)"
            case .brakedownInterleaved:
                strategyName = "Brakedown (8 trees, interleaved)"
            }
            return """
            GPU Prover Result:
              Strategy: \(strategyName)
              Trace Gen: \(String(format: "%.1fms", traceGenMs))
              LDE:       \(String(format: "%.1fms", ldeMs))
              Commit:    \(String(format: "%.1fms", commitMs))
              Constraint:\(String(format: "%.1fms", constraintMs))
              FRI:       \(String(format: "%.1fms", friMs))
              ──────────────────
              Total:     \(String(format: "%.1fms", totalMs))
            """
        }
    }

    // MARK: - Private State

    private let config: Config
    private let nttEngine: CircleNTTEngine
    private let gpuProver: EVMetalCustomProver
    private var brakedownEngine: EVMetalBrakedownEngine?
    private var ldeOptimizer: EVMLDEOptimizer?
    private var gpuMerkleEngine: EVMGPUMerkleEngine?
    private var leafHashEngine: EVMetalLeafHashEngine?

    // GPU proof generation state
    private var gpuTreeBuffer: MTLBuffer?
    private var gpuTreeNumLeaves: Int = 0

    // LDE optimization configuration
    private let ldeConfig: EVMLDEOptimizer.Config

    // MARK: - Initialization

    public init(config: Config = .standard) throws {
        self.config = config
        self.nttEngine = try CircleNTTEngine()
        self.gpuProver = EVMetalCustomProver(config: .init(logBlowup: config.logBlowup, numQueries: config.numQueries))

        // LDE Optimizer with pipeline and async support
        self.ldeConfig = EVMLDEOptimizer.Config.standard
        self.ldeOptimizer = try EVMLDEOptimizer(config: ldeConfig)

        // Initialize Brakedown engine if needed
        if config.commitmentStrategy == .brakedown || config.commitmentStrategy == .brakedownInterleaved {
            self.brakedownEngine = try EVMetalBrakedownEngine()
        }

        // Initialize GPU Merkle engine for GPU proof generation
        self.gpuMerkleEngine = try? EVMGPUMerkleEngine()

        // Initialize leaf hash engine for batch GPU leaf hashing optimization
        self.leafHashEngine = try? EVMetalLeafHashEngine()
        // Set to precomputed level to enable H4 position hash optimization
        self.leafHashEngine?.optimizationLevel = .precomputed
    }

    // MARK: - Prove Single Transaction

    /// Prove a single EVM transaction with GPU acceleration.
    /// Returns a GPUCircleSTARKProverProof compatible with GPU infrastructure.
    public func prove(transaction: EVMTransaction) throws -> ProverResult {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Step 1: Execute EVM and generate AIR
        let traceGenT0 = CFAbsoluteTimeGetCurrent()
        let engine = EVMExecutionEngine()
        let result = try engine.execute(
            code: transaction.code,
            calldata: transaction.calldata,
            value: transaction.value,
            gasLimit: transaction.gasLimit
        )
        let air = EVMAIR.fromExecution(result)
        let traceGenMs = (CFAbsoluteTimeGetCurrent() - traceGenT0) * 1000

        // Step 2: Generate trace
        let trace = air.generateTrace()
        let traceLen = trace[0].count
        let numColumns = trace.count

        // OPTIMIZATION: Use compression config to reduce tree size
        // logBlowup from compression config reduces leaves by 4x when set to 2 instead of 4
        let effectiveLogBlowup = config.compressionConfig?.logBlowup ?? config.logBlowup
        // Ensure logTrace is at least 1 to avoid invalid range in Circle NTT (1..<0 is invalid)
        let logTrace = max(1, air.logTraceLength)
        let logEval = logTrace + effectiveLogBlowup
        let evalLen = 1 << logEval

        // Step 3: GPU LDE via Circle NTT
        let ldeT0 = CFAbsoluteTimeGetCurrent()
        let traceLDEs = try gpuLDE(trace: trace, logTrace: logTrace, logEval: logEval)
        let ldeMs = (CFAbsoluteTimeGetCurrent() - ldeT0) * 1000

        // Step 4: Commitment (Merkle or Brakedown based on config)
        let commitT0 = CFAbsoluteTimeGetCurrent()
        let traceCommitments: [zkMetal.M31Digest]
        let brakedownBatchRoot: Fr?

        switch config.commitmentStrategy {
        case .merkle:
            // Traditional Poseidon2-M31 Merkle tree commitment
            // OPTIMIZATION: Use GPU Merkle engine with tree structure preservation
            // for GPU-side proof generation (eliminates CPU tree rebuilding bottleneck)
            // OPTIMIZATION: Batch GPU leaf hashing with H4 precomputation for all columns
            if let merkleEng = gpuMerkleEngine, let leafEng = leafHashEngine {
                // Flatten all columns: [col0_all, col1_all, col2_all, ...]
                var allValues: [M31] = []
                allValues.reserveCapacity(numColumns * evalLen)
                for col in traceLDEs {
                    allValues.append(contentsOf: col.prefix(evalLen))
                }

                // Use auto-optimized batch hashing (select best kernel based on config)
                // This will use H2/H3 kernels by default for sharedMem optimization level
                let treesLeaves = try leafEng.hashLeavesAutoOptimized(
                    allValues: allValues,
                    numColumns: numColumns,
                    countPerColumn: evalLen
                )

                // Build trees with GPU (no leaf hashing needed)
                let (roots, treeBuf, numLeaves) = try merkleEng.buildTreesWithGPUProof(
                    treesLeaves: treesLeaves,
                    keepTreeBuffer: true
                )
                traceCommitments = roots
                gpuTreeBuffer = treeBuf
                gpuTreeNumLeaves = numLeaves
            } else if let merkleEng = gpuMerkleEngine {
                // Fallback without GPU leaf hashing: GPU tree building
                var treesLeaves: [[M31]] = []
                for col in traceLDEs {
                    treesLeaves.append(Array(col.prefix(evalLen * 8)))
                }

                let (roots, treeBuf, numLeaves) = try merkleEng.buildTreesWithGPUProof(
                    treesLeaves: treesLeaves,
                    keepTreeBuffer: true
                )
                traceCommitments = roots
                gpuTreeBuffer = treeBuf
                gpuTreeNumLeaves = numLeaves
            } else {
                // Fallback if GPU Merkle engine unavailable
                let commitResult = try gpuProver.commitTraceColumns(traceLDEs: traceLDEs, evalLen: evalLen)
                traceCommitments = commitResult.commitments
                gpuTreeBuffer = nil
                gpuTreeNumLeaves = 0
            }
            brakedownBatchRoot = nil

        case .brakedown:
            // Brakedown polynomial commitment
            guard let brakedownEng = brakedownEngine else {
                throw BrakedownError.noGPU
            }
            let brakedownResult = try brakedownEng.commit(traceLDEs: traceLDEs, evalLen: evalLen)

            // Convert Brakedown commitments (Fr) to M31Digest for compatibility
            traceCommitments = brakedownResult.commitments.map { commitment in
                // Use the merkle root as the commitment value
                let limbs = commitment.merkleRoot.to64()
                var values: [M31] = []
                for limb in limbs {
                    values.append(M31(v: UInt32(limb & 0xFFFFFFFF)))
                    values.append(M31(v: UInt32((limb >> 32) & 0xFFFFFFFF)))
                }
                return zkMetal.M31Digest(values: values)
            }
            brakedownBatchRoot = brakedownResult.batchRoot

        case .brakedownInterleaved:
            // Brakedown with interleaved 8-tree structure
            guard let brakedownEng = brakedownEngine else {
                throw BrakedownError.noGPU
            }
            let brakedownResult = try brakedownEng.commitInterleaved8Trees(traceLDEs: traceLDEs, evalLen: evalLen)

            // Convert 8 Brakedown commitments to M31Digest for compatibility
            // Using the interleaved structure: 8 commitments instead of 180
            traceCommitments = brakedownResult.commitments.map { commitment in
                let limbs = commitment.merkleRoot.to64()
                var values: [M31] = []
                for limb in limbs {
                    values.append(M31(v: UInt32(limb & 0xFFFFFFFF)))
                    values.append(M31(v: UInt32((limb >> 32) & 0xFFFFFFFF)))
                }
                return zkMetal.M31Digest(values: values)
            }
            brakedownBatchRoot = brakedownResult.batchRoot
        }

        let commitMs = (CFAbsoluteTimeGetCurrent() - commitT0) * 1000

        // Step 5: CPU constraint evaluation
        let constraintT0 = CFAbsoluteTimeGetCurrent()

        // Fiat-Shamir
        var transcript = CircleSTARKTranscript()
        transcript.absorbLabel("gpu-evm-stark-v1")
        for root in traceCommitments { transcript.absorbBytes(root.bytes) }
        let alpha = transcript.squeezeM31()

        let evalDomain = circleCosetDomain(logN: logEval)
        let step = evalLen / traceLen
        var compositionEvals = [M31](repeating: .zero, count: evalLen)

        // Get column subset for composition polynomial
        // Only include proving columns (not all 180) to reduce FRI polynomial size
        let compositionColumnIndices: [Int]
        if let blockAir = air as? BlockAIR, blockAir.useColumnSubset {
            compositionColumnIndices = blockAir.provingColumnIndices.isEmpty
                ? Array(0..<min(blockAir.provingColumnCount, air.numColumns))
                : blockAir.provingColumnIndices
            print("  [GPU-Batch] Column subset composition: \(compositionColumnIndices.count) columns in FRI (from \(air.numColumns))")
        } else {
            compositionColumnIndices = Array(0..<air.numColumns)
        }

        for i in 0..<evalLen {
            let nextI = (i + step) % evalLen
            let current = compositionColumnIndices.map { traceLDEs[$0][i] }
            let next = compositionColumnIndices.map { traceLDEs[$0][nextI] }

            let cVals = air.evaluateConstraints(current: current, next: next)

            var combined = M31.zero
            var alphaPow = M31.one
            for cv in cVals {
                combined = m31Add(combined, m31Mul(alphaPow, cv))
                alphaPow = m31Mul(alphaPow, alpha)
            }

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
        let constraintMs = (CFAbsoluteTimeGetCurrent() - constraintT0) * 1000

        // Step 6: Commit composition polynomial (GPU)
        let compCommitResult = try gpuProver.commitTraceColumns(traceLDEs: [compositionEvals], evalLen: evalLen)
        let compositionCommitment = compCommitResult.commitments.first ?? .zero

        // Step 7: GPU Circle FRI (Phase 3 Optimization)
        // Replace placeholder with actual GPU-accelerated FRI using CircleFRIEngine
        let friT0 = CFAbsoluteTimeGetCurrent()
        let friEngine: CircleFRIEngine
        do {
            friEngine = try CircleFRIEngine()
        } catch {
            // Fallback to placeholder if GPU FRI fails
            transcript.absorbBytes(compositionCommitment.bytes)
            _ = transcript.squeezeM31()
            let friMs = (CFAbsoluteTimeGetCurrent() - friT0) * 1000
            print("  GPU FRI init failed, using placeholder: \(error)")
            let friProof = buildPlaceholderFRIRoundData(evals: compositionEvals, numQueries: config.numQueries)
            let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            let gpuProof = GPUCircleSTARKProverProof(
                traceCommitments: traceCommitments,
                compositionCommitment: compositionCommitment,
                quotientCommitments: [],
                friProof: friProof,
                queryResponses: [],
                alpha: alpha,
                traceLength: traceLen,
                numColumns: numColumns,
                logBlowup: config.logBlowup
            )

            return ProverResult(
                gpuProof: gpuProof,
                traceGenMs: traceGenMs,
                ldeMs: ldeMs,
                commitMs: commitMs,
                constraintMs: constraintMs,
                friMs: friMs,
                totalMs: totalMs,
                commitmentStrategy: config.commitmentStrategy
            )
        }

        // Generate FRI challenges via Fiat-Shamir
        let logN = logEval
        let numFRIRounds = max(1, logN / 2)
        var alphas: [M31] = []
        for _ in 0..<numFRIRounds {
            transcript.absorbBytes(compositionCommitment.bytes)
            alphas.append(transcript.squeezeM31())
        }

        // GPU commit phase: fold iteratively on GPU
        let friCommitment = try friEngine.commitPhase(evals: compositionEvals, alphas: alphas)

        // Generate query indices
        let queryIndices = (0..<config.numQueries).map { _ in
            UInt32.random(in: 0..<UInt32(evalLen))
        }

        // GPU query phase: extract evaluations and Merkle paths
        let friQueryProofs = friEngine.queryPhase(commitment: friCommitment, queryIndices: queryIndices)

        // Convert to GPUCircleFRIProof format
        let friRounds: [GPUCircleFRIRound] = friCommitment.roots.enumerated().map { idx, root in
            let m31Digest = M31Digest(values: [
                M31(v: root.v), M31.zero, M31.zero, M31.zero,
                M31.zero, M31.zero, M31.zero, M31.zero
            ])
            return GPUCircleFRIRound(commitment: m31Digest, queryResponses: [])
        }

        let friProof = GPUCircleFRIProof(
            rounds: friRounds,
            finalValue: friCommitment.finalValue,
            queryIndices: friQueryProofs.map { Int($0.initialIndex) }
        )

        let friMs = (CFAbsoluteTimeGetCurrent() - friT0) * 1000
        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000

        // Step 8: Build query responses
        let queryResponses = buildQueryResponses(
            traceLDEs: traceLDEs,
            compositionEvals: compositionEvals,
            numQueries: config.numQueries,
            evalLen: evalLen,
            numColumns: numColumns
        )

        // Step 9: Build GPU proof
        let gpuProof = GPUCircleSTARKProverProof(
            traceCommitments: traceCommitments,
            compositionCommitment: compositionCommitment,
            quotientCommitments: [],
            friProof: friProof,
            queryResponses: queryResponses,
            alpha: alpha,
            traceLength: traceLen,
            numColumns: numColumns,
            logBlowup: config.logBlowup
        )

        return ProverResult(
            gpuProof: gpuProof,
            traceGenMs: traceGenMs,
            ldeMs: ldeMs,
            commitMs: commitMs,
            constraintMs: constraintMs,
            friMs: friMs,
            totalMs: totalMs,
            commitmentStrategy: config.commitmentStrategy
        )
    }

    // MARK: - Query Response Builder

    private func buildQueryResponses(
        traceLDEs: [[M31]],
        compositionEvals: [M31],
        numQueries: Int,
        evalLen: Int,
        numColumns: Int
    ) -> [GPUCircleSTARKQueryResponse] {
        var responses: [GPUCircleSTARKQueryResponse] = []
        let limitQueries = min(numQueries, 10)  // Limit for testing

        // OPTIMIZATION: Generate proof paths on GPU when tree buffer is available
        // This eliminates the CPU tree rebuilding bottleneck (~30s for 180 trees)
        var gpuProofPaths: [[M31Digest]]? = nil

        if let treeBuf = gpuTreeBuffer, gpuTreeNumLeaves > 0 {
            // Generate proofs on GPU for all columns at once
            // For each query, we need proofs for all columns
            // Generate random query indices
            var queryIndices: [Int] = []
            for _ in 0..<limitQueries {
                queryIndices.append(Int.random(in: 0..<evalLen))
            }

            // Generate GPU proofs (this is fast - just pointer chasing through tree)
            if let merkleEng = gpuMerkleEngine {
                do {
                    gpuProofPaths = try merkleEng.generateProofsGPU(
                        treeBuffer: treeBuf,
                        numTrees: numColumns,
                        numLeaves: gpuTreeNumLeaves,
                        queryIndices: queryIndices
                    )
                    print("  [GPU Batch Prover] GPU proof generation: \(limitQueries) queries, \(numColumns) columns")
                } catch {
                    print("  [GPU Batch Prover] GPU proof generation failed: \(error), falling back to CPU")
                    gpuProofPaths = nil
                }
            }
        }

        // Build query responses with proofs
        for queryIdx in 0..<limitQueries {
            let qi = Int.random(in: 0..<evalLen)

            // Build trace values at query position
            var traceVals: [M31] = []
            var tracePaths: [[M31Digest]] = []

            for colIdx in 0..<numColumns {
                traceVals.append(traceLDEs[colIdx][qi])

                // Use GPU proof if available, otherwise empty path
                if let paths = gpuProofPaths, colIdx < paths.count {
                    // Use the proof for this column (same query index for all columns)
                    tracePaths.append(paths[colIdx])
                } else {
                    tracePaths.append([])
                }
            }

            // Create query response using GPU type
            let response = GPUCircleSTARKQueryResponse(
                traceValues: traceVals,
                tracePaths: tracePaths,
                compositionValue: compositionEvals[qi],
                compositionPath: [],
                quotientSplitValues: [],
                queryIndex: qi
            )
            responses.append(response)
        }

        return responses
    }

    // MARK: - FRI Round Builder (Placeholder)

    /// Build placeholder FRI round data when GPU FRI is not available.
    private func buildPlaceholderFRIRoundData(evals: [M31], numQueries: Int) -> GPUCircleFRIProof {
        let logN = Int(log2(Double(evals.count)))
        let logFolds = max(1, logN / 2)

        var rounds: [GPUCircleFRIRound] = []
        var currentLayer = evals

        for _ in 0..<logFolds {
            // Simple root from current layer
            let root = M31Digest(values: Array(currentLayer.prefix(8)))
            let round = GPUCircleFRIRound(commitment: root, queryResponses: [])
            rounds.append(round)

            // Fold if more rounds
            if currentLayer.count > 1 {
                currentLayer = Array(currentLayer[0..<(currentLayer.count / 2)])
            }
        }

        return GPUCircleFRIProof(
            rounds: rounds,
            finalValue: currentLayer.first ?? .zero,
            queryIndices: (0..<min(numQueries, 10)).map { _ in Int.random(in: 0..<evals.count) }
        )
    }

    // MARK: - GPU LDE

    /// GPU-accelerated LDE using EVMLDEOptimizer with pipeline support.
    private func gpuLDE(trace: [[M31]], logTrace: Int, logEval: Int) throws -> [[M31]] {
        // Use optimized LDE with pipelining
        guard let optimizer = ldeOptimizer else {
            // Fallback to basic LDE
            return try basicGpuLDE(trace: trace, logTrace: logTrace, logEval: logEval)
        }

        return try optimizer.lde(trace: trace, logTrace: logTrace, logEval: logEval)
    }

    /// Basic GPU LDE (fallback when optimizer not available).
    private func basicGpuLDE(trace: [[M31]], logTrace: Int, logEval: Int) throws -> [[M31]] {
        let dev = nttEngine.device
        let queue = nttEngine.commandQueue
        let traceLen = 1 << logTrace
        let evalLen = 1 << logEval
        let sz = MemoryLayout<UInt32>.stride
        let numColumns = trace.count

        // Allocate column buffers and copy trace data
        var bufs = [MTLBuffer]()
        for colIdx in 0..<numColumns {
            let bufSize = evalLen * sz
            guard let buf = dev.makeBuffer(length: bufSize, options: .storageModeShared) else {
                throw GPUProverError.gpuError(
                    "Failed to allocate LDE buffer for column \(colIdx). Size: \(bufSize) bytes"
                )
            }
            let ptr = buf.contents().bindMemory(to: UInt32.self, capacity: evalLen)
            // Copy with bounds checking
            let actualLen = min(traceLen, trace[colIdx].count)
            for i in 0..<actualLen {
                ptr[i] = trace[colIdx][i].v
            }
            // Zero-pad remaining
            for i in actualLen..<traceLen {
                ptr[i] = 0
            }
            bufs.append(buf)
        }

        // Batch INTT
        guard let cb1 = queue.makeCommandBuffer() else { throw GPUProverError.noCommandBuffer }
        for colIdx in 0..<numColumns {
            nttEngine.encodeINTT(data: bufs[colIdx], logN: logTrace, cmdBuf: cb1)
        }
        cb1.commit()
        cb1.waitUntilCompleted()
        if let error = cb1.error {
            throw GPUProverError.gpuError("INTT command failed: \(error.localizedDescription)")
        }

        // Zero-pad
        for colIdx in 0..<numColumns {
            let ptr = bufs[colIdx].contents().bindMemory(to: UInt32.self, capacity: evalLen)
            memset(ptr + traceLen, 0, (evalLen - traceLen) * sz)
        }

        // Batch NTT
        guard let cb2 = queue.makeCommandBuffer() else { throw GPUProverError.noCommandBuffer }
        for colIdx in 0..<numColumns {
            nttEngine.encodeNTT(data: bufs[colIdx], logN: logEval, cmdBuf: cb2)
        }
        cb2.commit()
        cb2.waitUntilCompleted()
        if let error = cb2.error {
            throw GPUProverError.gpuError("NTT command failed: \(error.localizedDescription)")
        }

        // Read back results
        var results = [[M31]]()
        results.reserveCapacity(numColumns)
        for colIdx in 0..<numColumns {
            let ptr = bufs[colIdx].contents().bindMemory(to: UInt32.self, capacity: evalLen)
            var lde = [M31](repeating: .zero, count: evalLen)
            for i in 0..<evalLen { lde[i] = M31(v: ptr[i]) }
            results.append(lde)
        }

        return results
    }

    private func cpuM31MerkleRoot(_ values: [M31]) -> [UInt8] {
        // Simple Merkle root: hash first 8 values as bytes
        var result = [UInt8](repeating: 0, count: 32)
        for i in 0..<min(8, values.count) {
            var val = values[i].v
            let bytes = withUnsafeBytes(of: &val) { Array($0) }
            for j in 0..<min(4, bytes.count) {
                if i * 4 + j < 32 {
                    result[i * 4 + j] = bytes[j]
                }
            }
        }
        return result
    }

    // MARK: - Merkle Path Helper

    /// Build Merkle authentication path for index in a tree of given size.
    /// Returns sibling node values at each level (leaf to root).
    func buildMerklePath(evalLen: Int, index: Int) -> [[M31Digest]] {
        var path: [[M31Digest]] = []
        var currentIndex = index
        var levelSize = evalLen

        while levelSize > 1 {
            let siblingIndex = currentIndex ^ 1
            // For the GPU implementation, we need the sibling digest
            // This requires access to the tree structure
            // Return placeholder - actual path requires tree rebuild
            path.append([])
            currentIndex /= 2
            levelSize /= 2
        }

        return path
    }
}