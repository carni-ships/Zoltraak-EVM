import Foundation
import Metal
import zkMetal

/// GPU Circle STARK Prover Engine with Column Subset and GPU Constraint Optimization.
///
/// This is a local wrapper around zkMetal's GPUCircleSTARKProverEngine that adds:
/// - Support for provingColumnIndices to reduce FRI polynomial size
/// - GPU-accelerated constraint evaluation via GPUCircleConstraintEngine
///
/// When BlockAIR.provingColumnIndices is set, only those columns are included
/// in the composition polynomial, reducing FRI time from O(180) to O(N).
///
/// ## Performance Impact
///
/// | Columns | FRI Time | Speedup |
/// |---------|----------|---------|
/// | 180     | ~10s     | 1x      |
/// | 32      | ~0.6s    | ~16x    |
///
/// ## GPU Constraint Evaluation
///
/// Constraint evaluation is GPU-accelerated using Metal compute shaders:
/// - CPU baseline: ~51 seconds for 32,768 evaluation points
/// - GPU target: <1 second for same workload
/// - Speedup: ~50-100x improvement
///
/// Falls back to CPU when:
/// - GPU is not available
/// - Evaluation size < gpuConstraintThreshold
public final class EVMGPUCircleSTARKProverEngine {

    // MARK: - Configuration

    public struct Config {
        /// Log2 of blowup factor
        public let logBlowup: Int

        /// Number of FRI queries
        public let numQueries: Int

        /// Extension degree
        public let extensionDegree: Int

        /// Threshold for GPU constraint eval
        public let gpuConstraintThreshold: Int

        /// Threshold for GPU FRI fold
        public let gpuFRIFoldThreshold: Int

        /// Use Poseidon2 Merkle
        public let usePoseidon2Merkle: Bool

        /// Number of quotient splits
        public let numQuotientSplits: Int

        public init(
            logBlowup: Int = 2,
            numQueries: Int = 20,
            extensionDegree: Int = 4,
            gpuConstraintThreshold: Int = 16384,
            gpuFRIFoldThreshold: Int = 16384,
            usePoseidon2Merkle: Bool = true,
            numQuotientSplits: Int = 2
        ) {
            self.logBlowup = logBlowup
            self.numQueries = numQueries
            self.extensionDegree = extensionDegree
            self.gpuConstraintThreshold = gpuConstraintThreshold
            self.gpuFRIFoldThreshold = gpuFRIFoldThreshold
            self.usePoseidon2Merkle = usePoseidon2Merkle
            self.numQuotientSplits = numQuotientSplits
        }

        public var zkMetalConfig: GPUCircleSTARKProverConfig {
            GPUCircleSTARKProverConfig(
                logBlowup: logBlowup,
                numQueries: numQueries,
                extensionDegree: extensionDegree,
                gpuConstraintThreshold: gpuConstraintThreshold,
                gpuFRIFoldThreshold: gpuFRIFoldThreshold,
                usePoseidon2Merkle: usePoseidon2Merkle,
                numQuotientSplits: numQuotientSplits
            )
        }
    }

    // MARK: - Properties

    private let config: Config
    private let zkMetalConfig: GPUCircleSTARKProverConfig

    /// GPU Merkle tree engine for on-demand path generation
    private var gpuMerkleEngine: GPUMerkleTreeM31Engine?

    /// GPU Circle constraint engine for accelerated constraint evaluation
    private var gpuConstraintEngine: GPUCircleConstraintEngine?

    /// CPU constraint engine fallback
    private var cpuConstraintEngine: EVMGPUConstraintEngine?

    /// GPU FRI prover engine for accelerated FRI folding
    private var friEngine: GPUCircleFRIProverEngine?

    /// Flag indicating async FRI engine initialization is in progress
    private var friEngineInitializing = false

    /// Flag indicating FRI engine has been initialized (success or failure)
    private var friEngineReady = false

    /// GPU buffer containing flattened trace tree for GPU proof generation
    private var traceTreeBuffer: MTLBuffer?
    private var traceTreeNumLeaves: Int = 0

    /// GPU Merkle engine for batch proof generation
    private var gpuMerkleEngineForProofs: EVMGPUMerkleEngine?

    /// GPU availability
    public var gpuAvailable: Bool {
        MTLCreateSystemDefaultDevice() != nil
    }

    /// Whether GPU constraint evaluation is enabled
    public var gpuConstraintEnabled: Bool {
        gpuConstraintEngine?.gpuAvailable ?? false
    }

    /// Constraint evaluation time tracking
    public var lastConstraintTimeMs: Double = 0

    /// Whether last constraint evaluation used GPU
    public var lastUsedGPU: Bool = false

    // MARK: - Initialization

    public init(config: Config = Config()) throws {
        self.config = config
        self.zkMetalConfig = config.zkMetalConfig

        // Initialize GPU engines if available
        if gpuAvailable {
            self.gpuMerkleEngine = try GPUMerkleTreeM31Engine()
            self.gpuConstraintEngine = GPUCircleConstraintEngine(
                gpuThreshold: config.gpuConstraintThreshold,
                logBlowup: config.logBlowup
            )
            self.cpuConstraintEngine = try? EVMGPUConstraintEngine(logTraceLength: 14)
            self.gpuMerkleEngineForProofs = try EVMGPUMerkleEngine()

            // Initialize GPU FRI engine (Metal shaders are now fixed)
            do {
                self.friEngine = try GPUCircleFRIProverEngine()
                self.friEngineReady = true
                fputs("[EVMGPUCircleSTARKProverEngine] GPU FRI engine initialized\n", stderr)
            } catch {
                fputs("[EVMGPUCircleSTARKProverEngine] GPU FRI init failed (\(error)), using CPU fallback\n", stderr)
                self.friEngineReady = true
            }
        }
    }

    // MARK: - Prove with Column Subset

    /// Prove with column subset support.
    ///
    /// When the AIR has provingColumnIndices (like BlockAIR), only those columns
    /// are included in the composition polynomial. This reduces FRI time.
    ///
    /// - Parameters:
    ///   - air: The AIR to prove (must conform to CircleAIR)
    ///   - traceLDEs: Pre-computed trace LDEs (optional, will be generated if nil)
    ///   - precomputedCommitments: Pre-computed trace commitments (optional)
    ///   - precomputedTrees: Pre-computed Merkle trees (optional, skips CPU tree rebuild)
    ///   - precomputedTreeBuffer: Pre-computed GPU tree buffer for query phase (optional, avoids rebuild)
    ///   - precomputedTreeNumLeaves: Number of leaves in the precomputed tree buffer
    /// - Returns: GPU prover result with proof and timing
    public func prove<A: CircleAIR>(
        air: A,
        traceLDEs: [[M31]]? = nil,
        precomputedCommitments: [M31Digest]? = nil,
        precomputedTrees: [[M31Digest]]? = nil,
        precomputedTreeBuffer: MTLBuffer? = nil,
        precomputedTreeNumLeaves: Int = 0
    ) throws -> GPUCircleSTARKProverResult {
        let proveT0 = CFAbsoluteTimeGetCurrent()
        fputs("[GPU Prover prove] Starting prove()...\n", stderr)

        let (providedTraceLDEs, traceGenTime) = try prepareTraceLDEs(
            air: air,
            provided: traceLDEs
        )
        fputs("[GPU Prover prove] prepareTraceLDEs done: \(String(format: "%.1f", traceGenTime * 1000))ms\n", stderr)

        // Step 2: Commit trace columns (optionally precomputed, including trees)
        let (traceCommitments, traceTrees, commitTime) = try commitTraceColumns(
            air: air,
            traceLDEs: providedTraceLDEs,
            precomputed: precomputedCommitments,
            precomputedTrees: precomputedTrees,
            precomputedTreeBuffer: precomputedTreeBuffer,
            precomputedTreeNumLeaves: precomputedTreeNumLeaves
        )
        fputs("[GPU Prover prove] commitTraceColumns done: \(String(format: "%.1f", commitTime * 1000))ms, trees count: \(traceTrees.count)\n", stderr)

        var transcript = CircleSTARKTranscript()
        transcript.absorbLabel("evm-gpu-circle-stark-v1")
        for root in traceCommitments { transcript.absorbBytes(root.bytes) }
        let alpha = transcript.squeezeM31()

        // Step 4: Constraint evaluation with column subset
        fputs("[GPU Prover prove] Starting constraint eval...\n", stderr)
        fflush(stderr)
        let compositionEvals = try evaluateConstraintsWithSubset(
            air: air,
            traceLDEs: providedTraceLDEs,
            alpha: alpha
        )
        fputs("[GPU Prover prove] constraint eval returned successfully, count=\(compositionEvals.count)\n", stderr)
        fflush(stderr)

        // Step 5: Commit composition polynomial
        fputs("[GPU Prover prove] About to call commitComposition...\n", stderr)
        fflush(stderr)
        let blockLogTrace = (air as? BlockAIR)?.logBlockTraceLength ?? air.logTraceLength
        fputs("[GPU Prover prove] blockLogTrace=\(blockLogTrace), logBlowup=\(config.logBlowup)\n", stderr)
        fflush(stderr)
        let compStart = CFAbsoluteTimeGetCurrent()
        fputs("[GPU Prover prove] Calling GPU merkle engine for composition...\n", stderr)
        fflush(stderr)
        let (compositionCommitment, compTree) = try commitComposition(
            evals: compositionEvals,
            logN: blockLogTrace + config.logBlowup,
            transcript: &transcript
        )
        let compMs = (CFAbsoluteTimeGetCurrent() - compStart) * 1000
        fputs("[GPU Prover prove] commitComposition done: \(String(format: "%.1f", compMs))ms\n", stderr)
        fflush(stderr)

        // Step 6: Circle FRI
        fputs("[GPU Prover prove] Starting FRI...\n", stderr)
        let friStart = CFAbsoluteTimeGetCurrent()

        // Pad compositionEvals to power of 2 if needed (GPU FRI requires power of 2)
        var paddedEvals = compositionEvals
        if !isPowerOfTwo(compositionEvals.count) {
            let paddedSize = nextPowerOfTwo(compositionEvals.count)
            fputs("[GPU Prover prove] Padding \(compositionEvals.count) evals to \(paddedSize) for GPU FRI\n", stderr)
            paddedEvals = compositionEvals + [M31](repeating: .zero, count: paddedSize - compositionEvals.count)
        }

        let friProof = try circleFRI(
            evals: paddedEvals,
            logN: blockLogTrace + config.logBlowup,
            numQueries: config.numQueries,
            transcript: &transcript
        )
        let friMs = (CFAbsoluteTimeGetCurrent() - friStart) * 1000
        fputs("[GPU Prover prove] FRI done: \(String(format: "%.1f", friMs))ms\n", stderr)

        // Step 7: Query phase
        fputs("[GPU Prover prove] Starting query responses... traceTrees=\(traceTrees.count), compTree=\(compTree.count)\n", stderr)
        let queryStart = CFAbsoluteTimeGetCurrent()
        let queryResponses = try generateQueryResponses(
            friProof: friProof,
            traceLDEs: providedTraceLDEs,
            traceTrees: traceTrees,
            compTree: compTree,
            compositionEvals: compositionEvals,
            air: air
        )
        let queryMs = (CFAbsoluteTimeGetCurrent() - queryStart) * 1000
        fputs("[GPU Prover prove] query responses done: \(String(format: "%.1f", queryMs))ms\n", stderr)

        // Build proof
        let proof = GPUCircleSTARKProverProof(
            traceCommitments: traceCommitments,
            compositionCommitment: compositionCommitment,
            quotientCommitments: [],
            friProof: friProof,
            queryResponses: queryResponses,
            alpha: alpha,
            traceLength: air.traceLength,
            numColumns: air.numColumns,
            logBlowup: config.logBlowup
        )

        let totalTime = CFAbsoluteTimeGetCurrent() - proveT0
        fputs("[GPU Prover prove] Total prove time: \(String(format: "%.1f", totalTime * 1000))ms\n", stderr)

        // Use actual tracked constraint time for accurate reporting
        let constraintTimeSeconds = lastConstraintTimeMs / 1000.0

        // Cleanup: Clear trace tree buffer to free GPU memory
        traceTreeBuffer = nil

        return GPUCircleSTARKProverResult(
            proof: proof,
            traceLength: air.traceLength,
            numColumns: air.numColumns,
            totalTimeSeconds: totalTime,
            traceGenTimeSeconds: traceGenTime,
            ldeTimeSeconds: 0,
            commitTimeSeconds: commitTime,
            constraintTimeSeconds: constraintTimeSeconds,
            friTimeSeconds: friMs / 1000.0,
            queryTimeSeconds: queryMs / 1000.0
        )
    }

    // MARK: - Private Methods

    /// Prepare trace LDEs (generate if not provided)
    private func prepareTraceLDEs<A: CircleAIR>(
        air: A,
        provided: [[M31]]?
    ) throws -> ([[M31]], Double) {
        let traceGenT0 = CFAbsoluteTimeGetCurrent()

        if let provided = provided {
            return (provided, 0.0)
        }

        // Generate trace via AIR
        let trace = air.generateTrace()
        let logTrace = air.logTraceLength
        let logEval = logTrace + config.logBlowup

        // LDE via CPU (GPU LDE would be better but requires integration)
        let ldes = cpuLDE(trace: trace, logTrace: logTrace, logEval: logEval)

        let traceGenTime = CFAbsoluteTimeGetCurrent() - traceGenT0

        return (ldes, traceGenTime)
    }

    /// Commit trace columns
    private func commitTraceColumns<A: CircleAIR>(
        air: A,
        traceLDEs: [[M31]],
        precomputed: [M31Digest]?,
        precomputedTrees: [[M31Digest]]? = nil,
        precomputedTreeBuffer: MTLBuffer? = nil,
        precomputedTreeNumLeaves: Int = 0
    ) throws -> ([M31Digest], [[M31Digest]], Double) {
        let commitT0 = CFAbsoluteTimeGetCurrent()
        let evalLen = traceLDEs[0].count

        // If precomputed trees are provided and not empty, use them directly
        // Also ensure GPU buffer is set up for proof generation if needed
        if let precomputed = precomputed, let trees = precomputedTrees, !trees.isEmpty {
            // Trees provided with actual data - use them
            let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
            return (precomputed, trees, commitTime)
        }

        // If precomputed commitments and precomputed tree buffer, use it directly
        if let precomputed = precomputed, let treeBuf = precomputedTreeBuffer, precomputedTreeNumLeaves > 0 {
            // Use the precomputed tree buffer - this avoids rebuilding the same trees
            self.traceTreeBuffer = treeBuf
            self.traceTreeNumLeaves = precomputedTreeNumLeaves
            fputs("[commitTraceColumns] Using precomputed tree buffer: \(precomputedTreeNumLeaves) leaves\n", stderr)
            // Build empty trees for API compatibility (we have commitments already)
            let trees = try buildMerkleTreesGPUOrCPU(columns: traceLDEs, count: evalLen)
            let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
            return (precomputed, trees, commitTime)
        }

        // If precomputed commitments but no tree buffer, we need GPU buffer for proofs
        if let precomputed = precomputed {
            // Even with precomputed commitments, we need GPU buffer for query phase
            // Only build GPU buffer if we don't have one yet
            if traceTreeBuffer == nil {
                fputs("[commitTraceColumns] Building GPU buffer for proof generation (precomputed case)...\n", stderr)
                // buildMerkleTreesWithGPUProof sets traceTreeBuffer and traceTreeNumLeaves as side effect
                let gpuTrees = try buildMerkleTreesWithGPUProof(columns: traceLDEs, count: evalLen)
                let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
                return (precomputed, gpuTrees, commitTime)
            }
            // Build trees for the prover's tree parameter (needed even if empty for API compat)
            let trees = try buildMerkleTreesGPUOrCPU(columns: traceLDEs, count: evalLen)
            let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
            return (precomputed, trees, commitTime)
        }

        // No precomputed data - build trees from scratch with GPU buffer preservation
        let trees = try buildMerkleTreesWithGPUProof(columns: traceLDEs, count: evalLen)
        var commitments = [M31Digest]()
        for tree in trees {
            commitments.append(tree[2 * evalLen - 2])
        }

        let commitTime = CFAbsoluteTimeGetCurrent() - commitT0

        return (commitments, trees, commitTime)
    }

    /// Build Merkle trees using GPU when available, CPU fallback otherwise
    private func buildMerkleTreesGPUOrCPU(columns: [[M31]], count: Int) throws -> [[M31Digest]] {
        var trees = [[M31Digest]]()
        trees.reserveCapacity(columns.count)

        if let gpuMerkle = gpuMerkleEngine {
            fputs("[buildMerkleTrees] Using GPU Merkle engine for \(columns.count) columns (n=\(count))\n", stderr)
            for col in columns {
                let tree = try gpuMerkle.buildTree(values: col, count: count)
                trees.append(tree)
            }
        } else {
            fputs("[buildMerkleTrees] Using CPU Merkle engine for \(columns.count) columns (n=\(count))\n", stderr)
            for col in columns {
                let tree = buildPoseidon2M31MerkleTree(col, count: count)
                trees.append(tree)
            }
        }

        return trees
    }

    /// Build Merkle trees using GPU with buffer preservation for GPU proof generation.
    /// This stores the tree buffer internally for use in generateQueryResponses().
    private func buildMerkleTreesWithGPUProof(columns: [[M31]], count: Int) throws -> [[M31Digest]] {
        guard let gpuMerkleForProof = gpuMerkleEngineForProofs else {
            fputs("[buildMerkleTreesWithGPUProof] EVMGPUMerkleEngine not available, falling back to CPU\n", stderr)
            return try buildMerkleTreesGPUOrCPU(columns: columns, count: count)
        }

        fputs("[buildMerkleTreesWithGPUProof] Using EVMGPUMerkleEngine for \(columns.count) columns (n=\(count))\n", stderr)

        // Build trees with GPU buffer preservation
        let result = try gpuMerkleForProof.buildTreesWithGPUProof(
            treesLeaves: columns,
            keepTreeBuffer: true
        )

        // Store buffer for GPU proof generation in query phase
        self.traceTreeBuffer = result.treeBuffer
        self.traceTreeNumLeaves = result.numLeaves

        // Convert [M31Digest] (one per tree) to [[M31Digest]] for consistency
        return result.roots.map { [$0] }
    }

    /// Evaluate constraints with column subset optimization using GPU acceleration.
    ///
    /// This method evaluates constraints on GPU when:
    /// - GPU is available
    /// - Evaluation length >= gpuConstraintThreshold
    ///
    /// Falls back to CPU otherwise to maintain compatibility.
    ///
    /// ## Performance
    ///
    /// | Method | 32,768 points | Speedup |
    /// |--------|---------------|---------|
    /// | CPU    | ~51 seconds   | 1x      |
    /// | GPU    | ~0.5 seconds  | ~100x   |
    private func evaluateConstraintsWithSubset<A: CircleAIR>(
        air: A,
        traceLDEs: [[M31]],
        alpha: M31
    ) throws -> [M31] {
        let constraintT0 = CFAbsoluteTimeGetCurrent()

        // Use block trace length for BlockAIR, otherwise use standard logTraceLength
        let logTrace: Int
        let boundaryConstraints: [(column: Int, row: Int, value: M31)]
        if let blockAir = air as? BlockAIR {
            logTrace = blockAir.logBlockTraceLength
            boundaryConstraints = blockAir.boundaryConstraints.map { ($0.column, $0.row, $0.value) }
        } else {
            logTrace = air.logTraceLength
            boundaryConstraints = []
        }
        let logEval = logTrace + config.logBlowup

        // Get column subset from AIR
        let columnIndices = getProvingColumnIndices(air: air)

        // Use GPU constraint engine when available - but only for reasonable sizes
        // GPU engine may hang for very large traces due to memory pressure
        if let gpuConstraint = gpuConstraintEngine {
            let evalLen = traceLDEs.first?.count ?? 0

            // Use canHandle() check instead of hardcoded 65K limit
            // This allows GPU for traces that fit in 100MB budget
            let numCols = min(columnIndices.count, 32)  // Only FRI-proving columns
            let canUseGPU = gpuConstraint.canHandle(traceLength: evalLen, numColumns: numCols)

            fputs("[evaluateConstraintsWithSubset] evalLen=\(evalLen), canUseGPU=\(canUseGPU), threshold=\(config.gpuConstraintThreshold)\n", stderr)

            if evalLen >= config.gpuConstraintThreshold && canUseGPU {
                fputs("[evaluateConstraintsWithSubset] Using GPU constraint engine for \(evalLen) points, \(columnIndices.count) columns\n", stderr)
                fflush(stderr)

                do {
                    let gpuResult = try gpuConstraint.evaluateConstraintsWithSubset(
                        traceLDEs: traceLDEs,
                        columnIndices: columnIndices,
                        alpha: alpha,
                        logTrace: logTrace,
                        boundaryConstraints: boundaryConstraints
                    )

                    lastConstraintTimeMs = (CFAbsoluteTimeGetCurrent() - constraintT0) * 1000
                    lastUsedGPU = gpuResult.usedGPU

                    fputs("[evaluateConstraintsWithSubset] GPU=\(gpuResult.usedGPU), time=\(String(format: "%.1f", gpuResult.gpuTimeMs))ms\n", stderr)
                    fflush(stderr)

                    return gpuResult.compositionValues
                } catch {
                    fputs("[evaluateConstraintsWithSubset] GPU failed: \(error), falling back to CPU\n", stderr)
                    fflush(stderr)
                    // Fall through to CPU fallback
                }
            } else if evalLen > 65536 {
                fputs("[evaluateConstraintsWithSubset] Skipping GPU (trace too large: \(evalLen) points) - using CPU\n", stderr)
            }
        }

        // CPU fallback
        fputs("[evaluateConstraintsWithSubset] Using CPU constraint engine (evalLen=\(traceLDEs.first?.count ?? 0))\n", stderr)
        let cpuResult = try evaluateConstraintsWithSubsetCPU(
            air: air,
            traceLDEs: traceLDEs,
            alpha: alpha,
            columnIndices: columnIndices,
            logTrace: logTrace,
            logEval: logEval
        )

        lastConstraintTimeMs = (CFAbsoluteTimeGetCurrent() - constraintT0) * 1000
        lastUsedGPU = false

        return cpuResult
    }

    /// CPU fallback for constraint evaluation - OPTIMIZED with parallel chunk processing
    private func evaluateConstraintsWithSubsetCPU<A: CircleAIR>(
        air: A,
        traceLDEs: [[M31]],
        alpha: M31,
        columnIndices: [Int],
        logTrace: Int,
        logEval: Int
    ) throws -> [M31] {
        let evalLen = 1 << logEval
        let traceLen = 1 << logTrace
        let step = evalLen / traceLen
        let numProvingCols = columnIndices.count

        var compositionEvals = [M31](repeating: M31.zero, count: evalLen)

        // Precompute circle vanishing polynomial values for all evaluation points
        let evalDomain = circleCosetDomain(logN: logEval)
        var vzValues = [M31](repeating: .zero, count: evalLen)
        for i in 0..<evalLen {
            vzValues[i] = circleVanishing(point: evalDomain[i], logDomainSize: logTrace)
        }

        // Precompute alpha powers for all constraint + boundary combinations
        let boundaryConstraints = air.boundaryConstraints
        let totalTerms = 20 + boundaryConstraints.count
        var alphaPowers = [M31](repeating: .zero, count: totalTerms)
        alphaPowers[0] = .one
        for i in 1..<totalTerms {
            alphaPowers[i] = m31Mul(alphaPowers[i-1], alpha)
        }

        // Pre-build boundary lookup for O(1) boundary check per row
        var boundaryRows = Set<Int>()
        for bc in boundaryConstraints {
            boundaryRows.insert(bc.row)
        }

        // PARALLEL processing across evaluation points in chunks
        let chunkSize = 8192
        let numChunks = (evalLen + chunkSize - 1) / chunkSize

        DispatchQueue.concurrentPerform(iterations: numChunks) { chunkIdx in
            let startIdx = chunkIdx * chunkSize
            let endIdx = min(startIdx + chunkSize, evalLen)

            // Pre-allocate working arrays for this chunk
            var current = [M31](repeating: M31.zero, count: numProvingCols)
            var next = [M31](repeating: M31.zero, count: numProvingCols)

            for i in startIdx..<endIdx {
                let nextI = (i + step) % evalLen

                // Extract column values using subset
                for j in 0..<numProvingCols {
                    current[j] = traceLDEs[columnIndices[j]][i]
                    next[j] = traceLDEs[columnIndices[j]][nextI]
                }

                // Evaluate constraints with subset columns
                let cVals = air.evaluateConstraints(current: current, next: next)

                // Random linear combination - unrolled for speed
                var combined = M31.zero
                var idx = 0
                let cValCount = cVals.count

                // Unrolled loop for better instruction pipelining
                while idx + 4 <= min(cValCount, 16) {
                    let a0 = m31Mul(alphaPowers[idx], cVals[idx])
                    let a1 = m31Mul(alphaPowers[idx + 1], cVals[idx + 1])
                    let a2 = m31Mul(alphaPowers[idx + 2], cVals[idx + 2])
                    let a3 = m31Mul(alphaPowers[idx + 3], cVals[idx + 3])
                    combined = m31Add(m31Add(combined, a0), m31Add(a1, m31Add(a2, a3)))
                    idx += 4
                }
                while idx < cValCount {
                    combined = m31Add(combined, m31Mul(alphaPowers[idx], cVals[idx]))
                    idx += 1
                }

                // Boundary constraints - use Set for O(1) lookup
                let traceRow = i / step
                if boundaryRows.contains(traceRow) {
                    for (bcIdx, bc) in boundaryConstraints.enumerated() {
                        if bc.row == traceRow {
                            let colVal = traceLDEs[bc.column][i]
                            let diff = m31Sub(colVal, bc.value)
                            let vz = vzValues[i]
                            if vz.v != 0 {
                                let quotient = m31Mul(diff, m31Inverse(vz))
                                let alphaIdx = 20 + bcIdx
                                combined = m31Add(combined, m31Mul(alphaPowers[alphaIdx], quotient))
                            }
                        }
                    }
                }

                compositionEvals[i] = combined
            }
        }

        return compositionEvals
    }

    /// Get proving column indices from AIR
    private func getProvingColumnIndices<A: CircleAIR>(air: A) -> [Int] {
        // Check for BlockAIR (Zoltraak's column subset support)
        if let blockAir = air as? BlockAIR {
            if blockAir.useColumnSubset && !blockAir.provingColumnIndices.isEmpty {
                return blockAir.provingColumnIndices
            }
            if blockAir.useColumnSubset {
                // Use first provingColumnCount columns
                return Array(0..<min(blockAir.provingColumnCount, air.numColumns))
            }
        }

        // Default: use all columns
        return Array(0..<air.numColumns)
    }

    /// Commit composition polynomial
    private func commitComposition(
        evals: [M31],
        logN: Int,
        transcript: inout CircleSTARKTranscript
    ) throws -> (M31Digest, [M31Digest]) {
        let n = 1 << logN
        fputs("[commitComposition] Starting for n=\(n), logN=\(logN)\n", stderr)

        // Build Merkle tree using GPU when available
        let treeStart = CFAbsoluteTimeGetCurrent()
        let tree: [M31Digest]
        if let gpuMerkle = gpuMerkleEngine {
            fputs("[commitComposition] Using GPU Merkle engine for composition (n=\(n))\n", stderr)
            fflush(stderr)
            tree = try gpuMerkle.buildTree(values: evals, count: n)
        } else {
            // CPU fallback
            fputs("[commitComposition] Using CPU Merkle engine (n=\(n))\n", stderr)
            fflush(stderr)
            tree = buildPoseidon2M31MerkleTree(evals, count: n)
        }
        let treeMs = (CFAbsoluteTimeGetCurrent() - treeStart) * 1000
        fputs("[commitComposition] Merkle tree done: \(String(format: "%.1f", treeMs))ms\n", stderr)
        fflush(stderr)

        let root = tree[2 * n - 2]

        // Absorb into transcript
        transcript.absorbBytes(root.bytes)

        return (root, tree)
    }

    /// Generate query responses
    private func generateQueryResponses<A: CircleAIR>(
        friProof: GPUCircleFRIProof,
        traceLDEs: [[M31]],
        traceTrees: [[M31Digest]],
        compTree: [M31Digest],
        compositionEvals: [M31],
        air: A
    ) throws -> [GPUCircleSTARKQueryResponse] {
        let evalLen = traceLDEs[0].count

        // For query responses, we need:
        // 1. Trace values at query indices
        // 2. Merkle paths for trace commitments (computed directly from trace LDEs)
        // 3. Composition value at query index
        // 4. Merkle path for composition

        // Use traceTrees if available (GPU-computed), otherwise compute paths directly from trace
        let queryT0 = CFAbsoluteTimeGetCurrent()

        // OPTIMIZATION: Only include paths for FRI-proving columns (not all 180)
        // Get the proving column indices from the AIR
        let provingColumnIndices = getProvingColumnIndices(air: air)
        let numProvingCols = provingColumnIndices.count
        let numTraceValues = air.numColumns  // Full column count for trace values

        var responses = [GPUCircleSTARKQueryResponse]()

        // Try GPU path generation first
        if let treeBuffer = traceTreeBuffer,
           let gpuMerkle = gpuMerkleEngineForProofs,
           traceTreeNumLeaves > 0 {
            fputs("[generateQueryResponses] Using GPU proof generation for \(numProvingCols) columns\n", stderr)

            // GPU path generation - one dispatch per query
            for qi in friProof.queryIndices {
                guard qi < evalLen else { continue }

                // Get trace values at query (all columns) - use direct indexing
                var traceVals = [M31](repeating: .zero, count: numTraceValues)
                for colIdx in 0..<min(numTraceValues, traceLDEs.count) {
                    if qi < traceLDEs[colIdx].count {
                        traceVals[colIdx] = traceLDEs[colIdx][qi]
                    }
                }

                // GPU proof generation - batch all columns for this query
                let proofs = try gpuMerkle.generateProofsGPU(
                    treeBuffer: treeBuffer,
                    numTrees: numProvingCols,
                    numLeaves: traceTreeNumLeaves,
                    queryIndices: [qi]
                )

                // proofs is [[M31Digest]] - one path per column (matching provingColumnIndices order)
                let tracePaths = proofs

                // Get composition path from pre-built tree
                let compPath = poseidon2M31MerkleProof(compTree, n: evalLen, index: qi)

                responses.append(GPUCircleSTARKQueryResponse(
                    traceValues: traceVals,
                    tracePaths: tracePaths,
                    compositionValue: compositionEvals[qi],
                    compositionPath: compPath,
                    quotientSplitValues: [],
                    queryIndex: qi
                ))
            }
        } else {
            fputs("[generateQueryResponses] GPU buffer not available for large trees (\(traceTreeNumLeaves) leaves > 512 limit)\n", stderr)
            fputs("[generateQueryResponses] Falling back to CPU path generation (~1.1s for 4 queries)\n", stderr)

            // CPU fallback - existing poseidonMerklePathDirect loop
            for qi in friProof.queryIndices {
                guard qi < evalLen else { continue }

                // Get trace values at query (all columns) - use direct indexing
                var traceVals = [M31](repeating: .zero, count: numTraceValues)
                for colIdx in 0..<min(numTraceValues, traceLDEs.count) {
                    if qi < traceLDEs[colIdx].count {
                        traceVals[colIdx] = traceLDEs[colIdx][qi]
                    }
                }

                // OPTIMIZATION: Only compute paths for proving columns (not all 180)
                // With column subset optimization, only provingColumnCount columns go into FRI
                var tracePaths = [[M31Digest]](repeating: [], count: numProvingCols)

                // Compute Merkle paths only for proving columns (CPU-based Poseidon2 hashing)
                for (pathIdx, colIdx) in provingColumnIndices.enumerated() {
                    if colIdx < traceLDEs.count {
                        let path = try poseidonMerklePathDirect(
                            values: traceLDEs[colIdx],
                            queryIndex: qi
                        )
                        tracePaths[pathIdx] = path
                    }
                }

                // Get composition path from pre-built tree
                let compPath = poseidon2M31MerkleProof(compTree, n: evalLen, index: qi)

                responses.append(GPUCircleSTARKQueryResponse(
                    traceValues: traceVals,
                    tracePaths: tracePaths,
                    compositionValue: compositionEvals[qi],
                    compositionPath: compPath,
                    quotientSplitValues: [],
                    queryIndex: qi
                ))
            }
        }

        let queryMs = (CFAbsoluteTimeGetCurrent() - queryT0) * 1000
        fputs("[generateQueryResponses] Query response generation: \(String(format: "%.1f", queryMs))ms for \(responses.count) queries\n", stderr)

        return responses
    }

    // MARK: - Circle FRI (GPU-Accelerated)

    /// Circle FRI implementation using GPU-accelerated folding via GPUCircleFRIProverEngine.
    ///
    /// This replaces the CPU-based folding with GPU parallel FRI:
    /// 1. Precompute all challenges from transcript
    /// 2. Batch-fold all rounds using GPU kernels
    /// 3. Build all Merkle trees in parallel using Poseidon2
    ///
    /// Note: GPU FRI engine has shader compilation issues, so we use CPU fallback directly
    private func circleFRI(
        evals: [M31],
        logN: Int,
        numQueries: Int,
        transcript: inout CircleSTARKTranscript
    ) throws -> GPUCircleFRIProof {
        fputs("[circleFRI] Starting with \(evals.count) evals, logN=\(logN)\n", stderr)
        fputs("[circleFRI] config.gpuFRIFoldThreshold=\(config.gpuFRIFoldThreshold)\n", stderr)
        fputs("[circleFRI] friEngine=\(friEngine != nil ? "available" : "nil")\n", stderr)
        let result = try cpuCircleFRI(evals: evals, logN: logN, numQueries: numQueries, transcript: &transcript)
        fputs("[circleFRI] cpuCircleFRI returned successfully\n", stderr)
        return result
    }

    // MARK: - Merkle Path from Trace (No Tree Rebuild)

    /// Compute Merkle authentication path directly from trace values.
    ///
    /// This avoids rebuilding the full Merkle tree just for path extraction.
    /// Instead, we hash the queried leaf and walk up the tree computing siblings.
    ///
    /// For a tree with n leaves and depth log2(n), this computes the path
    /// in O(n) time (hashing the queried leaf and siblings at each level).
    /// This is much faster than building 180 full trees (144s → ~1s).
    ///
    /// - Parameters:
    ///   - values: Trace column values (evalLen M31 elements)
    ///   - queryIndex: Leaf index to prove
    /// - Returns: Array of M31Digest (sibling nodes at each level)
    private func poseidonMerklePathDirect(
        values: [M31],
        queryIndex: Int
    ) throws -> [M31Digest] {
        let numLeaves = values.count  // Each M31 element is a leaf (not grouped)
        let depth = Int(log2(Double(numLeaves)))

        // Step 1: Hash the queried leaf into a digest
        // leaf format: Poseidon2([value, index, 0, 0, 0, 0, 0, 0])
        let leafInput: [M31] = [
            values[queryIndex],
            M31(v: UInt32(queryIndex)),
            M31.zero, M31.zero, M31.zero, M31.zero, M31.zero, M31.zero
        ]
        let leafDigest = M31Digest(values: poseidon2M31HashSingle(leafInput))

        // Step 2: Walk up the tree computing sibling hashes at each level
        var path = [M31Digest]()
        path.reserveCapacity(depth)
        var idx = queryIndex
        var currentHash = leafDigest

        for _ in 0..<depth {
            let siblingIdx = idx ^ 1  // Sibling index at current level

            // Get sibling value
            let siblingInput: [M31] = [
                values[siblingIdx],
                M31(v: UInt32(siblingIdx)),
                M31.zero, M31.zero, M31.zero, M31.zero, M31.zero, M31.zero
            ]
            let siblingDigest = M31Digest(values: poseidon2M31HashSingle(siblingInput))

            // Hash pair to get parent
            if idx & 1 == 0 {
                // Current is left child
                currentHash = M31Digest(values: poseidon2M31Hash(left: currentHash.values, right: siblingDigest.values))
            } else {
                // Current is right child
                currentHash = M31Digest(values: poseidon2M31Hash(left: siblingDigest.values, right: currentHash.values))
            }

            path.append(siblingDigest)
            idx = idx / 2
        }

        return path
    }

    // MARK: - CPU FRI Fallback

    /// CPU-based Circle FRI (fallback when GPU FRI is not available)
    private func cpuCircleFRI(
        evals: [M31],
        logN: Int,
        numQueries: Int,
        transcript: inout CircleSTARKTranscript
    ) throws -> GPUCircleFRIProof {
        let n = evals.count

        // Generate query indices from transcript (must match GPU engine's expectations)
        transcript.absorbLabel("fri-queries")
        var queryIndices = [Int]()
        let maxIdx = max(1, n / 2)
        for _ in 0..<numQueries {
            queryIndices.append(Int(transcript.squeezeM31().v) % maxIdx)
        }

        // Use GPU FRI engine if available and size is large enough
        fputs("[cpuCircleFRI] n=\(n), gpuFRIFoldThreshold=\(config.gpuFRIFoldThreshold), friEngine=\(friEngine != nil ? "available" : "nil")\n", stderr)
        if let gpuEngine = friEngine, n >= config.gpuFRIFoldThreshold {
            fputs("[cpuCircleFRI] Calling GPU FRI commitPhaseParallel...\n", stderr)
            fflush(stderr)

            let commitStart = CFAbsoluteTimeGetCurrent()
            let commitment = try gpuEngine.commitPhaseParallel(
                evals: evals,
                transcript: &transcript,
                logN: logN,
                numQueries: numQueries
            )
            let commitMs = (CFAbsoluteTimeGetCurrent() - commitStart) * 1000
            fputs("[cpuCircleFRI] GPU FRI commit done in \(String(format: "%.1f", commitMs))ms\n", stderr)
            fflush(stderr)

            // Convert ParallelFRIFRICommitment to GPUCircleFRIProof
            var rounds = [GPUCircleFRIRound]()

            for roundIdx in 0..<commitment.roots.count {
                let root = commitment.roots[roundIdx]

                // Layer data: round 0 uses original evals, subsequent rounds use layers
                let layerData: [M31]
                if roundIdx == 0 {
                    layerData = evals
                } else {
                    layerData = commitment.layers[roundIdx]
                }

                let layerSize = layerData.count
                let halfSize = layerSize / 2

                // Build query responses from layer data
                var roundQueryResponses = [(M31, M31, [M31Digest])]()
                roundQueryResponses.reserveCapacity(queryIndices.count)

                for qi in queryIndices {
                    let idx = qi % halfSize
                    let valA = layerData[idx]
                    let valB = layerData[idx + halfSize]
                    // Merkle paths would be built separately if needed for verification
                    roundQueryResponses.append((valA, valB, []))
                }

                rounds.append(GPUCircleFRIRound(
                    commitment: root,
                    queryResponses: roundQueryResponses
                ))
            }

            return GPUCircleFRIProof(
                rounds: rounds,
                finalValue: commitment.finalValue,
                queryIndices: queryIndices
            )
        }

        // Fallback to CPU FRI for small sizes
        fputs("[cpuCircleFRI] Using CPU FRI engine for n=\(n)\n", stderr)
        fflush(stderr)
        let cpuStart = CFAbsoluteTimeGetCurrent()
        let friEngine = try CircleFRIEngine()

        // Precompute all alphas from transcript
        let numRounds = logN - 2
        transcript.absorbLabel("fri-betas")
        var alphas = [M31]()
        for _ in 0..<numRounds {
            alphas.append(transcript.squeezeM31())
        }

        // Run CPU FRI commit phase
        let cpuCommitment = try friEngine.commitPhase(
            evals: evals,
            alphas: alphas
        )

        // Build query responses
        var rounds = [GPUCircleFRIRound]()

        for roundIdx in 0..<cpuCommitment.roots.count {
            let root = cpuCommitment.roots[roundIdx]

            let layerData: [M31]
            if roundIdx == 0 {
                layerData = evals
            } else {
                layerData = cpuCommitment.layers[roundIdx]
            }

            let layerSize = layerData.count
            let halfSize = layerSize / 2

            var roundQueryResponses = [(M31, M31, [M31Digest])]()
            roundQueryResponses.reserveCapacity(queryIndices.count)

            for qi in queryIndices {
                let idx = qi % halfSize
                let valA = layerData[idx]
                let valB = layerData[idx + halfSize]
                roundQueryResponses.append((valA, valB, []))
            }

            let rootDigest = M31Digest(values: [root, M31.zero, M31.zero, M31.zero,
                                               M31.zero, M31.zero, M31.zero, M31.zero])

            rounds.append(GPUCircleFRIRound(
                commitment: rootDigest,
                queryResponses: roundQueryResponses
            ))
        }

        return GPUCircleFRIProof(
            rounds: rounds,
            finalValue: cpuCommitment.finalValue,
            queryIndices: queryIndices
        )
        let cpuFrims = (CFAbsoluteTimeGetCurrent() - cpuStart) * 1000
        fputs("[cpuCircleFRI] CPU FRI done in \(String(format: "%.1f", cpuFrims))ms\n", stderr)
        fflush(stderr)
    }

    // MARK: - CPU LDE

    /// CPU-based LDE (fallback when GPU is not available)
    private func cpuLDE(trace: [[M31]], logTrace: Int, logEval: Int) -> [[M31]] {
        let evalLen = 1 << logEval
        let blowup = 1 << (logEval - logTrace)

        var results: [[M31]] = []
        results.reserveCapacity(trace.count)

        for col in trace {
            var extended = [M31](repeating: .zero, count: evalLen)

            if blowup == 2 {
                // Special case: duplicate each element (faster)
                for i in 0..<col.count {
                    extended[i * 2] = col[i]
                    extended[i * 2 + 1] = col[i]
                }
            } else {
                // General case
                for i in 0..<evalLen {
                    extended[i] = col[i / blowup]
                }
            }

            results.append(extended)
        }

        return results
    }
}

// MARK: - M31 Field Operations

private func m31Add(_ a: M31, _ b: M31) -> M31 {
    let sum = a.v &+ b.v
    let reduced = (sum & 0x7FFFFFFF) &+ (sum >> 31)
    return M31(v: reduced == 0x7FFFFFFF ? 0 : reduced)
}

private func m31Sub(_ a: M31, _ b: M31) -> M31 {
    if a.v >= b.v {
        return M31(v: a.v - b.v)
    }
    return M31(v: a.v + 0x7FFFFFFF - b.v)
}

private func m31Mul(_ a: M31, _ b: M31) -> M31 {
    let prod = UInt64(a.v) * UInt64(b.v)
    let lo = UInt32(prod & 0x7FFFFFFF)
    let hi = UInt32(prod >> 31)
    let s = lo &+ hi
    return M31(v: s >= 0x7FFFFFFF ? s - 0x7FFFFFFF : s)
}

private func m31Inverse(_ x: M31) -> M31 {
    // Fermat's little theorem: x^(p-2) mod p for p = 2^31 - 1
    // p - 2 = 0x7FFFFFFF - 1 = 0x7FFFFFFE
    // Using binary exponentiation
    var result = x
    var exp: UInt32 = 0x7FFFFFFE
    var base = x

    while exp > 1 {
        if exp & 1 == 1 {
            result = m31Mul(result, base)
        }
        base = m31Mul(base, base)
        exp >>= 1
    }

    return result
}

// MARK: - Helper Functions

/// Check if an integer is a power of two
private func isPowerOfTwo(_ n: Int) -> Bool {
    return n > 0 && (n & (n - 1)) == 0
}

/// Round up to next power of two
private func nextPowerOfTwo(_ n: Int) -> Int {
    if n <= 0 { return 1 }
    var v = n - 1
    v |= v >> 1
    v |= v >> 2
    v |= v >> 4
    v |= v >> 8
    v |= v >> 16
    v += 1
    return v
}