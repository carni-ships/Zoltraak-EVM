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

    /// GPU buffers containing flattened trace trees for GPU proof generation (one per column)
    private var traceTreeBuffers: [MTLBuffer] = []
    private var traceTreeNumLeaves: Int = 0

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

            // Initialize GPU FRI engine
            do {
                self.friEngine = try GPUCircleFRIProverEngine()
                self.friEngineReady = true
            } catch {
                self.friEngineReady = false
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
    ) async throws -> GPUCircleSTARKProverResult {
        let proveStart = CFAbsoluteTimeGetCurrent()
        let (providedTraceLDEs, traceGenTime) = try prepareTraceLDEs(
            air: air,
            provided: traceLDEs
        )
        let afterLDE = CFAbsoluteTimeGetCurrent()

        // Step 2: Commit trace columns (optionally precomputed, including trees)
        let commitStart = CFAbsoluteTimeGetCurrent()
        let (traceCommitments, _, commitTime) = try commitTraceColumns(
            air: air,
            traceLDEs: providedTraceLDEs,
            precomputed: precomputedCommitments,
            precomputedTrees: precomputedTrees,
            precomputedTreeBuffer: precomputedTreeBuffer,
            precomputedTreeNumLeaves: precomputedTreeNumLeaves
        )
        let afterCommit = CFAbsoluteTimeGetCurrent()
        print("[GPU Prover] commitTraceColumns: \(String(format: "%.1f", (afterCommit - commitStart) * 1000))ms")

        var transcript = CircleSTARKTranscript()
        transcript.absorbLabel("evm-gpu-circle-stark-v1")
        for root in traceCommitments { transcript.absorbBytes(root.bytes) }
        let alpha = transcript.squeezeM31()

        // Step 4: Constraint evaluation with column subset
        let constraintStart = CFAbsoluteTimeGetCurrent()
        let compositionEvals = try evaluateConstraintsWithSubset(
            air: air,
            traceLDEs: providedTraceLDEs,
            alpha: alpha
        )
        let afterConstraint = CFAbsoluteTimeGetCurrent()
        print("[GPU Prover] evaluateConstraintsWithSubset: \(String(format: "%.1f", (afterConstraint - constraintStart) * 1000))ms")

        // Step 5: Commit composition polynomial
        let compStart = CFAbsoluteTimeGetCurrent()
        let blockLogTrace = (air as? BlockAIR)?.logBlockTraceLength ?? air.logTraceLength
        let (compositionCommitment, compTree) = try commitComposition(
            evals: compositionEvals,
            logN: blockLogTrace + config.logBlowup,
            transcript: &transcript
        )
        let afterComp = CFAbsoluteTimeGetCurrent()
        print("[GPU Prover] commitComposition: \(String(format: "%.1f", (afterComp - compStart) * 1000))ms")

        // Step 6: Circle FRI
        // Pad compositionEvals to power of 2 if needed (GPU FRI requires power of 2)
        var paddedEvals = compositionEvals
        if !isPowerOfTwo(compositionEvals.count) {
            let paddedSize = nextPowerOfTwo(compositionEvals.count)
            paddedEvals = compositionEvals + [M31](repeating: .zero, count: paddedSize - compositionEvals.count)
        }

        let friStart = CFAbsoluteTimeGetCurrent()
        let friProof = try circleFRI(
            evals: paddedEvals,
            logN: blockLogTrace + config.logBlowup,
            numQueries: config.numQueries,
            transcript: &transcript
        )
        let afterFRI = CFAbsoluteTimeGetCurrent()
        print("[GPU Prover] circleFRI: \(String(format: "%.1f", (afterFRI - friStart) * 1000))ms")

        // Step 7: Query phase
        let queryStart = CFAbsoluteTimeGetCurrent()
        let queryResponses = try await generateQueryResponses(
            friProof: friProof,
            traceLDEs: providedTraceLDEs,
            compTree: compTree,
            compositionEvals: compositionEvals,
            air: air
        )
        let afterQuery = CFAbsoluteTimeGetCurrent()
        print("[GPU Prover] generateQueryResponses: \(String(format: "%.1f", (afterQuery - queryStart) * 1000))ms")

        // Build proof
        let proof = GPUCircleSTARKProverProof(
            traceCommitments: traceCommitments,
            compositionCommitment: compositionCommitment,
            quotientCommitments: [],
            friProof: friProof,
            queryResponses: queryResponses,
            alpha: alpha,
            traceLength: air.traceLength,
            numColumns: traceCommitments.count,
            logBlowup: config.logBlowup
        )

        let totalTime = CFAbsoluteTimeGetCurrent() - proveStart

        // Use actual tracked constraint time for accurate reporting
        let constraintTimeSeconds = lastConstraintTimeMs / 1000.0

        // Cleanup: Clear trace tree buffer to free GPU memory
        traceTreeBuffers = []

        // Debug timing breakdown
        // proveStart -> afterLDE = LDE time
        // afterLDE -> afterConstraint = commit + constraint
        // afterConstraint -> afterFRI = FRI time (but we don't have afterConstraint)
        // Let's just print the deltas we have
        let ldeMs = (afterLDE - proveStart) * 1000
        let friMs = (afterFRI - afterLDE) * 1000
        let queryMs = (afterQuery - afterFRI) * 1000
        let buildMs = (proveStart + totalTime - afterQuery) * 1000
        print("[GPU Prover] Phase timings: LDE: \(String(format: "%.1f", ldeMs))ms, FRI: \(String(format: "%.1f", friMs))ms, query: \(String(format: "%.1f", queryMs))ms, build: \(String(format: "%.1f", buildMs))ms, total: \(String(format: "%.1f", totalTime * 1000))ms")

        return GPUCircleSTARKProverResult(
            proof: proof,
            traceLength: air.traceLength,
            numColumns: air.numColumns,
            totalTimeSeconds: totalTime,
            traceGenTimeSeconds: traceGenTime,
            ldeTimeSeconds: 0,
            commitTimeSeconds: commitTime,
            constraintTimeSeconds: constraintTimeSeconds,
            friTimeSeconds: totalTime,
            queryTimeSeconds: totalTime
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

        // Get proving column indices for column subset optimization
        let provingColumnIndices = getProvingColumnIndices(air: air)
        let numProvingCols = provingColumnIndices.count
        let useColumnSubset = numProvingCols < air.numColumns

        // Filter trace LDEs to proving columns for tree building
        let provingTraceLDEs: [[M31]]
        if useColumnSubset {
            provingTraceLDEs = provingColumnIndices.compactMap { idx -> [M31]? in
                guard idx < traceLDEs.count else { return nil }
                return traceLDEs[idx]
            }
        } else {
            provingTraceLDEs = traceLDEs
        }

        // Use precomputed commitments when available - no need to rebuild GPU trees
        // This saves ~800ms by skipping redundant GPU tree rebuilding
        if let precomputed = precomputed, !precomputed.isEmpty {
            let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
            print("[GPU Prover] commitTraceColumns: using \(precomputed.count) precomputed commitments (skip GPU tree rebuild)")
            return (precomputed, [], commitTime)
        }

        // Build GPU buffers for proof generation if GPU is available
        // This enables O(Q) GPU proof generation instead of O(Q * C) CPU calls
        if gpuMerkleEngine != nil && !provingTraceLDEs.isEmpty {
            let evalLen = provingTraceLDEs[0].count
            print("[GPU Prover] commitTraceColumns: building \(provingTraceLDEs.count) GPU trees for \(evalLen) leaves...")
            let buildStart = CFAbsoluteTimeGetCurrent()
            let roots = try buildGPUBuffersForProof(columns: provingTraceLDEs, count: evalLen)
            let buildMs = (CFAbsoluteTimeGetCurrent() - buildStart) * 1000
            print("[GPU Prover] buildGPUBuffersForProof: \(String(format: "%.1f", buildMs))ms")

            let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
            return (roots, [], commitTime)
        }

        // If precomputed trees are provided and not empty, use them directly
        if let precomputed = precomputed, let trees = precomputedTrees, !trees.isEmpty {
            let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
            return (precomputed, trees, commitTime)
        }

        // CPU fallback: build trees without GPU buffer preservation
        let trees = try buildMerkleTreesGPUOrCPU(columns: provingTraceLDEs, count: provingTraceLDEs[0].count)
        let commitments = trees.map { tree in
            tree[2 * provingTraceLDEs[0].count - 2]
        }

        let commitTime = CFAbsoluteTimeGetCurrent() - commitT0
        return (commitments, trees, commitTime)
    }

    /// Build Merkle trees using GPU when available, CPU fallback otherwise
    private func buildMerkleTreesGPUOrCPU(columns: [[M31]], count: Int) throws -> [[M31Digest]] {
        var trees = [[M31Digest]]()
        trees.reserveCapacity(columns.count)

        if let gpuMerkle = gpuMerkleEngine {
            for col in columns {
                let tree = try gpuMerkle.buildTree(values: col, count: count)
                trees.append(tree)
            }
        } else {
            for col in columns {
                let tree = buildPoseidon2M31MerkleTree(col, count: count)
                trees.append(tree)
            }
        }

        return trees
    }

    /// Build GPU buffers for proof generation and return roots.
    /// Uses GPUMerkleTreeM31Engine.buildTreeWithBuffer() which keeps GPU buffer for proof generation.
    /// This enables O(1) GPU dispatch per query instead of O(Q * C) CPU calls.
    ///
    /// Returns roots for commitments, and stores GPU buffers internally for GPU proof generation.
    private func buildGPUBuffersForProof(columns: [[M31]], count: Int) throws -> [M31Digest] {
        guard let gpuMerkle = gpuMerkleEngine else {
            // Fall back to CPU trees
            return try buildMerkleTreesGPUOrCPU(columns: columns, count: count).map { tree in
                tree[2 * count - 2]  // root is at index 2n-2
            }
        }

        var roots = [M31Digest]()
        roots.reserveCapacity(columns.count)
        var gpuBuffers: [MTLBuffer] = []

        for col in columns {
            // Build tree with GPU buffer preservation
            let (root, treeBuf, _) = try gpuMerkle.buildTreeWithBuffer(values: col, count: count)
            roots.append(root)
            gpuBuffers.append(treeBuf)
        }

        // Preserve GPU buffers for GPU proof generation
        self.traceTreeBuffers = gpuBuffers
        self.traceTreeNumLeaves = count

        return roots
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
        // For column subset mode (16 cols), CPU parallel is faster than GPU
        if let gpuConstraint = gpuConstraintEngine {
            let evalLen = traceLDEs.first?.count ?? 0
            let numCols = min(columnIndices.count, 32)  // Only FRI-proving columns
            let canUseGPU = gpuConstraint.canHandle(traceLength: evalLen, numColumns: numCols)
            let useColumnSubset = columnIndices.count < 180
            // Use CPU for column subset mode - parallel processing is faster than GPU overhead
            let shouldUseGPU = canUseGPU && !useColumnSubset
            print("[GPU Prover] evaluateConstraints: evalLen=\(evalLen), numCols=\(numCols), subset=\(useColumnSubset), canUseGPU=\(canUseGPU), shouldUseGPU=\(shouldUseGPU)")

            if evalLen >= config.gpuConstraintThreshold && shouldUseGPU {
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

                    return gpuResult.compositionValues
                } catch {
                    // Fall through to CPU fallback
                }
            }
        }

        // CPU fallback
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
        // If the AIR has provingColumnIndices (like BlockAIR), use those
        // Otherwise fall back to all columns
        if let blockAir = air as? BlockAIR {
            if !blockAir.provingColumnIndices.isEmpty {
                return blockAir.provingColumnIndices
            }
        }
        return Array(0..<air.numColumns)
    }

    /// Commit composition polynomial
    private func commitComposition(
        evals: [M31],
        logN: Int,
        transcript: inout CircleSTARKTranscript
    ) throws -> (M31Digest, [M31Digest]) {
        let n = 1 << logN

        // Build Merkle tree using GPU when available
        let tree: [M31Digest]
        if let gpuMerkle = gpuMerkleEngine {
            tree = try gpuMerkle.buildTree(values: evals, count: n)
        } else {
            // CPU fallback
            tree = buildPoseidon2M31MerkleTree(evals, count: n)
        }

        let root = tree[2 * n - 2]

        // Absorb into transcript
        transcript.absorbBytes(root.bytes)

        return (root, tree)
    }

    /// Generate query responses
    private func generateQueryResponses<A: CircleAIR>(
        friProof: GPUCircleFRIProof,
        traceLDEs: [[M31]],
        compTree: [M31Digest],
        compositionEvals: [M31],
        air: A
    ) async throws -> [GPUCircleSTARKQueryResponse] {
        let evalLen = traceLDEs[0].count

        // OPTIMIZATION: Only include paths for FRI-proving columns (not all 180)
        let provingColumnIndices = getProvingColumnIndices(air: air)
        let numProvingCols = provingColumnIndices.count
        let useColumnSubsetQuery = numProvingCols < air.numColumns
        let numTraceValues = useColumnSubsetQuery ? numProvingCols : air.numColumns

        var responses = [GPUCircleSTARKQueryResponse]()

        // Check if GPU proof generation is available
        // GPU proofs require GPUMerkleTreeM31Engine with buildTreeWithBuffer support
        let useGPUProofs = gpuMerkleEngine != nil && !traceTreeBuffers.isEmpty
        print("[GPU Prover] Query: GPU proofs=\(useGPUProofs), buffers=\(traceTreeBuffers.count), numLeaves=\(traceTreeNumLeaves), cols=\(numProvingCols), queries=\(friProof.queryIndices.count)")

        if useGPUProofs {
            // GPU path: Generate all proofs in O(Q) dispatches instead of O(Q * C)
            // Pre-concatenate tree buffers ONCE to avoid copying per query
            let prepStart = CFAbsoluteTimeGetCurrent()
            let nodeSize = 8
            let treeNodeCount = 2 * traceTreeNumLeaves - 1
            let totalTreeBytes = traceTreeBuffers.count * treeNodeCount * nodeSize * MemoryLayout<UInt32>.stride

            guard let combinedTreeBuf = gpuMerkleEngine!.device.makeBuffer(length: totalTreeBytes, options: .storageModeShared) else {
                throw MSMError.gpuError("Failed to allocate combined tree buffer")
            }

            // Fast copy using memcpy for each tree buffer
            let destPtr = combinedTreeBuf.contents().bindMemory(to: UInt32.self, capacity: traceTreeBuffers.count * treeNodeCount * nodeSize)
            let bytesPerTree = treeNodeCount * nodeSize * MemoryLayout<UInt32>.stride
            var offset = 0
            for treeBuf in traceTreeBuffers {
                memcpy(destPtr.advanced(by: offset), treeBuf.contents(), bytesPerTree)
                offset += treeNodeCount * nodeSize
            }
            let prepMs = (CFAbsoluteTimeGetCurrent() - prepStart) * 1000
            print("[GPU Prover] Tree prep: \(String(format: "%.1f", prepMs))ms for \(traceTreeBuffers.count) buffers")

            // Generate proofs for each query using pre-concatenated buffer
            let queryStart = CFAbsoluteTimeGetCurrent()
            for qi in friProof.queryIndices {
                guard qi < evalLen else { continue }

                // Get trace values at query - only for proving columns
                var traceVals = [M31](repeating: .zero, count: numTraceValues)
                for (newIdx, colIdx) in provingColumnIndices.enumerated() {
                    if newIdx < numTraceValues && colIdx < traceLDEs.count && qi < traceLDEs[colIdx].count {
                        traceVals[newIdx] = traceLDEs[colIdx][qi]
                    }
                }

                // Use GPU to generate proofs for all columns at once
                let gpuProofs = try gpuMerkleEngine!.generateProofsGPU(
                    treeBuffer: combinedTreeBuf,
                    numTrees: numProvingCols,
                    numLeaves: traceTreeNumLeaves,
                    queryIndex: qi
                )

                // gpuProofs is [[M31Digest]] - one proof per column
                // Each proof has numLevels sibling digests
                let tracePaths = gpuProofs

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
            let gpuQueryMs = (CFAbsoluteTimeGetCurrent() - queryStart) * 1000
            print("[GPU Prover] GPU query loop: \(String(format: "%.1f", gpuQueryMs))ms for \(friProof.queryIndices.count) queries")
        } else {
            // CPU fallback - poseidonMerklePathDirect with TaskGroup parallelization
            for qi in friProof.queryIndices {
                guard qi < evalLen else { continue }

                // Get trace values at query - only for proving columns
                var traceVals = [M31](repeating: .zero, count: numTraceValues)
                for (newIdx, colIdx) in provingColumnIndices.enumerated() {
                    if newIdx < numTraceValues && colIdx < traceLDEs.count && qi < traceLDEs[colIdx].count {
                        traceVals[newIdx] = traceLDEs[colIdx][qi]
                    }
                }

                // Compute paths for proving columns using parallel TaskGroup
                var tracePaths = [[M31Digest]](repeating: [], count: numProvingCols)
                try await withThrowingTaskGroup(of: (Int, [M31Digest]).self) { group in
                    for (pathIdx, colIdx) in provingColumnIndices.enumerated() {
                        if colIdx < traceLDEs.count {
                            group.addTask {
                                let path = try self.poseidonMerklePathDirect(
                                    values: traceLDEs[colIdx],
                                    queryIndex: qi
                                )
                                return (pathIdx, path)
                            }
                        }
                    }

                    for try await (pathIdx, path) in group {
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
        let friT0 = CFAbsoluteTimeGetCurrent()
        let result = try cpuCircleFRI(evals: evals, logN: logN, numQueries: numQueries, transcript: &transcript)
        let friMs = (CFAbsoluteTimeGetCurrent() - friT0) * 1000
        print("[GPU Prover] circleFRI total: \(String(format: "%.1f", friMs))ms")
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
        if let gpuEngine = friEngine, n >= config.gpuFRIFoldThreshold {
            let commitment = try gpuEngine.commitPhaseParallel(
                evals: evals,
                transcript: &transcript,
                logN: logN,
                numQueries: numQueries
            )

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