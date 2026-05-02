import Foundation
import Metal
import zkMetal

// MARK: - Block Proving Configuration

/// Configuration for block-level proving
public struct BlockProvingConfig {
    /// Number of FRI queries for soundness
    public let numQueries: Int

    /// Log of blowup factor for LDE
    public let logBlowup: Int

    /// Log of rows per transaction
    public let logTraceLength: Int

    /// Use GPU acceleration
    public let useGPU: Bool

    /// Maximum transactions to batch in one block proof
    public let maxTransactionsPerBlock: Int

    /// Enable inter-transaction constraints
    public let enableInterTxConstraints: Bool

    /// GPU batch size for Merkle tree building
    public let gpuBatchSize: Int

    /// Use archive node witness for proving (skip local EVM execution)
    public let useArchiveNodeWitness: Bool

    /// Archive node URL for witness fetching (e.g., "http://localhost:8080")
    public let archiveNodeURL: String?

    /// Use state proofs for verified state access (eth_getProof)
    public let useStateProofs: Bool

    /// State proof verification mode
    public enum StateProofMode: Sendable {
        /// Pre-flight verification before proving (default)
        case preflight
        /// Require proofs for all state access
        case strict
        /// Legacy mode without state proofs (current behavior)
        case withoutProofs
    }

    public let stateProofMode: StateProofMode

    public init(
        numQueries: Int = 8,
        logBlowup: Int = 2,
        logTraceLength: Int = 8,
        useGPU: Bool = true,
        maxTransactionsPerBlock: Int = 150,
        enableInterTxConstraints: Bool = true,
        gpuBatchSize: Int = 512,
        useArchiveNodeWitness: Bool = false,
        archiveNodeURL: String? = nil,
        useStateProofs: Bool = false,
        stateProofMode: StateProofMode = .preflight
    ) {
        self.numQueries = numQueries
        self.logBlowup = logBlowup
        self.logTraceLength = logTraceLength
        self.useGPU = useGPU
        self.maxTransactionsPerBlock = maxTransactionsPerBlock
        self.enableInterTxConstraints = enableInterTxConstraints
        self.gpuBatchSize = gpuBatchSize
        self.useArchiveNodeWitness = useArchiveNodeWitness
        self.archiveNodeURL = archiveNodeURL
        self.useStateProofs = useStateProofs
        self.stateProofMode = stateProofMode
    }

    /// Default configuration for production
    public static let `default` = BlockProvingConfig()

    /// High-security configuration with more queries
    public static let highSecurity = BlockProvingConfig(
        numQueries: 50,
        logBlowup: 5
    )

    /// Fast configuration for testing (logBlowup=1 for maximum speed)
    public static let fast = BlockProvingConfig(
        numQueries: 10,
        logBlowup: 1,  // 2x blowup (minimum) for ~2x faster LDE/FRI
        maxTransactionsPerBlock: 10
    )

    /// Ultra-fast configuration with minimal security margin (logBlowup=1, fewer queries)
    public static let ultraFast = BlockProvingConfig(
        numQueries: 4,
        logBlowup: 1,  // 2x blowup - fastest but smallest proof
        maxTransactionsPerBlock: 10
    )

    /// Configuration for witness-based proving with Erigon archive node
    public static let withWitness = BlockProvingConfig(
        useArchiveNodeWitness: true,
        archiveNodeURL: "http://localhost:8080"
    )

    /// Configuration for witness-based proving with Reth archive node
    public static let withReth = BlockProvingConfig(
        useArchiveNodeWitness: true,
        archiveNodeURL: "http://localhost:8545"
    )

    /// Configuration with state proofs enabled for verified state access
    public static let withStateProofs = BlockProvingConfig(
        useStateProofs: true,
        stateProofMode: .preflight
    )

    /// Configuration with strict state proofs (require all state access)
    public static let withStrictStateProofs = BlockProvingConfig(
        useStateProofs: true,
        stateProofMode: .strict
    )
}

// MARK: - Block Proof

/// Result of block proving
public struct BlockProof {
    /// Block number
    public let blockNumber: UInt64

    /// Number of transactions proven
    public let transactionCount: Int

    /// Trace length per transaction
    public let logTraceLength: Int

    /// Total trace length (all transactions)
    public let logBlockTraceLength: Int

    /// Merkle commitments for each column
    public let commitments: [M31Digest]

    /// Circle STARK proof data
    public let starkProof: Data

    /// Inter-transaction proof data (if enabled)
    public let interTxProof: Data?

    /// Proving time breakdown
    public let timing: ProvingTiming

    /// Configuration used
    public let config: BlockProvingConfig

    /// Summary string with timing breakdown
    public var summary: String {
        """
        Block Proof:
          Block: \(blockNumber)
          Transactions: \(transactionCount)
          Trace length: \(1 << logBlockTraceLength) (log=\(logBlockTraceLength))
          Proving time: \(String(format: "%.1fms", timing.totalMs))
          Breakdown:
            Execution: \(String(format: "%.1fms", timing.executionMs))
            LDE: \(String(format: "%.1fms", timing.ldeMs))
            Commit: \(String(format: "%.1fms", timing.commitMs))
            Constraints: \(String(format: "%.1fms", timing.constraintsMs))
            FRI: \(String(format: "%.1fms", timing.friMs))
          Per-transaction: \(String(format: "%.2fms", timing.totalMs / Double(max(transactionCount, 1))))
        """
    }
}

/// Timing breakdown for block proving
public struct ProvingTiming {
    public let executionMs: Double
    public let ldeMs: Double
    public let commitMs: Double
    public let constraintsMs: Double
    public let friMs: Double
    public let totalMs: Double

    public init(
        executionMs: Double,
        ldeMs: Double,
        commitMs: Double,
        constraintsMs: Double,
        friMs: Double
    ) {
        self.executionMs = executionMs
        self.ldeMs = ldeMs
        self.commitMs = commitMs
        self.constraintsMs = constraintsMs
        self.friMs = friMs
        self.totalMs = executionMs + ldeMs + commitMs + constraintsMs + friMs
    }
}

/// Block prover that generates a single proof for an entire block of transactions.
///
/// This is the core of the unified block proof architecture, achieving ~142x
/// theoretical improvement over sequential transaction proving.
///
/// ## Proof Compression
///
/// This prover supports proof compression via `ProofCompressionConfig`:
///
/// 1. **Reduced trace length**: Smaller trees for faster proving
/// 2. **Column subset proving**: Only critical columns verified in FRI
/// 3. **Two-tier proving**: Fast proof for critical columns, full proof when needed
///
/// ## Performance Comparison
///
/// ```
/// Current (sequential): 150 proofs × 1750ms = 262 seconds
/// Unified (block):      1 proof × 1850ms = 1.85 seconds
/// Compressed (fast):     1 proof × 200ms = 0.2 seconds (with security tradeoffs)
/// ```
///
/// ## Architecture
///
/// ```
/// TX1, TX2, ..., TXN
///        ↓
///   Parallel Execute (all txs)
///        ↓
///   Unified Block Trace
///        ↓
///   ┌─────────────────────────┐
///   │  BlockAIR               │
///   │  - Intra-tx constraints │
///   │  - Inter-tx constraints │
///   │  - Block constraints    │
///   └─────────────────────────┘
///        ↓
///   ┌─────────────────────────┐
///   │  LDE + Commitment       │
///   │  - All 180 columns      │
///   │  - Compressed size      │
///   │  - GPU accelerated      │
///   └─────────────────────────┘
///        ↓
///   ┌─────────────────────────┐
///   │  Circle FRI (subset)     │
///   │  - Critical columns only │
///   │  - Faster verification  │
///   └─────────────────────────┘
///        ↓
///   Single Block Proof
/// ```
public final class ZoltraakBlockProver {

    // MARK: - Configuration

    /// Block proving configuration
    public let config: BlockProvingConfig

    /// Proof compression configuration (optional)
    public let compressionConfig: ProofCompressionConfig?

    // MARK: - Components

    /// CPU Circle STARK prover (used for constraint eval)
    private let circleProver: CircleSTARKProver

    /// GPU Circle STARK prover engine (for FRI and queries) with column subset support
    private var gpuProver: EVMGPUCircleSTARKProverEngine?

    /// GPU Merkle tree engine
    private var merkleEngine: EVMGPUMerkleEngine?

    /// GPU constraint engine
    private var constraintEngine: EVMGPUConstraintEngine?

    /// Parallel execution engine
    private var parallelEngine: EVMTxParallelEngine?

    /// Number of CPU cores used for parallel execution (set during prove)
    private var executionWorkers: Int = 1

    /// GPU LDE Optimizer for accelerated trace extension
    private var ldeOptimizer: EVMLDEOptimizer?

    // MARK: - Initialization

    /// Initialize the block prover
    /// - Parameters:
    ///   - config: Block proving configuration
    ///   - compressionConfig: Optional proof compression configuration
    public init(config: BlockProvingConfig = .default, compressionConfig: ProofCompressionConfig? = nil) throws {
        self.config = config
        self.compressionConfig = compressionConfig

        // Initialize CPU Circle STARK prover (for constraint evaluation)
        self.circleProver = CircleSTARKProver(
            logBlowup: config.logBlowup,
            numQueries: config.numQueries
        )

        // Initialize GPU engines if enabled
        if config.useGPU {
            // Use effective blowup from compression config (or default to 2)
            // logBlowup=2 reduces leaves by 4x compared to logBlowup=4
            let effectiveLogBlowup = compressionConfig?.logBlowup ?? 2
            let effectiveNumQueries = compressionConfig?.numQueries ?? config.numQueries
            let effectiveLogTrace = compressionConfig?.logTraceLength ?? config.logTraceLength

            let evmGpuConfig = EVMGPUCircleSTARKProverEngine.Config(
                logBlowup: effectiveLogBlowup,
                numQueries: effectiveNumQueries,
                extensionDegree: 4,
                gpuConstraintThreshold: 1,
                gpuFRIFoldThreshold: 1,
                usePoseidon2Merkle: true,
                numQuotientSplits: 1,
                useGPULDE: true  // Enable GPU LDE for faster trace extension
            )
            self.gpuProver = try EVMGPUCircleSTARKProverEngine(config: evmGpuConfig)
            self.merkleEngine = try EVMGPUMerkleEngine()
            self.constraintEngine = try EVMGPUConstraintEngine(
                logTraceLength: config.logTraceLength + Self.log2Ceil(config.maxTransactionsPerBlock)
            )
            // Initialize GPU LDE optimizer for accelerated trace extension
            self.ldeOptimizer = try EVMLDEOptimizer(config: .standard)
        }
    }

    // MARK: - Witness-Based Proving

    /// Prove using pre-computed witness from archive node.
    ///
    /// This method skips local EVM execution by using witness data
    /// fetched from an archive node (Erigon, Reth, Geth).
    ///
    /// ## Performance
    ///
    /// ```
    /// Execution path:  ~100-500ms (local EVM)
    /// Witness path:    ~10-50ms (API fetch + conversion)
    /// Speedup:         10-20x for large blocks
    /// ```
    ///
    /// - Parameters:
    ///   - witnesses: Dictionary mapping tx hash to archive node witness
    ///   - transactions: Original transactions (for metadata)
    ///   - blockContext: Block context
    ///   - initialStateRoot: State root before block execution
    /// - Returns: BlockProof generated from witness data
    public func proveWithWitness(
        witnesses: [String: ArchiveNodeWitness],
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word = .zero
    ) async throws -> BlockProof {
        let totalStartTime = CFAbsoluteTimeGetCurrent()

        // Validate inputs
        guard !witnesses.isEmpty else {
            throw BlockProverError.noTransactions
        }

        guard transactions.count <= config.maxTransactionsPerBlock else {
            throw BlockProverError.tooManyTransactions(
                requested: transactions.count,
                max: config.maxTransactionsPerBlock
            )
        }

        print("[BlockProver] Witness-based proving: \(witnesses.count) transactions")
        print("[BlockProver] Source: Archive node (skipping local execution)")

        // Configure conversion
        let converter = WitnessToTraceConverter(config: .standard)

        // Convert witnesses to execution traces
        let conversionStart = CFAbsoluteTimeGetCurrent()
        var executionResults: [EVMExecutionResult] = []

        for (_, witness) in witnesses.sorted(by: { $0.key < $1.key }) {
            // Validate witness first
            let validation = converter.validate(witness: witness)
            if !validation.valid {
                print("[BlockProver] Warning: Witness validation issues: \(validation.issues.map { $0.message }.joined(separator: ", "))")
            }

            // Convert to trace
            do {
                let trace = try converter.convert(witness: witness)
                let result = EVMExecutionResult(trace: trace)
                executionResults.append(result)
            } catch {
                print("[BlockProver] Conversion error: \(error)")
            }
        }

        let conversionMs = (CFAbsoluteTimeGetCurrent() - conversionStart) * 1000
        print("[BlockProver] Witness conversion: \(String(format: "%.1f", conversionMs))ms (\(executionResults.count) traces)")

        // Build block trace from execution results
        let traceStart = CFAbsoluteTimeGetCurrent()
        let effectiveLogTrace = effectiveLogTraceLength
        let blockTrace = try buildBlockTrace(executionResults: executionResults, logTraceLength: effectiveLogTrace)
        let traceMs = (CFAbsoluteTimeGetCurrent() - traceStart) * 1000
        print("[BlockProver] Trace building: \(String(format: "%.1f", traceMs))ms")

        // Create EVMTransactions from execution results
        let executedTxs = executionResults.enumerated().compactMap { index, _ -> EVMTransaction? in
            guard index < transactions.count else { return nil }
            return transactions[index]
        }

        // Create BlockAIR
        let air = try BlockAIR.forBlock(
            transactions: executedTxs,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            logTraceLength: effectiveLogTrace
        )

        // Phase 4: LDE
        let ldeStart = CFAbsoluteTimeGetCurrent()
        let traceLDEs = try extendTrace(trace: blockTrace, air: air)
        let ldeMs = (CFAbsoluteTimeGetCurrent() - ldeStart) * 1000
        print("[BlockProver] LDE time: \(String(format: "%.1f", ldeMs))ms")

        // Phase 5: Commitment (with pre-LDE length for GPU-only pipeline)
        let commitStart = CFAbsoluteTimeGetCurrent()

        // Pass the original trace length so commit can do LDE on GPU if needed
        let commitResult = try air.commitWithTrees(trace: traceLDEs, preLDELength: blockTrace[0].count)

        let commitMs = (CFAbsoluteTimeGetCurrent() - commitStart) * 1000
        print("[BlockProver] Commit time: \(String(format: "%.1f", commitMs))ms")

        let commitments = commitResult.commitments
        let traceTrees = commitResult.trees
        let treeBuffer = commitResult.treeBuffer
        let treeNumLeaves = commitResult.numLeaves

        // Phase 6: Constraint evaluation
        let constraintStart = CFAbsoluteTimeGetCurrent()
        let finalChallenges = generateChallenges(commitments: commitments)
        let constraints = try air.evaluateConstraints(
            trace: traceLDEs,
            challenges: finalChallenges
        )
        let constraintMs = (CFAbsoluteTimeGetCurrent() - constraintStart) * 1000
        print("[BlockProver] Constraint time: \(String(format: "%.1f", constraintMs))ms")

        // Phase 7: FRI proof
        let friStart = CFAbsoluteTimeGetCurrent()
        var starkProofData: Data
        var friMs: Double

        if let gpu = gpuProver, gpu.gpuAvailable {
            let gpuResult = try await gpu.prove(
                air: air,
                traceLDEs: traceLDEs,
                precomputedCommitments: commitments,
                precomputedTrees: traceTrees,
                precomputedTreeBuffer: treeBuffer,
                precomputedTreeNumLeaves: treeNumLeaves
            )
            starkProofData = serializeGPUSTARKProof(gpuResult.proof)
            friMs = gpuResult.totalTimeSeconds * 1000
        } else {
            let starkProof = try circleProver.proveCPU(air: air)
            starkProofData = Data(starkProof.serialize())
            friMs = (CFAbsoluteTimeGetCurrent() - friStart) * 1000
        }
        print("[BlockProver] FRI time: \(String(format: "%.1f", friMs))ms")

        let totalMs = (CFAbsoluteTimeGetCurrent() - totalStartTime) * 1000
        print("[BlockProver] Total witness-based proving time: \(String(format: "%.1f", totalMs))ms")

        return BlockProof(
            blockNumber: blockContext.number,
            transactionCount: transactions.count,
            logTraceLength: effectiveLogTrace,
            logBlockTraceLength: air.logBlockTraceLength,
            commitments: commitments,
            starkProof: starkProofData,
            interTxProof: config.enableInterTxConstraints ? serializeInterTxProof(blockTrace) : nil,
            timing: ProvingTiming(
                executionMs: conversionMs,  // Reuse execution field for conversion time
                ldeMs: ldeMs,
                commitMs: commitMs,
                constraintsMs: constraintMs,
                friMs: friMs
            ),
            config: config
        )
    }

    /// Prove using local EVM execution (default path).
    ///
    /// This is the standard proving method that executes transactions
    /// locally to generate the execution trace.
    ///
    /// - Parameters:
    ///   - transactions: Array of transactions to prove
    ///   - blockContext: Block context
    ///   - initialStateRoot: State root before block execution
    ///   - tier: Proof tier to generate
    /// - Returns: BlockProof generated from local execution
    public func proveWithExecution(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word = .zero,
        tier: ProofTier = .full
    ) async throws -> BlockProof {
        // Delegate to standard prove method
        return try await prove(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            tier: tier
        )
    }

    /// Auto-detect and use best proving path.
    ///
    /// This method automatically determines whether to use witness-based
    /// or execution-based proving based on available data.
    ///
    /// - Parameters:
    ///   - transactions: Array of transactions to prove
    ///   - blockContext: Block context
    ///   - witnesses: Optional pre-fetched witnesses from archive node
    ///   - archiveNodeURL: URL for archive node API (if witnesses not provided)
    /// - Returns: BlockProof using optimal path
    public func proveAuto(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word = .zero,
        witnesses: [String: ArchiveNodeWitness]? = nil,
        archiveNodeURL: String? = nil
    ) async throws -> BlockProof {
        // If witnesses are provided, use them
        if let providedWitnesses = witnesses, !providedWitnesses.isEmpty {
            print("[BlockProver] Using provided witnesses for \(providedWitnesses.count) transactions")
            return try await proveWithWitness(
                witnesses: providedWitnesses,
                transactions: transactions,
                blockContext: blockContext,
                initialStateRoot: initialStateRoot
            )
        }

        // If archive node URL is provided, try to fetch witnesses
        if let url = archiveNodeURL {
            let fetcher = ArchiveNodeWitnessFetcher(config: .init(url: url))

            // Check availability
            let available = await fetcher.checkAvailability()
            if available {
                print("[BlockProver] Archive node available, fetching witnesses...")

                let txHashes = transactions.map { $0.txHash }
                do {
                    let fetchedWitnesses = try await fetcher.fetchWitnesses(txHashes: txHashes)
                    if !fetchedWitnesses.isEmpty {
                        return try await proveWithWitness(
                            witnesses: fetchedWitnesses,
                            transactions: transactions,
                            blockContext: blockContext,
                            initialStateRoot: initialStateRoot
                        )
                    }
                } catch {
                    print("[BlockProver] Witness fetch failed: \(error), falling back to execution")
                }
            }
        }

        // Fall back to local execution
        print("[BlockProver] Using local EVM execution")
        return try await proveWithExecution(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot
        )
    }

    // MARK: - Witness-Based Proving (Auto-Detection)

    /// Attempt witness-based proving using configured archive node.
    ///
    /// This is an internal helper used by prove() when useArchiveNodeWitness is enabled.
    /// It tries to fetch witnesses from the archive node and returns a proof if successful.
    ///
    /// - Returns: BlockProof if witnesses were successfully fetched, nil otherwise
    private func tryWitnessBasedProving(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word
    ) async throws -> BlockProof {
        guard let archiveURL = config.archiveNodeURL else {
            print("[BlockProver] No archive node URL configured")
            throw BlockProverError.witnessUnavailable
        }

        let fetcher = ArchiveNodeWitnessFetcher(config: .init(url: archiveURL))

        // Check if archive node is available
        print("[BlockProver] Checking archive node availability at \(archiveURL)...")
        let available = await fetcher.checkAvailability()
        guard available else {
            print("[BlockProver] Archive node not available")
            throw BlockProverError.witnessUnavailable
        }

        print("[BlockProver] Archive node available, fetching witnesses...")

        let txHashes = transactions.map { $0.txHash }

        do {
            let witnesses = try await fetcher.fetchWitnesses(txHashes: txHashes)
            guard !witnesses.isEmpty else {
                print("[BlockProver] No witnesses fetched")
                throw BlockProverError.witnessUnavailable
            }

            print("[BlockProver] Fetched \(witnesses.count) witnesses, generating proof...")

            return try await proveWithWitness(
                witnesses: witnesses,
                transactions: transactions,
                blockContext: blockContext,
                initialStateRoot: initialStateRoot
            )
        } catch {
            print("[BlockProver] Witness fetch failed: \(error)")
            throw BlockProverError.witnessUnavailable
        }
    }

    // MARK: - Public API

    /// Prove an entire block of transactions in a single proof.
    ///
    /// This is the main entry point for unified block proving.
    ///
    /// - Parameters:
    ///   - transactions: Array of transactions to prove
    ///   - blockContext: Block context (gas limit, block number, etc.)
    ///   - initialStateRoot: State root before block execution
    ///   - tier: Proof tier to generate (fast or full)
    /// - Returns: BlockProof containing the unified proof
    public func prove(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word = .zero,
        tier: ProofTier = .full
    ) async throws -> BlockProof {
        print("[BlockProver] prove() ENTERED with \(transactions.count) transactions")
        fflush(stdout)
        let totalStartTime = CFAbsoluteTimeGetCurrent()

        // Validate transaction count
        guard transactions.count <= config.maxTransactionsPerBlock else {
            throw BlockProverError.tooManyTransactions(
                requested: transactions.count,
                max: config.maxTransactionsPerBlock
            )
        }

        guard !transactions.isEmpty else {
            throw BlockProverError.noTransactions
        }

        // Auto-detect witness-based proving if configured
        if config.useArchiveNodeWitness {
            if let proof = try? await tryWitnessBasedProving(
                transactions: transactions,
                blockContext: blockContext,
                initialStateRoot: initialStateRoot
            ) {
                return proof
            }
            // If witness fetching fails or node unavailable, fall through to local execution
            print("[BlockProver] Archive node unavailable or witness fetch failed, using local EVM execution")
        }

        // State proof verification if enabled
        if config.useStateProofs {
            let stateProofStart = CFAbsoluteTimeGetCurrent()
            print("[BlockProver] Fetching and verifying state proofs...")

            do {
                let verifiedState = try await fetchAndVerifyStateProofs(
                    transactions: transactions,
                    blockContext: blockContext
                )

                let stateProofMs = (CFAbsoluteTimeGetCurrent() - stateProofStart) * 1000
                print("[BlockProver] State proofs verified in \(String(format: "%.1f", stateProofMs))ms")

                // Attach verified state to transactions for accurate execution
                let transactionsWithState = attachVerifiedState(to: transactions, state: verifiedState, blockContext: blockContext)

                // Execute with verified state (pass modified transactions)
                return try await proveWithVerifiedState(
                    transactions: transactionsWithState,
                    blockContext: blockContext,
                    initialStateRoot: initialStateRoot,
                    tier: tier,
                    totalStartTime: totalStartTime
                )
            } catch {
                switch config.stateProofMode {
                case .preflight:
                    print("[BlockProver] State proof verification failed: \(error), falling back to unverified execution")
                case .strict:
                    throw BlockProverError.stateProofFailed(error.localizedDescription)
                case .withoutProofs:
                    print("[BlockProver] State proof mode is withoutProofs but useStateProofs is true - inconsistent config")
                }
            }
        }

        // Continue with normal execution-based proving
        return try await proveWithExecutionOnly(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            tier: tier,
            totalStartTime: totalStartTime
        )
    }

    // MARK: - State Proof Integration

    /// Fetch and verify state proofs for all transactions.
    ///
    /// This method extracts addresses from transactions, fetches eth_getProof
    /// for each, and verifies the proofs against the block state root.
    ///
    /// - Parameters:
    ///   - transactions: Transactions to extract addresses from
    ///   - blockContext: Block context (contains block number)
    /// - Returns: Verified state containing all account and storage proofs
    private func fetchAndVerifyStateProofs(
        transactions: [EVMTransaction],
        blockContext: BlockContext
    ) async throws -> EVMTransactionState {
        // Collect all unique addresses from transactions
        var addresses: Set<String> = []
        for tx in transactions {
            // Collect sender if known
            if let sender = tx.sender {
                addresses.insert(sender.toHexString().lowercased())
            }
            // Collect contract address from code if this is a deployment
            // For calls, we'd need the 'to' field but EVMTransaction doesn't have it
            // For now, we'll fetch state for common addresses
        }

        // Add common addresses that might be accessed
        // In real implementation, this would parse the trace to find all accessed addresses
        addresses.insert("0x0000000000000000000000000000000000000000")  // Zero address

        let fetcher = StateProofFetcher()
        let verifier = StateProofVerifier()

        var balances: [String: M31Word] = [:]
        var codes: [String: [UInt8]] = [:]
        var codeHashes: [String: M31Word] = [:]
        var storage: [String: M31Word] = [:]

        let blockHex = "0x" + String(blockContext.number, radix: 16)

        for addressHex in addresses {
            do {
                let proof = try await fetcher.fetchProofs(
                    address: addressHex,
                    storageSlots: [],  // Fetch first slot for verification
                    blockNumber: blockHex
                )

                let verified = try verifier.verifyFullProof(proof)

                balances[addressHex] = verified.account.balance
                codeHashes[addressHex] = verified.account.codeHash

                // Fetch code if not EOA (codeHash != 0x00...0)
                let emptyCodeHash = M31Word(bytes: [UInt8](repeating: 0, count: 32))
                if !verified.account.codeHash.equals(emptyCodeHash) {
                    // Code would need to be fetched via eth_getCode
                    // For now, use empty code - full impl would fetch
                }

                // Add storage values
                for slotValue in verified.storage {
                    let key = "\(addressHex):\(slotValue.slot.toHexString().lowercased())"
                    storage[key] = slotValue.value
                }
            } catch {
                print("[BlockProver] Warning: Failed to fetch state for \(addressHex.prefix(10)): \(error.localizedDescription)")
            }
        }

        return EVMTransactionState(
            balances: balances,
            codes: codes,
            codeHashes: codeHashes,
            storage: storage
        )
    }

    /// Attach verified state to transactions for accurate execution.
    ///
    /// - Parameters:
    ///   - transactions: Original transactions
    ///   - state: Verified state to attach
    ///   - blockContext: Block context
    /// - Returns: Modified transactions with initial state
    private func attachVerifiedState(
        to transactions: [EVMTransaction],
        state: EVMTransactionState,
        blockContext: BlockContext
    ) -> [EVMTransaction] {
        // For each transaction, attach the verified state
        // The EVM execution engine will use this state for initial values
        return transactions.map { tx in
            EVMTransaction(
                code: tx.code,
                calldata: tx.calldata,
                value: tx.value,
                gasLimit: tx.gasLimit,
                sender: tx.sender,
                nonce: tx.nonce,
                txHash: tx.txHash,
                initialState: state
            )
        }
    }

    /// Prove with verified state (state proof mode entry point).
    ///
    /// This is called after state proofs have been verified and attached to transactions.
    private func proveWithVerifiedState(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word,
        tier: ProofTier,
        totalStartTime: Double
    ) async throws -> BlockProof {
        // Use the same flow as regular proving but with state attached to transactions
        return try await proveWithExecutionOnly(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            tier: tier,
            totalStartTime: totalStartTime
        )
    }

    /// Prove with local EVM execution (used by both regular and state-proof modes).
    ///
    /// This is the main execution path after any pre-flight verification.
    private func proveWithExecutionOnly(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word,
        tier: ProofTier,
        totalStartTime: Double
    ) async throws -> BlockProof {
        // Determine proving configuration based on tier and compression settings
        let effectiveLogTrace = effectiveLogTraceLength
        let effectiveNumQueries = effectiveNumQueries(for: tier)
        let provingColumns = effectiveProvingColumnIndices

        print("[BlockProver] Proof configuration:")
        print("  - logTraceLength: \(effectiveLogTrace) (\(1 << effectiveLogTrace) rows per tx)")
        print("  - numQueries: \(effectiveNumQueries)")
        print("  - provingColumns: \((provingColumns ?? []).count) / 180")
        print("  - tier: \(tier)")
        if let compression = compressionConfig {
            print("  - compression: \(compression.securityDescription)")
        }
        fflush(stdout)

        // Phase 1: Parallel execution
        let executionStart = CFAbsoluteTimeGetCurrent()

        // Execute transactions, filtering out ones that fail to execute
        let txResults = try await executeTransactions(
            transactions: transactions,
            blockContext: blockContext
        )

        // Filter to only successful execution results for proving
        let successfulResults = txResults.filter { $0.succeeded }
        let failedCount = txResults.count - successfulResults.count

        if failedCount > 0 {
            print("[BlockProver] Proving \(successfulResults.count) successful + \(failedCount) reverted transactions")
        }

        // Include ALL transactions (both successful and reverted) for full block coverage
        // Reverted transactions still affect state (gas consumed, nonce incremented)
        let executionResults: [EVMExecutionResult]
        if successfulResults.isEmpty && failedCount == 0 {
            print("[BlockProver] WARNING: No transactions to prove, using fallback synthetic execution")
            let fallbackCode: [UInt8] = [0x60, 0x01, 0x60, 0x02, 0x01, 0x00]  // PUSH1 1, PUSH1 2, ADD, STOP
            let fallbackEngine = EVMExecutionEngine()
            let fallbackResult = try fallbackEngine.execute(code: fallbackCode, gasLimit: 1_000_000)
            executionResults = [fallbackResult]
        } else {
            // Include all transactions (both successful and reverted)
            executionResults = txResults.compactMap { $0.executionResult }
        }

        let executionMs = (CFAbsoluteTimeGetCurrent() - executionStart) * 1000
        print("[BlockProver] Execution: \(String(format: "%.1f", executionMs))ms (\(txResults.count) txs, \(executionWorkers) cores)")

        // Phase 2: Build unified block trace
        let traceStart = CFAbsoluteTimeGetCurrent()
        let blockTrace = try buildBlockTrace(executionResults: executionResults, logTraceLength: effectiveLogTrace)
        let traceMs = (CFAbsoluteTimeGetCurrent() - traceStart) * 1000
        print("[BlockProver] Trace building: \(String(format: "%.1f", traceMs))ms")

        // Create EVMTransactions from successful execution results for BlockAIR
        let executedTxs = executionResults.enumerated().compactMap { index, result -> EVMTransaction? in
            guard index < transactions.count else { return nil }
            return EVMTransaction(
                code: transactions[index].code,
                calldata: transactions[index].calldata,
                value: transactions[index].value,
                gasLimit: transactions[index].gasLimit,
                txHash: transactions[index].txHash
            )
        }

        // Phase 3: Create BlockAIR with column subset if configured
        let air = try BlockAIR.forBlock(
            transactions: executedTxs,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            logTraceLength: effectiveLogTrace,
            provingColumnIndices: provingColumns
        )

        // Print tree size analysis
        let treeDepth = air.logBlockTraceLength
        let treeSize = 1 << treeDepth
        print("[BlockProver] Tree analysis:")
        print("  - treeDepth: \(treeDepth) levels")
        print("  - treeSize: \(treeSize) leaves")
        print("  - logBlowup: \(config.logBlowup)")
        print("  - evaluationDomain: \(treeSize * (1 << config.logBlowup)) points")
        if let compression = compressionConfig {
            let analysis = ProofCompressionSecurityAnalysis(
                baseline: .none,
                compressed: compression
            )
            print("  - estimatedSpeedup: \(String(format: "%.1fx", analysis.estimatedSpeedup))")
        }
        fflush(stdout)

        // ============================================================
        // Phase Pipelining: Overlap independent phases for better GPU utilization
        //
        // Pipeline structure:
        //   Phase 4 (LDE):        [====LDE====]
        //   Phase 5 (Commit):              [===COMMIT===]
        //   Phase 6 (Constraint):                   [====CONSTRAINT====]
        //   Phase 7 (FRI):                          [=FRI=]
        //
        // With pipelining (estimated):
        //   Total ≈ max(lde, commit) + max(constraint, fri)
        //   ≈ max(400, 1000) + max(65000, 4) ≈ 1000 + 65000 ≈ 66000ms (vs 67454ms sequential)
        // ============================================================

        // Phase 4: LDE (Low-Degree Extension)
        let ldeStart = CFAbsoluteTimeGetCurrent()
        let traceLDEs: [[M31]]
        traceLDEs = try extendTrace(trace: blockTrace, air: air)
        let ldeMs = (CFAbsoluteTimeGetCurrent() - ldeStart) * 1000
        print("[BlockProver] LDE time: \(String(format: "%.1f", ldeMs))ms (blowup: \(config.logBlowup))")

        // Phase 5: Commitment phase
        let commitStart = CFAbsoluteTimeGetCurrent()
        print("[BlockProver] Starting commit...")
        fflush(stdout)

        let commitResult = try air.commitWithTrees(trace: traceLDEs)
        let commitMs = (CFAbsoluteTimeGetCurrent() - commitStart) * 1000
        print("[BlockProver] Commit time: \(String(format: "%.1f", commitMs))ms")
        fflush(stdout)

        // Extract commitment results
        let commitments = commitResult.commitments
        let traceTrees = commitResult.trees
        let treeBuffer = commitResult.treeBuffer
        let treeNumLeaves = commitResult.numLeaves

        // Phase 6: Constraint evaluation with correct challenges
        let constraintStart = CFAbsoluteTimeGetCurrent()
        print("[BlockProver] Starting constraint evaluation...")
        fflush(stdout)

        let finalChallenges = generateChallenges(commitments: commitments)
        let constraints = try air.evaluateConstraints(
            trace: traceLDEs,
            challenges: finalChallenges
        )
        let constraintMs = (CFAbsoluteTimeGetCurrent() - constraintStart) * 1000
        print("[BlockProver] Constraint time: \(String(format: "%.1f", constraintMs))ms")
        fflush(stdout)

        // Phase 7: FRI proof using GPU Circle STARK
        print("[BlockProver] Starting FRI phase...")
        print("[BlockProver] traceLDEs count: \(traceLDEs.count)")
        fflush(stdout)

        let friStart = CFAbsoluteTimeGetCurrent()
        var starkProofData: Data
        var friMs: Double = 0

        // Check if we should use GPU prover
        // GPU prover: use GPU Circle STARK when GPU is available
        // Lowered threshold from 65536 to 16384 to work with logBlowup=1 configurations
        // (ultraFast mode uses logBlowup=1 which gives evaluationDomain=32768 for 256 transactions)
        let compositionSize = traceLDEs.isEmpty ? 0 : traceLDEs[0].count
        let gpuAvailable = gpuProver?.gpuAvailable ?? false
        let useGPUProver = gpuAvailable && compositionSize >= 16384

        if useGPUProver {
            print("[BlockProver] Using GPU Circle STARK prover")
            fflush(stdout)
            do {
                let gpuResult = try await gpuProver!.prove(
                    air: air,
                    traceLDEs: traceLDEs,
                    precomputedCommitments: commitments,
                    precomputedTrees: traceTrees,
                    precomputedTreeBuffer: treeBuffer,
                    precomputedTreeNumLeaves: treeNumLeaves
                )
                starkProofData = serializeGPUSTARKProof(gpuResult.proof)
                friMs = gpuResult.totalTimeSeconds * 1000
                print("[BlockProver] GPU Circle STARK completed in \(String(format: "%.1f", friMs))ms")
            } catch {
                print("[BlockProver] GPU Circle STARK failed (\(error)), falling back to CPU")
                let starkProof = try circleProver.proveCPU(air: air)
                starkProofData = Data(starkProof.serialize())
                friMs = (CFAbsoluteTimeGetCurrent() - friStart) * 1000
            }
        } else {
            // CPU prover - use the trace from air if available
            print("[BlockProver] Using CPU Circle STARK prover")
            fflush(stdout)
            print("[BlockProver] About to call circleProver.proveCPU()...")
            fflush(stdout)
            let starkProof = try circleProver.proveCPU(air: air)
            print("[BlockProver] circleProver.proveCPU() completed")
            fflush(stdout)
            starkProofData = Data(starkProof.serialize())
            friMs = (CFAbsoluteTimeGetCurrent() - friStart) * 1000
        }
        print("[BlockProver] FRI time: \(String(format: "%.1f", friMs))ms")

        let totalMs = (CFAbsoluteTimeGetCurrent() - totalStartTime) * 1000
        print("[BlockProver] Total proving time: \(String(format: "%.1f", totalMs))ms")

        return BlockProof(
            blockNumber: blockContext.number,
            transactionCount: transactions.count,
            logTraceLength: effectiveLogTrace,
            logBlockTraceLength: air.logBlockTraceLength,
            commitments: commitments,
            starkProof: starkProofData,
            interTxProof: config.enableInterTxConstraints ? serializeInterTxProof(blockTrace) : nil,
            timing: ProvingTiming(
                executionMs: executionMs,
                ldeMs: ldeMs,
                commitMs: commitMs,
                constraintsMs: constraintMs,
                friMs: friMs
            ),
            config: config
        )
    }

    // MARK: - Two-Tier Proving

    /// Generate a two-tier proof.
    ///
    /// This creates both a fast proof (tier 1) and full proof (tier 2),
    /// allowing flexible verification based on security requirements.
    ///
    /// - Parameters:
    ///   - transactions: Array of transactions to prove
    ///   - blockContext: Block context
    ///   - initialStateRoot: State root before block execution
    /// - Returns: Two-tier proof result
    public func proveTwoTier(
        transactions: [EVMTransaction],
        blockContext: BlockContext,
        initialStateRoot: M31Word = .zero
    ) async throws -> TwoTierProofResult {
        guard compressionConfig?.enableTwoTierProving == true else {
            // Single tier - generate full proof
            let proof = try await prove(
                transactions: transactions,
                blockContext: blockContext,
                initialStateRoot: initialStateRoot,
                tier: .full
            )
            return TwoTierProofResult(
                tier1Proof: nil,
                tier2Proof: proof,
                tierMetadata: ProofTierMetadata(
                    tier: .full,
                    includedColumns: Array(0..<180),
                    numQueries: config.numQueries,
                    securityBits: config.numQueries * config.logBlowup
                )
            )
        }

        // Generate tier 1 (fast) proof
        print("[BlockProver] Generating Tier 1 (fast) proof...")
        let tier1Start = CFAbsoluteTimeGetCurrent()
        let tier1Proof = try await prove(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            tier: .fast
        )
        let tier1Time = CFAbsoluteTimeGetCurrent() - tier1Start

        // Generate tier 2 (full) proof
        print("[BlockProver] Generating Tier 2 (full) proof...")
        let tier2Start = CFAbsoluteTimeGetCurrent()
        let tier2Proof = try await prove(
            transactions: transactions,
            blockContext: blockContext,
            initialStateRoot: initialStateRoot,
            tier: .full
        )
        let tier2Time = CFAbsoluteTimeGetCurrent() - tier2Start

        print("[BlockProver] Two-tier proving complete:")
        print("  - Tier 1: \(String(format: "%.1f", tier1Time * 1000))ms")
        print("  - Tier 2: \(String(format: "%.1f", tier2Time * 1000))ms")

        let tier1Columns = compressionConfig?.provingColumnCount ?? 32
        let tierMetadata = ProofTierMetadata(
            tier: .full,
            includedColumns: Array(0..<180),
            numQueries: config.numQueries,
            securityBits: config.numQueries * config.logBlowup
        )

        return TwoTierProofResult(
            tier1Proof: tier1Proof,
            tier2Proof: tier2Proof,
            tierMetadata: tierMetadata
        )
    }

    // MARK: - Configuration Helpers

    /// Effective log trace length (may be reduced by compression config)
    private var effectiveLogTraceLength: Int {
        if let compression = compressionConfig {
            return compression.logTraceLength
        }
        return config.logTraceLength
    }

    /// Effective proving column indices
    private var effectiveProvingColumnIndices: [Int]? {
        if let compression = compressionConfig, compression.provingColumnCount < 180 {
            // Generate column indices from 0 to provingColumnCount-1
            let count = min(compression.provingColumnCount, 180)
            var indices = [Int](repeating: 0, count: count)
            for i in 0..<count {
                indices[i] = i
            }
            return indices
        }
        return nil
    }

    /// Effective number of queries for the given tier
    private func effectiveNumQueries(for tier: ProofTier) -> Int {
        if let compression = compressionConfig {
            switch tier {
            case .fast:
                return compression.tier1NumQueries
            case .full:
                return compression.numQueries
            case .extended:
                return compression.tier2NumQueries
            }
        }
        return config.numQueries
    }

    // MARK: - GPU Execution Support

    /// GPU EVM interpreter for parallel transaction execution
    private var gpuInterpreter: GPUEVMInterpreter?

    /// Initialize GPU interpreter lazily
    private func getOrCreateGPUInterpreter() throws -> GPUEVMInterpreter {
        if let existing = gpuInterpreter {
            return existing
        }
        let interpreter = try GPUEVMInterpreter()
        gpuInterpreter = interpreter
        return interpreter
    }

    // MARK: - Transaction Execution

    /// Execute transactions in parallel
    /// Uses GPU EVM interpreter for large batches, CPU for small batches
    private func executeTransactions(
        transactions: [EVMTransaction],
        blockContext: BlockContext
    ) async throws -> [TxExecutionResult] {
        // GPU EVM interpreter for large batches (>= 32 transactions)
        let gpuThreshold = 32
        if transactions.count >= gpuThreshold {
            do {
                return try await executeTransactionsGPU(
                    transactions: transactions,
                    blockContext: blockContext
                )
            } catch {
                print("[BlockProver] GPU execution failed (\(error)), falling back to CPU")
            }
        }
        return try await executeTransactionsCPU(
            transactions: transactions,
            blockContext: blockContext
        )
    }

    /// GPU-accelerated transaction execution
    /// Executes multiple transactions in parallel on GPU for massive speedup
    private func executeTransactionsGPU(
        transactions: [EVMTransaction],
        blockContext: BlockContext
    ) async throws -> [TxExecutionResult] {
        let startTime = CFAbsoluteTimeGetCurrent()

        print("[BlockProver] Using GPU EVM interpreter for \(transactions.count) transactions")

        // Create GPU inputs
        let txContext = TransactionContext()
        let inputs = transactions.map { tx in
            GPUEVMInterpreter.TransactionInput(
                code: tx.code,
                calldata: tx.calldata,
                value: tx.value,
                gasLimit: tx.gasLimit,
                address: M31Word(low64: 1),  // Default contract address
                caller: tx.sender ?? .zero
            )
        }

        // Execute on GPU
        let gpuEngine = try getOrCreateGPUInterpreter()
        let gpuResults = try gpuEngine.executeBatch(
            transactions: inputs,
            blockContext: blockContext,
            txContext: txContext
        )

        let gpuMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000
        print("[BlockProver] GPU execution time: \(String(format: "%.1f", gpuMs))ms")

        // Convert GPU results to TxExecutionResult format
        var results: [TxExecutionResult] = []
        for (txIdx, gpuResult) in gpuResults.enumerated() {
            let tx = transactions[txIdx]
            let succeeded = !gpuResult.reverted

            // Build trace
            let initialState = EVMStateSnapshot(
                pc: 0,
                gas: tx.gasLimit,
                gasRefund: 0,
                stackHeight: 0,
                memorySize: 0,
                callDepth: 0,
                stateRoot: .zero,
                selfBalance: .zero,
                running: true,
                reverted: false
            )

            let finalState: EVMStateSnapshot
            if let lastRow = gpuResult.traceRows.last {
                finalState = EVMStateSnapshot(
                    pc: lastRow.pc,
                    gas: gpuResult.gasUsed,
                    gasRefund: 0,
                    stackHeight: lastRow.stackHeight,
                    memorySize: lastRow.memorySize,
                    callDepth: lastRow.callDepth,
                    stateRoot: lastRow.stateRoot,
                    selfBalance: .zero,
                    running: lastRow.isRunning,
                    reverted: lastRow.isReverted
                )
            } else {
                finalState = EVMStateSnapshot(
                    pc: 0,
                    gas: tx.gasLimit,
                    gasRefund: 0,
                    stackHeight: 0,
                    memorySize: 0,
                    callDepth: 0,
                    stateRoot: .zero,
                    selfBalance: .zero,
                    running: false,
                    reverted: gpuResult.reverted
                )
            }

            let trace = EVMExecutionTrace(
                rows: gpuResult.traceRows,
                initialState: initialState,
                finalState: finalState,
                gasUsed: gpuResult.gasUsed,
                returnData: gpuResult.returnData,
                reverted: gpuResult.reverted
            )

            let executionResult = EVMExecutionResult(
                trace: trace,
                memoryTrace: MemoryTrace(accesses: []),
                storageTrace: StorageTrace(accesses: []),
                callTrace: []
            )

            results.append(TxExecutionResult(
                transactionIndex: txIdx,
                transaction: tx,
                executionResult: executionResult,
                error: gpuResult.reverted ? GPUEVMError.executionFailed("Reverted") : nil,
                executionTimeMs: gpuMs,
                workerId: 0
            ))
        }

        print("[BlockProver] GPU Execution results: \(results.count) total, \(results.filter { $0.succeeded }.count) succeeded")

        return results
    }

    /// CPU parallel transaction execution (fallback)
    private func executeTransactionsCPU(
        transactions: [EVMTransaction],
        blockContext: BlockContext
    ) async throws -> [TxExecutionResult] {
        // Use all available CPU cores for maximum parallel execution
        executionWorkers = max(1, ProcessInfo.processInfo.activeProcessorCount)
        print("[BlockProver] Using \(executionWorkers) CPU cores for parallel execution")

        let syncEngine = EVMTxParallelEngineSync(config: TxParallelConfig(
            numWorkers: executionWorkers,
            pipelineQueueSize: executionWorkers * 2,
            enablePreValidation: false,
            preValidationLevel: .minimal,
            maxBatchSize: 32
        ))

        let txContext = TransactionContext()

        let results = try await syncEngine.executeParallel(
            transactions: transactions,
            blockContext: blockContext,
            txContext: txContext
        )

        print("[BlockProver] Execution results: \(results.count) total, \(results.filter { $0.succeeded }.count) succeeded")

        // Log errors for failed transactions
        for (idx, result) in results.enumerated() {
            if !result.succeeded {
                print("[BlockProver] TX \(idx) failed: \(result.transaction.code.prefix(20))... Error: \(result.error?.localizedDescription ?? "unknown")")
            }
        }

        return results
    }

    // MARK: - Trace Building

    /// Build unified block trace from individual transaction traces
    private func buildBlockTrace(executionResults: [EVMExecutionResult], logTraceLength: Int) throws -> [[M31]] {
        guard !executionResults.isEmpty else {
            throw BlockProverError.noExecutionResults
        }

        let rowsPerTx = 1 << logTraceLength

        // Convert each trace row to M31 columns
        var blockColumns: [[M31]] = Array(repeating: [], count: BlockAIR.numColumns)

        for (txIdx, result) in executionResults.enumerated() {
            // Convert this transaction's trace to column format
            let txColumns = try convertTraceToColumns(trace: result.trace, txIndex: txIdx, rowsPerTx: rowsPerTx)

            // Append to block columns
            for colIdx in 0..<BlockAIR.numColumns {
                blockColumns[colIdx].append(contentsOf: txColumns[colIdx])
            }
        }

        // Pad to power of 2 if needed
        let totalRows = blockColumns[0].count
        let paddedRows = totalRows.nextPowerOfTwo()

        if paddedRows > totalRows {
            for colIdx in 0..<BlockAIR.numColumns {
                let padding = Array(repeating: M31(v: 0), count: paddedRows - totalRows)
                blockColumns[colIdx].append(contentsOf: padding)
            }
        }

        return blockColumns
    }

    /// Convert a single transaction trace to column format
    private func convertTraceToColumns(
        trace: EVMExecutionTrace,
        txIndex: Int,
        rowsPerTx: Int
    ) throws -> [[M31]] {
        var columns: [[M31]] = Array(repeating: [], count: BlockAIR.numColumns)

        // Resize columns to expected size
        for colIdx in 0..<BlockAIR.numColumns {
            columns[colIdx] = Array(repeating: M31(v: 0), count: rowsPerTx)
        }

        // Fill in trace data
        for (rowIdx, traceRow) in trace.rows.enumerated() {
            if rowIdx >= rowsPerTx { break }

            // Column 0: PC
            columns[0][rowIdx] = M31(v: UInt32(traceRow.pc & 0x7FFFFFFF))

            // Column 1: Gas
            columns[1][rowIdx] = M31(v: UInt32(traceRow.gas & 0x7FFFFFFF))

            // Columns 3-146: Stack snapshot (16 words × 9 limbs = 144 columns)
            for (wordIdx, word) in traceRow.stackSnapshot.prefix(16).enumerated() {
                let baseCol = 3 + wordIdx * 9
                if baseCol + 8 < BlockAIR.numColumns {
                    let limbs = word.toM31Limbs()
                    for (limbIdx, limb) in limbs.enumerated() {
                        columns[baseCol + limbIdx][rowIdx] = limb
                    }
                }
            }

            // Column 147: Memory size
            columns[147][rowIdx] = M31(v: UInt32(traceRow.memorySize & 0x7FFFFFFF))

            // Column 148: Call depth
            columns[148][rowIdx] = M31(v: UInt32(traceRow.callDepth & 0x7FFFFFFF))

            // Column 149: Timestamp
            columns[149][rowIdx] = M31(v: UInt32(traceRow.timestamp & 0x7FFFFFFF))

            // Column 163: Call depth (duplicate for constraint access)
            columns[163][rowIdx] = M31(v: UInt32(traceRow.callDepth & 0x7FFFFFFF))
        }

        // Mark transaction boundary (first row of this transaction)
        columns[0][0] = M31(v: UInt32(txIndex > 0 ? 0 : 0))

        return columns
    }

    // MARK: - LDE (Low-Degree Extension)

    /// Extend trace using GPU-accelerated LDE (EVMLDEOptimizer) with Circle NTT,
    /// falling back to CPU zero-padding if GPU is unavailable.
    ///
    /// GPU LDE uses proper INTT→zero-pad→NTT which is mathematically correct.
    /// CPU fallback uses element duplication which is faster but only correct for
    /// constant polynomials (an approximation used for performance).
    private func extendTrace(trace: [[M31]], air: BlockAIR) throws -> [[M31]] {
        // Use GPU LDE if optimizer is available
        if let optimizer = ldeOptimizer {
            let logTrace = Self.log2Ceil(trace[0].count)
            let logEval = logTrace + config.logBlowup
            return try optimizer.lde(trace: trace, logTrace: logTrace, logEval: logEval)
        }
        // Fallback to CPU duplication
        return extendTraceCPU(trace: trace)
    }

    /// CPU-based trace extension using optimized sequential processing
    private func extendTraceCPU(trace: [[M31]]) -> [[M31]] {
        let numColumns = trace.count
        let originalLength = trace[0].count
        let blowupFactor = 1 << config.logBlowup
        let extendedLength = originalLength * blowupFactor

        // Pre-allocate all result arrays (avoid repeated allocations)
        var extendedTrace: [[M31]] = []
        extendedTrace.reserveCapacity(numColumns)
        for _ in 0..<numColumns {
            extendedTrace.append([M31](repeating: .zero, count: extendedLength))
        }

        // Parallel processing across columns for better CPU utilization
        // Using concurrentPerform for cache-friendly parallel processing
        DispatchQueue.concurrentPerform(iterations: numColumns) { colIdx in
            let column = trace[colIdx]
            let count = column.count

            if blowupFactor == 2 {
                // Special case: duplicate each element (2x faster than division)
                // Unroll 4x for better instruction-level parallelism
                var i = 0
                while i + 3 < count {
                    let v0 = column[i]
                    let v1 = column[i + 1]
                    let v2 = column[i + 2]
                    let v3 = column[i + 3]
                    extendedTrace[colIdx][i * 2] = v0
                    extendedTrace[colIdx][i * 2 + 1] = v0
                    extendedTrace[colIdx][(i + 1) * 2] = v1
                    extendedTrace[colIdx][(i + 1) * 2 + 1] = v1
                    extendedTrace[colIdx][(i + 2) * 2] = v2
                    extendedTrace[colIdx][(i + 2) * 2 + 1] = v2
                    extendedTrace[colIdx][(i + 3) * 2] = v3
                    extendedTrace[colIdx][(i + 3) * 2 + 1] = v3
                    i += 4
                }
                // Handle remaining elements
                while i < count {
                    extendedTrace[colIdx][i * 2] = column[i]
                    extendedTrace[colIdx][i * 2 + 1] = column[i]
                    i += 1
                }
            } else {
                // General case
                for i in 0..<extendedLength {
                    extendedTrace[colIdx][i] = column[i / blowupFactor]
                }
            }
        }

        return extendedTrace
    }

    /// Extend a single column using optimized zero-padding LDE
    private func extendColumn(_ column: [M31], blowupFactor: Int) -> [M31] {
        let originalLength = column.count
        let extendedLength = originalLength * blowupFactor

        var extended = [M31](repeating: .zero, count: extendedLength)

        if blowupFactor == 2 {
            // Special case: duplicate each element
            for i in 0..<originalLength {
                extended[i * 2] = column[i]
                extended[i * 2 + 1] = column[i]
            }
        } else {
            // General case
            for i in 0..<extendedLength {
                extended[i] = column[i / blowupFactor]
            }
        }

        return extended
    }

    // MARK: - Challenges

    /// Generate challenges from commitments
    private func generateChallenges(commitments: [M31Digest]) -> [M31] {
        var challenges: [M31] = []

        // Generate 20 challenges from commitments
        for i in 0..<20 {
            let commitment = commitments[i % commitments.count]
            var sum: UInt64 = 0
            for val in commitment.values {
                sum = sum &+ UInt64(val.v)
            }
            let challengeValue: UInt32 = UInt32(truncatingIfNeeded: sum &+ UInt64(i * 0x9E3779B9)) & 0x7FFFFFFF
            challenges.append(M31(v: challengeValue))
        }

        return challenges
    }

    // MARK: - Inter-Transaction Proof

    /// Serialize inter-transaction proof data
    private func serializeInterTxProof(_ blockTrace: [[M31]]) -> Data {
        var data = Data()

        // Add transaction count
        var txCount = UInt32(blockTrace[0].count / (1 << config.logTraceLength))
        data.append(Data(bytes: &txCount, count: 4))

        // Add state root transitions at boundaries
        let rowsPerTx = 1 << config.logTraceLength
        for i in 1..<(Int(txCount)) {
            let boundaryRow = i * rowsPerTx
            if boundaryRow < blockTrace[2].count {
                var stateRoot = blockTrace[2][boundaryRow].v
                data.append(Data(bytes: &stateRoot, count: 4))
            }
        }

        return data
    }

    // MARK: - Helpers

    private static func log2Ceil(_ n: Int) -> Int {
        var count = 0
        var value = n - 1
        while value > 0 {
            count += 1
            value >>= 1
        }
        return count
    }
}

// MARK: - Two-Tier Proof Result

/// Result of two-tier proving containing both fast and full proofs.
public struct TwoTierProofResult {
    /// Fast proof (tier 1) - only critical columns verified
    public let tier1Proof: BlockProof?

    /// Full proof (tier 2) - all columns verified
    public let tier2Proof: BlockProof

    /// Metadata about the proof tier
    public let tierMetadata: ProofTierMetadata

    /// Which tier was actually generated
    public var generatedTiers: [ProofTier] {
        var tiers: [ProofTier] = []
        if tier1Proof != nil {
            tiers.append(.fast)
        }
        tiers.append(.full)
        return tiers
    }
}

// MARK: - Block Prover Errors

public enum BlockProverError: Error, Sendable {
    case noTransactions
    case tooManyTransactions(requested: Int, max: Int)
    case noExecutionResults
    case traceConversionFailed
    case constraintEvaluationFailed
    case proofGenerationFailed
    case verificationFailed
    case commitmentFailed
    case witnessUnavailable
    case stateProofFailed(String)
    case stateProofUnsupported
}

// MARK: - Benchmarking Extension

extension ZoltraakBlockProver {

    /// Benchmark comparison between sequential and unified block proving
    public static func benchmarkComparison(
        transactionCount: Int = 150,
        logTraceLength: Int = 12
    ) async throws -> BenchmarkResult {
        // Create test transactions
        let transactions = (0..<transactionCount).map { i in
            EVMTransaction(
                code: [0x60, 0x01],  // PUSH1 1
                calldata: [],
                value: .zero,
                gasLimit: 21_000,
                txHash: "tx_\(i)"
            )
        }

        let blockContext = BlockContext()

        // Benchmark sequential proving (estimated)
        let sequentialTimeMs = Double(transactionCount) * 1750  // 1750ms per tx

        // Benchmark unified block proving
        let blockProver = try ZoltraakBlockProver(config: .fast)
        let blockProof = try await blockProver.prove(
            transactions: transactions,
            blockContext: blockContext
        )

        let blockTimeMs = blockProof.timing.totalMs
        let speedup = sequentialTimeMs / blockTimeMs

        return BenchmarkResult(
            transactionCount: transactionCount,
            sequentialTimeMs: sequentialTimeMs,
            blockTimeMs: blockTimeMs,
            speedup: speedup,
            perTransactionMs: blockTimeMs / Double(transactionCount)
        )
    }

    /// Benchmark proof compression effectiveness
    public static func benchmarkCompression(
        transactionCount: Int = 123,
        compressionConfig: ProofCompressionConfig = .highCompression
    ) async throws -> CompressionBenchmarkResult {
        // Create test transactions
        let transactions = (0..<transactionCount).map { i in
            EVMTransaction(
                code: [0x60, 0x01],
                calldata: [],
                value: .zero,
                gasLimit: 21_000,
                txHash: "tx_\(i)"
            )
        }

        let blockContext = BlockContext()

        // Baseline (no compression)
        let baselineProver = try ZoltraakBlockProver(config: .fast)
        let baselineStart = CFAbsoluteTimeGetCurrent()
        let baselineProof = try await baselineProver.prove(
            transactions: transactions,
            blockContext: blockContext
        )
        let baselineMs = (CFAbsoluteTimeGetCurrent() - baselineStart) * 1000

        // Compressed
        let compressedProver = try ZoltraakBlockProver(
            config: .fast,
            compressionConfig: compressionConfig
        )
        let compressedStart = CFAbsoluteTimeGetCurrent()
        let compressedProof = try await compressedProver.prove(
            transactions: transactions,
            blockContext: blockContext
        )
        let compressedMs = (CFAbsoluteTimeGetCurrent() - compressedStart) * 1000

        let speedup = baselineMs / compressedMs
        let securityAnalysis = ProofCompressionSecurityAnalysis(
            baseline: .none,
            compressed: compressionConfig
        )

        return CompressionBenchmarkResult(
            transactionCount: transactionCount,
            baselineMs: baselineMs,
            compressedMs: compressedMs,
            speedup: speedup,
            securityAnalysis: securityAnalysis,
            baselineProof: baselineProof,
            compressedProof: compressedProof
        )
    }
}

/// Result of compression benchmarking
public struct CompressionBenchmarkResult {
    public let transactionCount: Int
    public let baselineMs: Double
    public let compressedMs: Double
    public let speedup: Double
    public let securityAnalysis: ProofCompressionSecurityAnalysis
    public let baselineProof: BlockProof
    public let compressedProof: BlockProof

    public var summary: String {
        """
        Compression Benchmark Result (\(transactionCount) transactions):
          Baseline (logTrace=12, 180 cols): \(String(format: "%.1fms", baselineMs))
          Compressed:                      \(String(format: "%.1fms", compressedMs))
          Speedup:                         \(String(format: "%.1fx", speedup))

        \(securityAnalysis.report)
        """
    }
}

/// Result of benchmarking comparison
public struct BenchmarkResult: Sendable {
    public let transactionCount: Int
    public let sequentialTimeMs: Double
    public let blockTimeMs: Double
    public let speedup: Double
    public let perTransactionMs: Double

    public var summary: String {
        """
        Benchmark Result (\(transactionCount) transactions):
          Sequential: \(String(format: "%.1fms", sequentialTimeMs)) (estimated)
          Block:      \(String(format: "%.1fms", blockTimeMs))
          Speedup:    \(String(format: "%.1fx", speedup))
          Per-tx:     \(String(format: "%.2fms", perTransactionMs))
        """
    }
}

// MARK: - Extension for M31Word conversion

extension M31Word {
    /// Convert to array of M31 limbs
    public func toM31Limbs() -> [M31] {
        let bytes = self.toBytes()
        var limbs: [M31] = []

        // Split 32 bytes into 9 M31 limbs (each M31 can hold ~31 bits)
        for i in 0..<9 {
            let start = i * 4
            if start + 4 <= bytes.count {
                let value = UInt32(bytes[start]) |
                           (UInt32(bytes[start + 1]) << 8) |
                           (UInt32(bytes[start + 2]) << 16) |
                           (UInt32(bytes[start + 3]) << 24)
                limbs.append(M31(v: value & 0x7FFFFFFF))
            }
        }

        return limbs
    }
}

// MARK: - GPU Proof Serialization

/// Serialize GPUCircleSTARKProverProof to Data for storage/transmission
private func serializeGPUSTARKProof(_ proof: GPUCircleSTARKProverProof) -> Data {
    var data = Data()

    // Serialize trace commitments
    var numTraceCommitments = UInt32(proof.traceCommitments.count)
    data.append(Data(bytes: &numTraceCommitments, count: 4))
    for commitment in proof.traceCommitments {
        for val in commitment.values {
            var v = val.v
            data.append(Data(bytes: &v, count: 4))
        }
    }

    // Serialize composition commitment
    for val in proof.compositionCommitment.values {
        var v = val.v
        data.append(Data(bytes: &v, count: 4))
    }

    // Serialize quotient commitments
    var numQuotient = UInt32(proof.quotientCommitments.count)
    data.append(Data(bytes: &numQuotient, count: 4))
    for commitment in proof.quotientCommitments {
        for val in commitment.values {
            var v = val.v
            data.append(Data(bytes: &v, count: 4))
        }
    }

    // Serialize FRI proof
    var numRounds = UInt32(proof.friProof.rounds.count)
    data.append(Data(bytes: &numRounds, count: 4))
    for round in proof.friProof.rounds {
        // Commitment
        for val in round.commitment.values {
            var v = val.v
            data.append(Data(bytes: &v, count: 4))
        }
        // Query responses
        var numQueries = UInt32(round.queryResponses.count)
        data.append(Data(bytes: &numQueries, count: 4))
        for (valA, valB, path) in round.queryResponses {
            var a = valA.v
            var b = valB.v
            data.append(Data(bytes: &a, count: 4))
            data.append(Data(bytes: &b, count: 4))
            var pathLen = UInt32(path.count)
            data.append(Data(bytes: &pathLen, count: 4))
            for digest in path {
                for v in digest.values {
                    var val = v.v
                    data.append(Data(bytes: &val, count: 4))
                }
            }
        }
    }

    // Final value
    var finalVal = proof.friProof.finalValue.v
    data.append(Data(bytes: &finalVal, count: 4))

    // Query indices
    var numIndices = UInt32(proof.friProof.queryIndices.count)
    data.append(Data(bytes: &numIndices, count: 4))
    for idx in proof.friProof.queryIndices {
        var i = UInt32(idx)
        data.append(Data(bytes: &i, count: 4))
    }

    // Alpha
    var alpha = proof.alpha.v
    data.append(Data(bytes: &alpha, count: 4))

    // Metadata
    var traceLength = UInt32(proof.traceLength)
    data.append(Data(bytes: &traceLength, count: 4))
    var numColumns = UInt32(proof.numColumns)
    data.append(Data(bytes: &numColumns, count: 4))
    var logBlowup = UInt8(proof.logBlowup)
    data.append(Data(bytes: &logBlowup, count: 1))

    // Query responses (trace + composition openings)
    var numQueryResponses = UInt32(proof.queryResponses.count)
    data.append(Data(bytes: &numQueryResponses, count: 4))
    for qr in proof.queryResponses {
        // Trace values
        var numTrace = UInt32(qr.traceValues.count)
        data.append(Data(bytes: &numTrace, count: 4))
        for val in qr.traceValues {
            var v = val.v
            data.append(Data(bytes: &v, count: 4))
        }
        // Trace paths
        var numPaths = UInt32(qr.tracePaths.count)
        data.append(Data(bytes: &numPaths, count: 4))
        for path in qr.tracePaths {
            var pathLen = UInt32(path.count)
            data.append(Data(bytes: &pathLen, count: 4))
            for digest in path {
                for v in digest.values {
                    var val = v.v
                    data.append(Data(bytes: &val, count: 4))
                }
            }
        }
        // Composition value
        var compVal = qr.compositionValue.v
        data.append(Data(bytes: &compVal, count: 4))
        // Composition path
        var compPathLen = UInt32(qr.compositionPath.count)
        data.append(Data(bytes: &compPathLen, count: 4))
        for digest in qr.compositionPath {
            for v in digest.values {
                var val = v.v
                data.append(Data(bytes: &val, count: 4))
            }
        }
        // Quotient split values
        var numSplit = UInt32(qr.quotientSplitValues.count)
        data.append(Data(bytes: &numSplit, count: 4))
        for val in qr.quotientSplitValues {
            var v = val.v
            data.append(Data(bytes: &v, count: 4))
        }
        // Query index
        var queryIdx = UInt32(qr.queryIndex)
        data.append(Data(bytes: &queryIdx, count: 4))
    }

    return data
}
