import Foundation
import zkMetal

/// Configuration for parallel transaction execution
public struct TxParallelConfig: Sendable {
    /// Number of worker threads for parallel execution
    public let numWorkers: Int

    /// Maximum queue size for pipeline (execution → proving)
    public let pipelineQueueSize: Int

    /// Enable pre-validation before execution
    public let enablePreValidation: Bool

    /// Pre-validation strictness level
    public let preValidationLevel: PreValidationLevel

    /// Maximum batch size for pre-validation
    public let maxBatchSize: Int

    public enum PreValidationLevel: Sendable {
        case minimal  // Only check gas limit
        case standard  // gas + nonce + basic structure
        case strict  // Full EVM pre-flight checks
    }

    public static let `default` = TxParallelConfig(
        numWorkers: 4,
        pipelineQueueSize: 8,
        enablePreValidation: true,
        preValidationLevel: .standard,
        maxBatchSize: 32
    )

    public static let highThroughput = TxParallelConfig(
        numWorkers: 8,
        pipelineQueueSize: 16,
        enablePreValidation: true,
        preValidationLevel: .minimal,
        maxBatchSize: 64
    )
}

/// Result of pre-validation
public struct TxPreValidation: Sendable {
    public enum ValidationStatus: Sendable {
        case valid
        case invalid(reason: String)
        case uncertain  // Could not determine, needs full execution
    }

    public let status: ValidationStatus
    public let estimatedGas: UInt64
    public let canSkipProving: Bool

    public static let valid = TxPreValidation(
        status: .valid,
        estimatedGas: 0,
        canSkipProving: false
    )

    public static func invalid(_ reason: String) -> TxPreValidation {
        TxPreValidation(
            status: .invalid(reason: reason),
            estimatedGas: 0,
            canSkipProving: true
        )
    }
}

/// Result of parallel execution for a single transaction
public struct TxExecutionResult: Sendable {
    public let transactionIndex: Int
    public let transaction: EVMTransaction
    public let executionResult: EVMExecutionResult?
    public let error: Error?
    public let executionTimeMs: Double
    public let workerId: Int

    public var succeeded: Bool { error == nil && executionResult != nil }
}

/// Actor-based parallel transaction execution engine
///
/// Uses Swift's actor isolation to safely execute transactions in parallel across CPU cores.
/// Each transaction gets its own isolated EVMExecutionEngine instance to prevent data races.
public actor EVMTxParallelEngine {

    // MARK: - Configuration

    public let config: TxParallelConfig

    // MARK: - State

    private let workerPool: [TxWorkerActor]
    private var executionResults: [Int: TxExecutionResult]
    private var completedCount: Int = 0
    private var totalCount: Int = 0

    // MARK: - Initialization

    public init(config: TxParallelConfig = .default) async throws {
        self.config = config
        self.executionResults = [:]
        self.workerPool = (0..<config.numWorkers).map { TxWorkerActor(workerId: $0) }
    }

    // MARK: - Public API

    /// Execute transactions in parallel across CPU cores
    /// - Parameters:
    ///   - transactions: Array of transactions to execute
    ///   - blockContext: Block context for EVM execution
    ///   - txContext: Transaction context
    /// - Returns: Array of execution results in original order
    public func executeParallel(
        transactions: [EVMTransaction],
        blockContext: BlockContext = BlockContext(),
        txContext: TransactionContext = TransactionContext()
    ) async throws -> [TxExecutionResult] {
        totalCount = transactions.count
        completedCount = 0
        executionResults = [:]

        // Split transactions into chunks for workers
        let chunks = splitIntoChunks(transactions, count: config.numWorkers)

        // Execute all chunks in parallel
        await withTaskGroup(of: [TxExecutionResult].self) { group in
            var currentIndex = 0
            for workerId in 0..<chunks.count {
                let chunk = chunks[workerId]
                let worker = workerPool[workerId % workerPool.count]
                let startIndex = currentIndex
                currentIndex += chunk.count
                group.addTask {
                    await worker.executeChunk(
                        transactions: chunk,
                        startIndex: startIndex,
                        blockContext: blockContext,
                        txContext: txContext
                    )
                }
            }

            // Collect results
            for await results in group {
                for result in results {
                    executionResults[result.transactionIndex] = result
                }
            }
        }

        // Return results in original order
        return (0..<totalCount).compactMap { executionResults[$0] }
    }

    /// Execute a single transaction
    public func executeSingle(
        transaction: EVMTransaction,
        blockContext: BlockContext = BlockContext(),
        txContext: TransactionContext = TransactionContext()
    ) async throws -> TxExecutionResult {
        let engine = EVMExecutionEngine(block: blockContext, tx: txContext)
        let startTime = CFAbsoluteTimeGetCurrent()

        do {
            let result = try engine.execute(
                code: transaction.code,
                calldata: transaction.calldata,
                value: transaction.value,
                gasLimit: transaction.gasLimit
            )

            let executionTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

            return TxExecutionResult(
                transactionIndex: 0,
                transaction: transaction,
                executionResult: result,
                error: nil,
                executionTimeMs: executionTimeMs,
                workerId: 0
            )
        } catch {
            return TxExecutionResult(
                transactionIndex: 0,
                transaction: transaction,
                executionResult: nil,
                error: error,
                executionTimeMs: (CFAbsoluteTimeGetCurrent() - startTime) * 1000,
                workerId: 0
            )
        }
    }

    // MARK: - Pre-Validation

    /// Pre-validate transactions to filter out invalid ones early
    public func preValidate(_ transactions: [EVMTransaction]) -> [TxPreValidation] {
        guard config.enablePreValidation else {
            return transactions.map { _ in TxPreValidation.valid }
        }

        return transactions.map { tx in
            validateTransaction(tx)
        }
    }

    /// Filter transactions based on pre-validation results
    public func filterByPreValidation(
        transactions: [EVMTransaction],
        validations: [TxPreValidation]
    ) -> (valid: [EVMTransaction], skipped: [(EVMTransaction, String)]) {
        var valid: [EVMTransaction] = []
        var skipped: [(EVMTransaction, String)] = []

        for (tx, validation) in zip(transactions, validations) {
            switch validation.status {
            case .valid:
                valid.append(tx)
            case .invalid(let reason):
                skipped.append((tx, reason))
            case .uncertain:
                valid.append(tx)  // Execute to determine
            }
        }

        return (valid, skipped)
    }

    // MARK: - Helpers

    private func splitIntoChunks(_ transactions: [EVMTransaction], count: Int) -> [[EVMTransaction]] {
        guard count > 0 && !transactions.isEmpty else { return [] }

        var chunks: [[EVMTransaction]] = Array(repeating: [], count: count)
        var counts = [Int](repeating: 0, count: count)

        // Distribute based on transaction size for load balancing
        for tx in transactions {
            // Find worker with least total work
            let workerIdx = counts.enumerated().min(by: { $0.element < $1.element })?.offset ?? 0
            chunks[workerIdx].append(tx)
            // Estimate work based on gas limit
            counts[workerIdx] += Int(tx.gasLimit / 1_000_000)
        }

        return chunks.filter { !$0.isEmpty }
    }

    private func validateTransaction(_ tx: EVMTransaction) -> TxPreValidation {
        switch config.preValidationLevel {
        case .minimal:
            return validateMinimal(tx)
        case .standard:
            return validateStandard(tx)
        case .strict:
            return validateStrict(tx)
        }
    }

    /// Minimal validation: only check gas limit
    private func validateMinimal(_ tx: EVMTransaction) -> TxPreValidation {
        // Basic gas limit check
        if tx.gasLimit == 0 {
            return TxPreValidation.invalid("Gas limit is zero")
        }
        if tx.gasLimit > 30_000_000 {
            return TxPreValidation.invalid("Gas limit exceeds block gas limit")
        }
        return TxPreValidation.valid
    }

    /// Standard validation: gas + basic structure
    private func validateStandard(_ tx: EVMTransaction) -> TxPreValidation {
        // Gas limit check
        if tx.gasLimit == 0 {
            return TxPreValidation.invalid("Gas limit is zero")
        }
        if tx.gasLimit > 30_000_000 {
            return TxPreValidation.invalid("Gas limit exceeds block gas limit")
        }

        // Empty code with non-zero value is invalid
        if tx.code.isEmpty && !tx.value.isZero {
            return TxPreValidation.invalid("Empty code with non-zero value")
        }

        // Calldata size sanity check (max 128KB)
        if tx.calldata.count > 128 * 1024 {
            return TxPreValidation.invalid("Calldata too large")
        }

        return TxPreValidation.valid
    }

    /// Strict validation: full pre-flight checks
    private func validateStrict(_ tx: EVMTransaction) -> TxPreValidation {
        // First run standard checks
        let standard = validateStandard(tx)
        if case .invalid = standard.status {
            return standard
        }

        // Code size sanity check (max 24KB for contract code)
        if tx.code.count > 24 * 1024 {
            return TxPreValidation.invalid("Code too large")
        }

        // Check for obviously invalid jump destinations
        // (simplified - real implementation would parse bytecode)
        if let firstOpcode = tx.code.first {
            // JUMP/JUMPI as first opcode is always invalid
            if firstOpcode == 0x56 || firstOpcode == 0x57 {
                return TxPreValidation.invalid("Invalid jump as first opcode")
            }
        }

        return TxPreValidation.valid
    }
}

// MARK: - Worker Actor

/// Actor that handles execution of a chunk of transactions on a single worker
private actor TxWorkerActor {
    public let workerId: Int

    init(workerId: Int) {
        self.workerId = workerId
    }

    func executeChunk(
        transactions: [EVMTransaction],
        startIndex: Int,
        blockContext: BlockContext,
        txContext: TransactionContext
    ) -> [TxExecutionResult] {
        var results: [TxExecutionResult] = []
        results.reserveCapacity(transactions.count)

        // Each worker has its own engine to avoid data races
        for (localIndex, tx) in transactions.enumerated() {
            let globalIndex = startIndex + localIndex
            let result = executeTransaction(
                tx,
                index: globalIndex,
                blockContext: blockContext,
                txContext: txContext
            )
            results.append(result)
        }

        return results
    }

    private func executeTransaction(
        _ tx: EVMTransaction,
        index: Int,
        blockContext: BlockContext,
        txContext: TransactionContext
    ) -> TxExecutionResult {
        let engine = EVMExecutionEngine(block: blockContext, tx: txContext)
        let startTime = CFAbsoluteTimeGetCurrent()

        do {
            let result = try engine.execute(
                code: tx.code,
                calldata: tx.calldata,
                value: tx.value,
                gasLimit: tx.gasLimit
            )

            let executionTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

            return TxExecutionResult(
                transactionIndex: index,
                transaction: tx,
                executionResult: result,
                error: nil,
                executionTimeMs: executionTimeMs,
                workerId: workerId
            )
        } catch {
            return TxExecutionResult(
                transactionIndex: index,
                transaction: tx,
                executionResult: nil,
                error: error,
                executionTimeMs: (CFAbsoluteTimeGetCurrent() - startTime) * 1000,
                workerId: workerId
            )
        }
    }
}

// MARK: - Synchronous Wrapper for Non-Actor Context

/// Synchronous wrapper for parallel execution engine
/// Provides a simpler interface when actor isolation is not required
public final class EVMTxParallelEngineSync: @unchecked Sendable {

    private let config: TxParallelConfig

    public init(config: TxParallelConfig = .default) {
        self.config = config
    }

    /// Execute transactions in parallel using GCD
    public func executeParallel(
        transactions: [EVMTransaction],
        blockContext: BlockContext = BlockContext(),
        txContext: TransactionContext = TransactionContext()
    ) async throws -> [TxExecutionResult] {
        let engine = try await EVMTxParallelEngine(config: config)
        return try await engine.executeParallel(
            transactions: transactions,
            blockContext: blockContext,
            txContext: txContext
        )
    }

    /// Pre-validate transactions
    public func preValidate(_ transactions: [EVMTransaction]) async -> [TxPreValidation] {
        let engine = try? await EVMTxParallelEngine(config: config)
        return await engine?.preValidate(transactions) ?? transactions.map { _ in TxPreValidation.valid }
    }

    /// Filter by pre-validation
    public func filterByPreValidation(
        transactions: [EVMTransaction],
        validations: [TxPreValidation]
    ) -> (valid: [EVMTransaction], skipped: [(EVMTransaction, String)]) {
        // This is synchronous, so we need a different approach
        var valid: [EVMTransaction] = []
        var skipped: [(EVMTransaction, String)] = []

        for (tx, validation) in zip(transactions, validations) {
            switch validation.status {
            case .valid:
                valid.append(tx)
            case .invalid(let reason):
                skipped.append((tx, reason))
            case .uncertain:
                valid.append(tx)
            }
        }

        return (valid, skipped)
    }
}
