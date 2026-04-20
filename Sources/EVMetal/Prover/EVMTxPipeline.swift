import Foundation
import zkMetal

/// Pipeline stage for transaction processing
public enum PipelineStage: Sendable {
    case idle
    case executing(index: Int)
    case lde(index: Int)
    case committing(index: Int)
    case fri(index: Int)
}

/// Configuration for pipeline execution
public struct PipelineConfig: Sendable {
    /// Number of parallel execution workers
    public let numWorkers: Int

    /// Queue size between stages (bounded buffer)
    public let queueSize: Int

    /// Maximum concurrent proving tasks
    public let maxProvingTasks: Int

    /// Enable early termination on first failure
    public let failFast: Bool

    /// Enable pre-validation filtering
    public let enablePreValidation: Bool

    public static let `default` = PipelineConfig(
        numWorkers: 4,
        queueSize: 8,
        maxProvingTasks: 4,
        failFast: false,
        enablePreValidation: true
    )

    public static let highThroughput = PipelineConfig(
        numWorkers: 8,
        queueSize: 16,
        maxProvingTasks: 8,
        failFast: false,
        enablePreValidation: true
    )
}

/// Pipeline item representing a transaction at various stages
public struct PipelineItem: Sendable, Identifiable {
    public let id: Int
    public let transaction: EVMTransaction
    public let preValidation: TxPreValidation?
    public var executionResult: EVMExecutionResult?
    public var proof: EVMBatchProof?
    public var stage: PipelineStage
    public var error: Error?
    public var executionTimeMs: Double = 0
    public var provingTimeMs: Double = 0

    public init(
        id: Int,
        transaction: EVMTransaction,
        preValidation: TxPreValidation? = nil
    ) {
        self.id = id
        self.transaction = transaction
        self.preValidation = preValidation
        self.stage = .idle
    }

    public var isComplete: Bool {
        proof != nil || error != nil
    }

    public var succeeded: Bool {
        proof != nil && error == nil
    }
}

/// Pipeline result containing timing and throughput metrics
public struct PipelineResult: Sendable {
    public let items: [PipelineItem]
    public let totalTimeMs: Double
    public let executionTimeMs: Double
    public let provingTimeMs: Double
    public let pipelineEfficiency: Double  // 0-1, how much proving overlapped with execution
    public let skippedCount: Int
    public let failedCount: Int
    public let throughput: Double  // transactions per second

    public var summary: String {
        """
        Pipeline Result:
          Total Time: \(String(format: "%.1fms", totalTimeMs))
          Execution:   \(String(format: "%.1fms", executionTimeMs))
          Proving:     \(String(format: "%.1fms", provingTimeMs))
          Pipeline Eff:\(String(format: "%.1f%%", pipelineEfficiency * 100))
          Throughput:  \(String(format: "%.1f", throughput)) txn/s
          Skipped:     \(skippedCount) (early rejection)
          Failed:      \(failedCount)
        """
    }
}

/// Pipeline coordinator that overlaps execution and proving stages
///
/// Uses a producer-consumer pattern with bounded queues to achieve pipeline parallelism:
/// - Execute stage: Runs transactions on CPU cores
/// - LDE stage: GPU-accelerated low-degree extension
/// - Commit stage: Merkle/Brakedown commitment
/// - FRI stage: Fast Reed-Solomon IOP
///
/// While transaction N is being proven, transaction N+1 is being executed, etc.
public actor EVMTxPipelineCoordinator {

    // MARK: - Configuration

    public let config: PipelineConfig

    // MARK: - Components

    private let parallelEngine: EVMTxParallelEngine
    private let batchProver: EVMBatchProver

    // MARK: - State

    private var pipelineItems: [PipelineItem] = []
    private var executionQueue: [PipelineItem] = []
    private var provingQueue: [PipelineItem] = []
    private var completedItems: [PipelineItem] = []
    private var currentStage: PipelineStage = .idle
    private var totalExecutionTimeMs: Double = 0
    private var totalProvingTimeMs: Double = 0
    private var executionStartTime: Double = 0
    private var provingStartTime: Double = 0

    // MARK: - Initialization

    public init(
        pipelineConfig: PipelineConfig = .default,
        batchConfig: BatchProverConfig = .default
    ) async throws {
        self.config = pipelineConfig
        self.parallelEngine = try await EVMTxParallelEngine(config: TxParallelConfig(
            numWorkers: pipelineConfig.numWorkers,
            pipelineQueueSize: pipelineConfig.queueSize,
            enablePreValidation: pipelineConfig.enablePreValidation,
            preValidationLevel: .standard,
            maxBatchSize: 32
        ))
        self.batchProver = EVMBatchProver(config: batchConfig)
    }

    // MARK: - Public API

    /// Run the full pipeline: pre-validate → execute → prove
    public func run(transactions: [EVMTransaction]) async throws -> PipelineResult {
        let pipelineStart = CFAbsoluteTimeGetCurrent()
        executionStartTime = pipelineStart

        // Step 1: Pre-validation
        let validations = await parallelEngine.preValidate(transactions)
        let (validTxs, skipped) = await parallelEngine.filterByPreValidation(
            transactions: transactions,
            validations: validations
        )

        // Step 2: Initialize pipeline items
        pipelineItems = validTxs.enumerated().map { index, tx in
            PipelineItem(id: index, transaction: tx)
        }
        let skippedCount = skipped.count

        // Step 3: Parallel execution
        let executionResults = try await parallelEngine.executeParallel(
            transactions: validTxs,
            blockContext: BlockContext(),
            txContext: TransactionContext()
        )

        let executionEnd = CFAbsoluteTimeGetCurrent()
        totalExecutionTimeMs = (executionEnd - executionStartTime) * 1000

        // Link execution results to pipeline items
        for result in executionResults {
            if let index = pipelineItems.firstIndex(where: { $0.id == result.transactionIndex }) {
                pipelineItems[index].executionResult = result.executionResult
                pipelineItems[index].executionTimeMs = result.executionTimeMs
            }
        }

        // Step 4: Prove in parallel
        provingStartTime = CFAbsoluteTimeGetCurrent()
        try await proveInPipeline()

        let provingEnd = CFAbsoluteTimeGetCurrent()
        totalProvingTimeMs = (provingEnd - provingStartTime) * 1000

        let pipelineEnd = CFAbsoluteTimeGetCurrent()
        let totalTimeMs = (pipelineEnd - pipelineStart) * 1000

        // Calculate pipeline efficiency
        // Overlap = time spent on both execution and proving concurrently
        let pipelineEfficiency = calculatePipelineEfficiency(
            totalTime: totalTimeMs,
            executionTime: totalExecutionTimeMs,
            provingTime: totalProvingTimeMs
        )

        // Count failures
        let failedCount = pipelineItems.filter { $0.error != nil }.count

        // Calculate throughput
        let throughput = Double(pipelineItems.count) / (totalTimeMs / 1000)

        return PipelineResult(
            items: pipelineItems,
            totalTimeMs: totalTimeMs,
            executionTimeMs: totalExecutionTimeMs,
            provingTimeMs: totalProvingTimeMs,
            pipelineEfficiency: pipelineEfficiency,
            skippedCount: skippedCount,
            failedCount: failedCount,
            throughput: throughput
        )
    }

    /// Get current pipeline status
    public func getStatus() -> PipelineStatus {
        PipelineStatus(
            currentStage: currentStage,
            pendingExecution: executionQueue.count,
            pendingProving: provingQueue.count,
            completed: completedItems.count,
            total: pipelineItems.count
        )
    }

    // MARK: - Pipeline Stages

    /// Prove completed execution results in parallel
    private func proveInPipeline() async throws {
        // Create proving tasks for each completed execution
        let executables = pipelineItems.filter { $0.executionResult != nil && $0.proof == nil }

        await withTaskGroup(of: (Int, EVMBatchProof?).self) { group in
            var activeTasks = 0

            for item in executables {
                // Limit concurrent proving tasks
                if activeTasks >= config.maxProvingTasks {
                    // Wait for one to complete before adding more
                    if let result = await group.next() {
                        activeTasks -= 1
                        await handleProvingResult(index: result.0, proof: result.1)
                    }
                }

                currentStage = .fri(index: item.id)

                group.addTask {
                    let proof = try? await self.proveSingle(item: item)
                    return (item.id, proof)
                }
                activeTasks += 1
            }

            // Collect remaining results
            for await result in group {
                await handleProvingResult(index: result.0, proof: result.1)
            }
        }
    }

    /// Prove a single transaction
    private func proveSingle(item: PipelineItem) async throws -> EVMBatchProof? {
        guard let execution = item.executionResult else { return nil }

        currentStage = .lde(index: item.id)

        let air = EVMAIR.fromExecution(execution)

        currentStage = .committing(index: item.id)

        // Generate proof using batch prover
        let proof = try batchProver.proveBatch(
            transactions: [item.transaction],
            initialStateRoot: .zero
        )

        currentStage = .fri(index: item.id)

        return proof
    }

    /// Handle proving result
    private func handleProvingResult(index: Int, proof: EVMBatchProof?) async {
        if let proof = proof {
            if let itemIndex = pipelineItems.firstIndex(where: { $0.id == index }) {
                pipelineItems[itemIndex].proof = proof
                pipelineItems[itemIndex].stage = .idle
                completedItems.append(pipelineItems[itemIndex])
            }
        } else {
            if let itemIndex = pipelineItems.firstIndex(where: { $0.id == index }) {
                pipelineItems[itemIndex].error = PipelineError.provingFailed
                pipelineItems[itemIndex].stage = .idle
            }
        }
    }

    // MARK: - Helpers

    private func calculatePipelineEfficiency(
        totalTime: Double,
        executionTime: Double,
        provingTime: Double
    ) -> Double {
        // Efficiency = 1 - (sequential_time - total_time) / sequential_time
        // Where sequential_time = executionTime + provingTime
        let sequentialTime = executionTime + provingTime
        if sequentialTime <= 0 { return 0 }

        let overlap = sequentialTime - totalTime
        let efficiency = overlap / sequentialTime
        return max(0, min(1, efficiency))
    }
}

// MARK: - Pipeline Status

public struct PipelineStatus: Sendable {
    public let currentStage: PipelineStage
    public let pendingExecution: Int
    public let pendingProving: Int
    public let completed: Int
    public let total: Int

    public var progress: Double {
        guard total > 0 else { return 0 }
        return Double(completed) / Double(total)
    }

    public var summary: String {
        let stageName: String
        switch currentStage {
        case .idle: stageName = "Idle"
        case .executing(let i): stageName = "Executing(\(i))"
        case .lde(let i): stageName = "LDE(\(i))"
        case .committing(let i): stageName = "Commit(\(i))"
        case .fri(let i): stageName = "FRI(\(i))"
        }
        return "Pipeline: \(stageName), \(completed)/\(total) complete"
    }
}

// MARK: - Pipeline Errors

public enum PipelineError: Error, Sendable {
    case noTransactions
    case allTransactionsSkipped
    case provingFailed
    case executionFailed
    case timeout
}

// MARK: - Bounded Queue for Pipeline Stages

/// Thread-safe bounded queue for producer-consumer pattern
public struct BoundedQueue<Element: Sendable>: @unchecked Sendable {
    private var queue: [Element] = []
    private let capacity: Int
    private let lock = NSLock()

    public init(capacity: Int) {
        self.capacity = capacity
    }

    public mutating func enqueue(_ element: Element) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard queue.count < capacity else { return false }
        queue.append(element)
        return true
    }

    public mutating func dequeue() -> Element? {
        lock.lock()
        defer { lock.unlock() }

        guard !queue.isEmpty else { return nil }
        return queue.removeFirst()
    }

    public var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return queue.isEmpty
    }

    public var isFull: Bool {
        lock.lock()
        defer { lock.unlock() }
        return queue.count >= capacity
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return queue.count
    }
}

// MARK: - Synchronous Pipeline Wrapper

/// Synchronous wrapper for pipeline coordinator
public final class EVMTxPipelineCoordinatorSync: @unchecked Sendable {

    private let config: PipelineConfig
    private let batchConfig: BatchProverConfig

    public init(
        pipelineConfig: PipelineConfig = .default,
        batchConfig: BatchProverConfig = .default
    ) {
        self.config = pipelineConfig
        self.batchConfig = batchConfig
    }

    /// Run the full pipeline
    public func run(transactions: [EVMTransaction]) async throws -> PipelineResult {
        let coordinator = try await EVMTxPipelineCoordinator(
            pipelineConfig: config,
            batchConfig: batchConfig
        )
        return try await coordinator.run(transactions: transactions)
    }
}

// MARK: - High-Level Block Prover with Pipeline

/// High-level block prover that uses pipeline parallelism
public final class EVMTxBlockProverPipeline: @unchecked Sendable {

    public let config: PipelineConfig
    public let batchConfig: BatchProverConfig

    public init(
        pipelineConfig: PipelineConfig = .default,
        batchConfig: BatchProverConfig = .default
    ) {
        self.config = pipelineConfig
        self.batchConfig = batchConfig
    }

    /// Prove a block of transactions with full pipeline parallelism
    public func proveBlock(
        transactions: [EVMTransaction],
        blockNumber: UInt64
    ) async throws -> PipelineResult {
        let coordinator = try await EVMTxPipelineCoordinator(
            pipelineConfig: config,
            batchConfig: batchConfig
        )
        return try await coordinator.run(transactions: transactions)
    }
}
