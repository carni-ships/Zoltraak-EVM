import Foundation
import zkMetal

/// Configuration for batch proving
public struct BatchProverConfig {
    /// Number of transactions to batch together
    public let batchSize: Int

    /// Use GPU acceleration
    public let useGPU: Bool

    /// Log of trace length per transaction
    public let logTraceLength: Int

    /// Number of FRI queries
    public let numQueries: Int

    /// Log of blowup factor for LDE
    public let logBlowup: Int

    public init(batchSize: Int, useGPU: Bool, logTraceLength: Int, numQueries: Int, logBlowup: Int) {
        self.batchSize = batchSize
        self.useGPU = useGPU
        self.logTraceLength = logTraceLength
        self.numQueries = numQueries
        self.logBlowup = logBlowup
    }

    public static let `default` = BatchProverConfig(
        batchSize: 1,
        useGPU: true,
        logTraceLength: 16,
        numQueries: 30,
        logBlowup: 4
    )

    public static let highThroughput = BatchProverConfig(
        batchSize: 8,
        useGPU: true,
        logTraceLength: 18,
        numQueries: 30,
        logBlowup: 4
    )
}

/// Result of a batch proof
public struct EVMBatchProof {
    /// Individual transaction proofs
    public let transactionProofs: [CircleSTARKProof]

    /// Aggregated proof (if batchSize > 1)
    public let aggregatedProof: Data?

    /// Batch configuration used
    public let batchConfig: BatchProverConfig

    /// Time taken to generate proofs in milliseconds
    public let provingTimeMs: Double

    public init(
        transactionProofs: [CircleSTARKProof],
        aggregatedProof: Data?,
        batchConfig: BatchProverConfig,
        provingTimeMs: Double
    ) {
        self.transactionProofs = transactionProofs
        self.aggregatedProof = aggregatedProof
        self.batchConfig = batchConfig
        self.provingTimeMs = provingTimeMs
    }
}

/// Batch prover using CircleSTARK
public final class EVMBatchProver: Sendable {

    public let config: BatchProverConfig
    private let circleProver: CircleSTARKProver

    public init(config: BatchProverConfig = .default) {
        self.config = config
        self.circleProver = CircleSTARKProver(logBlowup: config.logBlowup, numQueries: config.numQueries)
    }

    // MARK: - Batch Proving

    /// Prove multiple transactions in parallel
    public func proveBatch(
        transactions: [EVMTransaction],
        initialStateRoot: M31Word = .zero
    ) throws -> EVMBatchProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Execute each transaction and generate traces
        let engine = EVMExecutionEngine()
        var airInstances: [EVMAIR] = []
        var results: [EVMExecutionResult] = []

        for tx in transactions {
            let result = try engine.execute(
                code: tx.code,
                calldata: tx.calldata,
                value: tx.value,
                gasLimit: tx.gasLimit
            )
            results.append(result)

            // Create AIR from execution result
            let air = EVMAIR.fromExecution(result)
            airInstances.append(air)
        }

        // Generate CircleSTARK proofs for each transaction
        var proofs: [CircleSTARKProof] = []

        if config.useGPU {
            // Use CPU path since FibonacciAIR GPU path doesn't support our AIR
            for air in airInstances {
                let proof = try circleProver.proveCPU(air: air)
                proofs.append(proof)
            }
        } else {
            for air in airInstances {
                let proof = try circleProver.proveCPU(air: air)
                proofs.append(proof)
            }
        }

        let provingTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        return EVMBatchProof(
            transactionProofs: proofs,
            aggregatedProof: nil,
            batchConfig: config,
            provingTimeMs: provingTimeMs
        )
    }

    /// Prove a single transaction
    public func prove(
        transaction: EVMTransaction,
        initialStateRoot: M31Word = .zero
    ) throws -> CircleSTARKProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Execute transaction
        let engine = EVMExecutionEngine()
        let result = try engine.execute(
            code: transaction.code,
            calldata: transaction.calldata,
            value: transaction.value,
            gasLimit: transaction.gasLimit
        )

        // Create AIR from execution result
        let air = EVMAIR.fromExecution(result)

        // Generate proof
        let proof: CircleSTARKProof
        if config.useGPU {
            proof = try circleProver.proveCPU(air: air)
        } else {
            proof = try circleProver.proveCPU(air: air)
        }

        return proof
    }
}

// MARK: - EVM Transaction

/// A transaction to be proven
public struct EVMTransaction: Sendable {
    public let code: [UInt8]
    public let calldata: [UInt8]
    public let value: M31Word
    public let gasLimit: UInt64
    public let sender: M31Word?

    public init(
        code: [UInt8],
        calldata: [UInt8] = [],
        value: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000,
        sender: M31Word? = nil
    ) {
        self.code = code
        self.calldata = calldata
        self.value = value
        self.gasLimit = gasLimit
        self.sender = sender
    }

    /// Create a simple ETH transfer
    public static func transfer(to: M31Word, amount: M31Word, gasLimit: UInt64 = 21_000) -> EVMTransaction {
        return EVMTransaction(
            code: [],
            calldata: [],
            value: amount,
            gasLimit: gasLimit,
            sender: to
        )
    }

    /// Create a contract call with calldata
    public static func call(
        to: M31Word,
        calldata: [UInt8],
        value: M31Word = .zero,
        gasLimit: UInt64 = 100_000
    ) -> EVMTransaction {
        // Simple CALL bytecode
        var code = [UInt8]()
        code.append(0x60)  // PUSH1
        code.append(0x00)  // value
        code.append(0x73)  // PUSH20
        code.append(contentsOf: to.toBytes().suffix(20))
        code.append(0x61)  // PUSH2
        code.append(contentsOf: [UInt8](repeating: 0, count: 2))  // calldata length placeholder
        code.append(0x80)  // DUP1
        code.append(0x60)  // PUSH1
        code.append(0x00)  // offset
        code.append(0x60)  // PUSH1
        code.append(0x00)  // offset
        code.append(0xF4)  // DELEGATECALL
        // Need more for actual call...

        return EVMTransaction(
            code: code,
            calldata: calldata,
            value: value,
            gasLimit: gasLimit,
            sender: nil
        )
    }
}

// MARK: - Block Prover

/// Configuration for block proving
public struct BlockProverConfig {
    /// Transactions per block
    public let txsPerBlock: Int

    /// Use parallel batch proving
    public let parallelBatches: Int

    /// Use recursive aggregation
    public let useRecursion: Bool

    /// Aggregation cadence (every N blocks)
    public let aggregationCadence: Int

    public static let `default` = BlockProverConfig(
        txsPerBlock: 100,
        parallelBatches: 4,
        useRecursion: true,
        aggregationCadence: 1
    )
}

/// Result of a block proof
public struct EVMBlockProof {
    public let blockNumber: UInt64
    public let transactionProofs: [CircleSTARKProof]
    public let blockProof: Data?
    public let finalProof: Data?
    public let config: BlockProverConfig
    public let provingTimeMs: Double

    public var estimatedFinalProofSize: Int {
        guard let final = finalProof else { return 0 }
        return final.count
    }
}

/// Block-level prover with aggregation
public final class EVMBlockProver: Sendable {

    public let config: BlockProverConfig
    private let batchProver: EVMBatchProver

    public init(config: BlockProverConfig = .default) {
        self.config = config

        // Configure batch prover based on parallelization
        let batchConfig = BatchProverConfig(
            batchSize: max(1, config.txsPerBlock / config.parallelBatches),
            useGPU: true,
            logTraceLength: 18,
            numQueries: 30,
            logBlowup: 4
        )
        self.batchProver = EVMBatchProver(config: batchConfig)
    }

    // MARK: - Block Proving

    /// Prove a block of transactions
    public func proveBlock(
        transactions: [EVMTransaction],
        blockNumber: UInt64,
        previousStateRoot: M31Word = .zero
    ) throws -> EVMBlockProof {
        let startTime = CFAbsoluteTimeGetCurrent()

        // Split transactions into parallel batches
        let batches = splitIntoBatches(transactions, count: config.parallelBatches)

        // Prove each batch in parallel (conceptually - actual parallelization would use GCD)
        var allBatchProofs: [EVMBatchProof] = []
        for batch in batches {
            let batchProof = try batchProver.proveBatch(
                transactions: batch,
                initialStateRoot: previousStateRoot
            )
            allBatchProofs.append(batchProof)
        }

        let provingTimeMs = (CFAbsoluteTimeGetCurrent() - startTime) * 1000

        // Collect all transaction proofs
        let allTxProofs = allBatchProofs.flatMap { $0.transactionProofs }

        return EVMBlockProof(
            blockNumber: blockNumber,
            transactionProofs: allTxProofs,
            blockProof: nil,
            finalProof: nil,
            config: config,
            provingTimeMs: provingTimeMs
        )
    }

    // MARK: - Helpers

    private func splitIntoBatches(_ transactions: [EVMTransaction], count: Int) -> [[EVMTransaction]] {
        let batchSize = max(1, (transactions.count + count - 1) / count)
        var batches: [[EVMTransaction]] = []

        for i in 0..<count {
            let start = i * batchSize
            let end = min(start + batchSize, transactions.count)
            if start < end {
                batches.append(Array(transactions[start..<end]))
            }
        }

        return batches
    }
}

// MARK: - EVMAIR Extension for CircleSTARK Prover

extension EVMAIR {

    /// Create an AIR from an EVM execution result
    public static func fromExecution(_ result: EVMExecutionResult) -> EVMAIR {
        let traceLength = result.trace.rows.count
        let n = traceLength.nextPowerOfTwo()
        let logLength = max(10, (64 - n.leadingZeroBitCount - 1))

        return EVMAIR(
            logTraceLength: logLength,
            initialStateRoot: result.trace.initialState.stateRoot,
            gasLimit: result.trace.gasUsed + 1_000_000
        )
    }
}

// MARK: - Int Extension

extension Int {
    func nextPowerOfTwo() -> Int {
        var n = Swift.max(1, self)
        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        return n + 1
    }
}
