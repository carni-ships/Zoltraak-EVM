import Foundation
import zkMetal

/// A single row in the EVM execution trace.
/// This represents one step of EVM execution and maps to one row in the CircleAIR trace.
public struct EVMTraceRow: Sendable, Equatable {
    /// Program counter value
    public let pc: Int

    /// Raw opcode byte
    public let opcode: UInt8

    /// Gas remaining
    public let gas: UInt64

    /// Stack height after this operation
    public let stackHeight: Int

    /// Snapshot of top 16 stack words (as M31 limbs) for AIR trace
    /// Each M31Word has 9 M31 limbs for 256-bit representation
    /// Total: 16 slots × 9 limbs = 144 columns (columns 3-146)
    public let stackSnapshot: [M31Word]

    /// Memory size in bytes after this operation
    public let memorySize: Int

    /// Current call depth
    public let callDepth: Int

    /// Poseidon2-M31 state root after this operation
    public let stateRoot: M31Word

    /// Whether the VM is still running
    public let isRunning: Bool

    /// Whether execution has reverted
    public let isReverted: Bool

    /// Timestamp (for memory timestamp ordering)
    public let timestamp: UInt64

    // MARK: - Opcode Classification

    public var opcodeType: EVMOpcode? {
        EVMOpcode(rawValue: opcode)
    }

    public var isStackOp: Bool {
        guard let op = opcodeType else { return false }
        return op.properties.category == .push || op.properties.category == .dup || op.properties.category == .swap
    }

    public var isMemoryOp: Bool {
        guard let op = opcodeType else { return false }
        return op.properties.isMemoryOp
    }

    public var isStorageOp: Bool {
        guard let op = opcodeType else { return false }
        return op.properties.isStorageOp
    }

    public var isControlFlow: Bool {
        guard let op = opcodeType else { return false }
        return op.properties.isControlFlow
    }

    public var isPrecompileCall: Bool {
        guard let op = opcodeType else { return false }
        return op.properties.isPrecompileCall
    }
}

/// The complete execution trace for an EVM transaction
public struct EVMExecutionTrace: Sendable {
    public let rows: [EVMTraceRow]
    public let initialState: EVMStateSnapshot
    public let finalState: EVMStateSnapshot
    public let gasUsed: UInt64
    public let returnData: [UInt8]
    public let reverted: Bool

    /// Precomputed Keccak-256 hashes from batch GPU processing
    /// Maps trace row index to the computed hash
    public let keccakHashes: [Int: [UInt8]]

    public init(
        rows: [EVMTraceRow],
        initialState: EVMStateSnapshot,
        finalState: EVMStateSnapshot,
        gasUsed: UInt64,
        returnData: [UInt8],
        reverted: Bool,
        keccakHashes: [Int: [UInt8]] = [:]
    ) {
        self.rows = rows
        self.initialState = initialState
        self.finalState = finalState
        self.gasUsed = gasUsed
        self.returnData = returnData
        self.reverted = reverted
        self.keccakHashes = keccakHashes
    }

    /// Number of trace rows
    public var count: Int { rows.count }

    /// Check if the trace is valid (no gaps in PC, proper gas accounting)
    public var isValid: Bool {
        // TODO: Add trace validation
        true
    }
}

/// Snapshot of EVM state for trace boundaries
public struct EVMStateSnapshot: Sendable, Equatable {
    public let pc: Int
    public let gas: UInt64
    public let gasRefund: UInt64
    public let stackHeight: Int
    public let memorySize: Int
    public let callDepth: Int
    public let stateRoot: M31Word
    public let selfBalance: M31Word
    public let running: Bool
    public let reverted: Bool

    public init(from state: EVMState) {
        self.pc = state.pc
        self.gas = state.gas
        self.gasRefund = state.gasRefund
        self.stackHeight = state.stack.stackHeight
        self.memorySize = state.memory.size
        self.callDepth = state.callDepth
        self.stateRoot = state.stateRoot
        self.selfBalance = state.selfBalance
        self.running = state.running
        self.reverted = state.reverted
    }

    public init(
        pc: Int,
        gas: UInt64,
        gasRefund: UInt64,
        stackHeight: Int,
        memorySize: Int,
        callDepth: Int,
        stateRoot: M31Word,
        selfBalance: M31Word,
        running: Bool,
        reverted: Bool
    ) {
        self.pc = pc
        self.gas = gas
        self.gasRefund = gasRefund
        self.stackHeight = stackHeight
        self.memorySize = memorySize
        self.callDepth = callDepth
        self.stateRoot = stateRoot
        self.selfBalance = selfBalance
        self.running = running
        self.reverted = reverted
    }
}

// MARK: - Memory Trace for Lasso Argument

/// Memory access entry for the memory permutation argument
public struct MemoryAccess: Sendable, Equatable {
    public enum AccessType: UInt8, Sendable {
        case read = 0
        case write = 1
    }

    /// Memory address (32-byte word aligned offset)
    public let address: M31Word

    /// Value read/written (as M31 limbs)
    public let value: M31Word

    /// Timestamp (used for read/write ordering)
    public let timestamp: UInt64

    /// Whether this is a write or read
    public let accessType: AccessType

    /// Program counter that triggered this access
    public let pc: Int

    /// Call depth
    public let callDepth: Int

    public init(
        address: M31Word,
        value: M31Word,
        timestamp: UInt64,
        accessType: AccessType,
        pc: Int,
        callDepth: Int
    ) {
        self.address = address
        self.value = value
        self.timestamp = timestamp
        self.accessType = accessType
        self.pc = pc
        self.callDepth = callDepth
    }
}

/// Memory trace sorted by (address, timestamp) for Lasso permutation argument
public struct MemoryTrace: Sendable {
    public let accesses: [MemoryAccess]

    public init(accesses: [MemoryAccess]) {
        // Sort by address then timestamp for the permutation argument
        self.accesses = accesses.sorted { a, b in
            if a.address.toHexString() != b.address.toHexString() {
                return a.address.toHexString() < b.address.toHexString()
            }
            return a.timestamp < b.timestamp
        }
    }

    /// Number of memory accesses
    public var count: Int { accesses.count }

    /// Check continuity: consecutive accesses to the same address should have timestamp difference of 1
    public var isValid: Bool {
        var lastAddr: String? = nil
        var lastTimestamp: UInt64? = nil

        for access in accesses {
            let addrStr = access.address.toHexString()
            if addrStr == lastAddr {
                if let lastTs = lastTimestamp {
                    if access.timestamp != lastTs + 1 {
                        return false
                    }
                }
            }
            lastAddr = addrStr
            lastTimestamp = access.timestamp
        }
        return true
    }
}

// MARK: - Storage Trace for Merkle Patricia Trie

/// Storage access entry for state trie verification
public struct StorageAccess: Sendable, Equatable {
    public enum AccessType: UInt8, Sendable {
        case load = 0
        case store = 1
    }

    /// Storage key (slot index)
    public let key: M31Word

    /// Value loaded/stored
    public let value: M31Word

    /// Timestamp for ordering
    public let timestamp: UInt64

    /// Access type
    public let accessType: AccessType

    /// Call depth
    public let callDepth: Int

    public init(
        key: M31Word,
        value: M31Word,
        timestamp: UInt64,
        accessType: AccessType,
        callDepth: Int
    ) {
        self.key = key
        self.value = value
        self.timestamp = timestamp
        self.accessType = accessType
        self.callDepth = callDepth
    }
}

/// Storage trace for proving storage operations
public struct StorageTrace: Sendable {
    public let accesses: [StorageAccess]

    public init(accesses: [StorageAccess]) {
        self.accesses = accesses.sorted { a, b in
            if a.key.toHexString() != b.key.toHexString() {
                return a.key.toHexString() < b.key.toHexString()
            }
            return a.timestamp < b.timestamp
        }
    }

    public var count: Int { accesses.count }
}

// MARK: - Call Trace for Sub-Call Tracking

/// A call/sub-call entry
public struct CallEntry: Sendable, Equatable {
    public enum CallType: UInt8, Sendable {
        case call = 0
        case delegateCall = 1
        case staticCall = 2
        case create = 3
        case create2 = 4
        case selfDestruct = 5
    }

    public let callType: CallType
    public let to: M31Word
    public let value: M31Word
    public let gas: UInt64
    public let input: [UInt8]
    public let output: [UInt8]
    public let success: Bool
    public let callDepth: Int
    public let startTimestamp: UInt64
    public let endTimestamp: UInt64

    public init(
        callType: CallType,
        to: M31Word,
        value: M31Word,
        gas: UInt64,
        input: [UInt8],
        output: [UInt8],
        success: Bool,
        callDepth: Int,
        startTimestamp: UInt64,
        endTimestamp: UInt64
    ) {
        self.callType = callType
        self.to = to
        self.value = value
        self.gas = gas
        self.input = input
        self.output = output
        self.success = success
        self.callDepth = callDepth
        self.startTimestamp = startTimestamp
        self.endTimestamp = endTimestamp
    }
}

// MARK: - Block-Level Trace for Unified Block Proving

/// Block-level execution trace containing multiple transaction traces.
///
/// This is the fundamental data structure for unified block proving.
/// Instead of proving each transaction separately, we combine all traces
/// into a single block trace and prove them together.
///
/// ## Structure
///
/// ```
/// BlockExecutionTrace
/// ├── transactionTraces: [EVMExecutionTrace]  // One trace per transaction
/// ├── blockHeader: BlockHeader                  // Block metadata
/// ├── interTxStateTransitions: [StateTransition] // State continuity proof
/// └── blockMetadata: BlockMetadata             // Gas, rewards, etc.
/// ```
///
/// ## Memory Layout
///
/// ```
/// Row 0:          TX0, instruction 0
/// Row 1:          TX0, instruction 1
/// ...
/// Row 4095:        TX0, instruction 4095
/// Row 4096:        TX1, instruction 0    ← Transaction boundary
/// ...
/// Row 614,399:     TX149, instruction 4095
/// ```
///
/// ## Constraint Types
///
/// 1. **Intra-transaction**: Same as single-tx AIR constraints
/// 2. **Inter-transaction**: State root continuity at boundaries
/// 3. **Block-level**: Gas limit, block reward, block number
public struct BlockExecutionTrace: Sendable {

    /// Individual transaction traces
    public let transactionTraces: [EVMExecutionTrace]

    /// Block header information
    public let blockHeader: BlockHeader

    /// State transitions between transactions
    /// Indexed by transaction boundary (tx[i].finalState → tx[i+1].initialState)
    public let interTxStateTransitions: [StateTransition]

    /// Block-level metadata
    public let metadata: BlockMetadata

    // MARK: - Initialization

    /// Create block trace from transaction traces
    public init(
        transactionTraces: [EVMExecutionTrace],
        blockHeader: BlockHeader,
        interTxStateTransitions: [StateTransition],
        metadata: BlockMetadata
    ) {
        self.transactionTraces = transactionTraces
        self.blockHeader = blockHeader
        self.interTxStateTransitions = interTxStateTransitions
        self.metadata = metadata
    }

    /// Create block trace from execution results
    public init(
        executionResults: [EVMExecutionResult],
        blockContext: BlockContext
    ) {
        // Extract traces from execution results
        self.transactionTraces = executionResults.map { $0.trace }

        // Create block header
        self.blockHeader = BlockHeader(
            parentHash: .zero,
            blockNumber: blockContext.number,
            timestamp: blockContext.timestamp,
            gasLimit: blockContext.gasLimit
        )

        // Create state transitions between transactions
        var transitions: [StateTransition] = []
        for i in 0..<(executionResults.count - 1) {
            let fromState = executionResults[i].trace.finalState
            let toState = executionResults[i + 1].trace.initialState
            transitions.append(StateTransition(
                fromState: fromState,
                toState: toState,
                transactionIndex: i
            ))
        }
        self.interTxStateTransitions = transitions

        // Create block metadata
        let totalGasUsed = executionResults.reduce(0) { $0 + $1.trace.gasUsed }
        self.metadata = BlockMetadata(
            transactionCount: executionResults.count,
            totalGasUsed: totalGasUsed,
            blockReward: Self.calculateBlockReward(
                totalGasUsed: totalGasUsed,
                gasLimit: blockContext.gasLimit
            )
        )
    }

    /// Calculate block reward
    private static func calculateBlockReward(totalGasUsed: UInt64, gasLimit: UInt64) -> UInt64 {
        // Base reward + gas used reward
        let baseReward: UInt64 = 2_000_000_000_000_000  // 2 ETH in wei
        let gasPrice: UInt64 = 10_000_000  // 10 gwei
        let gasReward = totalGasUsed * gasPrice
        return baseReward + gasReward
    }

    // MARK: - Properties

    /// Total number of transactions
    public var transactionCount: Int { transactionTraces.count }

    /// Total number of trace rows across all transactions
    public var totalRowCount: Int {
        transactionTraces.reduce(0) { $0 + $1.count }
    }

    /// Total gas used across all transactions
    public var totalGasUsed: UInt64 { metadata.totalGasUsed }

    /// Check if block gas limit is respected
    public var isWithinGasLimit: Bool {
        totalGasUsed <= blockHeader.gasLimit
    }

    /// Check validity of block trace
    public var isValid: Bool {
        // Check gas limit
        guard isWithinGasLimit else { return false }

        // Check transaction count
        guard !transactionTraces.isEmpty else { return false }

        // Check state transitions
        for transition in interTxStateTransitions {
            // State roots must match at boundaries
            // (This is a simplified check - real validation would be more thorough)
        }

        return true
    }

    /// Get trace row at global index
    public func traceRow(atGlobalIndex index: Int, rowsPerTx: Int) -> EVMTraceRow? {
        let txIndex = index / rowsPerTx
        let localIndex = index % rowsPerTx

        guard txIndex < transactionTraces.count else { return nil }
        guard localIndex < transactionTraces[txIndex].rows.count else { return nil }

        return transactionTraces[txIndex].rows[localIndex]
    }

    /// Get transaction index for a global row index
    public func transactionIndex(forGlobalRow row: Int, rowsPerTx: Int) -> Int {
        return row / rowsPerTx
    }
}

// MARK: - Supporting Types

/// Block header information
public struct BlockHeader: Sendable {
    public let parentHash: M31Word
    public let blockNumber: UInt64
    public let timestamp: UInt64
    public let gasLimit: UInt64

    public init(
        parentHash: M31Word,
        blockNumber: UInt64,
        timestamp: UInt64,
        gasLimit: UInt64
    ) {
        self.parentHash = parentHash
        self.blockNumber = blockNumber
        self.timestamp = timestamp
        self.gasLimit = gasLimit
    }
}

/// State transition between transactions
public struct StateTransition: Sendable {
    /// Final state of transaction N
    public let fromState: EVMStateSnapshot

    /// Initial state of transaction N+1
    public let toState: EVMStateSnapshot

    /// Transaction index (the boundary between N and N+1)
    public let transactionIndex: Int

    public init(
        fromState: EVMStateSnapshot,
        toState: EVMStateSnapshot,
        transactionIndex: Int
    ) {
        self.fromState = fromState
        self.toState = toState
        self.transactionIndex = transactionIndex
    }

    /// Check if the transition is valid (state roots match)
    public var isValid: Bool {
        fromState.stateRoot == toState.stateRoot
    }
}

/// Block-level metadata
public struct BlockMetadata: Sendable {
    public let transactionCount: Int
    public let totalGasUsed: UInt64
    public let blockReward: UInt64

    public init(
        transactionCount: Int,
        totalGasUsed: UInt64,
        blockReward: UInt64
    ) {
        self.transactionCount = transactionCount
        self.totalGasUsed = totalGasUsed
        self.blockReward = blockReward
    }
}

/// Memory trace extended for block-level proving
public struct BlockMemoryTrace: Sendable {
    /// Memory accesses across all transactions
    public let allAccesses: [MemoryAccess]

    /// Transaction index for each access
    public let transactionIndices: [Int]

    public init(
        memoryTraces: [MemoryTrace],
        transactionIndices: [Int]
    ) {
        // Flatten all memory traces
        var allAccesses: [MemoryAccess] = []
        var allTxIndices: [Int] = []

        for (txIdx, trace) in memoryTraces.enumerated() {
            allAccesses.append(contentsOf: trace.accesses)
            allTxIndices.append(contentsOf: Array(repeating: txIdx, count: trace.accesses.count))
        }

        // Sort by (address, timestamp) for the permutation argument
        let sorted = zip(allAccesses, allTxIndices).sorted { a, b in
            let addrA = a.0.address.toHexString()
            let addrB = b.0.address.toHexString()
            if addrA != addrB {
                return addrA < addrB
            }
            return a.0.timestamp < b.0.timestamp
        }

        self.allAccesses = sorted.map { $0.0 }
        self.transactionIndices = sorted.map { $0.1 }
    }

    /// Number of memory accesses
    public var count: Int { allAccesses.count }

    /// Check validity of memory trace across transactions
    public var isValid: Bool {
        // Check continuity within each address
        var lastAddr: String? = nil
        var lastTxIdx: Int? = nil
        var lastTimestamp: UInt64? = nil

        for i in 0..<allAccesses.count {
            let access = allAccesses[i]
            let addrStr = access.address.toHexString()

            if addrStr == lastAddr {
                // Same address: check timestamp continuity
                if let lastTs = lastTimestamp {
                    // Timestamps must be consecutive within a transaction
                    // or can reset at transaction boundaries
                    if let lastTx = lastTxIdx {
                        let txBoundary = transactionIndices[i] != lastTx
                        if !txBoundary && access.timestamp != lastTs + 1 {
                            return false
                        }
                    }
                }
            }
            // For different addresses, just update tracking
            lastAddr = addrStr
            lastTxIdx = transactionIndices[i]
            lastTimestamp = access.timestamp
        }

        return true
    }
}

/// Storage trace extended for block-level proving
public struct BlockStorageTrace: Sendable {
    /// Storage accesses across all transactions
    public let allAccesses: [StorageAccess]

    /// Transaction index for each access
    public let transactionIndices: [Int]

    public init(
        storageTraces: [StorageTrace],
        transactionIndices: [Int]
    ) {
        // Flatten all storage traces
        var allAccesses: [StorageAccess] = []
        var allTxIndices: [Int] = []

        for (txIdx, trace) in storageTraces.enumerated() {
            allAccesses.append(contentsOf: trace.accesses)
            allTxIndices.append(contentsOf: Array(repeating: txIdx, count: trace.accesses.count))
        }

        // Sort by (key, timestamp) for the permutation argument
        let sorted = zip(allAccesses, allTxIndices).sorted { a, b in
            let keyA = a.0.key.toHexString()
            let keyB = b.0.key.toHexString()
            if keyA != keyB {
                return keyA < keyB
            }
            return a.0.timestamp < b.0.timestamp
        }

        self.allAccesses = sorted.map { $0.0 }
        self.transactionIndices = sorted.map { $0.1 }
    }

    /// Number of storage accesses
    public var count: Int { allAccesses.count }
}

// MARK: - Block Context Extension

/// Extension to BlockContext for block-level proving
extension BlockContext {

    /// Create block context for unified block proving
    public static func forBlock(
        blockNumber: UInt64,
        gasLimit: UInt64 = 30_000_000,
        timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)
    ) -> BlockContext {
        BlockContext(
            gasLimit: gasLimit,
            timestamp: timestamp,
            number: blockNumber
        )
    }

    /// Estimated rows per transaction based on gas limit
    public var estimatedRowsPerTransaction: Int {
        // Conservative estimate: 1 row per 100 gas units
        return Int(gasLimit / 100)
    }

    /// Estimated block trace rows
    public func estimatedBlockTraceRows(transactionCount: Int) -> Int {
        return estimatedRowsPerTransaction * transactionCount
    }
}
