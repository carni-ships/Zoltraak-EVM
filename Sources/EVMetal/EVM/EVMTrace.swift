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

    public init(
        rows: [EVMTraceRow],
        initialState: EVMStateSnapshot,
        finalState: EVMStateSnapshot,
        gasUsed: UInt64,
        returnData: [UInt8],
        reverted: Bool
    ) {
        self.rows = rows
        self.initialState = initialState
        self.finalState = finalState
        self.gasUsed = gasUsed
        self.returnData = returnData
        self.reverted = reverted
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
