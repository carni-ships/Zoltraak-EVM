import Foundation
import zkMetal

/// Errors during EVM execution
public enum EVMExecutionError: Error, Sendable {
    case outOfGas
    case stackUnderflow
    case stackOverflow
    case invalidJump(dest: Int)
    case revert(message: String)
    case invalidOpcode(opcode: UInt8)
    case callDepthExceeded
    case memoryOverflow
    case invalidCode(reason: String)
}

/// EVM Interpreter that executes bytecode and generates execution traces
public final class EVMExecutionEngine: Sendable {
    public let block: BlockContext
    public let tx: TransactionContext

    // Trace collectors
    private var traceRows: [EVMTraceRow] = []
    private var memoryAccesses: [MemoryAccess] = []
    private var storageAccesses: [StorageAccess] = []
    private var callEntries: [CallEntry] = []
    private var memoryTimestamp: UInt64 = 0

    public init(block: BlockContext = BlockContext(), tx: TransactionContext = TransactionContext()) {
        self.block = block
        self.tx = tx
    }

    // MARK: - Public API

    /// Execute a transaction/call and return the execution trace
    public func execute(
        code: [UInt8],
        calldata: [UInt8] = [],
        value: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000
    ) throws -> EVMExecutionResult {
        // Reset state
        traceRows = []
        memoryAccesses = []
        storageAccesses = []
        callEntries = []
        memoryTimestamp = 0

        // Initialize state
        var state = EVMState(block: block, tx: tx)
        state.gas = gasLimit

        // Set up initial frame
        var frame = CallFrame(code: code, calldata: calldata)
        frame.gas = gasLimit
        frame.address = M31Word(low64: UInt64(1))  // Contract address
        frame.caller = tx.origin
        frame.callValue = value
        state.pushFrame(frame)

        // Mark address as accessed
        state.accessedAddresses.insert(state.currentFrame.address.toHexString())

        // Execute until halt
        while state.running {
            try executeNextInstruction(&state)
        }

        // Build final trace
        let finalSnapshot = EVMStateSnapshot(from: state)
        let gasUsed = gasLimit - state.gas

        return EVMExecutionResult(
            trace: EVMExecutionTrace(
                rows: traceRows,
                initialState: EVMStateSnapshot(
                    pc: 0,
                    gas: gasLimit,
                    gasRefund: 0,
                    stackHeight: 0,
                    memorySize: 0,
                    callDepth: 0,
                    stateRoot: .zero,
                    selfBalance: .zero,
                    running: true,
                    reverted: false
                ),
                finalState: finalSnapshot,
                gasUsed: gasUsed,
                returnData: state.currentFrame.returnData,
                reverted: state.reverted
            ),
            memoryTrace: MemoryTrace(accesses: memoryAccesses),
            storageTrace: StorageTrace(accesses: storageAccesses),
            callTrace: callEntries
        )
    }

    // MARK: - Instruction Execution

    private func executeNextInstruction(_ state: inout EVMState) throws {
        let pc = state.pc
        let code = state.currentFrame.code

        guard pc < code.count else {
            state.stop()
            return
        }

        let opcode = code[pc]
        state.pc += 1

        // Record trace row BEFORE execution
        let row = EVMTraceRow(
            pc: pc,
            opcode: opcode,
            gas: state.gas,
            stackHeight: state.stack.stackHeight,
            memorySize: state.memory.size,
            callDepth: state.callDepth,
            stateRoot: state.stateRoot,
            isRunning: state.running,
            isReverted: state.reverted,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        )
        traceRows.append(row)

        // Execute opcode
        guard let evmOp = EVMOpcode(rawValue: opcode) else {
            throw EVMExecutionError.invalidOpcode(opcode: opcode)
        }

        switch evmOp {
        // Stop and Arithmetic
        case .STOP:     state.stop(); return
        case .ADD:      try add_op(&state)
        case .SUB:      try sub_op(&state)
        case .MUL:      try mul_op(&state)
        case .DIV:      try div_mod_op(&state, signed: false)
        case .SDIV:     try div_mod_op(&state, signed: true)
        case .MOD:      try mod_op(&state, signed: false)
        case .SMOD:     try mod_op(&state, signed: true)
        case .ADDMOD:   try addmod_op(&state)
        case .MULMOD:   try mulmod_op(&state)
        case .EXP:      try exp_op(&state)
        case .SIGNEXTEND: try signextend_op(&state)

        // Comparison and Bitwise
        case .LT, .GT, .SLT, .SGT: try comparison_op(&state, op: evmOp)
        case .EQ:      try eq_op(&state)
        case .ISZERO:  try iszero_op(&state)
        case .AND, .OR, .XOR: try bitwise_op(&state, op: evmOp)
        case .NOT:     try not_op(&state)
        case .BYTE:    try byte_op(&state)
        case .SHL:     try shift_op(&state, left: true)
        case .SHR:     try shift_op(&state, left: false)
        case .SAR:     try sar_op(&state)

        // SHA3
        case .KECCAK256: try keccak256_op(&state)

        // Environmental
        case .ADDRESS:     state.stack.push(state.currentFrame.address)
        case .BALANCE:     try balance_op(&state)
        case .ORIGIN:      state.stack.push(tx.origin)
        case .CALLER:      state.stack.push(state.currentFrame.caller)
        case .CALLVALUE:   state.stack.push(state.currentFrame.callValue)
        case .CALLDATALOAD: try calldataload_op(&state)
        case .CALLDATASIZE: state.stack.push(M31Word(low64: UInt64(state.currentFrame.calldata.count)))
        case .CALLDATACOPY: try calldatacopy_op(&state)
        case .CODESIZE:     state.stack.push(M31Word(low64: UInt64(state.currentFrame.code.count)))
        case .CODECOPY:     try codecopy_op(&state)
        case .GASPRICE:     state.stack.push(tx.gasPrice)
        case .EXTCODESIZE:  try extcodesize_op(&state)
        case .EXTCODECOPY:  try extcodecopy_op(&state)
        case .RETURNDATASIZE: state.stack.push(M31Word(low64: UInt64(state.currentFrame.returnData.count)))
        case .RETURNDATACOPY: try returndatacopy_op(&state)
        case .EXTCODEHASH:  try extcodehash_op(&state)

        // Block
        case .BLOCKHASH:   try blockhash_op(&state)
        case .COINBASE:    state.stack.push(block.beneficiary)
        case .TIMESTAMP:   state.stack.push(M31Word(low64: block.timestamp))
        case .NUMBER:      state.stack.push(M31Word(low64: block.number))
        case .PREVRANDAO:  state.stack.push(block.prevRandao)
        case .GASLIMIT:    state.stack.push(M31Word(low64: block.gasLimit))
        case .CHAINID:     state.stack.push(block.chainId)
        case .SELFBALANCE: state.stack.push(state.selfBalance)
        case .BASEFEE:     state.stack.push(block.baseFee)

        // Stack and Memory
        case .POP:     _ = state.stack.pop()
        case .MLOAD:   try mload_op(&state)
        case .MSTORE:  try mstore_op(&state)
        case .MSTORE8: try mstore8_op(&state)
        case .JUMP:   try jump_op(&state)
        case .JUMPI:  try jumpi_op(&state)
        case .JUMPDEST: break  // No-op, just a valid jump target
        case .PC:     state.stack.push(M31Word(low64: UInt64(pc)))
        case .MSIZE:  state.stack.push(M31Word(low64: UInt64(state.memory.size)))
        case .GAS:    state.stack.push(M31Word(low64: state.gas))

        // Push operations
        case .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8,
             .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16,
             .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24,
             .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32:
            try push_op(&state, op: evmOp, code: code)
        case .PUSH0:   state.stack.push(.zero)

        // Duplicate
        case .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8,
             .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16:
            try dup_op(&state, op: evmOp)

        // Swap
        case .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8,
             .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16:
            try swap_op(&state, op: evmOp)

        // Log
        case .LOG0, .LOG1, .LOG2, .LOG3, .LOG4: try log_op(&state, op: evmOp)

        // System
        case .RETURN:   state.stop(); return
        case .REVERT:   state.revert(message: "REVERT"); state.stop(); return
        case .CALL:     try call_op(&state)
        case .DELEGATECALL: try delegatecall_op(&state)
        case .STATICCALL: try staticcall_op(&state)
        case .CREATE:   try create_op(&state, create2: false)
        case .CREATE2:  try create_op(&state, create2: true)
        case .SELFDESTRUCT: try selfdestruct_op(&state)

        // EOF (not yet fully supported)
        case .RJUMP, .RJUMPI, .CALLF, .RETF, .JUMPF, .DUPN, .SWAPN,
             .SLOADBYTES, .SSTOREBYTES, .MSTORESIZE, .TRACKSTORAGE, .COPYLOG:
            throw EVMExecutionError.invalidOpcode(opcode: opcode)

        // Unimplemented
        default:
            throw EVMExecutionError.invalidOpcode(opcode: opcode)
        }
    }

    // MARK: - Arithmetic Operations

    private func add_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.push(a.add(b).result)
    }

    private func sub_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.push(a.sub(b).result)
    }

    private func mul_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(5) { throw EVMExecutionError.outOfGas }
        // Simplified multiplication - take first 9 limbs of full product
        let full = a.multiplyFull(b)
        var resultLimbs = [M31](repeating: .zero, count: 9)
        for i in 0..<min(9, full.count) {
            resultLimbs[i] = full[i]
        }
        let result = M31Word(limbs: resultLimbs)
        state.stack.push(result)
    }

    private func div_mod_op(_ state: inout EVMState, signed: Bool) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(5) { throw EVMExecutionError.outOfGas }
        // Simplified: in real implementation, handle division by zero and signed semantics
        if b.toBytes().allSatisfy({ $0 == 0 }) {
            state.stack.push(.zero)
        } else {
            state.stack.push(a)  // TODO: Actual division
        }
    }

    private func mod_op(_ state: inout EVMState, signed: Bool) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(5) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // TODO: Actual modulo
    }

    private func addmod_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let c = state.stack.pop()
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }
        // (a + b) mod c - simplified
        state.stack.push(.zero)
    }

    private func mulmod_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let c = state.stack.pop()
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // TODO: Actual mulmod
    }

    private func exp_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let exponent = state.stack.pop()
        let base = state.stack.pop()
        if !state.chargeGas(10) { throw EVMExecutionError.outOfGas }
        state.stack.push(.one)  // TODO: Actual exponentiation
    }

    private func signextend_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(5) { throw EVMExecutionError.outOfGas }
        state.stack.push(a)  // TODO: Actual signextend
    }

    // MARK: - Comparison and Bitwise

    private func comparison_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let result: Bool
        switch op {
        case .LT:  result = a.low32 < b.low32
        case .GT:  result = a.low32 > b.low32
        case .SLT: result = Int32(bitPattern: a.low32) < Int32(bitPattern: b.low32)
        case .SGT: result = Int32(bitPattern: a.low32) > Int32(bitPattern: b.low32)
        default:   result = false
        }
        state.stack.push(result ? .one : .zero)
    }

    private func eq_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.push(a.equals(b) ? .one : .zero)
    }

    private func iszero_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.push(a.isZero ? .one : .zero)
    }

    private func bitwise_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        var resultLimbs = [M31](repeating: .zero, count: M31Word.limbCount)
        for i in 0..<M31Word.limbCount {
            let aVal = a.limbs[i].v
            let bVal = b.limbs[i].v
            let r: UInt32
            switch op {
            case .AND: r = aVal & bVal
            case .OR:  r = aVal | bVal
            case .XOR: r = aVal ^ bVal
            default:   r = 0
            }
            resultLimbs[i] = M31(v: r)
        }
        let result = M31Word(limbs: resultLimbs)
        state.stack.push(result)
    }

    private func not_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        var resultLimbs = [M31](repeating: .zero, count: M31Word.limbCount)
        for i in 0..<M31Word.limbCount {
            resultLimbs[i] = M31(v: a.limbs[i].v ^ 0x7FFFFFFF)
        }
        let result = M31Word(limbs: resultLimbs)
        state.stack.push(result)
    }

    private func byte_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        let byteIndex = Int(b.low32)
        if byteIndex < 32 {
            let val = a.toBytes()[byteIndex]
            state.stack.push(M31Word(low64: UInt64(val)))
        } else {
            state.stack.push(.zero)
        }
    }

    private func shift_op(_ state: inout EVMState, left: Bool) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let shift = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // TODO: Actual shift
    }

    private func sar_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let shift = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // TODO: Actual SAR
    }

    // MARK: - Memory Operations

    private func mload_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(offset.low32)
        state.memory.expand(offset: offsetInt, size: 32)
        let value = state.memory.loadWord(offset: offsetInt)

        // Record memory access
        let access = MemoryAccess(
            address: M31Word(low64: UInt64(offsetInt / 32)),
            value: value,
            timestamp: memoryTimestamp,
            accessType: .read,
            pc: state.pc - 1,
            callDepth: state.callDepth
        )
        memoryAccesses.append(access)
        memoryTimestamp += 1

        state.stack.push(value)
    }

    private func mstore_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        let value = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(offset.low32)
        state.memory.expand(offset: offsetInt, size: 32)
        state.memory.storeWord(offset: offsetInt, value: value)

        // Record memory access
        let access = MemoryAccess(
            address: M31Word(low64: UInt64(offsetInt / 32)),
            value: value,
            timestamp: memoryTimestamp,
            accessType: .write,
            pc: state.pc - 1,
            callDepth: state.callDepth
        )
        memoryAccesses.append(access)
        memoryTimestamp += 1
    }

    private func mstore8_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        let value = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(offset.low32)
        state.memory.expand(offset: offsetInt, size: 1)
        state.memory.storeByte(offset: offsetInt, value: UInt8(value.low32 & 0xFF))
    }

    // MARK: - Control Flow

    private func jump_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let dest = state.stack.pop()
        if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }

        let destInt = Int(dest.low32)
        // In a real implementation, we'd verify this is a JUMPDEST
        state.pc = destInt
    }

    private func jumpi_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let dest = state.stack.pop()
        let condition = state.stack.pop()
        if !state.chargeGas(10) { throw EVMExecutionError.outOfGas }

        if !condition.isZero {
            let destInt = Int(dest.low32)
            state.pc = destInt
        }
    }

    // MARK: - Push Operations

    private func push_op(_ state: inout EVMState, op: EVMOpcode, code: [UInt8]) throws {
        guard let byteCount = op.pushBytes else { return }
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let pc = state.pc
        guard pc + byteCount <= code.count else { throw EVMExecutionError.invalidCode(reason: "Unexpected end of code") }

        var bytes = [UInt8]()
        bytes.reserveCapacity(byteCount)
        for i in 0..<byteCount {
            bytes.append(code[pc + i])
        }

        // Pad to 32 bytes
        while bytes.count < 32 {
            bytes.append(0x00)
        }

        state.pc = pc + byteCount
        state.stack.push(M31Word(bytes: bytes))
    }

    // MARK: - Duplicate

    private func dup_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard let pos = op.dupPosition else { return }
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.dup(position: pos)
    }

    // MARK: - Swap

    private func swap_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard let pos = op.swapPosition else { return }
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        state.stack.Swap(position: pos)
    }

    // MARK: - Log

    private func log_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard let topics = op.logTopics else { return }
        guard state.stack.stackHeight >= 2 + topics else { throw EVMExecutionError.stackUnderflow }

        let offset = state.stack.pop()
        let size = state.stack.pop()
        var topicWords = [M31Word]()
        for _ in 0..<topics {
            topicWords.append(state.stack.pop())
        }
        if !state.chargeGas(375) { throw EVMExecutionError.outOfGas }
        // Log data would be emitted - simplified here
    }

    // MARK: - Calls (Simplified)

    private func call_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 7 else { throw EVMExecutionError.stackUnderflow }
        let gas = state.stack.pop()
        let to = state.stack.pop()
        let value = state.stack.pop()
        let inOffset = state.stack.pop()
        let inSize = state.stack.pop()
        let retOffset = state.stack.pop()
        let retSize = state.stack.pop()

        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }

        // Simplified: just push success
        state.stack.push(.one)

        // Record call
        let entry = CallEntry(
            callType: .call,
            to: to,
            value: value,
            gas: UInt64(gas.low32),
            input: [],
            output: [],
            success: true,
            callDepth: state.callDepth,
            startTimestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            endTimestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        )
        callEntries.append(entry)
    }

    private func delegatecall_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 6 else { throw EVMExecutionError.stackUnderflow }
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }
        state.stack.push(.one)  // Simplified
    }

    private func staticcall_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 6 else { throw EVMExecutionError.stackUnderflow }
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }
        state.stack.push(.one)  // Simplified
    }

    private func create_op(_ state: inout EVMState, create2: Bool) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        if !state.chargeGas(32000) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // Simplified - return zero address
    }

    private func selfdestruct_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        if !state.chargeGas(5000) { throw EVMExecutionError.outOfGas }
        state.stop()
    }

    // MARK: - SHA3

    private func keccak256_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        let size = state.stack.pop()
        if !state.chargeGas(30) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(offset.low32)
        let sizeInt = Int(size.low32)
        state.memory.expand(offset: offsetInt, size: sizeInt)

        // TODO: Actually compute Keccak-256 via zkmetal's Keccak engine
        // For now, return a placeholder
        state.stack.push(.zero)
    }

    // MARK: - Environmental

    private func balance_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        _ = state.stack.pop()
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // Simplified
    }

    private func calldataload_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(offset.low32)
        let calldata = state.currentFrame.calldata
        var word = [UInt8](repeating: 0, count: 32)

        for i in 0..<min(32, calldata.count - offsetInt) {
            word[i] = calldata[offsetInt + i]
        }
        state.stack.push(M31Word(bytes: word))
    }

    private func calldatacopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let destOffset = state.stack.pop()
        let offset = state.stack.pop()
        let size = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        // Simplified - would copy calldata to memory
    }

    private func codecopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let destOffset = state.stack.pop()
        let offset = state.stack.pop()
        let size = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        // Simplified
    }

    private func extcodesize_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        _ = state.stack.pop()
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // Simplified
    }

    private func extcodecopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 4 else { throw EVMExecutionError.stackUnderflow }
        _ = state.stack.pop(); _ = state.stack.pop(); _ = state.stack.pop(); _ = state.stack.pop()
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }
    }

    private func returndatacopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        _ = state.stack.pop(); _ = state.stack.pop(); _ = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
    }

    private func extcodehash_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        _ = state.stack.pop()
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // Simplified
    }

    // MARK: - Block Operations

    private func blockhash_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let blockNum = state.stack.pop()
        if !state.chargeGas(20) { throw EVMExecutionError.outOfGas }
        state.stack.push(.zero)  // Simplified - return 0 for non-recent blocks
    }
}

// MARK: - Execution Result

public struct EVMExecutionResult: Sendable {
    public let trace: EVMExecutionTrace
    public let memoryTrace: MemoryTrace
    public let storageTrace: StorageTrace
    public let callTrace: [CallEntry]
}
