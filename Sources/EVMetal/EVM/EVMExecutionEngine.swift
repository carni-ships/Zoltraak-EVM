import Foundation
import zkMetal
import CryptoKit

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
///
/// Memory optimizations:
/// - Pre-allocated trace collections based on estimated execution size
/// - Reusable trace row builders to reduce allocations
/// - Efficient memory access tracking
public final class EVMExecutionEngine: Sendable {
    public let block: BlockContext
    public let tx: TransactionContext

    // MARK: - Trace collectors (optimized)

    private var traceRows: [EVMTraceRow] = []
    private var memoryAccesses: [MemoryAccess] = []
    private var storageAccesses: [StorageAccess] = []
    private var callEntries: [CallEntry] = []
    private var memoryTimestamp: UInt64 = 0
    private var storageTimestamp: UInt64 = 0

    // Estimated trace capacity based on gas limit
    // Each operation costs at least 2 gas, so we can estimate max rows
    private var estimatedTraceCapacity: Int = 0

    public init(block: BlockContext = BlockContext(), tx: TransactionContext = TransactionContext()) {
        self.block = block
        self.tx = tx
    }

    // MARK: - Thread-Local Factory

    /// Create a new engine instance for thread-local execution
    /// Ensures each thread has its own isolated state
    public static func threadLocal(
        block: BlockContext = BlockContext(),
        tx: TransactionContext = TransactionContext()
    ) -> EVMExecutionEngine {
        return EVMExecutionEngine(block: block, tx: tx)
    }

    // MARK: - Public API

    /// Execute a transaction/call and return the execution trace
    /// Memory-optimized with pre-allocated collections
    public func execute(
        code: [UInt8],
        calldata: [UInt8] = [],
        value: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000
    ) throws -> EVMExecutionResult {
        return try executeInternal(
            code: code,
            calldata: calldata,
            value: value,
            gasLimit: gasLimit,
            block: block,
            tx: tx
        )
    }

    /// Thread-safe execution with explicit state
    /// Use this method when executing from multiple threads
    internal func executeInternal(
        code: [UInt8],
        calldata: [UInt8] = [],
        value: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000,
        block: BlockContext,
        tx: TransactionContext
    ) throws -> EVMExecutionResult {
        // Estimate trace capacity based on gas limit
        // Conservative estimate: 1 row per 100 gas units
        estimatedTraceCapacity = Int(gasLimit / 100)

        // Reset state with pre-allocated capacity
        traceRows.reserveCapacity(estimatedTraceCapacity)
        memoryAccesses.reserveCapacity(estimatedTraceCapacity / 10)  // Assume 10% memory ops
        storageAccesses.reserveCapacity(estimatedTraceCapacity / 20)  // Assume 5% storage ops
        callEntries.reserveCapacity(10)  // Most txs have <10 calls
        memoryTimestamp = 0
        storageTimestamp = 0

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

        // Execute until halt or gas exhaustion
        // Wrap in try-catch to handle errors (invalid opcode, stack underflow, etc.)
        // On error, revert the transaction per EVM semantics
        do {
            var iterations = 0
            let maxIterations = 1_000_000  // Safety limit
            while state.running && iterations < maxIterations {
                try executeNextInstruction(&state)
                iterations += 1

                // Periodically check for gas exhaustion
                if iterations % 1000 == 0 && state.gas == 0 {
                    state.stop()
                }
            }

            if iterations >= maxIterations {
                print("WARNING: Execution hit max iterations limit (\(maxIterations))")
                state.stop()
            }
        } catch {
            // EVM semantics: any error causes REVERT
            // Record the REVERT with error info and record final trace row
            let errorInfo = "ERROR: \(error)"
            state.revert(message: errorInfo)

            // Record final state after revert
            recordTraceRow(
                pc: state.pc,
                opcode: 0xFD,  // REVERT opcode
                state: state
            )
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

    /// Reset engine state for reuse (reduces allocation overhead)
    public func reset() {
        traceRows.removeAll(keepingCapacity: true)
        memoryAccesses.removeAll(keepingCapacity: true)
        storageAccesses.removeAll(keepingCapacity: true)
        callEntries.removeAll(keepingCapacity: true)
        memoryTimestamp = 0
        storageTimestamp = 0
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

        // Execute opcode FIRST to get post-execution state
        guard let evmOp = EVMOpcode(rawValue: opcode) else {
            throw EVMExecutionError.invalidOpcode(opcode: opcode)
        }

        switch evmOp {
        // Stop and Arithmetic
        case .STOP:     state.stop(); recordTraceRow(pc: pc, opcode: opcode, state: state); return
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
        case .POP:
            guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
            _ = state.stack.pop()
        case .MLOAD:   try mload_op(&state)
        case .MSTORE:  try mstore_op(&state)
        case .MSTORE8: try mstore8_op(&state)
        case .SLOAD:   try sload_op(&state)
        case .SSTORE:  try sstore_op(&state)
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
        case .RETURN:   state.stop(); recordTraceRow(pc: pc, opcode: opcode, state: state); return
        case .REVERT:   state.revert(message: "REVERT"); state.stop(); recordTraceRow(pc: pc, opcode: opcode, state: state); return
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

        // Record trace row AFTER execution with post-state values
        // This captures the state AFTER the opcode took effect, which is what AIR constraints need
        recordTraceRow(pc: pc, opcode: opcode, state: state)
    }

    /// Helper to record a trace row with current state values
    private func recordTraceRow(pc: Int, opcode: UInt8, state: EVMState) {
        let stackSnapshot = state.stack.peekWords(count: 16)
        traceRows.append(EVMTraceRow(
            pc: pc,
            opcode: opcode,
            gas: state.gas,
            stackHeight: state.stack.stackHeight,
            stackSnapshot: stackSnapshot,
            memorySize: state.memory.size,
            callDepth: state.callDepth,
            stateRoot: state.stateRoot,
            isRunning: state.running,
            isReverted: state.reverted,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        ))
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

        let bBytes = b.toBytes()
        if bBytes.allSatisfy({ $0 == 0 }) {
            state.stack.push(.zero)
        } else {
            let (q, _) = divMod256(a, b)
            state.stack.push(q)
        }
    }

    private func mod_op(_ state: inout EVMState, signed: Bool) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(5) { throw EVMExecutionError.outOfGas }

        let bBytes = b.toBytes()
        if bBytes.allSatisfy({ $0 == 0 }) {
            state.stack.push(a)
        } else {
            let (_, r) = divMod256(a, b)
            state.stack.push(r)
        }
    }

    private func addmod_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let c = state.stack.pop()
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }

        // (a + b) mod c
        let (q, _) = divMod256(a.add(b).result, c)
        state.stack.push(q)
    }

    private func mulmod_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let c = state.stack.pop()
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }

        // Full 256-bit mulmod: (a * b) mod c
        // Handle c == 0 case (mod by zero returns 0 per EVM spec)
        if c.isZero {
            state.stack.push(M31Word.zero)
            return
        }

        // Convert operands to UInt64 limbs (4 x 64-bit = 256 bits)
        let a64 = toUInt64Limbs(a)
        let b64 = toUInt64Limbs(b)

        // Compute full 512-bit product using schoolbook multiplication
        var product512 = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (low, high) = a64[i].multipliedFullWidth(by: b64[j])
                let idx = i + j

                // Accumulate into product[idx] with carry
                let (sum0, o0) = product512[idx].addingReportingOverflow(low)
                let (sum1, o1) = sum0.addingReportingOverflow(carry)
                product512[idx] = sum1
                carry = high &+ (o0 ? 1 : 0) &+ (o1 ? 1 : 0)

                // Propagate carry to next word
                if idx + 1 < 8 {
                    let (sum2, o2) = product512[idx + 1].addingReportingOverflow(carry)
                    product512[idx + 1] = sum2
                    carry = o2 ? 1 : 0
                }
            }
            // Continue carry propagation
            var k = i + 2
            while carry != 0 && k < 8 {
                let (sumK, oK) = product512[k].addingReportingOverflow(carry)
                product512[k] = sumK
                carry = oK ? 1 : 0
                k += 1
            }
        }

        // Split into high and low 256-bit parts for modular reduction
        let low256 = m31WordFromUInt64Limbs([product512[0], product512[1], product512[2], product512[3]])
        let high256 = m31WordFromUInt64Limbs([product512[4], product512[5], product512[6], product512[7]])

        // Compute (a * b) mod c = (high * 2^256 + low) mod c
        // Using: X mod c = ((high mod c) * (2^256 mod c) + (low mod c)) mod c
        let (_, lowMod) = divMod256(low256, c)
        let (_, highMod) = divMod256(high256, c)

        // Compute 2^256 mod c using expMod256
        // Exponent 2^256 = [0, 0, 0, 1] in little-endian UInt64 representation
        let two256ModC = expMod256(
            M31Word(bytes: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            M31Word(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            c
        )

        // Compute (highMod * two256ModC) using mulBigInt then reduce
        let highTimesTwo256 = mulBigInt(toUInt64Limbs(highMod), toUInt64Limbs(two256ModC))
        let highTimesTwo256Word = m31WordFromUInt64Limbs(highTimesTwo256)
        let (_, productMod) = divMod256(highTimesTwo256Word, c)

        // Final result: (productMod + lowMod) mod c
        let finalSum = productMod.add(lowMod).result
        let (_, result) = divMod256(finalSum, c)
        state.stack.push(result)
    }

    private func exp_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let exponent = state.stack.pop()
        let base = state.stack.pop()
        if !state.chargeGas(10) { throw EVMExecutionError.outOfGas }

        // base^(exponent) mod 2^256
        let result = expMod256(base, exponent, .zero)  // mod 0 means no modulus
        state.stack.push(result)
    }

    private func signextend_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let b = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(5) { throw EVMExecutionError.outOfGas }

        let k = Int(b.low32)
        if k < 31 {
            let aBytes = a.toBytes()
            var result = aBytes
            // Sign bit is at bit (k+1)*8-1 = 8k+7
            let signByteIdx = 31 - k
            let signBitIdx = k * 8 + 7
            let signByte = aBytes[Int(signByteIdx)]
            let signBit = (signByte >> (7 - (k * 8))) & 1

            if signBit == 1 {
                // Extend with 0xFF
                for i in 0..<signByteIdx {
                    result[i] = 0xFF
                }
                // Mask the sign byte
                let mask: UInt8 = (1 << (8 - k)) - 1
                result[Int(signByteIdx)] = signByte | mask
            }
            state.stack.push(M31Word(bytes: result))
        } else {
            state.stack.push(a)
        }
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
        let byteIndex = Int(UInt64(b.low32))
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
        let value = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let shiftBits = Int(shift.low32)

        if shiftBits >= 256 {
            state.stack.push(.zero)
        } else {
            let valueLimbs = toUInt64Limbs(value)
            let shiftedLimbs: [UInt64]
            if left {
                shiftedLimbs = shiftLeft256(valueLimbs, by: shiftBits)
            } else {
                shiftedLimbs = shiftRight256(valueLimbs, by: shiftBits)
            }
            state.stack.push(m31WordFromUInt64Limbs(shiftedLimbs))
        }
    }

    private func sar_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let shift = state.stack.pop()
        let a = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let shiftBits = Int(shift.low32)

        // Convert to UInt64 limbs for 256-bit arithmetic
        let aLimbs = toUInt64Limbs(a)

        // Check sign bit (MSB of most significant limb limbs[3])
        let isNegative = (aLimbs[3] & 0x8000000000000000) != 0

        var result: [UInt64]

        if shiftBits >= 256 {
            // If shift >= 256: result is all 1s for negative, or 0 for positive/zero
            if isNegative {
                result = [UInt64](repeating: 0xFFFFFFFFFFFFFFFF, count: 4)
            } else {
                result = [UInt64](repeating: 0, count: 4)
            }
        } else if shiftBits == 0 {
            // No shift needed
            result = aLimbs
        } else {
            // Perform unsigned right shift first
            result = shiftRight256(aLimbs, by: shiftBits)

            // For negative values, sign-extend by filling high bits with 1s
            if isNegative {
                let wordShift = shiftBits / 64
                let bitShift = shiftBits % 64

                // Words completely shifted out become all 1s
                for i in 0..<wordShift {
                    result[i] = 0xFFFFFFFFFFFFFFFF
                }

                // Partial word: fill upper bits with 1s for sign extension
                if bitShift > 0 {
                    result[wordShift] |= ~0 << (64 - bitShift)
                }
            }
        }

        state.stack.push(m31WordFromUInt64Limbs(result))
    }

    // MARK: - Memory Operations

    private func mload_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(UInt64(offset.low32))
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

        let offsetInt = Int(UInt64(offset.low32))
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

        let offsetInt = Int(UInt64(offset.low32))
        state.memory.expand(offset: offsetInt, size: 1)
        state.memory.storeByte(offset: offsetInt, value: UInt8(value.low32 & 0xFF))
    }

    // MARK: - Control Flow

    private func jump_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let dest = state.stack.pop()
        if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }

        let destInt = Int(UInt64(dest.low32))
        // In a real implementation, we'd verify this is a JUMPDEST
        state.pc = destInt
    }

    private func jumpi_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        // In EVM, stack has [dest, condition] with condition on top
        let condition = state.stack.pop()
        let dest = state.stack.pop()
        if !state.chargeGas(10) { throw EVMExecutionError.outOfGas }

        if !condition.isZero {
            let destInt = Int(UInt64(dest.low32))
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

        // Pad to 32 bytes - prepend zeroes (high-order bytes in big-endian)
        while bytes.count < 32 {
            bytes.insert(0x00, at: 0)  // Insert at front for big-endian
        }

        state.pc = pc + byteCount

        // Check stack overflow before pushing
        guard state.stack.stackHeight < maxStackDepth else {
            throw EVMExecutionError.stackOverflow
        }
        state.stack.push(M31Word(bytes: bytes))
    }

    // MARK: - Duplicate

    private func dup_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard let pos = op.dupPosition else { return }
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        // Check stack height before DUP operation
        if state.stack.stackHeight < pos {
            throw EVMExecutionError.stackUnderflow
        }
        try state.stack.dup(position: pos)
    }

    // MARK: - Swap

    private func swap_op(_ state: inout EVMState, op: EVMOpcode) throws {
        guard let pos = op.swapPosition else { return }
        // SWAP swaps top with position (1-indexed from top), so need pos+1 items
        // SWAP1 needs 2 items, SWAP16 needs 17 items
        if state.stack.stackHeight < pos + 1 {
            throw EVMExecutionError.stackUnderflow
        }
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }
        try state.stack.swap(position: pos)
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

        // Gas calculation
        var callGas: UInt64 = 2600

        // Value transfer gas (EIP-150)
        if !value.isZero {
            callGas += 9000
        }

        // Memory gas for input and output
        let inWords = UInt64((Int(UInt64(inSize.low32)) + 31) / 32)
        let retWords = UInt64((Int(UInt64(retSize.low32)) + 31) / 32)
        callGas += 3 * (inWords + retWords) + ((inWords + retWords) * (inWords + retWords)) / 512

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(to)
        if !isWarm {
            callGas += 100
        }
        state.accountManager.markAccessed(to)

        if !state.chargeGas(callGas) { throw EVMExecutionError.outOfGas }

        // Check call depth
        if state.callDepth >= 1024 {
            state.stack.push(.zero)  // Fail - max call depth exceeded
            return
        }

        // Check value transfer
        let senderBalance = state.accountManager.getBalance(state.currentFrame.address)
        if value.low64 > senderBalance.low64 {
            state.stack.push(.zero)  // Fail - insufficient balance
            return
        }

        // Get target code
        let code = state.accountManager.getCode(to)
        let codeHash = state.accountManager.getCodeHash(to)

        // If no code, this is a transfer to EOA - success
        if code.isEmpty {
            // Transfer value
            if !value.isZero {
                state.accountManager.transferBalance(
                    from: state.currentFrame.address,
                    to: to,
                    amount: value
                )
            }
            state.stack.push(.one)  // Success
            return
        }

        // Prepare input data from memory
        let inOffsetInt = Int(UInt64(inOffset.low32))
        let inSizeInt = Int(UInt64(inSize.low32))
        var inputData: [UInt8] = []
        inputData.reserveCapacity(inSizeInt)
        for i in 0..<inSizeInt {
            inputData.append(state.memory.loadByte(offset: inOffsetInt + i))
        }

        // Create subcall frame
        var subFrame = CallFrame(code: code, calldata: inputData)
        subFrame.address = to
        subFrame.caller = state.currentFrame.address
        subFrame.callValue = value
        subFrame.gas = UInt64(gas.low32)

        // Execute subcall (simplified - mark success with empty return)
        state.pushFrame(subFrame)

        // For a proper implementation, would recursively execute the subcall
        // Here we pop immediately and use empty return data
        state.popFrame()

        // Copy return data to memory
        let retOffsetInt = Int(UInt64(retOffset.low32))
        let retSizeInt = min(Int(UInt64(retSize.low32)), 65536)
        let returnData = state.currentFrame.returnData

        if retSizeInt > 0 {
            state.memory.expand(offset: retOffsetInt, size: retSizeInt)
            for i in 0..<retSizeInt {
                let byte = i < returnData.count ? returnData[i] : 0
                state.memory.storeByte(offset: retOffsetInt + i, value: byte)
            }
        }

        // Record call entry
        let entry = CallEntry(
            callType: .call,
            to: to,
            value: value,
            gas: UInt64(gas.low32),
            input: inputData,
            output: returnData,
            success: true,
            callDepth: state.callDepth,
            startTimestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            endTimestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        )
        callEntries.append(entry)

        state.stack.push(.one)
    }

    private func delegatecall_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 6 else { throw EVMExecutionError.stackUnderflow }
        let gas = state.stack.pop()
        let to = state.stack.pop()
        let inOffset = state.stack.pop()
        let inSize = state.stack.pop()
        let retOffset = state.stack.pop()
        let retSize = state.stack.pop()

        // Gas calculation
        var callGas: UInt64 = 2600

        // Memory gas for input and output
        let inWords = UInt64((Int(UInt64(inSize.low32)) + 31) / 32)
        let retWords = UInt64((Int(UInt64(retSize.low32)) + 31) / 32)
        callGas += 3 * (inWords + retWords) + ((inWords + retWords) * (inWords + retWords)) / 512

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(to)
        if !isWarm {
            callGas += 100
        }
        state.accountManager.markAccessed(to)

        if !state.chargeGas(callGas) { throw EVMExecutionError.outOfGas }

        // Check call depth
        if state.callDepth >= 1024 {
            state.stack.push(.zero)
            return
        }

        // Get target code
        let code = state.accountManager.getCode(to)

        // Prepare input data from memory
        let inOffsetInt = Int(UInt64(inOffset.low32))
        let inSizeInt = Int(UInt64(inSize.low32))
        var inputData: [UInt8] = []
        inputData.reserveCapacity(inSizeInt)
        for i in 0..<inSizeInt {
            inputData.append(state.memory.loadByte(offset: inOffsetInt + i))
        }

        // Create subcall frame - delegatecall inherits caller and value
        var subFrame = CallFrame(code: code, calldata: inputData)
        subFrame.address = to
        subFrame.caller = state.currentFrame.caller  // Inherit caller's address
        subFrame.callValue = state.currentFrame.callValue  // Inherit value
        subFrame.gas = UInt64(gas.low32)

        // Execute subcall (simplified)
        state.pushFrame(subFrame)
        state.popFrame()

        // Copy return data to memory
        let retOffsetInt = Int(UInt64(retOffset.low32))
        let retSizeInt = min(Int(UInt64(retSize.low32)), 65536)
        let returnData = state.currentFrame.returnData

        if retSizeInt > 0 {
            state.memory.expand(offset: retOffsetInt, size: retSizeInt)
            for i in 0..<retSizeInt {
                let byte = i < returnData.count ? returnData[i] : 0
                state.memory.storeByte(offset: retOffsetInt + i, value: byte)
            }
        }

        // Record call entry
        let entry = CallEntry(
            callType: .delegateCall,
            to: to,
            value: state.currentFrame.callValue,
            gas: UInt64(gas.low32),
            input: inputData,
            output: returnData,
            success: true,
            callDepth: state.callDepth,
            startTimestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            endTimestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        )
        callEntries.append(entry)

        state.stack.push(.one)
    }

    private func staticcall_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 6 else { throw EVMExecutionError.stackUnderflow }
        let gas = state.stack.pop()
        let to = state.stack.pop()
        let inOffset = state.stack.pop()
        let inSize = state.stack.pop()
        let retOffset = state.stack.pop()
        let retSize = state.stack.pop()

        // Gas calculation
        var callGas: UInt64 = 2600

        // Memory gas for input and output
        let inWords = UInt64((Int(UInt64(inSize.low32)) + 31) / 32)
        let retWords = UInt64((Int(UInt64(retSize.low32)) + 31) / 32)
        callGas += 3 * (inWords + retWords) + ((inWords + retWords) * (inWords + retWords)) / 512

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(to)
        if !isWarm {
            callGas += 100
        }
        state.accountManager.markAccessed(to)

        if !state.chargeGas(callGas) { throw EVMExecutionError.outOfGas }

        // Check call depth
        if state.callDepth >= 1024 {
            state.stack.push(.zero)
            return
        }

        // Get target code
        let code = state.accountManager.getCode(to)

        // Prepare input data from memory
        let inOffsetInt = Int(UInt64(inOffset.low32))
        let inSizeInt = Int(UInt64(inSize.low32))
        var inputData: [UInt8] = []
        inputData.reserveCapacity(inSizeInt)
        for i in 0..<inSizeInt {
            inputData.append(state.memory.loadByte(offset: inOffsetInt + i))
        }

        // Create subcall frame - static call with no value transfer
        var subFrame = CallFrame(code: code, calldata: inputData)
        subFrame.address = to
        subFrame.caller = state.currentFrame.address
        subFrame.callValue = .zero  // No value in staticcall
        subFrame.gas = UInt64(gas.low32)
        subFrame.staticFlag = true  // Static call

        // Execute subcall (simplified)
        state.pushFrame(subFrame)
        state.popFrame()

        // Copy return data to memory
        let retOffsetInt = Int(UInt64(retOffset.low32))
        let retSizeInt = min(Int(UInt64(retSize.low32)), 65536)
        let returnData = state.currentFrame.returnData

        if retSizeInt > 0 {
            state.memory.expand(offset: retOffsetInt, size: retSizeInt)
            for i in 0..<retSizeInt {
                let byte = i < returnData.count ? returnData[i] : 0
                state.memory.storeByte(offset: retOffsetInt + i, value: byte)
            }
        }

        // Record call entry
        let entry = CallEntry(
            callType: .staticCall,
            to: to,
            value: .zero,
            gas: UInt64(gas.low32),
            input: inputData,
            output: returnData,
            success: true,
            callDepth: state.callDepth,
            startTimestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            endTimestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        )
        callEntries.append(entry)

        state.stack.push(.one)
    }

    private func create_op(_ state: inout EVMState, create2: Bool) throws {
        guard state.stack.stackHeight >= (create2 ? 4 : 3) else { throw EVMExecutionError.stackUnderflow }

        let value = state.stack.pop()
        let offset = state.stack.pop()
        let size = state.stack.pop()

        // Gas for CREATE/CREATE2
        if !state.chargeGas(32000) { throw EVMExecutionError.outOfGas }

        // Cannot create with value if not enough balance
        if !value.isZero {
            let selfBalance = state.accountManager.getBalance(state.currentFrame.address)
            if value.low64 > selfBalance.low64 {
                state.stack.push(.zero)  // Fail - insufficient balance
                return
            }
        }

        let salt: M31Word
        if create2 {
            salt = state.stack.pop()  // Additional argument for CREATE2
        } else {
            salt = .zero
        }

        let offsetInt = Int(UInt64(offset.low32))
        let sizeInt = min(Int(UInt64(size.low32)), 65536)

        // Copy init code from memory
        var initCode: [UInt8] = []
        initCode.reserveCapacity(sizeInt)
        for i in 0..<sizeInt {
            initCode.append(state.memory.loadByte(offset: offsetInt + i))
        }

        // For now, return zero address (not yet deployed)
        // A full implementation would:
        // 1. Increment nonce
        // 2. Compute address based on sender + nonce (or sender + salt for CREATE2)
        // 3. Deduct value from sender
        // 4. Execute init code
        // 5. If successful, store final code

        state.stack.push(.zero)  // Return zero for now
    }

    private func selfdestruct_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }

        // SELFDESTRUCT gas cost (EIP-150 rules)
        if !state.chargeGas(5000) { throw EVMExecutionError.outOfGas }

        let beneficiary = state.stack.pop()

        // Cannot SELFDESTRUCT in static context
        if state.currentFrame.staticFlag {
            // In a full implementation, this would revert
            // For now, just stop execution
            state.stop()
            return
        }

        // Transfer balance to beneficiary
        let balance = state.accountManager.getBalance(state.currentFrame.address)
        if !balance.isZero {
            state.accountManager.transferBalance(
                from: state.currentFrame.address,
                to: beneficiary,
                amount: balance
            )
        }

        state.stop()
    }

    // MARK: - SHA3

    private func keccak256_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        let size = state.stack.pop()
        if !state.chargeGas(30) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(UInt64(offset.low32))
        let sizeInt = Int(UInt64(size.low32))
        state.memory.expand(offset: offsetInt, size: sizeInt)

        // Extract memory region as bytes
        var memoryBytes = [UInt8]()
        memoryBytes.reserveCapacity(sizeInt)
        for i in 0..<sizeInt {
            memoryBytes.append(state.memory.loadByte(offset: offsetInt + i))
        }

        // Compute Keccak-256 hash using zkMetal's CPU implementation
        let hashBytes = zkMetal.keccak256(memoryBytes)

        // Convert 32-byte hash to M31Word (big-endian byte order)
        let resultWord = M31Word(bytes: hashBytes)
        state.stack.push(resultWord)
    }

    // MARK: - Environmental

    private func balance_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let address = state.stack.pop()

        // Base gas for BALANCE
        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(address)
        if !isWarm {
            if !state.chargeGas(100) { throw EVMExecutionError.outOfGas }
        }
        state.accountManager.markAccessed(address)

        state.stack.push(state.accountManager.getBalance(address))
    }

    private func calldataload_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let offset = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let offsetInt = Int(UInt64(offset.low32))
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

        let destInt = Int(UInt64(destOffset.low32))
        let offsetInt = Int(UInt64(offset.low32))
        let sizeInt = min(Int(UInt64(size.low32)), 65536)  // Cap at reasonable size

        // Memory expansion gas
        if sizeInt > 0 {
            let words = UInt64((sizeInt + 31) / 32)
            let memoryGas = 3 * words + (words * words) / 512
            if !state.chargeGas(memoryGas) { throw EVMExecutionError.outOfGas }
        }

        // Copy calldata to memory
        state.memory.expand(offset: destInt, size: sizeInt)
        let calldata = state.currentFrame.calldata
        for i in 0..<sizeInt {
            let byte = (offsetInt + i < calldata.count) ? calldata[offsetInt + i] : 0
            state.memory.storeByte(offset: destInt + i, value: byte)
        }
    }

    private func codecopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let destOffset = state.stack.pop()
        let offset = state.stack.pop()
        let size = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let destInt = Int(UInt64(destOffset.low32))
        let offsetInt = Int(UInt64(offset.low32))
        let sizeInt = min(Int(UInt64(size.low32)), 65536)

        // Memory expansion gas
        if sizeInt > 0 {
            let words = UInt64((sizeInt + 31) / 32)
            let memoryGas = 3 * words + (words * words) / 512
            if !state.chargeGas(memoryGas) { throw EVMExecutionError.outOfGas }
        }

        // Copy code to memory
        state.memory.expand(offset: destInt, size: sizeInt)
        let code = state.currentFrame.code
        for i in 0..<sizeInt {
            let byte = (offsetInt + i < code.count) ? code[offsetInt + i] : 0
            state.memory.storeByte(offset: destInt + i, value: byte)
        }
    }

    private func extcodesize_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let address = state.stack.pop()

        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(address)
        if !isWarm {
            if !state.chargeGas(100) { throw EVMExecutionError.outOfGas }
        }
        state.accountManager.markAccessed(address)

        state.stack.push(M31Word(low64: UInt64(state.accountManager.getCodeSize(address))))
    }

    private func extcodecopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 4 else { throw EVMExecutionError.stackUnderflow }
        let address = state.stack.pop()
        let destOffset = state.stack.pop()
        let offset = state.stack.pop()
        let size = state.stack.pop()

        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(address)
        if !isWarm {
            if !state.chargeGas(100) { throw EVMExecutionError.outOfGas }
        }
        state.accountManager.markAccessed(address)

        let destInt = Int(UInt64(destOffset.low32))
        let offsetInt = Int(UInt64(offset.low32))
        let sizeInt = min(Int(UInt64(size.low32)), 65536)

        // Memory expansion gas
        if sizeInt > 0 {
            let words = UInt64((sizeInt + 31) / 32)
            let memoryGas = 3 * words + (words * words) / 512
            if !state.chargeGas(memoryGas) { throw EVMExecutionError.outOfGas }
        }

        // Copy external code to memory
        state.memory.expand(offset: destInt, size: sizeInt)
        let code = state.accountManager.getCode(address)
        for i in 0..<sizeInt {
            let byte = (offsetInt + i < code.count) ? code[offsetInt + i] : 0
            state.memory.storeByte(offset: destInt + i, value: byte)
        }
    }

    private func returndatacopy_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 3 else { throw EVMExecutionError.stackUnderflow }
        let destOffset = state.stack.pop()
        let offset = state.stack.pop()
        let size = state.stack.pop()
        if !state.chargeGas(3) { throw EVMExecutionError.outOfGas }

        let destInt = Int(UInt64(destOffset.low32))
        let offsetInt = Int(UInt64(offset.low32))
        let sizeInt = min(Int(UInt64(size.low32)), 65536)

        // Memory expansion gas
        if sizeInt > 0 {
            let words = UInt64((sizeInt + 31) / 32)
            let memoryGas = 3 * words + (words * words) / 512
            if !state.chargeGas(memoryGas) { throw EVMExecutionError.outOfGas }
        }

        // Copy returnData to memory
        state.memory.expand(offset: destInt, size: sizeInt)
        let returnData = state.currentFrame.returnData
        for i in 0..<sizeInt {
            let byte = (offsetInt + i < returnData.count) ? returnData[offsetInt + i] : 0
            state.memory.storeByte(offset: destInt + i, value: byte)
        }
    }

    private func extcodehash_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let address = state.stack.pop()

        if !state.chargeGas(2600) { throw EVMExecutionError.outOfGas }

        // Cold access cost (EIP-2929)
        let isWarm = state.accountManager.isWarm(address)
        if !isWarm {
            if !state.chargeGas(100) { throw EVMExecutionError.outOfGas }
        }
        state.accountManager.markAccessed(address)

        // Non-existent account returns zero hash
        state.stack.push(state.accountManager.getCodeHash(address))
    }

    // MARK: - Block Operations

    private func blockhash_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let blockNumWord = state.stack.pop()
        if !state.chargeGas(20) { throw EVMExecutionError.outOfGas }

        // Extract block number as UInt64
        let blockNum = blockNumWord.low64

        // Get blockhash from block context
        let hash = state.block.getBlockhash(blockNum)
        state.stack.push(hash)
    }

    // MARK: - Storage Operations

    private func sload_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 1 else { throw EVMExecutionError.stackUnderflow }
        let key = state.stack.pop()

        // Track storage key for EIP-2929 access list
        let keyHex = key.toHexString()
        let address = state.currentFrame.address.toHexString()
        let storageKey = "\(address):\(keyHex)"

        // Calculate gas cost: 2100 for cold access, 100 for warm access (EIP-2929)
        let isWarm = state.accessedStorageKeys.contains(storageKey)
        let gasCost: UInt64 = isWarm ? 100 : 2100
        if !state.chargeGas(gasCost) { throw EVMExecutionError.outOfGas }

        // Mark as accessed
        state.accessedStorageKeys.insert(storageKey)

        // Load value from storage
        let value = state.storage.load(key: key)

        // Record storage access
        let access = StorageAccess(
            key: key,
            value: value,
            timestamp: storageTimestamp,
            accessType: .load,
            callDepth: state.callDepth
        )
        storageAccesses.append(access)
        storageTimestamp += 1

        state.stack.push(value)
    }

    private func sstore_op(_ state: inout EVMState) throws {
        guard state.stack.stackHeight >= 2 else { throw EVMExecutionError.stackUnderflow }
        let key = state.stack.pop()
        let value = state.stack.pop()

        // Track storage key for EIP-2929 access list
        let keyHex = key.toHexString()
        let address = state.currentFrame.address.toHexString()
        let storageKey = "\(address):\(keyHex)"

        // Get current value
        let currentValue = state.storage.load(key: key)

        // Calculate gas cost based on EIP-2929 and EIP-2200
        let isWarm = state.accessedStorageKeys.contains(storageKey)
        let gasCost: UInt64

        if !isWarm {
            // Cold access: 2100 to add to access list
            gasCost = 2100
        } else {
            // Warm access
            if currentValue.isZero && !value.isZero {
                // Setting a zero slot to non-zero (creation)
                gasCost = 20_000
            } else if !currentValue.isZero && value.isZero {
                // Setting a non-zero slot to zero (deletion/refund)
                gasCost = 5_000
                state.gasRefund += 15_000  // Refund for clearing storage
            } else {
                // Modifying an existing slot or setting zero to zero
                gasCost = 5_000
            }
        }

        if !state.chargeGas(gasCost) { throw EVMExecutionError.outOfGas }

        // Mark as accessed
        state.accessedStorageKeys.insert(storageKey)

        // Store value in storage
        state.storage.store(key: key, value: value)

        // Record storage access
        let access = StorageAccess(
            key: key,
            value: value,
            timestamp: storageTimestamp,
            accessType: .store,
            callDepth: state.callDepth
        )
        storageAccesses.append(access)
        storageTimestamp += 1

        // Update state root (simplified - in real implementation would compute Merkle root)
        // state.stateRoot = computeNewStateRoot(stateRoot, key, value)
    }
}

// MARK: - Execution Result

public struct EVMExecutionResult: Sendable {
    public let trace: EVMExecutionTrace
    public let memoryTrace: MemoryTrace
    public let storageTrace: StorageTrace
    public let callTrace: [CallEntry]
}
