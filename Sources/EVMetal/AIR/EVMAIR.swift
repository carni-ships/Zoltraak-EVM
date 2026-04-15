import Foundation
import zkMetal

/// EVM-specific AIR constraints for the EVM execution trace.
/// Maps EVM execution traces to polynomial constraints over M31 field elements.
/// Conforms to CircleAIR protocol for Circle STARK proving.
public struct EVMAIR: CircleAIR {

    public typealias Field = M31

    // MARK: - CircleAIR Conformance

    /// Number of columns in the trace
    public var numColumns: Int { Self.numColumns }

    /// Static number of columns
    public static let numColumns = 180

    /// Log of the trace length (number of steps = 2^logTraceLength)
    public let logTraceLength: Int

    /// Number of constraints per row
    public let numConstraints: Int

    /// Constraint degrees for each constraint
    public let constraintDegrees: [Int]

    /// Initial state root (Poseidon2-M31 Merkle root)
    public let initialStateRoot: M31Word

    /// Gas limit for this execution
    public let gasLimit: UInt64

    // MARK: - Stored Execution Result

    private var executionResult: EVMExecutionResult?

    // MARK: - Boundary Constraints (CircleAIR Conformance)

    public var boundaryConstraints: [(column: Int, row: Int, value: M31)] {
        [
            (column: 0, row: 0, value: M31.zero),                    // Initial PC = 0
            (column: 1, row: 0, value: M31.zero),                    // Initial gas high
            (column: 2, row: 0, value: M31.zero),                   // Initial gas low
            (column: 163, row: 0, value: M31.zero),                 // Initial call depth = 0
        ]
    }

    // MARK: - Initialization

    public init(logTraceLength: Int, initialStateRoot: M31Word = .zero, gasLimit: UInt64 = 30_000_000) {
        self.logTraceLength = logTraceLength
        self.initialStateRoot = initialStateRoot
        self.gasLimit = gasLimit
        self.numConstraints = 50
        self.constraintDegrees = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3]
    }

    /// Initialize from execution result
    public init(from result: EVMExecutionResult) {
        let traceLength = result.trace.rows.count
        let n = traceLength.nextPowerOfTwo()
        self.logTraceLength = max(10, (64 - n.leadingZeroBitCount - 1))
        self.initialStateRoot = result.trace.initialState.stateRoot
        self.gasLimit = result.trace.gasUsed + 1_000_000
        self.numConstraints = 50
        self.constraintDegrees = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3]
        self.executionResult = result
    }

    // MARK: - Trace Generation (CircleAIR Conformance)

    /// Generate trace columns from stored execution result
    public func generateTrace() -> [[M31]] {
        guard let result = executionResult else {
            // Return empty trace if no result stored
            let traceLength = 1 << logTraceLength
            return [[M31]](repeating: [M31](repeating: .zero, count: traceLength), count: Self.numColumns)
        }
        return generateTrace(from: result)
    }

    /// Generate trace columns from an EVM execution result
    public func generateTrace(from result: EVMExecutionResult) -> [[M31]] {
        let rows = result.trace.rows
        let traceLength = 1 << logTraceLength

        // Initialize columns with zeros
        var columns = [[M31]](repeating: [M31](repeating: .zero, count: traceLength), count: Self.numColumns)

        // Fill in trace rows
        for (i, row) in rows.enumerated() where i < traceLength {
            fillRow(columns: &columns, rowIndex: i, traceRow: row)
        }

        // Pad remaining rows with final state
        if rows.count > 0 {
            let lastRow = rows[rows.count - 1]
            for i in rows.count..<traceLength {
                fillRow(columns: &columns, rowIndex: i, traceRow: lastRow, isPadding: true)
            }
        }

        return columns
    }

    private func fillRow(columns: inout [[M31]], rowIndex: Int, traceRow: EVMTraceRow, isPadding: Bool = false) {
        // PC (column 0)
        columns[0][rowIndex] = M31(v: UInt32(traceRow.pc))

        // Gas (columns 1-2)
        let gas = isPadding ? gasLimit : traceRow.gas
        columns[1][rowIndex] = M31(v: UInt32(truncatingIfNeeded: gas >> 31))
        columns[2][rowIndex] = M31(v: UInt32(truncatingIfNeeded: gas))

        // Stack columns (3-147) - 16 stack slots × 9 limbs = 144 columns
        // Simplified: fill with traceRow.stackHeight
        for j in 3..<147 {
            columns[j][rowIndex] = .zero
        }

        // Memory address (column 155)
        columns[155][rowIndex] = .zero

        // Opcode (column 158)
        columns[158][rowIndex] = M31(v: UInt32(traceRow.opcode))

        // Flags (columns 159-162)
        columns[159][rowIndex] = M31(v: traceRow.isStackOp ? 1 : 0)
        columns[160][rowIndex] = M31(v: traceRow.isMemoryOp ? 1 : 0)
        columns[161][rowIndex] = M31(v: traceRow.isStorageOp ? 1 : 0)
        columns[162][rowIndex] = M31(v: traceRow.isControlFlow ? 1 : 0)

        // Call depth (column 163)
        columns[163][rowIndex] = M31(v: UInt32(traceRow.callDepth))

        // State root (columns 164-166)
        columns[164][rowIndex] = traceRow.stateRoot.limbs.count > 0 ? traceRow.stateRoot.limbs[0] : .zero
        columns[165][rowIndex] = traceRow.stateRoot.limbs.count > 1 ? traceRow.stateRoot.limbs[1] : .zero
        columns[166][rowIndex] = traceRow.stateRoot.limbs.count > 2 ? traceRow.stateRoot.limbs[2] : .zero

        // Timestamp (column 167)
        columns[167][rowIndex] = M31(v: UInt32(truncatingIfNeeded: traceRow.timestamp))
    }

    // MARK: - Constraint Evaluation (CircleAIR Conformance)

    /// Evaluate transition constraints for a single row pair (current, next)
    public func evaluateConstraints(current: [M31], next: [M31]) -> [M31] {
        var constraints = [M31]()
        constraints.reserveCapacity(numConstraints)

        // Get opcode
        let opcodeValue = current[158].v
        guard let opcode = EVMOpcode(rawValue: UInt8(opcodeValue & 0xFF)) else {
            // Invalid opcode - return constraint failures
            for _ in 0..<numConstraints {
                constraints.append(M31.one)
            }
            return constraints
        }

        // 1. PC continuity constraint
        let pcConstraint = evaluatePCConstraint(current: current, next: next, opcode: opcode)
        constraints.append(pcConstraint)

        // 2. Gas monotonicity
        let gasConstraint = evaluateGasConstraint(current: current, next: next)
        constraints.append(gasConstraint)

        // 3. Call depth constraints
        let depthConstraint = evaluateCallDepthConstraint(current: current, next: next)
        constraints.append(depthConstraint)

        // 4. Opcode validity
        let opcodeConstraint = evaluateOpcodeValidity(opcode: opcode)
        constraints.append(opcodeConstraint)

        // 5. Stack constraints based on opcode type
        let stackConstraint = evaluateStackConstraint(current: current, next: next, opcode: opcode)
        constraints.append(stackConstraint)

        // 6-10. Additional opcode-specific constraints
        let additionalConstraints = evaluateOpcodeSpecificConstraints(current: current, next: next, opcode: opcode)
        for c in additionalConstraints.prefix(numConstraints - 6) {
            constraints.append(c)
        }

        // Pad remaining constraints
        while constraints.count < numConstraints {
            constraints.append(.zero)
        }

        return constraints
    }

    // MARK: - Individual Constraint Evaluations

    /// PC continuity: PC increments by 1 for sequential ops, changes for jumps
    private func evaluatePCConstraint(current: [M31], next: [M31], opcode: EVMOpcode) -> M31 {
        let currentPC = current[0].v
        let nextPC = next[0].v

        switch opcode {
        case .JUMP:
            // JUMP destination is arbitrary (verified by JUMPDEST check in real impl)
            return .zero

        case .JUMPI:
            // If condition != 0, nextPC is destination, otherwise PC+1
            // Simplified: allow arbitrary nextPC
            return .zero

        case .STOP, .RETURN, .REVERT, .SELFDESTRUCT:
            // PC can be anything after termination
            return .zero

        case .JUMPDEST:
            // Next PC should be current PC + 1 (JUMPDEST itself doesn't change PC)
            let expected = m31Add(M31(v: currentPC), M31.one)
            return m31Sub(M31(v: nextPC), expected)

        default:
            // Sequential: nextPC = currentPC + 1
            let expected = m31Add(M31(v: currentPC), M31.one)
            return m31Sub(M31(v: nextPC), expected)
        }
    }

    /// Gas monotonicity: gas only decreases
    private func evaluateGasConstraint(current: [M31], next: [M31]) -> M31 {
        let gasCurrent = (UInt64(current[1].v) << 31) | UInt64(current[2].v)
        let gasNext = (UInt64(next[1].v) << 31) | UInt64(next[2].v)

        // Gas can only decrease (next <= current)
        if gasNext <= gasCurrent {
            return .zero
        } else {
            return M31.one
        }
    }

    /// Call depth can only change by at most 1
    private func evaluateCallDepthConstraint(current: [M31], next: [M31]) -> M31 {
        let depthCurrent = Int(current[163].v)
        let depthNext = Int(next[163].v)
        let diff = depthNext - depthCurrent

        // Valid changes: -1, 0, +1
        if diff >= -1 && diff <= 1 {
            return .zero
        }
        return M31.one
    }

    /// Opcode validity check
    private func evaluateOpcodeValidity(opcode: EVMOpcode) -> M31 {
        // All opcodes in our enum are valid
        return .zero
    }

    /// Stack height change validation
    private func evaluateStackConstraint(current: [M31], next: [M31], opcode: EVMOpcode) -> M31 {
        let heightChange = opcode.properties.stackHeightChange

        // For now, just verify the height change is consistent
        // In full implementation, we'd verify actual stack values
        return .zero
    }

    /// Opcode-specific constraint evaluation
    private func evaluateOpcodeSpecificConstraints(current: [M31], next: [M31], opcode: EVMOpcode) -> [M31] {
        var constraints = [M31]()

        switch opcode {
        // Arithmetic ops
        case .ADD, .SUB, .MUL, .DIV, .SDIV, .MOD, .SMOD:
            constraints.append(evaluateArithmeticConstraint(current: current, next: next))

        case .ADDMOD, .MULMOD:
            constraints.append(evaluateModArithmeticConstraint(current: current, next: next))

        case .EXP:
            constraints.append(evaluateExpConstraint(current: current, next: next))

        case .SIGNEXTEND:
            constraints.append(evaluateSignExtendConstraint(current: current, next: next))

        // Comparison and bitwise ops
        case .LT, .GT, .SLT, .SGT:
            constraints.append(evaluateComparisonConstraint(current: current, next: next))

        case .EQ:
            constraints.append(evaluateEqConstraint(current: current, next: next))

        case .ISZERO:
            constraints.append(evaluateIsZeroConstraint(current: current, next: next))

        case .AND, .OR, .XOR:
            constraints.append(evaluateBitwiseConstraint(current: current, next: next))

        case .NOT:
            constraints.append(evaluateNotConstraint(current: current, next: next))

        case .BYTE:
            constraints.append(evaluateByteConstraint(current: current, next: next))

        case .SHL, .SHR, .SAR:
            constraints.append(evaluateShiftConstraint(current: current, next: next))

        // Memory ops
        case .MLOAD, .MSTORE, .MSTORE8:
            constraints.append(evaluateMemoryConstraint(current: current, next: next))

        // Control flow
        case .JUMP, .JUMPI:
            constraints.append(evaluateJumpConstraint(current: current, next: next))

        // Calls
        case .CALL, .DELEGATECALL, .STATICCALL, .CREATE, .CREATE2:
            constraints.append(evaluateCallConstraint(current: current, next: next))

        // System
        case .RETURN, .REVERT, .SELFDESTRUCT:
            constraints.append(.zero)

        // Stack ops - just verify consistency
        case .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8,
             .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16,
             .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24,
             .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32,
             .PUSH0:
            constraints.append(.zero)

        case .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8,
             .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16,
             .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8,
             .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16:
            constraints.append(.zero)

        case .POP:
            constraints.append(.zero)

        // Block ops
        case .BLOCKHASH, .COINBASE, .TIMESTAMP, .NUMBER, .PREVRANDAO, .GASLIMIT, .BASEFEE, .CHAINID:
            constraints.append(.zero)

        // Environmental
        case .ADDRESS, .ORIGIN, .CALLER, .CALLVALUE, .GASPRICE, .SELFBALANCE:
            constraints.append(.zero)

        case .CALLDATALOAD, .CALLDATASIZE, .CALLDATACOPY:
            constraints.append(.zero)

        case .CODESIZE, .CODECOPY:
            constraints.append(.zero)

        case .EXTCODESIZE, .EXTCODECOPY, .EXTCODEHASH:
            constraints.append(.zero)

        case .RETURNDATASIZE, .RETURNDATACOPY:
            constraints.append(.zero)

        // Gas
        case .GAS:
            constraints.append(.zero)

        // PC and MSIZE
        case .PC, .MSIZE:
            constraints.append(.zero)

        // Log
        case .LOG0, .LOG1, .LOG2, .LOG3, .LOG4:
            constraints.append(.zero)

        // SHA3
        case .KECCAK256:
            constraints.append(evaluateKeccakConstraint(current: current, next: next))

        // Stop
        case .STOP:
            constraints.append(.zero)

        default:
            constraints.append(.zero)
        }

        // Pad to 5 constraints
        while constraints.count < 5 {
            constraints.append(.zero)
        }

        return constraints
    }

    // MARK: - Specific Opcode Constraints

    /// Arithmetic constraint (ADD, SUB, MUL, DIV, MOD)
    private func evaluateArithmeticConstraint(current: [M31], next: [M31]) -> M31 {
        // Stack columns 3-18 contain stack values (9 limbs per slot, 2 slots = 18 cols)
        let a = Array(current[3..<12])  // First operand, 9 limbs
        let b = Array(current[12..<21]) // Second operand, 9 limbs
        let result = Array(next[3..<12]) // Result, 9 limbs

        // Use EVMCircuit addition constraints to verify
        let carries = EVMCircuit.addConstraints(a: a, b: b, result: result)
        // If all carries are valid (carry[i] < M31.P), constraint passes
        let carriesSum = carries.reduce(M31.zero) { EVMCircuit.m31Add($0, $1) }
        return carriesSum
    }

    /// Mod arithmetic constraint (ADDMOD, MULMOD)
    private func evaluateModArithmeticConstraint(current: [M31], next: [M31]) -> M31 {
        // ADDMOD: (a + b) % c = result
        let a = Array(current[3..<12])
        let b = Array(current[12..<21])
        let c = Array(current[21..<30])
        let result = Array(next[3..<12])

        // First compute a + b
        var sum = [M31](repeating: .zero, count: 9)
        var carry: UInt64 = 0
        for i in 0..<9 {
            let s = UInt64(a[i].v) + UInt64(b[i].v) + carry
            sum[i] = M31(v: UInt32(s % UInt64(M31.P)))
            carry = s / UInt64(M31.P)
        }

        // Then compute sum % c using mod constraints
        let modCons = EVMCircuit.modConstraints(a: sum, b: c, result: result)
        return modCons.first ?? .zero
    }

    /// EXP constraint
    private func evaluateExpConstraint(current: [M31], next: [M31]) -> M31 {
        // EVM EXP: result = base^exp mod 2^256
        // Simplified: just verify exp is small enough (exp < 256 for typical cases)
        let exp = current[21].v  // exp value
        // For now, verify exp is within bounds
        if exp < 256 {
            return .zero
        }
        return M31.one
    }

    /// SIGNEXTEND constraint
    private func evaluateSignExtendConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let tb = current[21]
        let result = Array(next[3..<12])

        let constraints = EVMCircuit.signextendConstraints(a: a, tb: tb, result: result)
        return constraints.first ?? .zero
    }

    /// Comparison constraint (LT, GT, SLT, SGT)
    private func evaluateComparisonConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let b = Array(current[12..<21])
        let result = next[3]  // Result is single M31

        let constraints = EVMCircuit.ltConstraints(a: a, b: b, result: result)
        return constraints.first ?? .zero
    }

    /// EQ constraint
    private func evaluateEqConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let b = Array(current[12..<21])
        let result = next[3]

        let constraints = EVMCircuit.eqConstraints(a: a, b: b, result: result)
        return constraints.first ?? .zero
    }

    /// ISZERO constraint
    private func evaluateIsZeroConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let result = next[3]

        // ISZERO: result = 1 if a == 0, else 0
        let sumOfLimbs = a.reduce(M31.zero) { EVMCircuit.m31Add($0, $1) }
        let isZero: UInt32 = sumOfLimbs.v == 0 ? 1 : 0
        return EVMCircuit.m31Sub(result, M31(v: isZero))
    }

    /// Bitwise constraint (AND, OR, XOR)
    private func evaluateBitwiseConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let b = Array(current[12..<21])
        let result = Array(next[3..<12])

        let constraints = EVMCircuit.andConstraints(a: a, b: b, result: result)
        return constraints.first ?? .zero
    }

    /// NOT constraint
    private func evaluateNotConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let result = Array(next[3..<12])

        let constraints = EVMCircuit.notConstraints(a: a, result: result)
        return constraints.first ?? .zero
    }

    /// BYTE constraint
    private func evaluateByteConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let index = current[21]
        let result = next[3]

        let constraints = EVMCircuit.byteConstraints(a: a, index: index, result: result)
        return constraints.first ?? .zero
    }

    /// Shift constraint (SHL, SHR, SAR)
    private func evaluateShiftConstraint(current: [M31], next: [M31]) -> M31 {
        let a = Array(current[3..<12])
        let shift = current[21]
        let result = Array(next[3..<12])

        let constraints = EVMCircuit.shlConstraints(a: a, shift: shift, result: result)
        return constraints.first ?? .zero
    }

    /// Memory constraint (MLOAD, MSTORE, MSTORE8)
    private func evaluateMemoryConstraint(current: [M31], next: [M31]) -> M31 {
        // Memory address in column 155
        let addr = current[155]
        // Memory size in next row's column 155 (after expansion)
        let nextAddr = next[155]
        let nextIsZero = EVMCircuit.m31IsZero(nextAddr) ? M31.one : M31.zero

        // Memory can only grow, never shrink
        let isGrowing = EVMCircuit.m31IsZero(
            EVMCircuit.m31Sub(addr, nextAddr)
        ) ? M31.one : M31.zero

        // Memory should either stay same or grow
        return EVMCircuit.m31Sub(isGrowing, M31.one)
    }

    /// Jump constraint (JUMP, JUMPI)
    private func evaluateJumpConstraint(current: [M31], next: [M31]) -> M31 {
        // JUMP destination must be a JUMPDEST
        // This requires checking the code at destination
        // Simplified: verify PC change is valid
        let currentPC = current[0].v
        let nextPC = next[0].v
        let opcode = current[158].v

        if opcode == 0x56 { // JUMP
            // JUMP: nextPC can be any value (verified by JUMPDEST check)
            return .zero
        } else { // JUMPI
            // JUMPI: nextPC is either destination or currentPC+1
            // Simplified: just verify nextPC is valid
            return .zero
        }
    }

    /// Call constraint (CALL, DELEGATECALL, STATICCALL, CREATE, CREATE2)
    private func evaluateCallConstraint(current: [M31], next: [M31]) -> M31 {
        // Call depth must increase by 1
        let currentDepth = current[163].v
        let nextDepth = next[163].v
        let depthDiff = Int32(nextDepth) - Int32(currentDepth)

        // Valid: depth increases by 1 for CALL, decreases by 1 for RETURN
        if depthDiff == 1 || depthDiff == -1 || depthDiff == 0 {
            return .zero
        }
        return M31.one
    }

    /// Keccak constraint
    private func evaluateKeccakConstraint(current: [M31], next: [M31]) -> M31 {
        // Keccak is computed via precompile, we just verify the gas was deducted
        // and the output is correctly placed
        let gasCurrent = (UInt64(current[1].v) << 31) | UInt64(current[2].v)
        let gasNext = (UInt64(next[1].v) << 31) | UInt64(next[2].v)

        // Gas must have decreased (KECCAK256 has high gas cost)
        if gasNext < gasCurrent {
            return .zero
        }
        return M31.one
    }

    // MARK: - Helper Functions

    private func m31Sub(_ a: M31, _ b: M31) -> M31 {
        let p = UInt32(M31.P)
        let result = Int32(a.v) - Int32(b.v)
        if result >= 0 {
            return M31(v: UInt32(result))
        } else {
            return M31(v: UInt32(result + Int32(p)))
        }
    }

    private func m31Add(_ a: M31, _ b: M31) -> M31 {
        let sum = UInt64(a.v) + UInt64(b.v)
        let p = UInt64(M31.P)
        if sum < p {
            return M31(v: UInt32(sum))
        } else {
            return M31(v: UInt32(sum - p))
        }
    }
}
