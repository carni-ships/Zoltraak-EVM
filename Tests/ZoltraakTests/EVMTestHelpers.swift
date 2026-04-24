// EVMTestHelpers.swift - Shared helper functions for EVM opcode correctness tests
//
// Provides utilities for:
// - Creating test execution engines with default block/tx context
// - Executing bytecode and generating CircleSTARK proofs
// - Verifying proofs (constraint satisfaction proves correctness)
// - Simple execute-and-verify helper for quick tests

import Foundation
import zkMetal
@testable import Zoltraak

// MARK: - Test Engine Factory

/// Creates a test EVMExecutionEngine with default block/tx context
public func createTestEngine() -> EVMExecutionEngine {
    return EVMExecutionEngine()
}

/// Creates an engine with custom block context
public func createTestEngine(blockNumber: UInt64, gasLimit: UInt64 = 30_000_000) -> EVMExecutionEngine {
    let block = BlockContext(
        gasLimit: gasLimit,
        number: blockNumber
    )
    return EVMExecutionEngine(block: block)
}

// MARK: - Bytecode Helpers

/// Push a value onto the stack using PUSH1-PUSH32
public func pushBytecode(_ value: UInt64, size: Int = 1) -> [UInt8] {
    var code: [UInt8] = []
    switch size {
    case 1:
        code.append(0x60) // PUSH1
        code.append(UInt8(value & 0xFF))
    case 2:
        code.append(0x61) // PUSH2
        code.append(UInt8((value >> 8) & 0xFF))
        code.append(UInt8(value & 0xFF))
    default:
        // For larger pushes, use generic approach
        code.append(0x7F) // PUSH32
        for i in (0..<32).reversed() {
            code.append(UInt8((value >> (i * 8)) & 0xFF))
        }
    }
    return code
}

/// Creates bytecode for a simple opcode test with known inputs
public func simpleOpcodeBytecode(_ opcode: UInt8, inputs: [UInt8]) -> [UInt8] {
    return inputs + [opcode, 0x00] // End with STOP
}

// MARK: - Proof Generation

/// Execute bytecode and generate a CircleSTARK proof
/// - Parameters:
///   - code: EVM bytecode to execute
///   - gasLimit: Gas limit for execution (default 100_000)
/// - Returns: Tuple of execution result and generated proof
public func executeAndProve(
    code: [UInt8],
    gasLimit: UInt64 = 100_000
) throws -> (result: EVMExecutionResult, proof: CircleSTARKProof) {
    // Create engine and execute
    let engine = createTestEngine()
    let result = try engine.execute(code: code, gasLimit: gasLimit)

    // Create AIR from execution result
    let air = EVMAIR(from: result)

    // Generate proof using CircleSTARK prover
    let prover = CircleSTARKProver(logBlowup: 4, numQueries: 30)
    let proof = try prover.proveCPU(air: air)

    return (result, proof)
}

/// Execute bytecode and verify the proof
/// Returns the execution result if both execution and proof verification succeed
public func executeAndVerify(
    code: [UInt8],
    gasLimit: UInt64 = 100_000
) throws -> EVMExecutionResult {
    let (result, proof) = try executeAndProve(code: code, gasLimit: gasLimit)

    // Verify proof
    let verifier = CircleSTARKVerifier()
    let verified = try verifier.verify(air: EVMAIR(from: result), proof: proof)

    if !verified {
        throw EVMTestError.proofVerificationFailed
    }

    return result
}

// MARK: - Stack Assertions

/// Extracts final stack value after execution
public func getFinalStackValue(_ result: EVMExecutionResult) -> M31Word? {
    guard let lastRow = result.trace.rows.last else { return nil }
    // The trace rows contain the execution state; we need to extract stack value
    // This is a simplified version - actual implementation may need more context
    return nil
}

/// Helper to check if execution was successful (not reverted)
public func assertExecutionSuccess(_ result: EVMExecutionResult) {
    precondition(result.success, "Execution was reverted: gasUsed=\(result.trace.rows.last?.gas ?? 0)")
}

// MARK: - Custom Errors

public enum EVMTestError: Error, Sendable {
    case proofGenerationFailed(String)
    case proofVerificationFailed
    case executionFailed(String)
    case invalidBytecode(String)
}

// MARK: - Gas Constants for Common Opcodes

public struct EVMGas {
    // Base gas costs
    public static let STOP: UInt64 = 0
    public static let ADD: UInt64 = 3
    public static let MUL: UInt64 = 5
    public static let SUB: UInt64 = 3
    public static let DIV: UInt64 = 5
    public static let SDIV: UInt64 = 5
    public static let MOD: UInt64 = 5
    public static let SMOD: UInt64 = 5
    public static let ADDMOD: UInt64 = 8
    public static let MULMOD: UInt64 = 8
    public static let EXP: UInt64 = 10  // + 10 per byte of exponent

    // Comparison and bitwise
    public static let LT: UInt64 = 3
    public static let GT: UInt64 = 3
    public static let EQ: UInt64 = 3
    public static let ISZERO: UInt64 = 3
    public static let AND: UInt64 = 3
    public static let OR: UInt64 = 3
    public static let XOR: UInt64 = 3
    public static let NOT: UInt64 = 3
    public static let BYTE: UInt64 = 3
    public static let SHL: UInt64 = 3
    public static let SHR: UInt64 = 3
    public static let SAR: UInt64 = 3

    // Memory operations
    public static let MLOAD: UInt64 = 3
    public static let MSTORE: UInt64 = 3
    public static let MSTORE8: UInt64 = 3

    // Control flow
    public static let JUMP: UInt64 = 8
    public static let JUMPI: UInt64 = 10
    public static let JUMPDEST: UInt64 = 1

    // Stack operations
    public static let PUSH1: UInt64 = 3
    public static let DUP1: UInt64 = 3
    public static let SWAP1: UInt64 = 3

    // Environmental
    public static let ADDRESS: UInt64 = 2
    public static let CALLER: UInt64 = 2
    public static let CALLVALUE: UInt64 = 2
    public static let ORIGIN: UInt64 = 2
    public static let GASPRICE: UInt64 = 2
    public static let COINBASE: UInt64 = 2
    public static let TIMESTAMP: UInt64 = 2
    public static let NUMBER: UInt64 = 2
    public static let PREVRANDAO: UInt64 = 2
    public static let GASLIMIT: UInt64 = 2
    public static let CHAINID: UInt64 = 2
    public static let BASEFEE: UInt64 = 2
    public static let SELFBALANCE: UInt64 = 5

    // Block operations
    public static let BLOCKHASH: UInt64 = 20

    // System calls
    public static let CREATE: UInt64 = 32000
    public static let CALL: UInt64 = 100  // + 900 for call gas
    public static let DELEGATECALL: UInt64 = 100
    public static let STATICCALL: UInt64 = 100
    public static let SELFDESTRUCT: UInt64 = 5000  // + 25000 refund

    // Memory expansion
    public static func memoryExpand(_ words: UInt64) -> UInt64 {
        if words == 0 { return 0 }
        return 3 * words + (words * words) / 512
    }
}

// MARK: - Convenience Test Builders

/// Builds test bytecode for arithmetic opcodes
public struct ArithmeticTestBuilder {
    private var code: [UInt8] = []

    public init() {}

    public mutating func push(_ value: UInt8) -> ArithmeticTestBuilder {
        code.append(0x60) // PUSH1
        code.append(value)
        return self
    }

    public mutating func push2(_ value: UInt16) -> ArithmeticTestBuilder {
        code.append(0x61) // PUSH2
        code.append(UInt8((value >> 8) & 0xFF))
        code.append(UInt8(value & 0xFF))
        return self
    }

    public mutating func op(_ opcode: UInt8) -> ArithmeticTestBuilder {
        code.append(opcode)
        return self
    }

    public func build() -> [UInt8] {
        return code + [0x00] // End with STOP
    }

    public func buildNoStop() -> [UInt8] {
        return code
    }
}

// MARK: - Opcode Bytecode Constants

public struct OpcodeBytes {
    // Stop and arithmetic
    public static let STOP: UInt8 = 0x00
    public static let ADD: UInt8 = 0x01
    public static let MUL: UInt8 = 0x02
    public static let SUB: UInt8 = 0x03
    public static let DIV: UInt8 = 0x04
    public static let SDIV: UInt8 = 0x05
    public static let MOD: UInt8 = 0x06
    public static let SMOD: UInt8 = 0x07
    public static let ADDMOD: UInt8 = 0x08
    public static let MULMOD: UInt8 = 0x09
    public static let EXP: UInt8 = 0x0A
    public static let SIGNEXTEND: UInt8 = 0x0B

    // Comparison and bitwise
    public static let LT: UInt8 = 0x10
    public static let GT: UInt8 = 0x11
    public static let SLT: UInt8 = 0x12
    public static let SGT: UInt8 = 0x13
    public static let EQ: UInt8 = 0x14
    public static let ISZERO: UInt8 = 0x15
    public static let AND: UInt8 = 0x16
    public static let OR: UInt8 = 0x17
    public static let XOR: UInt8 = 0x18
    public static let NOT: UInt8 = 0x19
    public static let BYTE: UInt8 = 0x1A
    public static let SHL: UInt8 = 0x1B
    public static let SHR: UInt8 = 0x1C
    public static let SAR: UInt8 = 0x1D

    // SHA3
    public static let KECCAK256: UInt8 = 0x20

    // Memory operations
    public static let MLOAD: UInt8 = 0x51
    public static let MSTORE: UInt8 = 0x52
    public static let MSTORE8: UInt8 = 0x53

    // Control flow
    public static let JUMP: UInt8 = 0x56
    public static let JUMPI: UInt8 = 0x57
    public static let JUMPDEST: UInt8 = 0x5B

    // Stack operations
    public static let PUSH1: UInt8 = 0x60
    public static let PUSH2: UInt8 = 0x61
    public static let PUSH32: UInt8 = 0x7F
    public static let POP: UInt8 = 0x50
    public static let DUP1: UInt8 = 0x80
    public static let DUP16: UInt8 = 0x8F
    public static let SWAP1: UInt8 = 0x90
    public static let SWAP16: UInt8 = 0x9F

    // Environmental
    public static let ADDRESS: UInt8 = 0x30
    public static let CALLER: UInt8 = 0x33
    public static let CALLVALUE: UInt8 = 0x34
    public static let ORIGIN: UInt8 = 0x32
    public static let GASPRICE: UInt8 = 0x3A
    public static let SELFBALANCE: UInt8 = 0x47

    // Block operations
    public static let BLOCKHASH: UInt8 = 0x40
    public static let COINBASE: UInt8 = 0x41
    public static let TIMESTAMP: UInt8 = 0x42
    public static let NUMBER: UInt8 = 0x43
    public static let PREVRANDAO: UInt8 = 0x44
    public static let GASLIMIT: UInt8 = 0x45
    public static let CHAINID: UInt8 = 0x46
    public static let BASEFEE: UInt8 = 0x48

    // LOG operations
    public static let LOG0: UInt8 = 0xA0
    public static let LOG1: UInt8 = 0xA1
    public static let LOG2: UInt8 = 0xA2
    public static let LOG3: UInt8 = 0xA3
    public static let LOG4: UInt8 = 0xA4

    // System operations
    public static let CREATE: UInt8 = 0xF0
    public static let CALL: UInt8 = 0xF1
    public static let DELEGATECALL: UInt8 = 0xF4
    public static let STATICCALL: UInt8 = 0xFA
    public static let RETURN: UInt8 = 0xF3
    public static let REVERT: UInt8 = 0xFD
    public static let SELFDESTRUCT: UInt8 = 0xFF

    // EOF operations
    public static let RJUMP: UInt8 = 0xE0
    public static let RJUMPI: UInt8 = 0xE1
    public static let CALLF: UInt8 = 0xE2
    public static let RETF: UInt8 = 0xE3
}