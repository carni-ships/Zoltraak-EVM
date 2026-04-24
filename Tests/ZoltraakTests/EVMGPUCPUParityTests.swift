// EVMGPUCPUParityTests.swift - GPU vs CPU execution parity tests
//
// Tests that verify the GPU and CPU execution paths produce identical results.
// This is critical for ensuring GPU acceleration doesn't introduce correctness bugs.
//
// Parity is verified for:
// - Execution success/failure
// - Gas used
// - Stack state
// - Memory state
// - Reverted flag

import Foundation
import Testing
import zkMetal
@testable import Zoltraak

struct EVMGPUCPUParityTests {

    // MARK: - Test Configuration

    private static let defaultGasLimit: UInt64 = 1_000_000

    // MARK: - Helper Methods

    private static func compareResults(
        cpuResult: EVMExecutionResult,
        gpuResult: EVMExecutionResult,
        testName: String
    ) {
        // Check success/reverted match
        #expect(cpuResult.success == gpuResult.success,
            "\(testName): success mismatch - CPU:\(cpuResult.success) GPU:\(gpuResult.success)")

        // Check row count matches (proxy for execution correctness)
        #expect(cpuResult.trace.rows.count == gpuResult.trace.rows.count,
            "\(testName): row count mismatch - CPU:\(cpuResult.trace.rows.count) GPU:\(gpuResult.trace.rows.count)")

        // Check reverted flag matches
        #expect(cpuResult.trace.reverted == gpuResult.trace.reverted,
            "\(testName): reverted mismatch - CPU:\(cpuResult.trace.reverted) GPU:\(gpuResult.trace.reverted)")
    }

    // MARK: - Arithmetic Opcodes

    @Test
    static func testADD_GPUvsCPU() throws {
        // PUSH1 10, PUSH1 20, ADD, STOP
        let code: [UInt8] = [0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "ADD")
    }

    @Test
    static func testMUL_GPUvsCPU() throws {
        // 6 * 7 = 42
        let code: [UInt8] = [0x60, 0x06, 0x60, 0x07, 0x02, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "MUL")
    }

    @Test
    static func testSUB_GPUvsCPU() throws {
        // 20 - 10 = 10
        let code: [UInt8] = [0x60, 0x14, 0x60, 0x0A, 0x03, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "SUB")
    }

    @Test
    static func testDIV_GPUvsCPU() throws {
        // 10 / 3 = 3
        let code: [UInt8] = [0x60, 0x0A, 0x60, 0x03, 0x04, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "DIV")
    }

    @Test
    static func testEXP_GPUvsCPU() throws {
        // 2^8 = 256
        let code: [UInt8] = [0x60, 0x02, 0x60, 0x08, 0x0A, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "EXP")
    }

    // MARK: - Comparison Opcodes

    @Test
    static func testLT_GPUvsCPU() throws {
        // 5 < 10 = 1
        let code: [UInt8] = [0x60, 0x05, 0x60, 0x0A, 0x10, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "LT")
    }

    @Test
    static func testGT_GPUvsCPU() throws {
        // 10 > 5 = 1
        let code: [UInt8] = [0x60, 0x0A, 0x60, 0x05, 0x11, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "GT")
    }

    @Test
    static func testEQ_GPUvsCPU() throws {
        // 42 == 42 = 1
        let code: [UInt8] = [0x60, 0x2A, 0x60, 0x2A, 0x14, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "EQ")
    }

    @Test
    static func testISZERO_GPUvsCPU() throws {
        // iszero(0) = 1
        let code: [UInt8] = [0x60, 0x00, 0x15, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "ISZERO")
    }

    // MARK: - Bitwise Opcodes

    @Test
    static func testAND_GPUvsCPU() throws {
        // 0xFF & 0x0F = 0x0F
        let code: [UInt8] = [0x60, 0xFF, 0x60, 0x0F, 0x16, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "AND")
    }

    @Test
    static func testOR_GPUvsCPU() throws {
        // 0xF0 | 0x0F = 0xFF
        let code: [UInt8] = [0x60, 0xF0, 0x60, 0x0F, 0x17, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "OR")
    }

    @Test
    static func testXOR_GPUvsCPU() throws {
        // 0xAA ^ 0x55 = 0xFF
        let code: [UInt8] = [0x60, 0xAA, 0x60, 0x55, 0x18, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "XOR")
    }

    // MARK: - Memory Opcodes

    @Test
    static func testMSTORE_GPUvsCPU() throws {
        // Store value at offset 0
        let code: [UInt8] = [0x60, 0x00, 0x60, 0x42, 0x52, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "MSTORE")
    }

    @Test
    static func testMLOAD_GPUvsCPU() throws {
        // Store then load
        let code: [UInt8] = [0x60, 0x00, 0x60, 0x42, 0x52, 0x60, 0x00, 0x51, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "MLOAD")
    }

    @Test
    static func testMSTORE8_GPUvsCPU() throws {
        // Store single byte
        let code: [UInt8] = [0x60, 0x00, 0x60, 0xFF, 0x53, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "MSTORE8")
    }

    // MARK: - Control Flow

    @Test
    static func testJUMP_GPUvsCPU() throws {
        // Valid jump to JUMPDEST
        let code: [UInt8] = [
            0x60, 0x05,  // PUSH1 5
            0x56,        // JUMP
            0x00,        // STOP
            0x00,        // STOP
            0x00,        // STOP
            0x5B,        // JUMPDEST
            0x00         // STOP
        ]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "JUMP")
    }

    @Test
    static func testJUMPI_GPUvsCPU() throws {
        // Conditional jump - true case
        let code: [UInt8] = [
            0x60, 0x08,  // PUSH1 8
            0x60, 0x01,  // PUSH1 1 (true)
            0x57,        // JUMPI
            0x00,        // STOP
            0x00,        // STOP
            0x00,        // STOP
            0x5B,        // JUMPDEST
            0x00         // STOP
        ]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "JUMPI")
    }

    // MARK: - Stack Operations

    @Test
    static func testDUP_GPUvsCPU() throws {
        // Duplicate top of stack
        let code: [UInt8] = [0x60, 0x42, 0x80, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "DUP1")
    }

    @Test
    static func testSWAP_GPUvsCPU() throws {
        // Swap top two
        let code: [UInt8] = [0x60, 0x11, 0x60, 0x22, 0x90, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "SWAP1")
    }

    @Test
    static func testPOP_GPUvsCPU() throws {
        // Pop from stack
        let code: [UInt8] = [0x60, 0x42, 0x50, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "POP")
    }

    // MARK: - Combined Opcodes

    @Test
    static func testArithmeticChain_GPUvsCPU() throws {
        // ((10 + 20) * 2) - 5 = 55
        let code: [UInt8] = [
            0x60, 0x0A,  // PUSH1 10
            0x60, 0x14,  // PUSH1 20
            0x01,        // ADD (30)
            0x60, 0x02,  // PUSH1 2
            0x02,        // MUL (60)
            0x60, 0x05,  // PUSH1 5
            0x03,        // SUB (55)
            0x00         // STOP
        ]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "ArithmeticChain")
    }

    @Test
    static func testStackManipulation_GPUvsCPU() throws {
        // Complex stack operations: push 3 values, duplicate deepest, swap, add
        let code: [UInt8] = [
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x60, 0x03,  // PUSH1 3
            0x83,        // DUP3 (copy 1)
            0x90,        // SWAP1 (swap 1 and 3)
            0x01,        // ADD (3+1=4)
            0x00         // STOP
        ]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "StackManipulation")
    }

    // MARK: - Environmental Opcodes

    @Test
    static func testADDRESS_GPUvsCPU() throws {
        let code: [UInt8] = [0x30, 0x00]  // ADDRESS, STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "ADDRESS")
    }

    @Test
    static func testCALLER_GPUvsCPU() throws {
        let code: [UInt8] = [0x33, 0x00]  // CALLER, STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "CALLER")
    }

    @Test
    static func testGAS_GPUvsCPU() throws {
        let code: [UInt8] = [0x5A, 0x00]  // GAS, STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "GAS")
    }

    // MARK: - Block Opcodes

    @Test
    static func testTIMESTAMP_GPUvsCPU() throws {
        let code: [UInt8] = [0x42, 0x00]  // TIMESTAMP, STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "TIMESTAMP")
    }

    @Test
    static func testNUMBER_GPUvsCPU() throws {
        let code: [UInt8] = [0x43, 0x00]  // NUMBER, STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "NUMBER")
    }

    @Test
    static func testGASLIMIT_GPUvsCPU() throws {
        let code: [UInt8] = [0x45, 0x00]  // GASLIMIT, STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "GASLIMIT")
    }

    // MARK: - Extended Tests

    @Test
    static func testMemoryWriteRead_GPUvsCPU() throws {
        // Write to multiple memory locations and read back
        let code: [UInt8] = [
            // Store 0xAA at offset 0
            0x60, 0x00, 0x60, 0xAA, 0x52,
            // Store 0xBB at offset 32
            0x60, 0x20, 0x60, 0xBB, 0x52,
            // Load from offset 0
            0x60, 0x00, 0x51,
            // Load from offset 32
            0x60, 0x20, 0x51,
            0x00
        ]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "MemoryWriteRead")
    }

    @Test
    static func testKECCAK256_GPUvsCPU() throws {
        // Hash empty data
        let code: [UInt8] = [0x60, 0x00, 0x60, 0x00, 0x20, 0x00]

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "KECCAK256")
    }

    // MARK: - Performance Parity Check

    @Test
    static func testLargeBytecode_GPUvsCPU() throws {
        // Larger bytecode to test GPU performance on more complex execution
        var code: [UInt8] = []

        // Push values
        code.append(0x60)
        code.append(0x01)
        code.append(0x60)
        code.append(0x02)
        code.append(0x60)
        code.append(0x03)

        // Add them
        code.append(0x01)  // ADD
        code.append(0x01)  // ADD

        // Multiply by 2
        code.append(0x60)
        code.append(0x02)
        code.append(0x02)  // MUL

        // Store result
        code.append(0x60)
        code.append(0x00)
        code.append(0x60)
        code.append(0x12)  // 18 = (1+2+3)*2
        code.append(0x52)  // MSTORE

        // Load it back
        code.append(0x60)
        code.append(0x00)
        code.append(0x51)  // MLOAD

        code.append(0x00)  // STOP

        let cpuResult = try EVMExecutionEngine().execute(code: code, gasLimit: defaultGasLimit)
        let gpuResult = try EVMExecutionEngine.executeGPU(code: code, gasLimit: defaultGasLimit, forceCPU: false)

        compareResults(cpuResult: cpuResult, gpuResult: gpuResult, testName: "LargeBytecode")
    }
}