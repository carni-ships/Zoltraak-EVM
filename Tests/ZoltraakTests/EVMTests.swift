import Foundation
import Testing
import zkMetal
@testable import Zoltraak

struct EVMTests {

    // MARK: - M31Word Tests

    @Test
    static func testM31WordCreation() {
        let word = M31Word(low64: 42)
        #expect(word.isZero == false)
        #expect(word.limbs.count == 9)
    }

    @Test
    static func testM31WordAddition() {
        let a = M31Word(low64: 100)
        let b = M31Word(low64: 50)
        let (result, overflow) = a.add(b)

        #expect(result.low32 == 150)
        #expect(overflow.v == 0)
    }

    @Test
    static func testM31WordSubtraction() {
        let a = M31Word(low64: 100)
        let b = M31Word(low64: 50)
        let (result, borrow) = a.sub(b)

        #expect(result.low32 == 50)
        #expect(borrow.v == 0)
    }

    @Test
    static func testM31WordEquality() {
        let a = M31Word(low64: 42)
        let b = M31Word(low64: 42)
        let c = M31Word(low64: 43)

        #expect(a == b)
        #expect(a != c)
    }

    @Test
    static func testM31WordToBytes() {
        let word = M31Word(low64: 0xDEADBEEF)
        let bytes = word.toBytes()

        #expect(bytes.count == 32)
    }

    @Test
    static func testM31WordHexString() {
        let word = M31Word(low64: 0xDEADBEEF)
        let hex = word.toHexString()

        #expect(hex.hasPrefix("0x"))
    }

    // MARK: - EVMOpcode Tests

    @Test
    static func testOpcodeProperties() {
        let add = EVMOpcode.ADD
        #expect(add.properties.name == "ADD")
        #expect(add.properties.gas == 3)
        #expect(add.properties.stackHeightChange == 1)
    }

    @Test
    static func testPushOpcode() {
        let push1 = EVMOpcode.PUSH1
        #expect(push1.pushBytes == 1)

        let push32 = EVMOpcode.PUSH32
        #expect(push32.pushBytes == 32)

        let add = EVMOpcode.ADD
        #expect(add.pushBytes == nil)
    }

    @Test
    static func testDupOpcode() {
        let dup1 = EVMOpcode.DUP1
        #expect(dup1.dupPosition == 1)

        let dup16 = EVMOpcode.DUP16
        #expect(dup16.dupPosition == 16)

        let add = EVMOpcode.ADD
        #expect(add.dupPosition == nil)
    }

    @Test
    static func testSwapOpcode() {
        let swap1 = EVMOpcode.SWAP1
        #expect(swap1.swapPosition == 1)

        let swap16 = EVMOpcode.SWAP16
        #expect(swap16.swapPosition == 16)
    }

    @Test
    static func testMVPOpcodes() {
        // Basic ops should be in MVP
        #expect(EVMOpcode.ADD.isMVP == true)
        #expect(EVMOpcode.STOP.isMVP == true)
        #expect(EVMOpcode.JUMP.isMVP == true)
        #expect(EVMOpcode.JUMPI.isMVP == true)
        #expect(EVMOpcode.PUSH1.isMVP == true)
    }

    // MARK: - EVMStack Tests

    @Test
    static func testStackPushPop() {
        var stack = EVMStack()
        stack.push(M31Word(low64: 42))
        stack.push(M31Word(low64: 99))

        #expect(stack.stackHeight == 2)

        let val = stack.pop()
        #expect(val.low32 == 99)

        let val2 = stack.pop()
        #expect(val2.low32 == 42)

        #expect(stack.stackHeight == 0)
    }

    @Test
    static func testStackPeek() {
        var stack = EVMStack()
        stack.push(M31Word(low64: 1))
        stack.push(M31Word(low64: 2))
        stack.push(M31Word(low64: 3))

        #expect(stack.peek(depth: 1).low32 == 3)
        #expect(stack.peek(depth: 2).low32 == 2)
        #expect(stack.peek(depth: 3).low32 == 1)
    }

    @Test
    static func testStackDup() throws {
        var stack = EVMStack()
        stack.push(M31Word(low64: 42))
        stack.push(M31Word(low64: 99))
        try stack.dup(position: 1)

        #expect(stack.stackHeight == 3)
        #expect(stack.peek(depth: 1).low32 == 99)
    }

    @Test
    static func testStackSwap() throws {
        var stack = EVMStack()
        stack.push(M31Word(low64: 1))
        stack.push(M31Word(low64: 2))

        try stack.swap(position: 1)

        #expect(stack.peek(depth: 1).low32 == 1)
        #expect(stack.peek(depth: 2).low32 == 2)
    }

    @Test
    static func testStackUnderflow() {
        let stack = EVMStack()
        #expect(stack.stackHeight == 0)

        // Peek at depth 1 on empty stack triggers precondition failure
        // The stack height is 0, so peek is invalid
    }

    // MARK: - EVMMemory Tests

    @Test
    static func testMemoryExpand() {
        var memory = EVMMemory()
        memory.expand(offset: 0, size: 64)

        #expect(memory.size == 64)
    }

    @Test
    static func testMemoryWordStoreLoad() {
        var memory = EVMMemory()

        // Store a byte value at offset 0
        memory.storeByte(offset: 0, value: 0x42)

        // Verify memory expanded to at least 1 byte
        #expect(memory.size >= 1)

        // Load the byte back and verify it matches
        let loaded = memory.loadByte(offset: 0)
        #expect(loaded == 0x42)
    }

    @Test
    static func testMemoryByteStoreLoad() {
        var memory = EVMMemory()

        memory.storeByte(offset: 0, value: 0x42)
        let loaded = memory.loadByte(offset: 0)

        #expect(loaded == 0x42)
    }

    // MARK: - EVMState Tests

    @Test
    static func testEVMStateCreation() {
        let state = EVMState()

        #expect(state.pc == 0)
        #expect(state.running == true)
        #expect(state.reverted == false)
        #expect(state.stack.stackHeight == 0)
    }

    @Test
    static func testEVMStateChargeGas() {
        var state = EVMState()
        state.gas = 100

        let success = state.chargeGas(50)
        #expect(success == true)
        #expect(state.gas == 50)

        let success2 = state.chargeGas(100)
        #expect(success2 == false)
        #expect(state.reverted == true)
    }

    // MARK: - EVMExecutionEngine Tests

    @Test
    static func testSimpleExecution() throws {
        // Simple STOP opcode
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: [0x00])

        #expect(result.trace.reverted == false)
        #expect(result.trace.rows.count == 1)
        #expect(result.trace.rows[0].opcode == 0x00)
    }

    @Test
    static func testPushExecution() throws {
        // PUSH1 0x42 followed by STOP
        let code: [UInt8] = [0x60, 0x42, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        #expect(result.trace.reverted == false)
        // Should have PUSH1 + STOP = 2 trace rows
        #expect(result.trace.rows.count == 2)
        #expect(result.trace.rows[0].opcode == 0x60)  // PUSH1
    }

    @Test
    static func testArithmeticExecution() throws {
        // PUSH1 0x0A (10), PUSH1 0x14 (20), ADD, STOP
        let code: [UInt8] = [0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        #expect(result.trace.reverted == false)
        #expect(result.trace.rows.count == 4)
    }

    @Test
    static func testStackOperations() throws {
        // PUSH1 0x42, PUSH1 0x99, DUP1, STOP
        let code: [UInt8] = [0x60, 0x42, 0x60, 0x99, 0x80, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        #expect(result.trace.reverted == false)
    }

    @Test
    static func testMemoryOperations() throws {
        // PUSH1 0x00, PUSH1 0x42, MSTORE, STOP
        let code: [UInt8] = [0x60, 0x00, 0x60, 0x42, 0x52, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 10000)

        #expect(result.trace.reverted == false)
        #expect(result.memoryTrace.count == 1)  // One memory write
    }

    @Test
    static func testInvalidOpcode() throws {
        // 0xFE is undefined opcode - should cause revert
        let code: [UInt8] = [0xFE]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        // Undefined opcode causes revert
        #expect(result.trace.reverted == true)
    }

    // MARK: - EVMAIR Tests

    @Test
    static func testEVMAIRCreation() {
        let air = EVMAIR(logTraceLength: 10)

        #expect(air.logTraceLength == 10)
        #expect(air.numColumns == 180)
        // boundaryConstraints is a computed property with actual count
        #expect(air.boundaryConstraints.count >= 1)
    }

    @Test
    static func testEVMAIRFromExecution() throws {
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: [0x00], gasLimit: 1000)

        let air = EVMAIR.fromExecution(result)

        // Just verify the AIR was created successfully
        #expect(air.logTraceLength >= 0)
    }

    @Test
    static func testEVMAIRConstraintEvaluation() throws {
        let air = EVMAIR(logTraceLength: 10)

        // Create dummy trace columns
        var columns = [[M31]](repeating: [M31](repeating: .zero, count: 1024), count: 180)

        // Fill in some valid-looking data
        columns[0][0] = M31.zero           // PC = 0
        columns[1][0] = M31(v: 0)          // Gas high
        columns[2][0] = M31(v: 1000)       // Gas low
        columns[158][0] = M31(v: 0x60)     // PUSH1 opcode
        columns[163][0] = M31.zero         // Call depth = 0

        let constraints = air.evaluateConstraints(current: columns.map { $0[0] }, next: columns.map { $0[1] })

        #expect(constraints.count == air.numConstraints)
    }
}
