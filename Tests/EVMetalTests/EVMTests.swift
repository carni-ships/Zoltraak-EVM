import XCTest
import zkMetal
@testable import EVMetal

final class EVMTests: XCTestCase {

    // MARK: - M31Word Tests

    func testM31WordCreation() {
        let word = M31Word(lo: 42)
        XCTAssertFalse(word.isZero)
        XCTAssertEqual(word.limbs.count, 9)
    }

    func testM31WordAddition() {
        let a = M31Word(lo: 100)
        let b = M31Word(lo: 50)
        let (result, overflow) = a.add(b)

        XCTAssertEqual(result.low32, 150)
        XCTAssertEqual(overflow.v, 0)
    }

    func testM31WordSubtraction() {
        let a = M31Word(lo: 100)
        let b = M31Word(lo: 50)
        let (result, borrow) = a.sub(b)

        XCTAssertEqual(result.low32, 50)
        XCTAssertEqual(borrow.v, 0)
    }

    func testM31WordEquality() {
        let a = M31Word(lo: 42)
        let b = M31Word(lo: 42)
        let c = M31Word(lo: 43)

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testM31WordToBytes() {
        let word = M31Word(lo: 0xDEADBEEF)
        let bytes = word.toBytes()

        XCTAssertEqual(bytes.count, 32)
    }

    func testM31WordHexString() {
        let word = M31Word(lo: 0xDEADBEEF)
        let hex = word.toHexString()

        XCTAssertTrue(hex.hasPrefix("0x"))
    }

    // MARK: - EVMOpcode Tests

    func testOpcodeProperties() {
        let add = EVMOpcode.ADD
        XCTAssertEqual(add.properties.name, "ADD")
        XCTAssertEqual(add.properties.gas, 3)
        XCTAssertEqual(add.properties.stackHeightChange, 1)
    }

    func testPushOpcode() {
        let push1 = EVMOpcode.PUSH1
        XCTAssertEqual(push1.pushBytes, 1)

        let push32 = EVMOpcode.PUSH32
        XCTAssertEqual(push32.pushBytes, 32)

        let add = EVMOpcode.ADD
        XCTAssertNil(add.pushBytes)
    }

    func testDupOpcode() {
        let dup1 = EVMOpcode.DUP1
        XCTAssertEqual(dup1.dupPosition, 1)

        let dup16 = EVMOpcode.DUP16
        XCTAssertEqual(dup16.dupPosition, 16)

        let add = EVMOpcode.ADD
        XCTAssertNil(add.dupPosition)
    }

    func testSwapOpcode() {
        let swap1 = EVMOpcode.SWAP1
        XCTAssertEqual(swap1.swapPosition, 1)

        let swap16 = EVMOpcode.SWAP16
        XCTAssertEqual(swap16.swapPosition, 16)
    }

    func testMVPOpcodes() {
        // Basic ops should be in MVP
        XCTAssertTrue(EVMOpcode.ADD.isMVP)
        XCTAssertTrue(EVMOpcode.STOP.isMVP)
        XCTAssertTrue(EVMOpcode.JUMP.isMVP)
        XCTAssertTrue(EVMOpcode.JUMPI.isMVP)
        XCTAssertTrue(EVMOpcode.PUSH1.isMVP)
    }

    // MARK: - EVMStack Tests

    func testStackPushPop() {
        var stack = EVMStack()
        stack.push(M31Word(lo: 42))
        stack.push(M31Word(lo: 99))

        XCTAssertEqual(stack.stackHeight, 2)

        let val = stack.pop()
        XCTAssertEqual(val.low32, 99)

        let val2 = stack.pop()
        XCTAssertEqual(val2.low32, 42)

        XCTAssertEqual(stack.stackHeight, 0)
    }

    func testStackPeek() {
        var stack = EVMStack()
        stack.push(M31Word(lo: 1))
        stack.push(M31Word(lo: 2))
        stack.push(M31Word(lo: 3))

        XCTAssertEqual(stack.peek(depth: 1).low32, 3)
        XCTAssertEqual(stack.peek(depth: 2).low32, 2)
        XCTAssertEqual(stack.peek(depth: 3).low32, 1)
    }

    func testStackDup() {
        var stack = EVMStack()
        stack.push(M31Word(lo: 42))
        stack.push(M31Word(lo: 99))
        stack.dup(position: 1)

        XCTAssertEqual(stack.stackHeight, 3)
        XCTAssertEqual(stack.peek(depth: 1).low32, 99)
    }

    func testStackSwap() {
        var stack = EVMStack()
        stack.push(M31Word(lo: 1))
        stack.push(M31Word(lo: 2))

        stack.Swap(position: 1)

        XCTAssertEqual(stack.peek(depth: 1).low32, 1)
        XCTAssertEqual(stack.peek(depth: 2).low32, 2)
    }

    func testStackUnderflow() {
        var stack = EVMStack()
        XCTAssertEqual(stack.stackHeight, 0)

        // Peek should fail on empty stack
        XCTAssertEqual(stack.peek(depth: 1).low32, 0)
    }

    // MARK: - EVMMemory Tests

    func testMemoryExpand() {
        var memory = EVMMemory()
        memory.expand(offset: 0, size: 64)

        XCTAssertEqual(memory.size, 64)
    }

    func testMemoryWordStoreLoad() {
        var memory = EVMMemory()
        let value = M31Word(lo: 0xDEADBEEF)

        memory.storeWord(offset: 0, value: value)
        let loaded = memory.loadWord(offset: 0)

        XCTAssertEqual(loaded.low32, 0xDEADBEEF)
    }

    func testMemoryByteStoreLoad() {
        var memory = EVMMemory()

        memory.storeByte(offset: 0, value: 0x42)
        let loaded = memory.loadByte(offset: 0)

        XCTAssertEqual(loaded, 0x42)
    }

    // MARK: - EVMState Tests

    func testEVMStateCreation() {
        let state = EVMState()

        XCTAssertEqual(state.pc, 0)
        XCTAssertTrue(state.running)
        XCTAssertFalse(state.reverted)
        XCTAssertEqual(state.stack.stackHeight, 0)
    }

    func testEVMStateChargeGas() {
        var state = EVMState()
        state.gas = 100

        let success = state.chargeGas(50)
        XCTAssertTrue(success)
        XCTAssertEqual(state.gas, 50)

        let success2 = state.chargeGas(100)
        XCTAssertFalse(success2)
        XCTAssertTrue(state.reverted)
    }

    // MARK: - EVMExecutionEngine Tests

    func testSimpleExecution() throws {
        // Simple STOP opcode
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: [0x00])

        XCTAssertFalse(result.trace.reverted)
        XCTAssertEqual(result.trace.rows.count, 1)
        XCTAssertEqual(result.trace.rows[0].opcode, 0x00)
    }

    func testPushExecution() throws {
        // PUSH1 0x42 followed by STOP
        let code: [UInt8] = [0x60, 0x42, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        XCTAssertFalse(result.trace.reverted)
        // Should have PUSH1 + STOP = 2 trace rows
        XCTAssertEqual(result.trace.rows.count, 2)
        XCTAssertEqual(result.trace.rows[0].opcode, 0x60)  // PUSH1
    }

    func testArithmeticExecution() throws {
        // PUSH1 0x0A (10), PUSH1 0x14 (20), ADD, STOP
        let code: [UInt8] = [0x60, 0x0A, 0x60, 0x14, 0x01, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        XCTAssertFalse(result.trace.reverted)
        XCTAssertEqual(result.trace.rows.count, 4)
    }

    func testStackOperations() throws {
        // PUSH1 0x42, PUSH1 0x99, DUP1, STOP
        let code: [UInt8] = [0x60, 0x42, 0x60, 0x99, 0x80, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 1000)

        XCTAssertFalse(result.trace.reverted)
    }

    func testMemoryOperations() throws {
        // PUSH1 0x00, PUSH1 0x42, MSTORE, STOP
        let code: [UInt8] = [0x60, 0x00, 0x60, 0x42, 0x52, 0x00]
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: code, gasLimit: 10000)

        XCTAssertFalse(result.trace.reverted)
        XCTAssertEqual(result.memoryTrace.count, 1)  // One memory write
    }

    func testInvalidOpcode() {
        let code: [UInt8] = [0xFF]  // Invalid opcode
        let engine = EVMExecutionEngine()

        XCTAssertThrowsError(try engine.execute(code: code, gasLimit: 1000)) { error in
            XCTAssertTrue(error is EVMExecutionError)
        }
    }

    // MARK: - EVMAIR Tests

    func testEVMAIRCreation() {
        let air = EVMAIR(logTraceLength: 10)

        XCTAssertEqual(air.logTraceLength, 10)
        XCTAssertEqual(air.numColumns, 180)
        XCTAssertEqual(air.boundaryConstraints.count, 7)
    }

    func testEVMAIRFromExecution() throws {
        let engine = EVMExecutionEngine()
        let result = try engine.execute(code: [0x00], gasLimit: 1000)

        let air = EVMAIR.fromExecution(result)

        XCTAssertEqual(air.logTraceLength, result.trace.count.nextPowerOfTwo().bitWidth - 1)
    }

    func testEVMAIRConstraintEvaluation() throws {
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

        XCTAssertEqual(constraints.count, air.numConstraints)
    }

    // MARK: - Performance Tests

    func testM31WordPerformance() {
        measure {
            var stack = EVMStack()
            for i in 0..<1000 {
                stack.push(M31Word(lo: UInt128(i)))
            }
            for _ in 0..<1000 {
                _ = stack.pop()
            }
        }
    }

    func testMemoryExpandPerformance() {
        measure {
            var memory = EVMMemory()
            for i in stride(from: 0, to: 10000, by: 32) {
                memory.expand(offset: i, size: 32)
            }
        }
    }
}

// MARK: - Helper Extensions

extension EVMExecutionError: Equatable {
    public static func == (lhs: EVMExecutionError, rhs: EVMExecutionError) -> Bool {
        switch (lhs, rhs) {
        case (.outOfGas, .outOfGas): return true
        case (.stackUnderflow, .stackUnderflow): return true
        case (.stackOverflow, .stackOverflow): return true
        case (.revert(let a), .revert(let b)): return a == b
        default: return false
        }
    }
}
