import Foundation
import zkMetal

/// All EVM opcodes organized by category.
/// Gas costs follow Ethereum Yellow Paper (EIP-150 revision).
/// Note: Precompiled contracts (0x01-0x09) are NOT opcodes - they're called via CALL.
public enum EVMOpcode: UInt8, CaseIterable, Sendable {
    // MARK: - Stop and Arithmetic (0x00-0x0B)

    case STOP          = 0x00  // Halts execution, gas: 0
    case ADD           = 0x01  // Addition, gas: 3
    case MUL           = 0x02  // Multiplication, gas: 5
    case SUB           = 0x03  // Subtraction, gas: 3
    case DIV           = 0x04  // Integer division, gas: 5
    case SDIV          = 0x05  // Signed integer division, gas: 5
    case MOD           = 0x06  // Modulo, gas: 5
    case SMOD          = 0x07  // Signed modulo, gas: 5
    case ADDMOD        = 0x08  // Modular addition, gas: 8
    case MULMOD        = 0x09  // Modular multiplication, gas: 8
    case EXP           = 0x0A  // Exponential, gas: 10 + 50*exp_byte
    case SIGNEXTEND     = 0x0B  // Sign extend, gas: 5

    // MARK: - Comparison & Bitwise (0x10-0x1D)

    case LT            = 0x10  // Less than, gas: 3
    case GT            = 0x11  // Greater than, gas: 3
    case SLT           = 0x12  // Signed less than, gas: 3
    case SGT           = 0x13  // Signed greater than, gas: 3
    case EQ            = 0x14  // Equality, gas: 3
    case ISZERO        = 0x15  // Is zero, gas: 3
    case AND           = 0x16  // Bitwise AND, gas: 3
    case OR            = 0x17  // Bitwise OR, gas: 3
    case XOR           = 0x18  // Bitwise XOR, gas: 3
    case NOT           = 0x19  // Bitwise NOT, gas: 3
    case BYTE           = 0x1A  // Extract byte, gas: 3
    case SHL           = 0x1B  // Shift left, gas: 3
    case SHR           = 0x1C  // Shift right, gas: 3
    case SAR           = 0x1D  // Arithmetic shift right, gas: 3

    // MARK: - SHA3 (0x20)

    case KECCAK256     = 0x20  // Keccak-256 hash, gas: 30 + 6*words

    // MARK: - Environmental Information (0x30-0x3F)

    case ADDRESS       = 0x30  // Get address of executing contract, gas: 2
    case BALANCE       = 0x31  // Get balance, gas: 2600 (cold) / 100 (warm)
    case ORIGIN        = 0x32  // Get tx origin, gas: 2
    case CALLER        = 0x33  // Get caller, gas: 2
    case CALLVALUE     = 0x34  // Get call value, gas: 2
    case CALLDATALOAD  = 0x35  // Get calldata, gas: 3
    case CALLDATASIZE  = 0x36  // Get calldata size, gas: 2
    case CALLDATACOPY  = 0x37  // Copy calldata, gas: 3 + 3*words
    case CODESIZE      = 0x38  // Get code size, gas: 2
    case CODECOPY       = 0x39  // Copy code, gas: 3 + 3*words
    case GASPRICE       = 0x3A  // Get gas price, gas: 2
    case EXTCODESIZE    = 0x3B  // Get external code size, gas: 2600 (cold) / 100 (warm)
    case EXTCODECOPY    = 0x3C  // Copy external code, gas: 2600 + 3*words (cold)
    case RETURNDATASIZE = 0x3D  // Get returndata size, gas: 2
    case RETURNDATACOPY = 0x3E  // Copy returndata, gas: 3 + 3*words
    case EXTCODEHASH    = 0x3F  // Get extcodehash, gas: 2600 (cold) / 100 (warm)

    // MARK: - Block Operations (0x40-0x48)

    case BLOCKHASH     = 0x40  // Get block hash, gas: 20
    case COINBASE      = 0x41  // Get block coinbase, gas: 2
    case TIMESTAMP     = 0x42  // Get block timestamp, gas: 2
    case NUMBER        = 0x43  // Get block number, gas: 2
    case PREVRANDAO    = 0x44  // Get block prevrandao, gas: 2
    case GASLIMIT      = 0x45  // Get block gas limit, gas: 2
    case CHAINID       = 0x46  // Get chain ID, gas: 2
    case SELFBALANCE   = 0x47  // Get self balance, gas: 5
    case BASEFEE       = 0x48  // Get block base fee, gas: 2

    // MARK: - Memory Operations (0x50-0x5A)

    case POP           = 0x50  // Pop from stack, gas: 2
    case MLOAD         = 0x51  // Load from memory, gas: 3
    case MSTORE        = 0x52  // Store to memory, gas: 3
    case MSTORE8       = 0x53  // Store byte to memory, gas: 3
    case SLOAD         = 0x54  // Load from storage, gas: 2100 (cold) / 100 (warm)
    case SSTORE        = 0x55  // Store to storage, gas: dynamic
    case JUMP          = 0x56  // Conditional jump, gas: 8
    case JUMPI         = 0x57  // Conditional jump if true, gas: 10
    case JUMPDEST      = 0x5B  // Valid jump destination, gas: 1
    case PC            = 0x58  // Get program counter, gas: 2
    case MSIZE         = 0x59  // Get memory size, gas: 2
    case GAS           = 0x5A  // Get available gas, gas: 2
    case PUSH0         = 0x5F  // Push 0 constant (EIP-3855), gas: 2

    // MARK: - Push Operations (0x60-0x7F)

    case PUSH1         = 0x60  // Push 1 byte, gas: 3
    case PUSH2         = 0x61  // Push 2 bytes, gas: 3
    case PUSH3         = 0x62
    case PUSH4         = 0x63
    case PUSH5         = 0x64
    case PUSH6         = 0x65
    case PUSH7         = 0x66
    case PUSH8         = 0x67
    case PUSH9         = 0x68
    case PUSH10        = 0x69
    case PUSH11        = 0x6A
    case PUSH12        = 0x6B
    case PUSH13        = 0x6C
    case PUSH14        = 0x6D
    case PUSH15        = 0x6E
    case PUSH16        = 0x6F
    case PUSH17        = 0x70
    case PUSH18        = 0x71
    case PUSH19        = 0x72
    case PUSH20        = 0x73
    case PUSH21        = 0x74
    case PUSH22        = 0x75
    case PUSH23        = 0x76
    case PUSH24        = 0x77
    case PUSH25        = 0x78
    case PUSH26        = 0x79
    case PUSH27        = 0x7A
    case PUSH28        = 0x7B
    case PUSH29        = 0x7C
    case PUSH30        = 0x7D
    case PUSH31        = 0x7E
    case PUSH32        = 0x7F  // Push 32 bytes, gas: 3

    // MARK: - Duplicate Operations (0x80-0x8F)

    case DUP1           = 0x80  // Duplicate 1st stack item, gas: 3
    case DUP2           = 0x81
    case DUP3           = 0x82
    case DUP4           = 0x83
    case DUP5           = 0x84
    case DUP6           = 0x85
    case DUP7           = 0x86
    case DUP8           = 0x87
    case DUP9           = 0x88
    case DUP10          = 0x89
    case DUP11          = 0x8A
    case DUP12          = 0x8B
    case DUP13          = 0x8C
    case DUP14          = 0x8D
    case DUP15          = 0x8E
    case DUP16          = 0x8F  // Duplicate 16th stack item, gas: 3

    // MARK: - Exchange Operations (0x90-0x9F)

    case SWAP1          = 0x90  // Exchange 1st and 2nd stack items, gas: 3
    case SWAP2          = 0x91
    case SWAP3          = 0x92
    case SWAP4          = 0x93
    case SWAP5          = 0x94
    case SWAP6          = 0x95
    case SWAP7          = 0x96
    case SWAP8          = 0x97
    case SWAP9          = 0x98
    case SWAP10         = 0x99
    case SWAP11         = 0x9A
    case SWAP12         = 0x9B
    case SWAP13         = 0x9C
    case SWAP14         = 0x9D
    case SWAP15         = 0x9E
    case SWAP16         = 0x9F  // Exchange 1st and 17th stack items, gas: 3

    // MARK: - Log Operations (0xA0-0xA4)

    case LOG0           = 0xA0  // Emit log, gas: 375 + 8*topics
    case LOG1           = 0xA1
    case LOG2           = 0xA2
    case LOG3           = 0xA3
    case LOG4           = 0xA4

    // MARK: - System Operations (0xF0-0xFF)

    case CREATE         = 0xF0  // Create new contract, gas: 32000 + gas_code_bytes
    case CALL           = 0xF1  // Call contract, gas: 2600 + value_transfer + gas
    case CALLCODE       = 0xF2  // Call with code of another contract, gas: 2600 + ...
    case RETURN         = 0xF3  // Halt and return, gas: 0
    case DELEGATECALL   = 0xF4  // Delegate call, gas: 2600 + ...
    case CREATE2        = 0xF5  // Create2, gas: 32000 + 200*deploy_code_words + gas_code_bytes
    case STATICCALL     = 0xFA  // Static call, gas: 2600 + gas
    case REVERT         = 0xFD  // Halt and revert, gas: 0
    case SELFDESTRUCT   = 0xFF  // Self-destruct, gas: 5000 + 25000 if selfdestruct to new account

    // MARK: - EOF (Ethereum Object Format) - EIP-3540 (0xE0-0xEF)

    case RJUMP          = 0xE0  // Relative jump (EIP-3540)
    case RJUMPI         = 0xE1  // Conditional relative jump (EIP-3540)
    case RJUMPV        = 0xE2  // Relative jump with variable offset
    case CALLF         = 0xE3  // Call function (EIP-3540)
    case RETF          = 0xE4  // Return from function (EIP-3540)
    case JUMPF         = 0xE5  // Jump to function (EIP-3540)
    case DUPN          = 0xE8  // Duplicate Nth stack item
    case SWAPN         = 0xE9  // Exchange 1st and Nth stack items
    case SLOADBYTES    = 0xE6  // SLOAD with bytes
    case SSTOREBYTES   = 0xE7  // SSTORE with bytes
    case MSTORESIZE    = 0xEA  // Resize memory
    case TRACKSTORAGE  = 0xEB  // Track storage slot
    case COPYLOG       = 0xEC  // Copy log
}

// MARK: - Opcode Categories

public enum EVMOpcodeCategory: Sendable {
    case stop
    case arithmetic
    case comparison
    case bitwise
    case sha3
    case environmental
    case block
    case memory
    case controlFlow
    case push
    case dup
    case swap
    case log
    case system
    case precompile
    case eof
}

// MARK: - Opcode Properties

public struct OpcodeProperties: Sendable {
    public let name: String
    public let gas: UInt64
    public let stackHeightChange: Int
    public let category: EVMOpcodeCategory
    public let isMemoryOp: Bool
    public let isStorageOp: Bool
    public let isControlFlow: Bool
    public let isPrecompileCall: Bool

    public init(
        name: String,
        gas: UInt64,
        stackHeightChange: Int,
        category: EVMOpcodeCategory,
        isMemoryOp: Bool = false,
        isStorageOp: Bool = false,
        isControlFlow: Bool = false,
        isPrecompileCall: Bool = false
    ) {
        self.name = name
        self.gas = gas
        self.stackHeightChange = stackHeightChange
        self.category = category
        self.isMemoryOp = isMemoryOp
        self.isStorageOp = isStorageOp
        self.isControlFlow = isControlFlow
        self.isPrecompileCall = isPrecompileCall
    }
}

// MARK: - Opcode Property Lookup

extension EVMOpcode {
    public var properties: OpcodeProperties {
        switch self {
        case .STOP:          return OpcodeProperties(name: "STOP", gas: 0, stackHeightChange: 0, category: .stop)
        case .ADD:           return OpcodeProperties(name: "ADD", gas: 3, stackHeightChange: 1, category: .arithmetic)
        case .MUL:           return OpcodeProperties(name: "MUL", gas: 5, stackHeightChange: 1, category: .arithmetic)
        case .SUB:           return OpcodeProperties(name: "SUB", gas: 3, stackHeightChange: 1, category: .arithmetic)
        case .DIV:           return OpcodeProperties(name: "DIV", gas: 5, stackHeightChange: 1, category: .arithmetic)
        case .SDIV:          return OpcodeProperties(name: "SDIV", gas: 5, stackHeightChange: 1, category: .arithmetic)
        case .MOD:           return OpcodeProperties(name: "MOD", gas: 5, stackHeightChange: 1, category: .arithmetic)
        case .SMOD:          return OpcodeProperties(name: "SMOD", gas: 5, stackHeightChange: 1, category: .arithmetic)
        case .ADDMOD:        return OpcodeProperties(name: "ADDMOD", gas: 8, stackHeightChange: 1, category: .arithmetic)
        case .MULMOD:        return OpcodeProperties(name: "MULMOD", gas: 8, stackHeightChange: 1, category: .arithmetic)
        case .EXP:           return OpcodeProperties(name: "EXP", gas: 10, stackHeightChange: 1, category: .arithmetic)
        case .SIGNEXTEND:    return OpcodeProperties(name: "SIGNEXTEND", gas: 5, stackHeightChange: 1, category: .bitwise)

        case .LT:            return OpcodeProperties(name: "LT", gas: 3, stackHeightChange: 1, category: .comparison)
        case .GT:            return OpcodeProperties(name: "GT", gas: 3, stackHeightChange: 1, category: .comparison)
        case .SLT:           return OpcodeProperties(name: "SLT", gas: 3, stackHeightChange: 1, category: .comparison)
        case .SGT:           return OpcodeProperties(name: "SGT", gas: 3, stackHeightChange: 1, category: .comparison)
        case .EQ:            return OpcodeProperties(name: "EQ", gas: 3, stackHeightChange: 1, category: .comparison)
        case .ISZERO:        return OpcodeProperties(name: "ISZERO", gas: 3, stackHeightChange: 1, category: .comparison)

        case .AND:           return OpcodeProperties(name: "AND", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .OR:            return OpcodeProperties(name: "OR", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .XOR:           return OpcodeProperties(name: "XOR", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .NOT:           return OpcodeProperties(name: "NOT", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .BYTE:          return OpcodeProperties(name: "BYTE", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .SHL:           return OpcodeProperties(name: "SHL", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .SHR:           return OpcodeProperties(name: "SHR", gas: 3, stackHeightChange: 1, category: .bitwise)
        case .SAR:           return OpcodeProperties(name: "SAR", gas: 3, stackHeightChange: 1, category: .bitwise)

        case .KECCAK256:     return OpcodeProperties(name: "KECCAK256", gas: 30, stackHeightChange: 1, category: .sha3, isMemoryOp: true)

        case .ADDRESS:       return OpcodeProperties(name: "ADDRESS", gas: 2, stackHeightChange: 1, category: .environmental)
        case .BALANCE:      return OpcodeProperties(name: "BALANCE", gas: 2600, stackHeightChange: 1, category: .environmental)
        case .ORIGIN:       return OpcodeProperties(name: "ORIGIN", gas: 2, stackHeightChange: 1, category: .environmental)
        case .CALLER:        return OpcodeProperties(name: "CALLER", gas: 2, stackHeightChange: 1, category: .environmental)
        case .CALLVALUE:     return OpcodeProperties(name: "CALLVALUE", gas: 2, stackHeightChange: 1, category: .environmental)
        case .CALLDATALOAD: return OpcodeProperties(name: "CALLDATALOAD", gas: 3, stackHeightChange: 1, category: .environmental)
        case .CALLDATASIZE: return OpcodeProperties(name: "CALLDATASIZE", gas: 2, stackHeightChange: 1, category: .environmental)
        case .CALLDATACOPY: return OpcodeProperties(name: "CALLDATACOPY", gas: 3, stackHeightChange: 0, category: .environmental, isMemoryOp: true)
        case .CODESIZE:      return OpcodeProperties(name: "CODESIZE", gas: 2, stackHeightChange: 1, category: .environmental)
        case .CODECOPY:      return OpcodeProperties(name: "CODECOPY", gas: 3, stackHeightChange: 0, category: .environmental, isMemoryOp: true)
        case .GASPRICE:      return OpcodeProperties(name: "GASPRICE", gas: 2, stackHeightChange: 1, category: .environmental)
        case .EXTCODESIZE:   return OpcodeProperties(name: "EXTCODESIZE", gas: 2600, stackHeightChange: 1, category: .environmental)
        case .EXTCODECOPY:   return OpcodeProperties(name: "EXTCODECOPY", gas: 2600, stackHeightChange: 0, category: .environmental, isMemoryOp: true)
        case .RETURNDATASIZE: return OpcodeProperties(name: "RETURNDATASIZE", gas: 2, stackHeightChange: 1, category: .environmental)
        case .RETURNDATACOPY: return OpcodeProperties(name: "RETURNDATACOPY", gas: 3, stackHeightChange: 0, category: .environmental, isMemoryOp: true)
        case .EXTCODEHASH:   return OpcodeProperties(name: "EXTCODEHASH", gas: 2600, stackHeightChange: 1, category: .environmental)

        case .BLOCKHASH:     return OpcodeProperties(name: "BLOCKHASH", gas: 20, stackHeightChange: 1, category: .block)
        case .COINBASE:      return OpcodeProperties(name: "COINBASE", gas: 2, stackHeightChange: 1, category: .block)
        case .TIMESTAMP:     return OpcodeProperties(name: "TIMESTAMP", gas: 2, stackHeightChange: 1, category: .block)
        case .NUMBER:        return OpcodeProperties(name: "NUMBER", gas: 2, stackHeightChange: 1, category: .block)
        case .PREVRANDAO:    return OpcodeProperties(name: "PREVRANDAO", gas: 2, stackHeightChange: 1, category: .block)
        case .GASLIMIT:      return OpcodeProperties(name: "GASLIMIT", gas: 2, stackHeightChange: 1, category: .block)
        case .CHAINID:       return OpcodeProperties(name: "CHAINID", gas: 2, stackHeightChange: 1, category: .block)
        case .SELFBALANCE:   return OpcodeProperties(name: "SELFBALANCE", gas: 5, stackHeightChange: 1, category: .block)
        case .BASEFEE:       return OpcodeProperties(name: "BASEFEE", gas: 2, stackHeightChange: 1, category: .block)

        case .POP:           return OpcodeProperties(name: "POP", gas: 2, stackHeightChange: -1, category: .memory)
        case .MLOAD:         return OpcodeProperties(name: "MLOAD", gas: 3, stackHeightChange: 1, category: .memory, isMemoryOp: true)
        case .MSTORE:        return OpcodeProperties(name: "MSTORE", gas: 3, stackHeightChange: -2, category: .memory, isMemoryOp: true)
        case .MSTORE8:       return OpcodeProperties(name: "MSTORE8", gas: 3, stackHeightChange: -2, category: .memory, isMemoryOp: true)
        case .SLOAD:         return OpcodeProperties(name: "SLOAD", gas: 2100, stackHeightChange: 0, category: .memory, isStorageOp: true)
        case .SSTORE:        return OpcodeProperties(name: "SSTORE", gas: 20000, stackHeightChange: -2, category: .memory, isStorageOp: true)
        case .JUMP:          return OpcodeProperties(name: "JUMP", gas: 8, stackHeightChange: -1, category: .controlFlow, isControlFlow: true)
        case .JUMPI:         return OpcodeProperties(name: "JUMPI", gas: 10, stackHeightChange: -2, category: .controlFlow, isControlFlow: true)
        case .JUMPDEST:      return OpcodeProperties(name: "JUMPDEST", gas: 1, stackHeightChange: 0, category: .controlFlow)
        case .PC:            return OpcodeProperties(name: "PC", gas: 2, stackHeightChange: 1, category: .controlFlow)
        case .MSIZE:         return OpcodeProperties(name: "MSIZE", gas: 2, stackHeightChange: 1, category: .memory)
        case .GAS:           return OpcodeProperties(name: "GAS", gas: 2, stackHeightChange: 1, category: .controlFlow)

        case .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8,
             .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16,
             .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24,
             .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32:
            return OpcodeProperties(name: "PUSH*", gas: 3, stackHeightChange: 1, category: .push)

        case .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8,
             .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16:
            return OpcodeProperties(name: "DUP*", gas: 3, stackHeightChange: 1, category: .dup)

        case .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8,
             .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16:
            return OpcodeProperties(name: "SWAP*", gas: 3, stackHeightChange: 0, category: .swap)

        case .LOG0:          return OpcodeProperties(name: "LOG0", gas: 375, stackHeightChange: -2, category: .log)
        case .LOG1:          return OpcodeProperties(name: "LOG1", gas: 375, stackHeightChange: -3, category: .log)
        case .LOG2:          return OpcodeProperties(name: "LOG2", gas: 375, stackHeightChange: -4, category: .log)
        case .LOG3:          return OpcodeProperties(name: "LOG3", gas: 375, stackHeightChange: -5, category: .log)
        case .LOG4:          return OpcodeProperties(name: "LOG4", gas: 375, stackHeightChange: -6, category: .log)

        case .CREATE:        return OpcodeProperties(name: "CREATE", gas: 32000, stackHeightChange: 1, category: .system)
        case .CALL:          return OpcodeProperties(name: "CALL", gas: 2600, stackHeightChange: -6, category: .system)
        case .CALLCODE:      return OpcodeProperties(name: "CALLCODE", gas: 2600, stackHeightChange: -6, category: .system)
        case .RETURN:        return OpcodeProperties(name: "RETURN", gas: 0, stackHeightChange: -2, category: .stop)
        case .DELEGATECALL:  return OpcodeProperties(name: "DELEGATECALL", gas: 2600, stackHeightChange: -5, category: .system)
        case .CREATE2:       return OpcodeProperties(name: "CREATE2", gas: 32000, stackHeightChange: 1, category: .system)
        case .STATICCALL:    return OpcodeProperties(name: "STATICCALL", gas: 2600, stackHeightChange: -5, category: .system)
        case .REVERT:        return OpcodeProperties(name: "REVERT", gas: 0, stackHeightChange: -2, category: .stop)
        case .SELFDESTRUCT:  return OpcodeProperties(name: "SELFDESTRUCT", gas: 5000, stackHeightChange: -1, category: .system)
        case .PUSH0:         return OpcodeProperties(name: "PUSH0", gas: 2, stackHeightChange: 1, category: .push)

        case .RJUMP:
            return OpcodeProperties(name: "RJUMP", gas: 2, stackHeightChange: 0, category: .eof, isControlFlow: true)
        case .RJUMPI:
            return OpcodeProperties(name: "RJUMPI", gas: 4, stackHeightChange: -1, category: .eof, isControlFlow: true)
        case .RJUMPV:
            return OpcodeProperties(name: "RJUMPV", gas: 3, stackHeightChange: -1, category: .eof, isControlFlow: true)
        case .CALLF:
            return OpcodeProperties(name: "CALLF", gas: 2, stackHeightChange: 2, category: .eof, isControlFlow: true)
        case .RETF:
            return OpcodeProperties(name: "RETF", gas: 2, stackHeightChange: -2, category: .eof, isControlFlow: true)
        case .JUMPF:
            return OpcodeProperties(name: "JUMPF", gas: 2, stackHeightChange: -1, category: .eof, isControlFlow: true)
        case .DUPN:
            return OpcodeProperties(name: "DUPN", gas: 3, stackHeightChange: 1, category: .eof)
        case .SWAPN:
            return OpcodeProperties(name: "SWAPN", gas: 3, stackHeightChange: 0, category: .eof)
        case .SLOADBYTES:
            return OpcodeProperties(name: "SLOADBYTES", gas: 100, stackHeightChange: -3, category: .eof, isStorageOp: true)
        case .SSTOREBYTES:
            return OpcodeProperties(name: "SSTOREBYTES", gas: 2900, stackHeightChange: -3, category: .eof, isStorageOp: true)
        case .MSTORESIZE:
            return OpcodeProperties(name: "MSTORESIZE", gas: 3, stackHeightChange: -1, category: .eof, isMemoryOp: true)
        case .TRACKSTORAGE:
            return OpcodeProperties(name: "TRACKSTORAGE", gas: 100, stackHeightChange: -1, category: .eof, isStorageOp: true)
        case .COPYLOG:
            return OpcodeProperties(name: "COPYLOG", gas: 3, stackHeightChange: -3, category: .eof)
        }
    }

    /// Check if this is a PUSH opcode and how many bytes to read
    public var pushBytes: Int? {
        switch self {
        case .PUSH1: return 1
        case .PUSH2: return 2
        case .PUSH3: return 3
        case .PUSH4: return 4
        case .PUSH5: return 5
        case .PUSH6: return 6
        case .PUSH7: return 7
        case .PUSH8: return 8
        case .PUSH9: return 9
        case .PUSH10: return 10
        case .PUSH11: return 11
        case .PUSH12: return 12
        case .PUSH13: return 13
        case .PUSH14: return 14
        case .PUSH15: return 15
        case .PUSH16: return 16
        case .PUSH17: return 17
        case .PUSH18: return 18
        case .PUSH19: return 19
        case .PUSH20: return 20
        case .PUSH21: return 21
        case .PUSH22: return 22
        case .PUSH23: return 23
        case .PUSH24: return 24
        case .PUSH25: return 25
        case .PUSH26: return 26
        case .PUSH27: return 27
        case .PUSH28: return 28
        case .PUSH29: return 29
        case .PUSH30: return 30
        case .PUSH31: return 31
        case .PUSH32: return 32
        default: return nil
        }
    }

    /// Check if this is a DUP opcode and which stack position
    public var dupPosition: Int? {
        switch self {
        case .DUP1: return 1
        case .DUP2: return 2
        case .DUP3: return 3
        case .DUP4: return 4
        case .DUP5: return 5
        case .DUP6: return 6
        case .DUP7: return 7
        case .DUP8: return 8
        case .DUP9: return 9
        case .DUP10: return 10
        case .DUP11: return 11
        case .DUP12: return 12
        case .DUP13: return 13
        case .DUP14: return 14
        case .DUP15: return 15
        case .DUP16: return 16
        default: return nil
        }
    }

    /// Check if this is a SWAP opcode and which position
    public var swapPosition: Int? {
        switch self {
        case .SWAP1: return 1
        case .SWAP2: return 2
        case .SWAP3: return 3
        case .SWAP4: return 4
        case .SWAP5: return 5
        case .SWAP6: return 6
        case .SWAP7: return 7
        case .SWAP8: return 8
        case .SWAP9: return 9
        case .SWAP10: return 10
        case .SWAP11: return 11
        case .SWAP12: return 12
        case .SWAP13: return 13
        case .SWAP14: return 14
        case .SWAP15: return 15
        case .SWAP16: return 16
        default: return nil
        }
    }

    /// Check if this is a LOG opcode and how many topics
    public var logTopics: Int? {
        switch self {
        case .LOG0: return 0
        case .LOG1: return 1
        case .LOG2: return 2
        case .LOG3: return 3
        case .LOG4: return 4
        default: return nil
        }
    }
}

// MARK: - Minimal Viable EVM Opcodes (Phase 1)

extension EVMOpcode {
    /// Opcodes required for a minimal ETH transfer
    public static var mvpOpcodes: Set<EVMOpcode> {
        [
            .STOP, .ADD, .MUL, .SUB, .DIV, .MOD, .SDIV, .SMOD,
            .LT, .GT, .EQ, .ISZERO, .AND, .OR, .XOR, .NOT, .BYTE,
            .KECCAK256,
            .ADDRESS, .CALLER, .CALLVALUE, .CALLDATASIZE, .CALLDATACOPY,
            .CODESIZE, .CODECOPY, .GASPRICE,
            .BLOCKHASH, .NUMBER, .TIMESTAMP, .COINBASE, .PREVRANDAO, .GASLIMIT,
            .POP, .MLOAD, .MSTORE, .MSTORE8, .SLOAD, .SSTORE,
            .JUMP, .JUMPI, .JUMPDEST, .PC, .MSIZE, .GAS,
            .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8,
            .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16,
            .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24,
            .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32,
            .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8,
            .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16,
            .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8,
            .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16,
            .LOG0, .LOG1, .LOG2,
            .RETURN, .REVERT,
            .CALL, .DELEGATECALL, .STATICCALL, .CREATE, .CALLCODE,
            .SELFBALANCE, .BASEFEE, .CHAINID, .EXTCODEHASH, .EXTCODESIZE, .EXTCODECOPY,
            .EXP, .SIGNEXTEND, .ADDMOD, .MULMOD, .SLT, .SGT, .SELFDESTRUCT,
            .CREATE2, .RETURNDATASIZE, .RETURNDATACOPY,
            .PUSH0, .BALANCE, .SHR, .SHL, .SAR
        ]
    }

    /// Check if this opcode is in the MVP set
    public var isMVP: Bool {
        Self.mvpOpcodes.contains(self)
    }
}
