// GPU-accelerated EVM Interpreter - Environmental Opcodes (0x30-0x3F)
//
// Memory layout:
// - State buffer: [txIdx * 64] = { pc, gas, stackPtr, memoryPtr, running, reverted }
// - Stack buffer: [txIdx * 1024 * 32 + stackPtr * 32] = M31Word
// - Memory buffer: [txIdx * maxMemory + offset] = UInt8
// - Code buffer: [txIdx * maxCodeSize] = bytecode
// - Calldata buffer: [txIdx * maxCalldataSize] = calldata
// - ReturnData buffer: [txIdx * maxReturnDataSize] = returndata
// - Account state buffer: [txIdx * accountStateSize] = per-account state
// - Config buffer: [txIdx] = execution config

#include <metal_stdlib>
using namespace metal;

constant uint M31_P = 0x7FFFFFFF;

// ============================================================================
// M31 FIELD ARITHMETIC
// ============================================================================

// M31 field operations
struct M31 {
    uint v;
};

// 256-bit word as 8 x M31 limbs
struct M31Word {
    M31 limb[8];
};

M31 m31_zero() { return M31{0}; }
M31 m31_one() { return M31{1}; }

M31 m31_add(M31 a, M31 b) {
    uint s = a.v + b.v;
    uint r = (s & M31_P) + (s >> 31);
    return M31{r == M31_P ? 0u : r};
}

M31 m31_sub(M31 a, M31 b) {
    if (a.v >= b.v) return M31{a.v - b.v};
    return M31{a.v + M31_P - b.v};
}

M31 m31_mul(M31 a, M31 b) {
    ulong prod = ulong(a.v) * ulong(b.v);
    uint lo = uint(prod & ulong(M31_P));
    uint hi = uint(prod >> 31);
    uint s = lo + hi;
    uint r = (s & M31_P) + (s >> 31);
    return M31{r == M31_P ? 0u : r};
}

bool m31_is_zero(M31 a) { return a.v == 0; }

bool m31_lt(M31 a, M31 b) {
    return a.v < b.v;
}

bool m31_gt(M31 a, M31 b) {
    return a.v > b.v;
}

bool m31_eq(M31 a, M31 b) {
    return a.v == b.v;
}

M31 m31_and(M31 a, M31 b) {
    return M31{a.v & b.v};
}

M31 m31_or(M31 a, M31 b) {
    return M31{a.v | b.v};
}

M31 m31_xor(M31 a, M31 b) {
    return M31{a.v ^ b.v};
}

M31 m31_not(M31 a) {
    return M31{a.v ^ M31_P};
}

// Check if M31Word is zero
inline bool m31word_is_zero(M31Word a) {
    for (uint i = 0; i < 8; i++) {
        if (a.limb[i].v != 0) return false;
    }
    return true;
}

// Check if M31Word represents a negative signed value (sign bit at byte 31 bit 7)
inline bool m31word_is_negative(M31Word a) {
    // Byte 31 is stored in limb 7 at bits 0-7 (little-endian per bytes_to_m31word)
    // Sign bit is bit 7 of byte 31
    return (a.limb[7].v & 0x80) != 0;
}

// Convert M31Word to uint256 bytes (big-endian, 32 bytes)
inline void m31word_to_bytes(M31Word word, uchar* bytes) {
    for (uint i = 0; i < 8; i++) {
        uint val = word.limb[i].v;
        for (uint j = 0; j < 4; j++) {
            bytes[i * 4 + j] = uchar((val >> (j * 8)) & 0xFF);
        }
    }
}

// Helper: Get byte at index (0 = MSB, 31 = LSB) from M31Word
inline uchar m31word_get_byte(M31Word word, uint byteIdx) {
    if (byteIdx >= 32) return 0;
    uchar bytes[32];
    m31word_to_bytes(word, bytes);
    return bytes[byteIdx];
}

// Square-and-multiply modular exponentiation: base^exp mod 2^256
// Returns base^exp mod M31_P for each limb (full 256-bit exp would be expensive)
// For EXP opcode: base^exponent mod 2^256
inline M31Word m31word_exp(M31Word base, M31Word exponent) {
    M31Word result;
    // Initialize result to 1 (identity element)
    result.limb[0] = m31_one();
    for (uint i = 1; i < 8; i++) {
        result.limb[i] = m31_zero();
    }

    // Square-and-multiply algorithm
    // Process each byte of exponent (256 bits = 32 bytes)
    for (uint byteIdx = 0; byteIdx < 32; byteIdx++) {
        uchar expByte = m31word_get_byte(exponent, byteIdx);

        // Square for each bit position
        for (uint bitIdx = 0; bitIdx < 8; bitIdx++) {
            // Square result
            M31Word squared;
            for (uint i = 0; i < 8; i++) {
                squared.limb[i] = m31_mul(result.limb[i], result.limb[i]);
            }
            result = squared;

            // Multiply by base if bit is 1
            if ((expByte >> bitIdx) & 1) {
                M31Word multiplied;
                for (uint i = 0; i < 8; i++) {
                    multiplied.limb[i] = m31_mul(result.limb[i], base.limb[i]);
                }
                result = multiplied;
            }
        }
    }
    return result;
}

// Convert uint64 to M31Word (little-endian representation in M31 limbs)
inline M31Word uint64_to_m31word(uint64_t val) {
    M31Word word;
    for (uint i = 0; i < 8; i++) {
        word.limb[i] = M31{uint(val & 0x7FFFFFFF)};
        val >>= 31;
    }
    return word;
}

// Convert bytes to M31Word (bytes are laid out in memory as little-endian)
inline M31Word bytes_to_m31word(device const uchar* bytes) {
    M31Word word;
    for (uint i = 0; i < 8; i++) {
        uint val = 0;
        for (uint j = 0; j < 4; j++) {
            val |= uint(bytes[i * 4 + j]) << (j * 8);
        }
        word.limb[i] = M31{val & M31_P};
    }
    return word;
}

// ============================================================================
// TRANSACTION STATE STRUCTURES
// ============================================================================

// Transaction state structure - aligned layout
struct PackedTxState {
    uint pc;         // offset 0, 4 bytes
    uint padding1;   // offset 4, 4 bytes (padding to align gas)
    uint64_t gas;    // offset 8, 8 bytes (8-byte aligned)
    uint stackPtr;   // offset 16, 4 bytes
    uint memoryPtr;  // offset 20, 4 bytes
    uint running;    // offset 24, 4 bytes
    uint reverted;    // offset 28, 4 bytes
    uint callDepth;  // offset 32, 4 bytes
    uint calldataSize;    // offset 36, 4 bytes
    uint returndataSize;  // offset 40, 4 bytes
};

// Alias for backwards compatibility
typedef PackedTxState TxState;

// Trace row structure
struct TraceRow {
    uint pc;
    uchar opcode;
    uint gas;
    uint stackHeight;
    uint memorySize;
    uint callDepth;
    uint isRunning;
    uint isReverted;
    uint padding;
};

// Configuration - per transaction input
struct Config {
    uint64_t gasLimit;
    uint64_t blockTimestamp;
    uint64_t blockNumber;
    uint64_t blockPrevRandao;   // prevrandao (was difficulty pre-merge)
    uint64_t blockGasLimit;
    uint64_t blockBaseFee;      // EIP-1559 base fee
    uchar chainId[32];      // EIP-2718 chain ID
    uchar origin[32];       // tx.origin
    uchar caller[32];       // msg.sender
    uchar address[32];      // executing contract address
    uchar callvalue[32];    // msg.value
    uchar gasPrice[32];     // tx.gasprice
    uchar blockCoinbase[32]; // block beneficiary/coinbase
    uint calldataSize;      // size of calldata
    uint returndataSize;    // size of returndata
    uint isEofEnabled;      // EOF format enabled flag
};

// Account state for balance and code queries
struct AccountState {
    uchar address[32];
    uchar balance[32];      // account balance
    uchar codeHash[32];     // keccak256 of contract code
    uint codeSize;          // size of contract code
};

// ============================================================================
// STACK OPERATIONS
// ============================================================================

inline M31Word readStack(device const uchar* stack, uint txIdx, uint stackPtr, uint maxStackDepth) {
    M31Word word;
    uint offset = txIdx * maxStackDepth * 32 + stackPtr * 32;
    for (uint i = 0; i < 8; i++) {
        uint val = 0;
        for (uint j = 0; j < 4; j++) {
            val |= uint(stack[offset + i * 4 + j]) << (j * 8);
        }
        word.limb[i] = M31{val};
    }
    return word;
}

inline void writeStack(device uchar* stack, uint txIdx, uint stackPtr, uint maxStackDepth, M31Word word) {
    uint offset = txIdx * maxStackDepth * 32 + stackPtr * 32;
    for (uint i = 0; i < 8; i++) {
        uint val = word.limb[i].v;
        for (uint j = 0; j < 4; j++) {
            stack[offset + i * 4 + j] = uchar((val >> (j * 8)) & 0xFF);
        }
    }
}

inline void stackPush(device TxState* states, device uchar* stack,
                      uint txIdx, uint maxStackDepth, M31Word value) {
    uint stackPtr = states[txIdx].stackPtr;
    writeStack(stack, txIdx, stackPtr, maxStackDepth, value);
    states[txIdx].stackPtr = stackPtr + 1;
}

inline M31Word stackPop(device TxState* states, device uchar* stack,
                        uint txIdx, uint maxStackDepth) {
    uint stackPtr = states[txIdx].stackPtr - 1;
    states[txIdx].stackPtr = stackPtr;
    return readStack(stack, txIdx, stackPtr, maxStackDepth);
}

// ============================================================================
// MEMORY OPERATIONS
// ============================================================================

inline void memoryExpand(device TxState* states, device uchar* memory,
                         uint txIdx, uint maxMemory, uint offset, uint size) {
    if (offset + size > states[txIdx].memoryPtr) {
        uint newPtr = offset + size;
        states[txIdx].memoryPtr = min(newPtr, maxMemory);
    }
}

inline uchar memoryLoadByte(device uchar* memory, uint txIdx, uint maxMemory, uint offset) {
    if (offset >= txIdx * maxMemory) return 0;
    uint localOffset = offset - txIdx * maxMemory;
    if (localOffset >= maxMemory) return 0;
    return memory[txIdx * maxMemory + localOffset];
}

inline void memoryStoreByte(device uchar* memory, uint txIdx, uint maxMemory, uint offset, uchar value) {
    if (offset >= txIdx * maxMemory) return;
    uint localOffset = offset - txIdx * maxMemory;
    if (localOffset >= maxMemory) return;
    memory[txIdx * maxMemory + localOffset] = value;
}

inline M31Word memoryLoadWord(device uchar* memory, uint txIdx, uint maxMemory, uint offset) {
    M31Word word;
    for (uint i = 0; i < 8; i++) {
        uint val = 0;
        for (uint j = 0; j < 4; j++) {
            val |= uint(memoryLoadByte(memory, txIdx, maxMemory, offset + i * 4 + j)) << (j * 8);
        }
        word.limb[i] = M31{val & M31_P};
    }
    return word;
}

inline void memoryStoreWord(device uchar* memory, device TxState* states,
                            uint txIdx, uint maxMemory, uint offset, M31Word word) {
    memoryExpand(states, memory, txIdx, maxMemory, offset, 32);
    for (uint i = 0; i < 8; i++) {
        uint val = word.limb[i].v;
        for (uint j = 0; j < 4; j++) {
            memoryStoreByte(memory, txIdx, maxMemory, offset + i * 4 + j, uchar((val >> (j * 8)) & 0xFF));
        }
    }
}

// Memory copy operation
inline void memoryCopy(device uchar* memory, device TxState* states,
                       uint txIdx, uint maxMemory,
                       uint dest, uint src, uint size) {
    if (size == 0) return;
    memoryExpand(states, memory, txIdx, maxMemory, dest, size);
    memoryExpand(states, memory, txIdx, maxMemory, src, size);

    for (uint i = 0; i < size; i++) {
        uchar byte = memoryLoadByte(memory, txIdx, maxMemory, src + i);
        memoryStoreByte(memory, txIdx, maxMemory, dest + i, byte);
    }
}

// ============================================================================
// EVM OPCODE CONSTANTS
// ============================================================================

// Stop and Arithmetic
constant uchar OP_STOP = 0x00;
constant uchar OP_ADD = 0x01;
constant uchar OP_MUL = 0x02;
constant uchar OP_SUB = 0x03;
constant uchar OP_DIV = 0x04;
constant uchar OP_SDIV = 0x05;
constant uchar OP_MOD = 0x06;
constant uchar OP_SMOD = 0x07;
constant uchar OP_ADDMOD = 0x08;
constant uchar OP_MULMOD = 0x09;
constant uchar OP_EXP = 0x0A;

// Comparison and Bitwise
constant uchar OP_LT = 0x10;
constant uchar OP_GT = 0x11;
constant uchar OP_SLT = 0x12;
constant uchar OP_SGT = 0x13;
constant uchar OP_EQ = 0x14;
constant uchar OP_ISZERO = 0x15;
constant uchar OP_AND = 0x16;
constant uchar OP_OR = 0x17;
constant uchar OP_XOR = 0x18;
constant uchar OP_NOT = 0x19;
constant uchar OP_BYTE = 0x1A;
constant uchar OP_SHL = 0x1B;
constant uchar OP_SHR = 0x1C;
constant uchar OP_SAR = 0x1D;

// Environmental Opcodes (0x30-0x3F)
constant uchar OP_ADDRESS = 0x30;
constant uchar OP_BALANCE = 0x31;
constant uchar OP_ORIGIN = 0x32;
constant uchar OP_CALLER = 0x33;
constant uchar OP_CALLVALUE = 0x34;
constant uchar OP_CALLDATALOAD = 0x35;
constant uchar OP_CALLDATASIZE = 0x36;
constant uchar OP_CALLDATACOPY = 0x37;
constant uchar OP_CODESIZE = 0x38;
constant uchar OP_CODECOPY = 0x39;
constant uchar OP_GASPRICE = 0x3A;
constant uchar OP_EXTCODESIZE = 0x3B;
constant uchar OP_EXTCODECOPY = 0x3C;
constant uchar OP_RETURNDATASIZE = 0x3D;
constant uchar OP_RETURNDATACOPY = 0x3E;
constant uchar OP_EXTCODEHASH = 0x3F;

// Block Opcodes (0x40-0x48)
constant uchar OP_BLOCKHASH = 0x40;
constant uchar OP_COINBASE = 0x41;
constant uchar OP_TIMESTAMP = 0x42;
constant uchar OP_NUMBER = 0x43;
constant uchar OP_PREVRANDAO = 0x44;
constant uchar OP_GASLIMIT = 0x45;
constant uchar OP_CHAINID = 0x46;
constant uchar OP_SELFBALANCE = 0x47;
constant uchar OP_BASEFEE = 0x48;

// Stack Operations
constant uchar OP_PUSH0 = 0x5F;
constant uchar OP_POP = 0x50;
constant uchar OP_MLOAD = 0x51;
constant uchar OP_MSTORE = 0x52;
constant uchar OP_MSTORE8 = 0x53;
constant uchar OP_JUMP = 0x56;
constant uchar OP_JUMPI = 0x57;
constant uchar OP_PC = 0x58;
constant uchar OP_MSIZE = 0x59;
constant uchar OP_GAS = 0x5A;
constant uchar OP_JUMPDEST = 0x5B;

// Push Instructions
constant uchar OP_PUSH1 = 0x60;
constant uchar OP_PUSH2 = 0x61;
constant uchar OP_PUSH3 = 0x62;
constant uchar OP_PUSH4 = 0x63;
constant uchar OP_PUSH5 = 0x64;
constant uchar OP_PUSH6 = 0x65;
constant uchar OP_PUSH7 = 0x66;
constant uchar OP_PUSH8 = 0x67;
constant uchar OP_PUSH9 = 0x68;
constant uchar OP_PUSH10 = 0x69;
constant uchar OP_PUSH11 = 0x6A;
constant uchar OP_PUSH12 = 0x6B;
constant uchar OP_PUSH13 = 0x6C;
constant uchar OP_PUSH14 = 0x6D;
constant uchar OP_PUSH15 = 0x6E;
constant uchar OP_PUSH16 = 0x6F;
constant uchar OP_PUSH17 = 0x70;
constant uchar OP_PUSH18 = 0x71;
constant uchar OP_PUSH19 = 0x72;
constant uchar OP_PUSH20 = 0x73;
constant uchar OP_PUSH21 = 0x74;
constant uchar OP_PUSH22 = 0x75;
constant uchar OP_PUSH23 = 0x76;
constant uchar OP_PUSH24 = 0x77;
constant uchar OP_PUSH25 = 0x78;
constant uchar OP_PUSH26 = 0x79;
constant uchar OP_PUSH27 = 0x7A;
constant uchar OP_PUSH28 = 0x7B;
constant uchar OP_PUSH29 = 0x7C;
constant uchar OP_PUSH30 = 0x7D;
constant uchar OP_PUSH31 = 0x7E;
constant uchar OP_PUSH32 = 0x7F;

// Duplication and Exchange
constant uchar OP_DUP1 = 0x80;
constant uchar OP_DUP2 = 0x81;
constant uchar OP_DUP3 = 0x82;
constant uchar OP_DUP4 = 0x83;
constant uchar OP_DUP5 = 0x84;
constant uchar OP_DUP6 = 0x85;
constant uchar OP_DUP7 = 0x86;
constant uchar OP_DUP8 = 0x87;
constant uchar OP_DUP9 = 0x88;
constant uchar OP_DUP10 = 0x89;
constant uchar OP_DUP11 = 0x8A;
constant uchar OP_DUP12 = 0x8B;
constant uchar OP_DUP13 = 0x8C;
constant uchar OP_DUP14 = 0x8D;
constant uchar OP_DUP15 = 0x8E;
constant uchar OP_DUP16 = 0x8F;

constant uchar OP_SWAP1 = 0x90;
constant uchar OP_SWAP2 = 0x91;
constant uchar OP_SWAP3 = 0x92;
constant uchar OP_SWAP4 = 0x93;
constant uchar OP_SWAP5 = 0x94;
constant uchar OP_SWAP6 = 0x95;
constant uchar OP_SWAP7 = 0x96;
constant uchar OP_SWAP8 = 0x97;
constant uchar OP_SWAP9 = 0x98;
constant uchar OP_SWAP10 = 0x99;
constant uchar OP_SWAP11 = 0x9A;
constant uchar OP_SWAP12 = 0x9B;
constant uchar OP_SWAP13 = 0x9C;
constant uchar OP_SWAP14 = 0x9D;
constant uchar OP_SWAP15 = 0x9E;
constant uchar OP_SWAP16 = 0x9F;

// EOF Opcodes (0xE0-0xEF)
constant uchar OP_RJUMP = 0xE0;      // Relative jump (unconditional)
constant uchar OP_RJUMPI = 0xE1;     // Relative jump (conditional)
constant uchar OP_RJUMPV = 0xE2;     // Relative jump with table
constant uchar OP_CALLF = 0xE3;      // Call function
constant uchar OP_RETF = 0xE4;       // Return from function
constant uchar OP_JUMPF = 0xE5;      // Jump to function
constant uchar OP_DUPN = 0xE8;       // Duplicate Nth stack item (EOF)
constant uchar OP_SWAPN = 0xE9;      // Swap with Nth stack item (EOF)
constant uchar OP_MSTORESIZE = 0xEA; // Resize memory
constant uchar OP_TRACKSTORAGE = 0xEB; // Track storage slot

// Return and Revert
constant uchar OP_RETURN = 0xF3;
constant uchar OP_REVERT = 0xFD;
constant uchar OP_SELFDESTRUCT = 0xFF;

// Log Operations
constant uchar OP_LOG0 = 0xA0;
constant uchar OP_LOG1 = 0xA1;
constant uchar OP_LOG2 = 0xA2;
constant uchar OP_LOG3 = 0xA3;
constant uchar OP_LOG4 = 0xA4;

// Create operations
constant uchar OP_CREATE = 0xF0;
constant uchar OP_CALL = 0xF1;
constant uchar OP_CALLCODE = 0xF2;
constant uchar OP_DELEGATECALL = 0xF4;
constant uchar OP_CREATE2 = 0xF5;
constant uchar OP_STATICCALL = 0xFA;

// ============================================================================
// BYTECODE AND DATA ACCESS
// ============================================================================

// Read bytecode at pc
inline uchar readCode(device const uchar* code, uint txIdx, uint maxCodeSize, uint pc) {
    return code[txIdx * maxCodeSize + pc];
}

// Read immediate value (PUSH instructions)
inline M31Word readImmediate(device const uchar* code, uint txIdx, uint maxCodeSize, uint pc, uint numBytes) {
    M31Word word;
    for (uint i = 0; i < 8; i++) {
        word.limb[i] = m31_zero();
    }

    uint offset = txIdx * maxCodeSize + pc;
    uint limbIdx = 0;
    uint bitPos = 0;
    uint accumulated = 0;
    uint bitsInAccumulated = 0;

    for (uint i = 0; i < numBytes && i < 32; i++) {
        uint byte = code[offset + i];
        accumulated |= byte << bitPos;
        bitPos += 8;
        bitsInAccumulated += 8;

        while (bitsInAccumulated >= 31 && limbIdx < 8) {
            word.limb[limbIdx] = M31{accumulated & M31_P};
            accumulated >>= 31;
            bitPos -= 31;
            bitsInAccumulated -= 31;
            limbIdx++;
        }
    }

    if (bitsInAccumulated > 0 && limbIdx < 8) {
        word.limb[limbIdx] = M31{accumulated & M31_P};
    }

    return word;
}

// Read calldata byte
inline uchar readCalldataByte(device const uchar* calldata, uint txIdx, uint calldataSize, uint offset) {
    if (offset >= calldataSize) return 0;
    return calldata[txIdx * 32 + offset];  // Assuming maxCalldataSize = 32 for direct access
}

// Read returndata byte
inline uchar readReturndataByte(device const uchar* returndata, uint txIdx, uint returndataSize, uint offset) {
    if (offset >= returndataSize) return 0;
    return returndata[txIdx * 32 + offset];  // Assuming maxReturnDataSize = 32 for direct access
}

// Convert 32-byte address to M31Word
inline M31Word addressToM31Word(const uchar* address) {
    return bytes_to_m31word(address);
}

// ============================================================================
// ENVIRONMENTAL OPCODES IMPLEMENTATION (0x30-0x3F)
// ============================================================================

// OP_ADDRESS (0x30) - Get address of executing contract
// Stack: -> address
// Gas: 2
inline M31Word op_address(device const Config* config, uint txIdx) {
    return addressToM31Word(config[txIdx].address);
}

// OP_BALANCE (0x31) - Get balance of account
// Stack: address -> balance
// Gas: 100 (cold) or 0 (warm)
inline M31Word op_balance(device const uchar* accountBalances,
                          device const uchar* accountAddresses,
                          device const Config* config,
                          uint txIdx, uint numAccounts,
                          M31Word address) {
    // Search for the address in account list
    // For simplified GPU implementation, we use a direct lookup via address hash
    // In production, this would use the account state buffer

    // Simplified: return zero balance (actual implementation would query account state)
    M31Word result;
    for (uint i = 0; i < 8; i++) {
        result.limb[i] = m31_zero();
    }
    return result;
}

// OP_ORIGIN (0x32) - Get tx origin
// Stack: -> origin
// Gas: 2
inline M31Word op_origin(device const Config* config, uint txIdx) {
    return addressToM31Word(config[txIdx].origin);
}

// OP_CALLER (0x33) - Get caller
// Stack: -> caller
// Gas: 2
inline M31Word op_caller(device const Config* config, uint txIdx) {
    return addressToM31Word(config[txIdx].caller);
}

// OP_CALLVALUE (0x34) - Get call value
// Stack: -> value
// Gas: 2
inline M31Word op_callvalue(device const Config* config, uint txIdx) {
    return bytes_to_m31word(config[txIdx].callvalue);
}

// OP_CALLDATALOAD (0x35) - Get calldata
// Stack: offset -> value
// Gas: 3 (plus expansion)
inline M31Word op_calldataload(device const uchar* calldata,
                               device const Config* config,
                               uint txIdx, uint stackPtr,
                               device const uchar* stack) {
    // Get offset from stack
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 1, 1024);

    // Extract offset as uint (first limb)
    uint offset = offsetWord.limb[0].v;

    // Read 32 bytes from calldata at offset
    M31Word result;
    uint calldataSize = config[txIdx].calldataSize;

    for (uint i = 0; i < 8; i++) {
        uint val = 0;
        for (uint j = 0; j < 4; j++) {
            uint byteOffset = offset + i * 4 + j;
            if (byteOffset < calldataSize) {
                val |= uint(calldata[txIdx * 32 + byteOffset]) << (j * 8);
            }
        }
        result.limb[i] = M31{val & M31_P};
    }
    return result;
}

// OP_CALLDATASIZE (0x36) - Get calldata size
// Stack: -> size
// Gas: 2
inline M31Word op_calldatasize(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].calldataSize);
}

// OP_CALLDATACOPY (0x37) - Copy calldata to memory
// Stack: destOffset offset size ->
// Gas: 3 + 3 * words expansion
inline void op_calldatacopy(device uchar* memory,
                            device TxState* states,
                            device const uchar* calldata,
                            device const Config* config,
                            uint txIdx, uint maxMemory,
                            uint stackPtr) {
    // Pop size, offset, destOffset from stack
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word destWord = readStack(stack, txIdx, stackPtr - 3, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;
    uint dest = destWord.limb[0].v;

    uint calldataSize = config[txIdx].calldataSize;

    // Copy calldata to memory
    memoryExpand(states, memory, txIdx, maxMemory, dest, size);
    for (uint i = 0; i < size; i++) {
        uchar byte = 0;
        if (offset + i < calldataSize) {
            byte = calldata[txIdx * 32 + offset + i];
        }
        memoryStoreByte(memory, txIdx, maxMemory, dest + i, byte);
    }
}

// OP_CODESIZE (0x38) - Get code size
// Stack: -> size
// Gas: 2
inline M31Word op_codesize(device const Config* config, uint txIdx) {
    // Code size would need to be passed via config or computed
    // For now, return 0 (would need code size in config)
    M31Word result;
    for (uint i = 0; i < 8; i++) {
        result.limb[i] = m31_zero();
    }
    return result;
}

// OP_CODECOPY (0x39) - Copy code to memory
// Stack: destOffset offset size ->
// Gas: 3 + 3 * words expansion
inline void op_codecopy(device uchar* memory,
                       device TxState* states,
                       device const uchar* code,
                       device const Config* config,
                       uint txIdx, uint maxMemory, uint maxCodeSize,
                       uint stackPtr) {
    // Pop size, offset, destOffset from stack
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word destWord = readStack(stack, txIdx, stackPtr - 3, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;
    uint dest = destWord.limb[0].v;

    // Copy code to memory
    memoryExpand(states, memory, txIdx, maxMemory, dest, size);
    for (uint i = 0; i < size; i++) {
        uchar byte = 0;
        uint codeIdx = txIdx * maxCodeSize + offset + i;
        if (codeIdx < (txIdx + 1) * maxCodeSize) {
            byte = code[codeIdx];
        }
        memoryStoreByte(memory, txIdx, maxMemory, dest + i, byte);
    }
}

// OP_GASPRICE (0x3A) - Get gas price
// Stack: -> gasprice
// Gas: 2
inline M31Word op_gasprice(device const Config* config, uint txIdx) {
    return bytes_to_m31word(config[txIdx].gasPrice);
}

// OP_EXTCODESIZE (0x3B) - Get external code size
// Stack: address -> size
// Gas: 100 (cold) or 0 (warm)
inline M31Word op_extcodesize(device const Config* config,
                              device const uchar* accountAddresses,
                              device const uint* accountCodeSizes,
                              uint txIdx, uint numAccounts,
                              M31Word address) {
    // Simplified: return 0 (actual implementation would lookup account)
    M31Word result;
    for (uint i = 0; i < 8; i++) {
        result.limb[i] = m31_zero();
    }
    return result;
}

// OP_EXTCODECOPY (0x3C) - Copy external code to memory
// Stack: address destOffset offset size ->
// Gas: 100 (cold) + 3 * words
inline void op_extcodecopy(device uchar* memory,
                           device TxState* states,
                           device const uchar* accountAddresses,
                           device const uchar* accountCode,
                           device const uint* accountCodeSizes,
                           device const Config* config,
                           uint txIdx, uint maxMemory,
                           uint maxAccountCodeSize, uint numAccounts,
                           uint stackPtr) {
    // Pop size, offset, destOffset, address from stack
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word destWord = readStack(stack, txIdx, stackPtr - 3, 1024);
    M31Word addressWord = readStack(stack, txIdx, stackPtr - 4, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;
    uint dest = destWord.limb[0].v;

    // Simplified: copy zeros (actual implementation would lookup account code)
    memoryExpand(states, memory, txIdx, maxMemory, dest, size);
    for (uint i = 0; i < size; i++) {
        memoryStoreByte(memory, txIdx, maxMemory, dest + i, 0);
    }
}

// OP_RETURNDATASIZE (0x3D) - Get returndata size
// Stack: -> size
// Gas: 2
inline M31Word op_returndatasize(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].returndataSize);
}

// OP_RETURNDATACOPY (0x3E) - Copy returndata to memory
// Stack: destOffset offset size ->
// Gas: 3 + 3 * words expansion
inline void op_returndatacopy(device uchar* memory,
                              device TxState* states,
                              device const uchar* returndata,
                              device const Config* config,
                              uint txIdx, uint maxMemory,
                              uint stackPtr) {
    // Pop size, offset, destOffset from stack
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word destWord = readStack(stack, txIdx, stackPtr - 3, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;
    uint dest = destWord.limb[0].v;

    uint returndataSize = config[txIdx].returndataSize;

    // Copy returndata to memory
    memoryExpand(states, memory, txIdx, maxMemory, dest, size);
    for (uint i = 0; i < size; i++) {
        uchar byte = 0;
        if (offset + i < returndataSize) {
            byte = returndata[txIdx * 32 + offset + i];
        }
        memoryStoreByte(memory, txIdx, maxMemory, dest + i, byte);
    }
}

// OP_EXTCODEHASH (0x3F) - Get external code hash
// Stack: address -> hash
// Gas: 100 (cold) or 0 (warm)
inline M31Word op_extcodehash(device const Config* config,
                              device const uchar* accountAddresses,
                              device const uchar* accountCodeHashes,
                              uint txIdx, uint numAccounts,
                              M31Word address) {
    // Simplified: return zero hash (actual implementation would lookup account)
    M31Word result;
    for (uint i = 0; i < 8; i++) {
        result.limb[i] = m31_zero();
    }
    return result;
}

// ============================================================================
// LOG OPCODES IMPLEMENTATION (0xA0-0xA4)
// ============================================================================

// OP_LOG0 (0xA0) - Emit log with 0 topics
// Stack: memOffset memSize ->
// Gas: 375 + memory expansion
inline void op_log0(device TxState* states,
                    device uchar* memory,
                    uint txIdx, uint maxMemory,
                    uint stackPtr) {
    // Pop 2 items: memOffset, memSize
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Memory expansion
    memoryExpand(states, memory, txIdx, maxMemory, offset, size);
}

// OP_LOG1 (0xA1) - Emit log with 1 topic
// Stack: memOffset memSize topic1 ->
// Gas: 375 + 375 + memory expansion
inline void op_log1(device TxState* states,
                    device uchar* memory,
                    uint txIdx, uint maxMemory,
                    uint stackPtr) {
    // Pop 3 items: memOffset, memSize, topic1
    M31Word topic1Word = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 3, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Memory expansion
    memoryExpand(states, memory, txIdx, maxMemory, offset, size);
}

// OP_LOG2 (0xA2) - Emit log with 2 topics
// Stack: memOffset memSize topic1 topic2 ->
// Gas: 375 + 2*375 + memory expansion
inline void op_log2(device TxState* states,
                    device uchar* memory,
                    uint txIdx, uint maxMemory,
                    uint stackPtr) {
    // Pop 4 items: memOffset, memSize, topic1, topic2
    M31Word topic2Word = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word topic1Word = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 3, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 4, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Memory expansion
    memoryExpand(states, memory, txIdx, maxMemory, offset, size);
}

// OP_LOG3 (0xA3) - Emit log with 3 topics
// Stack: memOffset memSize topic1 topic2 topic3 ->
// Gas: 375 + 3*375 + memory expansion
inline void op_log3(device TxState* states,
                    device uchar* memory,
                    uint txIdx, uint maxMemory,
                    uint stackPtr) {
    // Pop 5 items: memOffset, memSize, topic1, topic2, topic3
    M31Word topic3Word = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word topic2Word = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word topic1Word = readStack(stack, txIdx, stackPtr - 3, 1024);
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 4, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 5, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Memory expansion
    memoryExpand(states, memory, txIdx, maxMemory, offset, size);
}

// OP_LOG4 (0xA4) - Emit log with 4 topics
// Stack: memOffset memSize topic1 topic2 topic3 topic4 ->
// Gas: 375 + 4*375 + memory expansion
inline void op_log4(device TxState* states,
                    device uchar* memory,
                    uint txIdx, uint maxMemory,
                    uint stackPtr) {
    // Pop 6 items: memOffset, memSize, topic1, topic2, topic3, topic4
    M31Word topic4Word = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word topic3Word = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word topic2Word = readStack(stack, txIdx, stackPtr - 3, 1024);
    M31Word topic1Word = readStack(stack, txIdx, stackPtr - 4, 1024);
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 5, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 6, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Memory expansion
    memoryExpand(states, memory, txIdx, maxMemory, offset, size);
}

// ============================================================================
// BLOCK OPCODES IMPLEMENTATION (0x40-0x48)
// ============================================================================

// OP_BLOCKHASH (0x40) - Get block hash
// Stack: blockNumber -> hash
// Gas: 20
inline M31Word op_blockhash(device const uchar* blockHashes,
                           device const Config* config,
                           uint txIdx, uint maxBlockHashes,
                           M31Word blockNumber) {
    // Extract block number from first limb
    uint64_t blockNum = blockNumber.limb[0].v;

    // Get current block number
    uint64_t currentBlock = config[txIdx].blockNumber;

    // BLOCKHASH returns bytes32 of the specified block's hash
    // Valid range: last 256 blocks (current block number - 256) to (current block number - 1)
    // Outside this range returns bytes32(0)

    M31Word result;
    for (uint i = 0; i < 8; i++) {
        result.limb[i] = m31_zero();
    }

    // Check if block number is in valid range
    if (blockNum < currentBlock && currentBlock - blockNum <= 256) {
        // Look up block hash from block hashes buffer
        // Each block hash is 32 bytes, stored consecutively
        uint hashIndex = blockNum % maxBlockHashes;
        uint offset = txIdx * maxBlockHashes * 32 + hashIndex * 32;

        for (uint i = 0; i < 8; i++) {
            uint val = 0;
            for (uint j = 0; j < 4; j++) {
                val |= uint(blockHashes[offset + i * 4 + j]) << (j * 8);
            }
            result.limb[i] = M31{val & M31_P};
        }
    }

    return result;
}

// OP_COINBASE (0x41) - Get block beneficiary/coinbase
// Stack: -> address
// Gas: 2
inline M31Word op_coinbase(device const Config* config, uint txIdx) {
    return addressToM31Word(config[txIdx].blockCoinbase);
}

// OP_TIMESTAMP (0x42) - Get block timestamp
// Stack: -> timestamp
// Gas: 2
inline M31Word op_timestamp(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].blockTimestamp);
}

// OP_NUMBER (0x43) - Get block number
// Stack: -> blockNumber
// Gas: 2
inline M31Word op_number(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].blockNumber);
}

// OP_PREVRANDAO (0x44) - Get block prevrandao (was DIFFICULTY pre-merge)
// Stack: -> prevrandao
// Gas: 2
inline M31Word op_prevrandao(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].blockPrevRandao);
}

// OP_GASLIMIT (0x45) - Get block gas limit
// Stack: -> gasLimit
// Gas: 2
inline M31Word op_gaslimit(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].blockGasLimit);
}

// OP_CHAINID (0x46) - Get chain ID
// Stack: -> chainId
// Gas: 2
inline M31Word op_chainid(device const Config* config, uint txIdx) {
    return addressToM31Word(config[txIdx].chainId);
}

// OP_SELFBALANCE (0x47) - Get self balance (cheaper than ADDRESS BALANCE)
// Stack: -> balance
// Gas: 5
inline M31Word op_selfbalance(device const uchar* accountBalances,
                              device const uchar* accountAddresses,
                              device const Config* config,
                              uint txIdx, uint numAccounts) {
    // Get self address and lookup balance
    M31Word address = addressToM31Word(config[txIdx].address);

    // Simplified: return zero balance (actual implementation would lookup account)
    M31Word result;
    for (uint i = 0; i < 8; i++) {
        result.limb[i] = m31_zero();
    }
    return result;
}

// OP_BASEFEE (0x48) - Get block base fee (EIP-1559)
// Stack: -> baseFee
// Gas: 2
inline M31Word op_basefee(device const Config* config, uint txIdx) {
    return uint64_to_m31word(config[txIdx].blockBaseFee);
}

// ============================================================================
// SYSTEM OPCODES IMPLEMENTATION (0xF0-0xFF)
// ============================================================================

// Constant for max call depth
constant uint MAX_CALL_DEPTH = 1024;

// OP_CREATE (0xF0) - Create new contract
// Stack: value offset size -> address
// Gas: 32000 + 200 * code size + gas for deployment
inline M31Word op_create(device TxState* states,
                         device uchar* memory,
                         device uchar* accountAddresses,
                         device uchar* accountCode,
                         device uint* accountCodeSizes,
                         device const Config* config,
                         uint txIdx, uint maxMemory,
                         uint maxAccountCodeSize, uint numAccounts,
                         uint stackPtr) {
    // Pop: size, offset, value from stack
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word valueWord = readStack(stack, txIdx, stackPtr - 3, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Check call depth limit
    if (states[txIdx].callDepth >= MAX_CALL_DEPTH) {
        M31Word result;
        for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
        return result;
    }

    // Simplified: return zero address (actual implementation would create contract)
    M31Word result;
    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
    return result;
}

// OP_CREATE2 (0xF5) - Create new contract with salt
// Stack: value offset size salt -> address
// Gas: 32000 + 200 * code size + gas for deployment + 6 * code word size
inline M31Word op_create2(device TxState* states,
                          device uchar* memory,
                          device uchar* accountAddresses,
                          device uchar* accountCode,
                          device uint* accountCodeSizes,
                          device const Config* config,
                          uint txIdx, uint maxMemory,
                          uint maxAccountCodeSize, uint numAccounts,
                          uint stackPtr) {
    // Pop: salt, size, offset, value from stack
    M31Word saltWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 2, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 3, 1024);
    M31Word valueWord = readStack(stack, txIdx, stackPtr - 4, 1024);

    uint size = sizeWord.limb[0].v;
    uint offset = offsetWord.limb[0].v;

    // Check call depth limit
    if (states[txIdx].callDepth >= MAX_CALL_DEPTH) {
        M31Word result;
        for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
        return result;
    }

    // Simplified: return zero address (actual implementation would create contract with salt)
    M31Word result;
    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
    return result;
}

// OP_CALL (0xF1) - Call contract
// Stack: gas addr value argsOffset argsSize retOffset retSize -> success
// Gas: base 100 + gas for memory expansion + value transfer gas
inline uint64_t op_call_gas(device const Config* config,
                            uint64_t gasAvailable,
                            M31Word valueWord) {
    // Base gas for CALL
    uint64_t baseGas = 100;

    // Add gas for value transfer if value > 0
    // Value transfer costs 9000 gas (cold) or 0 (warm)
    bool hasValue = !m31_is_zero(valueWord.limb[0]);
    if (hasValue) {
        baseGas += 9000;
    }

    return (gasAvailable > baseGas) ? (gasAvailable - baseGas) : 0;
}

// Execute a call to another contract
// Returns 1 on success, 0 on failure
inline uint execute_call(device TxState* states,
                        device uchar* stack,
                        device uchar* memory,
                        device const uchar* accountAddresses,
                        device const uchar* accountCode,
                        device const uint* accountCodeSizes,
                        device const Config* config,
                        uint txIdx, uint maxMemory,
                        uint maxAccountCodeSize, uint numAccounts,
                        uint stackPtr, uint maxStackDepth,
                        bool isDelegateCall, bool isStaticCall) {
    // Check call depth
    if (states[txIdx].callDepth >= MAX_CALL_DEPTH) {
        return 0;
    }

    // Pop: retSize, retOffset, argsSize, argsOffset, value, addr, gas
    M31Word retSizeWord = readStack(stack, txIdx, stackPtr - 1, maxStackDepth);
    M31Word retOffsetWord = readStack(stack, txIdx, stackPtr - 2, maxStackDepth);
    M31Word argsSizeWord = readStack(stack, txIdx, stackPtr - 3, maxStackDepth);
    M31Word argsOffsetWord = readStack(stack, txIdx, stackPtr - 4, maxStackDepth);
    M31Word valueWord = readStack(stack, txIdx, stackPtr - 5, maxStackDepth);
    M31Word addrWord = readStack(stack, txIdx, stackPtr - 6, maxStackDepth);
    M31Word gasWord = readStack(stack, txIdx, stackPtr - 7, maxStackDepth);

    uint retSize = retSizeWord.limb[0].v;
    uint retOffset = retOffsetWord.limb[0].v;
    uint argsSize = argsSizeWord.limb[0].v;
    uint argsOffset = argsOffsetWord.limb[0].v;
    uint gas = gasWord.limb[0].v;

    // Static call disallows state modifications
    if (isStaticCall) {
        bool hasValue = !m31_is_zero(valueWord.limb[0]);
        if (hasValue) {
            return 0;  // Static call cannot send value
        }
    }

    // Simplified: simulate success
    // In a real implementation, this would:
    // 1. Check if target exists
    // 2. Transfer value if value > 0
    // 3. Set up new execution frame
    // 4. Copy args to target's memory
    // 5. Execute target's code
    // 6. Copy return data back

    // For now, return success (1)
    return 1;
}

// OP_CALL (0xF1) - Call contract
// Stack: gas addr value argsOffset argsSize retOffset retSize -> success
inline void op_call(device TxState* states,
                    device uchar* stack,
                    device uchar* memory,
                    device const uchar* accountAddresses,
                    device const uchar* accountCode,
                    device const uint* accountCodeSizes,
                    device const Config* config,
                    uint txIdx, uint maxMemory,
                    uint maxAccountCodeSize, uint numAccounts,
                    uint stackPtr, uint maxStackDepth) {
    // Check stack has 7 items
    if (stackPtr < 7) {
        states[txIdx].running = 0;
        return;
    }

    // Increment call depth
    states[txIdx].callDepth++;

    // Execute the call
    uint success = execute_call(states, stack, memory, accountAddresses,
                                accountCode, accountCodeSizes, config,
                                txIdx, maxMemory, maxAccountCodeSize, numAccounts,
                                stackPtr, maxStackDepth, false, false);

    // Decrement call depth (after call returns)
    if (states[txIdx].callDepth > 0) {
        states[txIdx].callDepth--;
    }

    // Pop all 7 arguments from stack
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);

    // Push success (1) or failure (0)
    M31Word result;
    result.limb[0] = success ? m31_one() : m31_zero();
    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
    stackPush(&states[txIdx], stack, txIdx, maxStackDepth, result);
}

// OP_CALLCODE (0xF2) - Call with code of another contract
// Stack: gas addr value argsOffset argsSize retOffset retSize -> success
// Same as CALL but uses code from target, runs in context of caller
inline void op_callcode(device TxState* states,
                       device uchar* stack,
                       device uchar* memory,
                       device const uchar* accountAddresses,
                       device const uchar* accountCode,
                       device const uint* accountCodeSizes,
                       device const Config* config,
                       uint txIdx, uint maxMemory,
                       uint maxAccountCodeSize, uint numAccounts,
                       uint stackPtr, uint maxStackDepth) {
    // Check stack has 7 items
    if (stackPtr < 7) {
        states[txIdx].running = 0;
        return;
    }

    // Increment call depth
    states[txIdx].callDepth++;

    // Execute the call (callcode variant - doesn't change msg.sender or msg.value)
    uint success = execute_call(states, stack, memory, accountAddresses,
                                accountCode, accountCodeSizes, config,
                                txIdx, maxMemory, maxAccountCodeSize, numAccounts,
                                stackPtr, maxStackDepth, false, false);

    // Decrement call depth
    if (states[txIdx].callDepth > 0) {
        states[txIdx].callDepth--;
    }

    // Pop all 7 arguments from stack
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);

    // Push success (1) or failure (0)
    M31Word result;
    result.limb[0] = success ? m31_one() : m31_zero();
    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
    stackPush(&states[txIdx], stack, txIdx, maxStackDepth, result);
}

// OP_DELEGATECALL (0xF4) - Delegate call
// Stack: gas addr argsOffset argsSize retOffset retSize -> success
// Same as CALL but doesn't change msg.value or msg.sender
inline void op_delegatecall(device TxState* states,
                            device uchar* stack,
                            device uchar* memory,
                            device const uchar* accountAddresses,
                            device const uchar* accountCode,
                            device const uint* accountCodeSizes,
                            device const Config* config,
                            uint txIdx, uint maxMemory,
                            uint maxAccountCodeSize, uint numAccounts,
                            uint stackPtr, uint maxStackDepth) {
    // Check stack has 6 items (no value parameter)
    if (stackPtr < 6) {
        states[txIdx].running = 0;
        return;
    }

    // Increment call depth
    states[txIdx].callDepth++;

    // Execute the call (delegatecall variant)
    uint success = execute_call(states, stack, memory, accountAddresses,
                                accountCode, accountCodeSizes, config,
                                txIdx, maxMemory, maxAccountCodeSize, numAccounts,
                                stackPtr, maxStackDepth, true, false);

    // Decrement call depth
    if (states[txIdx].callDepth > 0) {
        states[txIdx].callDepth--;
    }

    // Pop all 6 arguments from stack
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);

    // Push success (1) or failure (0)
    M31Word result;
    result.limb[0] = success ? m31_one() : m31_zero();
    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
    stackPush(&states[txIdx], stack, txIdx, maxStackDepth, result);
}

// OP_STATICCALL (0xFA) - Static call (no state modification)
// Stack: gas addr argsOffset argsSize retOffset retSize -> success
inline void op_staticcall(device TxState* states,
                          device uchar* stack,
                          device uchar* memory,
                          device const uchar* accountAddresses,
                          device const uchar* accountCode,
                          device const uint* accountCodeSizes,
                          device const Config* config,
                          uint txIdx, uint maxMemory,
                          uint maxAccountCodeSize, uint numAccounts,
                          uint stackPtr, uint maxStackDepth) {
    // Check stack has 6 items (no value parameter)
    if (stackPtr < 6) {
        states[txIdx].running = 0;
        return;
    }

    // Increment call depth
    states[txIdx].callDepth++;

    // Execute the call (static variant - disallows state modifications)
    uint success = execute_call(states, stack, memory, accountAddresses,
                                accountCode, accountCodeSizes, config,
                                txIdx, maxMemory, maxAccountCodeSize, numAccounts,
                                stackPtr, maxStackDepth, false, true);

    // Decrement call depth
    if (states[txIdx].callDepth > 0) {
        states[txIdx].callDepth--;
    }

    // Pop all 6 arguments from stack
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);
    stackPop(&states[txIdx], stack, txIdx, maxStackDepth);

    // Push success (1) or failure (0)
    M31Word result;
    result.limb[0] = success ? m31_one() : m31_zero();
    for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
    stackPush(&states[txIdx], stack, txIdx, maxStackDepth, result);
}

// OP_REVERT (0xFD) - Halt and revert
// Stack: offset size ->
// Same as RETURN but sets reverted flag
inline void op_revert(device TxState* states,
                      device uchar* memory,
                      uint txIdx, uint maxMemory,
                      uint stackPtr) {
    // Pop size and offset
    M31Word sizeWord = readStack(stack, txIdx, stackPtr - 1, 1024);
    M31Word offsetWord = readStack(stack, txIdx, stackPtr - 2, 1024);

    // Set reverted flag
    states[txIdx].reverted = 1;

    // Stop execution
    states[txIdx].running = 0;
}

// OP_SELFDESTRUCT (0xFF) - Self-destruct
// Stack: recipient ->
// Gas: base 5000 + 25000 if destination is not existing
inline void op_selfdestruct(device TxState* states,
                            device uchar* memory,
                            device uchar* accountBalances,
                            device const Config* config,
                            uint txIdx, uint stackPtr) {
    // Pop recipient from stack
    M31Word recipientWord = readStack(stack, txIdx, stackPtr - 1, 1024);

    // Mark account for destruction
    // In a real implementation, this would:
    // 1. Check if beneficiary exists
    // 2. Transfer balance to beneficiary
    // 3. Mark contract for self-destruction

    // Stop execution (EIP-6780: SELFDESTRUCT only in same transaction)
    states[txIdx].running = 0;
}

// ============================================================================
// MAIN EVM EXECUTION LOOP
// ============================================================================

kernel void evm_main_loop(
    device TxState* states            [[buffer(0)]],
    device uchar* stack               [[buffer(1)]],
    device uchar* memory              [[buffer(2)]],
    device const uchar* code          [[buffer(3)]],
    device TraceRow* trace            [[buffer(4)]],
    device const Config* config       [[buffer(5)]],
    device const uchar* calldata      [[buffer(6)]],
    device const uchar* returndata    [[buffer(7)]],
    device const uchar* accountAddresses [[buffer(8)]],
    device const uchar* accountBalances  [[buffer(9)]],
    device const uchar* accountCodeHashes [[buffer(10)]],
    device const uint* accountCodeSizes   [[buffer(11)]],
    device const uchar* accountCode       [[buffer(12)]],
    device const uchar* blockHashes       [[buffer(21)]],
    constant uint& numTxs             [[buffer(13)]],
    constant uint& maxStackDepth       [[buffer(14)]],
    constant uint& maxMemory           [[buffer(15)]],
    constant uint& maxCodeSize         [[buffer(16)]],
    constant uint& maxTraceRows        [[buffer(17)]],
    constant uint& maxCalldataSize     [[buffer(18)]],
    constant uint& maxReturnDataSize   [[buffer(19)]],
    constant uint& numAccounts         [[buffer(20)]],
    constant uint& maxBlockHashes      [[buffer(22)]],
    uint gid                           [[thread_position_in_grid]]
) {
    if (gid >= numTxs) return;

    TxState state = states[gid];
    uint traceIdx = 0;
    uint maxSteps = 10000;  // Limit iterations per transaction

    // Initialize state from config
    state.gas = uint(config[gid].gasLimit);
    state.pc = 0;
    state.stackPtr = 0;
    state.memoryPtr = 0;
    state.running = 1;
    state.reverted = 0;
    state.callDepth = 0;
    state.calldataSize = config[gid].calldataSize;
    state.returndataSize = config[gid].returndataSize;
    states[gid] = state;

    // Main execution loop
    while (state.running && traceIdx < maxSteps) {
        uchar opcode = readCode(code, gid, maxCodeSize, state.pc);

        // Record trace row before execution
        if (traceIdx < maxTraceRows) {
            uint baseTrace = gid * maxTraceRows + traceIdx;
            trace[baseTrace].pc = state.pc;
            trace[baseTrace].opcode = opcode;
            trace[baseTrace].gas = state.gas;
            trace[baseTrace].stackHeight = state.stackPtr;
            trace[baseTrace].memorySize = state.memoryPtr;
            trace[baseTrace].callDepth = state.callDepth;
            trace[baseTrace].isRunning = state.running;
            trace[baseTrace].isReverted = state.reverted;
        }

        state.pc++;
        state.gas -= 3;  // Base gas cost

        // Execute opcode
        switch (opcode) {
            case OP_STOP:
                state.running = 0;
                break;

            // =============================================================
            // ENVIRONMENTAL OPCODES (0x30-0x3F)
            // =============================================================

            case OP_ADDRESS: {
                // Stack: -> address
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_address(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_BALANCE: {
                // Stack: address -> balance
                if (state.stackPtr < 1) { state.running = 0; break; }
                M31Word address = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result = op_balance(accountBalances, accountAddresses, config, gid, numAccounts, address);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_ORIGIN: {
                // Stack: -> origin
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_origin(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CALLER: {
                // Stack: -> caller
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_caller(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CALLVALUE: {
                // Stack: -> value
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_callvalue(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CALLDATALOAD: {
                // Stack: offset -> value
                if (state.stackPtr < 1) { state.running = 0; break; }
                M31Word result = op_calldataload(calldata, config, gid, state.stackPtr, stack);
                stackPop(&states[gid], stack, gid, maxStackDepth);  // Pop offset
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CALLDATASIZE: {
                // Stack: -> size
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_calldatasize(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CALLDATACOPY: {
                // Stack: destOffset offset size ->
                if (state.stackPtr < 3) { state.running = 0; break; }
                op_calldatacopy(memory, &states[gid], calldata, config, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_CODESIZE: {
                // Stack: -> size
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_codesize(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CODECOPY: {
                // Stack: destOffset offset size ->
                if (state.stackPtr < 3) { state.running = 0; break; }
                op_codecopy(memory, &states[gid], code, config, gid, maxMemory, maxCodeSize, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_GASPRICE: {
                // Stack: -> gasprice
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_gasprice(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_EXTCODESIZE: {
                // Stack: address -> size
                if (state.stackPtr < 1) { state.running = 0; break; }
                M31Word address = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result = op_extcodesize(config, accountAddresses, accountCodeSizes, gid, numAccounts, address);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_EXTCODECOPY: {
                // Stack: address destOffset offset size ->
                if (state.stackPtr < 4) { state.running = 0; break; }
                op_extcodecopy(memory, &states[gid], accountAddresses, accountCode, accountCodeSizes,
                               config, gid, maxMemory, maxCodeSize, numAccounts, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_RETURNDATASIZE: {
                // Stack: -> size
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_returndatasize(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_RETURNDATACOPY: {
                // Stack: destOffset offset size ->
                if (state.stackPtr < 3) { state.running = 0; break; }
                op_returndatacopy(memory, &states[gid], returndata, config, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_EXTCODEHASH: {
                // Stack: address -> hash
                if (state.stackPtr < 1) { state.running = 0; break; }
                M31Word address = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result = op_extcodehash(config, accountAddresses, accountCodeHashes, gid, numAccounts, address);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // =============================================================
            // BLOCK OPCODES (0x40-0x48)
            // =============================================================

            case OP_BLOCKHASH: {
                // Stack: blockNumber -> hash
                if (state.stackPtr < 1) { state.running = 0; break; }
                M31Word blockNumber = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result = op_blockhash(blockHashes, config, gid, maxBlockHashes, blockNumber);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_COINBASE: {
                // Stack: -> address
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_coinbase(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_TIMESTAMP: {
                // Stack: -> timestamp
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_timestamp(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_NUMBER: {
                // Stack: -> blockNumber
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_number(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_PREVRANDAO: {
                // Stack: -> prevrandao
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_prevrandao(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_GASLIMIT: {
                // Stack: -> gasLimit
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_gaslimit(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CHAINID: {
                // Stack: -> chainId
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_chainid(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_SELFBALANCE: {
                // Stack: -> balance
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_selfbalance(accountBalances, accountAddresses, config, gid, numAccounts);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_BASEFEE: {
                // Stack: -> baseFee
                if (state.stackPtr >= 1024) { state.running = 0; break; }
                M31Word result = op_basefee(config, gid);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // =============================================================
            // EXISTING OPCODES (for reference)
            // =============================================================

            case OP_ADD: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_add(a.limb[i], b.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_SUB: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_sub(a.limb[i], b.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_MUL: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_mul(a.limb[i], b.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_DIV: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPush(&states[gid], stack, gid, maxStackDepth, M31Word{});
                break;
            }

            case OP_MOD: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPush(&states[gid], stack, gid, maxStackDepth, M31Word{});
                break;
            }

            // SDIV (0x05) - Signed integer division
            case OP_SDIV: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                if (m31word_is_zero(b)) {
                    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                } else {
                    uint64_t aVal = 0, bVal = 0;
                    for (uint i = 0; i < 8; i++) {
                        aVal |= uint64_t(a.limb[i].v) << (i * 31);
                        bVal |= uint64_t(b.limb[i].v) << (i * 31);
                    }
                    bool aNeg = m31word_is_negative(a);
                    bool bNeg = m31word_is_negative(b);
                    if (aNeg) aVal = ~aVal + 1;
                    if (bNeg) bVal = ~bVal + 1;
                    uint64_t res = (bVal != 0) ? (aVal / bVal) : 0;
                    if (aNeg ^ bNeg) res = ~res + 1;
                    result = uint64_to_m31word(res);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_LT: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                result.limb[0] = m31_lt(a.limb[0], b.limb[0]) ? m31_one() : m31_zero();
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // SMOD (0x07) - Signed modulo
            case OP_SMOD: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                if (m31word_is_zero(b)) {
                    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                } else {
                    uint64_t aVal = 0, bVal = 0;
                    for (uint i = 0; i < 8; i++) {
                        aVal |= uint64_t(a.limb[i].v) << (i * 31);
                        bVal |= uint64_t(b.limb[i].v) << (i * 31);
                    }
                    bool aNeg = m31word_is_negative(a);
                    if (aNeg) aVal = ~aVal + 1;
                    if (bVal != 0) {
                        uint64_t rem = aVal % bVal;
                        if (aNeg) rem = ~rem + 1;
                        result = uint64_to_m31word(rem);
                    } else {
                        result = uint64_to_m31word(aNeg ? (~aVal + 1) : aVal);
                    }
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // ADDMOD (0x08) - Modular addition
            case OP_ADDMOD: {
                if (state.stackPtr < 3) { state.running = 0; break; }
                M31Word c = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                if (m31word_is_zero(c)) {
                    M31Word result;
                    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                } else {
                    uint64_t aVal = 0, bVal = 0, cVal = 0;
                    for (uint i = 0; i < 8; i++) {
                        aVal |= uint64_t(a.limb[i].v) << (i * 31);
                        bVal |= uint64_t(b.limb[i].v) << (i * 31);
                        cVal |= uint64_t(c.limb[i].v) << (i * 31);
                    }
                    uint64_t res = (aVal + bVal) % cVal;
                    M31Word result = uint64_to_m31word(res);
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                }
                break;
            }

            // MULMOD (0x09) - Modular multiplication
            case OP_MULMOD: {
                if (state.stackPtr < 3) { state.running = 0; break; }
                M31Word c = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                if (m31word_is_zero(c)) {
                    M31Word result;
                    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                } else {
                    uint64_t aVal = 0, bVal = 0, cVal = 0;
                    for (uint i = 0; i < 8; i++) {
                        aVal |= uint64_t(a.limb[i].v) << (i * 31);
                        bVal |= uint64_t(b.limb[i].v) << (i * 31);
                        cVal |= uint64_t(c.limb[i].v) << (i * 31);
                    }
                    uint64_t res = (aVal * bVal) % cVal;
                    M31Word result = uint64_to_m31word(res);
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                }
                break;
            }

            case OP_GT: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                result.limb[0] = m31_gt(a.limb[0], b.limb[0]) ? m31_one() : m31_zero();
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // SLT (0x12) - Signed less than
            case OP_SLT: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                bool aNeg = m31word_is_negative(a);
                bool bNeg = m31word_is_negative(b);
                M31Word result;
                result.limb[0] = m31_zero();
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                if (aNeg != bNeg) {
                    result.limb[0] = aNeg ? m31_one() : m31_zero();
                } else {
                    bool lt = false;
                    for (int i = 7; i >= 0; i--) {
                        if (a.limb[i].v < b.limb[i].v) { lt = true; break; }
                        if (a.limb[i].v > b.limb[i].v) { lt = false; break; }
                    }
                    result.limb[0] = lt ? m31_one() : m31_zero();
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // SGT (0x13) - Signed greater than
            case OP_SGT: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                bool aNeg = m31word_is_negative(a);
                bool bNeg = m31word_is_negative(b);
                M31Word result;
                result.limb[0] = m31_zero();
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                if (aNeg != bNeg) {
                    result.limb[0] = aNeg ? m31_zero() : m31_one();
                } else {
                    bool gt = false;
                    for (int i = 7; i >= 0; i--) {
                        if (a.limb[i].v > b.limb[i].v) { gt = true; break; }
                        if (a.limb[i].v < b.limb[i].v) { gt = false; break; }
                    }
                    result.limb[0] = gt ? m31_one() : m31_zero();
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_EQ: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                bool eq = true;
                for (uint i = 0; i < 8; i++) {
                    if (a.limb[i].v != b.limb[i].v) { eq = false; break; }
                }
                result.limb[0] = eq ? m31_one() : m31_zero();
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_ISZERO: {
                if (state.stackPtr < 1) { state.running = 0; break; }
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                bool isZero = true;
                for (uint i = 0; i < 8; i++) {
                    if (a.limb[i].v != 0) { isZero = false; break; }
                }
                result.limb[0] = isZero ? m31_one() : m31_zero();
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // SIGNEXTEND (0x0B) - Sign extend
            case OP_SIGNEXTEND: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word b = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word a = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint byteIdx = b.limb[0].v;
                if (byteIdx < 32) {
                    uchar aBytes[32];
                    m31word_to_bytes(a, aBytes);
                    uchar signBit = (aBytes[byteIdx] & 0x80) != 0 ? 0xFF : 0x00;
                    for (uint i = byteIdx + 1; i < 32; i++) {
                        aBytes[i] = signBit;
                    }
                    for (uint i = 0; i < 8; i++) {
                        uint val = 0;
                        for (uint j = 0; j < 4; j++) {
                            val |= uint(aBytes[i * 4 + j]) << (j * 8);
                        }
                        a.limb[i] = M31{val & M31_P};
                    }
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, a);
                break;
            }

            // BYTE (0x1A) - Extract byte
            case OP_BYTE: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word index = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word value = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint byteIdx = index.limb[0].v;
                uchar byteVal = m31word_get_byte(value, byteIdx);
                M31Word result;
                result.limb[0] = M31{uint(byteVal)};
                for (uint i = 1; i < 8; i++) result.limb[i] = m31_zero();
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // SHL (0x1B) - Shift left (EIP-145, Byzantium)
            case OP_SHL: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word shift = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word value = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint shiftAmt = shift.limb[0].v & 0xFF;
                if (shiftAmt == 0) {
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                } else if (shiftAmt >= 256) {
                    M31Word result;
                    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                } else {
                    uchar bytes[32];
                    m31word_to_bytes(value, bytes);
                    uint byteShift = shiftAmt / 8;
                    uint bitShift = shiftAmt % 8;
                    uchar resultBytes[32];
                    for (uint i = 0; i < 32; i++) resultBytes[i] = 0;
                    for (int i = 31; i >= 0; i--) {
                        int srcIdx = i - int(byteShift);
                        if (srcIdx >= 0) {
                            uint16_t val = uint16_t(bytes[srcIdx]) << bitShift;
                            resultBytes[i] = uchar(val & 0xFF);
                            if (srcIdx > 0 && bitShift != 0) {
                                uint16_t overflow = uint16_t(bytes[srcIdx - 1]) >> (8 - bitShift);
                                resultBytes[i] |= uchar(overflow & 0xFF);
                            }
                        }
                    }
                    for (uint i = 0; i < 8; i++) {
                        uint val = 0;
                        for (uint j = 0; j < 4; j++) {
                            val |= uint(resultBytes[i * 4 + j]) << (j * 8);
                        }
                        value.limb[i] = M31{val & M31_P};
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                }
                break;
            }

            // SHR (0x1C) - Logical shift right (EIP-145, Byzantium)
            case OP_SHR: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word shift = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word value = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint shiftAmt = shift.limb[0].v & 0xFF;
                if (shiftAmt == 0) {
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                } else if (shiftAmt >= 256) {
                    M31Word result;
                    for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                } else {
                    uchar bytes[32];
                    m31word_to_bytes(value, bytes);
                    uint byteShift = shiftAmt / 8;
                    uint bitShift = shiftAmt % 8;
                    uchar resultBytes[32];
                    for (uint i = 0; i < 32; i++) resultBytes[i] = 0;
                    for (int i = 0; i < 32; i++) {
                        uint srcIdx = i + byteShift;
                        if (srcIdx < 32) {
                            uint16_t val = uint16_t(bytes[srcIdx]) >> bitShift;
                            resultBytes[i] = uchar(val & 0xFF);
                            if (srcIdx + 1 < 32 && bitShift != 0) {
                                uint16_t overflow = uint16_t(bytes[srcIdx + 1]) << (8 - bitShift);
                                resultBytes[i] |= uchar(overflow & 0xFF);
                            }
                        }
                    }
                    for (uint i = 0; i < 8; i++) {
                        uint val = 0;
                        for (uint j = 0; j < 4; j++) {
                            val |= uint(resultBytes[i * 4 + j]) << (j * 8);
                        }
                        value.limb[i] = M31{val & M31_P};
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                }
                break;
            }

            // SAR (0x1D) - Arithmetic shift right (EIP-232, Byzantium)
            case OP_SAR: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word shift = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word value = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint shiftAmt = shift.limb[0].v & 0xFF;
                bool valueNeg = m31word_is_negative(value);
                if (shiftAmt == 0) {
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                } else if (shiftAmt >= 256) {
                    M31Word result;
                    if (valueNeg) {
                        for (uint i = 0; i < 8; i++) result.limb[i] = M31{M31_P};
                    } else {
                        for (uint i = 0; i < 8; i++) result.limb[i] = m31_zero();
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, result);
                } else {
                    uchar bytes[32];
                    m31word_to_bytes(value, bytes);
                    uint byteShift = shiftAmt / 8;
                    uint bitShift = shiftAmt % 8;
                    uchar signBit = valueNeg ? 0xFF : 0x00;
                    uchar resultBytes[32];
                    for (uint i = 0; i < 32; i++) resultBytes[i] = signBit;
                    for (int i = 0; i < 32; i++) {
                        uint srcIdx = i + byteShift;
                        if (srcIdx < 32) {
                            uint16_t val = uint16_t(bytes[srcIdx]) >> bitShift;
                            resultBytes[i] = uchar(val & 0xFF);
                            if (srcIdx + 1 < 32 && bitShift != 0) {
                                uint16_t overflow = uint16_t(bytes[srcIdx + 1]) << (8 - bitShift);
                                resultBytes[i] |= uchar(overflow & 0xFF);
                            }
                        }
                    }
                    for (uint i = 0; i < 8; i++) {
                        uint val = 0;
                        for (uint j = 0; j < 4; j++) {
                            val |= uint(resultBytes[i * 4 + j]) << (j * 8);
                        }
                        value.limb[i] = M31{val & M31_P};
                    }
                    stackPush(&states[gid], stack, gid, maxStackDepth, value);
                }
                break;
            }

            case OP_AND: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_and(a.limb[i], b.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_OR: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_or(a.limb[i], b.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_XOR: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                auto b = stackPop(&states[gid], stack, gid, maxStackDepth);
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_xor(a.limb[i], b.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_NOT: {
                if (state.stackPtr < 1) { state.running = 0; break; }
                auto a = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word result;
                for (uint i = 0; i < 8; i++) {
                    result.limb[i] = m31_not(a.limb[i]);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_PUSH0:
                stackPush(&states[gid], stack, gid, maxStackDepth, M31Word{});
                break;

            case OP_PUSH1:
            case OP_PUSH2:
            case OP_PUSH3:
            case OP_PUSH4:
            case OP_PUSH5:
            case OP_PUSH6:
            case OP_PUSH7:
            case OP_PUSH8:
            case OP_PUSH9:
            case OP_PUSH10:
            case OP_PUSH11:
            case OP_PUSH12:
            case OP_PUSH13:
            case OP_PUSH14:
            case OP_PUSH15:
            case OP_PUSH16:
            case OP_PUSH17:
            case OP_PUSH18:
            case OP_PUSH19:
            case OP_PUSH20:
            case OP_PUSH21:
            case OP_PUSH22:
            case OP_PUSH23:
            case OP_PUSH24:
            case OP_PUSH25:
            case OP_PUSH26:
            case OP_PUSH27:
            case OP_PUSH28:
            case OP_PUSH29:
            case OP_PUSH30:
            case OP_PUSH31:
            case OP_PUSH32: {
                uint pushBytes = opcode - OP_PUSH1 + 1;
                M31Word value = readImmediate(code, gid, maxCodeSize, state.pc, pushBytes);
                state.pc += pushBytes;
                stackPush(&states[gid], stack, gid, maxStackDepth, value);
                break;
            }

            case OP_POP:
                if (state.stackPtr < 1) { state.running = 0; break; }
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;

            case OP_MLOAD: {
                if (state.stackPtr < 1) { state.running = 0; break; }
                M31Word offset = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint memOffset = offset.limb[0].v;
                M31Word value = memoryLoadWord(memory, gid, maxMemory, memOffset);
                stackPush(&states[gid], stack, gid, maxStackDepth, value);
                break;
            }

            case OP_MSTORE: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word value = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word offset = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint memOffset = offset.limb[0].v;
                memoryStoreWord(memory, &states[gid], gid, maxMemory, memOffset, value);
                break;
            }

            case OP_JUMPDEST:
                // No-op, just a valid jump target
                break;

            case OP_JUMP: {
                if (state.stackPtr < 1) { state.running = 0; break; }
                stackPop(&states[gid], stack, gid, maxStackDepth);
                state.pc += 10;  // Simplified jump
                break;
            }

            case OP_JUMPI: {
                if (state.stackPtr < 2) { state.running = 0; break; }
                stackPop(&states[gid], stack, gid, maxStackDepth);
                auto cond = stackPop(&states[gid], stack, gid, maxStackDepth);
                if (!m31_is_zero(cond.limb[0])) {
                    state.pc += 10;  // Simplified conditional jump
                }
                break;
            }

            case OP_RETURN:
            case OP_REVERT:
                state.running = 0;
                if (opcode == OP_REVERT) {
                    state.reverted = 1;
                }
                break;

            // =============================================================
            // EXTENDED ARITHMETIC OPCODES
            // =============================================================

            case OP_EXP: {
                // Stack: base exponent -> result
                // Gas: 50 * floor(log256(exponent)) + 10
                if (state.stackPtr < 2) { state.running = 0; break; }
                M31Word exponent = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word base = stackPop(&states[gid], stack, gid, maxStackDepth);

                // Calculate dynamic gas: 50 * floor(log256(exponent)) + 10
                // Find the byte position of the highest non-zero byte (MSB)
                uint msbPos = 0;
                for (uint i = 32; i > 0; i--) {
                    uchar b = m31word_get_byte(exponent, i - 1);
                    if (b != 0) {
                        msbPos = i;
                        break;
                    }
                }

                // Gas: 50 * (msbPos - 1) + 10, minimum 10 if exponent > 0
                uint dynamicGas = (msbPos > 0) ? (50 * (msbPos - 1) + 10) : 10;
                if (state.gas < dynamicGas) {
                    state.running = 0;
                    break;
                }
                state.gas -= dynamicGas;

                // If base is 0 and exponent is 0, result is 1 (by convention 0^0 = 1)
                // If base is 0 and exponent > 0, result is 0
                M31Word result;
                if (m31word_is_zero(base)) {
                    // Return 0 (standard EVM behavior for 0^e where e > 0)
                    for (uint i = 0; i < 8; i++) {
                        result.limb[i] = m31_zero();
                    }
                    // Special case: 0^0 = 1 in EVM (according to some interpretations)
                    // But most implementations return 1 for EXP(0,0)
                    if (m31word_is_zero(exponent)) {
                        result.limb[0] = m31_one();
                    }
                } else if (m31word_is_zero(exponent)) {
                    // Any base ^ 0 = 1
                    result.limb[0] = m31_one();
                    for (uint i = 1; i < 8; i++) {
                        result.limb[i] = m31_zero();
                    }
                } else {
                    // Compute base^exponent mod 2^256
                    result = m31word_exp(base, exponent);
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            // =============================================================
            // EOF OPCODES (0xE0-0xEF) - Only valid in EOF-format contracts
            // =============================================================

            case OP_RJUMP: {
                // Relative jump (unconditional) - immediate jump offset
                // Stack: -> (consumes nothing, jump offset is immediate)
                // Gas: 2
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                // Read 16-bit signed immediate offset (2 bytes)
                uint offset = state.pc;
                uchar byte0 = readCode(code, gid, maxCodeSize, offset);
                uchar byte1 = readCode(code, gid, maxCodeSize, offset + 1);
                int16_t jumpOffset = int16_t(byte0) | (int16_t(byte1) << 8);
                // Sign extend if needed (jumpOffset is 16-bit signed)
                if (jumpOffset & 0x8000) {
                    jumpOffset |= 0xFFFF0000;
                }
                state.pc += 2;  // Advance past the immediate data
                state.pc = state.pc + uint(int32_t(jumpOffset));
                break;
            }

            case OP_RJUMPI: {
                // Relative jump (conditional)
                // Stack: cond ->
                // Gas: 2 + 4 if condition is true
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                M31Word cond = stackPop(&states[gid], stack, gid, maxStackDepth);

                // Read 16-bit signed immediate offset (2 bytes)
                uint offset = state.pc;
                uchar byte0 = readCode(code, gid, maxCodeSize, offset);
                uchar byte1 = readCode(code, gid, maxCodeSize, offset + 1);
                int16_t jumpOffset = int16_t(byte0) | (int16_t(byte1) << 8);
                if (jumpOffset & 0x8000) {
                    jumpOffset |= 0xFFFF0000;
                }
                state.pc += 2;  // Advance past the immediate data

                if (!m31word_is_zero(cond)) {
                    state.gas -= 4;
                    state.pc = state.pc + uint(int32_t(jumpOffset));
                }
                break;
            }

            case OP_RJUMPV: {
                // Relative jump with table
                // Stack: index ->
                // Gas: 2 + table size
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                M31Word indexWord = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint index = indexWord.limb[0].v;

                // Read table size (1 byte)
                uint tableSize = readCode(code, gid, maxCodeSize, state.pc);
                state.pc += 1;

                // Read jump table entries
                if (index <= tableSize) {
                    uchar byte0 = readCode(code, gid, maxCodeSize, state.pc + index * 2);
                    uchar byte1 = readCode(code, gid, maxCodeSize, state.pc + index * 2 + 1);
                    int16_t jumpOffset = int16_t(byte0) | (int16_t(byte1) << 8);
                    if (jumpOffset & 0x8000) {
                        jumpOffset |= 0xFFFF0000;
                    }
                    state.pc += (tableSize + 1) * 2;  // Advance past jump table
                    state.pc = state.pc + uint(int32_t(jumpOffset));
                } else {
                    // Invalid index - jump to abort (PC after table)
                    state.pc += (tableSize + 1) * 2;
                }
                break;
            }

            case OP_CALLF: {
                // Call function
                // Stack: argsOffset argsSize retOffset retSize ->
                // Gas: 2 + memory expansion
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                // Read 16-bit function index (2 bytes immediate)
                uchar byte0 = readCode(code, gid, maxCodeSize, state.pc);
                uchar byte1 = readCode(code, gid, maxCodeSize, state.pc + 1);
                uint16_t funcIdx = uint16_t(byte0) | (uint16_t(byte1) << 8);
                state.pc += 2;

                // Simplified: just push return PC for now
                // In full EOF, this would manage a call stack
                M31Word returnPc;
                returnPc.limb[0] = M31{state.pc & M31_P};
                returnPc.limb[1] = M31{(state.pc >> 31) & M31_P};
                for (uint i = 2; i < 8; i++) {
                    returnPc.limb[i] = m31_zero();
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, returnPc);

                // Jump to function (simplified - would need code section lookup)
                state.pc = funcIdx * 32;  // Simplified function address
                break;
            }

            case OP_RETF: {
                // Return from function
                // Stack: retOffset retSize ->
                // Gas: 2 + memory read
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                // Pop return data location (we'd copy to memory in real impl)
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);

                // Pop return PC from stack
                M31Word returnPc = stackPop(&states[gid], stack, gid, maxStackDepth);
                state.pc = returnPc.limb[0].v | (returnPc.limb[1].v << 31);
                break;
            }

            case OP_JUMPF: {
                // Jump to function (unconditional)
                // Stack: funcIdx ->
                // Gas: 2
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                M31Word funcIdxWord = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint16_t funcIdx = uint16_t(funcIdxWord.limb[0].v);

                // Jump to function (simplified)
                state.pc = funcIdx * 32;
                break;
            }

            // =============================================================
            // EOF STACK OPERATIONS (0xE8-0xEF)
            // =============================================================

            case OP_DUPN: {
                // Duplicate Nth stack item
                // Stack: ... -> ... value
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                // Read immediate stack height (1 byte)
                uint n = readCode(code, gid, maxCodeSize, state.pc);
                state.pc += 1;

                if (state.stackPtr < n + 1) { state.running = 0; break; }
                M31Word value = readStack(stack, gid, state.stackPtr - 1 - n, maxStackDepth);
                stackPush(&states[gid], stack, gid, maxStackDepth, value);
                break;
            }

            case OP_SWAPN: {
                // Swap with Nth stack item
                // Stack: ... value -> value ...
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                // Read immediate stack height (1 byte)
                uint n = readCode(code, gid, maxCodeSize, state.pc);
                state.pc += 1;

                if (state.stackPtr < n + 2) { state.running = 0; break; }
                uint pos1 = state.stackPtr - 1;
                uint pos2 = state.stackPtr - 1 - n;

                M31Word val1 = readStack(stack, gid, pos1, maxStackDepth);
                M31Word val2 = readStack(stack, gid, pos2, maxStackDepth);
                writeStack(stack, gid, pos1, maxStackDepth, val2);
                writeStack(stack, gid, pos2, maxStackDepth, val1);
                break;
            }

            case OP_MSTORESIZE: {
                // Resize memory
                // Stack: size ->
                // Gas: 2 + memory expansion
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 2) { state.running = 0; break; }
                state.gas -= 2;

                M31Word sizeWord = stackPop(&states[gid], stack, gid, maxStackDepth);
                uint newSize = sizeWord.limb[0].v;

                // Memory expansion gas (3 words = 96 bytes base, then quadratic)
                uint currentSize = states[gid].memoryPtr;
                if (newSize > currentSize) {
                    uint words = (newSize + 31) / 32;
                    uint currentWords = (currentSize + 31) / 32;
                    uint gasCost = 3 * words + (words * words / 512);
                    if (state.gas < gasCost) { state.running = 0; break; }
                    state.gas -= gasCost;
                }

                memoryExpand(&states[gid], memory, gid, maxMemory, 0, newSize);
                M31Word result;
                result.limb[0] = M31{currentSize & M31_P};
                for (uint i = 1; i < 8; i++) {
                    result.limb[i] = m31_zero();
                }
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_TRACKSTORAGE: {
                // Track storage slot
                // Stack: slot value ->
                // Gas: 20 (cold) or 5 (warm)
                // Only valid in EOF contracts
                if (!config[gid].isEofEnabled) { state.running = 0; break; }
                if (state.gas < 20) { state.running = 0; break; }
                state.gas -= 20;

                M31Word value = stackPop(&states[gid], stack, gid, maxStackDepth);
                M31Word slot = stackPop(&states[gid], stack, gid, maxStackDepth);

                // Simplified: just push the value back as "stored" confirmation
                // Real implementation would update storage trie
                stackPush(&states[gid], stack, gid, maxStackDepth, value);
                break;
            }

            // =============================================================
            // SYSTEM OPCODES (0xF0-0xFF)
            // =============================================================

            case OP_CREATE: {
                // Stack: value offset size -> address
                if (state.stackPtr < 3) { state.running = 0; break; }
                M31Word result = op_create(&states[gid], memory, accountAddresses,
                                           accountCode, accountCodeSizes,
                                           config, gid, maxMemory,
                                           maxCodeSize, numAccounts, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CREATE2: {
                // Stack: value offset size salt -> address
                if (state.stackPtr < 4) { state.running = 0; break; }
                M31Word result = op_create2(&states[gid], memory, accountAddresses,
                                           accountCode, accountCodeSizes,
                                           config, gid, maxMemory,
                                           maxCodeSize, numAccounts, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPush(&states[gid], stack, gid, maxStackDepth, result);
                break;
            }

            case OP_CALL: {
                // Stack: gas addr value argsOffset argsSize retOffset retSize -> success
                if (state.stackPtr < 7) { state.running = 0; break; }
                op_call(&states[gid], stack, memory, accountAddresses,
                        accountCode, accountCodeSizes, config,
                        gid, maxMemory, maxCodeSize, numAccounts,
                        state.stackPtr, maxStackDepth);
                break;
            }

            case OP_CALLCODE: {
                // Stack: gas addr value argsOffset argsSize retOffset retSize -> success
                if (state.stackPtr < 7) { state.running = 0; break; }
                op_callcode(&states[gid], stack, memory, accountAddresses,
                            accountCode, accountCodeSizes, config,
                            gid, maxMemory, maxCodeSize, numAccounts,
                            state.stackPtr, maxStackDepth);
                break;
            }

            case OP_DELEGATECALL: {
                // Stack: gas addr argsOffset argsSize retOffset retSize -> success
                if (state.stackPtr < 6) { state.running = 0; break; }
                op_delegatecall(&states[gid], stack, memory, accountAddresses,
                               accountCode, accountCodeSizes, config,
                               gid, maxMemory, maxCodeSize, numAccounts,
                               state.stackPtr, maxStackDepth);
                break;
            }

            case OP_STATICCALL: {
                // Stack: gas addr argsOffset argsSize retOffset retSize -> success
                if (state.stackPtr < 6) { state.running = 0; break; }
                op_staticcall(&states[gid], stack, memory, accountAddresses,
                              accountCode, accountCodeSizes, config,
                              gid, maxMemory, maxCodeSize, numAccounts,
                              state.stackPtr, maxStackDepth);
                break;
            }

            case OP_REVERT: {
                // Stack: offset size ->
                if (state.stackPtr < 2) { state.running = 0; break; }
                op_revert(&states[gid], memory, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_SELFDESTRUCT: {
                // Stack: recipient ->
                if (state.stackPtr < 1) { state.running = 0; break; }
                op_selfdestruct(&states[gid], memory, accountBalances, config,
                                gid, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            // =============================================================
            // LOG OPCODES (0xA0-0xA4)
            // =============================================================

            case OP_LOG0: {
                // Stack: memOffset memSize ->
                if (state.stackPtr < 2) { state.running = 0; break; }
                op_log0(&states[gid], memory, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_LOG1: {
                // Stack: memOffset memSize topic1 ->
                if (state.stackPtr < 3) { state.running = 0; break; }
                op_log1(&states[gid], memory, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_LOG2: {
                // Stack: memOffset memSize topic1 topic2 ->
                if (state.stackPtr < 4) { state.running = 0; break; }
                op_log2(&states[gid], memory, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_LOG3: {
                // Stack: memOffset memSize topic1 topic2 topic3 ->
                if (state.stackPtr < 5) { state.running = 0; break; }
                op_log3(&states[gid], memory, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            case OP_LOG4: {
                // Stack: memOffset memSize topic1 topic2 topic3 topic4 ->
                if (state.stackPtr < 6) { state.running = 0; break; }
                op_log4(&states[gid], memory, gid, maxMemory, state.stackPtr);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                stackPop(&states[gid], stack, gid, maxStackDepth);
                break;
            }

            default:
                // Unknown opcode - stop execution
                state.running = 0;
                break;
        }

        traceIdx++;
        states[gid] = state;
    }
}

// ============================================================================
// ADDITIONAL KERNEL FUNCTIONS
// ============================================================================

// Arithmetic kernel (for complex operations)
kernel void evm_arithmetic(
    device TxState* states            [[buffer(0)]],
    device uchar* stack               [[buffer(1)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxStackDepth      [[buffer(7)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for complex arithmetic (ADDMOD, MULMOD, EXP, etc.)
}

// Comparison kernel
kernel void evm_comparison(
    device TxState* states            [[buffer(0)]],
    device uchar* stack               [[buffer(1)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxStackDepth      [[buffer(7)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for SLT, SGT, BYTE, etc.
}

// Bitwise kernel
kernel void evm_bitwise(
    device TxState* states            [[buffer(0)]],
    device uchar* stack               [[buffer(1)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxStackDepth      [[buffer(7)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for SHL, SHR, SAR, SIGNEXTEND, etc.
}

// Stack operations kernel
kernel void evm_stack(
    device TxState* states            [[buffer(0)]],
    device uchar* stack               [[buffer(1)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxStackDepth      [[buffer(7)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for DUP, SWAP operations
}

// Memory operations kernel
kernel void evm_memory(
    device TxState* states            [[buffer(0)]],
    device uchar* memory              [[buffer(2)]],
    device uchar* stack               [[buffer(1)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxStackDepth      [[buffer(7)]],
    constant uint& maxMemory          [[buffer(8)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for MLOAD, MSTORE, MSIZE operations
}

// Control flow kernel
kernel void evm_control_flow(
    device TxState* states            [[buffer(0)]],
    device uchar* stack               [[buffer(1)]],
    device const uchar* code          [[buffer(3)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxStackDepth      [[buffer(7)]],
    constant uint& maxCodeSize        [[buffer(9)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for JUMP, JUMPI, JUMPDEST validation
}

// Trace collection kernel
kernel void evm_trace_collect(
    device TxState* states            [[buffer(0)]],
    device TraceRow* trace            [[buffer(4)]],
    constant uint& numTxs             [[buffer(6)]],
    constant uint& maxTraceRows       [[buffer(10)]],
    uint gid                          [[thread_position_in_grid]]
) {
    // Reserved for post-processing trace data
}
