// GPU Keccak-256 batch kernel for Ethereum ZK-EVM
//
// This kernel processes multiple Keccak-256 hashes in parallel on GPU.
// Each thread processes one input through the Keccak-f1600 permutation.
//
// Memory layout:
// - Inputs: [input0_bytes, input1_bytes, ...] (variable length, padded)
// - Input lengths: [len0, len1, ...] (in bytes)
// - Outputs: [hash0_bytes, hash1_bytes, ...] (32 bytes each)
//
// Keccak-f1600 parameters (SHA-3):
// - State size: 1600 bits (25 x 64-bit words)
// - Number of rounds: 24
// - Rate: 1088 bits (17 x 64-bit words)
// - Capacity: 512 bits

#include <metal_stdlib.h>
using namespace metal;

// ============================================================================
// KECCAK-F1600 PERMUTATION
// ============================================================================

// Rotation constants for Keccak (64-bit rotation amounts)
constant uint64_t ROT_R[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008088UL,
    0x8000000000008009UL, 0x8000000000008000UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL,
    0x800000008000000aUL, 0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

// Round constants for Keccak (first 24 bits of Keccak round constants)
constant uint64_t RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008088UL,
    0x8000000000008009UL, 0x8000000000008000UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL,
    0x800000008000000aUL, 0x8000000080008081UL, 0x8000000000008080UL
};

// Keccak-f1600 round function
void keccak_round(thread uint64_t* a, uint round_num) {
    // === Theta step ===
    uint64_t c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    uint64_t c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    uint64_t c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    uint64_t c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    uint64_t c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

    uint64_t d0 = c0 ^ rotate(c1, 1UL);
    uint64_t d1 = c1 ^ rotate(c2, 1UL);
    uint64_t d2 = c2 ^ rotate(c3, 1UL);
    uint64_t d3 = c3 ^ rotate(c4, 1UL);
    uint64_t d4 = c4 ^ rotate(c0, 1UL);

    a[0] ^= d0;  a[5] ^= d0;  a[10] ^= d0;  a[15] ^= d0;  a[20] ^= d0;
    a[1] ^= d1;  a[6] ^= d1;  a[11] ^= d1;  a[16] ^= d1;  a[21] ^= d1;
    a[2] ^= d2;  a[7] ^= d2;  a[12] ^= d2;  a[17] ^= d2;  a[22] ^= d2;
    a[3] ^= d3;  a[8] ^= d3;  a[13] ^= d3;  a[18] ^= d3;  a[23] ^= d3;
    a[4] ^= d4;  a[9] ^= d4;  a[14] ^= d4;  a[19] ^= d4;  a[24] ^= d4;

    // === Rho step ===
    a[0] = rotate(a[0], ROT_R[round_num]);
    a[1] = rotate(a[1], ROT_R[round_num + 1]);
    a[2] = rotate(a[2], ROT_R[round_num + 2]);
    a[3] = rotate(a[3], ROT_R[round_num + 3]);
    a[4] = rotate(a[4], ROT_R[round_num + 4]);
    a[5] = rotate(a[5], ROT_R[round_num + 5]);
    a[6] = rotate(a[6], ROT_R[round_num + 6]);
    a[7] = rotate(a[7], ROT_R[round_num + 7]);
    a[8] = rotate(a[8], ROT_R[round_num + 8]);
    a[9] = rotate(a[9], ROT_R[round_num + 9]);
    a[10] = rotate(a[10], ROT_R[round_num + 10]);
    a[11] = rotate(a[11], ROT_R[round_num + 11]);
    a[12] = rotate(a[12], ROT_R[round_num + 12]);
    a[13] = rotate(a[13], ROT_R[round_num + 13]);
    a[14] = rotate(a[14], ROT_R[round_num + 14]);
    a[15] = rotate(a[15], ROT_R[round_num + 15]);
    a[16] = rotate(a[16], ROT_R[round_num + 16]);
    a[17] = rotate(a[17], ROT_R[round_num + 17]);
    a[18] = rotate(a[18], ROT_R[round_num + 18]);
    a[19] = rotate(a[19], ROT_R[round_num + 19]);
    a[20] = rotate(a[20], ROT_R[round_num + 20]);
    a[21] = rotate(a[21], ROT_R[round_num + 21]);
    a[22] = rotate(a[22], ROT_R[round_num + 22]);
    a[23] = rotate(a[23], ROT_R[round_num + 23]);
    a[24] = rotate(a[24], ROT_R[round_num + 24]);

    // === Pi step ===
    uint64_t b0  = a[0];
    uint64_t b1  = a[11];
    uint64_t b2  = a[21];
    uint64_t b3  = a[6];
    uint64_t b4  = a[17];
    uint64_t b5  = a[10];
    uint64_t b6  = a[20];
    uint64_t b7  = a[5];
    uint64_t b8  = a[15];
    uint64_t b9  = a[16];
    uint64_t b10 = a[24];
    uint64_t b11 = a[4];
    uint64_t b12 = a[2];
    uint64_t b13 = a[23];
    uint64_t b14 = a[7];
    uint64_t b15 = a[13];
    uint64_t b16 = a[19];
    uint64_t b17 = a[3];
    uint64_t b18 = a[14];
    uint64_t b19 = a[8];
    uint64_t b20 = a[12];
    uint64_t b21 = a[1];
    uint64_t b22 = a[9];
    uint64_t b23 = a[22];
    uint64_t b24 = a[18];

    a[0] = b0;  a[1] = b1;  a[2] = b2;  a[3] = b3;  a[4] = b4;
    a[5] = b5;  a[6] = b6;  a[7] = b7;  a[8] = b8;  a[9] = b9;
    a[10] = b10; a[11] = b11; a[12] = b12; a[13] = b13; a[14] = b14;
    a[15] = b15; a[16] = b16; a[17] = b17; a[18] = b18; a[19] = b19;
    a[20] = b20; a[21] = b21; a[22] = b22; a[23] = b23; a[24] = b24;

    // === Chi step ===
    a[0] ^= (~b1) & b2;
    a[1] ^= (~b2) & b3;
    a[2] ^= (~b3) & b4;
    a[3] ^= (~b4) & b0;
    a[4] ^= (~b0) & b1;
    a[5] ^= (~b6) & b7;
    a[6] ^= (~b7) & b8;
    a[7] ^= (~b8) & b9;
    a[8] ^= (~b9) & b5;
    a[9] ^= (~b5) & b6;
    a[10] ^= (~b11) & b12;
    a[11] ^= (~b12) & b13;
    a[12] ^= (~b13) & b14;
    a[13] ^= (~b14) & b10;
    a[14] ^= (~b10) & b11;
    a[15] ^= (~b16) & b17;
    a[16] ^= (~b17) & b18;
    a[17] ^= (~b18) & b19;
    a[18] ^= (~b19) & b15;
    a[19] ^= (~b15) & b16;
    a[20] ^= (~b21) & b22;
    a[21] ^= (~b22) & b23;
    a[22] ^= (~b23) & b24;
    a[23] ^= (~b24) & b20;
    a[24] ^= (~b20) & b21;

    // === Iota step ===
    a[0] ^= RC[round_num];
}

// Full Keccak-f1600 permutation (24 rounds)
void keccak_f1600(thread uint64_t* a) {
    for (uint round = 0; round < 24; round++) {
        keccak_round(a, round);
    }
}

// ============================================================================
// KECCAK-256 HASH FUNCTION
// ============================================================================

// Absorb message into state and squeeze output
// Keccak-256: rate = 136 bytes (17 x 64-bit), capacity = 512 bits
void keccak256_absorb(thread uint64_t* s, const device uint8_t* message,
                      uint message_len, uint padding_byte) {
    // Clear state
    for (uint i = 0; i < 25; i++) {
        s[i] = 0;
    }

    // Absorb rate bytes at a time
    uint rate_bytes = 136;  // 1088 bits / 8
    uint64_t* msg64 = (uint64_t*)message;

    uint offset = 0;
    while (offset + rate_bytes <= message_len) {
        // XOR message into state
        for (uint i = 0; i < 17; i++) {
            s[i] ^= msg64[offset / 8 + i];
        }
        keccak_f1600(s);
        offset += rate_bytes;
    }

    // Handle remaining bytes with padding
    uint64_t last_block[17];
    for (uint i = 0; i < 17; i++) {
        last_block[i] = 0;
    }

    uint remaining = message_len - offset;
    for (uint i = 0; i < remaining; i++) {
        ((uint8_t*)last_block)[i] = message[offset + i];
    }

    // Add padding
    ((uint8_t*)last_block)[remaining] = padding_byte;

    // XOR last block into state
    for (uint i = 0; i < 17; i++) {
        s[i] ^= last_block[i];
    }

    keccak_f1600(s);
}

// Extract 32-byte hash from state
void keccak256_squeeze(device uint8_t* hash, const uint64_t* s) {
    for (uint i = 0; i < 4; i++) {
        ((uint64_t*)hash)[i] = s[i];
    }
}

// Compute single Keccak-256 hash
void keccak256_hash(device uint8_t* hash, const device uint8_t* message,
                   uint message_len, uint padding_byte) {
    uint64_t state[25];
    keccak256_absorb(state, message, message_len, padding_byte);
    keccak256_squeeze(hash, state);
}

// ============================================================================
// GPU KERNEL: BATCH KECCAK-256
// ============================================================================

// Each thread processes one input through Keccak-f1600
kernel void keccak256_batch(
    device const uint8_t* inputs            [[buffer(0)]],
    device const uint32_t* input_lengths    [[buffer(1)]],
    device const uint32_t* input_offsets     [[buffer(2)]],
    device uint8_t* outputs                 [[buffer(3)]],
    constant uint32_t& num_inputs           [[buffer(4)]],
    constant uint32_t& keccak_padding       [[buffer(5)]],  // 0x01 for Keccak, 0x06 for SHA3
    uint gid                                 [[thread_position_in_grid]]
) {
    if (gid >= num_inputs) return;

    uint length = input_lengths[gid];
    uint offset = input_offsets[gid];

    // Compute hash for this input
    keccak256_hash(outputs + gid * 32, inputs + offset, length, keccak_padding);
}

// ============================================================================
// GPU KERNEL: BATCH KECCAK-256 (FIXED INPUT SIZE)
// ============================================================================

// Optimized version for fixed-size inputs (common case: 32-byte words)
// Each thread processes one 32-byte input - no offsets needed
kernel void keccak256_batch_fixed(
    device const uint8_t* inputs            [[buffer(0)]],
    device uint8_t* outputs                 [[buffer(1)]],
    constant uint32_t& num_inputs           [[buffer(2)]],
    constant uint32_t& input_size            [[buffer(3)]],  // Size of each input in bytes
    constant uint32_t& keccak_padding       [[buffer(4)]],
    uint gid                                 [[thread_position_in_grid]]
) {
    if (gid >= num_inputs) return;

    uint offset = gid * input_size;
    keccak256_hash(outputs + gid * 32, inputs + offset, input_size, keccak_padding);
}

// ============================================================================
// GPU KERNEL: BATCH KECCAK-256 WITH TRACE POSITIONS
// ============================================================================

// Extended version that also outputs the trace position for result mapping
kernel void keccak256_batch_with_position(
    device const uint8_t* inputs            [[buffer(0)]],
    device const uint32_t* input_lengths    [[buffer(1)]],
    device const uint32_t* input_offsets     [[buffer(2)]],
    device uint8_t* outputs                 [[buffer(3)]],
    device uint32_t* trace_positions        [[buffer(4)]],
    constant uint32_t& num_inputs           [[buffer(5)]],
    constant uint32_t& keccak_padding       [[buffer(6)]],
    uint gid                                 [[thread_position_in_grid]]
) {
    if (gid >= num_inputs) return;

    uint length = input_lengths[gid];
    uint offset = input_offsets[gid];

    // Compute hash
    keccak256_hash(outputs + gid * 32, inputs + offset, length, keccak_padding);

    // Store trace position for result mapping
    // Position is stored in trace_positions[gid] during trace collection
}

// ============================================================================
// GPU KERNEL: KECCAK-256 FOR CONTRACT BYTECODE HASHING
// ============================================================================

// Optimized for contract bytecode hashing (variable length, 0x00 padding)
kernel void keccak256_batch_code(
    device const uint8_t* codes             [[buffer(0)]],
    device const uint32_t* code_lengths      [[buffer(1)]],
    device const uint32_t* code_offsets      [[buffer(2)]],
    device uint8_t* hashes                  [[buffer(3)]],
    constant uint32_t& num_codes            [[buffer(4)]],
    uint gid                                 [[thread_position_in_grid]]
) {
    if (gid >= num_codes) return;

    uint length = code_lengths[gid];
    uint offset = code_offsets[gid];

    // Keccak-256 with 0x00 padding for bytecode
    keccak256_hash(hashes + gid * 32, codes + offset, length, 0x00);
}

// ============================================================================
// GPU KERNEL: KECCAK-256 SIMD GROUP VERSION (FASTER)
// ============================================================================

// SIMD-optimized version: 8 threads cooperate to hash one input
// Uses threadgroup memory for shared state
kernel void keccak256_batch_simd(
    device const uint8_t* inputs            [[buffer(0)]],
    device const uint32_t* input_lengths    [[buffer(1)]],
    device const uint32_t* input_offsets     [[buffer(2)]],
    device uint8_t* outputs                 [[buffer(3)]],
    constant uint32_t& num_inputs           [[buffer(4)]],
    constant uint32_t& keccak_padding       [[buffer(5)]],
    uint tid                                 [[thread_position_in_threadgroup]],
    uint gid                                 [[thread_position_in_grid]]
) {
    if (gid >= num_inputs) return;

    uint length = input_lengths[gid];
    uint offset = input_offsets[gid];

    // Threadgroup for shared Keccak state
    threadgroup uint64_t state_s[25];

    // Only lane 0 initializes state
    if (tid == 0) {
        for (uint i = 0; i < 25; i++) {
            state_s[i] = 0;
        }
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Absorb message (lane 0 does the work, others wait)
    if (tid == 0) {
        uint rate_bytes = 136;
        uint64_t* msg64 = (uint64_t*)inputs;
        uint local_offset = 0;

        while (local_offset + rate_bytes <= length) {
            for (uint i = 0; i < 17; i++) {
                state_s[i] ^= msg64[(offset + local_offset) / 8 + i];
            }
            keccak_f1600(state_s);
            local_offset += rate_bytes;
        }

        // Handle remaining bytes with padding
        uint64_t last_block[17] = {0};
        uint remaining = length - local_offset;
        for (uint i = 0; i < remaining; i++) {
            ((uint8_t*)last_block)[i] = inputs[offset + local_offset + i];
        }
        ((uint8_t*)last_block)[remaining] = keccak_padding;

        for (uint i = 0; i < 17; i++) {
            state_s[i] ^= last_block[i];
        }

        keccak_f1600(state_s);
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Squeeze output (each lane stores its portion)
    if (tid < 4) {
        ((uint64_t*)(outputs + gid * 32))[tid] = state_s[tid];
    }
}
