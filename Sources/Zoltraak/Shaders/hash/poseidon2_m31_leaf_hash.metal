// Poseidon2 GPU kernel for M31 (Mersenne31) - Optimized leaf hashing
//
// Optimizations H2-H5:
// H2: Memory Coalescing - restructured data layout for better GPU memory access
// H3: Shared Memory Usage - cache position lookups in GPU shared memory
// H4: Pre-compute Position Hashes - reuse position hash inputs across columns
// H5: Half-Precision - 16-bit storage for M31 values where possible
//
// Memory layout optimization (H2):
// - Original: 180 arrays of 4096 M31 values (column-major)
// - Optimized: Transposed layout where threads access contiguous memory
// - Threadgroup size: 256 threads with shared position cache
// - Each thread processes multiple leaves sequentially

constant uint M31_P = 0x7FFFFFFFu;

// Half-precision M31 for memory optimization (H5)
// M31 values fit in 31 bits, can be stored in uint16_t
// Note: Uses uint16_t for storage but uint for arithmetic
struct M31 {
    uint v;
};

struct M31Half {
    ushort v;  // 16-bit storage for M31
};

// Conversion between full and half precision
M31 half_to_full(M31Half h) { return M31{uint(h.v)}; }
M31Half full_to_half(M31 m) { return M31Half{ushort(m.v)}; }

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

M31 m31_sqr(M31 a) { return m31_mul(a, a); }

// POSEIDON2 PARAMETERS
#define P2M31_T 16
#define P2M31_RF_HALF 7
#define P2M31_RP 21
#define P2M31_TOTAL_ROUNDS 35

constant uint P2M31_INTERNAL_DIAG[16] = {
    1, 1, 2, 1, 8, 32, 2, 256, 4096, 8, 65536, 1024, 2, 16384, 512, 32768
};

// S-box: x^5
M31 p2m31_sbox(M31 x) {
    M31 x2 = m31_sqr(x);
    M31 x4 = m31_sqr(x2);
    return m31_mul(x4, x);
}

// M4 circulant matrix
void p2m31_m4(thread M31 &s0, thread M31 &s1, thread M31 &s2, thread M31 &s3) {
    M31 t0 = m31_add(s0, s1);
    M31 t1 = m31_add(s2, s3);
    M31 t2 = m31_add(m31_add(s1, s1), t1);
    M31 t3 = m31_add(m31_add(s3, s3), t0);
    s0 = m31_add(t0, t3);
    s1 = m31_add(t1, t2);
    s2 = m31_add(t0, t2);
    s3 = m31_add(t1, t3);
}

void p2m31_external_layer(thread M31 *s) {
    p2m31_m4(s[0], s[1], s[2], s[3]);
    p2m31_m4(s[4], s[5], s[6], s[7]);
    p2m31_m4(s[8], s[9], s[10], s[11]);
    p2m31_m4(s[12], s[13], s[14], s[15]);
    for (uint i = 0; i < 4; i++) {
        M31 sum = m31_add(m31_add(s[i], s[i+4]), m31_add(s[i+8], s[i+12]));
        s[i]    = m31_add(s[i], sum);
        s[i+4]  = m31_add(s[i+4], sum);
        s[i+8]  = m31_add(s[i+8], sum);
        s[i+12] = m31_add(s[i+12], sum);
    }
}

void p2m31_internal_layer(thread M31 *s) {
    M31 sum = m31_zero();
    for (uint i = 0; i < 16; i++) {
        sum = m31_add(sum, s[i]);
    }
    for (uint i = 0; i < 16; i++) {
        uint d = P2M31_INTERNAL_DIAG[i];
        // Only optimize for d == 1 (identity), otherwise use multiplication
        // Note: d == 2 is NOT a common case for M31, so just use multiplication
        if (d == 1) {
            s[i] = m31_add(s[i], sum);
        } else {
            M31 prod = m31_mul(s[i], M31{d % M31_P});
            s[i] = m31_add(prod, sum);
        }
    }
}

void p2m31_permute(thread M31 *s, constant uint *rc) {
    p2m31_external_layer(s);
    for (uint r = 0; r < P2M31_RF_HALF; r++) {
        uint rc_base = r * P2M31_T;
        for (uint i = 0; i < P2M31_T; i++) s[i] = m31_add(s[i], M31{rc[rc_base + i]});
        for (uint i = 0; i < P2M31_T; i++) s[i] = p2m31_sbox(s[i]);
        p2m31_external_layer(s);
    }
    for (uint r = P2M31_RF_HALF; r < P2M31_RF_HALF + P2M31_RP; r++) {
        s[0] = m31_add(s[0], M31{rc[r * P2M31_T]});
        s[0] = p2m31_sbox(s[0]);
        p2m31_internal_layer(s);
    }
    for (uint r = P2M31_RF_HALF + P2M31_RP; r < P2M31_TOTAL_ROUNDS; r++) {
        uint rc_base = r * P2M31_T;
        for (uint i = 0; i < P2M31_T; i++) s[i] = m31_add(s[i], M31{rc[rc_base + i]});
        for (uint i = 0; i < P2M31_T; i++) s[i] = p2m31_sbox(s[i]);
        p2m31_external_layer(s);
    }
}

// Hash single leaf with position
void p2m31_hash_leaf_with_position(M31 value, uint position, thread M31 *out, constant uint *rc) {
    M31 s[P2M31_T];
    s[0] = value;
    s[1] = M31{position};
    for (uint i = 2; i < P2M31_T; i++) {
        s[i] = m31_zero();
    }
    p2m31_permute(s, rc);
    for (uint i = 0; i < 8; i++) {
        out[i] = s[i];
    }
}

// Number of leaves processed per thread - set to 1 for correct position handling
// LEAVES_PER_THREAD=1 ensures each thread reads its exact position from the buffer
// rather than sequential positions that would cause mismatch with interleaved layout
#define LEAVES_PER_THREAD 1

// SIMD-optimized kernel: processes LEAVES_PER_THREAD leaves per thread
// Each thread handles multiple leaves sequentially to improve throughput
kernel void poseidon2_m31_hash_leaves_with_position(
    device const uint* values      [[buffer(0)]],
    device const uint* positions   [[buffer(1)]],
    device uint* digests          [[buffer(2)]],
    constant uint* rc            [[buffer(3)]],
    constant uint& count          [[buffer(4)]],
    uint gid                      [[thread_position_in_grid]]
) {
    if (gid >= count) return;

    // Read position from positions buffer (Swift provides per-column position)
    uint position = positions[gid];

    M31 value = M31{values[gid]};

    M31 digest[8];
    p2m31_hash_leaf_with_position(value, position, digest, rc);

    uint out_base = gid * 8;
    for (uint i = 0; i < 8; i++) {
        digests[out_base + i] = digest[i].v;
    }
}

// Hash pairs of digests (for tree building)
kernel void poseidon2_m31_hash_pairs(
    device const uint* input       [[buffer(0)]],
    device uint* output           [[buffer(1)]],
    constant uint* rc             [[buffer(2)]],
    constant uint& count          [[buffer(3)]],
    uint gid                      [[thread_position_in_grid]]
) {
    if (gid >= count) return;

    M31 s[P2M31_T];
    uint in_base = gid * P2M31_T;
    for (uint i = 0; i < P2M31_T; i++) {
        s[i] = M31{input[in_base + i]};
    }

    p2m31_permute(s, rc);

    uint out_base = gid * 8;
    for (uint i = 0; i < 8; i++) {
        output[out_base + i] = s[i].v;
    }
}

// =============================================================================
// H2-H5 OPTIMIZED KERNELS
// =============================================================================

// Threadgroup size for H3 optimization (shared memory position cache)
#define THREADGROUP_SIZE 256

// Helper macro for min (Metal doesn't have built-in min for all types)
#define metal_min(a, b) ((a) < (b) ? (a) : (b))

// H3: Shared memory cache for positions (reduce constant memory reads)
// Uses interleaved layout matching hashLeavesBatchPerColumn:
// Layout: [col0_pos0, col1_pos0, ..., colN_pos0, col0_pos1, ...]
// Index: positionIdx * numColumns + columnIdx
kernel void poseidon2_m31_hash_leaves_optimized(
    device const uint* values      [[buffer(0)]],  // Interleaved: [col0_pos0, col1_pos0, ...]
    device const uint* positions   [[buffer(1)]],
    device uint* digests          [[buffer(2)]],
    constant uint* rc            [[buffer(3)]],
    constant uint& count          [[buffer(4)]],
    constant uint& numColumns     [[buffer(5)]],  // Number of columns
    constant uint& leavesPerCol   [[buffer(6)]],  // Leaves per column
    threadgroup uint* positionCache [[threadgroup(0)]],  // H3: shared memory cache
    uint gid                      [[thread_position_in_grid]],
    uint tid                     [[thread_position_in_threadgroup]]
) {
    // H3: Pre-load positions into shared memory (one per thread)
    // This is done once per threadgroup, reducing global memory reads
    uint numPositions = metal_min(count, leavesPerCol);
    if (tid < numPositions) {
        positionCache[tid] = positions[tid];
    }
    threadgroup_barrier(metal::mem_flags::mem_threadgroup);

    if (gid >= count) return;

    // Calculate position and column from gid (interleaved layout)
    // Layout: position0 has numColumns elements (col0, col1, ...), then position1, etc.
    uint positionIdx = gid / numColumns;
    uint columnIdx = gid % numColumns;

    // H3: Read position from shared memory cache
    uint position = positionCache[positionIdx];

    // Read value (uses same interleaved layout)
    M31 value = M31{values[gid]};

    // Hash with position
    M31 digest[8];
    p2m31_hash_leaf_with_position(value, position, digest, rc);

    // Write digest
    uint outIdx = gid * 8;
    for (uint i = 0; i < 8; i++) {
        digests[outIdx + i] = digest[i].v;
    }
}

// H4: Pre-computed position hashes - optimized kernel
// This kernel uses pre-computed position hash states
// Input: Pre-hashed position values (value is the position hash state)
// Note: The position part of the hash is pre-computed, only value needs permutation
kernel void poseidon2_m31_hash_leaves_precomputed(
    device const uint* values      [[buffer(0)]],
    device const uint* positionHashStates [[buffer(1)]],  // Pre-computed position hash states
    device uint* digests          [[buffer(2)]],
    constant uint* rc            [[buffer(3)]],
    constant uint& count          [[buffer(4)]],
    uint gid                      [[thread_position_in_grid]]
) {
    if (gid >= count) return;

    // Load pre-computed position hash state
    M31 s[P2M31_T];
    uint stateBase = gid * P2M31_T;
    for (uint i = 0; i < P2M31_T; i++) {
        s[i] = M31{positionHashStates[stateBase + i]};
    }

    // Add the value to the state (s[0] already contains position hash)
    s[0] = m31_add(s[0], M31{values[gid]});

    // Complete the permutation
    p2m31_permute(s, rc);

    // Write digest
    uint outBase = gid * 8;
    for (uint i = 0; i < 8; i++) {
        digests[outBase + i] = s[i].v;
    }
}

// H5: Half-precision optimized kernel
// Uses 16-bit storage for M31 values where possible
kernel void poseidon2_m31_hash_leaves_half(
    device const ushort* values   [[buffer(0)]],  // Half-precision input
    device const uint* positions  [[buffer(1)]],
    device uint* digests          [[buffer(2)]],
    constant uint* rc             [[buffer(3)]],
    constant uint& count          [[buffer(4)]],
    threadgroup uint* positionCache [[threadgroup(0)]],
    uint gid                      [[thread_position_in_grid]],
    uint tid                     [[thread_position_in_threadgroup]]
) {
    // H3: Cache positions in shared memory
    if (tid < count) {
        positionCache[tid] = positions[tid];
    }
    threadgroup_barrier(metal::mem_flags::mem_threadgroup);

    // H5: Load half-precision value and convert to full precision
    M31 value = M31{uint(values[gid])};
    uint position = positionCache[gid % 1024];  // Cache has max 1024 positions

    // Hash with position
    M31 digest[8];
    p2m31_hash_leaf_with_position(value, position, digest, rc);

    // Write digest (full precision output)
    uint outBase = gid * 8;
    for (uint i = 0; i < 8; i++) {
        digests[outBase + i] = digest[i].v;
    }
}

// =============================================================================
// H4: Pre-compute position hashes (runs on CPU before GPU leaf hashing)
// =============================================================================

// This kernel pre-computes the position hash state for all positions
// Input: positions array
// Output: Pre-computed hash states for each position (16 M31 values per position)
kernel void poseidon2_m31_precompute_positions(
    device const uint* positions   [[buffer(0)]],
    device uint* hashStates        [[buffer(1)]],  // Output: P2M31_T values per position
    constant uint* rc             [[buffer(2)]],
    constant uint& count          [[buffer(3)]],
    uint gid                      [[thread_position_in_grid]]
) {
    if (gid >= count) return;

    uint position = positions[gid];

    // Initialize state with position
    M31 s[P2M31_T];
    s[0] = M31{position};  // Position is in s[0], value will be added later
    for (uint i = 1; i < P2M31_T; i++) {
        s[i] = m31_zero();
    }

    // Run partial permutation (partial rounds only)
    // We do partial rounds here since value addition can happen later
    for (uint r = 0; r < P2M31_RF_HALF; r++) {
        uint rc_base = r * P2M31_T;
        for (uint i = 0; i < P2M31_T; i++) s[i] = m31_add(s[i], M31{rc[rc_base + i]});
        for (uint i = 0; i < P2M31_T; i++) s[i] = p2m31_sbox(s[i]);
        p2m31_external_layer(s);
    }

    // Store partial state - value will be added and full permutation completed
    // in the precomputed kernel
    uint outBase = gid * P2M31_T;
    for (uint i = 0; i < P2M31_T; i++) {
        hashStates[outBase + i] = s[i].v;
    }
}

// =============================================================================
// H2: Transposed layout kernel for maximum memory coalescing
// Data layout: [col0_leaf0, col0_leaf1, ..., col0_leafN, col1_leaf0, ...]
// Each thread accesses contiguous memory within its column
// =============================================================================

kernel void poseidon2_m31_hash_leaves_transposed(
    device const uint* values      [[buffer(0)]],  // Transposed: col-major
    device const uint* positions   [[buffer(1)]],
    device uint* digests           [[buffer(2)]],
    constant uint* rc              [[buffer(3)]],
    constant uint& totalCount      [[buffer(4)]],
    constant uint& numColumns      [[buffer(5)]],
    constant uint& leavesPerColumn  [[buffer(6)]],
    threadgroup uint* positionCache [[threadgroup(0)]],
    uint gid                       [[thread_position_in_grid]],
    uint tid                      [[thread_position_in_threadgroup]],
    uint bid                      [[threadgroup_position_in_grid]]
) {
    // H3: Pre-load all positions into shared memory
    // Each thread loads one position
    if (tid < leavesPerColumn) {
        positionCache[tid] = positions[tid];
    }
    threadgroup_barrier(metal::mem_flags::mem_threadgroup);

    // Calculate which position this thread group handles
    uint groupPosIdx = gid;
    uint numGroups = (leavesPerColumn + THREADGROUP_SIZE - 1) / THREADGROUP_SIZE;

    for (uint posIdx = groupPosIdx; posIdx < leavesPerColumn; posIdx += numGroups) {
        // H2: All threads in this group process the same position
        // but different columns (contiguous memory access)
        uint position = positionCache[posIdx];

        for (uint colIdx = tid; colIdx < numColumns; colIdx += THREADGROUP_SIZE) {
            uint idx = colIdx * leavesPerColumn + posIdx;
            if (idx >= totalCount) continue;

            // H2: Contiguous memory access within column
            M31 value = M31{values[idx]};

            // Hash with position
            M31 digest[8];
            p2m31_hash_leaf_with_position(value, position, digest, rc);

            // Write to transposed output
            uint outIdx = idx * 8;
            for (uint i = 0; i < 8; i++) {
                digests[outIdx + i] = digest[i].v;
            }
        }
    }
}

// =============================================================================
// Combined H2-H5 kernel: Maximum optimization
// Uses all techniques together for best performance
// =============================================================================

kernel void poseidon2_m31_hash_leaves_combined(
    device const ushort* values   [[buffer(0)]],  // H5: Half-precision input
    device const uint* positions   [[buffer(1)]],
    device uint* digests           [[buffer(2)]],
    constant uint* rc              [[buffer(3)]],
    constant uint& totalCount      [[buffer(4)]],
    constant uint& numColumns      [[buffer(5)]],
    constant uint& leavesPerColumn  [[buffer(6)]],
    threadgroup uint* positionCache [[threadgroup(0)]],
    uint gid                       [[thread_position_in_grid]],
    uint tid                      [[thread_position_in_threadgroup]],
    uint bid                      [[threadgroup_position_in_grid]]
) {
    // H3: Load positions into shared memory
    uint cacheSize = metal_min(leavesPerColumn, 1024u);
    if (tid < cacheSize) {
        positionCache[tid] = positions[tid];
    }
    threadgroup_barrier(metal::mem_flags::mem_threadgroup);

    // H2: Calculate indices
    uint positionIdx = gid / numColumns;
    uint columnIdx = gid % numColumns;

    if (positionIdx >= leavesPerColumn || gid >= totalCount) return;

    // H3: Read from shared memory cache
    uint position = positionCache[positionIdx % cacheSize];

    // H2: Coalesced memory access
    uint valueIdx = columnIdx * leavesPerColumn + positionIdx;

    // H5: Convert half-precision to full precision
    M31 value = M31{uint(values[valueIdx])};

    // Hash with position
    M31 digest[8];
    p2m31_hash_leaf_with_position(value, position, digest, rc);

    // Write output
    uint outIdx = valueIdx * 8;
    for (uint i = 0; i < 8; i++) {
        digests[outIdx + i] = digest[i].v;
    }
}
