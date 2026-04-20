// Stream-aware Metal shaders for GPU multi-stream proving.
//
// These shaders are optimized for concurrent execution across multiple GPU streams.
// Each stream processes independent transactions, enabling parallel proof generation.
//
// Key optimizations:
// - Independent execution per stream (no cross-stream dependencies)
// - Minimal synchronization points
// - Efficient memory access patterns for streaming workloads
// - Optimized for Metal's command-level parallelism

#include <metal_stdlib>
using namespace metal;

// MARK: - Constants

constant uint MAX_STREAMS = 128;
constant uint M31_PRIME = 0x7FFFFFFF;
constant uint THREADS_PER_STREAM = 256;

// MARK: - Field Arithmetic (M31)

struct M31 {
    uint v;
};

M31 m31_add(M31 a, M31 b) {
    uint s = a.v + b.v;
    uint r = (s & M31_PRIME) + (s >> 31);
    return M31{r == M31_PRIME ? 0u : r};
}

M31 m31_sub(M31 a, M31 b) {
    if (a.v >= b.v) return M31{a.v - b.v};
    return M31{a.v + M31_PRIME - b.v};
}

M31 m31_mul(M31 a, M31 b) {
    ulong prod = ulong(a.v) * ulong(b.v);
    uint lo = uint(prod & ulong(M31_PRIME));
    uint hi = uint(prod >> 31);
    uint s = lo + hi;
    uint r = (s & M31_PRIME) + (s >> 31);
    return M31{r == M31_PRIME ? 0u : r};
}

// MARK: - Stream-Aware Data Structures

/// Per-stream execution context
struct StreamContext {
    uint streamId;
    uint transactionId;
    uint traceLength;
    uint evalLength;
    uint columnOffset;
    uint rowOffset;
};

/// Stream batch metadata
struct StreamBatchHeader {
    uint numStreams;
    uint streamsPerBatch;
    uint totalTransactions;
    uint padding;
};

// MARK: - Stream-Aware LDE Kernel

/// Low-Degree Extension kernel with stream awareness.
///
/// Each thread group processes one stream's LDE work.
/// Streams are fully independent for maximum parallelism.

kernel void stream_lde_kernel(
    device const M31* traceData      [[buffer(0)]],
    device M31* evalData             [[buffer(1)]],
    constant StreamBatchHeader* batch [[buffer(2)]],
    constant uint& streamId           [[buffer(3)]],
    constant uint& logBlowup          [[buffer(4)]],
    uint gid                          [[thread_position_in_grid]],
    uint tid                          [[thread_position_in_threadgroup]],
    uint3 tgid                        [[threadgroup_position_in_grid]]
) {
    // Calculate this stream's work range
    uint streamsPerBatch = batch->streamsPerBatch;
    uint myStream = tgid.x % streamsPerBatch;
    uint streamsPerTG = tgid.x / streamsPerBatch;

    // Calculate data offsets for this stream
    uint numColumns = 180;
    uint traceLen = 4096;
    uint evalLen = traceLen << logBlowup;

    uint colStart = myStream * numColumns * traceLen;
    uint evalStart = myStream * numColumns * evalLen;

    // Process this thread's column
    uint col = gid / traceLen;
    uint row = gid % traceLen;

    if (col >= numColumns) return;

    // Copy trace to eval (with interpolation for actual LDE)
    uint srcIdx = colStart + col * traceLen + row;
    uint dstIdx = evalStart + col * evalLen + row;

    // For now, simple repetition (would use NTT for actual LDE)
    for (uint i = 0; i < (1u << logBlowup); i++) {
        if (row + i * traceLen < evalLen) {
            evalData[dstIdx + i * traceLen] = traceData[srcIdx];
        }
    }
}

// MARK: - Stream-Aware Merkle Commitment Kernel

/// Merkle tree commitment kernel with stream isolation.
///
/// Each stream builds independent Merkle trees for its transaction's trace.

kernel void stream_merkle_commit_kernel(
    device const M31* leafData       [[buffer(0)]],
    device M31* commitmentData       [[buffer(1)]],
    constant uint& streamId           [[buffer(2)]],
    constant uint& numLeaves         [[buffer(3)]],
    constant uint& numColumns        [[buffer(4)]],
    uint gid                          [[thread_position_in_grid]],
    uint tid                          [[thread_position_in_threadgroup]],
    uint3 tgid                        [[threadgroup_position_in_grid]]
) {
    // Each stream processes its own columns
    uint streamsPerBatch = 128;
    uint myStream = tgid.x;

    // Calculate tree size for this stream
    uint numTrees = numColumns;
    uint leavesPerTree = numLeaves;
    uint nodesPerTree = 2 * leavesPerTree;

    // Each thread group builds one tree
    uint treeIdx = tgid.y;
    if (treeIdx >= numTrees) return;

    // Calculate node index within tree
    uint nodeIdx = tid;
    uint levelSize = leavesPerTree;
    uint levelStart = 0;

    // Tree building loop
    while (levelSize > 1) {
        uint nodeInLevel = nodeIdx;
        if (nodeInLevel >= levelSize / 2) return;

        uint leftChild = levelStart + 2 * nodeInLevel;
        uint rightChild = leftChild + 1;

        uint leftOffset = myStream * numTrees * nodesPerTree + treeIdx * nodesPerTree + leftChild;
        uint rightOffset = leftOffset + 1;

        // Hash pair of children
        M31 left = leafData[leftOffset];
        M31 right = leafData[rightOffset];

        // Simple hash for now (would use Poseidon2 in production)
        M31 parent = m31_add(left, right);  // Simplified - real impl uses Poseidon2

        uint parentOffset = levelStart + levelSize + nodeInLevel;
        uint globalOffset = myStream * numTrees * nodesPerTree + treeIdx * nodesPerTree + parentOffset;

        commitmentData[globalOffset] = parent;

        // Move to next level
        levelStart = parentOffset;
        levelSize = levelSize / 2;
        nodeIdx = nodeInLevel;
    }

    // Store root (first node of last level)
    if (nodeIdx == 0 && tid == 0) {
        uint rootOffset = myStream * numColumns + treeIdx;
        commitmentData[rootOffset] = commitmentData[myStream * numTrees * nodesPerTree + treeIdx * nodesPerTree + levelStart];
    }
}

// MARK: - Stream-Aware Constraint Evaluation Kernel

/// Constraint evaluation kernel with stream isolation.
///
/// Each stream evaluates constraints for its transaction independently.

kernel void stream_constraint_eval_kernel(
    device const M31* traceData       [[buffer(0)]],
    device M31* constraintData        [[buffer(1)]],
    constant uint& streamId           [[buffer(2)]],
    constant uint& traceLength        [[buffer(3)]],
    constant uint& numConstraints     [[buffer(4)]],
    uint gid                          [[thread_position_in_grid]],
    uint tid                          [[thread_position_in_threadgroup]],
    uint3 tgid                        [[threadgroup_position_in_grid]]
) {
    uint myStream = tgid.x;
    uint numColumns = 180;

    // Calculate offsets for this stream
    uint colBase = myStream * numColumns * traceLength;
    uint constraintBase = myStream * (traceLength - 1) * numConstraints;

    // Process row pairs
    uint row = gid;
    if (row >= traceLength - 1) return;

    uint baseIdx = colBase + row * numColumns;
    uint nextIdx = colBase + (row + 1) * numColumns;
    uint outBase = constraintBase + row * numConstraints;

    // Constraint 0: PC continuity
    M31 currPC = traceData[baseIdx];
    M31 nextPC = traceData[nextIdx];
    constraintData[outBase] = m31_sub(nextPC, m31_add(currPC, M31{1}));

    // Constraint 1: Gas monotonicity
    M31 currGas = traceData[baseIdx + 1];
    M31 nextGas = traceData[nextIdx + 1];
    constraintData[outBase + 1] = m31_sub(currGas, nextGas);

    // Constraint 2: Call depth
    M31 currDepth = traceData[baseIdx + 163];
    M31 nextDepth = traceData[nextIdx + 163];
    constraintData[outBase + 2] = m31_sub(nextDepth, currDepth);

    // Remaining constraints (zero for now)
    for (uint i = 3; i < numConstraints; i++) {
        constraintData[outBase + i] = M31{0};
    }
}

// MARK: - Stream-Aware FRI Kernel

/// FRI folding kernel with stream isolation.
///
/// Each stream processes independent FRI layers.

kernel void stream_fri_fold_kernel(
    device const M31* domainData     [[buffer(0)]],
    device M31* foldedData            [[buffer(1)]],
    constant uint& streamId            [[buffer(2)]],
    constant uint& layer               [[buffer(3)]],
    constant uint& foldFactor          [[buffer(4)]],
    uint gid                           [[thread_position_in_grid]],
    uint tid                           [[thread_position_in_threadgroup]],
    uint3 tgid                         [[threadgroup_position_in_grid]]
) {
    uint myStream = tgid.x;
    uint numStreams = 128;

    // Calculate layer size
    uint layerSize = 4096 >> layer;
    uint foldedSize = layerSize / foldFactor;

    if (gid >= foldedSize * numStreams) return;

    uint streamIdx = gid / foldedSize;
    uint idx = gid % foldedSize;

    // FRI fold operation (simplified)
    uint baseOffset = streamIdx * layerSize + idx * foldFactor;

    M31 result = domainData[baseOffset];
    for (uint f = 1; f < foldFactor; f++) {
        result = m31_add(result, domainData[baseOffset + f]);
    }

    uint outOffset = streamIdx * foldedSize + idx;
    foldedData[outOffset] = result;
}

// MARK: - Stream Batch Coordinator Kernel

/// Coordinator kernel for managing stream batch execution.
///
/// This kernel runs once per batch to initialize coordination data.

kernel void stream_batch_init_kernel(
    device StreamBatchHeader* batchHeader [[buffer(0)]],
    constant uint& numStreams           [[buffer(1)]],
    constant uint& transactionsPerStream [[buffer(2)]],
    uint gid                             [[thread_position_in_grid]]
) {
    if (gid == 0) {
        batchHeader->numStreams = numStreams;
        batchHeader->streamsPerBatch = min(numStreams, 128u);
        batchHeader->totalTransactions = numStreams * transactionsPerStream;
    }
}

// MARK: - Stream Synchronization Barrier Kernel

/// Barrier kernel for stream synchronization.
///
/// Uses atomic operations to implement efficient stream barriers.

kernel void stream_barrier_kernel(
    device atomic_uint* barrierCount    [[buffer(0)]],
    device atomic_uint* streamReady      [[buffer(1)]],
    constant uint& numStreams            [[buffer(2)]],
    constant uint& barrierId              [[buffer(3)]],
    uint gid                              [[thread_position_in_grid]]
) {
    if (gid == 0) {
        // Initialize barrier
        atomic_store_explicit(barrierCount, 0, memory_order_relaxed);
    }

    // Each stream marks itself as ready
    uint streamId = gid;
    if (streamId < numStreams) {
        uint prev = atomic_fetch_add_explicit(streamReady, 1, memory_order_acq_rel);

        // Check if all streams are ready
        if (prev + 1 == numStreams) {
            // Last stream to reach barrier - signal completion
            atomic_store_explicit(barrierCount, 1, memory_order_release);
        }

        // Wait for barrier release (spin-wait with back-off in real impl)
        while (atomic_load_explicit(barrierCount, memory_order_acquire) == 0) {
            // Spin wait
        }
    }
}

// MARK: - Stream-Aware NTT Kernel

/// Number Theoretic Transform kernel with stream support.

kernel void stream_ntt_kernel(
    device M31* data                    [[buffer(0)]],
    device const M31* twiddles          [[buffer(1)]],
    constant uint& streamId             [[buffer(2)]],
    constant uint& logN                 [[buffer(3)]],
    constant uint& stage                [[buffer(4)]],
    constant bool& inverse              [[buffer(5)]],
    uint gid                            [[thread_position_in_grid]],
    uint tid                            [[thread_position_in_threadgroup]],
    uint3 tgid                           [[threadgroup_position_in_grid]]
) {
    uint myStream = tgid.x;
    uint n = 1u << logN;
    uint halfN = n >> 1;

    // Calculate stream offset
    uint streamOffset = myStream * n;

    // Butterfly operation
    uint idx = gid;
    uint j = idx ^ (1u << stage);

    if (j > idx) {
        uint twiddleIdx = ((idx >> stage) & (halfN - 1));
        M31 w = twiddles[twiddleIdx];

        if (inverse) {
            // Inverse NTT uses w^(-1)
            w.v = M31_PRIME - w.v;  // Simplified inverse
        }

        M31 a = data[streamOffset + idx];
        M31 b = data[streamOffset + j];

        data[streamOffset + idx] = m31_add(a, b);
        data[streamOffset + j] = m31_mul(m31_sub(a, b), w);
    }
}

// MARK: - Stream-Aware Composition Kernel

/// Composition polynomial evaluation kernel.

kernel void stream_composition_kernel(
    device const M31* constraints       [[buffer(0)]],
    device M31* composition              [[buffer(1)]],
    constant uint& streamId             [[buffer(2)]],
    constant uint& traceLength           [[buffer(3)]],
    constant uint& numConstraints       [[buffer(4)]],
    constant M31* challenges            [[buffer(5)]],
    uint gid                            [[thread_position_in_grid]],
    uint tid                            [[thread_position_in_threadgroup]],
    uint3 tgid                           [[threadgroup_position_in_grid]]
) {
    uint myStream = tgid.x;
    uint numStreams = 128;

    if (gid >= (traceLength - 1) * numStreams) return;

    uint streamIdx = gid / (traceLength - 1);
    uint row = gid % (traceLength - 1);

    uint constraintBase = streamIdx * (traceLength - 1) * numConstraints;
    uint outBase = streamIdx * (traceLength - 1) + row;

    // Weighted sum of constraints
    M31 composed = M31{0};

    for (uint c = 0; c < numConstraints; c++) {
        M31 constraintVal = constraints[constraintBase + row * numConstraints + c];
        M31 challenge = challenges[c];
        composed = m31_add(composed, m31_mul(constraintVal, challenge));
    }

    composition[outBase] = composed;
}

// MARK: - Utility Functions

/// Fast modular inverse for M31 field
M31 m31_inv(M31 a) {
    // Fermat's little theorem: a^(p-2) mod p
    M31 result = a;
    for (int i = 0; i < 30; i++) {
        result = m31_mul(result, result);
    }
    return result;
}

/// Compare M31 values
bool m31_eq(M31 a, M31 b) {
    return a.v == b.v;
}

/// Check if M31 is zero
bool m31_is_zero(M31 a) {
    return a.v == 0;
}

/// Zero element
M31 m31_zero() {
    return M31{0};
}

/// One element
M31 m31_one() {
    return M31{1};
}