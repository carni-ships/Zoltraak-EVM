#include <metal_stdlib>
using namespace metal;

// Zero-padding LDE kernel for extending trace values
//
// For blowup=2: Each trace element is duplicated
// For blowup=4: Each trace element is repeated 4 times
//
// Input: trace values [0, traceLen)
// Output: Extended values [0, evalLen) where extended[i] = trace[i / blowupFactor]

kernel void zeroPadLDE(
    device uint32_t* input [[buffer(0)]],
    device uint32_t* output [[buffer(1)]],
    constant uint32_t& traceLen [[buffer(2)]],
    constant uint32_t& evalLen [[buffer(3)]],
    uint id [[thread_position_in_grid]]
) {
    if (id >= evalLen) return;

    uint32_t idx = id / (evalLen / traceLen);
    if (idx < traceLen) {
        output[id] = input[idx];
    } else {
        output[id] = 0;
    }
}

// Alternative: Simple duplication kernel for blowup=2
kernel void duplicateLDE(
    device uint32_t* input [[buffer(0)]],
    device uint32_t* output [[buffer(1)]],
    constant uint32_t& traceLen [[buffer(2)]],
    uint id [[thread_position_in_grid]]
) {
    if (id >= traceLen * 2) return;

    uint32_t srcIdx = id / 2;
    output[id] = input[srcIdx];
}

// Batch version: Process multiple columns in one kernel launch
kernel void zeroPadLDEBatch(
    device uint32_t* inputs [[buffer(0)]],
    device uint32_t* outputs [[buffer(1)]],
    constant uint32_t& traceLen [[buffer(2)]],
    constant uint32_t& evalLen [[buffer(3)]],
    constant uint32_t& numColumns [[buffer(4)]],
    uint id [[thread_position_in_grid]]
) {
    uint32_t columnsPerThread = (numColumns + 255) / 256;
    uint32_t threadBaseCol = (id / columnsPerThread) * columnsPerThread;

    if (threadBaseCol >= numColumns) return;

    uint32_t elementsPerColumn = evalLen;
    uint32_t totalElements = numColumns * elementsPerColumn;

    if (id >= totalElements) return;

    uint32_t colIdx = id / elementsPerColumn;
    uint32_t elemIdx = id % elementsPerColumn;

    uint32_t srcIdx = elemIdx / (evalLen / traceLen);
    uint32_t srcOffset = colIdx * traceLen;
    uint32_t dstOffset = colIdx * evalLen;

    if (srcIdx < traceLen) {
        outputs[dstOffset + elemIdx] = inputs[srcOffset + srcIdx];
    } else {
        outputs[dstOffset + elemIdx] = 0;
    }
}