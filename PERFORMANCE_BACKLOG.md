# GPU FRI Engine Investigation & Fix

## Status: INVESTIGATION NEEDED

The GPU FRI engine (`GPUCircleFRIProverEngine`) fails to initialize, causing FRI to fall back to CPU. This was identified in context #S3550 ("GPU FRI engine has shader compilation issues, uses CPU fallback").

### Known Issue
In `EVMGPUCircleSTARKProverEngine.init()`, the error handling was:
```swift
do {
    self.friEngine = try GPUCircleFRIProverEngine()
    self.friEngineReady = true
} catch {
    self.friEngineReady = true  // BUG: set to true on error!
}
```
**FIXED**: Now sets `friEngineReady = false` on error.

### Investigation Steps
1. Add debug logging to catch the actual error in `GPUCircleFRIProverEngine.init()`
2. Verify Metal shader compilation succeeds for `circle_fri.metal` and `circle_fri_parallel.metal`
3. Check if `Poseidon2M31Engine()` fails (used by FRI engine)
4. Test with a minimal FRI proof to isolate the issue

### Potential Causes
- Missing kernel functions in compiled shader
- Metal API compatibility issue
- GPU memory allocation failure

### Expected Impact
GPU FRI measured at ~79ms vs CPU FRI. Enabling GPU FRI could reduce query phase time by additional ~50%.

---

# GPU Boundary Constraint Evaluation

## Status: INVESTIGATION NEEDED

Context #S3551 identified: "Boundary constraint contributions are CPU-based bottleneck"

### Current State
- `GPUCircleConstraintEngine` handles main constraint evaluation on GPU
- Boundary constraints evaluated on CPU in `evaluateConstraintsWithSubsetCPU()`
- For UltraFast mode with 32K trace points, boundary evaluation is significant overhead

### Location
`EVMGPUCircleSTARKProverEngine.evaluateConstraintsWithSubset()` at ~line 559:
```swift
// Boundary constraints - use Set for O(1) lookup
let traceRow = i / step
if boundaryRows.contains(traceRow) {
    // CPU boundary evaluation for each matching row
}
```

### Investigation Steps
1. Profile boundary constraint time vs main constraint time
2. Determine if boundary constraints can be merged into GPU kernel
3. Check if boundary constraints use different computation pattern

### Expected Impact
~0.1-0.3s reduction depending on number of boundary constraints.

---

# GPU LDE (Low-Degree Extension)

## Status: CANDIDATE

### Current State
Trace LDE is CPU-based in `cpuLDE()` at line 917 of `EVMGPUCircleSTARKProverEngine.swift`.

### Location
```swift
private func cpuLDE(trace: [[M31]], logTrace: Int, logEval: Int) -> [[M31]]
```

### Approach
Use GPU Circle NTT engine (`CircleNTTEngine`) for LDE:
- Run inverse NTT → zero-pad → forward NTT
- Similar to how GPU FRI uses parallel computation

### Expected Impact
~0.2-0.5s for 32K trace points with blowup=4.

---

# GPU Composition Merkle Proof

## Status: LOW PRIORITY

### Current State
Composition tree Merkle proof uses CPU `poseidon2M31MerkleProof()` at line 703.

### Location
`EVMGPUCircleSTARKProverEngine.generateQueryResponses()` at ~line 703:
```swift
let compPath = poseidon2M31MerkleProof(compTree, n: evalLen, index: qi)
```

### Approach
Could use `GPUMerkleTreeM31Engine.generateProofsGPU()` for composition tree too.

### Expected Impact
Minimal - single tree, few levels, low overhead.

---

# Summary Table

| Optimization | Impact | Effort | Priority |
|--------------|--------|--------|----------|
| GPU FRI Fix | High (~50ms) | Medium | P0 |
| GPU Boundary | Medium (~200ms) | Medium | P1 |
| GPU LDE | Medium (~300ms) | High | P2 |
| GPU Composition Proof | Low (~10ms) | Low | P3 |
