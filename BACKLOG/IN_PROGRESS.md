# EVMetal Backlog — In Progress

## Current Focus (2026-04-15)
- Establishing baseline: understanding architecture, running tests, documenting bugs

## Active Issues Found This Session

### 🔴 CRITICAL: GPU vs CPU Commitment MISMATCH
- **Location**: `testGPUCPUCommitmentMatch` in ProverTests.swift
- **Symptom**: "Column 0 chunked: MISMATCH" and "Column 1 chunked: MISMATCH"
- **Impact**: GPU batch proving produces wrong results vs CPU reference
- **Possible causes**:
  1. Position hashing mismatch between GPU kernel and CPU tree builder
  2. Leaf data layout difference (GPU uses position-hashed format per Benchmarks.swift comment)
  3. Chunked batch handling bug (512-leaf boundary handling)
- **Fix approach**: Need to compare exact leaf data going into GPU vs CPU. Add debug output to see which leaves differ.

### 🔴 CRITICAL: JUMP/JUMPI failing with outOfGas
- **Location**: EVMExecutionEngine.swift, `jump_op` and `jumpi_op`
- **Symptom**: Control Flow Opcodes test fails with "JUMP: FAILED - outOfGas"
- **Impact**: Any contract with jumps/reverts will fail
- **Root cause**: Likely gas charging issue or destination validation issue

### 🟡 HIGH: EVMGPUMerkleEngine is actually CPU-only
- **Location**: `EVMGPUMerkleProver.swift`
- **Symptom**: The `buildTreesBatch` method builds trees on CPU, not GPU
- **Comment says**: "GPU batch tree building for M31 is not yet available"
- **Impact**: All batch Merkle work is actually CPU-bound
- **Fix**: Implement actual GPU tree building kernel or use zkMetal's existing GPU Merkle

### 🟡 HIGH: EVMGPUConstraintEngine is a stub
- **Location**: `EVMGPUConstraintEngine.swift`
- **Symptom**: `evaluateConstraints` loops over rows sequentially on CPU
- **Comment says**: "Uses zkmetal's GPU engines" but actually calls EVMAIR.evaluateConstraints row by row
- **Impact**: 180 columns × many rows = sequential CPU evaluation = massive bottleneck
- **Fix**: Connect to zkMetal's GPU constraint evaluation kernels

### 🟡 HIGH: AIR constraint evaluation not using GPU
- **Location**: `EVMAIR.evaluateConstraints`
- **Symptom**: Evaluated one row at a time on CPU in a for loop
- **Impact**: 50 constraints × 2^14 rows = 819,200 sequential evaluations

## TODO This Session
- [ ] Investigate GPU vs CPU commitment mismatch (add debug output)
- [ ] Fix JUMP/JUMPI outOfGas bug
- [ ] Document all unimplemented opcodes
