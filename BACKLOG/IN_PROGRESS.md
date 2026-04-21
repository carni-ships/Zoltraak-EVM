# EVMetal Backlog — In Progress

## Current Focus (2026-04-15)
- Establishing baseline: understanding architecture, running tests, documenting bugs

## Active Issues Found This Session

### ✅ FIXED: GPU vs CPU Commitment MISMATCH (2026-04-21)
- **Status**: RESOLVED - Tests now pass
- **Test output**: "✓ All 4 GPU commitments MATCH CPU commitments" and "Chunked path: 2 columns MATCH"
- Both regular and chunked paths now work correctly

### ✅ FIXED: JUMP/JUMPI outOfGas (2026-04-21)
- **Status**: RESOLVED - Tests now pass
- **Test output**: "JUMP: OK", "JUMPI (true): OK"
- Both JUMP and JUMPI opcodes work correctly

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
- [x] Investigate GPU vs CPU commitment mismatch (FIXED - tests pass)
- [x] Fix JUMP/JUMPI outOfGas bug (FIXED - tests pass)
- [ ] Document all unimplemented opcodes
