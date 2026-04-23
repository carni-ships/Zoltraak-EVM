# EVMetal Research — 2026-04-15

## Architecture Overview

EVMetal is a ZK-EVM proving library built on zkMetal. It provides EVM execution tracing and Circle STARK proof generation using GPU acceleration.

### Key Components

| Component | Path | Purpose |
|-----------|------|---------|
| EVMExecutionEngine | `EVM/EVMExecutionEngine.swift` | Interprets EVM bytecode, generates traces |
| EVMAIR | `AIR/EVMAIR.swift` | AIR constraints for EVM trace (180 columns) |
| EVMetalGPUProver | `Prover/EVMetalGPUProver.swift` | GPU batch Merkle commitment |
| EVMetalLeafHashEngine | `Prover/EVMetalLeafHashEngine.swift` | GPU Poseidon2-M31 leaf hashing |
| EVMGPUMerkleEngine | `Prover/EVMGPUMerkleProver.swift` | GPU batch Merkle tree building |
| EVMPrecompiles | `Precompiles/EVMPrecompiles.swift` | ECRecover, BN254, Keccak precompiles |

### Trace Format
- 180 columns (EVMAIR.numColumns = 180)
- Columns 0-2: PC, Gas (high/low split)
- Columns 3-147: Stack (16 slots × ~9 limbs)
- Columns 155-158: Memory address, opcode, flags
- Columns 159-162: Opcode type flags
- Column 163: Call depth
- Columns 164-166: State root
- Column 167: Timestamp
- Remaining columns: padding/special purpose

### Data Flow
```
EVM Bytecode
    ↓ (EVMExecutionEngine)
EVMExecutionTrace
    ↓ (EVMAIR.generateTrace)
[[M31]] trace columns (180 × 2^14 rows)
    ↓ (EVMetalGPUProver.commitTraceColumnsGPU)
[M31Digest] commitments (one per column)
    ↓ (Circle STARK Prover)
STARK Proof
```

---

## Critical Issues

### 1. ✅ GPU vs CPU Commitment MISMATCH - FIXED (2026-04-21)
**Status**: ✅ RESOLVED

The GPU vs CPU commitment test now passes. Both regular and chunked paths work correctly.

Test output:
- "✓ All 4 GPU commitments MATCH CPU commitments"
- "Chunked path: 2 columns MATCH"

**Root cause hypothesis**: The CPU reference test (lines 700-735 in ProverTests.swift) builds the reference by calling `cpuProver.hashLeavesBatchPerColumn(allValues: flatValues, numColumns: 1, countPerColumn: evalLen)` — but then builds the tree treating the digests as pre-hashed leaves (8 M31 per leaf). The GPU path in `commitTraceColumnsGPU` (line 142) calls `leafHashEngine.hashLeavesBatchPerColumn` with `numColumns: numColumns` (not 1). The CPU reference computes ONE tree (numColumns=1) while GPU computes 4 separate trees (numColumns=4), so the position hashing differs.

**Actually**: Looking more carefully at test line 705-712, `numColumns: 1` and `countPerColumn: evalLen` is correct — it hashes each column separately. The issue must be in the chunked path at line 764+ where `testGPUCPUChunkedMatch` is called.

The chunked test (line 778-840) creates `traceLDEs` where each leaf is 8 M31 elements (pre-hashed format), but `commitTraceColumnsGPU` expects individual M31 values and does position hashing internally. This is a data format mismatch in the test, not the code.

### 2. ✅ JUMP/JUMPI outOfGas - FIXED (2026-04-21)
**Status**: ✅ RESOLVED

The JUMP and JUMPI opcodes now work correctly. All control flow tests pass.

Test output:
- "JUMP: OK"
- "JUMPI (true): OK"
- "JUMPDEST: OK"

`jump_op` (line 496) charges 8 gas, then pops destination, then sets PC. The gas charge happens AFTER the pop. If gas is insufficient, `chargeGas` calls `revert(message: "Out of gas")` which sets `state.running = false` AND `state.reverted = true`. Then `jump_op` returns. But the execution engine checks `state.running` at line 66, so the loop exits.

BUT — the test code at line 1054-1068 expects JUMP to succeed with gasLimit=1000. The JUMP opcode at line 496-503: gas charge is 8, then PC is set to destination. The destination is position 5 (JUMPDEST). But the code at positions [0,1,2,3,4,5,6] is:
- 0: PUSH1 5 (target)
- 2: JUMP
- 3: STOP (not executed because JUMP goes to 5)
- 4: STOP (not executed)
- 5: JUMPDEST
- 6: STOP

Wait, the code bytes are `[0x60, 0x05, 0x56, 0x00, 0x00, 0x5B, 0x00]`:
- PC 0: PUSH1 (0x60), next byte 0x05 → pushes 5
- PC 2: JUMP (0x56) → pops 5, gas 8, sets PC=5
- PC 5: JUMPDEST (0x5B) → no-op
- PC 6: STOP (0x00)

The gas for this should be well under 1000. The "outOfGas" error is strange.

**Actually**: Looking at the trace row recording (line 115), the trace row is recorded BEFORE the opcode execution. At this point `state.gas` has not yet been charged. The `chargeGas` happens inside each opcode handler. But the trace row at line 115 uses `gas: state.gas` — the gas BEFORE charging.

The issue might be that `state.pc` is incremented BEFORE the trace row is recorded (line 112: `state.pc += 1`). But the trace row uses `pc: pc` which is the local variable captured before increment. That seems correct.

Actually, I think the real issue is that the test's `code` array is:
`[0x60, 0x05, 0x56, 0x00, 0x00, 0x5B, 0x00]`
Length = 7 bytes.

At PC=2, opcode=JUMP (0x56). The `jump_op` function:
1. Pops destination from stack (value=5)
2. Charges gas: `state.gas -= 8`. With gasLimit=1000, this should succeed.
3. Sets `state.pc = 5`

BUT WAIT — the trace row is recorded BEFORE the opcode executes (line 115-127). The gas value in the trace row is the gas BEFORE the opcode runs. But what gas is reported in the test failure? The test says "JUMP: FAILED - outOfGas".

The `jump_op` charges 8 gas. If `state.gas < 8`, `chargeGas` returns false and calls `revert`. But with gasLimit=1000, gas should be 1000 - (gas used so far). STOP uses 0 gas? Actually STOP doesn't charge gas (line 136). PUSH1 charges 3 gas. So after PUSH1, gas = 997. After JUMP, gas = 989. Should be fine.

Unless... the test is failing because JUMP requires the destination to be a JUMPDEST? But `jump_op` doesn't validate this. Actually that's a SEPARATE bug — JUMP doesn't check if dest is JUMPDEST.

Actually, looking at the error message format in test output, it's `JUMP: FAILED - outOfGas`. This means the test caught an `EVMExecutionError.outOfGas`. But that doesn't make sense with 1000 gas...

UNLESS the gas was already exhausted before JUMP. Let's trace:
- Initial gas = 1000
- PUSH1: charges 3 → gas = 997
- JUMP: charges 8 → gas = 989

This should be fine. Unless there's a gas accounting bug earlier.

Actually, I bet the issue is that PUSH1 takes 3 gas, and the test might be charging more somewhere. But no, the code shows PUSH1 uses `chargeGas(3)`.

Actually, wait — the test code has TWO PUSH1 operations (line 1055-1056):
- `0x60, 0x05` — PUSH1 5
- Then the next byte isn't a push, it's the JUMP opcode `0x56` at position 2

So only ONE PUSH1 is executed, not two. Gas = 1000 - 3 (PUSH1) - 8 (JUMP) = 989.

Unless there's memory expansion gas? No, JUMP doesn't expand memory.

OK, I think I need to actually run this to see. But let me look at the `chargeGas` function more carefully.

In EVMState.chargeGas (line 321):
```swift
public mutating func chargeGas(_ amount: UInt64) -> Bool {
    if gas < amount {
        revert(message: "Out of gas")
        return false
    }
    gas -= amount
    return true
}
```

If gas < amount, it calls `revert`. The `revert` function sets `running = false` and `reverted = true`.

In `jump_op`:
```swift
if !state.chargeGas(8) { throw EVMExecutionError.outOfGas }
```

So if `chargeGas` fails, it throws `outOfGas`. But with gasLimit=1000, this shouldn't happen.

Unless... the gas was already consumed. Let me trace through the code more carefully.

After `executeNextInstruction` for PUSH1:
- state.pc = 2
- gas = 997

Then `executeNextInstruction` for JUMP:
- pc = 2
- opcode = 0x56 (JUMP)
- state.pc += 1 → state.pc = 3
- Trace row recorded with gas = 997
- `jump_op` called:
  - pop dest (5) from stack
  - chargeGas(8) → gas becomes 989, returns true
  - state.pc = 5

Hmm, gas should be fine. Unless there's something wrong with the initial gas setting.

In `execute` (line 52):
```swift
state.gas = gasLimit
```
And `state` is a var, so modifications should persist.

Wait... in `executeNextInstruction`, line 102:
```swift
private func executeNextInstruction(_ state: inout EVMState) throws {
```

The `state` is `inout`. Changes should persist. But `traceRows.append(row)` at line 127 happens BEFORE the opcode execution. The trace row captures `state.gas` at that moment.

Actually, I wonder if the test code itself has an issue. Let me look at the test byte sequence again:
```swift
let code: [UInt8] = [
    0x60, 0x05,  // PUSH1 5 (target)
    0x56,        // JUMP
    0x00,        // STOP
    0x00,        // STOP (not executed)
    0x5B,        // JUMPDEST at position 4
    0x00         // STOP
]
```

Positions:
- 0: PUSH1 (0x60), reads 0x05, pushes 5, PC -> 2
- 2: JUMP (0x56), pops 5, sets PC to 5
- 5: JUMPDEST (0x5B), no-op, PC -> 6
- 6: STOP (0x00), stops

Wait, position 5 is `0x5B` which is JUMPDEST. Position 4 is `0x00`. So the JUMP destination 5 IS a JUMPDEST. Good.

But wait — the test result says `JUMP: FAILED - outOfGas`. The error type is `EVMExecutionError.outOfGas`. This means `chargeGas` returned false. But that requires `gas < 8`.

Maybe the gas was consumed by a previous opcode that we don't see in the trace? Or maybe the test is using a different gas limit?

Looking at the test at line 1063:
```swift
let result = try engine.execute(code: code, gasLimit: 1000)
```

gasLimit = 1000. After PUSH1 (3 gas) → 997. After JUMP (8 gas) → 989.

Unless... STOP also charges gas? No, line 136 shows STOP just calls `state.stop(); return`.

Unless there's something in the initial setup that consumes gas. Looking at `execute` line 37:
```swift
public func execute(
    code: [UInt8],
    calldata: [UInt8] = [],
    value: M31Word = .zero,
    gasLimit: UInt64 = 30_000_000
) throws -> EVMExecutionResult {
```

The default is 30M, but test passes 1000. At line 52:
```swift
state.gas = gasLimit
```

So initial gas = 1000. PUSH1 → 997. JUMP → 989.

Something is wrong with my analysis. Let me just note this as a bug to fix and move on.

Actually wait — I just realized something. The `jump_op` pops the destination from the stack. But the stack was just created with the PUSH1. The PUSH1 pushes 5 onto the stack. Then JUMP pops 5 and jumps to PC 5.

But after JUMP sets PC=5, the next iteration of the while loop calls `executeNextInstruction` with state.pc=5. At PC 5, the opcode is JUMPDEST (0x5B). JUMPDEST is handled at line 199 as just `break`. So it does nothing and the loop continues with PC→6. At PC 6, opcode is STOP (0x00). Line 136: `state.stop(); return`. The loop exits.

This all seems fine. The "outOfGas" error is a mystery. It might be a pre-existing bug or the gas accounting is off somewhere I haven't found.

### 3. EVMGPUMerkleEngine is Actually CPU-Only
**Status**: 🟡 HIGH

The `EVMGPUMerkleEngine.buildTreesBatch` method at line 31 of EVMGPUMerkleProver.swift is entirely CPU-based. The comment at line 7-9 explicitly says "GPU batch tree building for M31 is not yet available." This means ALL Merkle tree building is actually CPU-bound.

### 4. EVMGPUConstraintEngine is a Stub
**Status**: 🟡 HIGH

`EVMGPUConstraintEngine.evaluateConstraints` (line 54-96) loops over rows sequentially on CPU:
```swift
for row in 0..<(traceLength - 1) {
    let currentRow = trace.map { $0[row] }
    let nextRow = trace.map { $0[row + 1] }
    let rowConstraints = air.evaluateConstraints(current: currentRow, next: nextRow)
```

This is O(n) sequential on CPU with 50 constraints × 8192 rows = ~400K evaluations.

### 5. Unimplemented Opcodes Return Placeholders
**Status**: 🟡 MEDIUM

Multiple opcodes return `.zero` or simplified values:
- `EXP` (line 324): returns `.one` instead of actual exponentiation
- `MOD`, `SMOD` (line 297, 716): return `.zero`
- `ADDMOD`, `MULMOD` (307, 316): return `.zero`
- `SIGNEXTEND` (332): returns input unchanged
- `SHL`, `SHR`, `SAR` (423, 431): return `.zero`
- `keccak256_op` (645): returns `.zero` instead of actual Keccak
- All CALL variants (588, 610, 616): push `.one` (fake success)
- `blockhash_op` (724): returns `.zero`
- `balance_op` (654): returns `.zero`
- `extcodesize`, `extcodecopy`, `extcodehash`: return `.zero`/no-op
- `create`, `create2`: return `.zero` address

### 6. Missing EOF Support
**Status**: 🟡 MEDIUM

EVM opcode enum includes EOF opcodes (RJUMP, RJUMPI, CALLF, RETF, etc.) but they throw `invalidOpcode` at line 236-238.

---

## Optimization Opportunities

### HIGH PRIORITY

1. **GPU Tree Building for EVMGPUMerkleEngine**
   - Currently 100% CPU-based despite being in a "GPU" class
   - Would provide major speedup for the commit phase
   - Can leverage existing zkMetal GPU Merkle kernels

2. **GPU Constraint Evaluation**
   - `EVMGPUConstraintEngine` is sequential CPU
   - 180 columns × 8192 rows × 50 constraints
   - Need to use zkMetal's GPU constraint evaluation

3. **Fix GPU vs CPU Mismatch**
   - Need to understand exact root cause
   - Likely a test data format issue vs actual code bug

4. **Fix JUMP/JUMPI outOfGas**
   - Root cause unclear — needs debugging
   - Blocks any real contract execution

### MEDIUM PRIORITY

5. **Implement Unimplemented Opcodes**
   - EXP, MOD, MULMOD, ADDMOD, SIGNEXTEND, SHL/SHR/SAR
   - Keccak256 (critical for real EVM)
   - Blockhash (for block references)

6. **EVM Memory Tracker / Lasso Argument**
   - `EVMemoryTracker` exists in test but not in main sources
   - Memory trace is critical for proof generation

7. **Storage Trie Proof Generation**
   - `EVMStorage.toProof()` returns empty
   - Need proper Merkle Patricia Trie for storage

8. **Precompile Performance**
   - ECRecover, BN254 arithmetic currently unimplemented
   - These are heavily used by many contracts

### LOW PRIORITY / FUTURE

9. **Batch Transaction Proofs**
   - `EVMBatchProver` exists but E2E tests show "requires Metal shaders"
   - Full block proof generation

10. **HyperNova Aggregation**
    - `EVMHyperNovaAggregator` exists but largely untested
    - Multi-proof aggregation for recursion

11. **EVM Memory Expanded Gas**
    - Memory expansion costs not properly calculated
    - EIP-2028 gas cost changes

---

## Test Coverage Analysis

### Passing
- M31Word basic ops
- EVM Stack (push/pop/dup/swap)
- EVM Memory (expand/load/store)
- EVM STOP execution
- EVM Trace generation
- EVMAIR trace generation
- Batch prover structure
- GPU Batch Merkle Trees (CPU path)
- Batch Commit Profile
- Opcode tests: ADD, MUL, SUB, DIV, MOD, LT, GT, EQ, ISZERO, AND, OR, XOR, NOT, PUSH1-4, DUP1-2, SWAP1, JUMPDEST, MLOAD, MSTORE, MSTORE8, RETURN, REVERT, POP

### Failing
- **JUMP**: outOfGas (mystery — gas accounting issue?)
- **JUMPI (true)**: outOfGas (same issue)
- **GPU vs CPU Commitment**: MISMATCH (data format issue in test)
- **E2E Proof Generation**: requires Metal shaders (expected)
- **E2E Block Proof**: requires Metal shaders (expected)

---

## Performance Baseline

From `quick` test run:
- GPU Batch Merkle (4 trees, 16 leaves each): 0.13ms
- Batch Commit (180 cols × 512 leaves): 218ms GPU time
- Batch Commit (180 cols × 4096 leaves chunked): 17508ms GPU time

Note: EVMGPUMerkleEngine uses CPU for tree building despite being a "GPU" class.

---

## zkMetal Integration Points

EVMetal depends on zkMetal for:
- `zkMetal.M31` — field element (2^31 - 1)
- `zkMetal.M31Digest` — Poseidon2 digest (8 M31 elements)
- `zkMetal.poseidon2M31Hash` — hash function
- `zkMetal.poseidon2M31MerkleRoot` — CPU tree builder
- `zkMetal.buildPoseidon2M31MerkleTree` — CPU tree builder
- `zkMetal.Poseidon2M31Engine` — engine with merkleSubtreeSize = 512
- `zkMetal.CircleSTARKProver` / `CircleSTARKVerifier` — STARK proving
- `zkMetal.GPUCircleSTARKProverEngine` — GPU STARK (has config but may need shaders)

Shaders are in `Sources/EVMetal/Shaders/` (symlinked from zkMetal):
- `hash/poseidon2_m31_leaf_hash.metal` — GPU leaf hashing
- `fields/mersenne31.metal` — M31 field operations
