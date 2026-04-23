# Circle FRI GPU Prover Metal Shader Compilation Error

## Issue Description

When using `GPUCircleFRIProverEngine.commitPhaseParallel()` with column subset compression (32 columns), Metal shader compilation fails with a "redefinition of 'M31_INV2'" error.

## Error Message

```
Error Domain=MTLLibraryErrorDomain Code=3 "program_source:261:15: error: redefinition of 'M31_INV2'
constant uint M31_INV2 = 1073741824u;  // (2^31 - 1 + 1) / 2 = 2^30
              ^
program_source:123:15: note: previous definition is here
constant uint M31_INV2 = 1073741824u;  // (2^31 - 1 + 1) / 2 = 2^30
              ^
```

## Affected Code Path

**File:** `zkMetal/Sources/zkMetal/STARK/GPUCircleFRIProverEngine.swift`

**Method:** `commitPhaseParallel()`

**Trigger Conditions:**
- Column subset compression enabled (e.g., 32 out of 180 columns)
- `GPUCircleFRIProverEngine.commitPhaseParallel()` is called
- Metal library compilation fails due to duplicate constant definitions

## Root Cause

The `GPUCircleFRIProverEngine` combines multiple Metal shader source strings into a single library for compilation. When these shaders are combined, symbols like `M31_INV2` that are defined in both `circle_fri.metal` and `fused_circle_ntt_constraint.metal` cause redefinition errors.

The error output shows:
- `program_source:123` - first definition (likely from an include)
- `program_source:261` - second definition (likely from a combined shader)
- `program_source:283` - additional syntax errors cascade from the redefinition

## Additional Error (Cascade Effect)

```
error: invalid address space qualification for buffer pointee type 'const device M31 *'
    device const M31** inv2xArray  [[buffer(3)]],    // Array of inv2x buffers per round
    ^
error: cannot combine with previous 'type-name' declaration specifier
    uint half = n >> 1;
         ^
```

This suggests the Metal compiler continues parsing after the redefinition error, causing variable declarations to conflict with previously declared types.

## Affected Configurations

| Compression | Columns | logBlowup | Status |
|-------------|---------|-----------|--------|
| `fast` (16 cols) | 16 | 1 | Works |
| `standard` (32 cols) | 32 | 2 | **FAILS** |
| `none` (180 cols) | 180 | 4 | Unknown |

## Reproduction Steps

1. Use EVMetal to process a real Ethereum block with unified proving
2. Enable column subset compression with 32 columns:
```bash
./EVMetalRunner real-block-unified <block_number> standard
```
3. Observe the Metal shader compilation error

## Expected Behavior

GPU Circle FRI should compile and execute successfully regardless of column subset size.

## Suggested Fixes

1. **Add include guards to Metal shaders**: Use `#ifndef M31_INV2` / `#define M31_INV2` pattern
2. **Separate shader compilation**: Compile each shader source into a separate library, then link
3. **Deduplicate constants**: Move shared constants (M31_INV2, etc.) to a common header that is included once
4. **Use shader regions**: Metal supports `[[kernel]]` attributes to separate kernels - compile each kernel separately

## Metal Shader Files Involved

- `zkMetal/Sources/Shaders/fri/circle_fri.metal` (line 14)
- `zkMetal/Sources/Shaders/fri/circle_fri_parallel.metal` (line 21)
- `zkMetal/Sources/Shaders/constraint/fused_circle_ntt_constraint.metal` (line 12)
- `zkMetal/Sources/Shaders/fri/p1_fri.metal` (line 15)

All define `M31_INV2` without guards.

## Additional Context

- The issue does not occur with smaller E2E test traces (1024 rows, 180 columns all used)
- The E2E tests pass because they use a different code path that doesn't trigger the problematic GPU FRI code
- The error only manifests when `GPUCircleFRIProverEngine.commitPhaseParallel()` is actually used in the proof flow
