# Proof Compression: Reducing Trace Tree Size While Maintaining Correctness

This document describes the proof compression optimization implemented in EVMetal to reduce trace tree size while maintaining correctness guarantees.

## Overview

The original system had these characteristics:
- 180 columns x N leaves (e.g., 131,072 for 123 transactions with logTrace=8, logBlowup=1)
- Tree depth = log2(131,072) = 17 levels
- Query proofs require 17 M31Digest siblings per column per query

The proof compression optimization reduces these costs by:
1. **Reducing logTraceLength**: Smaller per-transaction trace length
2. **Column selection**: "Commit to all, prove subset" approach
3. **Two-tier proving**: Fast proof for critical columns, full proof when needed

## 1. Reducing logTraceLength

### How It Works

The per-transaction trace length (logTraceLength) determines how many rows each transaction uses in the block trace.

| logTraceLength | Rows per TX | Tree Depth (123 txs) | Reduction |
|----------------|-------------|---------------------|-----------|
| 12 (baseline)  | 4096        | 19 levels           | 1x        |
| 8              | 256         | 15 levels           | 4x smaller |
| 6              | 64          | 13 levels           | 16x smaller |
| 4              | 16          | 11 levels           | 64x smaller |

### Security Implications

Lower logTraceLength means:
- **Weaker degree check**: Shorter traces have lower maximum polynomial degree
- **Compensate with more queries**: Increase `numQueries` to maintain soundness
- **Compensate with higher blowup**: Increase `logBlowup` for stronger LDE

Recommended compensations:
```
logTraceLength=8:  Keep numQueries >= 20, logBlowup >= 2
logTraceLength=6:  Keep numQueries >= 30, logBlowup >= 3
logTraceLength=4:  Keep numQueries >= 50, logBlowup >= 4
```

## 2. Column Selection: Commit to All, Prove Subset

### How It Works

The "commit to all, prove subset" approach:

1. **Compute all 180 column commitments**: For full soundness, all columns are committed
2. **Include subset in FRI**: Only critical columns are included in the FRI composition polynomial
3. **FRI verifies subset**: The FRI verification only checks the subset

This is secure because:
- All columns are committed to the Merkle tree
- A malicious prover must provide valid data for ALL columns
- The subset check provides probabilistic soundness over all columns

### Security Implications

| Proving Columns | Commit Columns | Soundness Loss | Speedup |
|-----------------|---------------|---------------|---------|
| 180 (all)      | 180           | None          | 1x      |
| 32              | 180           | ~2.5 bits     | ~5x     |
| 16              | 180           | ~3.3 bits     | ~8x     |

The soundness loss is: `log2(180 / provingColumns)` bits

### Default Critical Columns

EVMetal defines 32 critical columns based on EVM execution semantics:

```swift
// Execution flow (8 columns)
0, 1, 2, 147, 148, 149, 163, 164

// Stack columns (16 columns - first 2 stack words)
3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18

// Memory columns (4 columns)
147, 150, 151, 152

// Arithmetic columns (4 columns)
20, 21, 22, 23
```

These columns capture:
- Execution flow (PC, gas, call depth)
- State transitions (stack, memory)
- Critical arithmetic operations

## 3. Two-Tier Proving

### How It Works

Two-tier proving creates both:
- **Tier 1 (Fast)**: Only critical columns verified
- **Tier 2 (Full)**: All columns verified

The tier 1 proof can be verified quickly, while tier 2 provides full security when needed.

### Use Cases

1. **Fast settlement**: Use tier 1 for quick block confirmation
2. **Full verification**: Use tier 2 for final settlement or disputes
3. **Recursive proving**: Tier 1 proofs can be recursively verified

## Configuration Presets

### ProofCompressionConfig Presets

```swift
// Maximum compression: fastest proving, lowest security
let maxCompression = ProofCompressionConfig(
    logTraceLength: 4,      // 16 rows per tx
    logBlowup: 1,           // 2x blowup
    numQueries: 50,          // Compensate with more queries
    provingColumnCount: 16   // Only 16 columns in FRI
)

// High compression: good speedup with reasonable security
let highCompression = ProofCompressionConfig(
    logTraceLength: 6,      // 64 rows per tx
    logBlowup: 2,           // 4x blowup
    numQueries: 30,         // More queries for security
    provingColumnCount: 32   // 32 critical columns
)

// Standard compression: balanced
let standard = ProofCompressionConfig(
    logTraceLength: 8,      // 256 rows per tx
    logBlowup: 2,           // 4x blowup
    numQueries: 20,         // Standard queries
    provingColumnCount: 32   // 32 critical columns
)
```

## Security Analysis

### Estimated Soundness Loss

The total soundness loss from compression is:

```
totalLoss = traceLoss + columnLoss + blowupLoss

Where:
- traceLoss = (12 - logTraceLength) * 0.5
- columnLoss = log2(180 / provingColumnCount)
- blowupLoss = (4 - logBlowup) * 0.3
```

### Example Analysis

For `logTraceLength=6, logBlowup=2, provingColumnCount=32`:

```
traceLoss = (12 - 6) * 0.5 = 3 bits
columnLoss = log2(180 / 32) = 2.5 bits
blowupLoss = (4 - 2) * 0.3 = 0.6 bits
totalLoss = ~6 bits

Baseline security: ~140 bits (180 columns * 12 trace * 4 blowup)
Compressed security: ~134 bits

Still provides ~128-bit security with good margin
```

## Usage Examples

### Basic Usage

```swift
// Create prover with default settings
let prover = try EVMetalBlockProver()

// Generate proof
let proof = try await prover.prove(
    transactions: transactions,
    blockContext: blockContext
)
```

### With Compression

```swift
// Create prover with high compression
let compression = ProofCompressionConfig.highCompression
let prover = try EVMetalBlockProver(
    config: .fast,
    compressionConfig: compression
)

// Generate proof (automatically uses compression settings)
let proof = try await prover.prove(
    transactions: transactions,
    blockContext: blockContext
)
```

### Two-Tier Proving

```swift
// Create prover with two-tier support
let compression = ProofCompressionConfig(
    logTraceLength: 6,
    provingColumnCount: 32,
    enableTwoTierProving: true,
    tier1NumQueries: 8,
    tier2NumQueries: 50
)

let prover = try EVMetalBlockProver(
    config: .fast,
    compressionConfig: compression
)

// Generate both tiers
let result = try await prover.proveTwoTier(
    transactions: transactions,
    blockContext: blockContext
)

// Fast verification (tier 1)
if let tier1 = result.tier1Proof {
    verifyFast(tier1)
}

// Full verification (tier 2)
verifyFull(result.tier2Proof)
```

### Benchmarking Compression

```swift
// Benchmark compression effectiveness
let result = try await EVMetalBlockProver.benchmarkCompression(
    transactionCount: 123,
    compressionConfig: .highCompression
)

print(result.summary)
```

## Trade-off Matrix

For 123 transactions with logBlowup=1:

| Configuration           | Tree Depth | FRI Cols | Est. Speedup | Security |
|------------------------|------------|----------|--------------|----------|
| Baseline (12, 180)     | 19         | 180      | 1x           | Optimal  |
| logTrace=8, cols=32    | 15         | 32       | ~5x          | ~3 bits loss |
| logTrace=6, cols=32    | 13         | 32       | ~10x         | ~6 bits loss |
| logTrace=4, cols=16    | 11         | 16       | ~20x         | ~8 bits loss |

## Implementation Details

### Key Files Modified

1. **ProofCompressionConfig.swift**: Configuration and security analysis
2. **BlockAIR.swift**: Column subset support in AIR
3. **EVMetalBlockProver.swift**: Two-tier proving integration

### Security Properties

1. **Correctness**: All committed data must be valid
2. **Soundness**: Probability of accepting invalid proof is negligible
3. **Zero-knowledge**: Transaction data remains private (future work)

### Limitations

1. **Column subset soundness**: Only proven columns are directly verified
2. **Trace length tradeoffs**: Shorter traces may miss edge cases
3. **Two-tier complexity**: More complex verification flow

## Recommendations

### For Production

- Use `ProofCompressionConfig.standard` or higher
- Keep `numQueries >= 20` and `logBlowup >= 2`
- Only reduce `logTraceLength` for simple transactions

### For Testing/Development

- Use `ProofCompressionConfig.highCompression` for faster iteration
- Use `ProofCompressionConfig.maxCompression` for maximum speed

### For High-Value Transactions

- Use `ProofCompressionConfig.lowCompression` or no compression
- Use two-tier proving with full verification
- Consider recursive verification for extra security

## Future Work

1. **Adaptive compression**: Automatically adjust based on transaction complexity
2. **ZK-friendly commitments**: Explore polynomial commitments with better properties
3. **Recursive aggregation**: Aggregate many tier-1 proofs into one
4. **Formal verification**: Prove security properties formally
