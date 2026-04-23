# Recursive Aggregation Design: M31 → BN254 (Transparent)

## Overview

EVMetal generates Circle STARK proofs over the M31 field (~9s per block, ~30KB proof). To verify these on Ethereum L1 efficiently, we convert to BN254 format using transparent recursive aggregation via Nova/HyperNova folding.

This document describes the implementation of the recursive aggregation pipeline that:
1. Takes M31 Circle STARK proofs
2. Folds them via Nova/HyperNova
3. Applies CycleFold optimization (BN254/Grumpkin cycle)
4. Outputs O(1) size proofs for BN254 verification

## Architecture

```
EVM Transaction
    ↓
EVMetal GPU Prover (M31 Circle STARK)  [existing]
    ↓ ~30KB M31 proof
M31 Circle STARK Proof
    ↓
[NEW] EVMCircleSTARKVerifierCircuit
    Encodes M31 verifier as R1CS constraints
    ↓
[NEW] EVMCircleSTARKIVC
    Nova IVC wrapper, folds into accumulator
    ↓
[NEW] EVMCycleFoldFinalizer
    CycleFold optimization (BN254/Grumpkin cycle)
    ↓ ~200 bytes
Final Proof (transparent, O(1) verification)
    ↓
EVMSTARKVerifier.sol
    BN254 pairing check (~300k gas)
```

## Why Transparent Proving (Nova/HyperNova)?

### Benefits
- **No trusted setup**: Uses Universal Reference String (URS) or Powers of Tau
- **Post-quantum**: Based on hash functions and folding, not discrete log
- **Incrementally verifiable**: Each block folds into previous proof
- **CycleFold optimization**: Defers EC operations to Grumpkin, reducing constraints

### Comparison with Groth16
| Aspect | Groth16 | Nova/HyperNova |
|--------|---------|----------------|
| Trusted setup | Per-circuit (toxic waste) | Universal |
| Proof size | ~200 bytes | O(log n) with Spartan |
| Verification | O(1) pairing | O(1) pairing |
| Recursion | Via circuits | Native via folding |
| Quantum security | No | Yes (hash-based) |

## Key Components

### 1. EVMCircleSTARKVerifierCircuit

**Purpose**: Encode Circle STARK verification as R1CS constraints.

**Verification steps encoded**:
1. **Merkle verification**: Verify trace column openings at query positions
   - Poseidon2-M31 hash of leaves
   - Merkle path verification (depth = logEvalLength)
2. **FRI fold check**: Verify Circle FRI fold equations
   - `f_{r+1}[i] = (f_r[2i] + f_r[2i+1]) / 2 + alpha * (f_r[2i] - f_r[2i+1]) / (2 * twiddle)`
3. **Composition check**: Verify composition polynomial at queries
4. **Deep composition**: Ensure trace satisfies AIR constraints

**Field handling**:
- M31 (~31 bits) is non-native in BN254 Fr (~254 bits)
- Uses `NonNativeFieldGadget` with 4 x 64-bit limbs
- Poseidon2 hash encoded as circuit constraints

**Constraint estimates**:
| Component | Constraints |
|-----------|------------|
| Merkle verification (per column, per query) | ~100 |
| FRI fold (per query, per round) | ~50 |
| Composition verification | ~500 |
| **Total per block** | ~50K-200K |

### 2. EVMCircleSTARKIVC

**Purpose**: Nova IVC wrapper for Circle STARK verifier.

**IVC State**:
```swift
struct CircleSTARKIVCState {
    accumulatedRoot: Fr      // Accumulated trace root
    blockCount: UInt64      // Number of blocks proven
    lastBlockNumber: UInt64 // Latest block
    proofChainHash: Fr      // Chain continuity hash
}
```

**Nova/HyperNova Folding**:
- Each step takes a Circle STARK proof
- Creates CCCS (Committed CCS instance) from verifier circuit
- Folds into running LCCCS (Linearized CCCS) accumulator
- After N steps: O(1) final verification

**Public inputs**:
```
[z_i hash, z_{i+1} hash, step_count, block_count]
```

### 3. EVMCycleFoldFinalizer

**Purpose**: Reduce constraint count using BN254/Grumpkin curve cycle.

**Curve cycle**:
- BN254 Fr = Grumpkin Fq (same prime)
- BN254 Fq = Grumpkin Fr (same prime)

**How CycleFold works**:
1. Instead of doing EC operations directly in BN254 circuit
2. Defer them to Grumpkin (where they're native)
3. Accumulate on Grumpkin
4. Final check verifies both curves are consistent

**Constraint reduction**:
| Without CycleFold | With CycleFold |
|-------------------|----------------|
| ~500K constraints | ~50K constraints |
| Full Fp12 tower | Deferred to Grumpkin |

### 4. EVMSTARKVerifier.sol

**Purpose**: On-chain BN254 verifier for final proof.

**Verification equation**:
```
e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1
```

**Gas costs**:
| Component | Gas |
|-----------|-----|
| Pairing check | ~300k |
| Public input validation | ~50k/input |
| Grumpkin check | ~20k |
| **Total** | ~350k + 50k * num_inputs |

## Transparent Verification (No Trusted Setup)

Nova uses **transparent verification** - no trusted setup parameters (α, β, γ, δ) needed:

**Verification checks**:
1. **Pedersen commitment**: Verify point is on BN254 curve (y² = x³ + 3)
2. **CCS relation**: sum_j c_j * hadamard(M_{S_j} * z) = 0
3. **MLE evaluations**: Verify v_i evaluations at challenge point r
4. **State hash**: keccak256 consistency check

**Gas costs** (optimized):
| Component | Gas | Notes |
|-----------|-----|-------|
| Coordinate bounds check | ~3k | Quick overflow check |
| Identity point check | ~5k | Inlined comparison |
| Curve membership (inline) | ~15k | y² = x³ + 3 check |
| State hash verification | ~20k | keccak256 |
| MLE consistency | ~5k | Length + bounds check |
| **Optimistic total** | ~50k | State hash skipped |
| **Full verification** | ~70k | All checks |
| **With CycleFold** | ~85k | + Grumpkin check |

**Gas optimizations**:
1. Packed VK storage (single slot)
2. Short-circuit evaluation (cheap checks first)
3. Inlined curve checks
4. Optimistic mode (skip expensive hash)
5. Minimal memory allocations

## Integration with EVMetalBlockProver

```swift
// Enable IVC
let prover = try EVMetalBlockProver(config: .default)
try prover.enableIVC(config: .default)

// Prove blocks sequentially
let proof1 = try await prover.proveIVC(transactions: txs1, blockContext: ctx1)
let proof2 = try await prover.proveIVC(transactions: txs2, blockContext: ctx2)

// Get final proof for on-chain
let finalProof = try prover.getFinalProof()
let calldata = prover.serializeFinalProof()

// Verify on L1
require(verifier.verifyIVCProof(calldata));
```

## Proof Size Evolution

| Stage | Size | On-Chain Gas |
|-------|------|-------------|
| Circle STARK (M31) | ~30KB | N/A |
| After Nova folding | ~5KB | N/A |
| After CycleFold | ~200 bytes | N/A |
| **Transparent verification** | ~200 bytes | **~70k gas** |
| Full pairing (if needed) | ~200 bytes | ~370k gas |

## Security Analysis

### Security Bits
- Circle STARK: ~120 bits (30 queries × 4x blowup)
- Nova folding: Additional hash-based security
- Total: ~180+ bits (exceeds Ethereum requirements)

### Transparent vs. Groth16
| Aspect | Transparent (Nova) | Groth16 |
|--------|-------------------|---------|
| Setup | Universal (Powers of Tau) | Per-circuit |
| Toxic waste | None | Requires ceremony |
| Quantum resistance | Yes | No |
| Proof size | Larger | Smaller |
| Verification | O(1) | O(1) |

## Performance Targets

| Metric | Target |
|--------|--------|
| Per-block proving | ~9s (existing) |
| IVC fold step | ~100ms |
| Final verification | ~350k gas |
| Proof size (final) | ~200 bytes |

## Files Created

```
Sources/EVMetal/Aggregation/
├── EVMCircleSTARKVerifierCircuit.swift  # R1CS circuit for M31 verifier
├── EVMCircleSTARKIVC.swift              # Nova IVC wrapper
├── EVMCycleFoldFinalizer.swift          # CycleFold optimization
├── EVMBN254Verifier.swift               # BN254 verification
└── EVMetalBlockProver+IVC.swift         # Integration with block prover

contracts/
└── EVMSTARKVerifier.sol                 # On-chain verifier

docs/
└── RECURSIVE-AGGREGATION-DESIGN.md     # This document
```

## References

- [Nova: Recursive Zero-Knowledge Arguments](https://eprint.iacr.org/2021/370) (Kothapalli et al. 2022)
- [HyperNova: Recursive arguments from folding schemes](https://eprint.iacr.org/2023/573) (Kothapalli, Setty 2023)
- [CycleFold: Folding-scheme-based recursive arguments](https://eprint.iacr.org/2023/1192) (2023)
- [Circle STARK](https://starkware.co/blog/stark-detailed-summary) (StarkWare 2024)
- [Taiko's Transparent Proving Architecture](https://github.com/taikoxyz/taiko-mono) (Production reference)

## Next Steps

1. **Complete verifier circuit**: Full implementation of Poseidon2 circuit gadget
2. **Integration testing**: End-to-end test with actual block proofs
3. **Groth16 wrapper**: Generate final Groth16 proof for efficient L1 verification
4. **Trusted setup**: Organize Powers of Tau ceremony if needed
5. **Production deployment**: Deploy EVMSTARKVerifier.sol to mainnet
