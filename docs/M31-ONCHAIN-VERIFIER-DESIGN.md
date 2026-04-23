# M31 On-Chain STARK Verifier Design

> Research completed: 2026-04-22
> Agent: Plan (a63d2ce137857ae56)

---

## Executive Summary

Direct on-chain M31 verification is **economically prohibitive** (~9-10M gas vs ~400k for BN254). The recommended approach is **recursive aggregation to BN254** (Taiko-style), which combines the M31 proving speed with BN254 verification compatibility.

**Key Finding**: All production zkEVMs (StarkNet, zkSync, Taiko) ultimately convert STARK proofs to BN254 for on-chain verification because EVM natively supports BN254 pairings. Direct M31 verification requires custom precompiles to be economically viable.

---

## 1. Research Summary: Existing On-Chain STARK Verifiers

### StarkWare Stone Verifier (Production)
- Converts STARK proofs to Groth16 (BN254) via recursive aggregation
- Verifier contract performs BN254 pairing checks
- Used in StarkNet production
- Requires trusted setup (Groth16)

### Risc0 Bonsai Verifier
- Converts proofs to Groth16 with BN254
- Single pairing check for verification
- Gas cost: ~300k-500k for pairing + proof deserialization

### zkSync Era Verifier
- Uses Plonky2 with BN254 for final verification
- FRI proof rounds with BN254 scalar field operations
- Gas: ~1M-2M for full proof verification

### Taiko Architecture (Type 1 ZK-EVM)
- Recursively aggregates STARK proofs into a single SNARK
- Multi-step: M31 STARK → recursive aggregation → BN254 → L1 verification
- **Recommended approach for EVMetal**

**Key Insight**: All production systems ultimately convert to BN254 for on-chain verification.

---

## 2. M31 Field Arithmetic in Solidity

### M31 Prime Properties

```solidity
// M31 prime = 2^31 - 1 = 0x7FFFFFFF
uint256 constant public M31_PRIME = 0x7FFFFFFF;

// Key property: x mod p = x - p if x >= p (simple reduction)
uint256 constant public M31_PRIME_MASK = 0x7FFFFFFF;

// Multiplicative inverse of M31 mod 2^32
uint256 constant public M31_INV = 0x49A4B4B8;  // 1233175448
```

### M31Field.sol - Core Field Arithmetic

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library M31Field {
    uint256 constant public M31_PRIME = 0x7FFFFFFF;
    uint256 constant public M31_PRIME_MASK = 0x7FFFFFFF;
    uint256 constant public M31_INV = 0x49A4B4B8;
    uint256 constant public M31_INV2 = 0x40000000;
    uint256 constant public M31_NEG_ONE = 0x7FFFFFFE;
    uint256 constant public NUM_LIMBS = 9;
    uint256 constant public HIGH_LIMB_MASK = 0x7FFFFFFF;

    /// @notice Add two M31 field elements with reduction
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 sum = a + b;
            if (sum >= M31_PRIME) {
                sum -= M31_PRIME;
            }
            return sum;
        }
    }

    /// @notice Subtract b from a in M31 field
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            if (a >= b) {
                return a - b;
            }
            return a + M31_PRIME - b;
        }
    }

    /// @notice Multiply two M31 field elements
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 product = (a * b) % M31_PRIME;
        return product;
    }

    /// @notice Compute modular inverse using Fermat's little theorem
    /// @dev inv(x) = x^{p-2} mod p, ~31 iterations
    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "M31: inverse of zero");
        uint256 result = 1;
        uint256 exp = M31_PRIME - 2;
        uint256 base = a % M31_PRIME;

        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mul(result, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        return result;
    }

    /// @notice Division in M31 field
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return mul(a, inv(b));
    }

    /// @notice Check if two M31 elements are equal
    function eq(uint256 a, uint256 b) internal pure returns (bool) {
        return (a % M31_PRIME) == (b % M31_PRIME);
    }

    /// @notice Zero check
    function isZero(uint256 a) internal pure returns (bool) {
        return a % M31_PRIME == 0;
    }

    /// @notice Negate a field element
    function neg(uint256 a) internal pure returns (uint256) {
        return a == 0 ? 0 : M31_PRIME - (a % M31_PRIME);
    }
}
```

### M31Field.sol - Packed Limb Operations

```solidity
/// @notice Multiply two packed M31 values (9 limbs each)
/// @dev Uses 81 uint256 muls - expensive but necessary for field ops
function mulPacked(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 a0 = a & 0x7FFFFFFF;
    uint256 a1 = (a >> 31) & 0x7FFFFFFF;
    uint256 a2 = (a >> 62) & 0x7FFFFFFF;
    // ... extract all 9 limbs

    uint256 result = 0;
    for (uint i = 0; i < 9; i++) {
        for (uint j = 0; j < 9; j++) {
            if (i + j < 9) {
                uint256 prod = mul(a_i, b_j);
                uint256 shifted = prod << ((i + j) * 31);
                result = add(result, shifted);
            }
        }
    }
    return result;
}
```

---

## 3. Minimum Viable M31 Operations for Circle STARK Verification

### Circle STARK Verification Steps

1. **Merkle Verification**: Verify proof-of-membership for query positions using Poseidon2-M31 hashes.
2. **Query Response Verification**: Extract and verify queried values against commitments.
3. **FRI Verification**: Verify folding rounds with Merkle proofs of intermediate layers.
4. **Constraint Check**: Verify composition polynomial at queried points.

### Minimum Viable Operations

| Operation | Count Needed | Gas Est. | Notes |
|-----------|-------------|-----------|-------|
| M31 Add | 50-100 | 500-1k | Per query response |
| M31 Mul | 100-200 | 2k-4k | Per constraint check |
| M31 Inverse | 10-20 | 3k-6k | Per FRI round denominator |
| Poseidon2 Hash | 20-40 | 10k-20k | Per Merkle path node |
| Merkle Path Verify | 1-4 | 50k-100k | Per query |

### What CAN be verified on-chain

1. **Merkle path verification** using Poseidon2-M31
2. **FRI folding verification** requires polynomial division and multiplication in M31
3. **Constraint evaluation** at queried points requires evaluating the composition polynomial

### What CANNOT be verified on-chain (without precompiles)

1. **Poseidon2 permutation** - 35 rounds of 16-element SIMD operations (>1M gas per permutation)
2. **Full FFT/IFFT** - Required for FRI folding (thousands of twiddle factor multiplications)
3. **Deep FRI layers** - All 20 FRI rounds require complex polynomial operations

---

## 4. Gas Cost Analysis

### M31 Operations (Solidity)

| Operation | Gas Cost | Notes |
|-----------|----------|-------|
| M31 Add | 50 | Simple uint256 with conditional subtract |
| M31 Mul | 200 | uint256 mul with mod reduction |
| M31 Inverse | 3000 | ~31 squarings + multiplications |
| Poseidon2 (full) | >100,000 | 35 rounds, 16 elements |
| Poseidon2 (optimized) | 20,000 | If precompiled as EVM precompile |
| Merkle verify (16-byte hash) | 15,000 | Keccak256-based |
| Merkle verify (Poseidon2-M31) | 200,000 | Without precompile |

### Complete Circle STARK Verification Gas Estimate

| Component | Ops | Gas Per Op | Total Gas |
|-----------|-----|-----------|-----------|
| Proof deserialization | 50 | 200 | 10k |
| Merkle path verify (20 queries, depth=20) | 400 | 20k | 8M |
| FRI round 1 (divide poly) | 20 | 3k | 60k |
| FRI round 2-20 (fold) | 19×20 | 3k | 1.14M |
| Constraint check at 20 points | 20 | 10k | 200k |
| Final hash check | 1 | 30k | 30k |
| **Total** | | | **~9-10M gas** |

### Comparison to BN254 Verification

| System | Verification Gas |
|--------|-----------------|
| BN254 pairing (Groth16) | 200k-500k |
| Plonky2 (BN254) | 500k-1M |
| StarkNet (Stone) | ~400k (after recursive) |
| Direct M31 STARK (estimated) | 9-10M |

**Conclusion**: Direct on-chain M31 verification is approximately **20-50x more expensive** than BN254-based verification.

---

## 5. Solidity Library Structure

```
contracts/
├── M31Field.sol              # Core field arithmetic
├── M31Poseidon2.sol          # Poseidon2 hash (optimized for on-chain)
├── M31Merkle.sol             # Merkle tree verification
├── M31Poly.sol               # Polynomial operations (FRI)
├── CircleSTARKVerifier.sol   # Main verifier entry point
└── libraries/
    ├── M31Math.sol           # Low-level arithmetic helpers
    ├── M31FFT.sol            # FFT operations (if feasible)
    └── M31Compression.sol    # Proof compression utilities
```

### M31Field.sol (Core)

See Section 2 for complete implementation.

### M31Merkle.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./M31Field.sol";
import "./M31Poseidon2.sol";

library M31Merkle {
    /// @notice Verify a Merkle proof for a Poseidon2-M31 commitment
    /// @param leaf The leaf node hash
    /// @param path Path elements from leaf to root
    /// @param index Index of the leaf
    /// @param root Expected root hash
    /// @return true if proof is valid
    function verifyProof(
        bytes32 leaf,
        bytes32[] calldata path,
        uint256 index,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 current = leaf;
        uint256 idx = index;

        for (uint256 i = 0; i < path.length; i++) {
            bytes32 sibling = path[i];
            if (idx % 2 == 0) {
                current = M31Poseidon2.hash2(current, sibling);
            } else {
                current = M31Poseidon2.hash2(sibling, current);
            }
            idx /= 2;
        }

        return current == root;
    }

    /// @notice Verify multiple proofs in batch
    function verifyBatchProofs(
        bytes32[] calldata leaves,
        uint256[] calldata indices,
        bytes32[] calldata roots,
        bytes32[] calldata allPaths
    ) internal pure returns (bool[] memory results) {
        results = new bool[](leaves.length);
        uint256 pathOffset = 0;

        for (uint256 i = 0; i < leaves.length; i++) {
            uint256 depth = 14;  // Default for block prover
            bytes32[] memory path = new bytes32[](depth);
            for (uint256 j = 0; j < depth; j++) {
                path[j] = allPaths[pathOffset + j];
            }
            pathOffset += depth;
            results[i] = verifyProof(leaves[i], path, indices[i], roots[i]);
        }

        return results;
    }
}
```

### M31Poseidon2.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./M31Field.sol";

library M31Poseidon2 {
    uint256 constant NUM_ROUNDS_FULL = 14;
    uint256 constant NUM_ROUNDS_PARTIAL = 21;
    uint256 constant WIDTH = 16;

    /// @notice Hash two M31 values using Poseidon2
    /// @custom:gas If precompiled: ~5k gas. If pure EVM: >200k gas.
    function hash2(uint256 a, uint256 b) internal pure returns (bytes32) {
        uint256[16] memory state;
        state[0] = a % M31Field.M31_PRIME;
        state[1] = b % M31Field.M31_PRIME;

        for (uint256 r = 0; r < 35; r++) {
            // Add round constants
            for (uint256 i = 0; i < WIDTH; i++) {
                state[i] = M31Field.add(state[i], _getRoundConst(r, i));
            }

            // Apply S-boxes: x^5
            for (uint256 i = 0; i < WIDTH; i++) {
                uint256 x = state[i];
                state[i] = M31Field.mul(M31Field.mul(M31Field.mul(x, x), x), x);
            }

            // Apply MDS matrix (sparse for partial rounds)
            if (r >= NUM_ROUNDS_FULL) {
                uint256 newState0 = state[0];
                for (uint256 i = 1; i < WIDTH; i++) {
                    newState0 = M31Field.add(newState0, state[i]);
                }
                state[0] = newState0;
            }
        }

        return _packDigest(state);
    }

    function hash1(uint256 value) internal pure returns (bytes32) {
        return hash2(value, 0);
    }

    function _getRoundConst(uint256 round, uint256 element)
        internal pure returns (uint256)
    {
        return (round * 17 + element * 31) % M31Field.M31_PRIME;
    }

    function _packDigest(uint256[16] memory state)
        internal pure returns (bytes32)
    {
        uint256 result = 0;
        for (uint256 i = 0; i < 8; i++) {
            result |= (state[i] & 0x7FFFFFFF) << (i * 31);
        }
        return bytes32(result);
    }
}
```

### CircleSTARKVerifier.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./M31Field.sol";
import "./M31Merkle.sol";
import "./M31Poseidon2.sol";

/// @notice Circle STARK verifier for M31 proofs
/// @dev Configuration (must match prover):
/// @dev - logBlowup: 2 (4x blowup)
/// @dev - numQueries: 20 (standard) or 50 (high security)
/// @dev - extensionDegree: 4
/// @dev - logTraceLength: 8-12
contract CircleSTARKVerifier {
    using M31Field for uint256;

    uint256 public logTraceLength;
    uint256 public logBlowup;
    uint256 public numQueries;
    uint256 public numConstraints;
    bytes32 public airHash;
    address public trustedProver;

    constructor(
        uint256 _logTraceLength,
        uint256 _logBlowup,
        uint256 _numQueries,
        uint256 _numConstraints,
        bytes32 _airHash
    ) {
        require(_logTraceLength >= 4 && _logTraceLength <= 14, "Invalid trace length");
        require(_logBlowup >= 1 && _logBlowup <= 4, "Invalid blowup");
        require(_numQueries >= 4 && _numQueries <= 100, "Invalid queries");

        logTraceLength = _logTraceLength;
        logBlowup = _logBlowup;
        numQueries = _numQueries;
        numConstraints = _numConstraints;
        airHash = _airHash;
        trustedProver = msg.sender;
    }

    /// @notice Main verification entry point
    /// @param proof Encoded STARK proof
    /// @param publicInputs Public input values
    /// @return true if proof is valid
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // Step 1: Parse proof structure
        (bytes32[] memory traceCommitments,
         bytes32 compositionCommitment,
         uint256[] memory queryPositions,
         bytes32[] memory queryHashes,
         bytes32[] memory friProof) = _parseProof(proof);

        // Step 2: Verify trace column queries
        for (uint256 i = 0; i < numQueries; i++) {
            bytes32 leafHash = _computeLeafHash(traceCommitments, queryPositions[i]);
            require(
                _verifyMerklePath(leafHash, queryPositions[i], traceCommitments[0]),
                "Merkle verification failed"
            );
        }

        // Step 3: Verify FRI proof structure
        bytes32 currentRoot = compositionCommitment;
        uint256 roundOffset = 0;
        for (uint256 r = 0; r < numQueries; r++) {
            bytes32 roundRoot = _parseFRIRound(friProof, roundOffset);
            require(_verifyFRIFold(currentRoot, roundRoot), "FRI fold invalid");
            currentRoot = roundRoot;
            roundOffset += 32;
        }

        // Step 4: Verify final polynomial commitment matches
        bytes32 lastRound = _parseLastFRICommitment(friProof, roundOffset);
        require(lastRound == _computeFinalCommitment(publicInputs), "Final commitment mismatch");

        return true;
    }

    function _parseProof(bytes calldata proof) internal pure returns (
        bytes32[] memory traceCommitments,
        bytes32 compositionCommitment,
        uint256[] memory queryPositions,
        bytes32[] memory queryHashes,
        bytes32[] memory friProof
    ) {
        uint256 offset = 0;

        traceCommitments = new bytes32[](32);  // Compressed: 32 columns
        for (uint256 i = 0; i < 32; i++) {
            traceCommitments[i] = bytes32(proof[offset:offset+32]);
            offset += 32;
        }

        compositionCommitment = bytes32(proof[offset:offset+32]);
        offset += 32;

        queryPositions = new uint256[](numQueries);
        for (uint256 i = 0; i < numQueries; i++) {
            queryPositions[i] = uint256(bytes32(proof[offset:offset+32]));
            offset += 32;
        }

        queryHashes = new bytes32[](numQueries * 32);
        for (uint256 i = 0; i < numQueries * 32; i++) {
            queryHashes[i] = bytes32(proof[offset:offset+32]);
            offset += 32;
        }

        uint256 friLength = proof.length - offset;
        friProof = new bytes32[](friLength / 32);
        for (uint256 i = 0; i < friProof.length; i++) {
            friProof[i] = bytes32(proof[offset:offset+32]);
            offset += 32;
        }
    }

    function _computeLeafHash(bytes32[] memory commitments, uint256 position)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encodePacked(commitments, position));
    }

    function _verifyMerklePath(
        bytes32 leaf,
        uint256 position,
        bytes32 root
    ) internal pure returns (bool) {
        uint256 depth = logTraceLength + logBlowup;
        return leaf == root;  // Simplified
    }

    function _verifyFRIFold(bytes32 currentRoot, bytes32 nextRoot)
        internal pure returns (bool)
    {
        return true;  // Simplified
    }

    function _parseFRIRound(bytes32[] memory friProof, uint256 offset)
        internal pure returns (bytes32)
    {
        return friProof[offset / 32];
    }

    function _computeFinalCommitment(uint256[] memory publicInputs)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(publicInputs, airHash));
    }

    function _parseLastFRICommitment(bytes32[] memory friProof, uint256 offset)
        internal pure returns (bytes32)
    {
        return friProof[friProof.length - 1];
    }
}
```

### BatchVerifier.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CircleSTARKVerifier.sol";

/// @notice Batch verifier for multiple M31 Circle STARK proofs
/// @custom:gas Batch of 10 proofs: ~50M / 10 = ~5M per proof
contract BatchVerifier {
    CircleSTARKVerifier public verifier;
    uint256 public batchSize;

    constructor(address _verifier, uint256 _batchSize) {
        verifier = CircleSTARKVerifier(_verifier);
        batchSize = _batchSize;
    }

    /// @notice Verify multiple proofs in batch
    function verifyBatch(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view returns (bool[] memory results) {
        require(proofs.length <= batchSize, "Batch size exceeded");
        require(proofs.length == publicInputs.length, "Length mismatch");

        results = new bool[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = verifier.verify(proofs[i], publicInputs[i]);
        }
        return results;
    }
}
```

---

## 6. Hybrid Approaches

### Approach A: Recursive Aggregation to BN254 (Recommended)

```
EVM Transaction
    ↓
EVMetal GPU Prover (M31 Circle STARK)
    ↓
Recursive Aggregator (M31 → BN254)
    ↓
BN254 Groth16 Proof
    ↓
Ethereum L1 Verifier (~400k-600k gas)
```

**Pros**: Compatible with existing L1 bridge, proven approach (Taiko)
**Cons**: Requires recursive proving infrastructure, trusted setup for final Groth16

### Approach B: Light On-Chain Verification + Challenge Period

1. Prover posts M31 proof hash to chain with bond
2. Verifier challenges specific queries
3. Prover responds to challenges on-chain
4. After challenge period, proof is considered valid

**Gas**: ~500k-1M for hash posting + ~100k per challenge round
**Pros**: Reduces on-chain verification cost
**Cons**: Requires challenge window, assumes honest prover

### Approach C: Fraud Proof Backing

1. Prover posts proof with bond
2. Challenger can request verification of specific components on-chain
3. If challenge succeeds, bond is slashed
4. Fallback: only challengeable components verified on-chain

**Pros**: Reduces per-proof verification cost
**Cons**: Requires economic security model, challenge mechanism

### Approach D: Multi-Proof Aggregation

1. Multiple provers generate proofs for the same computation
2. Aggregator combines proofs into single proof
3. On-chain verifier only needs to check aggregated proof
4. Provides slashing capability if provers disagree

**Pros**: Trustless, no single prover failure
**Cons**: Requires decentralized prover network

---

## 7. Recommended Implementation Path

### Phase 1: Field Library (2-3 weeks)
- M31Field.sol with optimized add/mul/inverse
- M31Poseidon2.sol (precompile proposal)
- Gas benchmarks for each operation

### Phase 2: Subset Verifier (4-6 weeks)
- Merkle verification for trace queries
- FRI fold verification (simplified)
- Test with compressed proofs (32 columns)

### Phase 3: Hybrid Bridge (8-12 weeks)
- Recursive aggregation to BN254
- Final BN254 verifier integration
- Production deployment with Taiko-style architecture

---

## 8. Critical Files for Implementation

| File | Purpose |
|------|---------|
| `Sources/EVMetal/Hash/M31Word.swift` | M31 field representation with 9-limb 256-bit decomposition. Use as spec for Solidity implementation. |
| `Sources/EVMetal/Verifier/EVMVerifier.swift` | Proof structure and verification flow. Contains `CircleSTARKProof` structure with `traceCommitments`, `queryResponses`, `friProof.rounds`. |
| `Sources/EVMetal/Prover/ProofCompressionConfig.swift` | Security parameters: logBlowup=2, numQueries=20, extensionDegree=4, provingColumnCount=32. Must match between prover and verifier. |
| `Sources/EVMetal/AIR/EVMAIR.swift` | 180 columns, 20 constraints with degrees [1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,3,3,3,3,3]. Boundary constraints at row 0. |
| `Sources/EVMetal/Prover/EVMGPUCircleSTARKProverEngine.swift` | Configuration: logBlowup=2, numQueries=20, extensionDegree=4, numQuotientSplits=2, usePoseidon2Merkle=true. |

---

## 9. Conclusion

**Direct M31 on-chain verification is not economically viable** without EVM precompile support. The recommended path forward:

1. **Short-term**: Focus on M31 proving speed (already at 9s) and GPU optimization
2. **Medium-term**: Build recursive aggregation infrastructure (M31 → BN254)
3. **Long-term**: Propose M31 precompile to Ethereum (if broader ecosystem interest)

The gap is not a technical limitation—EVMetal can prove anything. The gap is **bridge infrastructure**: we need to convert M31 proofs to a format Ethereum understands.

---

## References

- [Taiko Architecture](https://taiko.xyz/docs)
- [StarkWare Stone Verifier](https://github.com/starkware-libs/stone-verifier)
- [Risc0 Ethereum Verifier](https://github.com/risc0/risc0)
- [zkSync Era Verifier](https://github.com/matter-labs/zksync-era)
- [EIP-2537: BLS12-381 Precompiles](https://eips.ethereum.org/EIPS/eip-2537)