# Consensus Proof Research: Is Proving Ethereum Consensus Rules Necessary?

> Research completed: 2026-04-22
> Agent: Explore (a888a1740ffd95482)

---

## Executive Summary

**For single-sequencer rollups (like EVMetal's current architecture): NO, consensus rule proving is NOT necessary.**
**For multi-sequencer/decentralized provers: YES, but with caveats.**

The distinction between Type 1 and Type 2 zkEVMs is fundamentally about **trust models**, not technical capability. Type 1 (Taiko) targets Ethereum equivalence for trustless bridging. Type 2/3/4 (Polygon zkEVM, Scroll, zkSync) target application-level EVM equivalence where the sequencer is already trusted.

---

## 1. How Other zkEVMs Handle Consensus Verification

### Taiko (Type 1 - Full Ethereum Equivalence)

- **Architecture**: Fully decentralized prover network. Provers compete to prove blocks.
- **Consensus**: Proves beacon chain proposer signatures (BLS12-381), Casper FFG finality, and execution payload validity.
- **Bridge**: Uses recursive STARK-to-BN254 conversion for L1 verification.
- **Key insight**: Taiko's consensus proof is what enables trustless L1 bridging — anyone can verify the proof on Ethereum without trusting a sequencer.

### Polygon zkEVM (Type 2 - EVM Bytecode Equivalence)

- **Architecture**: Trusted sequencer aggregates transactions. Proof submitted by aggregator.
- **Consensus**: Does NOT prove PoS consensus. Relies on trusted bridge for L1 state sync.
- **Bridge design**: Uses its own consensus mechanism separate from Ethereum PoS. L2 transactions are sequenced by the Polygon PoS validator set, not Ethereum validators.

### Scroll (Type 2 - EVM Bytecode Equivalence)

- **Architecture**: Scroll coordinator coordinates proving. Provers generate proofs for pre-confirmed blocks.
- **Consensus**: Does NOT prove Ethereum consensus. Focuses on EVM execution correctness.
- **Finality**: Uses Ethereum finalized blocks as input but does not prove the consensus layer.

### zkSync (Type 4 - High-Level Language Equivalence)

- **Architecture**: zkSync Era uses a single sequencer (Matter Labs run).
- **Consensus**: No Ethereum consensus proof. Uses its own proof mechanism for L2 correctness.
- **Bridge**: Uses the zkSync bridge (separate from Ethereum canonical bridge).

---

## 2. The Three Layers of "Proof"

| Layer | Description | Who needs it |
|-------|-------------|--------------|
| **EVM Bytecode Execution** | Prove the EVM state transition is correct | All zkEVMs (Type 1-4) ✓ |
| **Consensus Rules** | Prove block proposer signature, beacon state, execution payload | Only Type 1 (Taiko) |
| **Bridge Withdrawal** | Prove L1 can trust L2 state | Trustless bridging requirements |

**EVMetal currently proves Layer 1** (EVM bytecode execution via EVMAIR + Circle STARK).

---

## 3. What "Consensus Rules" Actually Require

### 3.1 Block Proposer Signature Verification (BLS12-381)

- Ethereum PoS uses **BLS12-381** for validator signatures, NOT secp256k1
- The execution payload contains a `prev_randao` field from beacon chain
- **Requires**: BLS12-381 precompiles (0x0E, 0x0F, 0x11, 0x12) — currently missing in EVMetal

### 3.2 Finality Gadget (Casper FFG)

- Casper FFG provides economic finality after 2 epochs (~12 minutes)
- Proving finality requires beacon chain state access (Merkle proofs)
- **Requires**: Beacon chain light client or state oracle + Merkle proof verification

### 3.3 Beacon Chain State Access

- `BLOCKHASH` opcode requires historical block hashes from beacon chain
- `NUMBER` and `TIMESTAMP` must match beacon chain values
- **Requires**: Historical beacon state Merkle proofs or trusted oracle

### 3.4 Execution Payload Validation

- Verify the execution payload header against beacon chain
- Check parent block hash, state root, gas limit, etc.
- **Requires**: Full payload validation against beacon roots

---

## 4. Minimum Consensus Requirements by Use Case

### Single Sequencer Rollup (EVMetal's current model)

```
MINIMUM REQUIRED:
- EVM bytecode execution proof ✓ (EVMetal already does this)
- State root commitment (Merkle proof of L2 state)
- No consensus proof needed (sequencer is trusted)

BRIDGE REQUIREMENTS:
- L2 state oracle (trusted)
- Withdrawal proof (EVM execution only)
- No BLS signature verification needed
```

### Multi-Sequencer / Shared Sequencer

```
MINIMUM REQUIRED:
- EVM bytecode execution proof
- Transaction ordering proof (by whom?)
- At minimum: verify transaction came from valid sequencer

CONSORTIUM VARIANT:
- Verify multi-sig of sequencer set (ECDSA secp256k1)
- No beacon chain access needed
```

### Type 1 / Trustless Bridging

```
FULL REQUIREMENTS:
- EVM bytecode execution proof
- Beacon chain proposer signature (BLS12-381)
- Casper FFG finality gadget proof
- Execution payload validation
- Historical beacon state Merkle proofs

COMPLEXITY: ~10x more constraints than pure EVM execution
```

---

## 5. Can EVMetal Prove Consensus Rules Using Existing STARK Infrastructure?

**Short answer: PARTIALLY, with significant additions required.**

### What EVMetal Has

- Circle STARK prover over M31 field (can prove arbitrary computations)
- GPU-accelerated Poseidon2 hashing
- Merkle commitment scheme
- EVM bytecode execution traces (EVMAIR)

### What's Missing for Consensus Proof

| Component | Status in EVMetal | Required for Consensus |
|-----------|-------------------|------------------------|
| BLS12-381 G1/G2 map | Missing (Gap 5) | Required for validator sigs |
| BLS12-381 pairing | Implemented (GPU) | Required for aggregate verification |
| secp256k1 ECDSA | Not implemented | NOT needed (beacon uses BLS) |
| Beacon state Merkle proofs | Not implemented | Required for Type 1 |
| Execution payload validation | Not implemented | Required for Type 1 |
| Casper FFG constraint | Not implemented | Required for Type 1 |

### Honest Assessment

**For Single-Sequencer Model (Recommended for EVMetal):**
- EVMetal's current architecture is SUFFICIENT
- Add Merkle proof verification for L2 state access (Gap 2)
- No consensus proof needed
- Bridge verification uses different mechanism (trusted oracle)

**For Type 1 / Trustless Bridging:**
- Would require ~6-12 months of additional development
- BLS12-381 precompiles (Gap 5) are prerequisite
- Beacon chain state access (Gap 3) is prerequisite
- Casper FFG proof would be entirely new AIR constraints

---

## 6. Actionable Recommendations for EVMetal Roadmap

### Phase 1: Current Trajectory (Single Sequencer)

```
IMMEDIATE (P0):
1. Fix GPU/CPU commitment mismatch (test infrastructure issue)
2. Implement unimplemented opcodes (EXP, MULMOD, SHL/SHR/SAR)
3. Add Merkle proof verifier for L2 state (Gap 2)

SHORT-TERM (P1):
4. GPU tree building for EVMGPUMerkleEngine
5. GPU constraint evaluation in EVMGPUConstraintEngine
6. BLS12-381 precompiles (for ecRecover completeness)
```

### Phase 2: Type 2+ zkEVM (Application Rollup)

```
REQUIREMENTS:
- EVM bytecode execution proof ✓ (EVMetal does this)
- L2 state witness generation ✓ (Gap 3)
- Merkle proof verification for storage access ✓ (Gap 2)

NOT REQUIRED:
- Consensus proof
- Beacon chain integration
- BLS validator signatures
```

### Phase 3: Type 1 / Trustless Bridge (If Desired)

```
REQUIREMENTS:
- BLS12-381 map precompiles (0x11, 0x12)
- Beacon chain light client
- Execution payload validation AIR
- Casper FFG finality constraints

ESTIMATED EFFORT: 6-12 months
DECISION: Only needed if EVMetal wants trustless Ethereum bridging
```

---

## Conclusion

**EVMetal does NOT need to prove consensus rules for its current single-sequencer architecture.** This is the right call for a proving library focused on performance. Type 1 equivalence (Taiko) comes with significant complexity overhead that only matters for trustless L1 bridging.

**Recommended path forward:**
1. Complete EVM opcode coverage and GPU optimization (current work)
2. Add L2 state Merkle proof verification (enables arbitrary block proving)
3. Target Type 2 classification (Polygon/Scroll-equivalent)
4. Revisit Type 1 only if trustless Ethereum bridge becomes a requirement

The distinction is clear: **proving execution != proving consensus**. EVMetal correctly focuses on the former. Consensus proving is a separate product decision, not a technical necessity.

---

## References

- [Taiko Architecture](https://taiko.xyz/docs)
- [Vitalik's zkEVM Classification](https://vitalik.eth.limo/general/2022/08/04/zkevm.html)
- [Polygon zkEVM Bridge Design](https://docs.polygon.technology/zkEVM/)
- [Scroll Architecture](https://scroll.io/blog/architecture)
- [EIP-2537: BLS12-381 Precompiles](https://eips.ethereum.org/EIPS/eip-2537)