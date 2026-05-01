# Zoltraak Gap Analysis: EVM Proving Coverage

> Document created: 2026-04-22
> Status: In Progress

## Overview

Zoltraak is a GPU-accelerated ZK-EVM proving system using Circle STARK over the Mersenne31 field. This document catalogs the gaps between current implementation and production-grade zkEVM systems (Polygon zkEVM, Scroll, Taiko, zkSync).

---

## Gap 1: Verification Bridge to Ethereum

### Problem

Zoltraak generates proofs in the **Mersenne31 field** (prime: 2^31 - 1), but Ethereum Mainnet verifies proofs on **BN254** (alt_bn128 curve). STARK proofs over M31 cannot be directly verified in EVM bytecode using BN254 pairings.

### Current Implementation

**Architecture exists** in `Sources/Zoltraak/Aggregation/`:
- `EVMBN254Verifier.swift` - Transparent BN254 verifier (Pedersen + CCS)
- `EVMCircleSTARKIVC.swift` - Nova IVC for Circle STARK folding
- `EVMHyperNovaAggregator.swift` - HyperNova aggregation
- `EVMCycleFoldFinalizer.swift` - CycleFold optimization (BN254/Grumpkin)
- `EVMSTARKVerifier.sol` - On-chain BN254 verifier with pairing

**Flow:**
```
M31 Circle STARK (~30KB) → IVC folding → HyperNova → CycleFold → ~200 bytes
                                                              ↓
                                               EVMSTARKVerifier.sol (pairing)
```

### Status

| Component | Status | Notes |
|-----------|--------|-------|
| Circle STARK IVC | ⚠️ Partial | Stubbed field arithmetic |
| HyperNova Aggregator | ⚠️ Partial | CCS builder exists |
| CycleFold Finalizer | ⚠️ Partial | Recursive stubs |
| FieldArithmetic | ❌ Stubbed | frAdd/frMul recursive |
| EVMBN254Verifier | ⚠️ Partial | Pedersen commitments only |
| On-chain verifier | ✅ Implemented | Solidity + ecPairing |

### Known Issues

1. `FieldArithmetic.swift` functions are stubs (frAdd calls itself)
2. M31 to BN254 Fr conversion needs verification
3. Actual EC point arithmetic not fully implemented
4. IVC verify() depends on unimplemented HyperNovaProver.engine.decide()

---

## Gap 2: State Access / Merkle Proof Verification

### Problem

Production zkEVMs must handle:
- `SLOAD` / `SSTORE` with Merkle proofs from Ethereum state
- `EXTCODEHASH`, `EXTCODESIZE`, `EXTCODECOPY` requiring code/state proofs
- `BLOCKHASH` requiring historical block hash queries

**Status**: ✅ IMPLEMENTED (State Proof Mode)

Zoltraak now supports verified state access via `eth_getProof` RPC (EIP-1186).

### Implementation

**Files**:
- `Sources/Zoltraak/Prover/StateProofFetcher.swift` - Fetches proofs via `eth_getProof`
- `Sources/Zoltraak/Prover/StateProofVerifier.swift` - Verifies proofs against state root
- `Sources/Zoltraak/Prover/StateProofBenchmark.swift` - Benchmark utilities
- `Sources/Zoltraak/EVM/MerklePatriciaTrie.swift` - Full Patricia Trie implementation
- `Sources/Zoltraak/EVM/KeccakPatriciaEngine.swift` - Keccak-256 for trie node hashing

**Usage**:

```swift
// Fetch state proofs
let fetcher = StateProofFetcher()
let proof = try await fetcher.fetchProofs(
    address: "0x1234...",
    storageSlots: [slot1, slot2],
    blockNumber: "0x10d4f5e"
)

// Verify proofs
let verifier = StateProofVerifier()
let verified = try verifier.verifyFullProof(proof)

// Or via ArchiveNodeWitnessFetcher
let witnessFetcher = ArchiveNodeWitnessFetcher(config: .erigon)
let verifiedState = try await witnessFetcher.fetchStateProofs(
    address: address,
    storageSlots: slots,
    blockNumber: blockNum
)
```

**Configuration** (`BlockProvingConfig`):
- `useStateProofs: Bool` - Enable state proof mode
- `stateProofMode: StateProofMode` - `.preflight`, `.strict`, or `.withoutProofs`

### Performance

**Measured on publicnode.com (May 2026)**:

| Metric | Value |
|--------|-------|
| Fetch time (5 slots) | ~90-110ms |
| Total per account | ~90-150ms |
| Proof size/account | ~1-5 KB |
| Current block support | ✅ YES |
| Ancient block (block 1) | ❌ Pruned |

**Note**: Archive nodes (Erigon, Reth) required for historical proofs. Public nodes prune old state.

### Impact

- ✅ Can prove transactions dependent on external chain state
- ✅ BLOCKHASH lookups can be verified via proof
- ✅ Precompile results can be verified (not just assumed)
- ⚠️ Requires archive node for production use
- ⚠️ Network latency is the main bottleneck

---

## Gap 3: Witness Generation Infrastructure

### Problem

Full EVM state consists of:
- Account state (balance, nonce, code, storageRoot)
- Contract storage (key-value merkle trie)
- Code cache (all deployed bytecode)
- Call stack (nested execution context)

Zoltraak generates execution traces but doesn't build complete state witnesses.

### Impact

- Cannot prove arbitrary historical blocks without state provider
- Missing witnesses for storage-heavy applications
- No cold storage access patterns

### Solution

```swift
/// EvmStateProvider interface for fetching required state
public protocol EvmStateProvider: Sendable {
    /// Get account state at given block
    func getAccount(address: Address, block: UInt64) -> AccountState?

    /// Get storage value at key
    func getStorage(address: Address, key: UInt256, block: UInt64) -> UInt256?

    /// Get contract bytecode
    func getCode(address: Address) -> Bytes

    /// Get historical block hash
    func getBlockHash(number: UInt64) -> Bytes
}
```

**Implementation path**:
1. Create `EvmStateProvider` protocol
2. Implement `RPCStateProvider` for Ethereum JSON-RPC
3. Add witness caching for repeated block proving
4. Integrate into block prover initialization

---

## Gap 4: Type Classification Clarification

### zkEVM Type Categories (Vitalik's Taxonomy)

| Type | Definition | Example | EVM Equivalence |
|------|------------|---------|----------------|
| **Type 1** | Full Ethereum equivalent (EVM + all Consensus) | Taiko | 100% |
| **Type 2** | EVM equivalent, different state tree | Polygon, Scroll | 100% bytecode, different state |
| **Type 3** | Almost EVM equivalent (some opcodes differ) | — | ~95% |
| **Type 4** | High-level language equivalence (no bytecode) | zkSync | ~90%, requires Solidity |

### Zoltraak Classification

**Current**: Type 2 (EVM bytecode equivalence)
- Executes EVM bytecode directly ✓
- Supports all ~140 opcodes ✓
- Uses different state representation (M31 Merkle vs BN254)

**Target**: Type 1 (for full Ethereum equivalence)
- Requires consensus mechanism proof
- Block proposer/builder integration
- Historical state verification

**Gap to Type 1**:
1. Consensus rules (proposer signature verification)
2. Beacon chain state integration
3. Execution payload validation per Ethereum spec

---

## Gap 5: Precompile Completeness

### Current Status (GPU-accelerated)

| Precompile | Status | Engine |
|------------|--------|--------|
| ecRecover | ✅ GPU | GPUEVMPrecompileEngine |
| sha256 | ✅ CPU | CryptoKit fallback |
| ripemd160 | ✅ CPU | Foundation fallback |
| identity | ✅ Trivial | Pass-through |
| modExp | ✅ GPU | GPUEVMPrecompileEngine |
| ecAdd | ✅ GPU | GPUEVMPrecompileEngine |
| ecMul | ✅ GPU | GPUEVMPrecompileEngine |
| ecPairing | ✅ GPU | GPUEVMPrecompileEngine |
| blake2f | ✅ GPU | GPUEVMPrecompileEngine |
| bls2f | ✅ CPU | Foundation fallback |
| **BLS12-381** | ✅ Partial | G1/G2 ops wired, map stubs |
| blsMapG1 | ⚠️ Stub | Wired up, SWU isogeny TODO |
| blsMapG2 | ⚠️ Stub | Wired up, extended SWU TODO |
| blsPairing | ✅ CPU | Implemented |

### Missing Precompiles

1. **BLS12-381 map operations** (`0x11`, `0x12`)
   - Map Fp to G1 and Fp2 to G2
   - Required for BLS signature verification

2. **BLS multi-exponential** (`0x0E`, `0x0F`)
   - Batch G1/G2 exponentiation for signature aggregation

### Solution

```swift
extension GPUEVMPrecompileEngine {
    /// Map field element to G1 point (EIP-2537)
    public func blsMapG1(input: Bytes) -> Bytes?

    /// Map field element to G2 point (EIP-2537)
    public func blsMapG2(input: Bytes) -> Bytes?

    /// Multi-exponentiation for BLS signatures
    public func blsMultiExpG1(bases: [Bytes], scalars: [Bytes]) -> Bytes?
}
```

---

## Gap 6: AIR Constraint Completeness

### Current Constraints

EVMAIR currently implements **20 constraints** covering:
- Basic arithmetic (ADD, MUL, DIV)
- Comparison (LT, GT, EQ)
- Bitwise (AND, OR, XOR)
- Memory operations (MLOAD, MSTORE)
- Control flow (JUMP, JUMPI)

### Missing Constraints

| Category | Missing Constraints |
|----------|---------------------|
| **Arithmetic** | SDIV, SMOD, SIGNEXTEND, EXP, ADDMOD, MULMOD |
| **Bitwise** | NOT, BYTE, SHL, SHR, SAR |
| **Stack** | Stack height validation, underflow/overflow checks |
| **Calls** | Call depth, gas accounting, return data |
| **Storage** | Storage read/write consistency |
| **Precompile** | Precompile call validity |
| **Gas** | Gas depletion validation |

### Current Status

**Implemented constraints** (EVMAIR lines 544-604):
- Arithmetic: ADD, SUB, MUL, DIV, MOD, EXP, ADDMOD, MULMOD, SIGNEXTEND
- Comparison: LT, GT, SLT, SGT
- Bitwise: AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
- Memory: MLOAD, MSTORE, MSTORE8
- Control: JUMP, JUMPI
- Calls: CALL, DELEGATECALL, STATICCALL, CREATE, CREATE2
- Crypto: KECCAK256

### Known Issues

| Constraint | Issue | Severity |
|------------|-------|----------|
| EXP | Simplified - only checks exp < 256, not actual result | Medium |
| SDIV/SMOD | Uses unsigned division, may not handle signed semantics | Medium |
| Stack validation | Only checks height change, not actual values | High |

---

## Gap 7: EOF (Ethereum Object Format) Support

### Status

**Partial Implementation:**

| Opcode | Status | Notes |
|--------|--------|-------|
| RJUMP (0xE0) | ✅ Implemented | Basic relative jump |
| RJUMPI (0xE1) | ✅ Implemented | Conditional relative jump |
| RJUMPV (0xE2) | ⚠️ Partial | Basic table dispatch |
| CALLF (0xE3) | ⚠️ Stubbed | Simplified addressing, no frame save |
| RETF (0xE4) | ✅ Basic | Basic return |
| JUMPF (0xE5) | ⚠️ Stubbed | Simplified addressing |
| DUPN (0xE8) | ✅ Implemented | Uses immediate byte |
| SWAPN (0xE9) | ✅ Implemented | Uses immediate byte |
| SLOADBYTES (0xE6) | ❌ Missing | Throws invalidOpcode |
| SSTOREBYTES (0xE7) | ❌ Missing | Throws invalidOpcode |
| MSTORESIZE (0xEA) | ❌ Missing | Throws invalidOpcode |
| TRACKSTORAGE (0xEB) | ❌ Missing | Throws invalidOpcode |
| COPYLOG (0xEC) | ❌ Missing | Throws invalidOpcode |

### Missing

- EOF container validation (magic bytes 0xEF00)
- Jump table analysis / static analysis
- CALLF/RETF stack frame management
- Code section lookup (not simple funcIdx * 32)
- Dynamic gas costs (EIP-4200/EIP-5450)
- RJUMPV destination validation

---

## Priority Implementation Order

| Priority | Gap | Impact | Effort |
|----------|-----|--------|--------|
| **P0** | Verification Bridge | Enables L1 bridge | High |
| **P0** | AIR Constraints | Soundness guarantee | Medium |
| **P1** | State Access | Arbitrary block proving | High |
| **P1** | Missing Precompiles | BLS compatibility | Medium |
| **P2** | Witness Generation | Full state coverage | High |
| **P2** | EOF Support | Post-merge contracts | Medium |
| **P3** | Type 1 Classification | Full Ethereum equivalence | Very High |

---

## References

- [Vitalik's zkEVM Classification](https://vitalik.eth.limo/general/2022/08/04/zkevm.html)
- [EIP-2537: BLS12-381 Precompiles](https://eips.ethereum.org/EIPS/eip-2537)
- [EIP-3540: EOF Version 1](https://eips.ethereum.org/EIPS/eip-3540)
- [Taiko Architecture](https://taiko.xyz/docs)
- [Polygon zkEVM Documentation](https://docs.polygon.technology/zkEVM/)