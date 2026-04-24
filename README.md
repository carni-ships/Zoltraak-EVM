# Zoltraak

```
                                  ..      s                                               ..
  :~"""88hx.                x .d88"      :8                                         < .z@8"`
.~      ?888x          u.    5888R      .88       .u    .                            !@88E
X       '8888k   ...ue888b   '888R     :888ooo  .d88B :@8c        u           u      '888E   u
  H8h    8888X   888R Y888r   '888R   -*8888888 ="8888f8888r    us888u.     us888u.    888E u@8NL
 ?888~   8888    888R I888>   888R     8888      4888>'88"  .@88 "8888" .@88 "8888"   888E`"88*"
  %X   .X8*"     888R I888>   888R     8888      4888> '    9888  9888  9888  9888    888E .dN.
  .-/"""tnx.     888R I888>   888R     8888      4888>      9888  9888  9888  9888    888E~8888
 :~      8888.  u8888cJ888    888R    .8888Lu=  .d888L .+   9888  9888  9888  9888    888E '888&
 ~       X8888   "*888*P"    .888B .  ^%888*    ^"8888*"    9888  9888  9888  9888    888E  9888.
...      '8888L    'Y"       ^*888%     'Y"        "Y"      "888*""888" "888*""888" '"888*" 4888"
888k     '8888f                "%                            ^Y"   ^Y'   ^Y"   ^Y'     ""    ""
8888>    <8888
`888>    X888~
 '"88...x8""
```

**GPU-accelerated ZK proving for Ethereum blocks.** Generate STARK proofs for Ethereum transactions in ~7-9 seconds using Apple Silicon GPUs — fast enough to keep up with Ethereum's 12-second block time.

## Key Highlights

- **Real-time proving**: ~7-9s/block on Apple Silicon M3 Max, verified in ~5ms
- **Circle STARK**: Efficient proof system over the Mersenne-31 field with Poseidon2 hashing
- **Unified block proofs**: Single proof for all transactions in a block (not one-per-tx)
- **Live Ethereum mode**: `./ZoltraakProver real-block-unified <block> standard` fetches and proves real mainnet blocks
- **On-chain verification**: Solidity verifiers for BN254 pairing checks (~300k gas)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/carni-ships/Zoltraak-EVM.git
cd Zoltraak-EVM

# Initialize submodules (needed for foundry/zkMetal dependencies)
git submodule update --init --recursive

# Build (or use the build.sh script: ./build.sh)
swift build

# Run the binary
./.build/debug/ZoltraakProver real-block-unified <block_number> standard
```

## Architecture

```
Ethereum Block → GPU EVM Interpreter → Circle STARK Proof → Verification
     ↓                 ↓                    ↓               ↓
   RPC Fetch      GPU Execution        M31 STARK      On-chain verifier
                  (~80ms)            (~7-9s/block)      (~300k gas)
```

## Live Proving

Fetch blocks from Ethereum mainnet and generate STARK proofs in real-time:

```bash
# Prove blocks against mainnet
./ZoltraakProver real-block-unified <block_number> standard
./ZoltraakProver real-block-unified <block_number> balanced
./ZoltraakProver real-block-unified <block_number> ultra

# Performance tracking
# - Standard: ~7-9s per block (full security)
# - Balanced: ~4-6s per block (reduced security)
# - Ultra: ~1-2s per block (minimal security)
```

See [DOCUMENTATION/LiveEthereumProving.md](DOCUMENTATION/LiveEthereumProving.md) for full documentation.

## Key Components

| Component | Description |
|-----------|-------------|
| `ZoltraakBlockProver` | Unified block proving (all txs in single proof) |
| `EVMBatchProver` | Batch proving with GPU acceleration |
| `EVMGPUCircleSTARKProverEngine` | GPU Circle STARK proving |
| `EVMVerifier` | Proof verification |
| `EVMGPUMerkleProver` | GPU Merkle tree construction |
| `EVMExecutionEngine` | GPU-accelerated EVM bytecode execution |
| `EVMAIR` | AIR constraints (180 trace columns) |

## Trace Format

The EVM trace uses **180 columns** to capture execution state:

| Columns | Content |
|---------|---------|
| 0-2 | PC, Gas (high/low split) |
| 3-147 | Stack (16 slots × ~9 limbs) |
| 155-158 | Memory address, opcode, flags |
| 159-162 | Opcode type flags |
| 163 | Call depth |
| 164-166 | State root |
| 167+ | Padding/special purpose |

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| GPU Batch Merkle | 201x speedup vs CPU |
| GPU Leaf Hash | 83x speedup |
| GPU FRI | 22.8ms per fold |
| Real blocks (standard) | ~7-9s/block |
| Real blocks (balanced) | ~4-6s/block |
| Real blocks (ultra) | ~1-2s/block |

### Phase Breakdown (111 tx block, standard mode)

| Phase | Time | % of Total |
|-------|------|------------|
| GPU Merkle Commit | 1,600ms | 19% |
| GPU Tree Buffer Rebuild | 4,300ms | 52% |
| GPU Constraint Eval | 1,400ms | 17% |
| FRI | 94ms | 1% |
| Query Responses | 5ms | <1% |

## Proving Pipeline

1. **Execution**: GPU-accelerated EVM execution via Metal
2. **Trace**: Generate execution trace (trace length = 2^logTraceLength)
3. **LDE**: Low-degree extension over circle coset domain
4. **Commit**: Poseidon2-M31 Merkle tree commitments
5. **Constraints**: Evaluate AIR constraints
6. **FRI**: Circle FRI low-degree testing
7. **Verify**: STARK proof verification

## Technical Details

- **Field**: M31 (Mersenne-31) - 2^31 - 1
- **Hash**: Poseidon2-M31 for Merkle commitments
- **Proof**: Circle STARK over M31
- **Security**: ~100-bit soundness (configurable)
- **GPU**: Apple Silicon Metal for acceleration

## Security Analysis

Zoltraak targets **~134 bits of security**, slightly exceeding the industry standard of 128 bits.

| System | Security Level | Notes |
|--------|---------------|-------|
| **Zoltraak** | **~134 bits** | Targets 128 + margin for production safety |
| Ethereum (BN254) | ~128 bits | Standard for EVM ZK circuits |
| Groth16 zkSNARK | ~128 bits | Most deployed SNARK system |
| STARKs (typical) | ~100-128 bits | Varies by configuration |
| SHA-256 | 256 bits | Hash function standard |

**What 134 bits means in practice:**
- ~2^134 operations to break via brute force
- At 10^18 ops/sec (supercomputer): ~500 quadrillion years
- Exceeds the ~128-bit standard used by most production ZK systems
- Margin above standard allows for configuration flexibility

**Note:** Actual security depends on FRI configuration. Full 180-column proving provides maximum security. Column subset proving (32 columns) trades some security for speed.

## Documentation

- [LiveEthereumProving.md](DOCUMENTATION/LiveEthereumProving.md) - Real-time proving guide
- [ProofCompression.md](DOCUMENTATION/ProofCompression.md) - FRI column optimization
- [RECURSIVE-AGGREGATION-DESIGN.md](docs/RECURSIVE-AGGREGATION-DESIGN.md) - Nova IVC for aggregation

## Solidity Verifiers

On-chain verifiers in `contracts/`:

| Contract | Description | Estimated Gas |
|----------|-------------|---------------|
| `TransparentEVMSTARKVerifier.sol` | Transparent Nova IVC verifier | ~50-70k |
| `OptimizedTransparentEVMSTARKVerifier.sol` | Gas-optimized version | ~50k (optimistic mode) |
| `EVMSTARKVerifier.sol` | BN254 pairing verifier | ~350k |

The **transparent verifiers** use Nova IVC (no trusted setup), making them ideal for production. Gas estimates from Foundry tests:
- Optimistic mode: ~50k gas
- Full verification: ~70k gas
- CycleFold extension: +15k gas

## Dependencies

- [zkMetal](https://github.com/carbearnara/zkMetal) - Circle STARK and Nova infrastructure

## License

See [LICENSE](LICENSE) for details.
