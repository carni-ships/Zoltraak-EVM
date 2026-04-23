# EVMetal

GPU-accelerated ZK proving for Ethereum blocks using Circle STARK proofs over the M31 field.

## Quick Start

```bash
# Build
swift build

# Run tests
swift test

# Live Ethereum proving
./EVMetalRunner eth-live 1        # Prove 1 block
./EVMetalRunner eth-live-cont    # Continuous proving

# Benchmarks
./EVMetalRunner benchmarks
./EVMetalRunner full-compare
```

## Architecture

```
Ethereum Block → GPU EVM Interpreter → Circle STARK Proof → Verification
     ↓                 ↓                    ↓               ↓
   RPC Fetch      GPU Execution        M31 STARK      On-chain verifier
                  (~100ms)           (~10s/block)       (~300k gas)
```

## Live Proving

Fetch blocks from Ethereum mainnet and generate STARK proofs in real-time:

```bash
# Prove blocks against mainnet
./EVMetalRunner eth-live 3        # Prove 3 blocks
./EVMetalRunner eth-live-cont     # Continuous (until Ctrl+C)

# Performance tracking
# - Proving time: ~10-12s per block
# - Verification: ~5ms per block
# - Realtime rate: % of blocks proven within 12s window
```

See [DOCUMENTATION/LiveEthereumProving.md](DOCUMENTATION/LiveEthereumProving.md) for full documentation.

## Key Components

| Component | Description |
|-----------|-------------|
| `EVMetalBlockProver` | Unified block proving (all txs in single proof) |
| `EVMBatchProver` | Batch proving with GPU acceleration |
| `EVMGPUCircleSTARKProverEngine` | GPU Circle STARK proving |
| `EVMVerifier` | Proof verification |
| `EVMGPUMerkleProver` | GPU Merkle tree construction |

## Proving Pipeline

1. **Execution**: GPU-accelerated EVM execution via Metal
2. **Trace**: Generate execution trace (trace length = 2^logTraceLength)
3. **LDE**: Low-degree extension over circle coset domain
4. **Commit**: Poseidon2-M31 Merkle tree commitments
5. **Constraints**: Evaluate AIR constraints
6. **FRI**: Circle FRI low-degree testing
7. **Verify**: STARK proof verification

## Technical Details

- **Field**: M31 (BabyBear) - ~31-bit prime
- **Hash**: Poseidon2-M31 for Merkle commitments
- **Proof**: Circle STARK over M31
- **Security**: ~100-bit soundness (configurable)
- **GPU**: Apple Silicon Metal for acceleration

## Documentation

- [LiveEthereumProving.md](DOCUMENTATION/LiveEthereumProving.md) - Real-time proving guide
- [ProofCompression.md](DOCUMENTATION/ProofCompression.md) - FRI column optimization
- [RECURSIVE-AGGREGATION-DESIGN.md](docs/RECURSIVE-AGGREGATION-DESIGN.md) - Nova IVC for aggregation

## Solidity Verifiers

On-chain BN254 verifiers in `contracts/`:

| Contract | Description |
|----------|-------------|
| `TransparentEVMSTARKVerifier.sol` | Standard transparent verifier |
| `OptimizedTransparentEVMSTARKVerifier.sol` | Gas-optimized version |

## Dependencies

- [zkMetal](https://github.com/carbearnara/zkMetal) - Circle STARK and Nova infrastructure
- [NeonFieldOps](https://github.com/carbearnara/NeonFieldOps) - M31 field operations

## License

See [LICENSE](LICENSE) for details.
