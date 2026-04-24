# Zoltraak Documentation

Technical documentation for the Zoltraak ZK proving system.

## Documentation Index

### Architecture & Design

| Document | Description |
|----------|-------------|
| [LiveEthereumProving](LiveEthereumProving.md) | Real-time block proving against Ethereum mainnet |
| [ProofCompression](ProofCompression.md) | FRI column subset optimization for smaller proofs |

### Research & Analysis

| Document | Description |
|----------|-------------|
| [M31-ONCHAIN-VERIFIER-DESIGN](../docs/M31-ONCHAIN-VERIFIER-DESIGN.md) | On-chain verification of M31 STARK proofs |
| [RECURSIVE-AGGREGATION-DESIGN](../docs/RECURSIVE-AGGREGATION-DESIGN.md) | Nova IVC for recursive proof aggregation |

## Quick Reference

### Running Tests

```bash
# All tests
swift test

# Specific test
swift test --filter <test_name>
```

### Live Proving

```bash
# Prove a block (standard mode - 32 columns, ~6-7s)
./ZoltraakProver real-block-unified <block_number> standard

# Balanced mode (24 columns, ~4-6s)
./ZoltraakProver real-block-unified <block_number> balanced

# Ultra mode (16 columns, ~1-2s)
./ZoltraakProver real-block-unified <block_number> ultra

# Full mode (180 columns, ~18s, max security)
./ZoltraakProver real-block-unified <block_number> full
```

### Comparison Benchmarks

```bash
# Unified block proving benchmark
./ZoltraakProver unified

# Full comparison of all approaches
./ZoltraakProver full-compare
```
