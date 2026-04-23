# Zoltraak Documentation

Technical documentation for the Zoltraak ZK proving system.

## Documentation Index

### Architecture & Design

| Document | Description |
|----------|-------------|
| [LiveEthereumProving](LiveEthereumProving.md) | Real-time block proving against Ethereum mainnet |
| [ProofCompression](ProofCompression.md) | FRI column subset optimization for smaller proofs |
| [M31-ONCHAIN-VERIFIER-DESIGN](docs/M31-ONCHAIN-VERIFIER-DESIGN.md) | On-chain verification of M31 STARK proofs |
| [RECURSIVE-AGGREGATION-DESIGN](docs/RECURSIVE-AGGREGATION-DESIGN.md) | Nova IVC for recursive proof aggregation |

### Research & Analysis

| Document | Description |
|----------|-------------|
| [CONSENSUS-PROOF-RESEARCH](docs/CONSENSUS-PROOF-RESEARCH.md) | Consensus proof mechanisms |
| [EVM-COVERAGE-GAPS](docs/EVM-COVERAGE-GAPS.md) | EVM opcode coverage analysis |

## Quick Reference

### Running Tests

```bash
# All tests
swift test

# Specific test
./ZoltraakRunner test <name>

# Benchmarks
./ZoltraakRunner benchmarks
```

### Live Proving

```bash
# Single block
./ZoltraakRunner eth-live 1

# Continuous (until Ctrl+C)
./ZoltraakRunner eth-live-cont

# Quiet mode
./ZoltraakRunner eth-live 3 -q
```

### Comparison Benchmarks

```bash
# Full block comparison
./ZoltraakRunner full-compare

# Phase 2/3 integration
./ZoltraakRunner phase-bench
```
