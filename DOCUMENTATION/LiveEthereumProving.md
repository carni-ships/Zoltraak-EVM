# Live Ethereum Proving Mode

Real-time STARK proof generation and verification against Ethereum mainnet.

## Overview

`ZoltraakRunner eth-live` fetches blocks from Ethereum RPC endpoints, generates Circle STARK proofs for each block using GPU acceleration, and verifies the proofs on-the-fly.

## Quick Start

```bash
# Prove a single block with standard compression (32 columns)
./ZoltraakProver real-block-unified <block_number> standard

# Prove with balanced compression (24 columns, ~4-6s)
./ZoltraakProver real-block-unified <block_number> balanced

# Prove with ultra-fast compression (16 columns, ~1-2s)
./ZoltraakProver real-block-unified <block_number> ultra

# Prove with full columns (180 columns, ~18s, max security)
./ZoltraakProver real-block-unified <block_number> full
```

## Architecture

```
Ethereum RPC
    ↓
RealEthereumBlockFetcher.fetchBlock() → BlockData (hash, txs, timestamp)
    ↓
EVMetalBlockProver.prove() → GPU Circle STARK Proof
    ↓
EVMVerifier.verify() → STARK Verification Result
    ↓
Statistics (proving time, verification time, throughput)
```

## Commands

### `real-block-unified <block> [compression]`

Fetch and prove a single block with unified block proving.

**Options:**
- `block`: Block number to prove (e.g., `18351000`)
- `compression`: One of `standard` (32 cols), `balanced` (24 cols), `ultra` (16 cols), `full` (180 cols)

**Output Example:**
```
[BatchProver] Unified block proof completed: Transactions: 256, Total time: 1322.1ms, Per-tx: 5.16ms, Speedup: 338.9x
Block #24952737: STARK 1/1 | prove 1322.1ms | 0.0% realtime | 193.6 tx/s
```

## Quiet Mode

Use `-q` or `--quiet` flag to reduce output:

```bash
./ZoltraakProver eth-live-cont -q 10  # Prove 10 blocks quietly
./ZoltraakProver real-block-unified -q 18351000 standard  # Prove single block quietly
```

Quiet mode output shows only essential per-block status:
```
#24952737: 1/1 STARK | 1322.1ms | 0.0% realtime | 193.6 tx/s
```

### `eth-live-cont [block_limit]`

Continuous live proving mode - fetches and proves blocks sequentially as they appear on mainnet.

```bash
./ZoltraakProver eth-live-cont            # Unlimited continuous proving
./ZoltraakProver eth-live-cont 100        # Prove 100 blocks then exit
./ZoltraakProver eth-live-cont -q 50      # Quiet mode, prove 50 blocks
```

Uses `ultraFast` compression (16 columns) for realtime performance.

### State Witness Mode

For accurate transaction execution with real state (balances, storage):

```bash
# Requires archive node (Erigon at localhost:8080 or Reth at localhost:8545)
# Use benchmarkRealBlockUnifiedWithState() from code
```

This fetches:
- Contract bytecode via `eth_getCode`
- Transaction calldata from `tx.input`
- Initial state (balances, storage) from archive node

## Realtime Tracking

The prover tracks whether proofs complete before the next Ethereum block (~12s intervals):

- **ON TIME**: Proof completed in < 12s
- **LATE**: Proof took > 12s
- **Realtime rate**: Percentage of blocks proven on-time

## RPC Endpoints

The prover tries these endpoints in order:
1. `https://ethereum-rpc.publicnode.com`
2. `https://1rpc.io/eth`
3. `https://rpc.ankr.com/eth`

If one endpoint fails, the prover automatically tries the next.

## Proof Verification

### Transaction-Level Proofs

For non-unified proving, each transaction has its own `CircleSTARKProof`. Verification uses `EVMVerifier.verify()` which:

1. Creates `EVMAIR` with correct `logTraceLength` (derived from `proof.traceLength`)
2. Calls `CircleSTARKVerifier` for full proof verification
3. Returns `EVMVerificationResult.valid` or `EVMVerificationResult.invalid`

### Unified Block Proofs

For unified batch proving, a single `GPUCircleSTARKProverProof` covers all transactions. Verification:

1. Deserializes the proof from `aggregatedProof: Data`
2. Verifies proof structure (metadata, Merkle paths)
3. Note: Full FRI verification requires prover's internal transcript state

## Key Files

| File | Purpose |
|------|---------|
| `LiveEthereumProving.swift` | Live proving implementation |
| `EVMVerifier.swift` | Proof verification (Circle STARK + GPU) |
| `EVMBatchProver.swift` | Batch proving with unified block support |
| `CircleSTARKProofHelpers.swift` | Proof deserialization utilities |

## Limitations

1. **Full state access**: Real EVM verification requires archive node data (state diffs)
2. **Synthetic transactions**: Calldata is simplified for proving (no full EVM execution traces)
3. **Witness generation**: Full witness requires `eth_getTransactionReceipt` calls from archive nodes

## Performance

Typical performance on Apple Silicon M3 Max (111 tx block):

| Mode | Time | Security |
|------|------|----------|
| Ultra (16 cols) | ~2s | ~130 bits |
| Balanced (24 cols) | ~4-6s | ~132 bits |
| Standard (32 cols) | ~6-7s | ~134 bits |
| Full (180 cols) | ~18s | ~137 bits |

- **Verifying**: ~5ms per block
- **Throughput**: 15-20 tx/s (standard mode)

## Limitations

1. **Archive node required**: Full state witness (balances, storage) requires archive node RPC
   - Standard public RPCs don't support historical state queries
   - Use Erigon (`localhost:8080`) or Reth (`localhost:8545`)
2. **IVC aggregation**: Not yet available via CLI (under development)

## Future Improvements

- [ ] ethrex integration for local block syncing
- [ ] IVC recursive aggregation for multiple blocks
- [ ] Full FRI verification for unified proofs
