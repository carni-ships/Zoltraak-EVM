# Live Ethereum Proving Mode

Real-time STARK proof generation and verification against Ethereum mainnet.

## Overview

`ZoltraakRunner eth-live` fetches blocks from Ethereum RPC endpoints, generates Circle STARK proofs for each block using GPU acceleration, and verifies the proofs on-the-fly.

## Quick Start

```bash
# Prove a single block
./ZoltraakRunner eth-live 1

# Prove 3 blocks
./ZoltraakRunner eth-live 3

# Prove continuously (until Ctrl+C)
./ZoltraakRunner eth-live-cont

# Prove up to N blocks continuously
./ZoltraakRunner eth-live-cont 10

# Quiet mode (summary only)
./ZoltraakRunner eth-live 1 -q
./ZoltraakRunner eth-live-cont 5 -q
```

## Architecture

```
Ethereum RPC
    ↓
fetchBlockData() → LiveBlockData (hash, txs, timestamp)
    ↓
EVMBatchProver.proveBatch() → GPU Circle STARK Proof
    ↓
EVMVerifier.verify() → STARK Verification Result
    ↓
Statistics (proving time, realtime rate, throughput)
```

## Commands

### `eth-live [blocks] [-q|--quiet]`

Fetch and prove N blocks (default: 1). Each block is processed sequentially.

**Options:**
- `blocks`: Number of blocks to prove (default: 1)
- `-q`, `--quiet`: Summary-only output

**Output Example:**
```
Block #24940906: STARK 1/1 | prove 11897.6ms | verify 5.24ms | 100.0% realtime | 36.2 tx/s

SUMMARY
Blocks: 1 | Success: 1 | Failed: 0
Realtime: 100.0% on-time (1/1)
Transactions: 431
Proving: 11897.6ms total
Verifying: 5.24ms
Throughput: 36.2 tx/s
```

### `eth-live-cont [limit] [-q|--quiet]`

Continuous proving mode. Fetches the latest block, proves it, then waits for the next block. Repeats until interrupted or `limit` blocks are reached.

**Options:**
- `limit`: Maximum blocks to prove (0 = unlimited)
- `-q`, `--quiet`: Summary-only output

**Output Example:**
```
Continuous Live Ethereum Proving Mode
Starting from block #24940907

Block #24940907: STARK 1/1 | prove 10234.1ms | verify 4.87ms | 100.0% realtime | 38.1 tx/s
Block #24940908: STARK 1/1 | prove 9876.3ms | verify 4.92ms | 100.0% realtime | 40.2 tx/s
...
```

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

Typical performance on Apple Silicon M3 Max:
- **Proving**: ~10-12s per block (depends on transaction count)
- **Verifying**: ~5ms per block
- **Throughput**: 30-40 tx/s

## Future Improvements

- [ ] Archive node support for full state witness
- [ ] ethrex integration for local block syncing
- [ ] Full FRI verification for unified proofs
- [ ] Recursive aggregation (Nova IVC) for multiple blocks
