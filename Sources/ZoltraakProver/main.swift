import Foundation
import zkMetal
import Zoltraak

/// Command-line arguments for running tests:
///   ./ZoltraakProver              - Run continuous live Ethereum proving (default)
///   ./ZoltraakProver tests        - Run all tests
///   ./ZoltraakProver benchmarks   - Run benchmarks
///   ./ZoltraakProver quick        - Run quick tests (skip slow E2E)
///   ./ZoltraakProver gpu          - Run GPU batch tests only
///   ./ZoltraakProver e2e         - Run E2E tests only
///   ./ZoltraakProver opcode       - Run opcode tests only
///   ./ZoltraakProver eth-live [n] - Prove n blocks from live Ethereum
///   ./ZoltraakProver eth-live-cont [limit] - Continuous proving (default)
///     - -q/--quiet for summary-only output
///   ./ZoltraakProver real-block-unified [num] [compression] - compression: standard (32 cols), balanced (24 cols), fast (16 cols)
///   ./ZoltraakProver synthetic-block - Run synthetic block benchmark
///   ./ZoltraakProver test <name> - Run specific test by name

let args = ProcessInfo.processInfo.arguments
let mode = args.count > 1 ? args[1] : "eth-live-cont"
let testFilter = args.count > 2 ? args[2] : nil

// Print header for interactive modes (unless quiet flag is set)
let quietMode = args.contains("-q") || args.contains("--quiet")
switch mode {
case "eth-live", "eth-live-cont", "benchmarks", "quick", "gpu", "e2e", "opcode":
    if !quietMode {
        printZoltraakHeader()
    }
default:
    break
}

switch mode {
case "benchmarks":
    Benchmarks.runAll()

case "quick":
    print("=== Zoltraak Quick Tests (skipping slow E2E) ===\n")
    ProverTests.runQuickTests()

case "gpu":
    print("=== Zoltraak GPU Batch Tests ===\n")
    ProverTests.runGPUBatchTests()

case "e2e":
    print("=== Zoltraak E2E Tests ===\n")
    ProverTests.runE2ETests()

case "opcode":
    print("=== Zoltraak Opcode Tests ===\n")
    ProverTests.runOpcodeTests()

case "test":
    if let filter = testFilter {
        print("=== Running test matching: \(filter) ===\n")
        ProverTests.runTest(named: filter)
    } else {
        print("Usage: ./ZoltraakRunner test <test_name>")
    }

case "comparison":
    print("=== Full Comparison: All Proving Approaches ===\n")
    PhaseIntegrationBenchmark.benchmarkComparison()

case "unified":
    // Run unified block proving benchmark
    Task {
        print("=== Unified Block Proving Benchmark (Phase 3) ===\n")
        await Benchmarks.benchmarkUnifiedBlockProving()
    }

case "full-compare":
    // Run full block comparison (all approaches)
    Task {
        print("=== Full Block Proving Comparison ===\n")
        await Benchmarks.benchmarkProvingComparison()
    }

case "real-block":
    // Fetch and process a real Ethereum block
    let blockNumber = args.count > 2 ? args[2] : nil
    RealEthereumBlockFetcher.benchmarkRealBlock(blockNumber: blockNumber)

case "real-block-unified":
    // Fetch and process a real Ethereum block with unified proving
    let blockNumber = args.count > 2 ? args[2] : nil
    let compressionArg = args.count > 3 ? args[3] : "standard"

    let compressionConfig: BatchProverConfig
    switch compressionArg {
    case "balanced":
        print("Using balanced compression (24 columns, ~5s proving)")
        compressionConfig = .balancedFast
    case "fast", "ultra":
        print("Using ultra-fast compression (16 columns)")
        compressionConfig = .ultraFast
    case "none", "full":
        print("Using full columns (180 columns)")
        compressionConfig = .unifiedBlock  // Will be modified below
    default:
        print("Using standard compression (32 columns)")
        compressionConfig = .unifiedBlock
    }

    // Update compression config for "none" case
    let finalConfig: BatchProverConfig
    if compressionArg == "none" || compressionArg == "full" {
        finalConfig = BatchProverConfig(
            batchSize: 150,
            useGPU: true,
            logTraceLength: 8,
            numQueries: 4,
            logBlowup: 2,
            useUnifiedProof: true,
            provingColumnCount: 180,
            criticalColumnIndices: []
        )
    } else {
        finalConfig = compressionConfig
    }

    let group = DispatchGroup()
    group.enter()
    Task {
        await RealEthereumBlockFetcher.benchmarkRealBlockUnified(
            blockNumber: blockNumber,
            config: finalConfig
        )
        group.leave()
    }
    group.wait()

case "synthetic-block":
    // Run synthetic block benchmark (no RPC needed)
    RealEthereumBlockFetcher.benchmarkSyntheticBlock()

case "phase-bench", "multi-stream":
    // Async benchmarks - run in Task block
    Task {
        switch mode {
        case "phase-bench":
            print("=== Phase 2/3 Integration Benchmark ===\n")
            await PhaseIntegrationBenchmark.runAll()
        case "multi-stream":
            print("=== Phase 2: GPU Multi-Stream Benchmark ===\n")
            await PhaseIntegrationBenchmark.benchmarkMultiStream()
        default:
            break
        }
    }

case "compression":
    // Run proof compression benchmarks
    Task {
        print("=== Proof Compression Benchmark ===\n")
        do {
            let result = try await ProofCompressionBenchmarks.runCompressionBenchmark(
                transactionCount: 64,
                config: .highCompression
            )
            print("\nBenchmark complete!")
        } catch {
            print("Benchmark failed: \(error)")
        }
    }

case "compression-compare":
    // Compare baseline vs compressed
    Task {
        print("=== Proof Compression Comparison ===\n")
        do {
            try await ProofCompressionBenchmarks.runComparison(
                transactionCount: 32
            )
            print("\nComparison complete!")
        } catch {
            print("Comparison failed: \(error)")
        }
    }

case "compression-tests":
    // Run proof compression tests
    Task {
        print("=== Proof Compression Tests ===\n")
        do {
            try await ProofCompressionTests.runAll()
            print("\nTests complete!")
        } catch {
            print("Tests failed: \(error)")
        }
    }

case "eth-live":
    // Live Ethereum proving mode
    let blockCount = args.count > 2 ? Int(args[2]) ?? 1 : 1
    let quietMode = args.contains("-q") || args.contains("--quiet")
    runLiveProvingMode(blockCount: blockCount, quiet: quietMode)

case "eth-live-cont":
    // Continuous live proving - run forever (default: unified mode for speed)
    let blockLimit = args.count > 2 ? Int(args[2]) ?? 0 : 0  // 0 = unlimited
    let quietMode = args.contains("-q") || args.contains("--quiet")
    runContinuousLiveProving(blockLimit: blockLimit, quiet: quietMode, mode: .unified)

default:
    print("=== Zoltraak Prover Test Suite ===\n")
    ProverTests.runAllTests()
}