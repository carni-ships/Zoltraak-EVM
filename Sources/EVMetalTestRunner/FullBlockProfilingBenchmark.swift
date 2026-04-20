import Foundation
import zkMetal
import EVMetal

/// Benchmark to profile full Ethereum block proving
/// Measures time per transaction and extrapolates to full block
public struct FullBlockProfilingBenchmark {

    // MARK: - Configuration

    public struct Config {
        public let numTransactions: Int
        public let transactionsPerBlock: Int
        public let logBlowup: Int
        public let numQueries: Int

        public static let standard = Config(
            numTransactions: 10,
            transactionsPerBlock: 150,  // Average ETH block
            logBlowup: 4,
            numQueries: 30
        )

        public static let small = Config(
            numTransactions: 5,
            transactionsPerBlock: 150,
            logBlowup: 2,
            numQueries: 20
        )
    }

    // MARK: - Benchmark Results

    public struct BenchmarkResult {
        public let numTransactions: Int
        public let perTransactionMs: Double
        public let totalBatchMs: Double
        public let estimatedFullBlockMs: Double
        public let throughputTxPerSec: Double
        public let phaseBreakdown: [String: Double]
    }

    // MARK: - Run Benchmark

    public static func run(config: Config = .standard) {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║         Full Ethereum Block Profiling Benchmark                  ║
        ║         Transactions per block: \(config.transactionsPerBlock)                             ║
        ╚══════════════════════════════════════════════════════════════════╝

        """)

        // Generate test transactions with varying complexity
        let transactions = generateTestTransactions(count: config.numTransactions)

        print("Generated \(config.numTransactions) test transactions")
        print("Simulating \(config.transactionsPerBlock) transactions per block\n")

        // Run batch benchmark
        let result = runBatchBenchmark(
            transactions: transactions,
            config: config
        )

        // Print results
        printResult(result, estimatedBlockSize: config.transactionsPerBlock)
    }

    // MARK: - Generate Test Transactions

    private static func generateTestTransactions(count: Int) -> [EVMTransaction] {
        var transactions: [EVMTransaction] = []

        // Mix of different transaction types
        let patterns: [[UInt8]] = [
            [0x60, 0x01, 0x00],  // PUSH1 1, STOP - simple
            [0x60, 0x01, 0x60, 0x02, 0x01, 0x00],  // ADD - arithmetic
            [0x60, 0x05, 0x60, 0x01, 0x14, 0x00],  // PUSH1 5, PUSH1 1, EQ - comparison
            [0x60, 0x01, 0x60, 0x00, 0x52, 0x00],  // PUSH1 1, PUSH1 0, MSTORE, STOP - memory
            [0x60, 0x01, 0x54, 0x00],  // PUSH1 1, SLOAD, STOP - storage
        ]

        for i in 0..<count {
            let pattern = patterns[i % patterns.count]
            transactions.append(EVMTransaction(
                code: pattern,
                calldata: [],
                value: M31Word(low64: UInt64(i)),
                gasLimit: 100000
            ))
        }

        return transactions
    }

    // MARK: - Run Batch Benchmark

    private static func runBatchBenchmark(
        transactions: [EVMTransaction],
        config: Config
    ) -> BenchmarkResult {
        let t0 = CFAbsoluteTimeGetCurrent()

        // Create GPU prover
        let proverConfig = EVMGPUBatchProver.Config(
            logBlowup: config.logBlowup,
            numQueries: config.numQueries
        )

        let prover = try! EVMGPUBatchProver(config: proverConfig)

        var individualResults: [EVMGPUBatchProver.ProverResult] = []
        var phaseTotals: [String: Double] = [
            "traceGen": 0,
            "lde": 0,
            "commit": 0,
            "constraint": 0,
            "fri": 0
        ]

        print("Proving \(transactions.count) transactions...\n")

        for (i, tx) in transactions.enumerated() {
            let result: EVMGPUBatchProver.ProverResult
            do {
                result = try prover.prove(transaction: tx)
            } catch {
                print("  Transaction \(i+1) failed: \(error)")
                continue
            }
            individualResults.append(result)

            phaseTotals["traceGen"]! += result.traceGenMs
            phaseTotals["lde"]! += result.ldeMs
            phaseTotals["commit"]! += result.commitMs
            phaseTotals["constraint"]! += result.constraintMs
            phaseTotals["fri"]! += result.friMs

            let elapsed = (CFAbsoluteTimeGetCurrent() - t0) * 1000
            print("  Transaction \(i+1)/\(transactions.count): \(String(format: "%.1fms", elapsed - phaseTotals.values.reduce(0, +) + phaseTotals.values.reduce(0, +)))")
        }

        let totalMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        let perTxMs = totalMs / Double(transactions.count)
        let estimatedBlockMs = perTxMs * Double(config.transactionsPerBlock)
        let throughput = 1000.0 / perTxMs

        return BenchmarkResult(
            numTransactions: transactions.count,
            perTransactionMs: perTxMs,
            totalBatchMs: totalMs,
            estimatedFullBlockMs: estimatedBlockMs,
            throughputTxPerSec: throughput,
            phaseBreakdown: phaseTotals
        )
    }

    // MARK: - Print Results

    private static func printResult(_ result: BenchmarkResult, estimatedBlockSize: Int) {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║                        BENCHMARK RESULTS                          ║
        ╚══════════════════════════════════════════════════════════════════╝

        Per-Transaction Performance:
        ─────────────────────────────────────────────────────────────────────
        Average time per transaction: \(String(format: "%.2fms", result.perTransactionMs))
        Throughput: \(String(format: "%.2f", result.throughputTxPerSec)) transactions/sec

        Phase Breakdown (per transaction):
        ─────────────────────────────────────────────────────────────────────
        """)

        let phases = [
            ("Trace Gen", result.phaseBreakdown["traceGen"]! / Double(result.numTransactions)),
            ("LDE (NTT)", result.phaseBreakdown["lde"]! / Double(result.numTransactions)),
            ("Commit (Merkle)", result.phaseBreakdown["commit"]! / Double(result.numTransactions)),
            ("Constraint", result.phaseBreakdown["constraint"]! / Double(result.numTransactions)),
            ("FRI", result.phaseBreakdown["fri"]! / Double(result.numTransactions))
        ]

        for (name, time) in phases {
            let pct = (time / result.perTransactionMs) * 100
            print("  \(name.padEnd(20)): \(String(format: "%7.2fms", time)) (\(String(format: "%5.1f", pct))%)")
        }

        print("""
        ─────────────────────────────────────────────────────────────────────

        Estimated Full Block Proving Time:
        ─────────────────────────────────────────────────────────────────────
        Block size: \(estimatedBlockSize) transactions
        Time per transaction: \(String(format: "%.2fms", result.perTransactionMs))
        ─────────────────────────────────────────────────────────────────────
        ESTIMATED TOTAL: \(formatDuration(result.estimatedFullBlockMs))
        ─────────────────────────────────────────────────────────────────────

        """)
    }

    private static func formatDuration(_ ms: Double) -> String {
        if ms < 1000 {
            return String(format: "%.0fms", ms)
        } else if ms < 60000 {
            return String(format: "%.2fs", ms / 1000)
        } else if ms < 3600000 {
            let mins = Int(ms / 60000)
            let secs = (ms.truncatingRemainder(dividingBy: 60000)) / 1000
            return "\(mins)m \(String(format: "%.1f", secs))s"
        } else {
            let hours = Int(ms / 3600000)
            let mins = Int((ms.truncatingRemainder(dividingBy: 3600000)) / 60000)
            return "\(hours)h \(mins)m"
        }
    }
}

// Extension for string padding
extension String {
    func padEnd(_ length: Int) -> String {
        let spaces = length - self.count
        if spaces > 0 {
            return self + String(repeating: " ", count: spaces)
        }
        return self
    }
}