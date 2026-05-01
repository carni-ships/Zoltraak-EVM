import Foundation
import zkMetal

/// Benchmark utilities for state proof fetching and verification.
public struct StateProofBenchmark {

    // MARK: - Benchmark Configuration

    /// Configuration for benchmark runs
    public struct BenchmarkConfig: Sendable {
        /// RPC endpoint to use
        public let rpcURL: String

        /// Number of iterations for timing
        public let iterations: Int

        /// Block number to benchmark against
        public let blockNumber: UInt64

        /// Number of storage slots to fetch per account
        public let storageSlotsPerAccount: Int

        /// Number of accounts to benchmark
        public let numAccounts: Int

        public init(
            rpcURL: String = "https://ethereum-rpc.publicnode.com",
            iterations: Int = 3,
            blockNumber: UInt64 = 20_000_000,
            storageSlotsPerAccount: Int = 5,
            numAccounts: Int = 3
        ) {
            self.rpcURL = rpcURL
            self.iterations = iterations
            self.blockNumber = blockNumber
            self.storageSlotsPerAccount = storageSlotsPerAccount
            self.numAccounts = numAccounts
        }
    }

    // MARK: - Benchmark Results

    /// Results from a state proof benchmark run
    public struct BenchmarkResult: Sendable {
        /// Average fetch time per account (ms)
        public let avgFetchTimeMs: Double

        /// Average verify time per account (ms)
        public let avgVerifyTimeMs: Double

        /// Average total time per account (ms)
        public let avgTotalTimeMs: Double

        /// Min time per account (ms)
        public let minTimeMs: Double

        /// Max time per account (ms)
        public let maxTimeMs: Double

        /// Standard deviation of total time
        public let stdDevMs: Double

        /// Number of accounts benchmarked
        public let numAccounts: Int

        /// Number of storage slots per account
        public let storageSlotsPerAccount: Int

        /// Total proof bytes received
        public let totalProofBytes: Int

        /// Number of iterations
        public let iterations: Int

        /// Whether eth_getProof is supported by the RPC
        public let ethGetProofSupported: Bool
    }

    // MARK: - Well-Known Test Accounts

    /// Common Ethereum addresses for benchmarking
    public struct TestAccounts {
        /// Ethereum Foundation multisig
        public static let foundation = "0xde0b29467822f13e2e2a70e600b1c1e73f5f73b3"

        /// Wrapped Ether contract
        public static let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

        /// USDC contract
        public static let usdc = "0xA0b86991c6218b36c1d19D4a2e9EbE0E3606eFB4"

        /// Uniswap V2 Router
        public static let uniswapV2Router = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"

        /// Test addresses for benchmarking
        public static let all: [String] = [
            foundation,
            weth,
            usdc,
            uniswapV2Router,
            "0xBE0eB53F46cd790Cd13851d5EFf43D12404dC851" // Maker Governance
        ]
    }

    // MARK: - Benchmark Runner

    /// Run benchmark for state proof fetching and verification.
    ///
    /// This benchmark:
    /// 1. Fetches state proofs via `eth_getProof` RPC
    /// 2. Verifies the proofs against the state root
    /// 3. Reports timing statistics
    ///
    /// - Parameter config: Benchmark configuration
    /// - Returns: Benchmark results
    public static func run(config: BenchmarkConfig = .init()) async throws -> BenchmarkResult {
        let fetcher = StateProofFetcher(config: .init(url: config.rpcURL, timeout: 120))
        let verifier = StateProofVerifier()

        // Select test accounts
        let accounts = Array(TestAccounts.all.prefix(config.numAccounts))

        // Generate storage slots to fetch
        let storageSlots: [M31Word] = (0..<config.storageSlotsPerAccount).map { i in
            M31Word(low64: UInt64(i))
        }

        var fetchTimes: [Double] = []
        var verifyTimes: [Double] = []
        var totalProofBytes = 0

        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║           State Proof Benchmark                          ║
        ╠═══════════════════════════════════════════════════════════╣
        ║ RPC: \(config.rpcURL)
        ║ Block: \(config.blockNumber) (0x\(String(config.blockNumber, radix: 16)))
        ║ Accounts: \(config.numAccounts)
        ║ Storage slots/account: \(config.storageSlotsPerAccount)
        ║ Iterations: \(config.iterations)
        ╚═══════════════════════════════════════════════════════════╝
        """)

        for iteration in 0..<config.iterations {
            print("\n[Iteration \(iteration + 1)/\(config.iterations)]")

            for account in accounts {
                let fetchStart = CFAbsoluteTimeGetCurrent()

                // Fetch proofs
                let proof: StateProofFetcher.StateProof
                let blockHex = "0x" + String(config.blockNumber, radix: 16)
                do {
                    proof = try await fetcher.fetchProofs(
                        address: account,
                        storageSlots: storageSlots,
                        blockNumber: blockHex
                    )
                } catch StateProofFetcherError.rpcError(let msg) where msg.contains("method not found") ||
                         msg.contains("not supported") {
                    print("  ⚠️ eth_getProof not supported by this RPC endpoint")
                    print("  ℹ️  Try an archive node (Erigon, Reth, or a node with eth_getProof support)")
                    return BenchmarkResult(
                        avgFetchTimeMs: 0,
                        avgVerifyTimeMs: 0,
                        avgTotalTimeMs: 0,
                        minTimeMs: 0,
                        maxTimeMs: 0,
                        stdDevMs: 0,
                        numAccounts: config.numAccounts,
                        storageSlotsPerAccount: config.storageSlotsPerAccount,
                        totalProofBytes: 0,
                        iterations: config.iterations,
                        ethGetProofSupported: false
                    )
                }

                let fetchTimeMs = (CFAbsoluteTimeGetCurrent() - fetchStart) * 1000

                // Count proof bytes
                let accountProofBytes = proof.accountProof.reduce(0) { $0 + $1.count }
                let storageProofBytes = proof.storageProofs.reduce(0) { sum, sp in
                    sum + sp.proof.reduce(0) { $0 + $1.count }
                }
                totalProofBytes += accountProofBytes + storageProofBytes

                let verifyStart = CFAbsoluteTimeGetCurrent()
                let verified = try verifier.verifyFullProof(proof)
                let verifyTimeMs = (CFAbsoluteTimeGetCurrent() - verifyStart) * 1000

                let totalTimeMs = fetchTimeMs + verifyTimeMs
                fetchTimes.append(fetchTimeMs)
                verifyTimes.append(verifyTimeMs)

                print("  \(account.prefix(10))...")
                print("    Fetch: \(String(format: "%.1f", fetchTimeMs))ms | Verify: \(String(format: "%.1f", verifyTimeMs))ms | Total: \(String(format: "%.1f", totalTimeMs))ms")
                print("    Proof: \(accountProofBytes) bytes (account) + \(storageProofBytes) bytes (storage)")
                print("    Balance: \(verified.account.balance.toHexString().prefix(20))... | Storage slots: \(verified.storage.count)")
            }
        }

        // Calculate statistics
        let totalTimes = zip(fetchTimes, verifyTimes).map { $0 + $1 }

        let avgFetch = fetchTimes.reduce(0, +) / Double(fetchTimes.count)
        let avgVerify = verifyTimes.reduce(0, +) / Double(verifyTimes.count)
        let avgTotal = totalTimes.reduce(0, +) / Double(totalTimes.count)
        let minTime = totalTimes.min() ?? 0
        let maxTime = totalTimes.max() ?? 0

        // Standard deviation
        let mean = avgTotal
        let variance = totalTimes.map { pow($0 - mean, 2) }.reduce(0, +) / Double(totalTimes.count)
        let stdDev = sqrt(variance)

        let result = BenchmarkResult(
            avgFetchTimeMs: avgFetch,
            avgVerifyTimeMs: avgVerify,
            avgTotalTimeMs: avgTotal,
            minTimeMs: minTime,
            maxTimeMs: maxTime,
            stdDevMs: stdDev,
            numAccounts: config.numAccounts,
            storageSlotsPerAccount: config.storageSlotsPerAccount,
            totalProofBytes: totalProofBytes,
            iterations: config.iterations,
            ethGetProofSupported: true
        )

        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║              Benchmark Results                           ║
        ╠═══════════════════════════════════════════════════════════╣
        ║ eth_getProof supported: YES
        ║
        ║ Per-Account Timing:
        ║   Average fetch:  \(String(format: "%.1f", avgFetch))ms
        ║   Average verify: \(String(format: "%.1f", avgVerify))ms
        ║   Average total:  \(String(format: "%.1f", avgTotal))ms
        ║   Min time:       \(String(format: "%.1f", minTime))ms
        ║   Max time:       \(String(format: "%.1f", maxTime))ms
        ║   Std deviation:  \(String(format: "%.1f", stdDev))ms
        ║
        ║ Proof Sizes:
        ║   Total proof bytes: \(totalProofBytes) bytes
        ║   Avg per account:   \(totalProofBytes / config.numAccounts) bytes
        ║
        ║ Throughput (single-threaded):
        ║   Accounts/second: \(String(format: "%.1f", 1000.0 / avgTotal))
        ╚═══════════════════════════════════════════════════════════╝
        """)

        return result
    }

    /// Run benchmark with default configuration.
    public static func runDefault() async throws -> BenchmarkResult {
        try await run(config: .init())
    }
}
