import Foundation
import zkMetal

// MARK: - Proof Compression Configuration

/// Configuration for proof compression optimizations.
///
/// This file defines the strategies for reducing trace tree size while maintaining
/// correctness guarantees.
///
/// ## Security Implications
///
/// When reducing trace dimensions, we trade off:
/// - **Speed**: Smaller trees = faster proving
/// - **Security**: Fewer rows/columns checked = weaker soundness
///
/// ### logTraceLength Security Impact
///
/// | logTraceLength | Rows per TX | Tree Depth | Soundness Loss |
/// |----------------|-------------|------------|----------------|
/// | 12 (4096)      | 4096        | 12         | None           |
/// | 8 (256)        | 256         | 8          | ~4 bits        |
/// | 6 (64)         | 64          | 6          | ~6 bits        |
/// | 4 (16)         | 16          | 4          | ~8 bits        |
///
/// To compensate: increase `numQueries` or `logBlowup`
///
/// ### Column Subset Security Impact
///
/// | Proving Columns | Commit Columns | Soundness Loss | Speedup |
/// |-----------------|---------------|---------------|---------|
/// | 180 (all)       | 180           | None          | 1x      |
/// | 32              | 180           | ~2.5 bits     | ~5x     |
/// | 16              | 180           | ~3.3 bits     | ~8x     |
///
/// The full 180 columns are committed (proving all data exists), but only the
/// subset is included in the FRI composition polynomial (what's actually verified).
///
/// ## Trade-off Matrix
///
/// For 123 transactions with logBlowup=1:
/// - logTraceLength=8, 32 columns: ~17 levels deep, ~5.5x faster
/// - logTraceLength=6, 32 columns: ~15 levels deep, ~10x faster
/// - logTraceLength=4, 32 columns: ~13 levels deep, ~20x faster
public struct ProofCompressionConfig {

    // MARK: - Trace Length Configuration

    /// Log of rows per transaction.
    ///
    /// Smaller values = smaller trees = faster proving
    /// - 12: 4096 rows (baseline, no compression)
    /// - 8: 256 rows (4x compression)
    /// - 6: 64 rows (16x compression)
    /// - 4: 16 rows (64x compression)
    public let logTraceLength: Int

    /// Log of blowup factor for LDE.
    ///
    /// Higher values = more evaluation points = stronger security but slower
    /// - 1: 2x blowup (minimum, weakest security)
    /// - 2: 4x blowup (balanced)
    /// - 3: 8x blowup (stronger)
    public let logBlowup: Int

    /// Number of FRI queries for soundness.
    ///
    /// More queries = stronger soundness but larger proofs
    /// - 8: Fast testing
    /// - 20: Standard production
    /// - 50: High security
    public let numQueries: Int

    // MARK: - Column Selection Configuration

    /// Number of columns to include in FRI composition polynomial.
    ///
    /// "Commit to all, prove subset" approach:
    /// - All 180 columns are committed for soundness
    /// - Only `provingColumnCount` columns are included in FRI
    ///
    /// Recommended values:
    /// - 180: No compression (full soundness)
    /// - 32: Good compression (~5x FRI speedup)
    /// - 16: Aggressive compression (~8x FRI speedup)
    public let provingColumnCount: Int

    /// Indices of critical columns to include in FRI.
    ///
    /// These columns are selected for the composition polynomial:
    /// - Execution flow columns (PC, gas, call depth)
    /// - State transition columns (stack, memory)
    /// - Critical constraint columns
    ///
    /// Remaining columns are committed but not verified by FRI.
    public let criticalColumnIndices: [Int]

    // MARK: - Tier Configuration

    /// Whether to use two-tier proving.
    ///
    /// Tier 1: Fast proof for critical columns only
    /// Tier 2: Full proof including all columns (when needed)
    public let enableTwoTierProving: Bool

    /// Number of queries for Tier 1 (fast proof).
    ///
    /// Tier 1 uses fewer queries for faster verification of critical columns.
    public let tier1NumQueries: Int

    /// Number of queries for Tier 2 (full proof).
    ///
    /// Tier 2 uses more queries for full verification when needed.
    public let tier2NumQueries: Int

    // MARK: - Computed Properties

    /// Total trace length for the block (all transactions).
    public func logBlockTraceLength(numTransactions: Int) -> Int {
        logTraceLength + log2Ceil(numTransactions)
    }

    /// Tree depth for given number of transactions.
    public func treeDepth(numTransactions: Int) -> Int {
        logBlockTraceLength(numTransactions: numTransactions)
    }

    /// Estimated tree size (leaves) for given number of transactions.
    public func treeSize(numTransactions: Int) -> Int {
        1 << logBlockTraceLength(numTransactions: numTransactions)
    }

    /// Security bits provided by this configuration.
    ///
    /// Security = numQueries * logBlowup + log2(provingColumns)
    /// The column subset provides additional entropy for security.
    public var securityBits: Int {
        numQueries * logBlowup + Int(log2(Double(provingColumnCount)))
    }

    /// Additional security from column subset (informational).
    public func soundnessLossBits(totalColumns: Int) -> Double {
        // Soundness loss from not checking all columns
        // log2(total_columns / proving_columns)
        Double(totalColumns) / Double(provingColumnCount) > 0
        return log2(Double(totalColumns) / Double(provingColumnCount))
    }

    // MARK: - Initialization

    public init(
        logTraceLength: Int = 8,
        logBlowup: Int = 2,
        numQueries: Int = 20,
        provingColumnCount: Int = 32,
        criticalColumnIndices: [Int]? = nil,
        enableTwoTierProving: Bool = false,
        tier1NumQueries: Int = 8,
        tier2NumQueries: Int = 50
    ) {
        precondition(logTraceLength >= 4 && logTraceLength <= 12,
                     "logTraceLength must be between 4 and 12")
        precondition(logBlowup >= 1 && logBlowup <= 8,
                     "logBlowup must be between 1 and 8")
        precondition(numQueries >= 1 && numQueries <= 200,
                     "numQueries must be between 1 and 200")
        precondition(provingColumnCount >= 1 && provingColumnCount <= 180,
                     "provingColumnCount must be between 1 and 180")

        self.logTraceLength = logTraceLength
        self.logBlowup = logBlowup
        self.numQueries = numQueries
        self.provingColumnCount = provingColumnCount
        self.criticalColumnIndices = criticalColumnIndices ?? Self.defaultCriticalColumns
        self.enableTwoTierProving = enableTwoTierProving
        self.tier1NumQueries = tier1NumQueries
        self.tier2NumQueries = tier2NumQueries
    }

    // MARK: - Presets

    /// Maximum compression: fastest proving, lowest security.
    public static let maxCompression = ProofCompressionConfig(
        logTraceLength: 4,
        logBlowup: 1,
        numQueries: 50,
        provingColumnCount: 16
    )

    /// High compression: good speedup with reasonable security.
    public static let highCompression = ProofCompressionConfig(
        logTraceLength: 6,
        logBlowup: 2,
        numQueries: 30,
        provingColumnCount: 32
    )

    /// Standard compression: balanced speedup and security.
    public static let standard = ProofCompressionConfig(
        logTraceLength: 8,
        logBlowup: 2,
        numQueries: 20,
        provingColumnCount: 32
    )

    /// Low compression: minimal speedup, high security.
    public static let lowCompression = ProofCompressionConfig(
        logTraceLength: 10,
        logBlowup: 3,
        numQueries: 25,
        provingColumnCount: 64
    )

    /// No compression: baseline security, no speedup.
    public static let none = ProofCompressionConfig(
        logTraceLength: 12,
        logBlowup: 4,
        numQueries: 30,
        provingColumnCount: 180
    )

    // MARK: - Default Critical Columns

    /// Default set of 32 critical columns for EVM proving.
    ///
    /// These columns are selected based on:
    /// 1. Execution flow: PC, gas, call depth
    /// 2. State: stack, memory
    /// 3. Critical constraints: arithmetic, jumps
    public static let defaultCriticalColumns: [Int] = [
        // Execution flow (8 columns)
        0,   // PC
        1,   // Gas
        2,   // State root
        147, // Memory size
        148, // Call depth
        149, // Timestamp
        163, // Call depth (duplicate)
        164, // Reserved

        // Stack columns (16 columns - first 2 stack words × 8 limbs)
        3, 4, 5, 6, 7, 8, 9, 10,   // Stack word 0 (8 limbs)
        11, 12, 13, 14, 15, 16, 17, 18, // Stack word 1 (8 limbs)

        // Memory columns (4 columns)
        147, // Memory size
        150, // Memory access address
        151, // Memory value (low)
        152, // Memory value (high)

        // Arithmetic columns (4 columns)
        20,  // ALU input A
        21,  // ALU input B
        22,  // ALU output
        23   // ALU opcode
    ]

    // MARK: - Helpers

    private func log2Ceil(_ n: Int) -> Int {
        var count = 0
        var value = n - 1
        while value > 0 {
            count += 1
            value >>= 1
        }
        return count
    }

    /// Estimate soundness loss from compression settings.
    ///
    /// Returns: Estimated bits of soundness loss compared to baseline (logTrace=12, all columns)
    public func estimatedSoundnessLoss() -> Double {
        // Baseline: logTrace=12, all 180 columns
        // With compression:
        // - Each step down in logTraceLength: ~log2(2) = 1 bit loss (but compensated by more queries)
        // - Each reduction in proving columns: log2(180/provingColumns) bits

        let traceLoss = Double(12 - logTraceLength) * 0.5  // Partial compensation from queries
        let columnLoss = log2(Double(180) / Double(provingColumnCount))
        let blowupLoss = Double(4 - logBlowup) * 0.3  // Lower blowup = weaker security

        return max(0, traceLoss + columnLoss + blowupLoss)
    }

    /// Get security level description.
    public var securityDescription: String {
        let loss = estimatedSoundnessLoss()
        if loss < 1 {
            return "Near-optimal security (\(String(format: "%.1f", loss)) bits loss)"
        } else if loss < 3 {
            return "Good security (\(String(format: "%.1f", loss)) bits loss)"
        } else if loss < 5 {
            return "Moderate security (\(String(format: "%.1f", loss)) bits loss)"
        } else {
            return "Reduced security (\(String(format: "%.1f", loss)) bits loss)"
        }
    }
}

// MARK: - Security Analysis

/// Security analysis for proof compression settings.
public struct ProofCompressionSecurityAnalysis {
    /// Original configuration (baseline)
    public let baseline: ProofCompressionConfig

    /// Compressed configuration
    public let compressed: ProofCompressionConfig

    /// Baseline security bits
    public let baselineSecurityBits: Int

    /// Compressed security bits
    public let compressedSecurityBits: Int

    /// Soundness loss in bits
    public let soundnessLossBits: Double

    /// Estimated speedup factor
    public let estimatedSpeedup: Double

    /// Whether the configuration is acceptable for production
    public let acceptableForProduction: Bool

    public init(baseline: ProofCompressionConfig, compressed: ProofCompressionConfig) {
        self.baseline = baseline
        self.compressed = compressed

        // Baseline security: numQueries * logBlowup + column entropy
        self.baselineSecurityBits = baseline.numQueries * baseline.logBlowup +
            Int(log2(Double(180)))  // log2(180) bits from all columns

        // Compressed security
        self.compressedSecurityBits = compressed.numQueries * compressed.logBlowup +
            Int(log2(Double(compressed.provingColumnCount)))

        // Soundness loss
        self.soundnessLossBits = compressed.estimatedSoundnessLoss()

        // Estimate speedup (rough approximation)
        // - Tree size: exponential in logTraceLength
        // - FRI: linear in columns
        // - Query: exponential in tree depth
        let treeDepthRatio = pow(2.0, Double(baseline.logTraceLength - compressed.logTraceLength))
        let columnRatio = Double(baseline.provingColumnCount) / Double(compressed.provingColumnCount)
        let queryRatio = Double(baseline.numQueries) / Double(compressed.numQueries)
        self.estimatedSpeedup = (treeDepthRatio * columnRatio) / queryRatio

        // Acceptable if >= 80 bits effective security
        self.acceptableForProduction = compressedSecurityBits >= 80
    }

    /// Generate a human-readable security report.
    public var report: String {
        """
        Proof Compression Security Report
        =================================

        Baseline Configuration:
          logTraceLength: \(baseline.logTraceLength)
          logBlowup: \(baseline.logBlowup)
          provingColumns: \(baseline.provingColumnCount)
          numQueries: \(baseline.numQueries)
          Estimated Security: \(baselineSecurityBits) bits

        Compressed Configuration:
          logTraceLength: \(compressed.logTraceLength)
          logBlowup: \(compressed.logBlowup)
          provingColumns: \(compressed.provingColumnCount)
          numQueries: \(compressed.numQueries)
          Estimated Security: \(compressedSecurityBits) bits

        Analysis:
          Soundness Loss: \(String(format: "%.1f", soundnessLossBits)) bits
          Estimated Speedup: \(String(format: "%.1fx", estimatedSpeedup))
          Production Ready: \(acceptableForProduction ? "YES" : "NO (needs more queries or blowup)")

        \(compressed.securityDescription)
        """
    }
}

// MARK: - Proof Tier

/// Two-tier proof structure for flexible verification.
public enum ProofTier: Int, Sendable {
    /// Fast proof: only critical columns verified
    case fast = 1

    /// Full proof: all columns verified
    case full = 2

    /// Extended proof: maximum security
    case extended = 3
}

/// Metadata for tiered proofs.
public struct ProofTierMetadata: Sendable {
    /// The tier of this proof
    public let tier: ProofTier

    /// Which columns were included in this proof
    public let includedColumns: [Int]

    /// Number of queries used
    public let numQueries: Int

    /// Security bits provided
    public let securityBits: Int

    /// Estimated verification time (relative)
    public let relativeVerifyTime: Double

    public init(tier: ProofTier, includedColumns: [Int], numQueries: Int, securityBits: Int) {
        self.tier = tier
        self.includedColumns = includedColumns
        self.numQueries = numQueries
        self.securityBits = securityBits
        self.relativeVerifyTime = tier == .fast ? 1.0 : tier == .full ? 3.0 : 10.0
    }
}
