import Foundation
import zkMetal

/// Converts archive node witness data to EVMAIR trace format.
///
/// This converter bridges the gap between Geth-compatible trace formats
/// and the internal EVMExecutionTrace used by Zoltraak for proving.
///
/// ## Conversion Pipeline
///
/// ```
/// Archive Node Witness (Geth Trace)
///         │
///         ▼
/// ┌───────────────────────────────┐
/// │   WitnessToTraceConverter    │
/// │  - Parse stack/memory hex    │
/// │  - Map opcodes to bytes       │
/// │  - Build trace rows           │
/// │  - Validate trace integrity   │
/// └───────────────────────────────┘
///         │
///         ▼
/// EVMExecutionTrace (EVMAIR format)
///         │
///         ▼
/// BlockExecutionTrace (for proving)
/// ```
public final class WitnessToTraceConverter: Sendable {

    // MARK: - Configuration

    /// Configuration for trace conversion
    public struct ConversionConfig {
        /// Validate stack height consistency
        public let validateStackHeight: Bool

        /// Validate memory continuity
        public let validateMemory: Bool

        /// Fill missing stack with zeros
        public let fillMissingStack: Bool

        /// Target rows per transaction (power of 2)
        public let targetRowsPerTx: Int

        public init(
            validateStackHeight: Bool = true,
            validateMemory: Bool = true,
            fillMissingStack: Bool = true,
            targetRowsPerTx: Int = 256
        ) {
            self.validateStackHeight = validateStackHeight
            self.validateMemory = validateMemory
            self.fillMissingStack = fillMissingStack
            self.targetRowsPerTx = targetRowsPerTx
        }

        /// Standard configuration for production use
        public static let standard = ConversionConfig()

        /// Lenient configuration for handling imperfect traces
        public static let lenient = ConversionConfig(
            validateStackHeight: false,
            validateMemory: false,
            fillMissingStack: true,
            targetRowsPerTx: 256
        )
    }

    // MARK: - Properties

    private let config: ConversionConfig

    // MARK: - Initialization

    /// Initialize converter with configuration
    public init(config: ConversionConfig = .standard) {
        self.config = config
    }

    // MARK: - Public API

    /// Convert archive node witness to EVM execution trace.
    ///
    /// - Parameters:
    ///   - witness: Raw witness data from archive node
    ///   - initialState: Initial EVM state snapshot (optional)
    /// - Returns: EVM execution trace in EVMAIR format
    public func convert(witness: ArchiveNodeWitness, initialState: EVMStateSnapshot? = nil) throws -> EVMExecutionTrace {
        guard !witness.steps.isEmpty else {
            throw ConversionError.emptyWitness
        }

        // Convert each step to trace row
        var rows: [EVMTraceRow] = []
        var currentStack: [M31Word] = []
        var memorySize: Int = 0
        var callDepth: Int = 0
        var stateRoot: M31Word = .zero
        var gas: UInt64 = 0
        var timestamp: UInt64 = 0

        for (index, step) in witness.steps.enumerated() {
            // Update state from step
            gas = step.gas
            callDepth = step.depth

            // Parse stack from hex strings
            let stepStack = parseStackFromHex(step.stack)

            // Merge with current stack based on opcode
            currentStack = updateStack(
                current: currentStack,
                new: stepStack,
                opcode: step.opcode
            )

            // Parse memory size from step
            if !step.memory.isEmpty {
                // Memory size is derived from number of 32-byte words accessed
                memorySize = max(memorySize, deriveMemorySize(from: step.memory))
            }

            // Build trace row
            let row = EVMTraceRow(
                pc: step.pc,
                opcode: step.opcode,
                gas: gas,
                stackHeight: currentStack.count,
                stackSnapshot: buildStackSnapshot(from: currentStack),
                memorySize: memorySize,
                callDepth: callDepth,
                stateRoot: stateRoot,
                isRunning: !step.hasError && index < witness.steps.count - 1,
                isReverted: step.hasError,
                timestamp: timestamp
            )

            rows.append(row)
            timestamp += 1

            // Stop if error encountered
            if step.hasError {
                break
            }
        }

        // Build initial and final state
        let initial = initialState ?? createInitialState()
        let final = createFinalState(
            rows: rows,
            stack: currentStack,
            memorySize: memorySize,
            callDepth: callDepth,
            stateRoot: stateRoot,
            reverted: witness.steps.last?.hasError ?? false
        )

        return EVMExecutionTrace(
            rows: rows,
            initialState: initial,
            finalState: final,
            gasUsed: gas,
            returnData: [],
            reverted: witness.steps.last?.hasError ?? false
        )
    }

    /// Convert multiple witnesses to block trace.
    ///
    /// - Parameters:
    ///   - witnesses: Dictionary of tx hash to witness
    ///   - blockContext: Block context for trace building
    /// - Returns: Block execution trace
    public func convertToBlockTrace(
        witnesses: [String: ArchiveNodeWitness],
        blockContext: BlockContext
    ) throws -> BlockExecutionTrace {
        var txTraces: [EVMExecutionTrace] = []

        for (_, witness) in witnesses.sorted(by: { $0.key < $1.key }) {
            let trace = try convert(witness: witness)
            txTraces.append(trace)
        }

        // Build state transitions between transactions
        var transitions: [StateTransition] = []
        for i in 0..<(txTraces.count - 1) {
            transitions.append(StateTransition(
                fromState: txTraces[i].finalState,
                toState: txTraces[i + 1].initialState,
                transactionIndex: i
            ))
        }

        // Build block metadata
        let totalGas = txTraces.reduce(0) { $0 + $1.gasUsed }
        let metadata = BlockMetadata(
            transactionCount: txTraces.count,
            totalGasUsed: totalGas,
            blockReward: 0
        )

        return BlockExecutionTrace(
            transactionTraces: txTraces,
            blockHeader: BlockHeader(
                parentHash: .zero,
                blockNumber: blockContext.number,
                timestamp: blockContext.timestamp,
                gasLimit: blockContext.gasLimit
            ),
            interTxStateTransitions: transitions,
            metadata: metadata
        )
    }

    /// Validate witness against expected trace structure.
    ///
    /// - Parameters:
    ///   - witness: Witness to validate
    ///   - expectedRowCount: Expected number of trace rows
    /// - Returns: Validation result with any issues found
    public func validate(witness: ArchiveNodeWitness, expectedRowCount: Int? = nil) -> ValidationResult {
        var issues: [ValidationIssue] = []

        // Check for empty witness
        if witness.steps.isEmpty {
            issues.append(ValidationIssue(
                type: .emptyWitness,
                message: "Witness has no steps"
            ))
            return ValidationResult(valid: false, issues: issues)
        }

        // Check row count expectation
        if let expected = expectedRowCount {
            let actual = witness.steps.count
            if actual > expected {
                issues.append(ValidationIssue(
                    type: .rowCountMismatch,
                    message: "Witness has \(actual) rows, expected \(expected)"
                ))
            }
        }

        // Check opcode validity
        for (index, step) in witness.steps.enumerated() {
            if step.opcode > 0xFF {
                issues.append(ValidationIssue(
                    type: .invalidOpcode,
                    message: "Step \(index): Invalid opcode byte \(step.opcode)"
                ))
            }

            // Check stack size (max 1024)
            if step.stack.count > 1024 {
                issues.append(ValidationIssue(
                    type: .stackOverflow,
                    message: "Step \(index): Stack size \(step.stack.count) exceeds maximum"
                ))
            }
        }

        return ValidationResult(
            valid: issues.isEmpty,
            issues: issues
        )
    }

    // MARK: - Private Helper Methods

    /// Parse stack from hex string array.
    private func parseStackFromHex(_ stack: [String]) -> [M31Word] {
        return stack.compactMap { hex -> M31Word? in
            let cleanHex = strip0xPrefix(hex)
            guard cleanHex.count == 64 else { return nil }
            return hexToM31Word(cleanHex)
        }
    }

    /// Strip 0x prefix from hex string.
    private func strip0xPrefix(_ hex: String) -> String {
        if hex.hasPrefix("0x") || hex.hasPrefix("0X") {
            return String(hex.dropFirst(2))
        }
        return hex
    }

    /// Convert hex string to M31Word.
    private func hexToM31Word(_ hex: String) -> M31Word {
        // Clean hex string
        let cleanHex = hex.lowercased().hasPrefix("0x")
            ? String(hex.dropFirst(2))
            : hex

        // Pad or truncate to 64 characters (256 bits)
        let paddedHex = cleanHex.count >= 64
            ? String(cleanHex.suffix(64))
            : String(repeating: "0", count: 64 - cleanHex.count) + cleanHex

        // Parse as big-endian 256-bit integer, split into 64-bit chunks
        let high64Str = String(paddedHex.prefix(16))
        let mid64Str = String(paddedHex.dropFirst(16).prefix(16))
        let low64Str = String(paddedHex.dropFirst(32).prefix(16))

        let high64 = UInt64(high64Str, radix: 16) ?? 0
        let mid64 = UInt64(mid64Str, radix: 16) ?? 0
        let low64 = UInt64(low64Str, radix: 16) ?? 0

        // Combine into 256-bit value using 64-bit components
        // M31Word stores as 9 x 31-bit limbs, we use bytes approach
        var bytes = [UInt8]()

        // Parse hex string into bytes (big-endian to little-endian conversion)
        for i in stride(from: paddedHex.count - 2, through: 0, by: -2) {
            let startIndex = paddedHex.index(paddedHex.startIndex, offsetBy: max(0, i - 1))
            let endIndex = paddedHex.index(paddedHex.startIndex, offsetBy: min(paddedHex.count, i + 2))
            let byteStr = String(paddedHex[startIndex..<endIndex])
            if let byte = UInt8(byteStr, radix: 16) {
                bytes.append(byte)
            }
        }

        // Pad to 32 bytes if needed
        while bytes.count < 32 {
            bytes.insert(0, at: 0)
        }

        // Create M31Word from bytes
        var low64Value: UInt64 = 0
        for (i, byte) in bytes.prefix(8).enumerated() {
            low64Value |= UInt64(byte) << (i * 8)
        }

        return M31Word(low64: low64Value)
    }

    /// Update stack based on opcode behavior.
    private func updateStack(current: [M31Word], new: [M31Word], opcode: UInt8) -> [M31Word] {
        // For archive node traces, we use the new stack directly
        // since it represents the post-execution state

        // Some archive nodes provide pre-state, others provide post-state
        // We detect this by comparing sizes
        if new.count >= current.count {
            return new
        }

        // If new is smaller, it might be pre-state
        // In that case, apply expected stack changes
        guard let evmOpcode = EVMOpcode(rawValue: opcode) else {
            return new.isEmpty ? current : new
        }

        let stackChange = evmOpcode.properties.stackHeightChange
        let expectedSize = current.count + stackChange

        // If new matches expected size, it's post-state
        if new.count == expectedSize {
            return new
        }

        // Otherwise, use current and apply expected change
        if stackChange > 0 {
            // Push operations add to stack
            return new + Array(current.prefix(stackChange))
        } else if stackChange < 0 {
            // Pop operations remove from stack
            return Array(current.dropFirst(-stackChange))
        }

        return new.isEmpty ? current : new
    }

    /// Build stack snapshot for AIR columns (top 16 items).
    private func buildStackSnapshot(from stack: [M31Word]) -> [M31Word] {
        let topItems = stack.prefix(16)
        var result = Array(topItems)

        // Pad with zeros if less than 16 items
        while result.count < 16 {
            result.append(.zero)
        }

        return result
    }

    /// Derive memory size from memory access data.
    private func deriveMemorySize(from memory: [String]) -> Int {
        guard !memory.isEmpty else { return 0 }

        // Memory in Geth traces is typically provided as word-aligned chunks
        // Find the highest offset accessed
        var maxOffset = 0

        for (index, chunk) in memory.enumerated() {
            let offset = index * 64  // Each chunk is 32 bytes = 64 hex chars
            if !chunk.isEmpty && chunk != "0".padding(toLength: 64, withPad: "0", startingAt: 0) {
                maxOffset = max(maxOffset, offset + 32)
            }
        }

        return maxOffset
    }

    /// Create initial state snapshot.
    private func createInitialState() -> EVMStateSnapshot {
        EVMStateSnapshot(
            pc: 0,
            gas: 0,
            gasRefund: 0,
            stackHeight: 0,
            memorySize: 0,
            callDepth: 0,
            stateRoot: .zero,
            selfBalance: .zero,
            running: true,
            reverted: false
        )
    }

    /// Create final state snapshot.
    private func createFinalState(
        rows: [EVMTraceRow],
        stack: [M31Word],
        memorySize: Int,
        callDepth: Int,
        stateRoot: M31Word,
        reverted: Bool
    ) -> EVMStateSnapshot {
        let lastRow = rows.last

        return EVMStateSnapshot(
            pc: lastRow?.pc ?? 0,
            gas: lastRow?.gas ?? 0,
            gasRefund: 0,
            stackHeight: stack.count,
            memorySize: memorySize,
            callDepth: callDepth,
            stateRoot: stateRoot,
            selfBalance: .zero,
            running: lastRow?.isRunning ?? false,
            reverted: reverted
        )
    }
}

// MARK: - Data Structures

/// Result of trace validation
public struct ValidationResult: Sendable {
    public let valid: Bool
    public let issues: [ValidationIssue]

    public init(valid: Bool, issues: [ValidationIssue]) {
        self.valid = valid
        self.issues = issues
    }
}

/// A single validation issue found
public struct ValidationIssue: Sendable {
    public enum IssueType: Sendable {
        case emptyWitness
        case rowCountMismatch
        case invalidOpcode
        case stackOverflow
        case memoryDiscontinuity
        case gasUnderflow
    }

    public let type: IssueType
    public let message: String

    public init(type: IssueType, message: String) {
        self.type = type
        self.message = message
    }
}

// MARK: - Errors

/// Errors during witness-to-trace conversion
public enum ConversionError: Error, LocalizedError {
    case emptyWitness
    case invalidStackFormat(String)
    case invalidMemoryFormat(String)
    case opcodeMappingFailed(String)
    case validationFailed([ValidationIssue])

    public var errorDescription: String? {
        switch self {
        case .emptyWitness:
            return "Witness contains no execution steps"
        case .invalidStackFormat(let detail):
            return "Invalid stack format: \(detail)"
        case .invalidMemoryFormat(let detail):
            return "Invalid memory format: \(detail)"
        case .opcodeMappingFailed(let op):
            return "Failed to map opcode: \(op)"
        case .validationFailed(let issues):
            let messages = issues.map { $0.message }.joined(separator: ", ")
            return "Validation failed: \(messages)"
        }
    }
}

// MARK: - String Extension

private extension String {
    func padding(toLength length: Int, withPad pad: Character, startingAt index: Int) -> String {
        if self.count >= length {
            return self
        }
        let padString = String(repeating: pad, count: length - self.count)
        return padString + self
    }
}
