import Foundation
import zkMetal

/// Fetches pre-computed witness data from Ethereum archive nodes.
///
/// Archive nodes (Erigon, Reth) store complete execution traces for historical blocks.
/// This allows skipping local EVM execution by using the pre-generated witness data.
///
/// ## Supported APIs
///
/// - `trace_transaction` - Geth-compatible (Erigon, Reth)
/// - `debug_traceTransaction` - Geth-compatible debugging API
///
/// ## Response Format
///
/// ```json
/// {
///   "steps": [...],
///   "stack": [...],
///   "memory": [...],
///   "storage": {...}
/// }
/// ```
public final class ArchiveNodeWitnessFetcher: Sendable {

    // MARK: - Configuration

    /// Configuration for archive node connection
    public struct ArchiveNodeConfig {
        public let url: String
        public let timeout: TimeInterval
        public let enableTracing: Bool

        /// Default Erigon endpoint (archive node)
        public static let erigon = ArchiveNodeConfig(
            url: "http://localhost:8080",
            timeout: 120,
            enableTracing: true
        )

        /// Default Reth endpoint (archive node)
        public static let reth = ArchiveNodeConfig(
            url: "http://localhost:8545",
            timeout: 120,
            enableTracing: true
        )

        /// Local Geth debug endpoint
        public static let geth = ArchiveNodeConfig(
            url: "http://localhost:8545",
            timeout: 120,
            enableTracing: true
        )

        public init(url: String, timeout: TimeInterval = 120, enableTracing: Bool = true) {
            self.url = url
            self.timeout = timeout
            self.enableTracing = enableTracing
        }
    }

    // MARK: - Properties

    private let config: ArchiveNodeConfig

    // MARK: - Initialization

    /// Initialize fetcher with archive node configuration
    public init(config: ArchiveNodeConfig = .erigon) {
        self.config = config
    }

    // MARK: - Public API

    /// Fetch witness data for a transaction by hash.
    ///
    /// This method attempts to fetch the full execution trace from an archive node.
    /// The trace includes every opcode execution with stack, memory, and storage state.
    ///
    /// - Parameters:
    ///   - txHash: Transaction hash (with or without 0x prefix)
    /// - Returns: Raw witness data from archive node
    /// - Throws: ArchiveNodeError if fetch fails
    public func fetchWitness(txHash: String) async throws -> ArchiveNodeWitness {
        // Try trace_transaction first (Erigon/Reth)
        if let witness = try? await fetchTraceTransaction(txHash: txHash) {
            return witness
        }

        // Fall back to debug_traceTransaction (Geth-compatible)
        return try await fetchDebugTraceTransaction(txHash: txHash)
    }

    /// Fetch witnesses for multiple transactions in parallel.
    ///
    /// - Parameters:
    ///   - txHashes: Array of transaction hashes
    /// - Returns: Dictionary mapping tx hash to witness data
    public func fetchWitnesses(txHashes: [String]) async throws -> [String: ArchiveNodeWitness] {
        try await withThrowingTaskGroup(of: (String, ArchiveNodeWitness?).self) { group in
            for txHash in txHashes {
                group.addTask {
                    let witness = try await self.fetchWitness(txHash: txHash)
                    return (txHash, witness)
                }
            }

            var results: [String: ArchiveNodeWitness] = [:]
            for try await (txHash, witness) in group {
                if let witness = witness {
                    results[txHash] = witness
                }
            }
            return results
        }
    }

    /// Check if archive node is available and supports tracing.
    ///
    /// - Returns: true if node is available
    public func checkAvailability() async -> Bool {
        guard let url = URL(string: config.url) else { return false }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10

        let body: [String: Any] = [
            "jsonrpc": "2.0",
            "method": "trace_block",
            "params": ["0x0"],
            "id": 1
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            let (_, response) = try await URLSession.shared.data(for: request)
            return (response as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }

    // MARK: - Private API Methods

    /// Fetch using trace_transaction API (Erigon/Reth)
    private func fetchTraceTransaction(txHash: String) async throws -> ArchiveNodeWitness {
        let method = "trace_transaction"
        let params = [normalizeHash(txHash)]

        return try await rpcCall(method: method, params: params)
    }

    /// Fetch using debug_traceTransaction API (Geth-compatible)
    private func fetchDebugTraceTransaction(txHash: String) async throws -> ArchiveNodeWitness {
        let method = "debug_traceTransaction"
        let params: [Any] = [
            normalizeHash(txHash),
            [
                "tracer": "callTracer",
                "enableMemory": true,
                "enableStack": true,
                "enableReturnData": true
            ]
        ]

        return try await rpcCall(method: method, params: params)
    }

    /// Make generic RPC call to archive node.
    private func rpcCall(method: String, params: [Any]) async throws -> ArchiveNodeWitness {
        guard let url = URL(string: config.url) else {
            throw ArchiveNodeError.invalidURL(config.url)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = config.timeout

        let requestBody: [String: Any] = [
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: requestBody)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ArchiveNodeError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            throw ArchiveNodeError.httpError(httpResponse.statusCode)
        }

        return try parseResponse(data: data, method: method)
    }

    /// Parse RPC response into ArchiveNodeWitness.
    private func parseResponse(data: Data, method: String) throws -> ArchiveNodeWitness {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ArchiveNodeError.parseError("Invalid JSON")
        }

        if let error = json["error"] as? [String: Any] {
            let message = error["message"] as? String ?? "Unknown error"
            throw ArchiveNodeError.rpcError(message)
        }

        guard let result = json["result"] else {
            throw ArchiveNodeError.parseError("No result in response")
        }

        // Parse based on method and response type
        if let resultDict = result as? [String: Any] {
            return try parseTraceResult(resultDict)
        } else if let resultArray = result as? [[String: Any]] {
            // Multiple results - concatenate steps
            var allSteps: [GethTraceStep] = []
            for item in resultArray {
                if let steps = parseSteps(from: item) {
                    allSteps.append(contentsOf: steps)
                }
            }
            return ArchiveNodeWitness(steps: allSteps, rawJson: data)
        }

        throw ArchiveNodeError.parseError("Unexpected result format")
    }

    /// Parse trace result from Geth-compatible response.
    private func parseTraceResult(_ json: [String: Any]) throws -> ArchiveNodeWitness {
        // Handle different trace formats

        // 1. Parity-style trace (Erigon/Reth)
        if let calls = json["calls"] as? [[String: Any]] {
            let steps = parseParityTrace(calls: calls)
            return ArchiveNodeWitness(steps: steps, rawJson: Data())
        }

        // 2. Geth struct_logs style (debug_traceTransaction)
        if let logs = json["structLogs"] as? [[String: Any]] {
            let steps = parseGethStructLogs(logs)
            return ArchiveNodeWitness(steps: steps, rawJson: Data())
        }

        // 3. Raw step array
        if let steps = parseSteps(from: json) {
            return ArchiveNodeWitness(steps: steps, rawJson: Data())
        }

        // 4. Simple call tree
        let steps = parseCallTree(topLevel: json)
        return ArchiveNodeWitness(steps: steps, rawJson: Data())
    }

    /// Parse Parity-style trace calls.
    private func parseParityTrace(calls: [[String: Any]]) -> [GethTraceStep] {
        var steps: [GethTraceStep] = []
        parseCallRecursive(calls: calls, depth: 0, steps: &steps)
        return steps
    }

    /// Recursively parse call tree into flat steps.
    private func parseCallRecursive(calls: [[String: Any]], depth: Int, steps: inout [GethTraceStep]) {
        for call in calls {
            guard let opcode = call["action"] as? [String: Any],
                  let op = opcode["callType"] as? String ?? opcode["op"] as? String else {
                continue
            }

            let step = GethTraceStep(
                pc: (call["traceAddress"] as? [Int])?.last ?? 0,
                opcode: opcodeStringToByte(op),
                depth: depth,
                gas: parseHexGas(call["gas"] as? String),
                stack: parseStack(opcode["stack"] as? [String]),
                memory: parseMemory(opcode["memory"] as? [String]),
                storage: parseStorage(opcode["storage"] as? [String: String]),
                error: call["error"] as? String
            )
            steps.append(step)

            // Recurse into subcalls
            if let subcalls = call["calls"] as? [[String: Any]] {
                parseCallRecursive(calls: subcalls, depth: depth + 1, steps: &steps)
            }
        }
    }

    /// Parse Geth struct_logs format.
    private func parseGethStructLogs(_ logs: [[String: Any]]) -> [GethTraceStep] {
        return logs.enumerated().compactMap { index, log in
            guard let op = log["op"] as? String else { return nil }

            return GethTraceStep(
                pc: index,
                opcode: opcodeStringToByte(op),
                depth: log["depth"] as? Int ?? 0,
                gas: UInt64(log["gas"] as? Int ?? 0),
                stack: parseStack(log["stack"] as? [String]),
                memory: parseMemory(log["memory"] as? [String]),
                storage: parseStorage(log["storage"] as? [String: String]),
                error: log["error"] as? String
            )
        }
    }

    /// Parse simple call tree into flat steps.
    private func parseCallTree(topLevel: [String: Any]) -> [GethTraceStep] {
        var steps: [GethTraceStep] = []

        func traverse(_ node: [String: Any], depth: Int) {
            if let op = node["op"] as? String {
                let step = GethTraceStep(
                    pc: steps.count,
                    opcode: opcodeStringToByte(op),
                    depth: depth,
                    gas: parseHexGas(node["gas"] as? String),
                    stack: parseStack(node["stack"] as? [String]),
                    memory: parseMemory(node["memory"] as? [String]),
                    storage: parseStorage(node["storage"] as? [String: String]),
                    error: node["error"] as? String
                )
                steps.append(step)
            }

            if let calls = node["calls"] as? [[String: Any]] {
                for call in calls {
                    traverse(call, depth: depth + 1)
                }
            }
        }

        traverse(topLevel, depth: 0)
        return steps
    }

    /// Parse steps from JSON object.
    private func parseSteps(from json: [String: Any]) -> [GethTraceStep]? {
        guard let stepsArray = json["steps"] as? [[String: Any]] else {
            return nil
        }

        return stepsArray.enumerated().compactMap { index, step in
            guard let opcode = step["opcode"] as? String ?? step["op"] as? String else {
                return nil
            }

            return GethTraceStep(
                pc: step["pc"] as? Int ?? index,
                opcode: opcodeStringToByte(opcode),
                depth: step["depth"] as? Int ?? 0,
                gas: UInt64(step["gas"] as? Int ?? 0),
                stack: step["stack"] as? [String] ?? [],
                memory: step["memory"] as? [String] ?? [],
                storage: step["storage"] as? [String: String] ?? [:],
                error: step["error"] as? String
            )
        }
    }

    // MARK: - Helper Methods

    private func normalizeHash(_ hash: String) -> String {
        if hash.hasPrefix("0x") || hash.hasPrefix("0X") {
            return hash.lowercased()
        }
        return "0x" + hash.lowercased()
    }

    private func opcodeStringToByte(_ op: String) -> UInt8 {
        // Map common opcode names to bytes
        switch op.uppercased() {
        case "STOP": return 0x00
        case "ADD": return 0x01
        case "MUL": return 0x02
        case "SUB": return 0x03
        case "DIV": return 0x04
        case "SDIV": return 0x05
        case "MOD": return 0x06
        case "SMOD": return 0x07
        case "ADDMOD": return 0x08
        case "MULMOD": return 0x09
        case "EXP": return 0x0A
        case "SIGNEXTEND": return 0x0B
        case "LT": return 0x10
        case "GT": return 0x11
        case "SLT": return 0x12
        case "SGT": return 0x13
        case "EQ": return 0x14
        case "ISZERO": return 0x15
        case "AND": return 0x16
        case "OR": return 0x17
        case "XOR": return 0x18
        case "NOT": return 0x19
        case "BYTE": return 0x1A
        case "SHL": return 0x1B
        case "SHR": return 0x1C
        case "SAR": return 0x1D
        case "KECCAK256", "SHA3": return 0x20
        case "ADDRESS": return 0x30
        case "BALANCE": return 0x31
        case "ORIGIN": return 0x32
        case "CALLER": return 0x33
        case "CALLVALUE": return 0x34
        case "CALLDATALOAD": return 0x35
        case "CALLDATASIZE": return 0x36
        case "CALLDATACOPY": return 0x37
        case "CODESIZE": return 0x38
        case "CODECOPY": return 0x39
        case "GASPRICE": return 0x3A
        case "EXTCODESIZE": return 0x3B
        case "EXTCODECOPY": return 0x3C
        case "RETURNDATASIZE": return 0x3D
        case "RETURNDATACOPY": return 0x3E
        case "EXTCODEHASH": return 0x3F
        case "BLOCKHASH": return 0x40
        case "COINBASE": return 0x41
        case "TIMESTAMP": return 0x42
        case "NUMBER": return 0x43
        case "PREVRANDAO", "DIFFICULTY": return 0x44
        case "GASLIMIT": return 0x45
        case "CHAINID": return 0x46
        case "SELFBALANCE": return 0x47
        case "BASEFEE": return 0x48
        case "POP": return 0x50
        case "MLOAD": return 0x51
        case "MSTORE": return 0x52
        case "MSTORE8": return 0x53
        case "SLOAD": return 0x54
        case "SSTORE": return 0x55
        case "JUMP": return 0x56
        case "JUMPI": return 0x57
        case "JUMPDEST": return 0x5B
        case "PC": return 0x58
        case "MSIZE": return 0x59
        case "GAS": return 0x5A
        case "PUSH0": return 0x5F
        case "PUSH1": return 0x60
        case "PUSH2": return 0x61
        case "PUSH3": return 0x62
        case "PUSH4": return 0x63
        case "PUSH5": return 0x64
        case "PUSH6": return 0x65
        case "PUSH7": return 0x66
        case "PUSH8": return 0x67
        case "PUSH9": return 0x68
        case "PUSH10": return 0x69
        case "PUSH11": return 0x6A
        case "PUSH12": return 0x6B
        case "PUSH13": return 0x6C
        case "PUSH14": return 0x6D
        case "PUSH15": return 0x6E
        case "PUSH16": return 0x6F
        case "PUSH17": return 0x70
        case "PUSH18": return 0x71
        case "PUSH19": return 0x72
        case "PUSH20": return 0x73
        case "PUSH21": return 0x74
        case "PUSH22": return 0x75
        case "PUSH23": return 0x76
        case "PUSH24": return 0x77
        case "PUSH25": return 0x78
        case "PUSH26": return 0x79
        case "PUSH27": return 0x7A
        case "PUSH28": return 0x7B
        case "PUSH29": return 0x7C
        case "PUSH30": return 0x7D
        case "PUSH31": return 0x7E
        case "PUSH32": return 0x7F
        case "DUP1": return 0x80
        case "DUP2": return 0x81
        case "DUP3": return 0x82
        case "DUP4": return 0x83
        case "DUP5": return 0x84
        case "DUP6": return 0x85
        case "DUP7": return 0x86
        case "DUP8": return 0x87
        case "DUP9": return 0x88
        case "DUP10": return 0x89
        case "DUP11": return 0x8A
        case "DUP12": return 0x8B
        case "DUP13": return 0x8C
        case "DUP14": return 0x8D
        case "DUP15": return 0x8E
        case "DUP16": return 0x8F
        case "SWAP1": return 0x90
        case "SWAP2": return 0x91
        case "SWAP3": return 0x92
        case "SWAP4": return 0x93
        case "SWAP5": return 0x94
        case "SWAP6": return 0x95
        case "SWAP7": return 0x96
        case "SWAP8": return 0x97
        case "SWAP9": return 0x98
        case "SWAP10": return 0x99
        case "SWAP11": return 0x9A
        case "SWAP12": return 0x9B
        case "SWAP13": return 0x9C
        case "SWAP14": return 0x9D
        case "SWAP15": return 0x9E
        case "SWAP16": return 0x9F
        case "LOG0": return 0xA0
        case "LOG1": return 0xA1
        case "LOG2": return 0xA2
        case "LOG3": return 0xA3
        case "LOG4": return 0xA4
        case "CREATE": return 0xF0
        case "CALL": return 0xF1
        case "CALLCODE": return 0xF2
        case "RETURN": return 0xF3
        case "DELEGATECALL": return 0xF4
        case "CREATE2": return 0xF5
        case "STATICCALL": return 0xFA
        case "REVERT": return 0xFD
        case "SELFDESTRUCT": return 0xFF
        default:
            // Try parsing as hex number
            if let value = UInt8(op, radix: 16) {
                return value
            }
            return 0x00 // STOP as fallback
        }
    }

    private func parseHexGas(_ gas: String?) -> UInt64 {
        guard let gas = gas else { return 0 }
        return UInt64(gas.strippingPrefix("0x"), radix: 16) ?? 0
    }

    private func parseStack(_ stack: [String]?) -> [String] {
        return stack ?? []
    }

    private func parseMemory(_ memory: [String]?) -> [String] {
        return memory ?? []
    }

    private func parseStorage(_ storage: [String: String]?) -> [String: String] {
        return storage ?? [:]
    }
}

// MARK: - Data Structures

/// Raw witness data from archive node.
public struct ArchiveNodeWitness: Sendable {
    /// Individual trace steps from archive node
    public let steps: [GethTraceStep]

    /// Original raw JSON response (for debugging)
    public let rawJson: Data

    public init(steps: [GethTraceStep], rawJson: Data) {
        self.steps = steps
        self.rawJson = rawJson
    }

    /// Number of execution steps
    public var count: Int { steps.count }
}

/// A single step from Geth-compatible trace.
public struct GethTraceStep: Sendable {
    /// Program counter
    public let pc: Int

    /// Opcode byte value
    public let opcode: UInt8

    /// Call depth
    public let depth: Int

    /// Gas remaining
    public let gas: UInt64

    /// Stack contents (hex strings)
    public let stack: [String]

    /// Memory contents (hex strings)
    public let memory: [String]

    /// Storage changes (key-value pairs)
    public let storage: [String: String]

    /// Error message if any
    public let error: String?

    public init(
        pc: Int,
        opcode: UInt8,
        depth: Int,
        gas: UInt64,
        stack: [String],
        memory: [String],
        storage: [String: String],
        error: String?
    ) {
        self.pc = pc
        self.opcode = opcode
        self.depth = depth
        self.gas = gas
        self.stack = stack
        self.memory = memory
        self.storage = storage
        self.error = error
    }

    /// Check if this step has an error
    public var hasError: Bool {
        error != nil && !error!.isEmpty
    }
}

// MARK: - Errors

/// Errors during archive node witness fetching.
public enum ArchiveNodeError: Error, LocalizedError {
    case invalidURL(String)
    case networkError(String)
    case httpError(Int)
    case parseError(String)
    case rpcError(String)
    case witnessUnavailable(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url):
            return "Invalid archive node URL: \(url)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        case .httpError(let code):
            return "HTTP error: \(code)"
        case .parseError(let msg):
            return "Parse error: \(msg)"
        case .rpcError(let msg):
            return "RPC error: \(msg)"
        case .witnessUnavailable(let txHash):
            return "Witness unavailable for transaction: \(txHash)"
        }
    }
}

// MARK: - State Proof Integration

/// Extension for integrating state proof fetching with witness fetcher.
extension ArchiveNodeWitnessFetcher {

    /// Fetch and verify state proofs for an account.
    ///
    /// This method fetches Merkle Patricia Trie proofs via `eth_getProof` RPC,
    /// enabling verified state access for Zoltraak's EVM proof system.
    ///
    /// - Parameters:
    ///   - address: Ethereum address to fetch state for
    ///   - storageSlots: Storage slots to fetch proofs for (optional)
    ///   - blockNumber: Block number
    /// - Returns: Verified state from proofs
    /// - Throws: StateProofFetcherError if fetch or verification fails
    public func fetchStateProofs(
        address: M31Word,
        storageSlots: [M31Word] = [],
        blockNumber: UInt64
    ) async throws -> StateProofFetcher.VerifiedState {
        let fetcher = StateProofFetcher()
        let proof = try await fetcher.fetchProofs(
            address: address,
            storageSlots: storageSlots,
            blockNumber: blockNumber
        )

        let verifier = StateProofVerifier()
        return try verifier.verifyFullProof(proof)
    }
}

private extension String {
    func strippingPrefix(_ prefix: String) -> String {
        if hasPrefix(prefix) {
            return String(dropFirst(prefix.count))
        }
        return self
    }
}
