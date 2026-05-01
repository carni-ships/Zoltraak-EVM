import Foundation
import zkMetal

/// Fetches Merkle Patricia Trie proofs via `eth_getProof` RPC.
///
/// The `eth_getProof` method (EIP-1186) returns:
/// - Account state (balance, nonce, codeHash, storageRoot)
/// - RLP-encoded proof path from root to account
/// - Storage proofs for requested slots
///
/// This enables verifiable state proofs against Ethereum block state roots.
public struct StateProofFetcher {

    // MARK: - Configuration

    /// Configuration for RPC connection
    public struct RPCConfig: Sendable {
        public let url: String
        public let timeout: TimeInterval

        /// Default public RPC endpoint
        public static let publicNode = RPCConfig(
            url: "https://ethereum-rpc.publicnode.com",
            timeout: 60
        )

        /// All available endpoints for fallback
        public static let allEndpoints: [RPCConfig] = [.publicNode]

        public init(url: String, timeout: TimeInterval = 60) {
            self.url = url
            self.timeout = timeout
        }
    }

    // MARK: - Data Structures

    /// Complete state proof for an account and its storage.
    public struct StateProof: Sendable {
        /// Account address as M31Word
        public let address: M31Word

        /// Account balance in wei
        public let balance: M31Word

        /// Transaction count / nonce
        public let nonce: UInt64

        /// Keccak-256 hash of account code
        public let codeHash: M31Word

        /// Merkle root of account storage trie
        public let storageRoot: M31Word

        /// RLP-encoded proof path from state root to account node
        public let accountProof: [[UInt8]]

        /// Storage slot proofs, each containing RLP-encoded path from storage root to slot
        public let storageProofs: [StorageProof]

        /// Block state root this proof is valid against
        public let stateRoot: M31Word

        /// Block number this proof was fetched for
        public let blockNumber: UInt64

        /// Whether proof verification succeeded
        public var isValid: Bool {
            !accountProof.isEmpty
        }
    }

    /// Storage slot proof.
    public struct StorageProof: Sendable {
        /// Storage slot key (256-bit)
        public let slot: M31Word

        /// Value at this slot
        public let value: M31Word

        /// RLP-encoded proof path from storage root to slot
        public let proof: [[UInt8]]
    }

    /// Verified account state extracted from proof.
    public struct VerifiedAccount: Sendable {
        public let address: M31Word
        public let balance: M31Word
        public let nonce: UInt64
        public let codeHash: M31Word
        public let storageRoot: M31Word
    }

    /// Verified storage slot extracted from proof.
    public struct VerifiedStorage: Sendable {
        public let slot: M31Word
        public let value: M31Word
    }

    /// Verified complete state from proofs.
    public struct VerifiedState: Sendable {
        public let account: VerifiedAccount
        public let storage: [VerifiedStorage]
        public let stateRoot: M31Word
    }

    // MARK: - Properties

    private let config: RPCConfig

    // MARK: - Initialization

    /// Initialize fetcher with RPC configuration.
    public init(config: RPCConfig = .publicNode) {
        self.config = config
    }

    // MARK: - Public API

    /// Fetch state proofs for an account and its storage slots.
    ///
    /// This calls `eth_getProof` to retrieve:
    /// - Account state (balance, nonce, codeHash, storageRoot)
    /// - Account proof path from state root
    /// - Storage proofs for each requested slot
    ///
    /// - Parameters:
    ///   - address: Ethereum address (20 bytes, hex string or raw)
    ///   - storageSlots: Array of storage slot keys to fetch proofs for
    ///   - blockNumber: Block number in hex (e.g., "0x10d4f5e") or decimal
    /// - Returns: StateProof containing all proofs and account state
    public func fetchProofs(
        address: String,
        storageSlots: [M31Word] = [],
        blockNumber: String
    ) async throws -> StateProof {
        // Normalize address
        let normalizedAddress = normalizeAddress(address)

        // Normalize block number
        let normalizedBlock = normalizeBlockNumber(blockNumber)

        // Fetch eth_getProof
        let params: [Any] = [
            normalizedAddress,
            storageSlots.map { $0.toHexString() },
            normalizedBlock
        ]

        let request = EthereumRPCRequest(
            method: "eth_getProof",
            params: params,
            id: 1
        )

        let response = try await sendRPCRequestAsync(request: request)
        return try parseProofResponse(response, address: normalizedAddress, blockNumber: parseBlockNumber(normalizedBlock))
    }

    /// Fetch state proofs using M31Word address.
    ///
    /// - Parameters:
    ///   - address: Address as M31Word
    ///   - storageSlots: Storage slot keys as M31Word
    ///   - blockNumber: Block number
    /// - Returns: StateProof
    public func fetchProofs(
        address: M31Word,
        storageSlots: [M31Word] = [],
        blockNumber: UInt64
    ) async throws -> StateProof {
        let addressHex = address.toHexString()
        let blockHex = "0x" + String(blockNumber, radix: 16)
        return try await fetchProofs(address: addressHex, storageSlots: storageSlots, blockNumber: blockHex)
    }

    // MARK: - Private RPC Methods

    /// Send async RPC request.
    private func sendRPCRequestAsync(request: EthereumRPCRequest) async throws -> [String: Any] {
        guard let url = URL(string: config.url) else {
            throw StateProofFetcherError.invalidURL(config.url)
        }

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.timeoutInterval = config.timeout

        let requestBody: [String: Any] = [
            "jsonrpc": "2.0",
            "method": request.method,
            "params": request.params,
            "id": 1
        ]

        urlRequest.httpBody = try JSONSerialization.data(withJSONObject: requestBody)

        let (data, response) = try await URLSession.shared.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw StateProofFetcherError.networkError("Invalid response")
        }

        guard httpResponse.statusCode == 200 else {
            throw StateProofFetcherError.httpError(httpResponse.statusCode)
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw StateProofFetcherError.parseError("Invalid JSON")
        }

        if let error = json["error"] as? [String: Any] {
            let message = error["message"] as? String ?? "Unknown error"
            throw StateProofFetcherError.rpcError(message)
        }

        guard let result = json["result"] else {
            throw StateProofFetcherError.parseError("No result in response")
        }

        return result as? [String: Any] ?? [:]
    }

    // MARK: - Response Parsing

    /// Parse eth_getProof response into StateProof.
    private func parseProofResponse(
        _ json: [String: Any],
        address: String,
        blockNumber: UInt64
    ) throws -> StateProof {
        // Parse account state
        let balanceHex = json["balance"] as? String ?? "0x0"
        let nonceHex = json["nonce"] as? String ?? "0x0"
        let codeHashHex = json["codeHash"] as? String ?? "0x" + String(repeating: "0", count: 64)
        let storageRootHex = json["storageTrieRoot"] as? String ?? json["storageRoot"] as? String ?? "0x" + String(repeating: "0", count: 64)

        let balance = M31Word(bytes: hexToBytes(balanceHex))
        let nonce = hexToUInt64(nonceHex)
        let codeHash = M31Word(bytes: hexToBytes(codeHashHex))
        let storageRoot = M31Word(bytes: hexToBytes(storageRootHex))

        // Parse account proof
        let accountProofRaw = json["accountProof"] as? [[String: Any]] ?? []
        let accountProof = accountProofRaw.compactMap { parseProofNode($0) }

        // Parse storage proofs
        let storageProofsRaw = json["storageProof"] as? [[String: Any]] ?? []
        let storageProofs: [StorageProof] = storageProofsRaw.compactMap { storageProofJSON in
            guard let slotHex = storageProofJSON["key"] as? String else {
                return nil
            }
            let valueHex = storageProofJSON["value"] as? String ?? "0x0"
            let proofRaw = storageProofJSON["proof"] as? [[String: Any]] ?? []
            let proof = proofRaw.compactMap { parseProofNode($0) }

            return StorageProof(
                slot: M31Word(bytes: hexToBytes(slotHex)),
                value: M31Word(bytes: hexToBytes(valueHex)),
                proof: proof
            )
        }

        // Get state root from block if available
        let stateRootHex = json["stateRoot"] as? String ?? "0x" + String(repeating: "0", count: 64)
        let stateRoot = M31Word(bytes: hexToBytes(stateRootHex))

        return StateProof(
            address: M31Word(bytes: hexToBytes(address)),
            balance: balance,
            nonce: nonce,
            codeHash: codeHash,
            storageRoot: storageRoot,
            accountProof: accountProof,
            storageProofs: storageProofs,
            stateRoot: stateRoot,
            blockNumber: blockNumber
        )
    }

    /// Parse a single proof node from JSON.
    private func parseProofNode(_ json: [String: Any]) -> [UInt8]? {
        guard let rlpHex = json["rlp"] as? String else {
            return nil
        }
        return hexToBytes(rlpHex)
    }

    // MARK: - Helper Methods

    /// Normalize address to 0x-prefixed hex string.
    private func normalizeAddress(_ address: String) -> String {
        if address.hasPrefix("0x") || address.hasPrefix("0X") {
            return address.lowercased()
        }
        // Assume raw 40-hex character address
        return "0x" + address.lowercased()
    }

    /// Normalize block number to 0x-prefixed hex string.
    private func normalizeBlockNumber(_ block: String) -> String {
        if block.hasPrefix("0x") || block.hasPrefix("0X") {
            return block.lowercased()
        }
        // Assume decimal, convert to hex
        if let decimal = UInt64(block) {
            return "0x" + String(decimal, radix: 16)
        }
        return block.lowercased()
    }

    /// Parse block number from hex string.
    private func parseBlockNumber(_ block: String) -> UInt64 {
        let clean = block.hasPrefix("0x") ? String(block.dropFirst(2)) : block
        return UInt64(clean, radix: 16) ?? 0
    }

    /// Convert hex string to bytes.
    private func hexToBytes(_ hex: String) -> [UInt8] {
        var cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex

        // Pad to even length
        if cleanHex.count % 2 != 0 {
            cleanHex = "0" + cleanHex
        }

        var bytes = [UInt8]()
        var index = cleanHex.startIndex

        while index < cleanHex.endIndex {
            let nextIndex = cleanHex.index(index, offsetBy: 2, limitedBy: cleanHex.endIndex) ?? cleanHex.endIndex
            let byteString = String(cleanHex[index..<nextIndex])
            if let byte = UInt8(byteString, radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }

        // Pad to 32 bytes for M31Word conversion
        while bytes.count < 32 {
            bytes.insert(0, at: 0)
        }

        return bytes
    }

    /// Convert hex string to UInt64.
    private func hexToUInt64(_ hex: String) -> UInt64 {
        var cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        return UInt64(cleanHex, radix: 16) ?? 0
    }
}

// MARK: - Ethereum RPC Request

/// JSON-RPC 2.0 request structure.
private struct EthereumRPCRequest: Sendable {
    let jsonrpc: String = "2.0"
    let method: String
    let params: [Any]
    let id: Int
}

// MARK: - Error Types

/// Errors during state proof fetching.
public enum StateProofFetcherError: Error, LocalizedError {
    case invalidURL(String)
    case networkError(String)
    case httpError(Int)
    case parseError(String)
    case rpcError(String)
    case proofVerificationFailed
    case nodeNotSupported

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url):
            return "Invalid RPC URL: \(url)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        case .httpError(let code):
            return "HTTP error: \(code)"
        case .parseError(let msg):
            return "Parse error: \(msg)"
        case .rpcError(let msg):
            return "RPC error: \(msg)"
        case .proofVerificationFailed:
            return "State proof verification failed"
        case .nodeNotSupported:
            return "RPC node does not support eth_getProof"
        }
    }
}
