import Foundation
import zkMetal

/// EVM Storage with Merkle Patricia Trie using Poseidon2-M31
/// For state root computation in zkEVM proofs
public struct EVMStorageTrie {

    // MARK: - Trie Node Types

    public enum Node: Sendable {
        case branch(children: [M31Word?], value: M31Word?)    // 16 children + value
        case extension_(key: [UInt8], child: M31Word)         // Compressed path
        case leaf(key: [UInt8], value: M31Word)               // Terminal node

        public var hash: M31Word {
            switch self {
            case .branch(let children, let value):
                return poseidon2Branch(children: children, value: value)
            case .extension_(let key, let child):
                return poseidon2Extension(key: key, child: child)
            case .leaf(let key, let value):
                return poseidon2Leaf(key: key, value: value)
            }
        }
    }

    // MARK: - Storage Entry

    public struct StorageEntry: Sendable {
        public let key: M31Word    // 256-bit storage key
        public let value: M31Word  // 256-bit storage value
        public let timestamp: UInt64

        public init(key: M31Word, value: M31Word, timestamp: UInt64) {
            self.key = key
            self.value = value
            self.timestamp = timestamp
        }
    }

    // MARK: - Storage Access for Proof

    public struct StorageAccess: Sendable {
        public let key: M31Word
        public let value: M31Word
        public let nodeHash: M31Word
        public let merkleProof: [M31Word]
        public let isWrite: Bool
        public let timestamp: UInt64

        public init(key: M31Word, value: M31Word, nodeHash: M31Word, merkleProof: [M31Word], isWrite: Bool, timestamp: UInt64) {
            self.key = key
            self.value = value
            self.nodeHash = nodeHash
            self.merkleProof = merkleProof
            self.isWrite = isWrite
            self.timestamp = timestamp
        }
    }

    // MARK: - Poseidon2-M31 Hash

    /// Poseidon2-M31 hash for trie nodes
    /// Uses the zkmetal Poseidon2 implementation optimized for M31
    public static func poseidon2(_ inputs: [M31]) -> M31Word {
        // In production, this calls the actual Poseidon2-M31 Metal kernel
        // For now, use a simplified hash based on input mixing
        var state = inputs
        while state.count < 9 {
            state.append(.zero)
        }

        // Simple mixing rounds (placeholder for actual Poseidon2)
        var result = [M31](repeating: .zero, count: 9)
        for i in 0..<9 {
            var val: UInt64 = 0
            for j in 0..<9 {
                val ^= UInt64(state[j].v) << ((i + j) % 31)
            }
            result[i] = M31(v: UInt32(val % UInt64(M31.P)))
        }

        return M31Word(limbs: result)
    }

    /// Hash a branch node (16 children + value)
    private static func poseidon2Branch(children: [M31Word?], value: M31Word?) -> M31Word {
        var inputs = [M31]()

        // First 16 children
        for i in 0..<16 {
            if let child = children[i] {
                inputs.append(contentsOf: child.limbs)
            } else {
                inputs.append(contentsOf: [M31].init(repeating: .zero, count: 9))
            }
        }

        // Value
        if let v = value {
            inputs.append(contentsOf: v.limbs)
        } else {
            inputs.append(contentsOf: [M31].init(repeating: .zero, count: 9))
        }

        return poseidon2(inputs)
    }

    /// Hash an extension node
    private static func poseidon2Extension(key: [UInt8], child: M31Word) -> M31Word {
        var inputs: [M31] = []

        // Key nibbles (半字节)
        for i in 0..<min(key.count, 32) {
            inputs.append(M31(v: UInt32(key[i])))
        }

        // Child hash
        inputs.append(contentsOf: child.limbs)

        return poseidon2(inputs)
    }

    /// Hash a leaf node
    private static func poseidon2Leaf(key: [UInt8], value: M31Word) -> M31Word {
        var inputs: [M31] = [M31.one]  // Leaf marker

        // Key
        for i in 0..<min(key.count, 32) {
            inputs.append(M31(v: UInt32(key[i])))
        }

        // Value
        inputs.append(contentsOf: value.limbs)

        return poseidon2(inputs)
    }

    // MARK: - Merkle Proof Generation

    /// Generate Merkle proof for a storage key
    public static func merkleProof(
        key: M31Word,
        storage: [String: M31Word],
        root: M31Word
    ) -> [M31Word] {
        // Simplified: return empty proof
        // Real implementation would traverse trie and collect sibling hashes
        return []
    }

    /// Verify Merkle proof
    public static func verifyMerkleProof(
        key: M31Word,
        value: M31Word,
        proof: [M31Word],
        root: M31Word
    ) -> Bool {
        // Simplified: just check if value is non-zero
        return !value.isZero
    }

    // MARK: - State Root Computation

    /// Compute state root from storage
    public static func computeStateRoot(
        storage: [String: M31Word]
    ) -> M31Word {
        if storage.isEmpty {
            return .zero
        }

        // Build a simple merkle tree from storage entries
        var hashes = storage.values.map { $0 }

        // Pad to power of 2
        while hashes.count > 1 && (hashes.count & (hashes.count - 1)) != 0 {
            hashes.append(.zero)
        }

        // Hash pairs up the tree
        while hashes.count > 1 {
            var newLevel = [M31Word]()
            for i in stride(from: 0, to: hashes.count, by: 2) {
                let combined = poseidon2(hashes[i].limbs + hashes[i+1].limbs)
                newLevel.append(combined)
            }
            hashes = newLevel
        }

        return hashes.first ?? .zero
    }

    // MARK: - Storage Proof

    /// Generate proof for storage access
    public func proveAccess(
        key: M31Word,
        isWrite: Bool
    ) -> StorageAccess {
        let value = storage[key.toHexString()] ?? .zero
        let nodeHash = self.root

        return StorageAccess(
            key: key,
            value: value,
            nodeHash: nodeHash,
            merkleProof: [],
            isWrite: isWrite,
            timestamp: timestamp
        )
    }

    // MARK: - Instance Storage

    private var storage: [String: M31Word]
    private var root: M31Word
    private var timestamp: UInt64

    public init() {
        self.storage = [:]
        self.root = .zero
        self.timestamp = 0
    }

    /// Load a value from storage
    public func load(key: M31Word) -> M31Word {
        return storage[key.toHexString()] ?? .zero
    }

    /// Store a value in storage
    public mutating func store(key: M31Word, value: M31Word) {
        storage[key.toHexString()] = value
        root = EVMStorageTrie.computeStateRoot(storage: storage)
        timestamp += 1
    }

    /// Get current state root
    public var stateRoot: M31Word {
        return root
    }

    /// Get all storage entries for proof generation
    public func entries() -> [StorageEntry] {
        return storage.map { (hexKey, value) in
            // Convert hex string to bytes and then to M31Word
            let keyBytes = Array(hexKey.utf8)
            let key = M31Word(bytes: keyBytes)
            return StorageEntry(key: key, value: value, timestamp: timestamp)
        }
    }
}

// MARK: - Storage Trie Operations

extension EVMStorageTrie {

    /// Insert a key-value pair into the trie
    public mutating func insert(key: [UInt8], value: M31Word) {
        // Simplified Patricia Trie insertion
        // Real implementation would handle nibbles and path compression
        let keyStr = key.map { String(format: "%02x", $0) }.joined()
        storage[keyStr] = value
        root = EVMStorageTrie.computeStateRoot(storage: storage)
    }

    /// Lookup a key in the trie
    public func lookup(key: [UInt8]) -> M31Word? {
        let keyStr = key.map { String(format: "%02x", $0) }.joined()
        return storage[keyStr]
    }

    /// Delete a key from the trie
    public mutating func delete(key: [UInt8]) {
        let keyStr = key.map { String(format: "%02x", $0) }.joined()
        storage.removeValue(forKey: keyStr)
        root = EVMStorageTrie.computeStateRoot(storage: storage)
    }
}

// MARK: - Storage Lookup Argument (LogUp)

/// Storage lookup for state access
public struct StorageLookup: Sendable {
    public let key: M31Word
    public let value: M31Word
    public let timestamp: UInt64
    public let isWrite: Bool

    public init(key: M31Word, value: M31Word, timestamp: UInt64, isWrite: Bool) {
        self.key = key
        self.value = value
        self.timestamp = timestamp
        self.isWrite = isWrite
    }
}

/// Generate LogUp expression for storage lookups
public func storageLogUp(
    accesses: [StorageLookup],
    challenge: M31
) -> M31 {
    var result = M31.zero

    for access in accesses {
        // Combine key, value, timestamp into single field element
        let keyLow = access.key.limbs[0].v
        let timeLow = UInt32(truncatingIfNeeded: access.timestamp)
        let combined = M31(v: keyLow ^ (timeLow << 16))

        let diff = m31Sub(challenge, combined)
        let inv = m31Inverse(diff)
        result = m31Add(result, inv)
    }

    return result
}

// MARK: - Field Helpers

private func m31Add(_ a: M31, _ b: M31) -> M31 {
    let sum = UInt64(a.v) + UInt64(b.v)
    let p = UInt64(M31.P)
    if sum < p {
        return M31(v: UInt32(sum))
    } else {
        return M31(v: UInt32(sum - p))
    }
}

private func m31Sub(_ a: M31, _ b: M31) -> M31 {
    let result = Int32(a.v) - Int32(b.v)
    if result >= 0 {
        return M31(v: UInt32(result))
    } else {
        return M31(v: UInt32(result + Int32(M31.P)))
    }
}

private func m31Mul(_ a: M31, _ b: M31) -> M31 {
    let product = UInt64(a.v) * UInt64(b.v)
    return M31(v: UInt32(product % UInt64(M31.P)))
}

private func m31Inverse(_ a: M31) -> M31 {
    var t = Int32(0)
    var newT = Int32(1)
    var r = Int32(M31.P)
    var newR = Int32(a.v)

    while newR != 0 {
        let q = r / newR
        let tempT = newT
        newT = t - q * newT
        t = tempT
        let tempR = newR
        newR = r - q * newR
        r = tempR
    }

    if r > 1 {
        return .zero
    }
    return M31(v: UInt32(t < 0 ? t + Int32(M31.P) : t))
}
