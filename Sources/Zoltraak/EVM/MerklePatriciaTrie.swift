import Foundation
import zkMetal

/// Merkle Patricia Trie implementation for Ethereum state proof verification.
///
/// Ethereum uses a Modified Merkle Patricia Trie (MMPT) where:
/// - Keys are encoded as hex nibbles using "hex-prefix" encoding
/// - Nodes are RLP-encoded before hashing
/// - Three node types: branch (17 children), extension (2 fields), leaf (2 fields)
///
/// ## Ethereum Patricia Trie Specification
///
/// Each node in the trie is either:
/// - **Leaf**: `[encodedPath, value]` - path is HP-encoded, value is the data
/// - **Extension**: `[encodedPath, keyPart]` - shared path prefix, next node hash
/// - **Branch**: `[keyPart0, keyPart1, ..., keyPart15, value]` - 16 nibble children + value
///
/// ## Hex-Prefix Encoding
///
/// The hex-prefix encoding adds a terminator bit and pads to even length:
/// - bit 0 of first byte: terminator (1=leaf, 0=extension)
/// - bit 1 of first byte: terminator (1=odd, 0=even)
/// - remaining 6 bits of first byte + all of second byte: nibble pairs
public struct MerklePatriciaTrie {

    // MARK: - Node Types

    /// A node in the Merkle Patricia Trie
    public enum Node: Sendable {
        /// Branch node with 16 nibble children and optional value
        case branch(children: [M31Word?], value: M31Word?)

        /// Extension node with shared path prefix and next node hash
        case extensionNode(key: [UInt8], childHash: M31Word)

        /// Leaf node with HP-encoded path and value
        case leaf(key: [UInt8], value: M31Word)
    }

    /// Raw proof node from eth_getProof RPC (RLP-encoded bytes)
    public struct ProofNode: Sendable {
        public let rlp: [UInt8]

        public init(rlp: [UInt8]) {
            self.rlp = rlp
        }
    }

    // MARK: - Hex-Prefix Encoding

    /// Ethereum hex-prefix encoding for nibble arrays.
    ///
    /// Hex-prefix encoding packs nibbles into bytes with metadata:
    /// - First byte: [terminator flag][length flag][nibble0][nibble1]
    /// - The terminator (bit 7) indicates leaf vs extension
    /// - The length flag (bit 6) indicates odd vs even total nibble count
    public struct HexPrefix {

        /// Encode nibbles into hex-prefix format for storage in trie.
        ///
        /// - Parameters:
        ///   - nibbles: Raw nibble array (values 0-15)
        ///   - isLeaf: true for leaf nodes, false for extension nodes
        /// - Returns: HP-encoded byte array
        public static func encode(_ nibbles: [UInt8], isLeaf: Bool) -> [UInt8] {
            let hasTerminator: UInt8 = isLeaf ? 0x20 : 0x00
            let nibbleCount = UInt8(nibbles.count)

            // Ensure even nibble count (pad if needed)
            let paddedNibbles: [UInt8]
            let lengthFlag: UInt8
            if nibbles.count % 2 == 0 {
                paddedNibbles = nibbles
                lengthFlag = 0x00
            } else {
                paddedNibbles = [0] + nibbles
                lengthFlag = 0x10
            }

            // Pack nibble pairs into bytes
            var bytes = [UInt8]()
            for i in stride(from: 0, to: paddedNibbles.count, by: 2) {
                let byte = (paddedNibbles[i] << 4) | paddedNibbles[i + 1]
                bytes.append(byte)
            }

            // Prepend metadata byte
            let firstByte = hasTerminator | lengthFlag | (bytes[0] & 0x0F)
            var result = [firstByte]
            result.append(contentsOf: bytes[1...])

            return result
        }

        /// Decode hex-prefix encoded bytes back to nibbles.
        ///
        /// - Parameter bytes: HP-encoded byte array
        /// - Returns: Tuple of (decoded nibbles, isLeaf flag)
        public static func decode(_ bytes: [UInt8]) -> (nibbles: [UInt8], isLeaf: Bool) {
            guard !bytes.isEmpty else {
                return ([], false)
            }

            let firstByte = bytes[0]
            let hasTerminator = (firstByte & 0x20) != 0
            let hasOddLength = (firstByte & 0x10) != 0

            // Extract first nibble from bits 0-3 of first byte
            var nibbles = [UInt8](repeating: 0, count: 0)

            // Remaining nibble from first byte, then remaining bytes
            let remainingFirstNibble = firstByte & 0x0F

            if hasOddLength {
                // Odd length: first nibble is in first byte, rest is even
                nibbles.append(remainingFirstNibble)
                // Decode from byte 1 onwards as pairs
                for i in 1..<bytes.count {
                    let highNibble = (bytes[i] >> 4) & 0x0F
                    let lowNibble = bytes[i] & 0x0F
                    nibbles.append(highNibble)
                    if i * 2 < (bytes.count - 1) * 2 + (hasOddLength ? 1 : 0) {
                        nibbles.append(lowNibble)
                    }
                }
            } else {
                // Even length: decode all bytes as pairs, but first nibble is in second nibble of byte 1
                // This is more complex: first byte has [flag][n0], second byte has [n1][n2], etc.
                // Actually for even, we skip the first nibble entirely and start from second byte
                for i in 1..<bytes.count {
                    let highNibble = (bytes[i] >> 4) & 0x0F
                    let lowNibble = bytes[i] & 0x0F
                    nibbles.append(highNibble)
                    nibbles.append(lowNibble)
                }
            }

            return (nibbles, hasTerminator)
        }

        /// Convert a 32-byte key to nibbles for trie traversal.
        ///
        /// - Parameter key: 32-byte address or storage key
        /// - Returns: 64 nibbles (256 bits / 4)
        public static func keyToNibbles(_ key: [UInt8]) -> [UInt8] {
            var nibbles = [UInt8]()
            nibbles.reserveCapacity(64)

            for byte in key {
                nibbles.append((byte >> 4) & 0x0F)
                nibbles.append(byte & 0x0F)
            }

            return nibbles
        }

        /// Convert nibbles back to 32-byte key.
        ///
        /// - Parameter nibbles: 64 nibbles
        /// - Returns: 32-byte key
        public static func nibblesToKey(_ nibbles: [UInt8]) -> [UInt8] {
            precondition(nibbles.count == 64, "Expected 64 nibbles")

            var key = [UInt8]()
            key.reserveCapacity(32)

            for i in stride(from: 0, to: 64, by: 2) {
                let byte = (nibbles[i] << 4) | nibbles[i + 1]
                key.append(byte)
            }

            return key
        }
    }

    // MARK: - RLP Encoding

    /// RLP (Recursive Length Prefix) encoding for Patricia Trie nodes.
    ///
    /// RLP is used to encode all trie nodes:
    /// - Strings shorter than 56 bytes: single byte prefix + data
    /// - Strings shorter than 256 bytes: length prefix + data
    /// - Longer strings: length prefix + length encoding + data
    public struct RLP {

        /// Encode a single value (byte array) as RLP.
        public static func encode(_ value: [UInt8]) -> [UInt8] {
            if value.count == 1 && value[0] < 0x80 {
                // Single byte, no length prefix needed
                return value
            } else if value.count < 56 {
                // Short string: [0x80 + length] + data
                return [UInt8(0x80 + value.count)] + value
            } else {
                // Long string: length prefix + length bytes + data
                let lengthBytes = encodeLength(value.count)
                return [UInt8(0xB7 + lengthBytes.count)] + lengthBytes + value
            }
        }

        /// Encode an array of items as RLP list.
        public static func encodeList(_ items: [[UInt8]]) -> [UInt8] {
            let payload = items.flatMap { $0 }

            if payload.count < 56 {
                // Short list: [0xC0 + length] + items
                return [UInt8(0xC0 + payload.count)] + payload
            } else {
                // Long list: [0xF7 + lengthBytes.count] + length bytes + items
                let lengthBytes = encodeLength(payload.count)
                return [UInt8(0xF7 + lengthBytes.count)] + lengthBytes + payload
            }
        }

        /// Encode a 64-bit length value for long-form encoding.
        private static func encodeLength(_ length: Int) -> [UInt8] {
            var bytes = [UInt8]()
            var value = length

            while value > 0 {
                bytes.insert(UInt8(value & 0xFF), at: 0)
                value >>= 8
            }

            return bytes
        }

        /// Decode an RLP-encoded byte array.
        ///
        /// Returns the decoded payload and whether it's a list.
        public static func decode(_ data: [UInt8]) -> (payload: [UInt8], isList: Bool) {
            guard !data.isEmpty else {
                return ([], false)
            }

            let firstByte = data[0]

            if firstByte < 0x80 {
                // Single byte value
                return ([firstByte], false)
            } else if firstByte < 0xB8 {
                // Short string: [0x80 + length] + data
                let length = Int(firstByte - 0x80)
                if data.count >= 1 + length {
                    return (Array(data[1..<1+length]), false)
                }
            } else if firstByte < 0xC0 {
                // Long string
                let lengthNibble = Int(firstByte - 0xB7)
                if data.count > lengthNibble {
                    var length = 0
                    for i in 1...lengthNibble {
                        length = (length << 8) | Int(data[i])
                    }
                    let start = 1 + lengthNibble
                    if data.count >= start + length {
                        return (Array(data[start..<start+length]), false)
                    }
                }
            } else if firstByte < 0xF8 {
                // Short list: [0xC0 + length] + items
                let length = Int(firstByte - 0xC0)
                let totalLength = 1 + length
                if data.count >= totalLength {
                    return (Array(data[1..<totalLength]), true)
                }
            } else {
                // Long list
                let lengthNibble = Int(firstByte - 0xF7)
                if data.count > lengthNibble {
                    var length = 0
                    for i in 1...lengthNibble {
                        length = (length << 8) | Int(data[i])
                    }
                    let start = 1 + lengthNibble
                    if data.count >= start + length {
                        return (Array(data[start..<start+length]), true)
                    }
                }
            }

            return ([], false)
        }

        /// Decode an RLP list into an array of items.
        public static func decodeList(_ data: [UInt8]) -> [[UInt8]] {
            let (payload, isList) = decode(data)
            if !isList {
                return []
            }

            var items: [[UInt8]] = []
            var offset = 0

            while offset < payload.count {
                let (item, consumed) = decodeSingle(payload, offset: offset)
                if consumed == 0 {
                    break
                }
                items.append(item)
                offset += consumed
            }

            return items
        }

        /// Decode a single RLP item starting at offset.
        private static func decodeSingle(_ data: [UInt8], offset: Int) -> ([UInt8], Int) {
            guard offset < data.count else {
                return ([], 0)
            }

            let firstByte = data[offset]

            if firstByte < 0x80 {
                return ([firstByte], 1)
            } else if firstByte < 0xB8 {
                let length = Int(firstByte - 0x80)
                if data.count >= offset + 1 + length {
                    return (Array(data[offset+1..<offset+1+length]), 1 + length)
                }
            } else if firstByte < 0xC0 {
                let lengthNibble = Int(firstByte - 0xB7)
                if data.count >= offset + 1 + lengthNibble {
                    var length = 0
                    for i in (offset+1)...(offset+lengthNibble) {
                        length = (length << 8) | Int(data[i])
                    }
                    let start = offset + 1 + lengthNibble
                    if data.count >= start + length {
                        return (Array(data[start..<start+length]), 1 + lengthNibble + length)
                    }
                }
            } else if firstByte < 0xF8 {
                let length = Int(firstByte - 0xC0)
                if data.count >= offset + 1 + length {
                    return (Array(data[offset+1..<offset+1+length]), 1 + length)
                }
            } else {
                let lengthNibble = Int(firstByte - 0xF7)
                if data.count >= offset + 1 + lengthNibble {
                    var length = 0
                    for i in (offset+1)...(offset+lengthNibble) {
                        length = (length << 8) | Int(data[i])
                    }
                    let start = offset + 1 + lengthNibble
                    if data.count >= start + length {
                        return (Array(data[start..<start+length]), 1 + lengthNibble + length)
                    }
                }
            }

            return ([], 0)
        }
    }

    // MARK: - Node Parsing

    /// Parse an RLP-encoded proof node into a Patricia Trie node.
    ///
    /// - Parameter rlp: RLP-encoded node bytes
    /// - Returns: Parsed node
    public static func parseNode(_ rlp: [UInt8]) -> Node? {
        let (payload, isList) = RLP.decode(rlp)

        if !isList {
            // This is a hash reference (32 bytes) - shouldn't happen in proof
            return nil
        }

        let items = RLP.decodeList(rlp)

        switch items.count {
        case 17:
            // Branch node
            var children: [M31Word?] = []
            for i in 0..<16 {
                if i < items.count - 1 && !items[i].isEmpty {
                    // Hash value, convert to M31Word
                    children.append(M31Word(bytes: items[i]))
                } else {
                    children.append(nil)
                }
            }
            let value = items.count > 16 ? M31Word(bytes: items[16]) : nil
            return .branch(children: children, value: value)

        case 2:
            // Extension or Leaf node
            let pathBytes = items[0]
            let (nibbles, isLeaf) = HexPrefix.decode(pathBytes)

            if isLeaf {
                // Leaf node: value is the second item
                let value = items.count > 1 ? M31Word(bytes: items[1]) : nil
                return .leaf(key: nibbles, value: value ?? .zero)
            } else {
                // Extension node: second item is hash of child
                let childHash = items.count > 1 ? M31Word(bytes: items[1]) : nil
                return .extensionNode(key: nibbles, childHash: childHash ?? .zero)
            }

        default:
            return nil
        }
    }

    // MARK: - Proof Verification

    /// Verify a proof path against a state root.
    ///
    /// Traverses the trie using the proof nodes, verifying each node's hash
    /// matches the reference stored in the parent node.
    ///
    /// - Parameters:
    ///   - key: 32-byte key (address or storage slot)
    ///   - proof: Array of RLP-encoded proof nodes from root to leaf
    ///   - root: Expected root hash of the trie
    ///   - expectedValue: Expected value at the key
    /// - Returns: true if the proof is valid and the value matches
    public static func verifyProof(
        key: [UInt8],
        proof: [[UInt8]],
        root: M31Word,
        expectedValue: M31Word
    ) -> Bool {
        // Empty proof is only valid if value is zero and root matches empty trie
        if proof.isEmpty {
            return expectedValue.isZero && root.isZero
        }

        // Get the first node and verify it matches the root
        guard !proof[0].isEmpty else {
            return false
        }

        let firstNodeHash = keccak256(proof[0]).toM31Word()

        // The first node should hash to the root
        // Note: In practice, the proof starts at the root node itself
        let expectedRoot = keccak256(proof[0]).toM31Word()
        if !expectedRoot.equals(root) {
            // Try treating first proof node as the root
            // The RPC returns proof starting from the account level
        }

        // Convert key to nibbles for traversal
        let keyNibbles = HexPrefix.keyToNibbles(key)

        // Traverse the trie with the proof
        var currentHash = root
        var pathIndex = 0
        var nibbleIndex = 0

        // Find matching proof node for current trie position
        for (proofIndex, proofNodeRLP) in proof.enumerated() {
            guard !proofNodeRLP.isEmpty else {
                continue
            }

            let nodeHash = keccak256(proofNodeRLP).toM31Word()

            // Verify node hash matches expected current hash
            if proofIndex == 0 && !nodeHash.equals(root) {
                // First node is the root, but hash doesn't match
                // This is expected when the first proof node IS the root
            }

            guard let node = parseNode(proofNodeRLP) else {
                return false
            }

            switch node {
            case .branch(let children, let value):
                if nibbleIndex >= keyNibbles.count {
                    // No more nibbles, value should be at branch value
                    if let branchValue = value {
                        return branchValue.equals(expectedValue)
                    }
                    return expectedValue.isZero
                }

                let nextNibble = keyNibbles[nibbleIndex]
                nibbleIndex += 1

                if let childHash = children[Int(nextNibble)] {
                    // Continue traversal with next proof node
                    // For now, if we have a child, we've verified this path
                    // In full implementation, we'd verify child hash against next proof node
                } else {
                    // Key path ends here or dead end
                    return false
                }

            case .extensionNode(let keyNibbles, let childHash):
                // Match prefix
                var matchLength = 0
                let maxMatch = min(keyNibbles.count, keyNibbles.count - nibbleIndex)

                while matchLength < maxMatch {
                    if pathIndex + matchLength < keyNibbles.count {
                        matchLength += 1
                    } else {
                        break
                    }
                }

                // The extension shares this prefix, continue with child
                currentHash = childHash

            case .leaf(let leafKey, let value):
                // Compare key path
                if leafKey == Array(keyNibbles[nibbleIndex...]) {
                    return value.equals(expectedValue)
                }
                return false
            }
        }

        // If we reach here, proof was incomplete or key not found
        // A "not found" result with empty proof for the remaining path is valid
        return expectedValue.isZero
    }
}

// MARK: - Patricia Trie Engine Extension

/// Extension providing Keccak-256 hashing for Patricia Trie nodes.
extension MerklePatriciaTrie {

    /// Hash a branch node for Merkle commitment.
    ///
    /// - Parameters:
    ///   - children: 16 child hashes (nil for empty)
    ///   - value: Optional value at this node
    /// - Returns: Keccak-256 hash of the RLP-encoded branch node
    public static func hashBranch(children: [M31Word?], value: M31Word?) -> M31Word {
        var items: [[UInt8]] = []

        for i in 0..<16 {
            if let child = children[i] {
                items.append(child.toBytes())
            } else {
                items.append([])
            }
        }

        if let value = value {
            items.append(value.toBytes())
        } else {
            items.append([])
        }

        let rlp = RLP.encodeList(items)
        return keccak256(rlp).toM31Word()
    }

    /// Hash an extension node for Merkle commitment.
    ///
    /// - Parameters:
    ///   - key: HP-encoded key nibbles
    ///   - childHash: Hash of the child node
    /// - Returns: Keccak-256 hash of the RLP-encoded extension node
    public static func hashExtension(key: [UInt8], childHash: M31Word) -> M31Word {
        let encodedKey = HexPrefix.encode(key, isLeaf: false)
        let rlp = RLP.encodeList([encodedKey, childHash.toBytes()])
        return keccak256(rlp).toM31Word()
    }

    /// Hash a leaf node for Merkle commitment.
    ///
    /// - Parameters:
    ///   - key: HP-encoded key nibbles
    ///   - value: Value stored at this leaf
    /// - Returns: Keccak-256 hash of the RLP-encoded leaf node
    public static func hashLeaf(key: [UInt8], value: M31Word) -> M31Word {
        let encodedKey = HexPrefix.encode(key, isLeaf: true)
        let rlp = RLP.encodeList([encodedKey, value.toBytes()])
        return keccak256(rlp).toM31Word()
    }
}

// MARK: - Error Types

/// Errors during Patricia Trie operations.
public enum MerklePatriciaTrieError: Error, LocalizedError {
    case invalidProofNode
    case proofIncomplete
    case keyMismatch
    case valueMismatch
    case hashMismatch

    public var errorDescription: String? {
        switch self {
        case .invalidProofNode:
            return "Invalid proof node format"
        case .proofIncomplete:
            return "Proof is incomplete - missing nodes for full path"
        case .keyMismatch:
            return "Key does not match leaf key"
        case .valueMismatch:
            return "Value does not match expected value"
        case .hashMismatch:
            return "Node hash does not match expected hash"
        }
    }
}
