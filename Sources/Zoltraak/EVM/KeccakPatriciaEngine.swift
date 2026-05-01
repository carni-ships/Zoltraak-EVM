import Foundation
import zkMetal

/// Engine for computing Keccak-256 hashes of Merkle Patricia Trie nodes.
///
/// This engine implements proper Patricia Trie node hashing:
/// - Branch nodes: RLP([child0, ..., child15, value]) → Keccak-256
/// - Extension nodes: RLP([hp_encoded_key, child_hash]) → Keccak-256
/// - Leaf nodes: RLP([hp_encoded_key, value]) → Keccak-256
///
/// The Keccak-256 hash of a trie node is used as the node's reference
/// in the parent node's children array.
public struct KeccakPatriciaEngine {

    // MARK: - Keccak-256 Wrapper

    /// Compute Keccak-256 hash of data.
    ///
    /// Uses zkMetal's keccak256 implementation.
    ///
    /// - Parameter data: Byte array to hash
    /// - Returns: 32-byte Keccak-256 hash
    public static func keccak256(_ data: [UInt8]) -> [UInt8] {
        return zkMetal.keccak256(data)
    }

    // MARK: - Node Hashing

    /// Hash a branch node for Merkle commitment.
    ///
    /// - Parameters:
    ///   - children: 16 child hashes (empty byte array for nil children)
    ///   - value: Optional value hash (empty if none)
    /// - Returns: Keccak-256 hash of RLP-encoded branch node
    public static func hashBranch(children: [[UInt8]], value: [UInt8] = []) -> [UInt8] {
        var items: [[UInt8]] = []

        for i in 0..<16 {
            if i < children.count {
                items.append(children[i])
            } else {
                items.append([])
            }
        }

        items.append(value)

        let rlp = MerklePatriciaTrie.RLP.encodeList(items)
        return keccak256(rlp)
    }

    /// Hash an extension node for Merkle commitment.
    ///
    /// - Parameters:
    ///   - key: HP-encoded key nibbles
    ///   - childHash: Hash of the child node
    /// - Returns: Keccak-256 hash of RLP-encoded extension node
    public static func hashExtension(key: [UInt8], childHash: [UInt8]) -> [UInt8] {
        let encodedKey = MerklePatriciaTrie.HexPrefix.encode(key, isLeaf: false)
        let rlp = MerklePatriciaTrie.RLP.encodeList([encodedKey, childHash])
        return keccak256(rlp)
    }

    /// Hash a leaf node for Merkle commitment.
    ///
    /// - Parameters:
    ///   - key: HP-encoded key nibbles
    ///   - value: Value stored at this leaf
    /// - Returns: Keccak-256 hash of RLP-encoded leaf node
    public static func hashLeaf(key: [UInt8], value: [UInt8]) -> [UInt8] {
        let encodedKey = MerklePatriciaTrie.HexPrefix.encode(key, isLeaf: true)
        let rlp = MerklePatriciaTrie.RLP.encodeList([encodedKey, value])
        return keccak256(rlp)
    }

    // MARK: - Empty Trie Hash

    /// Compute the hash of an empty trie.
    ///
    /// An empty trie is RLP of empty list.
    ///
    /// - Returns: Keccak-256(RLP([]))
    public static func emptyTrieHash() -> [UInt8] {
        let emptyRLP: [UInt8] = [0x80]  // RLP empty string
        return keccak256(emptyRLP)
    }

    // MARK: - Account State Hashing

    /// Hash account state for storage in Patricia Trie.
    ///
    /// Account state is stored as RLP of:
    /// [nonce, balance, storageRoot, codeHash]
    ///
    /// - Parameters:
    ///   - nonce: Transaction count
    ///   - balance: Account balance in wei
    ///   - storageRoot: Keccak-256 hash of account's storage trie root
    ///   - codeHash: Keccak-256 hash of account code (0x00...0 for EOA)
    /// - Returns: Hash of account state node
    public static func hashAccountState(
        nonce: UInt64,
        balance: M31Word,
        storageRoot: M31Word,
        codeHash: M31Word
    ) -> [UInt8] {
        // Encode each component
        let nonceBytes = encodeUInt64(nonce)
        let balanceBytes = balance.toBytes()
        let storageRootBytes = storageRoot.toBytes()
        let codeHashBytes = codeHash.toBytes()

        let rlp = MerklePatriciaTrie.RLP.encodeList([
            nonceBytes,
            balanceBytes,
            storageRootBytes,
            codeHashBytes
        ])

        return keccak256(rlp)
    }

    /// Encode UInt64 as RLP bytes.
    private static func encodeUInt64(_ value: UInt64) -> [UInt8] {
        if value == 0 {
            return []
        }

        var bytes = [UInt8]()
        var v = value

        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }

        return bytes
    }

    // MARK: - Storage Value Hashing

    /// Hash a storage value for Patricia Trie storage.
    ///
    /// Storage values in Ethereum tries are stored as raw 32-byte values,
    /// RLP-encoded if they're short enough.
    ///
    /// - Parameter value: 32-byte storage value
    /// - Returns: Hash of the storage value node
    public static func hashStorageValue(_ value: M31Word) -> [UInt8] {
        let valueBytes = value.toBytes()

        // If value fits in short RLP, encode it directly
        if valueBytes.count < 56 {
            let rlp = MerklePatriciaTrie.RLP.encode(valueBytes)
            return keccak256(rlp)
        }

        // Otherwise, use direct encoding
        return keccak256(valueBytes)
    }
}
