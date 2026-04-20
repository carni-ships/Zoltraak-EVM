import Foundation
import zkMetal

/// Represents a 256-bit EVM word decomposed into M31 (31-bit Mersenne prime) limbs.
/// We need ⌈256/31⌉ = 9 limbs to represent a full EVM word.
///
/// EVM words use little-endian byte order for efficient stack operations.
/// Each M31 limb holds 31 bits, with the final limb holding the remaining bits.
public struct M31Word: Equatable, Sendable {
    /// Number of M31 limbs needed for a 256-bit word: ceil(256/31) = 9
    public static let limbCount = 9

    /// The 31-bit limbs in little-endian order (limb[0] is the least significant)
    public let limbs: [M31]

    /// Maximum value for each limb (2^31 - 1 for full limbs)
    public static let maxLimbValue: UInt64 = 0x7FFFFFFF

    /// Mask for extracting 31 bits from a 64-bit value
    public static let limbMask: UInt64 = 0x7FFFFFFF

    // MARK: - Initialization

    /// Create from an array of 9 M31 limbs
    public init(limbs: [M31]) {
        precondition(limbs.count == M31Word.limbCount, "M31Word requires exactly \(M31Word.limbCount) limbs")
        self.limbs = limbs
    }

    /// Create from a 64-bit unsigned integer (lower 64 bits)
    public init(low64: UInt64) {
        var result = [M31](repeating: .zero, count: M31Word.limbCount)
        result[0] = M31(v: UInt32(truncatingIfNeeded: low64))
        result[1] = M31(v: UInt32(truncatingIfNeeded: low64 >> 32))
        self.limbs = result
    }

    /// Create from a big-endian byte array (32 bytes)
    public init(bytes: [UInt8]) {
        precondition(bytes.count == 32, "M31Word requires exactly 32 bytes")
        var result = [M31]()
        result.reserveCapacity(9)

        for i in 0..<8 {
            let val = UInt32(bytes[28 - 4*i]) << 24 |
                      UInt32(bytes[29 - 4*i]) << 16 |
                      UInt32(bytes[30 - 4*i]) << 8 |
                      UInt32(bytes[31 - 4*i])
            result.append(M31(reduced: val))
        }
        // 9th limb (8 bits only)
        result.append(M31(reduced: UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])))

        self.limbs = result
    }

    /// Zero word
    public static let zero = M31Word(limbs: [M31](repeating: .zero, count: limbCount))

    /// One word
    public static let one: M31Word = {
        var limbs = [M31](repeating: .zero, count: limbCount)
        limbs[0] = M31.one
        return M31Word(limbs: limbs)
    }()

    /// Extract low 64 bits as UInt64
    public var low64: UInt64 {
        let lo = UInt64(limbs[0].v)
        let hi = UInt64(limbs.count > 1 ? limbs[1].v : 0)
        return lo | (hi << 32)
    }

    // MARK: - Arithmetic

    /// Addition of two M31Words with carry propagation.
    /// Returns (result, overflow_bit)
    public func add(_ other: M31Word) -> (result: M31Word, overflow: M31) {
        var resultLimbs = [M31]()
        var carry: UInt64 = 0

        for i in 0..<M31Word.limbCount {
            let sum = UInt64(limbs[i].v) + UInt64(other.limbs[i].v) + carry
            resultLimbs.append(M31(v: UInt32(truncatingIfNeeded: sum & M31Word.limbMask)))
            carry = sum >> 31
        }

        return (M31Word(limbs: resultLimbs), M31(v: UInt32(truncatingIfNeeded: carry)))
    }

    /// Subtraction of two M31Words with borrow propagation.
    /// Returns (result, borrow_bit)
    public func sub(_ other: M31Word) -> (result: M31Word, borrow: M31) {
        var resultLimbs = [M31]()
        var borrow: UInt64 = 0

        for i in 0..<M31Word.limbCount {
            let diff = Int64(UInt64(limbs[i].v)) - Int64(UInt64(other.limbs[i].v)) - Int64(borrow)
            if diff >= 0 {
                resultLimbs.append(M31(v: UInt32(truncatingIfNeeded: diff)))
                borrow = 0
            } else {
                resultLimbs.append(M31(v: UInt32(truncatingIfNeeded: diff + Int64(0x7FFFFFFF) + 1)))
                borrow = 1
            }
        }

        return (M31Word(limbs: resultLimbs), M31(v: UInt32(borrow)))
    }

    /// Multiplication: O(n^2) schoolbook multiplication returning cross-terms.
    public func multiplyFull(_ other: M31Word) -> [M31] {
        var result = [UInt64](repeating: 0, count: 2 * M31Word.limbCount)

        for i in 0..<M31Word.limbCount {
            for j in 0..<M31Word.limbCount {
                let iJ = i + j
                if iJ < result.count {
                    result[iJ] &+= UInt64(limbs[i].v) * UInt64(other.limbs[j].v)
                }
            }
        }

        // Reduce to M31 limbs
        var reduced = [M31]()
        var carry: UInt64 = 0

        for i in 0..<result.count {
            let sum = result[i] &+ carry
            reduced.append(M31(v: UInt32(truncatingIfNeeded: sum & M31Word.limbMask)))
            carry = sum >> 31
        }

        return reduced
    }

    // MARK: - Comparison

    /// Check if equal to zero
    public var isZero: Bool {
        limbs.allSatisfy { $0.v == 0 }
    }

    /// Check if equal to another word
    public func equals(_ other: M31Word) -> Bool {
        limbs == other.limbs
    }

    // MARK: - Bit Operations

    /// Get the low 32 bits as a UInt32
    public var low32: UInt32 {
        limbs[0].v
    }

    /// Get the high 32 bits of the low 128 bits
    public var high32OfLow128: UInt32 {
        limbs.count > 1 ? limbs[1].v : 0
    }

    // MARK: - Conversion

    /// Convert to big-endian byte array (32 bytes)
    public func toBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<8 {
            let limbVal = UInt64(limbs[i].v)
            bytes[31 - 4*i] = UInt8(truncatingIfNeeded: limbVal >> 24)
            bytes[30 - 4*i] = UInt8(truncatingIfNeeded: limbVal >> 16)
            bytes[29 - 4*i] = UInt8(truncatingIfNeeded: limbVal >> 8)
            bytes[28 - 4*i] = UInt8(truncatingIfNeeded: limbVal)
        }
        // 9th limb
        let limb8Val = UInt64(limbs[8].v)
        bytes[0] = UInt8(truncatingIfNeeded: limb8Val >> 24)
        bytes[1] = UInt8(truncatingIfNeeded: limb8Val >> 16)
        bytes[2] = UInt8(truncatingIfNeeded: limb8Val >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: limb8Val)
        return bytes
    }

    /// Convert to a hex string
    public func toHexString() -> String {
        let bytes = toBytes()
        return "0x" + bytes.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - M31 Word Array for Memory

/// A contiguous region of M31Words representing EVM memory or code
public struct M31WordArray: Equatable, Sendable {
    public let words: [M31Word]

    public var count: Int { words.count }

    public init(words: [M31Word]) {
        self.words = words
    }

    public init(zeros count: Int) {
        self.words = [M31Word](repeating: .zero, count: count)
    }

    public subscript(index: Int) -> M31Word {
        words[index]
    }
}

// MARK: - Carry Lookup Tables for Lasso

/// Precomputed carry chains for 31-bit addition.
/// These are used with the Lasso lookup argument.
public struct CarryLookupTables {
    public static let tableSize = 64  // 6-bit lookup

    /// Carry table: given (a_i, b_i, carry_in), what's carry_out?
    public static func generateCarryTable() -> [M31] {
        var table = [M31](repeating: .zero, count: tableSize)
        for i in 0..<tableSize {
            table[i] = M31(v: UInt32(i > 30 ? 1 : 0))
        }
        return table
    }

    /// Identity subtable for byte extraction: f(x) = x
    public static func generateIdentityTable(size: Int = 256) -> [M31] {
        (0..<size).map { M31(v: UInt32($0)) }
    }

    /// XOR subtable: f(a, b) = a XOR b (as 32-bit values)
    public static func generateXORTable() -> [M31] {
        var table = [M31]()
        for a in 0..<256 {
            for b in 0..<256 {
                table.append(M31(v: UInt32(a ^ b)))
            }
        }
        return table
    }
}
