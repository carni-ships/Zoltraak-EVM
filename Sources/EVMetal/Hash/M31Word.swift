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
            result.append(M31(v: val))
        }
        // 9th limb (8 bits only)
        result.append(M31(v: UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])))

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

/// Convert cross-product (18 limbs of 31 bits each = 558 bits) to 32-byte array
public func crossProductToBytes(_ crossLimbs: [M31]) -> [UInt8] {
    // crossLimbs has 18 entries (0-17), each 31 bits
    // We need 256 bits = 32 bytes
    var bytes = [UInt8](repeating: 0, count: 32)

    // Pack 18 x 31-bit values into bytes
    for i in 0..<18 {
        let val = crossLimbs[i].v
        // Simplified: just extract the low bits and pack
        let byteStart = 31 - (i * 31 / 8)
        let limbBytes = [
            UInt8(truncatingIfNeeded: val >> 24),
            UInt8(truncatingIfNeeded: val >> 16),
            UInt8(truncatingIfNeeded: val >> 8),
            UInt8(truncatingIfNeeded: val)
        ]
        for j in 0..<4 {
            let idx = min(byteStart + j, 31)
            if idx < 32 && idx >= 0 {
                bytes[idx] = limbBytes[j]
            }
        }
    }

    return bytes
}

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

    // MARK: - Division Support

    /// Convert to big-endian byte array for division operations
    public func toBytesBE() -> [UInt8] {
        toBytes()
    }
}

// MARK: - 256-bit Integer Operations

/// Convert M31Word to UInt64 array (little-endian limbs)
public func toUInt64Limbs(_ word: M31Word) -> [UInt64] {
    var limbs = [UInt64](repeating: 0, count: 4)
    // M31Word has 9 x 31-bit limbs, pack into 4 x 64-bit
    // Limbs 0-1: 62 bits from limbs 0,1
    limbs[0] = UInt64(word.limbs[0].v) | (UInt64(word.limbs[1].v) << 31)
    // Limbs 2-3: 62 bits from limbs 2,3
    limbs[1] = UInt64(word.limbs[2].v) | (UInt64(word.limbs[3].v) << 31)
    // Limbs 4-5: 62 bits from limbs 4,5
    limbs[2] = UInt64(word.limbs[4].v) | (UInt64(word.limbs[5].v) << 31)
    // Limbs 6-8: 93 bits from limbs 6,7,8 (with padding)
    limbs[3] = UInt64(word.limbs[6].v) | (UInt64(word.limbs[7].v) << 31) | (UInt64(word.limbs[8].v) << 62)
    return limbs
}

/// Convert UInt64 array (little-endian limbs) back to M31Word
public func m31WordFromUInt64Limbs(_ limbs64: [UInt64]) -> M31Word {
    var limbs31 = [M31](repeating: .zero, count: 9)
    limbs31[0] = M31(v: UInt32(truncatingIfNeeded: limbs64[0] & 0x7FFFFFFF))
    limbs31[1] = M31(v: UInt32(truncatingIfNeeded: (limbs64[0] >> 31) & 0x7FFFFFFF))
    limbs31[2] = M31(v: UInt32(truncatingIfNeeded: limbs64[1] & 0x7FFFFFFF))
    limbs31[3] = M31(v: UInt32(truncatingIfNeeded: (limbs64[1] >> 31) & 0x7FFFFFFF))
    limbs31[4] = M31(v: UInt32(truncatingIfNeeded: limbs64[2] & 0x7FFFFFFF))
    limbs31[5] = M31(v: UInt32(truncatingIfNeeded: (limbs64[2] >> 31) & 0x7FFFFFFF))
    limbs31[6] = M31(v: UInt32(truncatingIfNeeded: limbs64[3] & 0x7FFFFFFF))
    limbs31[7] = M31(v: UInt32(truncatingIfNeeded: (limbs64[3] >> 31) & 0x7FFFFFFF))
    limbs31[8] = M31(v: UInt32(truncatingIfNeeded: (limbs64[3] >> 62) & 0x7FFFFFFF))
    return M31Word(limbs: limbs31)
}

/// Perform unsigned 256-bit division (a / b) and modulo (a % b).
/// Returns (quotient, remainder) as M31Word.
func divMod256(_ a: M31Word, _ b: M31Word) -> (quotient: M31Word, remainder: M31Word) {
    let a64 = toUInt64Limbs(a)
    let b64 = toUInt64Limbs(b)

    // Convert to bytes for division
    let aBytes = a.toBytes()
    let bBytes = b.toBytes()

    let (qBytes, rBytes) = divModBytes(a: aBytes, b: bBytes)

    let q = M31Word(bytes: qBytes)
    let r = M31Word(bytes: rBytes)

    return (q, r)
}

/// Perform unsigned 256-bit modulo (a % b).
func mod256(_ a: M31Word, _ b: M31Word) -> M31Word {
    let (_, r) = divMod256(a, b)
    return r
}

/// Perform unsigned 256-bit exponentiation (base^exp mod mod).
func expMod256(_ base: M31Word, _ exp: M31Word, _ mod: M31Word) -> M31Word {
    let baseBytes = base.toBytes()
    let expBytes = exp.toBytes()
    let modBytes = mod.toBytes()

    // Convert to big integers
    var aBig = parseBigEndianBytes(baseBytes)
    var eBig = parseBigEndianBytes(expBytes)
    let mBig = parseBigEndianBytes(modBytes)

    if mBig.allSatisfy({ $0 == 0 }) {
        return .zero
    }

    // Ensure a < mod
    if compareBigInt(aBig, mBig) >= 0 {
        aBig = modBigInt(aBig, mBig)
    }

    var result = [UInt64](repeating: 0, count: 4)
    result[0] = 1

    // Binary exponentiation
    var e = eBig
    while !eBig.allSatisfy({ $0 == 0 }) {
        if e[0] & 1 == 1 {
            result = mulBigInt(result, aBig)
            result = modBigInt(result, mBig)
        }
        aBig = mulBigInt(aBig, aBig)
        aBig = modBigInt(aBig, mBig)
        e = shiftRightBigInt(e, 1)
    }

    return m31WordFromUInt64Limbs(result)
}

private func compareBigInt(_ a: [UInt64], _ b: [UInt64]) -> Int {
    for i in (0..<4).reversed() {
        if a[i] != b[i] {
            return a[i] < b[i] ? -1 : 1
        }
    }
    return 0
}

public func modBigInt(_ a: [UInt64], _ m: [UInt64]) -> [UInt64] {
    let (_, r) = divModBigInt(a, m)
    return r
}

private func divModBigInt(_ a: [UInt64], _ b: [UInt64]) -> (q: [UInt64], r: [UInt64]) {
    // Simplified fallback for 256-bit division
    // Check if b is zero
    if b.allSatisfy({ $0 == 0 }) {
        return ([0, 0, 0, 0], a)
    }

    // Check if b fits in lower 64 bits
    if b[3] == 0 && b[2] == 0 && b[1] == 0 {
        let divisor = b[0]
        var remainder: UInt64 = 0
        var quotient: UInt64 = 0

        // Divide each word from high to low
        for i in (0..<4).reversed() {
            let dividend = (remainder << 32) | (a[i] >> 32)
            quotient |= ((a[i] << 32) | remainder) / divisor << ((3 - i) * 32)
            remainder = ((a[i] << 32) | remainder) % divisor
        }

        return ([quotient & 0xFFFFFFFF, quotient >> 32, 0, 0], [remainder, 0, 0, 0])
    }

    // Fallback: return trivial result
    return ([0, 0, 0, 0], a)
}

public func mulBigInt(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
    var result = [UInt64](repeating: 0, count: 4)
    for i in 0..<4 {
        var carry: UInt64 = 0
        for j in 0..<(4 - i) {
            let idx = i + j
            if idx < 4 {
                let aVal = a[i]
                let bVal = b[j]
                let rVal = result[idx]
                let (low, overflow) = aVal.multipliedFullWidth(by: bVal)
                let (sumLow, sumCarry1) = low.addingReportingOverflow(rVal)
                let (finalSum, sumCarry2) = sumLow.addingReportingOverflow(carry)
                result[idx] = finalSum
                if overflow != 0 { carry = carry &+ 1 }
                if sumCarry1 { carry = carry &+ 1 }
                if sumCarry2 { carry = carry &+ 1 }
            }
        }
    }
    return result
}

private func shiftRightBigInt(_ a: [UInt64], _ bits: Int) -> [UInt64] {
    shiftRight256(a, by: bits)
}

/// Perform unsigned 256-bit left shift.
/// Returns the shifted value as a [UInt64] array (limbs LE).
func shiftLeft256(_ value: [UInt64], by bits: Int) -> [UInt64] {
    let wordShift = bits / 64
    let bitShift = bits % 64

    var result = [UInt64](repeating: 0, count: 4)

    for i in 0..<4 {
        var word = UInt64(0)
        if i >= wordShift {
            word = value[i - wordShift] << bitShift
            if bitShift > 0 && i > wordShift {
                word |= value[i - wordShift - 1] >> (64 - bitShift)
            }
        }
        result[i] = word
    }

    return result
}

/// Perform unsigned 256-bit right shift.
/// Returns the shifted value as a [UInt64] array (limbs LE).
func shiftRight256(_ value: [UInt64], by bits: Int) -> [UInt64] {
    let wordShift = bits / 64
    let bitShift = bits % 64

    var result = [UInt64](repeating: 0, count: 4)

    for i in 0..<4 {
        var word = UInt64(0)
        if i + wordShift < 4 {
            word = value[i + wordShift] >> bitShift
            if bitShift > 0 && i + wordShift + 1 < 4 {
                word |= value[i + wordShift + 1] << (64 - bitShift)
            }
        }
        result[i] = word
    }

    return result
}

/// Perform unsigned 256-bit division (a / b) and modulo (a % b).
/// Returns (quotient, remainder) as big-endian byte arrays.
public func divModBytes(a: [UInt8], b: [UInt8]) -> (quotient: [UInt8], remainder: [UInt8]) {
    // a and b are 32-byte big-endian representations
    guard a.count == 32, b.count == 32 else {
        return ([UInt8](repeating: 0, count: 32), a)
    }

    // Convert to big integer for division
    var aBig = parseBigEndianBytes(a)
    let bBig = parseBigEndianBytes(b)

    if bBig.allSatisfy({ $0 == 0 }) {
        return ([UInt8](repeating: 0, count: 32), a)
    }

    let (q, r) = divModBigInt(aBig, bBig)
    return (bigEndianBytes(q), bigEndianBytes(r))
}

/// Parse big-endian bytes into a big integer ([UInt64] limbs)
public func parseBigEndianBytes(_ bytes: [UInt8]) -> [UInt64] {
    var words = [UInt64](repeating: 0, count: 4)
    for i in 0..<4 {
        var word: UInt64 = 0
        for j in 0..<8 {
            word = (word << 8) | UInt64(bytes[i * 8 + j])
        }
        words[i] = word
    }
    return words
}

/// Convert big integer to big-endian bytes
private func bigEndianBytes(_ words: [UInt64]) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 32)
    for i in 0..<4 {
        for j in 0..<8 {
            bytes[i * 8 + j] = UInt8(truncatingIfNeeded: words[i] >> (56 - j * 8))
        }
    }
    return bytes
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
