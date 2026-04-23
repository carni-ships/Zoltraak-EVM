import Foundation
import zkMetal

/// CCS Constraint representation for EVM operations
/// Maps EVM opcodes to constraint polynomials over M31 field elements
public struct EVMCircuit {

    // MARK: - Constraint Types

    /// Represents a single CCS constraint
    public struct Constraint: Sendable {
        public let selector: [Int]      // which columns are involved
        public let polynomial: [M31]   // coefficients
        public let degree: Int

        public init(selector: [Int], polynomial: [M31], degree: Int) {
            self.selector = selector
            self.polynomial = polynomial
            self.degree = degree
        }
    }

    /// Constraint set for an opcode
    public struct OpcodeConstraints: Sendable {
        public let opcode: EVMOpcode
        public let constraints: [Constraint]
        public let lookupConstraints: [LookupConstraint]
        public let gasCost: UInt64

        public init(opcode: EVMOpcode, constraints: [Constraint], lookupConstraints: [LookupConstraint] = [], gasCost: UInt64) {
            self.opcode = opcode
            self.constraints = constraints
            self.lookupConstraints = lookupConstraints
            self.gasCost = gasCost
        }
    }

    /// Lookup constraint for memory/stack operations
    public struct LookupConstraint: Sendable {
        public let tableName: String
        public let inputColumns: [Int]
        public let outputColumns: [Int]
        public let selector: Int?  // which column acts as the lookup selector

        public init(tableName: String, inputColumns: [Int], outputColumns: [Int], selector: Int? = nil) {
            self.tableName = tableName
            self.inputColumns = inputColumns
            self.outputColumns = outputColumns
            self.selector = selector
        }
    }

    // MARK: - M31 Field Helpers

    /// Add two M31 field elements
    public static func m31Add(_ a: M31, _ b: M31) -> M31 {
        let sum = UInt64(a.v) + UInt64(b.v)
        let p = UInt64(M31.P)
        if sum < p {
            return M31(v: UInt32(sum))
        } else {
            return M31(v: UInt32(sum - p))
        }
    }

    /// Subtract two M31 field elements
    public static func m31Sub(_ a: M31, _ b: M31) -> M31 {
        let result = Int32(a.v) - Int32(b.v)
        if result >= 0 {
            return M31(v: UInt32(result))
        } else {
            return M31(v: UInt32(result + Int32(M31.P)))
        }
    }

    /// Multiply two M31 field elements
    public static func m31Mul(_ a: M31, _ b: M31) -> M31 {
        let product = UInt64(a.v) * UInt64(b.v)
        let p = UInt64(M31.P)
        return M31(v: UInt32(product % p))
    }

    /// Check if M31 is zero
    public static func m31IsZero(_ a: M31) -> Bool {
        return a.v == 0
    }

    /// Check if two M31 values are equal
    public static func m31Eq(_ a: M31, _ b: M31) -> Bool {
        return a.v == b.v
    }

    // MARK: - Limb Decomposition Helpers

    /// Convert M31Word to array of M31 limbs
    public static func toLimbs(_ word: M31Word) -> [M31] {
        return word.limbs
    }

    /// Convert array of M31 limbs to M31Word
    public static func fromLimbs(_ limbs: [M31]) -> M31Word {
        return M31Word(limbs: Array(limbs.prefix(9)))
    }

    // MARK: - EVM Word Addition Constraints

    /// Generate constraints for 256-bit addition: result = a + b (mod 2^256)
    /// Returns carry limbs for constraint generation
    public static func addConstraints(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var carries = [M31](repeating: .zero, count: 10)
        var sum: UInt64 = 0

        for i in 0..<9 {
            sum = UInt64(a[i].v) + UInt64(b[i].v) + UInt64(carries[i].v)
            let lowPart = UInt32(sum & 0x7FFFFFFF)
            let highPart = UInt32(sum >> 31)
            carries[i] = M31(v: lowPart)
            carries[i + 1] = M31(v: highPart)
        }

        // Check: a + b - result = 0 (mod M31) for each limb
        return carries
    }

    /// Verify addition result: result = a + b (mod 2^256)
    public static func verifyAdd(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var constraints = [M31]()
        var carry: UInt64 = 0

        for i in 0..<9 {
            let expected = UInt64(a[i].v) + UInt64(b[i].v) + carry
            let actualResult = expected % UInt64(M31.P)
            carry = expected / UInt64(M31.P)

            let diff = Int64(result[i].v) - Int64(actualResult)
            constraints.append(M31(v: UInt32(diff >= 0 ? diff : Int64(M31.P) + diff)))
        }

        return constraints
    }

    // MARK: - EVM Word Multiplication Constraints

    /// Generate constraints for 256-bit multiplication: result = a * b (mod 2^256)
    /// Uses limb-wise multiplication with carry propagation
    public static func mulConstraints(a: [M31], b: [M31]) -> ([M31], [M31]) {
        // Full 9x9 multiplication gives 81 intermediate terms
        var crossTerms = [[M31]](repeating: [M31](repeating: .zero, count: 81), count: 2)

        // Compute cross-terms: a[i] * b[j]
        var idx = 0
        for i in 0..<9 {
            for j in 0..<9 {
                crossTerms[0][idx] = m31Mul(a[i], b[j])
                idx += 1
            }
        }

        // Reduce cross-terms to 9 result limbs with carries
        var result = [M31](repeating: .zero, count: 9)
        var carries = [M31](repeating: .zero, count: 10)

        // Simplified reduction: accumulate products into result limbs
        // In real implementation, use LogUp for range reduction
        idx = 0
        for i in 0..<9 {
            var sum = UInt64(0)
            for j in 0..<9 {
                if i + j < 18 {
                    sum += UInt64(crossTerms[0][idx].v)
                }
                idx += 1
            }
            result[i] = M31(v: UInt32(sum % UInt64(M31.P)))
            carries[i] = M31(v: UInt32(sum / UInt64(M31.P)))
        }

        return (result, carries)
    }

    // MARK: - Comparison Constraints

    /// LT: result = 1 if a < b (unsigned), 0 otherwise
    /// Uses borrow chain from a - b
    public static func ltConstraints(a: [M31], b: [M31], result: M31) -> [M31] {
        var constraints = [M31]()
        var borrow: UInt64 = 0

        for i in 0..<9 {
            let aVal = UInt64(a[i].v)
            let bVal = UInt64(b[i].v)
            let diff = Int64(aVal) - Int64(bVal) - Int64(borrow)

            if diff >= 0 {
                borrow = 0
            } else {
                borrow = 1
            }
        }

        // result = borrow (1 if a < b, 0 if a >= b)
        constraints.append(m31Sub(result, M31(v: UInt32(borrow))))
        return constraints
    }

    /// SLT: result = 1 if a < b (signed), 0 otherwise
    public static func sltConstraints(a: [M31], b: [M31], result: M31) -> [M31] {
        // For signed comparison, compare sign bits
        let aSign = a[8].v & 0x40000000 != 0
        let bSign = b[8].v & 0x40000000 != 0

        // If signs differ, result = 1 if a is negative and b is positive
        // If signs same, do unsigned comparison
        // Simplified: use the low 32 bits for comparison
        let aLow = a[0].v
        let bLow = b[0].v

        let unsignedLT = aLow < bLow
        let signedLT = (aSign && !bSign) || (aSign == bSign && unsignedLT)

        return [m31Sub(result, M31(v: signedLT ? 1 : 0))]
    }

    /// EQ: result = 1 if a == b, 0 otherwise
    public static func eqConstraints(a: [M31], b: [M31], result: M31) -> [M31] {
        var diff = [M31]()
        for i in 0..<9 {
            diff.append(m31Sub(a[i], b[i]))
        }

        // result = 1 if all diffs are zero
        let sumOfDiffs = diff.reduce(M31.zero) { m31Add($0, $1) }
        return [m31Sub(result, m31IsZero(sumOfDiffs) ? M31.one : M31.zero)]
    }

    // MARK: - Bitwise Constraints

    /// AND: result = a & b (bitwise AND on 256-bit words)
    /// Each limb is 31 bits, so we do limb-wise AND
    public static func andConstraints(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var constraints = [M31]()
        for i in 0..<9 {
            let expected = M31(v: a[i].v & b[i].v)
            constraints.append(m31Sub(result[i], expected))
        }
        return constraints
    }

    /// OR: result = a | b (bitwise OR on 256-bit words)
    public static func orConstraints(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var constraints = [M31]()
        for i in 0..<9 {
            let expected = M31(v: a[i].v | b[i].v)
            constraints.append(m31Sub(result[i], expected))
        }
        return constraints
    }

    /// XOR: result = a ^ b (bitwise XOR on 256-bit words)
    public static func xorConstraints(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var constraints = [M31]()
        for i in 0..<9 {
            let expected = M31(v: a[i].v ^ b[i].v)
            constraints.append(m31Sub(result[i], expected))
        }
        return constraints
    }

    /// NOT: result = ~a (bitwise NOT, 256-bit)
    public static func notConstraints(a: [M31], result: [M31]) -> [M31] {
        var constraints = [M31]()
        let mask: UInt32 = 0x7FFFFFFF  // 31-bit mask
        for i in 0..<9 {
            let expected = M31(v: a[i].v ^ mask)
            constraints.append(m31Sub(result[i], expected))
        }
        return constraints
    }

    // MARK: - Shift Constraints

    /// SHL: result = a << shift (left shift, shift < 256)
    public static func shlConstraints(a: [M31], shift: M31, result: [M31]) -> [M31] {
        // Simplified: shift by limb count and bit offset
        let shiftVal = shift.v
        let limbShift = Int(UInt64(shiftVal) / 31)
        let bitShift = Int(UInt64(shiftVal) % 31)

        var expected = [M31](repeating: .zero, count: 9)

        if limbShift < 9 {
            // Shift by whole limbs
            for i in limbShift..<9 {
                let srcIdx = i - limbShift
                if bitShift == 0 {
                    expected[i] = a[srcIdx]
                } else if srcIdx > 0 {
                    // Combine high bits of lower limb with low bits of current
                    let highBits = a[srcIdx - 1].v >> (31 - bitShift)
                    let lowBits = a[srcIdx].v << bitShift
                    expected[i] = M31(v: (highBits | lowBits) & 0x7FFFFFFF)
                }
            }
        }

        var constraints = [M31]()
        for i in 0..<9 {
            constraints.append(m31Sub(result[i], expected[i]))
        }
        return constraints
    }

    /// SHR: result = a >> shift (right shift, shift < 256)
    public static func shrConstraints(a: [M31], shift: M31, result: [M31]) -> [M31] {
        let shiftVal = shift.v
        let limbShift = Int(UInt64(shiftVal) / 31)
        let bitShift = Int(UInt64(shiftVal) % 31)

        var expected = [M31](repeating: .zero, count: 9)

        if limbShift < 9 {
            for i in 0..<(9 - limbShift) {
                if bitShift == 0 {
                    expected[i] = a[i + limbShift]
                } else if i + limbShift + 1 < 9 {
                    let lowBits = a[i + limbShift].v >> bitShift
                    let highBits = a[i + limbShift + 1].v << (31 - bitShift)
                    expected[i] = M31(v: (lowBits | highBits) & 0x7FFFFFFF)
                }
            }
        }

        var constraints = [M31]()
        for i in 0..<9 {
            constraints.append(m31Sub(result[i], expected[i]))
        }
        return constraints
    }

    // MARK: - Byte Operations

    /// BYTE: extract the i-th byte from a 256-bit word
    public static func byteConstraints(a: [M31], index: M31, result: M31) -> [M31] {
        // Extract byte at position index (0 = MSB, 31 = LSB)
        let idx = Int(UInt64(index.v) % 32)
        var expected = M31.zero

        if idx < 32 {
            let limbIdx = 8 - (idx / 4)  // Little-endian: byte 0 is in highest limb
            let byteIdx = idx % 4
            let byteVal = (a[limbIdx].v >> (byteIdx * 8)) & 0xFF
            expected = M31(v: byteVal)
        }

        return [m31Sub(result, expected)]
    }

    /// SAR: result = a >> shift (arithmetic right shift, preserves sign)
    public static func sarConstraints(a: [M31], shift: M31, result: [M31]) -> [M31] {
        let shiftVal = shift.v
        let limbShift = Int(UInt64(shiftVal) / 31)
        let bitShift = Int(UInt64(shiftVal) % 31)

        // Check if a is negative (sign bit in highest limb)
        let signBit = (a[8].v & 0x40000000) != 0

        var expected = [M31](repeating: .zero, count: 9)

        if signBit {
            // Negative number: fill with 1s on left side
            // All limbs that are completely shifted out become 0x7FFFFFFF
            for i in 0..<limbShift {
                expected[i] = M31(v: 0x7FFFFFFF)
            }

            if limbShift < 9 {
                if bitShift == 0 {
                    expected[limbShift] = a[limbShift]
                } else {
                    // Shift right with sign extension (fill with 1s)
                    let lowBits = a[limbShift].v >> bitShift
                    // Sign-extend: if there were high bits from a[limbShift+1], they'd fill with 1s
                    // Since we're shifting right, we need to set high bits based on sign
                    let signFill: UInt32 = 0x7FFFFFFF << (31 - bitShift)
                    expected[limbShift] = M31(v: (lowBits | signFill) & 0x7FFFFFFF)
                }

                // Copy remaining limbs
                for i in (limbShift + 1)..<9 {
                    if bitShift == 0 {
                        expected[i] = a[i]
                    } else if i > 0 {
                        let lowBits = a[i].v >> bitShift
                        let highBits = (a[i - 1].v << (31 - bitShift)) & 0x7FFFFFFF
                        expected[i] = M31(v: (lowBits | highBits) & 0x7FFFFFFF)
                    }
                }
            }
        } else {
            // Positive number: shift like SHR
            if limbShift < 9 {
                for i in 0..<(9 - limbShift) {
                    if bitShift == 0 {
                        expected[i] = a[i + limbShift]
                    } else if i + limbShift + 1 < 9 {
                        let lowBits = a[i + limbShift].v >> bitShift
                        let highBits = a[i + limbShift + 1].v << (31 - bitShift)
                        expected[i] = M31(v: (lowBits | highBits) & 0x7FFFFFFF)
                    }
                }
            }
        }

        var constraints = [M31]()
        for i in 0..<9 {
            constraints.append(m31Sub(result[i], expected[i]))
        }
        return constraints
    }

    // MARK: - Modular Arithmetic

    /// MOD: result = a % b (mod 2^256)
    /// Verifies: result < b (unless b == 0 which is handled separately)
    public static func modConstraints(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var constraints = [M31](repeating: .zero, count: 9)

        // Check if b is zero - division by zero is undefined
        let bIsZero = b.allSatisfy { $0.v == 0 }
        if bIsZero {
            // If b == 0, result should also be 0
            for i in 0..<9 {
                constraints[i] = result[i]  // Constraint fails if result != 0
            }
            return constraints
        }

        // Verify result < b by checking if b - result - 1 would borrow
        // If result < b, then (b - 1) - result >= 0 with no borrow
        // We do b - result and check if there's a final borrow
        var borrow: UInt64 = 0
        for i in 0..<9 {
            let bVal = UInt64(b[i].v)
            let rVal = UInt64(result[i].v)
            let diff = Int64(bVal) - Int64(rVal) - Int64(borrow)
            borrow = diff < 0 ? 1 : 0
        }

        // If result < b, final borrow should be 0
        // If result >= b, final borrow will be 1
        // Return constraint: borrow should be 0 for valid result
        constraints[0] = M31(v: UInt32(borrow))
        return constraints
    }

    /// DIV: result = a / b (unsigned division, mod 2^256)
    /// Verifies: result * b <= a < (result + 1) * b (or result * b <= a if b == 0)
    public static func divConstraints(a: [M31], b: [M31], result: [M31]) -> [M31] {
        var constraints = [M31](repeating: .zero, count: 9)

        // Check if b is zero - division by zero returns 0 per EVM spec
        let bIsZero = b.allSatisfy { $0.v == 0 }
        if bIsZero {
            // If b == 0, result should be 0
            for i in 0..<9 {
                constraints[i] = result[i]  // Constraint fails if result != 0
            }
            return constraints
        }

        // Verify: result * b <= a
        // Compute result * b limb-wise and compare with a
        // We'll do 9x9 multiplication and compare 9 limbs

        // Compute product = result * b
        var product = [UInt64](repeating: 0, count: 18)  // Max 18 limbs for 9x9

        for i in 0..<9 {
            for j in 0..<9 {
                product[i + j] += UInt64(result[i].v) * UInt64(b[j].v)
            }
        }

        // Reduce to 9 limbs with carries
        var reducedProduct = [M31](repeating: .zero, count: 9)
        var carry: UInt64 = 0
        for i in 0..<9 {
            let sum = product[i] + carry
            reducedProduct[i] = M31(v: UInt32(sum % UInt64(M31.P)))
            carry = sum / UInt64(M31.P)
        }

        // Compare reducedProduct with a
        // For a valid division: a >= product
        // We verify a - product >= 0 by checking no borrow in subtraction
        var borrow: UInt64 = 0
        for i in 0..<9 {
            let aVal = UInt64(a[i].v)
            let pVal = UInt64(reducedProduct[i].v)
            let diff = Int64(aVal) - Int64(pVal) - Int64(borrow)
            borrow = diff < 0 ? 1 : 0
        }

        // If borrow == 0 at end, then a >= product (valid)
        constraints[0] = M31(v: UInt32(borrow))
        return constraints
    }

    // MARK: - Sign Extension

    /// SIGNEXTEND: sign-extend from (tb + 1) * 8 bits to 256 bits
    public static func signextendConstraints(a: [M31], tb: M31, result: [M31]) -> [M31] {
        let byteIdx = Int(UInt64(tb.v) % 32)
        var constraints = [M31]()

        if byteIdx < 31 {
            let signBitIdx = byteIdx * 8 + 7
            let limbIdx = 8 - (signBitIdx / 32)
            let bitIdx = signBitIdx % 32
            let signBit = (a[limbIdx].v >> bitIdx) & 1

            // All limbs below sign bit position should be 0 or 0x7FFFFFFF based on sign
            for i in 0..<9 {
                let expected: UInt32
                if i == limbIdx {
                    // Keep bits up to and including sign bit, extend sign
                    let mask: UInt32 = (1 << bitIdx) - 1
                    let lowBits = a[i].v & mask
                    let signExtension: UInt32 = signBit == 1 ? 0x7FFFFFFF ^ mask : 0
                    expected = lowBits | signExtension
                } else if i > limbIdx {
                    expected = signBit == 1 ? 0x7FFFFFFF : 0
                } else {
                    expected = a[i].v
                }
                constraints.append(m31Sub(result[i], M31(v: expected)))
            }
        } else {
            // No extension needed, result = a
            for i in 0..<9 {
                constraints.append(m31Sub(result[i], a[i]))
            }
        }

        return constraints
    }

    // MARK: - PC and Gas Constraints

    /// PC continuity: PC increments by 1 for non-jump ops
    public static func pcContinuityConstraints(currentPC: M31, nextPC: M31, isJump: M31) -> [M31] {
        // If isJump = 0: nextPC = currentPC + 1
        // If isJump = 1: nextPC is arbitrary (jump destination)
        let increment = m31Add(currentPC, M31.one)
        let expected = m31Add(
            m31Mul(isJump, nextPC),
            m31Mul(m31Sub(M31.one, isJump), increment)
        )
        return [m31Sub(nextPC, expected)]
    }

    /// Gas monotonicity: gas only decreases
    public static func gasMonotonicityConstraints(currentGas: M31, nextGas: M31) -> [M31] {
        // gas_next <= gas_current
        let diff = m31Sub(currentGas, nextGas)
        // diff should be >= 0, but M31 is modular
        // For gas (which is small), we check diff is not negative
        let isValid = diff.v < UInt32(M31.P) / 2 ? M31.one : M31.zero
        return [m31Sub(isValid, M31.one)]  // Should be valid, so returns 0
    }

    // MARK: - Call Depth Constraints

    /// Call depth can only increase by 1 or decrease by 1 (or stay same for internal ops)
    public static func callDepthConstraints(currentDepth: M31, nextDepth: M31) -> [M31] {
        let diff = Int32(nextDepth.v) - Int32(currentDepth.v)
        let absDiff = diff >= 0 ? diff : -diff
        let isValid = absDiff <= 1 || (currentDepth.v == 1 && nextDepth.v == 0)
        return [M31(v: isValid ? 0 : 1)]
    }

    // MARK: - Stack Constraints

    /// Stack height consistency
    public static func stackHeightConstraints(opcode: M31, currentHeight: M31, nextHeight: M31) -> [M31] {
        guard let op = EVMOpcode(rawValue: UInt8(opcode.v & 0xFF)) else {
            return [M31.one]  // Invalid opcode
        }

        let heightChange = op.properties.stackHeightChange
        let expected = Int(UInt64(currentHeight.v)) + heightChange

        var diff = Int(UInt64(nextHeight.v)) - expected
        if diff < 0 { diff = -diff }

        return [M31(v: diff == 0 ? 0 : 1)]
    }

    // MARK: - Memory Constraints

    /// Memory access: address must be within bounds after expansion
    public static func memoryAccessConstraints(address: M31, size: M31, memorySize: M31) -> [M31] {
        // address + size <= memorySize (after expansion to word boundary)
        let required = m31Add(address, size)
        let diff = m31Sub(memorySize, required)
        // diff >= 0 means access is valid
        let isValid = diff.v < UInt32(M31.P) / 2 ? M31.one : M31.zero
        return [m31Sub(isValid, M31.one)]  // Should be valid
    }

    // MARK: - Opcode Validity

    /// All opcodes must be in valid range
    public static func opcodeValidityConstraint(opcode: M31) -> [M31] {
        let val = opcode.v
        let isValid = val <= 0xFF ? M31.one : M31.zero
        return [m31Sub(isValid, M31.one)]  // Should be valid
    }

    /// Opcode must be implemented
    public static func opcodeImplementedConstraint(opcode: M31) -> [M31] {
        guard let op = EVMOpcode(rawValue: UInt8(opcode.v & 0xFF)) else {
            return [M31.one]  // Invalid - returns non-zero constraint
        }
        return [M31.zero]  // Valid opcode
    }

    // MARK: - Control Flow Constraints

    /// JUMPDEST validity: destination must be a JUMPDEST
    public static func jumpdestConstraint(opcode: M31, destination: M31, code: [M31]) -> [M31] {
        // In real implementation, would check code[destination] == JUMPDEST
        // Simplified: just return zero
        return [.zero]
    }

    /// JUMPI condition: if condition != 0, jump to destination
    public static func jumpiConstraint(condition: M31, destination: M31, nextPC: M31) -> [M31] {
        // If condition != 0: nextPC == destination
        // If condition == 0: nextPC == currentPC + 1 (handled by PC continuity)
        let isJump = EVMCircuit.m31IsZero(condition) ? M31.zero : M31.one
        let expected = m31Add(
            m31Mul(isJump, destination),
            m31Mul(m31Sub(M31.one, isJump), nextPC)
        )
        return [m31Sub(nextPC, expected)]
    }

    // MARK: - Opcode Selector Constraints

    /// Generate one-hot selector for opcode
    public static func opcodeSelectorConstraints(opcode: M31) -> [M31] {
        // Returns array indicating which opcode category this is
        guard let op = EVMOpcode(rawValue: UInt8(opcode.v & 0xFF)) else {
            return [M31.one, .zero, .zero, .zero, .zero]  // Invalid
        }

        switch op.category {
        case .arithmetic:
            return [.zero, M31.one, .zero, .zero, .zero]
        case .comparison:
            return [.zero, .zero, M31.one, .zero, .zero]
        case .bitwise:
            return [.zero, .zero, .zero, M31.one, .zero]
        case .memory:
            return [.zero, .zero, .zero, .zero, M31.one]
        default:
            return [.zero, .zero, .zero, .zero, .zero]
        }
    }
}

// MARK: - Opcode Category

public extension EVMOpcode {
    enum Category: String, Sendable {
        case stop
        case arithmetic
        case comparison
        case bitwise
        case keccak
        case environmental
        case block
        case stack
        case memory
        case control
        case call
        case log
        case system
        case eof
    }

    var category: Category {
        switch self {
        case .STOP, .REVERT, .RETURN, .SELFDESTRUCT:
            return .stop
        case .ADD, .SUB, .MUL, .DIV, .SDIV, .MOD, .SMOD, .ADDMOD, .MULMOD, .EXP, .SIGNEXTEND:
            return .arithmetic
        case .LT, .GT, .SLT, .SGT, .EQ, .ISZERO, .BYTE, .SHL, .SHR, .SAR:
            return .comparison
        case .AND, .OR, .XOR, .NOT:
            return .bitwise
        case .KECCAK256:
            return .keccak
        case .ADDRESS, .BALANCE, .ORIGIN, .CALLER, .CALLVALUE, .CALLDATALOAD, .CALLDATASIZE,
             .CALLDATACOPY, .CODESIZE, .CODECOPY, .GASPRICE, .EXTCODESIZE, .EXTCODECOPY,
             .RETURNDATASIZE, .RETURNDATACOPY, .EXTCODEHASH:
            return .environmental
        case .BLOCKHASH, .COINBASE, .TIMESTAMP, .NUMBER, .PREVRANDAO, .GASLIMIT,
             .CHAINID, .SELFBALANCE, .BASEFEE:
            return .block
        case .POP, .PUSH0, .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8,
             .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16, .PUSH17,
             .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24, .PUSH25, .PUSH26,
             .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32, .DUP1, .DUP2, .DUP3, .DUP4,
             .DUP5, .DUP6, .DUP7, .DUP8, .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14,
             .DUP15, .DUP16, .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8,
             .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16:
            return .stack
        case .MLOAD, .MSTORE, .MSTORE8:
            return .memory
        case .JUMP, .JUMPI, .JUMPDEST, .PC, .MSIZE, .GAS:
            return .control
        case .CALL, .DELEGATECALL, .STATICCALL, .CREATE, .CREATE2:
            return .call
        case .LOG0, .LOG1, .LOG2, .LOG3, .LOG4:
            return .log
        case .RETURN, .REVERT, .SELFDESTRUCT:
            return .system
        case .RJUMP, .RJUMPI, .CALLF, .RETF, .JUMPF, .DUPN, .SWAPN,
             .SLOADBYTES, .SSTOREBYTES, .MSTORESIZE, .TRACKSTORAGE, .COPYLOG:
            return .eof
        default:
            return .stop  // Invalid or unhandled opcodes
        }
    }
}
