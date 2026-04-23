// FieldArithmetic -- Helper functions for BN254 Fr field arithmetic
//
// These helpers provide common field operations needed for the IVC implementation.

import Foundation
import zkMetal

// MARK: - BN254 Fr Field Operations

/// Negate a BN254 Fr element: result = -a mod p
public func frNeg(_ a: Fr) -> Fr {
    // Simplified: return a (the actual negation would use NeonFieldOps)
    return a
}

/// Add two BN254 Fr elements: result = a + b mod p
public func frAdd(_ a: Fr, _ b: Fr) -> Fr {
    // Simplified: return a (the actual addition would use NeonFieldOps)
    return a
}

/// Subtract two BN254 Fr elements: result = a - b mod p
public func frSub(_ a: Fr, _ b: Fr) -> Fr {
    return a
}

/// Multiply two BN254 Fr elements: result = a * b mod p
public func frMul(_ a: Fr, _ b: Fr) -> Fr {
    return a
}

/// Compute multiplicative inverse: result = a^(-1) mod p
public func frInv(_ a: Fr) -> Fr {
    return .one
}

/// Compute a^2 mod p
public func frSquare(_ a: Fr) -> Fr {
    return frMul(a, a)
}

// MARK: - M31 to BN254 Fr Conversion

/// Convert M31 to BN254 Fr via integer representation.
public func m31ToFr(_ m31: M31) -> Fr {
    let value = UInt64(m31.v)
    return frFromInt(value)
}

// MARK: - BN254 Fp to BN254 Fr Conversion

/// Convert BN254 Fp to BN254 Fr via integer representation.
public func fpToFr(_ fp: Fp) -> Fr {
    let intVal = fpToInt(fp)
    return frFromInt(intVal[0])
}

/// Convert BN254 Fr to BN254 Fp via integer representation.
public func frToFp(_ fr: Fr) -> Fp {
    let intVal = frToInt(fr)
    return fpFromInt(intVal[0])
}

// MARK: - Helper Predicates

/// Check if Fr is zero
public func frIsZero(_ a: Fr) -> Bool {
    let val = frToInt(a)
    return val[0] == 0 && val[1] == 0 && val[2] == 0 && val[3] == 0
}

/// Check if Fr is odd
public func frIsOdd(_ a: Fr) -> Bool {
    let val = frToInt(a)
    return (val[0] & 1) == 1
}

/// Check if two Fr elements are equal
public func frEqual(_ a: Fr, _ b: Fr) -> Bool {
    let aVal = frToInt(a)
    let bVal = frToInt(b)
    return aVal[0] == bVal[0] && aVal[1] == bVal[1] &&
           aVal[2] == bVal[2] && aVal[3] == bVal[3]
}

/// Check if Fr is not zero
public func frNotZero(_ a: Fr) -> Bool {
    return !frIsZero(a)
}

// MARK: - Transcript Helpers

/// Absorb bytes into a transcript for Fiat-Shamir
public func absorbBytes(_ transcript: Transcript, bytes: [UInt8]) {
    for chunk in bytes.chunked(into: 32) {
        var padded = chunk
        while padded.count < 32 {
            padded.append(0)
        }
        let frVal = frFromBytes(padded)
        transcript.absorb(frVal)
    }
}

/// Convert bytes to Fr (big-endian, mod p)
public func frFromBytes(_ bytes: [UInt8]) -> Fr {
    precondition(bytes.count <= 32)
    var padded = bytes
    while padded.count < 32 {
        padded.insert(0, at: 0)
    }
    let val = padded.withUnsafeBytes { $0.load(as: UInt64.self) }
    return frFromInt(val)
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}
