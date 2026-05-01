// FieldArithmetic -- Helper functions for BN254 Fr field arithmetic
//
// BN254 Fr field: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// This file re-exports and provides compatibility wrappers for zkMetal's BN254Fr.swift.
// All actual arithmetic is implemented in zkMetal.

import Foundation
import zkMetal
import NeonFieldOps

// NOTE: All field operations (frAdd, frSub, frMul, frNeg, frFromInt, frToInt, etc.)
// are defined in zkMetal's BN254Fr.swift.
// This file provides additional helpers and transcript utilities.

// MARK: - Re-export zkMetal Fr functions for convenience

// These call zkMetal's implementations directly
public typealias FieldFr = Fr

// MARK: - M31 to BN254 Fr Conversion

/// Convert M31 to BN254 Fr via integer representation.
public func m31ToFr(_ m31: M31) -> Fr {
    let value = UInt64(m31.v)
    return zkMetal_frFromInt(value)
}

/// Convert UInt64 to Fr (interprets as field element)
public func zkMetal_frFromInt(_ value: UInt64) -> Fr {
    let limbs: [UInt64] = [value, 0, 0, 0]
    let raw = Fr.from64(limbs)
    // Multiply by R2 to convert to Montgomery form
    return frMul(raw, Fr.from64(Fr.R2_MOD_R))
}

// MARK: - BN254 Fp to BN254 Fr Conversion

/// Convert BN254 Fp to BN254 Fr via integer representation.
public func fpToFr(_ fp: Fp) -> Fr {
    let intVal = fp.to64()
    return zkMetal_frFromInt(intVal[0])
}

/// Convert BN254 Fr to BN254 Fp via integer representation.
public func frToFp(_ fr: Fr) -> Fp {
    let intVal = fr.to64()
    let limbs: [UInt64] = [intVal[0], 0, 0, 0]
    return Fp.from64(limbs)
}

// MARK: - Helper Predicates

/// Check if Fr is zero
public func frIsZero(_ a: Fr) -> Bool {
    return a.isZero
}

/// Check if Fr is odd
public func frIsOdd(_ a: Fr) -> Bool {
    let val = a.to64()
    return (val[0] & 1) == 1
}

/// Check if two Fr elements are equal
public func frEqual(_ a: Fr, _ b: Fr) -> Bool {
    let aVal = a.to64()
    let bVal = b.to64()
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
    return zkMetal_frFromInt(val)
}

// MARK: - Array Extension

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}
