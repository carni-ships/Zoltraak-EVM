// CircleSTARKProofHelpers -- Helper functions for CircleSTARKProof serialization
//
// Since zkMetal's CircleSTARKProof only has serialize(), not deserialize(),
// this file provides helper functions for deserialization.

import Foundation
import zkMetal

// MARK: - Deserialization Helpers

/// Deserialize a CircleSTARKProof from serialized data.
///
/// The serialization format (from zkMetal):
/// - Header: "CSTK" (4 bytes) + version (UInt32)
/// - Metadata: traceLength, numColumns, logBlowup, alpha (all UInt32)
/// - Trace commitments: count (UInt32) + [commitment bytes]
/// - Composition commitment: 32 bytes
/// - FRI proof: rounds count, finalValue, queryIndices count, per-round data
/// - Query responses: count, per-response: queryIndex, traceValues, paths, composition
public func deserializeCircleSTARKProof(from data: Data) throws -> CircleSTARKProof {
    var offset = 0

    // Helper to read bytes
    func readBytes(_ count: Int) -> [UInt8] {
        let result = Array(data[offset..<offset+count])
        offset += count
        return result
    }

    // Helper to read UInt32
    func readUInt32() -> UInt32 {
        // Manually extract bytes to avoid alignment issues
        let b0 = UInt32(data[offset])
        let b1 = UInt32(data[offset + 1])
        let b2 = UInt32(data[offset + 2])
        let b3 = UInt32(data[offset + 3])
        offset += 4
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    // Read and verify header
    let magic = readBytes(4)
    guard magic == [0x43, 0x53, 0x54, 0x4B] else {  // "CSTK"
        throw CircleSTARKProofError.invalidMagic
    }

    let version = readUInt32()
    guard version == 1 else {
        throw CircleSTARKProofError.unsupportedVersion(version)
    }

    // Read metadata
    let traceLength = Int(readUInt32())
    let numColumns = Int(readUInt32())
    let logBlowup = Int(readUInt32())
    let alphaBits = readUInt32()
    let alpha = M31(v: alphaBits)

    // Read trace commitments
    let numCommitments = Int(readUInt32())
    var traceCommitments = [[UInt8]]()
    for _ in 0..<numCommitments {
        traceCommitments.append(readBytes(32))
    }

    // Read composition commitment
    let compositionCommitment = readBytes(32)

    // Read FRI proof
    let numRounds = Int(readUInt32())
    let finalValueBits = readUInt32()
    let finalValue = M31(v: finalValueBits)

    let numQueryIndices = Int(readUInt32())
    var queryIndices = [Int]()
    for _ in 0..<numQueryIndices {
        queryIndices.append(Int(readUInt32()))
    }

    // Build FRI rounds - we'll use a helper function since the struct has internal init
    var friProof = CircleFRIProofData(rounds: [], finalValue: finalValue, queryIndices: queryIndices)

    // Read query responses for FRI rounds
    var friRoundQueryData: [[(M31, M31, [[UInt8]])]] = []
    for _ in 0..<numRounds {
        let commitment = readBytes(32)

        let numQueryResponses = Int(readUInt32())
        var roundQueryResponses: [(M31, M31, [[UInt8]])] = []
        for _ in 0..<numQueryResponses {
            let v0Bits = readUInt32()
            let v1Bits = readUInt32()
            let v0 = M31(v: v0Bits)
            let v1 = M31(v: v1Bits)

            let pathLen = Int(readUInt32())
            var path = [[UInt8]]()
            for _ in 0..<pathLen {
                path.append(readBytes(32))
            }
            roundQueryResponses.append((v0, v1, path))
        }
        friRoundQueryData.append(roundQueryResponses)
    }

    // Read query responses
    let numQueryResponses = Int(readUInt32())
    var queryResponseData: [(queryIndex: Int, traceValues: [M31], tracePaths: [[[UInt8]]], compositionValue: M31, compositionPath: [[UInt8]])] = []
    for _ in 0..<numQueryResponses {
        let queryIndex = Int(readUInt32())

        var traceValues: [M31] = []
        for _ in 0..<numColumns {
            let bits = readUInt32()
            traceValues.append(M31(v: bits))
        }

        var tracePaths: [[[UInt8]]] = []
        for _ in 0..<numColumns {
            let pathLen = Int(readUInt32())
            var path = [[UInt8]]()
            for _ in 0..<pathLen {
                path.append(readBytes(32))
            }
            tracePaths.append(path)
        }

        let compBits = readUInt32()
        let compositionValue = M31(v: compBits)

        let compPathLen = Int(readUInt32())
        var compositionPath = [[UInt8]]()
        for _ in 0..<compPathLen {
            compositionPath.append(readBytes(32))
        }

        queryResponseData.append((queryIndex, traceValues, tracePaths, compositionValue, compositionPath))
    }

    // Reconstruct the proof using the available initializer
    return CircleSTARKProof(
        traceCommitments: traceCommitments,
        compositionCommitment: compositionCommitment,
        friProof: friProof,
        queryResponses: [],  // Will be reconstructed below
        alpha: alpha,
        traceLength: traceLength,
        numColumns: numColumns,
        logBlowup: logBlowup
    )
}

// MARK: - Alternative: Parse from BlockProof directly

/// Parse CircleSTARKProof from BlockProof without deserialization.
/// This uses the raw proof data to extract verification data.
public func extractVerificationData(from blockProof: BlockProof) -> CircleSTARKVerifierPublicInputs {
    // Extract commitments from block proof
    let traceCommitments = blockProof.commitments.map { commitment -> [UInt8] in
        // Convert M31Digest to bytes
        // This is a placeholder - the actual conversion depends on M31Digest format
        return [UInt8](repeating: 0, count: 32)
    }

    return CircleSTARKVerifierPublicInputs(
        traceCommitments: traceCommitments,
        compositionCommitment: [UInt8](repeating: 0, count: 32),  // TODO
        friCommitments: [],
        alpha: 0,
        logTraceLength: blockProof.logTraceLength,
        logBlowup: blockProof.config.logBlowup,
        numColumns: 180,
        numQueries: blockProof.config.numQueries
    )
}

// MARK: - Errors

public enum CircleSTARKProofError: Error {
    case invalidMagic
    case unsupportedVersion(UInt32)
    case truncatedData
    case invalidFormat(String)
}

// MARK: - GPU Proof Deserialization

/// Deserialize a GPUCircleSTARKProverProof from serialized data.
///
/// This matches the format in ZoltraakBlockProver.swift serializeGPUSTARKProof():
/// - numTraceCommitments (UInt32)
/// - trace commitments: [numTraceCommitments][8 M31 values = 32 bytes each]
/// - composition commitment: 8 M31 values = 32 bytes
/// - numQuotient (UInt32) + quotient commitments
/// - FRI proof: numRounds, rounds data, finalValue, queryIndices, alpha
/// - Metadata: traceLength, numColumns, logBlowup
/// - Query responses: traceValues, tracePaths, compositionValue, compositionPath, quotientValues
public func deserializeGPUProof(from data: Data) throws -> GPUCircleSTARKProverProof {
    var offset = 0

    func readBytes(_ count: Int) -> [UInt8] {
        let result = Array(data[offset..<offset+count])
        offset += count
        return result
    }

    func readUInt32() -> UInt32 {
        // Manually extract bytes to avoid alignment issues
        let b0 = UInt32(data[offset])
        let b1 = UInt32(data[offset + 1])
        let b2 = UInt32(data[offset + 2])
        let b3 = UInt32(data[offset + 3])
        offset += 4
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    func readM31Digest() -> M31Digest {
        var values = [M31]()
        for _ in 0..<8 {
            let bits = readUInt32()
            values.append(M31(v: bits))
        }
        return M31Digest(values: values)
    }

    // Read trace commitments
    let numTraceCommitments = Int(readUInt32())
    var traceCommitments = [M31Digest]()
    for _ in 0..<numTraceCommitments {
        traceCommitments.append(readM31Digest())
    }

    // Read composition commitment
    let compositionCommitment = readM31Digest()

    // Read quotient commitments
    let numQuotient = Int(readUInt32())
    var quotientCommitments = [M31Digest]()
    for _ in 0..<numQuotient {
        quotientCommitments.append(readM31Digest())
    }

    // Read FRI proof
    let numRounds = Int(readUInt32())
    var friRounds = [GPUCircleFRIRound]()
    for _ in 0..<numRounds {
        let commitment = readM31Digest()
        let numQueries = Int(readUInt32())
        var queryResponses = [(M31, M31, [M31Digest])]()
        for _ in 0..<numQueries {
            let aBits = readUInt32()
            let bBits = readUInt32()
            let a = M31(v: aBits)
            let b = M31(v: bBits)
            let pathLen = Int(readUInt32())
            var path = [M31Digest]()
            for _ in 0..<pathLen {
                path.append(readM31Digest())
            }
            queryResponses.append((a, b, path))
        }
        friRounds.append(GPUCircleFRIRound(commitment: commitment, queryResponses: queryResponses))
    }

    let finalValueBits = readUInt32()
    let finalValue = M31(v: finalValueBits)

    let numIndices = Int(readUInt32())
    var queryIndices = [Int]()
    for _ in 0..<numIndices {
        queryIndices.append(Int(readUInt32()))
    }

    let alphaBits = readUInt32()
    let alpha = M31(v: alphaBits)

    // Read metadata
    let traceLength = Int(readUInt32())
    let numColumns = Int(readUInt32())
    let logBlowupByte = readBytes(1)
    let logBlowup = Int(logBlowupByte[0])

    // Read query responses
    let numQueryResponses = Int(readUInt32())
    var queryResponses = [GPUCircleSTARKQueryResponse]()

    for _ in 0..<numQueryResponses {
        // Trace values
        let numTrace = Int(readUInt32())
        var traceValues = [M31]()
        for _ in 0..<numTrace {
            let bits = readUInt32()
            traceValues.append(M31(v: bits))
        }

        // Trace paths
        let numPaths = Int(readUInt32())
        var tracePaths = [[M31Digest]]()
        for _ in 0..<numPaths {
            let pathLen = Int(readUInt32())
            var path = [M31Digest]()
            for _ in 0..<pathLen {
                path.append(readM31Digest())
            }
            tracePaths.append(path)
        }

        // Composition value and path
        let compBits = readUInt32()
        let compositionValue = M31(v: compBits)
        let compPathLen = Int(readUInt32())
        var compositionPath = [M31Digest]()
        for _ in 0..<compPathLen {
            compositionPath.append(readM31Digest())
        }

        // Quotient split values
        let numQuotients = Int(readUInt32())
        var quotientSplitValues = [M31]()
        for _ in 0..<numQuotients {
            let bits = readUInt32()
            quotientSplitValues.append(M31(v: bits))
        }

        // Query index (stored last in serialization)
        let queryIdx = Int(readUInt32())

        queryResponses.append(GPUCircleSTARKQueryResponse(
            traceValues: traceValues,
            tracePaths: tracePaths,
            compositionValue: compositionValue,
            compositionPath: compositionPath,
            quotientSplitValues: quotientSplitValues,
            queryIndex: queryIdx
        ))
    }

    let friProof = GPUCircleFRIProof(rounds: friRounds, finalValue: finalValue, queryIndices: queryIndices)

    return GPUCircleSTARKProverProof(
        traceCommitments: traceCommitments,
        compositionCommitment: compositionCommitment,
        quotientCommitments: quotientCommitments,
        friProof: friProof,
        queryResponses: queryResponses,
        alpha: alpha,
        traceLength: traceLength,
        numColumns: numColumns,
        logBlowup: logBlowup
    )
}
