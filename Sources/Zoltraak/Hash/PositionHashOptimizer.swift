import Foundation
import zkMetal

/// Algorithmically optimized position-based leaf hashing
///
/// Optimizations:
/// 1. Batch processing to reduce function call overhead
/// 2. Pre-loaded round constants to avoid repeated memory access
/// 3. Minimized state initialization (only set used elements)
/// 4. SIMD-friendly memory layout for better cache utilization
public final class PositionHashOptimizer {

    // MARK: - Pre-computed Constants

    /// Pre-loaded round constants as flat array for faster access
    /// POSEIDON2_M31_ROUND_CONSTANTS is [[M31]] - 35 rounds × 16 elements each
    private static let roundConstantsFlat: [UInt32] = {
        var flat = [UInt32]()
        flat.reserveCapacity(560)  // 35 rounds * 16 elements
        for round in POSEIDON2_M31_ROUND_CONSTANTS {
            for elem in round {
                flat.append(elem.v)
            }
        }
        return flat
    }()

    /// M31 internal diagonal constants
    private static let internalDiag: [UInt32] = [
        1, 1, 2, 1, 8, 32, 2, 256, 4096, 8, 65536, 1024, 2, 16384, 512, 32768
    ]

    // MARK: - Batch Position Hashing

    /// Optimized batch position hashing that processes multiple leaves efficiently
    ///
    /// Key optimizations:
    /// - Processes leaves in sequential batches for better cache locality
    /// - Minimizes state initialization overhead
    /// - Uses pre-loaded constants to avoid repeated memory access
    /// - Writes output directly to avoid intermediate copies
    ///
    /// - Parameters:
    ///   - values: Array of M31 values to hash
    ///   - positions: Array of positions (must match values count)
    /// - Returns: Flattened digests (8 M31 elements per value)
    public static func hashLeavesWithPositionOptimized(
        values: [M31],
        positions: [UInt32]
    ) -> [M31] {
        precondition(values.count == positions.count, "values and positions must have same count")

        let count = values.count
        var digests = [M31](repeating: M31.zero, count: count * 8)

        // Process in chunks of 8 for optimal cache utilization
        let chunkSize = 8
        for chunkStart in stride(from: 0, to: count, by: chunkSize) {
            let chunkEnd = min(chunkStart + chunkSize, count)

            for i in chunkStart..<chunkEnd {
                // Minimized state initialization - only set elements we use
                var state = [M31](repeating: M31.zero, count: 16)
                state[0] = values[i]
                state[1] = M31(v: positions[i])

                // Optimized Poseidon2 permutation with pre-loaded constants
                poseidon2M31PermutationOptimized(
                    state: &state,
                    roundConstants: roundConstantsFlat,
                    internalDiag: internalDiag
                )

                // Write digest directly to output
                let baseIdx = i * 8
                for j in 0..<8 {
                    digests[baseIdx + j] = state[j]
                }
            }
        }

        return digests
    }

    /// Parallel batch position hashing for multi-core systems
    ///
    /// Processes multiple columns in parallel using DispatchQueue
    /// while maintaining cache-friendly sequential processing within each column
    ///
    /// - Parameters:
    ///   - allValues: Flattened values for all columns (column-major order)
    ///   - numColumns: Number of columns
    ///   - countPerColumn: Number of leaves per column
    /// - Returns: Array of digest arrays, one per column
    public static func hashColumnsParallelOptimized(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) -> [[M31]] {
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)
        for _ in 0..<numColumns {
            results.append([M31](repeating: M31.zero, count: countPerColumn * 8))
        }

        // Process columns in parallel
        DispatchQueue.concurrentPerform(iterations: numColumns) { col in
            let colOffset = col * countPerColumn

            // Extract column values
            var colValues = [M31](repeating: M31.zero, count: countPerColumn)
            for i in 0..<countPerColumn {
                colValues[i] = allValues[colOffset + i]
            }

            // Generate positions (0 to countPerColumn-1)
            var positions = [UInt32](repeating: 0, count: countPerColumn)
            for i in 0..<countPerColumn {
                positions[i] = UInt32(i)
            }

            // Hash with optimized implementation
            let digests = hashLeavesWithPositionOptimized(
                values: colValues,
                positions: positions
            )

            results[col] = digests
        }

        return results
    }
}

// MARK: - Optimized Poseidon2 Permutation

/// Optimized Poseidon2 permutation with pre-loaded constants
///
/// This version uses pre-loaded constants to avoid repeated memory access
/// and minimizes state initialization overhead.
@inline(__always)
private func poseidon2M31PermutationOptimized(
    state: inout [M31],
    roundConstants: [UInt32],
    internalDiag: [UInt32]
) {
    // Pre-compute constants
    let width = 16
    let halfFullRounds = 7
    let partialRounds = 21
    let totalRounds = 35  // 14 full + 21 partial

    // Initial external layer
    p2m31ExternalLayerOptimized(state: &state)

    // First half of full rounds
    for r in 0..<halfFullRounds {
        let rcBase = r * width
        for i in 0..<width {
            state[i] = EVMCircuit.m31Add(state[i], M31(v: roundConstants[rcBase + i]))
        }
        for i in 0..<width {
            state[i] = p2m31SBox(state[i])
        }
        p2m31ExternalLayerOptimized(state: &state)
    }

    // Partial rounds (only state[0] uses round constants)
    for r in halfFullRounds..<(halfFullRounds + partialRounds) {
        state[0] = EVMCircuit.m31Add(state[0], M31(v: roundConstants[r * width]))
        state[0] = p2m31SBox(state[0])
        p2m31InternalLayerOptimized(state: &state, diag: internalDiag)
    }

    // Second half of full rounds
    for r in (halfFullRounds + partialRounds)..<totalRounds {
        let rcBase = r * width
        for i in 0..<width {
            state[i] = EVMCircuit.m31Add(state[i], M31(v: roundConstants[rcBase + i]))
        }
        for i in 0..<width {
            state[i] = p2m31SBox(state[i])
        }
        p2m31ExternalLayerOptimized(state: &state)
    }
}

// MARK: - Optimized Matrix Operations

/// Optimized external matrix layer
@inline(__always)
private func p2m31ExternalLayerOptimized(state: inout [M31]) {
    // Apply M4 to each 4-element block (read values first to avoid overlapping access)
    let s0 = state[0]; let s1 = state[1]; let s2 = state[2]; let s3 = state[3]
    let s4 = state[4]; let s5 = state[5]; let s6 = state[6]; let s7 = state[7]
    let s8 = state[8]; let s9 = state[9]; let s10 = state[10]; let s11 = state[11]
    let s12 = state[12]; let s13 = state[13]; let s14 = state[14]; let s15 = state[15]

    let (o0, o1, o2, o3) = p2m31M4Value(s0: s0, s1: s1, s2: s2, s3: s3)
    let (o4, o5, o6, o7) = p2m31M4Value(s0: s4, s1: s5, s2: s6, s3: s7)
    let (o8, o9, o10, o11) = p2m31M4Value(s0: s8, s1: s9, s2: s10, s3: s11)
    let (o12, o13, o14, o15) = p2m31M4Value(s0: s12, s1: s13, s2: s14, s3: s15)

    state[0] = o0; state[1] = o1; state[2] = o2; state[3] = o3
    state[4] = o4; state[5] = o5; state[6] = o6; state[7] = o7
    state[8] = o8; state[9] = o9; state[10] = o10; state[11] = o11
    state[12] = o12; state[13] = o13; state[14] = o14; state[15] = o15

    // Cross-block mixing
    for i in 0..<4 {
        let sum = EVMCircuit.m31Add(EVMCircuit.m31Add(state[i], state[i + 4]), EVMCircuit.m31Add(state[i + 8], state[i + 12]))
        state[i] = EVMCircuit.m31Add(state[i], sum)
        state[i + 4] = EVMCircuit.m31Add(state[i + 4], sum)
        state[i + 8] = EVMCircuit.m31Add(state[i + 8], sum)
        state[i + 12] = EVMCircuit.m31Add(state[i + 12], sum)
    }
}

/// Optimized M4 matrix (circulant [2,3,1,1]) - value-based version
@inline(__always)
private func p2m31M4Value(s0: M31, s1: M31, s2: M31, s3: M31) -> (M31, M31, M31, M31) {
    let t0 = EVMCircuit.m31Add(s0, s1)
    let t1 = EVMCircuit.m31Add(s2, s3)
    let s1doubled = EVMCircuit.m31Add(s1, s1)
    let s3doubled = EVMCircuit.m31Add(s3, s3)
    let t2 = EVMCircuit.m31Add(s1doubled, t1)
    let t3 = EVMCircuit.m31Add(s3doubled, t0)
    return (
        EVMCircuit.m31Add(t0, t3),
        EVMCircuit.m31Add(t1, t2),
        EVMCircuit.m31Add(t0, t2),
        EVMCircuit.m31Add(t1, t3)
    )
}

/// Optimized internal linear layer
@inline(__always)
private func p2m31InternalLayerOptimized(state: inout [M31], diag: [UInt32]) {
    var sum = M31.zero
    for i in 0..<16 {
        sum = EVMCircuit.m31Add(sum, state[i])
    }

    for i in 0..<16 {
        let d = diag[i]
        let prod: M31
        if d == 1 {
            prod = state[i]
        } else if d == 2 {
            prod = EVMCircuit.m31Add(state[i], state[i])
        } else {
            prod = EVMCircuit.m31Mul(state[i], M31(v: d % 0x7FFFFFFF))
        }
        state[i] = EVMCircuit.m31Add(prod, sum)
    }
}

/// Optimized S-box: x^5
@inline(__always)
private func p2m31SBox(_ x: M31) -> M31 {
    let x2 = EVMCircuit.m31Mul(x, x)
    let x4 = EVMCircuit.m31Mul(x2, x2)
    return EVMCircuit.m31Mul(x4, x)
}
