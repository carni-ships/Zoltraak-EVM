import Foundation
import zkMetal

/// ARM NEON-optimized Poseidon2 M31 permutation for batch processing
///
/// Uses the m31_poseidon2_permutation_neon C function from NeonFieldOps
/// to process multiple Poseidon2 permutations in parallel using ARM NEON SIMD.
public final class Poseidon2M31NEON {

    // MARK: - Constants

    public static let width = 16  // Poseidon2 width for M31
    public static let rate = 8    // Rate portion
    public static let capacity = 8 // Capacity portion

    // M31 internal diagonal constants (from Plonky3/Stwo reference)
    private static let internalDiag: [UInt32] = [
        1, 1, 2, 1, 8, 32, 2, 256, 4096, 8, 65536, 1024, 2, 16384, 512, 32768
    ]

    // MARK: - Batch Permutation

    /// Process multiple Poseidon2 permutations in parallel using NEON SIMD
    ///
    /// - Parameters:
    ///   - states: Array of states to permute, flattened as [state0_elem0, ..., state0_elem15, state1_elem0, ...]
    ///   - count: Number of states to process
    /// - Returns: Array of permuted states
    public static func permuteBatch(_ states: [[UInt32]], count: Int) -> [[UInt32]] {
        precondition(states.count >= count, "Not enough states provided")
        precondition(count % 4 == 0, "Batch size must be multiple of 4 for NEON alignment")

        var result = states
        result.reserveCapacity(count)

        // Process 4 states at a time (optimal for NEON 4-wide SIMD)
        let batchSize = 4
        for start in stride(from: 0, to: count, by: batchSize) {
            let end = min(start + batchSize, count)
            let actualBatchSize = end - start

            // Prepare round constants (shared across all permutations) - flatten from [[M31]] to [UInt32]
            var roundConstants = [UInt32]()
            roundConstants.reserveCapacity(560)
            for round in POSEIDON2_M31_ROUND_CONSTANTS {
                for elem in round {
                    roundConstants.append(elem.v)
                }
            }

            // Process batch
            for i in start..<start + actualBatchSize {
                var state = states[i]

                // Call NEON-optimized permutation
                state.withUnsafeMutableBytes { statePtr in
                    let stateArray = statePtr.baseAddress!.assumingMemoryBound(to: UInt32.self)

                    roundConstants.withUnsafeBytes { rcPtr in
                        let rcArray = rcPtr.baseAddress!.assumingMemoryBound(to: UInt32.self)

                        internalDiag.withUnsafeBytes { diagPtr in
                            let diagArray = diagPtr.baseAddress!.assumingMemoryBound(to: UInt32.self)

                            // Call the C function
                            m31_poseidon2_permutation_neon_impl(
                                stateArray,
                                rcArray,
                                diagArray,
                                Int32(14),  // 14 full rounds
                                Int32(21)   // 21 partial rounds
                            )
                        }
                    }
                }

                result[i] = state
            }
        }

        return Array(result.prefix(count))
    }

    /// Hash multiple leaves with positions using NEON-optimized Poseidon2
    ///
    /// - Parameters:
    ///   - values: Individual M31 values to hash
    ///   - positions: Position for each value
    /// - Returns: Array of digests (8 M31 elements each)
    public static func hashLeavesWithPosition(values: [M31], positions: [UInt32]) -> [M31] {
        precondition(values.count == positions.count, "values and positions must have same count")

        let count = values.count
        var digests = [M31](repeating: M31.zero, count: count * 8)

        // Prepare round constants once (flatten from [[M31]] to [UInt32])
        var roundConstants = [UInt32]()
        roundConstants.reserveCapacity(560)
        for round in POSEIDON2_M31_ROUND_CONSTANTS {
            for elem in round {
                roundConstants.append(elem.v)
            }
        }

        // Process in batches of 4 for NEON alignment
        let batchSize = 4
        for start in stride(from: 0, to: count, by: batchSize) {
            let end = min(start + batchSize, count)

            for i in start..<end {
                // Initialize state: [value, position, 0, 0, 0, 0, 0, 0] + [0, 0, 0, 0, 0, 0, 0, 0]
                var state = [UInt32](repeating: 0, count: 16)
                state[0] = values[i].v
                state[1] = positions[i] % 0x7FFFFFFF  // M31 prime

                // Apply Poseidon2 permutation using NEON
                state.withUnsafeMutableBytes { statePtr in
                    let stateArray = statePtr.baseAddress!.assumingMemoryBound(to: UInt32.self)

                    roundConstants.withUnsafeBytes { rcPtr in
                        let rcArray = rcPtr.baseAddress!.assumingMemoryBound(to: UInt32.self)

                        internalDiag.withUnsafeBytes { diagPtr in
                            let diagArray = diagPtr.baseAddress!.assumingMemoryBound(to: UInt32.self)

                            m31_poseidon2_permutation_neon_impl(
                                stateArray,
                                rcArray,
                                diagArray,
                                Int32(14),  // 14 full rounds
                                Int32(21)   // 21 partial rounds
                            )
                        }
                    }
                }

                // Copy digest (first 8 elements)
                for j in 0..<8 {
                    digests[i * 8 + j] = M31(v: state[j])
                }
            }
        }

        return digests
    }
}

// MARK: - C Function Declaration

/// C function declaration for NEON-optimized M31 Poseidon2 permutation
///
/// - Parameters:
///   - state: 16-element array representing the Poseidon2 state
///   - round_constants: 560-element array (35 rounds × 16 elements) of round constants
///   - internal_diag: 16-element array of diagonal constants for internal layer
///   - num_full_rounds: Number of full rounds (typically 14)
///   - num_partial_rounds: Number of partial rounds (typically 21)
@_silgen_name("m31_poseidon2_permutation_neon")
func m31_poseidon2_permutation_neon_impl(
    _ state: UnsafeMutablePointer<UInt32>,
    _ round_constants: UnsafePointer<UInt32>,
    _ internal_diag: UnsafePointer<UInt32>,
    _ num_full_rounds: Int32,
    _ num_partial_rounds: Int32
)

