import Foundation
import zkMetal

// MARK: - EVMetalCPUMerkleProver

/// CPU-based parallel leaf hashing using multithreading.
///
/// This complements the GPU approach by using CPU cores for position hashing,
/// then passing pre-hashed digests to GPU for fast tree building.
///
/// The key insight is that Poseidon2 permutation is computationally intensive
/// but embarrassingly parallel - each leaf can be hashed independently on
/// separate CPU cores using Grand Central Dispatch (GCD).
public final class EVMetalCPUMerkleProver {

    // MARK: - Private State

    /// Number of worker threads to use (equals CPU core count).
    private let numThreads: Int

    // MARK: - Initialization

    /// Creates a new CPU Merkle prover using all available CPU cores.
    public init() {
        // Use all available cores, minimum 1
        self.numThreads = max(1, ProcessInfo.processInfo.processorCount)
    }

    // MARK: - Public API

    /// Hash individual M31 values with position to create leaf digests.
    ///
    /// Uses all available CPU cores for parallel processing via GCD.
    ///
    /// - Parameters:
    ///   - values: Individual M31 values to hash.
    ///   - positions: Position for each value (must have same count as values).
    /// - Returns: Array of digests (8 M31 elements each, matching Poseidon2 output).
    public func hashLeavesWithPosition(values: [M31], positions: [UInt32]) -> [M31] {
        let count = values.count
        precondition(count == positions.count, "values and positions must have same count")

        // Pre-allocate output array
        var digests = [M31](repeating: M31.zero, count: count * 8)

        // Partition work across threads
        let chunkSize = max(1, (count + numThreads - 1) / numThreads)

        DispatchQueue.concurrentPerform(iterations: numThreads) { threadIdx in
            let start = threadIdx * chunkSize
            let end = min(start + chunkSize, count)

            guard start < end else { return }

            for i in start..<end {
                let digest = hashSingleLeafWithPosition(value: values[i], position: positions[i])
                let baseIdx = i * 8
                for j in 0..<8 {
                    digests[baseIdx + j] = digest[j]
                }
            }
        }

        return digests
    }

    /// Hash leaves for multiple columns in parallel.
    ///
    /// Each column's leaves are at positions [colOffset, colOffset + countPerColumn).
    /// This is more efficient than calling `hashLeavesWithPosition` for each column
    /// separately because it parallelizes across columns.
    ///
    /// - Parameters:
    ///   - allValues: Flattened M31 values for all columns concatenated.
    ///   - numColumns: Number of columns.
    ///   - countPerColumn: Number of leaves per column.
    /// - Returns: Array of digest arrays, one per column.
    public func hashLeavesBatchPerColumn(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) -> [[M31]] {
        let totalCount = numColumns * countPerColumn

        // Pre-allocate results
        var results: [[M31]] = []
        results.reserveCapacity(numColumns)
        for _ in 0..<numColumns {
            results.append([M31](repeating: M31.zero, count: countPerColumn * 8))
        }

        // Partition columns across threads
        let chunkSize = max(1, (numColumns + numThreads - 1) / numThreads)

        DispatchQueue.concurrentPerform(iterations: numThreads) { threadIdx in
            let start = threadIdx * chunkSize
            let end = min(start + chunkSize, numColumns)

            guard start < end else { return }

            for col in start..<end {
                let colOffset = col * countPerColumn
                for i in 0..<countPerColumn {
                    let globalIdx = colOffset + i
                    let value = allValues[globalIdx]
                    let position = UInt32(globalIdx)
                    let digest = hashSingleLeafWithPosition(value: value, position: position)
                    let baseIdx = i * 8
                    for j in 0..<8 {
                        results[col][baseIdx + j] = digest[j]
                    }
                }
            }
        }

        return results
    }

    /// Builds a complete Merkle tree from individual M31 values using CPU.
    ///
    /// This matches the GPU tree builder exactly and serves as the reference
    /// implementation for correctness verification.
    ///
    /// - Parameters:
    ///   - values: Individual M31 values (one per leaf).
    ///   - numLeaves: Number of leaves (must be a power of 2).
    /// - Returns: Root digest (8 M31 elements).
    public func buildMerkleTree(values: [M31], numLeaves: Int) -> zkMetal.M31Digest {
        precondition(numLeaves > 0 && (numLeaves & (numLeaves - 1)) == 0, "numLeaves must be power of 2")
        precondition(values.count >= numLeaves, "Not enough values for numLeaves")

        // Step 1: Hash leaves with position
        let leafValues = Array(values.prefix(numLeaves))
        let positions = (0..<numLeaves).map { UInt32($0) }
        let digests = hashLeavesWithPosition(values: leafValues, positions: positions)

        // Step 2: Build tree from digests
        var nodes: [zkMetal.M31Digest] = []
        nodes.reserveCapacity(numLeaves)
        for i in 0..<numLeaves {
            let start = i * 8
            let digestValues = Array(digests[start..<start + 8])
            nodes.append(zkMetal.M31Digest(values: digestValues))
        }

        // Build tree bottom-up
        var levelSize = numLeaves
        while levelSize > 1 {
            var nextLevel: [zkMetal.M31Digest] = []
            nextLevel.reserveCapacity((levelSize + 1) / 2)
            for i in stride(from: 0, to: levelSize, by: 2) {
                let left = nodes[i]
                let right = i + 1 < levelSize ? nodes[i + 1] : left
                let hash = zkMetal.M31Digest(values: poseidon2M31Hash(left: left.values, right: right.values))
                nextLevel.append(hash)
            }
            nodes = nextLevel
            levelSize = nodes.count
        }

        return nodes[0]
    }

    // MARK: - Single Leaf Hashing

    /// Hashes a single leaf with position using Poseidon2 permutation.
    ///
    /// This is the same algorithm as the GPU kernel and produces identical results.
    /// The state is initialized as [value, position, 0, 0, ..., 0] (16 elements),
    /// then the Poseidon2 permutation is applied, and the first 8 elements
    /// are returned as the digest.
    ///
    /// - Parameters:
    ///   - value: The M31 value to hash.
    ///   - position: The position to include in the hash.
    /// - Returns: Array of 8 M31 elements representing the digest.
    private func hashSingleLeafWithPosition(value: M31, position: UInt32) -> [M31] {
        // Initialize state: [value, position, 0, 0, ..., 0] (16 elements)
        var state = [M31](repeating: M31.zero, count: 16)
        state[0] = value
        state[1] = M31(v: position)

        // Run Poseidon2 permutation
        poseidon2M31Permutation(state: &state)

        // Return first 8 elements as digest
        return Array(state[0..<8])
    }
}

// MARK: - M31 Field Operations (from zkMetal)

@inline(__always)
private func m31Add(_ a: M31, _ b: M31) -> M31 {
    let s = a.v &+ b.v
    let r = (s & M31.P) &+ (s >> 31)
    return M31(v: r == M31.P ? 0 : r)
}

@inline(__always)
private func m31Sub(_ a: M31, _ b: M31) -> M31 {
    if a.v >= b.v {
        return M31(v: a.v &- b.v)
    }
    return M31(v: a.v &+ M31.P &- b.v)
}

@inline(__always)
private func m31Mul(_ a: M31, _ b: M31) -> M31 {
    let prod = UInt64(a.v) &* UInt64(b.v)
    let lo = UInt32(truncatingIfNeeded: prod)
    let hi = UInt32(truncatingIfNeeded: prod >> 32)
    let s = lo &+ hi
    let r = (s & M31.P) &+ (s >> 31)
    return M31(v: r == M31.P ? 0 : r)
}

@inline(__always)
private func m31Sqr(_ a: M31) -> M31 {
    return m31Mul(a, a)
}
