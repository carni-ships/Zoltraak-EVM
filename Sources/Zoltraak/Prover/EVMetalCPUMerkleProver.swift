import Foundation
import zkMetal

// MARK: - Thread-Local State Cache

/// Thread-local cache for hash state to avoid repeated allocations.
/// Each thread gets its own state array that's reused across hashing operations.
private struct ThreadLocalHashState {
    /// Reusable state array for Poseidon2 permutation (16 elements)
    var state: [M31]

    init() {
        state = [M31](repeating: .zero, count: 16)
    }
}

// Thread-local storage key using OSAllocatedUnmanagedLock for thread safety
private final class ThreadStateCache {
    static let shared = ThreadStateCache()
    private let lock = NSLock()
    private var cache: [ObjectIdentifier: ThreadLocalHashState] = [:]

    func getState() -> ThreadLocalHashState {
        let threadId = ObjectIdentifier(Thread.current)
        lock.lock()
        let state = cache[threadId] ?? ThreadLocalHashState()
        lock.unlock()
        return state
    }

    func setState(_ state: ThreadLocalHashState) {
        let threadId = ObjectIdentifier(Thread.current)
        lock.lock()
        cache[threadId] = state
        lock.unlock()
    }
}

// MARK: - ZoltraakCPUMerkleProver

/// CPU-based parallel leaf hashing using multithreading.
///
/// This complements the GPU approach by using CPU cores for position hashing,
/// then passing pre-hashed digests to GPU for fast tree building.
///
/// The key insight is that Poseidon2 permutation is computationally intensive
/// but embarrassingly parallel - each leaf can be hashed independently on
/// separate CPU cores using Grand Central Dispatch (GCD).
///
/// Memory Optimizations:
/// - Thread-local state arrays eliminate per-leaf allocations
/// - Pre-allocated output buffers avoid dynamic array growth
/// - Reusable digest buffers across hashing operations
public final class ZoltraakCPUMerkleProver {

    // MARK: - Private State

    /// Number of worker threads to use (equals CPU core count).
    private let numThreads: Int

    /// Thread-local queues for parallel hashing with state reuse
    private let threadQueues: [DispatchQueue]

    // MARK: - Initialization

    /// Creates a new CPU Merkle prover using all available CPU cores.
    public init() {
        // Use all available cores, minimum 1
        self.numThreads = max(1, ProcessInfo.processInfo.processorCount)

        // Create dedicated queues for each thread to maintain thread-local state
        var queues: [DispatchQueue] = []
        queues.reserveCapacity(numThreads)
        for i in 0..<numThreads {
            let queue = DispatchQueue(label: "com.evmetal.hasher.\(i)",
                                     attributes: .concurrent,
                                     target: .global(qos: .userInitiated))
            queues.append(queue)
        }
        self.threadQueues = queues
    }

    // MARK: - Thread-Local State Management

    /// Get or create thread-local hash state
    private func getThreadState() -> ThreadLocalHashState {
        return ThreadStateCache.shared.getState()
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

    /// Hash leaves for multiple columns in parallel with memory optimizations.
    ///
    /// Each column's leaves are at positions [0, countPerColumn).
    /// This is more efficient than calling `hashLeavesWithPosition` for each column
    /// separately because it parallelizes across columns.
    ///
    /// Memory Optimizations:
    /// - Thread-local state arrays eliminate per-leaf allocations
    /// - Pre-allocated output buffers avoid dynamic array growth
    /// - Batch processing reduces memory allocation overhead
    ///
    /// - Parameters:
    ///   - allValues: Flattened M31 values for all columns concatenated (column-major).
    ///   - numColumns: Number of columns.
    ///   - countPerColumn: Number of leaves per column.
    /// - Returns: Array of digest arrays, one per column.
    public func hashLeavesBatchPerColumn(
        allValues: [M31],
        numColumns: Int,
        countPerColumn: Int
    ) -> [[M31]] {
        let totalCount = numColumns * countPerColumn

        // Pre-allocate results with exact capacity
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

            // Get thread-local state for reuse
            var threadState = getThreadState()

            for col in start..<end {
                for i in 0..<countPerColumn {
                    // Column-major indexing: flatValues[col * countPerColumn + i]
                    let srcIdx = col * countPerColumn + i
                    let value = allValues[srcIdx]

                    // Per-column position (same as GPU kernel): position = i for each column
                    let position = UInt32(i)

                    // Use optimized hashing with reusable state
                    hashSingleLeafWithPositionOptimized(
                        value: value,
                        position: position,
                        state: &threadState.state,
                        output: &results[col][i * 8]
                    )
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
        return buildMerkleTreeFromDigests(digests: digests, numLeaves: numLeaves)
    }

    /// Build Merkle tree from pre-computed digests (8 M31 elements per leaf).
    /// Useful for testing GPU tree building against CPU.
    public func buildMerkleTreeFromDigests(digests: [M31], numLeaves: Int) -> zkMetal.M31Digest {
        precondition(digests.count >= numLeaves * 8, "digests must have numLeaves * 8 M31 elements")

        // Build tree from pre-computed digests
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

    // MARK: - Single Leaf Hashing (Optimized)

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
        // Elements 2-15 are already zero from initialization

        // Run Poseidon2 permutation
        poseidon2M31Permutation(state: &state)

        // Return first 8 elements as digest
        return Array(state[0..<8])
    }

    /// Optimized leaf hashing that reuses state and output buffers.
    ///
    /// Memory optimizations:
    /// - Reuses state array instead of allocating new [M31](16) each call
    /// - Writes directly to output buffer instead of creating intermediate array
    /// - Eliminates Array slicing overhead
    ///
    /// - Parameters:
    ///   - value: The M31 value to hash.
    ///   - position: The position to include in the hash.
    ///   - state: Reusable state array (16 elements).
    ///   - output: Output buffer pointer (must have space for 8 M31 elements).
    @inline(__always)
    private func hashSingleLeafWithPositionOptimized(
        value: M31,
        position: UInt32,
        state: inout [M31],
        output: UnsafeMutablePointer<M31>
    ) {
        // Initialize state: [value, position, 0, 0, ..., 0] (16 elements)
        // Must reset ALL elements since state is reused from previous iterations
        state[0] = value
        state[1] = M31(v: position)
        // Reset elements 2-15 to zero (required for correct permutation)
        for i in 2..<16 {
            state[i] = M31.zero
        }

        // Run Poseidon2 permutation
        poseidon2M31Permutation(state: &state)

        // Write first 8 elements directly to output buffer
        // This avoids allocating a new array and copying
        output.initialize(from: state, count: 8)
    }

    /// Optimized batch hashing that minimizes allocations.
    ///
    /// This version processes multiple leaves in a single call, allowing
    /// for better cache locality and reduced allocation overhead.
    ///
    /// - Parameters:
    ///   - values: Array of M31 values to hash.
    ///   - positions: Array of positions (must match values count).
    /// - Returns: Flattened digests (8 M31 elements per value).
    @inline(__always)
    private func hashLeavesBatchOptimized(
        values: [M31],
        positions: [UInt32]
    ) -> [M31] {
        let count = values.count
        precondition(count == positions.count, "values and positions must have same count")

        // Pre-allocate output array
        var digests = [M31](repeating: M31.zero, count: count * 8)

        // Get thread-local state for reuse
        var threadState = getThreadState()

        // Process all leaves
        for i in 0..<count {
            hashSingleLeafWithPositionOptimized(
                value: values[i],
                position: positions[i],
                state: &threadState.state,
                output: &digests[i * 8]
            )
        }

        return digests
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
