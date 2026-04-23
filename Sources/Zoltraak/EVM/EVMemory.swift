import Foundation
import zkMetal

/// Lasso-based memory argument for EVM memory operations
/// Provides memory consistency checks through lookup arguments
public struct EVMemory {

    // MARK: - Memory Access Types

    public enum AccessType: UInt8, Sendable {
        case read = 0
        case write = 1
    }

    // MARK: - Memory Row for Trace

    /// A single memory access row for the memory trace
    public struct MemoryRow: Sendable {
        public let addr: M31Word      // Memory address (32-byte word address)
        public let value: M31Word    // Value read/written
        public let timestamp: UInt64  // Monotonic timestamp
        public let isWrite: Bool
        public let pc: Int
        public let callDepth: Int

        public init(addr: M31Word, value: M31Word, timestamp: UInt64, isWrite: Bool, pc: Int, callDepth: Int) {
            self.addr = addr
            self.value = value
            self.timestamp = timestamp
            self.isWrite = isWrite
            self.pc = pc
            self.callDepth = callDepth
        }

        /// Convert to trace columns
        public func toColumns() -> [M31] {
            var cols = [M31]()
            // Address limbs
            cols.append(contentsOf: addr.limbs)
            // Value limbs
            cols.append(contentsOf: value.limbs)
            // Timestamp
            cols.append(M31(v: UInt32(truncatingIfNeeded: timestamp >> 31)))
            cols.append(M31(v: UInt32(truncatingIfNeeded: timestamp)))
            // Flags
            cols.append(M31(v: isWrite ? 1 : 0))
            // PC and call depth
            cols.append(M31(v: UInt32(pc)))
            cols.append(M31(v: UInt32(callDepth)))
            return cols
        }
    }

    // MARK: - Sorted Memory Trace

    /// Memory trace sorted by (addr, timestamp) for Lasso argument
    public struct SortedMemoryTrace: Sendable {
        public let rows: [MemoryRow]

        public init(rows: [MemoryRow]) {
            // Sort by (addr, timestamp)
            self.rows = rows.sorted { (a, b) in
                let aAddr = a.addr.toBytes().prefix(8).withUnsafeBytes { $0.load(as: UInt64.self) }
                let bAddr = b.addr.toBytes().prefix(8).withUnsafeBytes { $0.load(as: UInt64.self) }
                if aAddr != bAddr { return aAddr < bAddr }
                return a.timestamp < b.timestamp
            }
        }

        /// Number of rows
        public var count: Int { rows.count }

        /// Get sorted columns for trace
        public func toColumns() -> [[M31]] {
            guard !rows.isEmpty else { return [] }

            let numCols = rows[0].toColumns().count
            var columns = [[M31]](repeating: [M31](repeating: .zero, count: count), count: numCols)

            for (i, row) in rows.enumerated() {
                let cols = row.toColumns()
                for j in 0..<min(cols.count, numCols) {
                    columns[j][i] = cols[j]
                }
            }

            return columns
        }
    }

    // MARK: - Memory Lookup Argument

    /// Memory lookup for Lasso: find most recent write to an address
    public struct MemoryLookup: Sendable {
        public let addr: M31Word
        public let timestamp: UInt64
        public let value: M31Word
        public let found: Bool

        public init(addr: M31Word, timestamp: UInt64, value: M31Word, found: Bool) {
            self.addr = addr
            self.timestamp = timestamp
            self.value = value
            self.found = found
        }
    }

    // MARK: - Lookup Table Columns

    /// Generate identity permutation table for memory lookups
    /// Columns: [addr, timestamp, value_0, ..., value_8, is_write]
    public static func identityTable(size: Int) -> [[M31]] {
        var columns = [[M31]](repeating: [M31](repeating: .zero, count: size), count: 11)

        for i in 0..<size {
            columns[0][i] = M31(v: UInt32(i))  // addr
            columns[1][i] = M31(v: UInt32(i))  // timestamp
            // Value limbs are 0 (identity)
            columns[10][i] = M31.one  // is_write = 1
        }

        return columns
    }

    // MARK: - Memory Consistency Check

    /// Check that consecutive reads to same address return most recent write
    public static func checkMemoryConsistency(
        sortedTrace: SortedMemoryTrace
    ) -> [M31] {
        var constraints = [M31]()

        for i in 1..<sortedTrace.count {
            let prev = sortedTrace.rows[i - 1]
            let curr = sortedTrace.rows[i]

            // If same address, timestamp must increase
            if prev.addr.equals(curr.addr) {
                let timeDiff = Int64(curr.timestamp) - Int64(prev.timestamp)
                if timeDiff <= 0 {
                    constraints.append(M31.one)  // Invalid: timestamp didn't increase
                } else {
                    constraints.append(.zero)
                }

                // If current is a read, it must see the previous write's value
                if !curr.isWrite && prev.isWrite {
                    // Value should match
                    for j in 0..<9 {
                        if curr.value.limbs[j].v != prev.value.limbs[j].v {
                            constraints.append(M31.one)
                        } else {
                            constraints.append(.zero)
                        }
                    }
                }
            }
        }

        return constraints
    }

    // MARK: - LogUp Helper for Memory

    /// Generate LogUp challenge for memory lookup
    /// Returns the lookup expression: sum(1 / (x - f(i))) where f(i) = addr + timestamp * offset
    public static func memoryLogUp(
        sortedTrace: SortedMemoryTrace,
        challenge: M31
    ) -> M31 {
        var result = M31.zero
        let offset = M31(v: UInt32(1 << 20))  // Offset to separate addr and timestamp

        for (i, row) in sortedTrace.rows.enumerated() {
            // f(i) = addr + timestamp * offset
            let addrVal = row.addr.limbs[0].v
            let timeVal = UInt64(row.timestamp)
            let timeLow = UInt32(truncatingIfNeeded: timeVal)
            let timeHigh = UInt32(truncatingIfNeeded: timeVal >> 32)
            let combined = M31(v: addrVal ^ (timeLow << 16) ^ (timeHigh << 8))

            // 1 / (challenge - combined)
            let diff = m31Sub(challenge, combined)
            let inv = m31Inverse(diff)
            result = m31Add(result, inv)
        }

        return result
    }

    // MARK: - M31 Field Helpers

    private static func m31Add(_ a: M31, _ b: M31) -> M31 {
        let sum = UInt64(a.v) + UInt64(b.v)
        let p = UInt64(M31.P)
        if sum < p {
            return M31(v: UInt32(sum))
        } else {
            return M31(v: UInt32(sum - p))
        }
    }

    private static func m31Sub(_ a: M31, _ b: M31) -> M31 {
        let result = Int32(a.v) - Int32(b.v)
        if result >= 0 {
            return M31(v: UInt32(result))
        } else {
            return M31(v: UInt32(result + Int32(M31.P)))
        }
    }

    private static func m31Mul(_ a: M31, _ b: M31) -> M31 {
        let product = UInt64(a.v) * UInt64(b.v)
        return M31(v: UInt32(product % UInt64(M31.P)))
    }

    private static func m31Inverse(_ a: M31) -> M31 {
        // Extended Euclidean Algorithm for M31 inverse
        var t = Int32(0)
        var newT = Int32(1)
        var r = Int32(M31.P)
        var newR = Int32(a.v)

        while newR != 0 {
            let q = r / newR
            let tempT = newT
            newT = t - q * newT
            t = tempT
            let tempR = newR
            newR = r - q * newR
            r = tempR
        }

        if r > 1 {
            return M31.zero  // Not invertible
        }
        return M31(v: UInt32(t < 0 ? t + Int32(M31.P) : t))
    }

    // MARK: - Memory Expansion Constraints

    /// Check that memory accesses don't exceed allocated memory
    public static func memoryExpansionConstraints(
        accessAddr: M31,
        accessSize: M31,
        currentMemorySize: M31
    ) -> [M31] {
        // Memory words needed = (accessAddr + accessSize + 31) / 32
        let wordsNeeded = m31Add(accessAddr, m31Add(accessSize, M31(v: 31)))
        let wordsNeededAligned = M31(v: wordsNeeded.v & ~31)  // Align to 32

        // Check: wordsNeeded <= currentMemorySize
        let diff = m31Sub(currentMemorySize, wordsNeededAligned)
        let isValid = diff.v < UInt32(M31.P) / 2 ? M31.one : M31.zero

        return [m31Sub(isValid, M31.one)]  // Should be valid
    }

    // MARK: - Memory Read Value Constraint

    /// Verify that a read returns the value from the most recent write
    public static func memoryReadConstraint(
        readAddr: M31Word,
        readTimestamp: UInt64,
        readValue: M31Word,
        writeAddr: M31Word,
        writeTimestamp: UInt64,
        writeValue: M31Word,
        isWrite: Bool
    ) -> [M31] {
        var constraints = [M31]()

        // If this is a read (not write), value must come from most recent write
        if !isWrite && readAddr.equals(writeAddr) && readTimestamp > writeTimestamp {
            // Value should match
            for i in 0..<9 {
                let diff = m31Sub(readValue.limbs[i], writeValue.limbs[i])
                if diff.v != 0 {
                    constraints.append(diff)
                } else {
                    constraints.append(.zero)
                }
            }
        } else {
            // Not a read, no constraint
            for _ in 0..<9 {
                constraints.append(.zero)
            }
        }

        return constraints
    }
}

// MARK: - EVM Memory with Trace Generation

/// EVM Memory that tracks accesses for proof generation
public final class EVMemoryTracker: Sendable {
    private var accesses: [EVMemory.MemoryRow] = []
    private var timestamp: UInt64 = 0
    private let maxSize: Int

    public init(maxSize: Int = 1 << 26) {
        self.maxSize = maxSize
    }

    /// Record a memory read
    public func recordRead(addr: M31Word, value: M31Word, pc: Int, callDepth: Int) {
        let row = EVMemory.MemoryRow(
            addr: addr,
            value: value,
            timestamp: timestamp,
            isWrite: false,
            pc: pc,
            callDepth: callDepth
        )
        accesses.append(row)
        timestamp += 1
    }

    /// Record a memory write
    public func recordWrite(addr: M31Word, value: M31Word, pc: Int, callDepth: Int) {
        let row = EVMemory.MemoryRow(
            addr: addr,
            value: value,
            timestamp: timestamp,
            isWrite: true,
            pc: pc,
            callDepth: callDepth
        )
        accesses.append(row)
        timestamp += 1
    }

    /// Get sorted memory trace for Lasso
    public func sortedTrace() -> EVMemory.SortedMemoryTrace {
        return EVMemory.SortedMemoryTrace(rows: accesses)
    }

    /// Get all accesses
    public var allAccesses: [EVMemory.MemoryRow] {
        return accesses
    }

    /// Clear all accesses
    public func reset() {
        accesses.removeAll()
        timestamp = 0
    }
}
