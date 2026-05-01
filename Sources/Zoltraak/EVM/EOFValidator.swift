import Foundation
import zkMetal

/// EOF (Ethereum Object Format) validation errors
public enum EOFValidationError: Error, Sendable {
    case invalidMagic
    case invalidVersion(version: UInt8)
    case incompleteHeader
    case missingTypeSection
    case missingCodeSection
    case missingDataSection
    case invalidSectionBounds
    case invalidCodeSectionSize
    case invalidTypeSectionSize
    case invalidDataSectionSize
    case invalidFunctionIndex(index: Int, maxIndex: Int)
    case invalidJumpTarget(target: Int, codeLength: Int)
    case stackUnderflow(required: Int, available: Int)
    case stackOverflow(required: Int, maxHeight: Int)
    case invalidInstructions(reason: String)
    case jumpIntoImmediate(target: Int)
    case unreachableInstructions(unreachable: [Int])
    case rjumpvTableInvalid(index: Int, tableSize: Int)
    case callfArgsMismatch(funcIndex: Int, expectedArgs: Int, providedArgs: Int)
}

/// Container format version
public enum EOFVersion: UInt8, Sendable {
    case version1 = 0x01
}

/// Section type in EOF container
public enum EOFSectionType: UInt8, Sendable {
    case type = 0x01
    case code = 0x02
    case data = 0x03
}

/// Type section entry describing a code section's inputs/outputs
public struct EOFTypeEntry: Sendable {
    /// Number of stack items consumed (inputs)
    public let numInputs: UInt8
    /// Number of stack items produced (outputs)
    public let numOutputs: UInt8
    /// Maximum stack height during execution
    public let maxStackHeight: UInt16

    public init(numInputs: UInt8, numOutputs: UInt8, maxStackHeight: UInt16) {
        self.numInputs = numInputs
        self.numOutputs = numOutputs
        self.maxStackHeight = maxStackHeight
    }
}

/// Code section entry with offset and size
public struct EOFCodeSection: Sendable {
    /// Offset in container
    public let offset: Int
    /// Size in bytes
    public let size: Int
    /// Entrypoint (first instruction executed)
    public let entrypoint: Int

    public init(offset: Int, size: Int, entrypoint: Int = 0) {
        self.offset = offset
        self.size = size
        self.entrypoint = entrypoint
    }
}

/// Data section entry
public struct EOFDataSection: Sendable {
    /// Offset in container
    public let offset: Int
    /// Size in bytes
    public let size: Int

    public init(offset: Int, size: Int) {
        self.offset = offset
        self.size = size
    }
}

/// Parsed EOF container
public struct EOFContainer: Sendable {
    /// Magic bytes (0xEF00)
    public let magic: UInt16
    /// Version byte
    public let version: UInt8
    /// Type section entries
    public let typeSection: [EOFTypeEntry]
    /// Code sections
    public let codeSections: [EOFCodeSection]
    /// Data section
    public let dataSection: EOFDataSection?
    /// Raw code for each code section
    public let codeSectionData: [[UInt8]]
    /// Raw data section bytes
    public let dataSectionBytes: [UInt8]

    public init(
        magic: UInt16,
        version: UInt8,
        typeSection: [EOFTypeEntry],
        codeSections: [EOFCodeSection],
        dataSection: EOFDataSection?,
        codeSectionData: [[UInt8]],
        dataSectionBytes: [UInt8]
    ) {
        self.magic = magic
        self.version = version
        self.typeSection = typeSection
        self.codeSections = codeSections
        self.dataSection = dataSection
        self.codeSectionData = codeSectionData
        self.dataSectionBytes = dataSectionBytes
    }
}

/// Static analysis result for a code section
public struct EOFCodeAnalysis: Sendable {
    /// Valid jump destinations (pc positions that are valid JUMPDEST equivalents)
    public let validJumpDestinations: Set<Int>
    /// For RJUMPV, mapping from table index to target positions
    public let rjumpvTables: [[Int]]
    /// Maximum stack height required
    public let maxStackHeight: Int
    /// Whether analysis completed successfully
    public let isValid: Bool
    /// Error reason if invalid
    public let errorReason: String?
}

/// EOF Validator and Parser
public struct EOFValidator: Sendable {

    // MARK: - Constants

    /// EOF magic bytes
    public static let magicBytes: UInt16 = 0xEF00

    /// Minimum container size (magic + version + empty sections)
    public static let minContainerSize: Int = 4

    /// Maximum number of code sections
    public static let maxCodeSections: Int = 1024

    /// Maximum code section size
    public static let maxCodeSectionSize: Int = 0x4000  // 16KB

    /// Maximum data section size
    public static let maxDataSectionSize: Int = 0x4000  // 16KB

    // MARK: - Validation

    /// Validate an EOF container and return parsed structure
    public static func validate(_ data: [UInt8]) throws -> EOFContainer {
        // Check minimum size
        guard data.count >= minContainerSize else {
            throw EOFValidationError.incompleteHeader
        }

        // Check magic bytes (0xEF00)
        let magic = UInt16(data[0]) | (UInt16(data[1]) << 8)
        guard magic == magicBytes else {
            throw EOFValidationError.invalidMagic
        }

        // Check version
        let version = data[2]
        guard version == 0x01 else {
            throw EOFValidationError.invalidVersion(version: version)
        }

        // Parse container using EIP-5450 format
        var offset = 3

        // Read section table
        guard offset < data.count else {
            throw EOFValidationError.incompleteHeader
        }

        let sectionCount = Int(data[offset])
        offset += 1

        // Skip section sizes (we recalculate from actual data)
        guard offset + sectionCount * 2 <= data.count else {
            throw EOFValidationError.incompleteHeader
        }

        // Calculate section offsets based on header
        let headerSize = 3 + 1 + sectionCount * 2  // magic + version + section count + sizes
        var sectionOffsets: [Int] = []
        var sectionSizes: [Int] = []

        for i in 0..<sectionCount {
            let size = Int(data[3 + 1 + i * 2]) | (Int(data[3 + 1 + i * 2 + 1]) << 8)
            sectionSizes.append(size)
        }

        // First section is type section (if present), followed by code sections, then data
        // Type section is 1 + num_code_sections * 3 bytes
        var currentOffset = headerSize

        // Type section
        guard sectionSizes.count >= 1 else {
            throw EOFValidationError.missingTypeSection
        }

        let typeSectionSize = sectionSizes[0]
        currentOffset += typeSectionSize

        // Code sections
        var codeSections: [EOFCodeSection] = []
        var codeSectionData: [[UInt8]] = []

        for i in 1..<sectionSizes.count {
            let codeOffset = currentOffset
            let codeSize = sectionSizes[i]

            guard codeOffset + codeSize <= data.count else {
                throw EOFValidationError.invalidSectionBounds
            }

            let codeBytes = Array(data[codeOffset..<(codeOffset + codeSize)])
            codeSections.append(EOFCodeSection(offset: codeOffset, size: codeSize, entrypoint: 0))
            codeSectionData.append(codeBytes)

            currentOffset += codeSize
        }

        // Data section (last section if present)
        var dataSection: EOFDataSection? = nil
        var dataSectionBytes: [UInt8] = []

        if sectionSizes.count >= 3 {
            let dataOffset = currentOffset
            let dataSize = sectionSizes.last!

            guard dataOffset + dataSize <= data.count else {
                throw EOFValidationError.invalidSectionBounds
            }

            dataSection = EOFDataSection(offset: dataOffset, size: dataSize)
            dataSectionBytes = Array(data[dataOffset..<(dataOffset + dataSize)])
        }

        // Parse type section
        let typeSection = try parseTypeSection(data: Array(data[3...]), codeSectionCount: codeSections.count)

        // Build container
        let container = EOFContainer(
            magic: magic,
            version: version,
            typeSection: typeSection,
            codeSections: codeSections,
            dataSection: dataSection,
            codeSectionData: codeSectionData,
            dataSectionBytes: dataSectionBytes
        )

        // Validate static properties
        try validateStaticConstraints(container)

        return container
    }

    /// Parse type section into type entries
    private static func parseTypeSection(data: [UInt8], codeSectionCount: Int) throws -> [EOFTypeEntry] {
        guard data.count >= 1 else {
            throw EOFValidationError.missingTypeSection
        }

        let typeSectionSize = Int(data[0]) | (Int(data[1]) << 8)
        guard data.count >= 1 + typeSectionSize else {
            throw EOFValidationError.invalidTypeSectionSize
        }

        // Skip size header
        var offset = 2
        var types: [EOFTypeEntry] = []

        // First type entry is for code section 0
        while offset < data.count && types.count < codeSectionCount {
            let numInputs = data[offset]
            let numOutputs = data[offset + 1]
            let maxStackHeight = UInt16(data[offset + 2]) | (UInt16(data[offset + 3]) << 8)

            types.append(EOFTypeEntry(
                numInputs: numInputs,
                numOutputs: numOutputs,
                maxStackHeight: maxStackHeight
            ))

            offset += 4
        }

        return types
    }

    /// Validate static constraints (EIP-5450)
    private static func validateStaticConstraints(_ container: EOFContainer) throws {
        // Ensure code sections don't overlap with each other or data section
        var allBounds: [(start: Int, end: Int)] = []

        for codeSection in container.codeSections {
            allBounds.append((codeSection.offset, codeSection.offset + codeSection.size))
        }

        if let dataSection = container.dataSection {
            allBounds.append((dataSection.offset, dataSection.offset + dataSection.size))
        }

        // Check no overlaps
        for i in 0..<allBounds.count {
            for j in (i+1)..<allBounds.count {
                let a = allBounds[i]
                let b = allBounds[j]
                if a.start < b.end && b.start < a.end {
                    throw EOFValidationError.invalidSectionBounds
                }
            }
        }

        // Each code section must be non-empty and <= maxCodeSectionSize
        for (i, codeSection) in container.codeSections.enumerated() {
            if codeSection.size == 0 || codeSection.size > maxCodeSectionSize {
                throw EOFValidationError.invalidCodeSectionSize
            }
        }

        // Data section size check
        if let dataSection = container.dataSection {
            if dataSection.size > maxDataSectionSize {
                throw EOFValidationError.invalidDataSectionSize
            }
        }
    }

    // MARK: - Static Analysis

    /// Perform static analysis on a code section
    public static func analyzeCode(
        code: [UInt8],
        typeEntry: EOFTypeEntry? = nil,
        container: EOFContainer? = nil,
        codeSectionIndex: Int = 0
    ) throws -> EOFCodeAnalysis {
        var validJumpDests: Set<Int> = []
        var rjumpvTables: [[Int]] = []
        var maxStack = 0
        var currentStack = typeEntry.map { Int($0.numInputs) } ?? 0

        var pc = 0
        var unreachable: [Int] = []

        while pc < code.count {
            let opcode = code[pc]

            // Track unreachable (except from fallthrough)
            if pc > 0 && !validJumpDests.contains(pc - 1) && !validJumpDests.contains(pc) {
                // Could be unreachable if not a jump destination
            }

            switch opcode {
            case 0xE0: // RJUMP
                guard pc + 2 < code.count else {
                    throw EOFValidationError.invalidInstructions(reason: "RJUMP truncated at \(pc)")
                }
                let offset = Int16(bitPattern: UInt16(code[pc+1]) | (UInt16(code[pc+2]) << 8))
                let target = pc + 2 + Int(offset)
                if target >= 0 && target < code.count {
                    validJumpDests.insert(target)
                } else {
                    throw EOFValidationError.invalidJumpTarget(target: target, codeLength: code.count)
                }
                pc += 3

            case 0xE1: // RJUMPI
                guard pc + 2 < code.count else {
                    throw EOFValidationError.invalidInstructions(reason: "RJUMPI truncated at \(pc)")
                }
                let offset = Int16(bitPattern: UInt16(code[pc+1]) | (UInt16(code[pc+2]) << 8))
                let target = pc + 2 + Int(offset)
                if target >= 0 && target < code.count {
                    validJumpDests.insert(target)
                } else {
                    throw EOFValidationError.invalidJumpTarget(target: target, codeLength: code.count)
                }
                pc += 3

            case 0xE2: // RJUMPV
                guard pc + 1 < code.count else {
                    throw EOFValidationError.invalidInstructions(reason: "RJUMPV truncated at \(pc)")
                }
                let tableSize = Int(code[pc + 1])
                guard pc + 2 + tableSize * 2 <= code.count else {
                    throw EOFValidationError.rjumpvTableInvalid(index: tableSize, tableSize: tableSize)
                }
                var targets: [Int] = []
                for i in 0...tableSize {
                    let entryOffset = pc + 2 + i * 2
                    let offset = Int16(bitPattern: UInt16(code[entryOffset]) | (UInt16(code[entryOffset+1]) << 8))
                    let target = entryOffset + Int(offset)
                    targets.append(target)
                }
                rjumpvTables.append(targets)
                for target in targets {
                    if target >= 0 && target < code.count {
                        validJumpDests.insert(target)
                    }
                }
                pc += 2 + tableSize * 2

            case 0x5B: // JUMPDEST (for legacy EVM compatibility in EOF)
                validJumpDests.insert(pc)
                pc += 1

            // Stack-manipulating opcodes
            case 0x50: // POP
                currentStack -= 1
                pc += 1

            case 0x60...0x7F: // PUSH1-PUSH32
                let n = Int(opcode - 0x5F)
                currentStack += 1
                maxStack = max(maxStack, currentStack)
                pc += n + 1

            case 0x80...0x8F: // DUP1-DUP16
                let n = Int(opcode - 0x7F) + 1
                currentStack += 1
                maxStack = max(maxStack, currentStack)
                pc += 1

            case 0x90...0x9F: // SWAP1-SWAP16
                pc += 1

            case 0x10...0x1D: // Arithmetic/comparison - binary ops
                currentStack -= 1
                currentStack += 1
                maxStack = max(maxStack, currentStack)
                pc += 1

            case 0x01: // ADD
                currentStack -= 1
                currentStack += 1
                maxStack = max(maxStack, currentStack)
                pc += 1

            default:
                pc += 1
            }
        }

        return EOFCodeAnalysis(
            validJumpDestinations: validJumpDests,
            rjumpvTables: rjumpvTables,
            maxStackHeight: maxStack,
            isValid: true,
            errorReason: nil
        )
    }

    /// Validate jump destination
    public static func isValidJumpTarget(_ target: Int, code: [UInt8], analysis: EOFCodeAnalysis) -> Bool {
        // In EOF, RJUMP/RJUMPI/RJUMPV destinations must land on valid opcodes
        // (not in the middle of multi-byte instructions)
        guard target >= 0 && target < code.count else {
            return false
        }

        // Target must be a valid instruction start
        let opcode = code[target]
        return !isImmediateOpcode(opcode)
    }

    /// Check if opcode has immediate data (and thus cannot be a jump target)
    public static func isImmediateOpcode(_ opcode: UInt8) -> Bool {
        switch opcode {
        case 0x60...0x7F: // PUSH1-PUSH32
            return true
        case 0xE0: // RJUMP
            return true
        case 0xE1: // RJUMPI
            return true
        case 0xE2: // RJUMPV
            return true
        case 0xE3: // CALLF
            return true
        case 0xE8: // DUPN
            return true
        case 0xE9: // SWAPN
            return true
        default:
            return false
        }
    }
}

// MARK: - EOF Code Section Access

extension EOFContainer {

    /// Get code for a specific code section
    public func code(at index: Int) -> [UInt8]? {
        guard index >= 0 && index < codeSectionData.count else {
            return nil
        }
        return codeSectionData[index]
    }

    /// Get type entry for a specific code section
    public func typeEntry(for codeIndex: Int) -> EOFTypeEntry? {
        guard codeIndex >= 0 && codeIndex < typeSection.count else {
            return nil
        }
        return typeSection[codeIndex]
    }

    /// Analyze a code section
    public func analyze(codeIndex: Int) throws -> EOFCodeAnalysis {
        guard let code = code(at: codeIndex) else {
            throw EOFValidationError.invalidFunctionIndex(index: codeIndex, maxIndex: codeSections.count)
        }
        let typeEntry = typeEntry(for: codeIndex)
        return try EOFValidator.analyzeCode(
            code: code,
            typeEntry: typeEntry,
            container: self,
            codeSectionIndex: codeIndex
        )
    }
}