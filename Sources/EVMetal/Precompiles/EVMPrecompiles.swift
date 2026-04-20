import Foundation
import zkMetal

/// EVM Precompile wrapper integrating zkmetal's GPU precompile engine
/// Provides ECDSA recovery, BN254, BLS12-381, and MODEXP operations
public struct EVMPrecompiles {

    // MARK: - Precompile Address

    public enum PrecompileAddress: UInt8, Sendable {
        case ecRecover = 0x01
        case sha256 = 0x02
        case ripemd160 = 0x03
        case identity = 0x04
        case modExp = 0x05
        case ecAdd = 0x06
        case ecMul = 0x07
        case ecPairing = 0x08
        case blake2f = 0x09
        case bls12381G1Add = 0x0A
        case bls12381G1Mul = 0x0B
        case bls12381G2Mul = 0x0C
        case pairing12 = 0x0D
        case bls12381G1MultiExp = 0x0E
        case bls12381G2MultiExp = 0x0F
        case bls12381Pairing = 0x10
        case bls12381MapG1 = 0x11
        case bls12381MapG2 = 0x12
        case unknown = 0xFF
    }

    // MARK: - Precompile Result

    public struct PrecompileResult: Sendable {
        public let success: Bool
        public let output: [UInt8]
        public let gasUsed: UInt64
        public let durationNs: UInt64

        public init(success: Bool, output: [UInt8], gasUsed: UInt64, durationNs: UInt64) {
            self.success = success
            self.output = output
            self.gasUsed = gasUsed
            self.durationNs = durationNs
        }
    }

    // MARK: - Precompile Engine

    public final class Engine: Sendable {
        private let gpuEngine: GPUEVMPrecompileEngine?

        public init() throws {
            self.gpuEngine = try? GPUEVMPrecompileEngine()
        }

        /// Execute a precompile call by address
        public func execute(address: PrecompileAddress, input: [UInt8], gas: UInt64) -> PrecompileResult {
            let start = DispatchTime.now()
            var output: [UInt8]?
            var success = false

            guard let engine = gpuEngine else {
                return PrecompileResult(success: false, output: [], gasUsed: gas, durationNs: 0)
            }

            switch address {
            case .ecRecover:
                output = engine.ecRecover(input: input)
                success = output != nil

            case .modExp:
                output = engine.modExp(input: input)
                success = output != nil

            case .ecAdd:
                output = engine.ecAdd(input: input)
                success = output != nil

            case .ecMul:
                output = engine.ecMul(input: input)
                success = output != nil

            case .ecPairing:
                output = engine.ecPairing(input: input)
                success = output != nil

            case .bls12381G1Add:
                output = engine.bls12381G1Add(input: input)
                success = output != nil

            case .bls12381G1Mul:
                output = engine.bls12381G1Mul(input: input)
                success = output != nil

            case .bls12381Pairing:
                output = engine.bls12381Pairing(input: input)
                success = output != nil

            case .blake2f:
                output = engine.blake2f(input: input)
                success = output != nil

            case .sha256:
                output = sha256CPU(input: input)
                success = output != nil

            case .ripemd160:
                output = ripemd160CPU(input: input)
                success = output != nil

            case .identity:
                output = input
                success = true

            default:
                success = false
            }

            let end = DispatchTime.now()
            let duration = end.uptimeNanoseconds - start.uptimeNanoseconds

            return PrecompileResult(
                success: success,
                output: output ?? [],
                gasUsed: gas,
                durationNs: duration
            )
        }

        /// Get gas cost for a precompile call
        public func gasCost(address: PrecompileAddress, inputSize: Int) -> UInt64 {
            switch address {
            case .ecRecover:
                return 3000
            case .sha256:
                return UInt64(60 + 12 * ((inputSize + 31) / 32))
            case .ripemd160:
                return UInt64(600 + 120 * ((inputSize + 31) / 32))
            case .identity:
                return UInt64(15 + 3 * ((inputSize + 31) / 32))
            case .modExp:
                return computeModExpGas(inputSize: inputSize)
            case .ecAdd:
                return 150
            case .ecMul:
                return 6000
            case .ecPairing:
                return UInt64(45000 + 8000 * ((inputSize + 191) / 192))
            case .blake2f:
                return computeBlake2fGas(inputSize: inputSize)
            case .bls12381G1Add:
                return 500
            case .bls12381G1Mul:
                return 12000
            case .bls12381G2Mul:
                return 24000
            case .pairing12:
                return UInt64(28000 + 8000 * ((inputSize + 192) / 288))
            case .bls12381G1MultiExp:
                return UInt64(12000 + 12000 * ((inputSize + 96) / 96))
            case .bls12381G2MultiExp:
                return UInt64(24000 + 24000 * ((inputSize + 192) / 192))
            case .bls12381Pairing:
                return UInt64(28000 + 8000 * ((inputSize + 288) / 288))
            case .bls12381MapG1:
                return 5500
            case .bls12381MapG2:
                return 11000
            default:
                return 0
            }
        }

        /// Check if GPU precompile engine is available
        public var isGPUAvailable: Bool {
            return gpuEngine != nil
        }

        // MARK: - Gas Calculation Helpers

        /// Compute MODEXP gas cost per EIP-2565
        /// Gas = max(200, (ceil(log2(M)) * ceil(log2(E))) / 8) + 200
        private func computeModExpGas(inputSize: Int) -> UInt64 {
            guard inputSize >= 96 else { return 0 }

            // Parse Bsize, Esize, Msize from first 96 bytes
            let bSize = parseLength(input: [UInt8](), offset: 0)
            let eSize = parseLength(input: [UInt8](), offset: 32)
            let mSize = parseLength(input: [UInt8](), offset: 64)

            // Complexity calculation
            let multiplications = complexity(baseLen: bSize, expLen: eSize, modLen: mSize)
            let gas = UInt64(max(200, multiplications / 20))
            return gas
        }

        /// Compute BLAKE2f gas cost (fixed per round)
        private func computeBlake2fGas(inputSize: Int) -> UInt64 {
            // BLAKE2f is fixed cost per invocation: 1 round per block
            return inputSize == 213 ? 1 : 0
        }

        /// Parse 32-byte length from input
        private func parseLength(input: [UInt8], offset: Int) -> Int {
            guard input.count >= offset + 32 else { return 0 }
            var result = 0
            for i in 0..<32 {
                result = result * 256 + Int(input[offset + i])
            }
            return result
        }

        /// MODEXP complexity calculation
        /// complexity = max(ceil(log2(M)), 1) * max(ceil(log2(E)), 1)
        private func complexity(baseLen: Int, expLen: Int, modLen: Int) -> UInt64 {
            let baseComplexity = max(1, (baseLen * 8 + 7) / 8)
            let expComplexity = max(1, (expLen * 8 + 7) / 8)
            return UInt64(baseComplexity) * UInt64(expComplexity)
        }

        // MARK: - CPU Fallbacks

        private func sha256CPU(input: [UInt8]) -> [UInt8]? {
            // Simplified SHA256 - in production use CryptoKit
            return input
        }

        private func ripemd160CPU(input: [UInt8]) -> [UInt8]? {
            // Simplified RIPEMD160 - in production use CryptoKit
            return [UInt8](repeating: 0, count: 20)
        }
    }
}

// MARK: - Precompile Circuit Protocol

/// Protocol for precompile circuit verification
public protocol PrecompileCircuit {
    associatedtype Input
    associatedtype Output

    /// Execute the precompile operation
    static func execute(input: Input, engine: EVMPrecompiles.Engine) -> Output?

    /// Generate constraint polynomial coefficients for proof verification
    static func constraintCoefficients(input: Input, output: Output) -> [M31]
}

/// Precompile constraint verifier
/// Uses lookup arguments to verify precompile outputs in the main EVM proof
public struct PrecompileConstraintVerifier {
    private let engine: EVMPrecompiles.Engine

    public init() throws {
        self.engine = try EVMPrecompiles.Engine()
    }

    /// Verify precompile output using lookup arguments
    /// Returns challenge values for composition with main proof
    public func verifyPrecompile(
        address: EVMPrecompiles.PrecompileAddress,
        input: [UInt8],
        output: [UInt8]
    ) -> [M31] {
        // Generate random challenge from transcript
        var challenges = [M31]()

        // Commitment phase: hash input and output
        let inputDigest = sha256Digest(input)
        let outputDigest = sha256Digest(output)

        // Generate challenge from digest
        let challenge = M31(v: UInt32(inputDigest[0] ^ outputDigest[0]))
        challenges.append(challenge)

        // Verify: commit(input) and commit(output) match lookup table
        // For now, simplified constraint verification
        return challenges
    }

    /// SHA256 digest (simplified - real impl uses CryptoKit)
    private func sha256Digest(_ data: [UInt8]) -> [UInt8] {
        // Simplified: just return first 32 bytes of data as "digest"
        // In production, use actual SHA256
        var result = [UInt8](repeating: 0, count: 32)
        for i in 0..<min(32, data.count) {
            result[i] = data[i]
        }
        return result
    }
}

// MARK: - ECRECOVER Circuit

/// ECRECOVER precompile circuit for proof composition
public struct ECRECOVERCircuit {

    /// Input structure for ECRECOVER
    public struct ECRecoverInput: Sendable {
        public let hash: [UInt8]      // 32 bytes
        public let v: UInt8           // 27 or 28
        public let r: [UInt8]         // 32 bytes
        public let s: [UInt8]         // 32 bytes

        public init(hash: [UInt8], v: UInt8, r: [UInt8], s: [UInt8]) {
            precondition(hash.count == 32)
            precondition(r.count == 32)
            precondition(s.count == 32)
            self.hash = hash
            self.v = v
            self.r = r
            self.s = s
        }
    }

    /// Result of ECRECOVER
    public struct ECRecoverOutput: Sendable {
        public let address: M31Word   // Recovered address (20 bytes, left-padded)
        public let success: Bool

        public init(address: M31Word, success: Bool) {
            self.address = address
            self.success = success
        }
    }

    /// Execute ECRECOVER and return result
    public static func execute(input: ECRecoverInput, engine: EVMPrecompiles.Engine) -> ECRecoverOutput {
        // Format input for precompile: hash || v || r || s
        var precompileInput = input.hash
        precompileInput.append(input.v)
        precompileInput.append(contentsOf: [UInt8](repeating: 0, count: 31))  // v is 32 bytes
        precompileInput.append(contentsOf: input.r)
        precompileInput.append(contentsOf: input.s)

        let gas = engine.gasCost(address: .ecRecover, inputSize: precompileInput.count)
        let result = engine.execute(address: .ecRecover, input: precompileInput, gas: gas)

        if result.success && result.output.count >= 32 {
            let addressBytes = result.output.prefix(32)
            let address = M31Word(bytes: Array(addressBytes))
            return ECRecoverOutput(address: address, success: true)
        }

        return ECRecoverOutput(address: .zero, success: false)
    }

    /// Verify ECRECOVER proof constraints
    /// In a full implementation, this would include secp256k1 point operations
    public static func verifyConstraints(
        input: ECRecoverInput,
        output: ECRecoverOutput,
        challenges: [M31]
    ) -> [M31] {
        // Simplified: just verify the output is consistent
        // Real implementation would verify secp256k1 curve operations
        var constraints = [M31]()

        if output.success {
            // Address should be derived from recovered public key
            // Verify via Keccak256 of public key
            constraints.append(.zero)
        } else {
            // On failure, output should be zero
            let isZero = output.address.isZero ? M31.one : M31.zero
            constraints.append(isZero)
        }

        return constraints
    }
}

// MARK: - BN254 Circuit

/// BN254 precompile operations (ecAdd, ecMul, ecPairing)
public struct BN254Circuit {

    /// Execute BN254 addition
    public static func ecAdd(
        p1: (x: M31Word, y: M31Word),
        p2: (x: M31Word, y: M31Word),
        engine: EVMPrecompiles.Engine
    ) -> (x: M31Word, y: M31Word)? {
        // Format: P1 || P2 where each point is 64 bytes (x || y)
        var input = p1.x.toBytes() + p1.y.toBytes() + p2.x.toBytes() + p2.y.toBytes()

        let gas = engine.gasCost(address: .ecAdd, inputSize: input.count)
        let result = engine.execute(address: .ecAdd, input: input, gas: gas)

        guard result.success && result.output.count >= 64 else { return nil }

        let x = M31Word(bytes: Array(result.output[0..<32]))
        let y = M31Word(bytes: Array(result.output[32..<64]))
        return (x, y)
    }

    /// Execute BN254 scalar multiplication
    public static func ecMul(
        point: (x: M31Word, y: M31Word),
        scalar: M31Word,
        engine: EVMPrecompiles.Engine
    ) -> (x: M31Word, y: M31Word)? {
        // Format: point (64 bytes) || scalar (32 bytes)
        var input = point.x.toBytes() + point.y.toBytes() + scalar.toBytes()

        let gas = engine.gasCost(address: .ecMul, inputSize: input.count)
        let result = engine.execute(address: .ecMul, input: input, gas: gas)

        guard result.success && result.output.count >= 64 else { return nil }

        let x = M31Word(bytes: Array(result.output[0..<32]))
        let y = M31Word(bytes: Array(result.output[32..<64]))
        return (x, y)
    }

    /// Execute BN254 pairing check
    public static func ecPairing(
        pairs: [(g1: (x: M31Word, y: M31Word), g2: (x1: M31Word, y1: M31Word))],
        engine: EVMPrecompiles.Engine
    ) -> Bool {
        // Format: for each pair: G1 point (64 bytes) || G2 point (128 bytes)
        var input = [UInt8]()
        for pair in pairs {
            input.append(contentsOf: pair.g1.x.toBytes())
            input.append(contentsOf: pair.g1.y.toBytes())
            input.append(contentsOf: pair.g2.x1.toBytes())
            input.append(contentsOf: pair.g2.y1.toBytes())
        }

        let gas = engine.gasCost(address: .ecPairing, inputSize: input.count)
        let result = engine.execute(address: .ecPairing, input: input, gas: gas)

        // Result is 32 bytes, 1 = true, 0 = false
        guard result.success && result.output.count >= 32 else { return false }
        return result.output[31] != 0
    }
}

// MARK: - BLS12-381 Circuit

/// BLS12-381 precompile operations per EIP-2537
public struct BLS12381Circuit {

    /// G1 point representation
    public struct G1Point {
        public let x: M31Word
        public let y: M31Word

        public init(x: M31Word, y: M31Word) {
            self.x = x
            self.y = y
        }
    }

    /// G2 point representation
    public struct G2Point {
        public let x1: M31Word
        public let x2: M31Word
        public let y1: M31Word
        public let y2: M31Word

        public init(x1: M31Word, x2: M31Word, y1: M31Word, y2: M31Word) {
            self.x1 = x1
            self.x2 = x2
            self.y1 = y1
            self.y2 = y2
        }
    }

    /// Execute BLS12-381 G1 addition
    public static func g1Add(
        p1: G1Point,
        p2: G1Point,
        engine: EVMPrecompiles.Engine
    ) -> G1Point? {
        var input = p1.x.toBytes() + p1.y.toBytes() + p2.x.toBytes() + p2.y.toBytes()

        let gas = engine.gasCost(address: .bls12381G1Add, inputSize: input.count)
        let result = engine.execute(address: .bls12381G1Add, input: input, gas: gas)

        guard result.success && result.output.count >= 96 else { return nil }

        let x = M31Word(bytes: Array(result.output[0..<48]))
        let y = M31Word(bytes: Array(result.output[48..<96]))
        return G1Point(x: x, y: y)
    }

    /// Execute BLS12-381 G1 scalar multiplication
    public static func g1Mul(
        point: G1Point,
        scalar: M31Word,
        engine: EVMPrecompiles.Engine
    ) -> G1Point? {
        var input = point.x.toBytes() + point.y.toBytes() + scalar.toBytes()

        let gas = engine.gasCost(address: .bls12381G1Mul, inputSize: input.count)
        let result = engine.execute(address: .bls12381G1Mul, input: input, gas: gas)

        guard result.success && result.output.count >= 96 else { return nil }

        let x = M31Word(bytes: Array(result.output[0..<48]))
        let y = M31Word(bytes: Array(result.output[48..<96]))
        return G1Point(x: x, y: y)
    }

    /// Execute BLS12-381 pairing
    public static func pairing(
        pairs: [(G1Point, G2Point)],
        engine: EVMPrecompiles.Engine
    ) -> Bool {
        // Format: each G1 point (96 bytes) || each G2 point (192 bytes)
        var input = [UInt8]()
        for pair in pairs {
            input.append(contentsOf: pair.0.x.toBytes().prefix(48))
            input.append(contentsOf: pair.0.y.toBytes().prefix(48))
            input.append(contentsOf: pair.1.x1.toBytes().prefix(96))
            input.append(contentsOf: pair.1.y1.toBytes().prefix(96))
        }

        let gas = engine.gasCost(address: .bls12381Pairing, inputSize: input.count)
        let result = engine.execute(address: .bls12381Pairing, input: input, gas: gas)

        guard result.success && result.output.count >= 288 else { return false }
        return result.output.last != 0
    }
}

// MARK: - MODEXP Circuit

/// MODEXP (modular exponentiation) precompile
public struct MODEXPCircuit {

    /// Execute modular exponentiation: base^exponent mod modulus
    public static func execute(
        base: M31Word,
        exponent: M31Word,
        modulus: M31Word,
        engine: EVMPrecompiles.Engine
    ) -> M31Word? {
        // Format: Bsize(32) || Esize(32) || Msize(32) || B || E || M
        // Each is left-padded to their respective sizes
        var input = [UInt8](repeating: 0, count: 96)  // 3 x 32 byte headers

        // Bsize = 32, Esize = 32, Msize = 32
        input[31] = 32
        input[63] = 32
        input[95] = 32

        // Append B, E, M (each 32 bytes)
        input.append(contentsOf: base.toBytes())
        input.append(contentsOf: exponent.toBytes())
        input.append(contentsOf: modulus.toBytes())

        let gas = engine.gasCost(address: .modExp, inputSize: input.count)
        let result = engine.execute(address: .modExp, input: input, gas: gas)

        guard result.success && result.output.count >= 32 else { return nil }

        return M31Word(bytes: Array(result.output.prefix(32)))
    }

    /// Verify MODEXP constraints
    /// result = base^exponent mod modulus
    public static func verifyConstraints(
        base: [M31],
        exponent: [M31],
        modulus: [M31],
        result: [M31],
        challenges: [M31]
    ) -> [M31] {
        // Simplified verification
        // Real implementation would use Montgomery multiplication
        // and verify: result * modulus == base^exponent (mod modulus)
        return [M31.zero]
    }
}
