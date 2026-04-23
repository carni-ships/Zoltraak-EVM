import Foundation
import zkMetal

/// Account in the EVM state
public struct Account: Sendable {
    public var address: M31Word
    public var balance: M31Word
    public var code: [UInt8]
    public var codeHash: M31Word  // keccak256(code)
    public var nonce: UInt64

    public init(address: M31Word, balance: M31Word = .zero, code: [UInt8] = [], nonce: UInt64 = 0) {
        self.address = address
        self.balance = balance
        self.code = code
        self.codeHash = code.isEmpty ? .zero : zkMetal.keccak256(code).toM31Word()
        self.nonce = nonce
    }

    public mutating func setCode(_ newCode: [UInt8]) {
        code = newCode
        codeHash = newCode.isEmpty ? .zero : zkMetal.keccak256(newCode).toM31Word()
    }
}

/// Account manager handling all EVM accounts
public final class AccountManager: @unchecked Sendable {
    public var accounts: [String: Account]
    public var accessedAddresses: Set<String>

    public init() {
        self.accounts = [:]
        self.accessedAddresses = []
    }

    public func getAccount(_ address: M31Word) -> Account? {
        accounts[address.toHexString()]
    }

    public func getBalance(_ address: M31Word) -> M31Word {
        accounts[address.toHexString()]?.balance ?? .zero
    }

    public func getCodeSize(_ address: M31Word) -> Int {
        accounts[address.toHexString()]?.code.count ?? 0
    }

    public func getCodeHash(_ address: M31Word) -> M31Word {
        accounts[address.toHexString()]?.codeHash ?? .zero
    }

    public func getCode(_ address: M31Word) -> [UInt8] {
        accounts[address.toHexString()]?.code ?? []
    }

    public func isWarm(_ address: M31Word) -> Bool {
        accessedAddresses.contains(address.toHexString())
    }

    public func markAccessed(_ address: M31Word) {
        accessedAddresses.insert(address.toHexString())
    }

    public func createAccount(_ account: Account) {
        accounts[account.address.toHexString()] = account
    }

    public func transferBalance(from: M31Word, to: M31Word, amount: M31Word) {
        let fromHex = from.toHexString()
        let toHex = to.toHexString()

        if var fromAccount = accounts[fromHex] {
            let (_, overflow) = fromAccount.balance.sub(amount)
            if overflow.v == 0 {
                fromAccount.balance = fromAccount.balance.sub(amount).result
                accounts[fromHex] = fromAccount
            }
        }

        if var toAccount = accounts[toHex] {
            let (newBalance, _) = toAccount.balance.add(amount)
            toAccount.balance = newBalance
            accounts[toHex] = toAccount
        } else {
            let newAccount = Account(address: to, balance: amount)
            accounts[toHex] = newAccount
        }
    }
}

extension [UInt8] {
    func toM31Word() -> M31Word {
        M31Word(bytes: self)
    }
}

/// Maximum stack depth per EVM spec
public let maxStackDepth = 1024

/// Maximum memory size in 32-byte words (2^26 / 32)
public let maxMemoryWords = 1 << 19

/// EVM Stack: 1024 × 256-bit words
public struct EVMStack: Sendable {
    private var items: [M31Word]
    private var height: Int

    public init() {
        self.items = [M31Word](repeating: .zero, count: maxStackDepth)
        self.height = 0
    }

    public var stackHeight: Int { height }

    public mutating func push(_ value: M31Word) {
        precondition(height < maxStackDepth, "Stack overflow")
        items[height] = value
        height += 1
    }

    public mutating func pop() -> M31Word {
        precondition(height > 0, "Stack underflow")
        height -= 1
        let value = items[height]
        items[height] = .zero
        return value
    }

    /// Peek at stack item at given depth (1 = top)
    public func peek(depth: Int) -> M31Word {
        precondition(depth >= 1 && depth <= height, "Invalid stack peek depth")
        return items[height - depth]
    }

    /// Duplicate stack item
    /// - Throws: EVMExecutionError.stackUnderflow if position is invalid
    public mutating func dup(position: Int) throws {
        guard position >= 1 && position <= height else {
            throw EVMExecutionError.stackUnderflow
        }
        let value = items[height - position]
        push(value)
    }

    /// Swap top with position
    /// - Throws: EVMExecutionError.stackUnderflow if position is invalid
    public mutating func swap(position: Int) throws {
        guard position >= 1 && position < height else {
            throw EVMExecutionError.stackUnderflow
        }
        let topIndex = height - 1
        let swapIndex = height - position - 1
        let temp = items[topIndex]
        items[topIndex] = items[swapIndex]
        items[swapIndex] = temp
    }

    /// Get all items for trace (padded to max depth)
    public func traceItems() -> [M31Word] {
        Array(items.prefix(maxStackDepth))
    }

    /// Peek at top N stack items for trace snapshot
    /// - Parameter count: Number of items to peek (max 16 for AIR columns)
    /// - Returns: Array of M31Word from top of stack, newest first
    public func peekWords(count: Int) -> [M31Word] {
        let actualCount = min(count, height)
        return (0..<actualCount).map { items[height - 1 - $0] }
    }
}

/// EVM Memory: Byte-addressable, expands in 32-byte words
public struct EVMMemory: Sendable {
    private var bytes: [UInt8]
    private var wordCount: Int  // Number of 32-byte words

    public init() {
        self.bytes = [UInt8]()
        self.wordCount = 0
    }

    public var size: Int { bytes.count }

    /// Expand memory to include the given offset + size
    public mutating func expand(offset: Int, size: Int) {
        guard size > 0 else { return }
        let required = offset &+ size
        if bytes.count < required {
            let newWordCount = (required + 31) / 32
            if newWordCount > wordCount {
                bytes.append(contentsOf: [UInt8](repeating: 0, count: (newWordCount - wordCount) * 32))
                wordCount = newWordCount
            }
        }
    }

    /// Load a 256-bit (32-byte) word from memory
    public func loadWord(offset: Int) -> M31Word {
        precondition(offset >= 0 && offset + 32 <= bytes.count, "Memory read out of bounds")
        let slice = Array(bytes[offset..<offset + 32])
        return M31Word(bytes: slice)
    }

    /// Store a 256-bit (32-byte) word to memory
    public mutating func storeWord(offset: Int, value: M31Word) {
        expand(offset: offset, size: 32)
        let bytes = value.toBytes()
        for (i, b) in bytes.enumerated() {
            self.bytes[offset + i] = b
        }
    }

    /// Load a single byte from memory
    public func loadByte(offset: Int) -> UInt8 {
        guard offset < bytes.count else { return 0 }
        return bytes[offset]
    }

    /// Store a single byte to memory
    public mutating func storeByte(offset: Int, value: UInt8) {
        expand(offset: offset, size: 1)
        bytes[offset] = value
    }

    /// Copy data from calldata or code
    public mutating func copy(from source: [UInt8], destOffset: Int) {
        expand(offset: destOffset, size: source.count)
        for (i, b) in source.enumerated() {
            bytes[destOffset + i] = b
        }
    }
}

/// EVM Storage: Key-value store with 256-bit keys and values
public struct EVMStorage: Sendable {
    private var storage: [String: M31Word]

    public init() {
        self.storage = [:]
    }

    public func load(key: M31Word) -> M31Word {
        storage[key.toHexString()] ?? .zero
    }

    public mutating func store(key: M31Word, value: M31Word) {
        storage[key.toHexString()] = value
    }

    public func allKeys() -> [M31Word] {
        []  // Simplified
    }

    /// Get storage for proof generation
    public func toProof() -> [(key: M31Word, value: M31Word)] {
        []  // Simplified
    }
}

/// Call frame within the EVM
public struct CallFrame: Sendable {
    public var programCounter: Int
    public var code: [UInt8]
    public var calldata: [UInt8]
    public var returnData: [UInt8]
    public var gas: UInt64
    public var address: M31Word
    public var caller: M31Word
    public var callValue: M31Word
    public var staticFlag: Bool

    public init(code: [UInt8] = [], calldata: [UInt8] = []) {
        self.programCounter = 0
        self.code = code
        self.calldata = calldata
        self.returnData = []
        self.gas = 0
        self.address = .zero
        self.caller = .zero
        self.callValue = .zero
        self.staticFlag = false
    }
}

/// Block context for EVM execution
public struct BlockContext: Sendable {
    public let beneficiary: M31Word      // Coinbase address
    public let gasLimit: UInt64
    public let timestamp: UInt64
    public let number: UInt64
    public let difficulty: M31Word
    public let prevRandao: M31Word
    public let baseFee: M31Word
    public let chainId: M31Word

    /// Block hashes for BLOCKHASH opcode (last 256 blocks)
    /// Index by block number mod 256
    public let blockhashes: [M31Word]

    public init(
        beneficiary: M31Word = .zero,
        gasLimit: UInt64 = 30_000_000,
        timestamp: UInt64 = 0,
        number: UInt64 = 0,
        difficulty: M31Word = .zero,
        prevRandao: M31Word = .zero,
        baseFee: M31Word = .zero,
        chainId: M31Word = M31Word(low64: UInt64(1)),  // Mainnet = 1
        blockhashes: [M31Word] = [M31Word](repeating: .zero, count: 256)
    ) {
        self.beneficiary = beneficiary
        self.gasLimit = gasLimit
        self.timestamp = timestamp
        self.number = number
        self.difficulty = difficulty
        self.prevRandao = prevRandao
        self.baseFee = baseFee
        self.chainId = chainId
        self.blockhashes = blockhashes
    }

    /// Get blockhash for a given block number
    /// BLOCKHASH opcode returns keccak256 of block N for N in [currentBlock-256, currentBlock)
    public func getBlockhash(_ blockNum: UInt64) -> M31Word {
        // Only return hash for recent blocks (last 256)
        guard blockNum < number && number - blockNum <= 256 else {
            return .zero
        }
        let idx = Int(blockNum % 256)
        return idx < blockhashes.count ? blockhashes[idx] : .zero
    }
}

/// Transaction context
public struct TransactionContext: Sendable {
    public let origin: M31Word
    public let gasPrice: M31Word

    public init(origin: M31Word = .zero, gasPrice: M31Word = M31Word(low64: UInt64(1))) {
        self.origin = origin
        self.gasPrice = gasPrice
    }
}

/// Full EVM execution state
public struct EVMState: Sendable {
    // Registers
    public var pc: Int = 0
    public var gas: UInt64 = 0
    public var gasRefund: UInt64 = 0

    // Stack and memory
    public var stack: EVMStack
    public var memory: EVMMemory
    public var storage: EVMStorage

    // Call frames
    public var frames: [CallFrame]
    public var callDepth: Int

    // State
    public var stateRoot: M31Word  // Poseidon2-M31 Merkle root
    public var selfBalance: M31Word

    // Execution control
    public var running: Bool
    public var reverted: Bool
    public var revertedData: [UInt8]

    // Block and transaction context
    public let block: BlockContext
    public let tx: TransactionContext

    // Access list (for EIP-2929)
    public var accessedAddresses: Set<String>
    public var accessedStorageKeys: Set<String>

    // Account management
    public var accountManager: AccountManager

    public init(block: BlockContext = BlockContext(), tx: TransactionContext = TransactionContext()) {
        self.stack = EVMStack()
        self.memory = EVMMemory()
        self.storage = EVMStorage()
        self.frames = [CallFrame()]
        self.callDepth = 0
        self.gas = block.gasLimit
        self.stateRoot = .zero
        self.selfBalance = .zero
        self.running = true
        self.reverted = false
        self.revertedData = []
        self.block = block
        self.tx = tx
        self.accessedAddresses = []
        self.accessedStorageKeys = []
        self.accountManager = AccountManager()

        // Initialize with tx.origin as a default account with balance
        let originAccount = Account(address: tx.origin, balance: M31Word(low64: 1_000_000_000_000_000_000))  // 1000 ETH in wei
        self.accountManager.createAccount(originAccount)
    }

    // MARK: - Current Frame

    public var currentFrame: CallFrame {
        get { frames[callDepth] }
        set { frames[callDepth] = newValue }
    }

    public mutating func pushFrame(_ frame: CallFrame) {
        frames.append(frame)
        callDepth += 1
    }

    public mutating func popFrame() {
        precondition(callDepth > 0, "Cannot pop base frame")
        frames.removeLast()
        callDepth -= 1
    }

    // MARK: - Execution

    public mutating func step(code: [UInt8]) -> EVMTraceRow? {
        guard running else { return nil }
        guard pc < code.count else {
            running = false
            return nil
        }

        let opcode = code[pc]
        let row = EVMTraceRow(
            pc: pc,
            opcode: opcode,
            gas: gas,
            stackHeight: stack.stackHeight,
            stackSnapshot: stack.peekWords(count: 16),
            memorySize: memory.size,
            callDepth: callDepth,
            stateRoot: stateRoot,
            isRunning: running,
            isReverted: reverted,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000)
        )

        pc += 1
        return row
    }

    // MARK: - Gas Tracking

    public var availableGas: UInt64 { gas }

    public mutating func chargeGas(_ amount: UInt64) -> Bool {
        if gas < amount {
            revert(message: "Out of gas")
            return false
        }
        gas -= amount
        return true
    }

    // MARK: - Execution Control

    public mutating func stop() {
        running = false
    }

    public mutating func revert(message: String) {
        running = false
        reverted = true
        revertedData = Array(message.utf8.prefix(32))
    }

    public mutating func returnData(_ data: [UInt8]) {
        currentFrame.returnData = data
    }
}
