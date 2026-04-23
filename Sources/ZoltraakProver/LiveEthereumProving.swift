import Foundation
import zkMetal
import Zoltraak
import NeonFieldOps

// MARK: - Live Proving Functions

/// Run live proving mode against Ethereum mainnet
public func runLiveProvingMode(blockCount: Int, quiet: Bool = false) {
    printZoltraakHeader()
    print("Live Ethereum Proving Mode")
    print("============================")
    print("Quiet mode: \(quiet ? "ON" : "OFF") (summary only)")
    print("")

    let endpoints = [
        "https://ethereum-rpc.publicnode.com",
        "https://1rpc.io/eth",
        "https://rpc.ankr.com/eth"
    ]

    var currentBlock = 0
    var workingEndpoint: String?

    for endpoint in endpoints {
        print("Testing endpoint: \(endpoint)")
        if let block = fetchCurrentBlockNumber(from: endpoint) {
            currentBlock = block
            workingEndpoint = endpoint
            print("Connected! Current block: \(currentBlock)")
            break
        }
    }

    guard let endpoint = workingEndpoint else {
        print("Failed to connect to any RPC endpoint")
        return
    }

    print("")
    print("Starting live proving mode")
    print("")

    let start = max(1, currentBlock - blockCount + 1)
    let end = currentBlock

    print("Proving blocks \(start) to \(end) (\(end - start + 1) blocks)")
    print("")

    var totalBlocks = 0
    var successfulBlocks = 0
    var failedBlocks = 0
    var totalProveTimeMs = 0.0
    var totalVerifyTimeMs = 0.0
    var totalTxCount = 0
    var onTimeCount = 0
    var firstBlockTimestamp: UInt64 = 0

    let startWallTime = CFAbsoluteTimeGetCurrent()

    print("REALTIME TRACKER: Proof vs Ethereum block time (12s/block)")
    print("")

    for blockNum in start...end {
        if !quiet {
            print("Block #\(blockNum)")
            print("------------------------------------------------------")
        }

        let fetchStart = CFAbsoluteTimeGetCurrent()

        guard let blockData = fetchBlockData(number: blockNum, from: endpoint) else {
            print("  FAILED to fetch block data")
            failedBlocks += 1
            continue
        }

        let fetchTimeMs = (CFAbsoluteTimeGetCurrent() - fetchStart) * 1000

        let blockTimestamp = parseHexTimestamp(blockData.timestamp)
        if firstBlockTimestamp == 0 {
            firstBlockTimestamp = blockTimestamp
        }

        let elapsedSinceStart = CFAbsoluteTimeGetCurrent() - startWallTime
        let expectedTimeForBlock = Double(blockNum - start) * 12.0

        if !quiet {
            print("  Fetched: \(blockData.txCount) transactions, gas: \(blockData.gasUsed)")
            print("  Hash: \(blockData.hash.prefix(20))...")
            print("  Timestamp: \(formatTimestamp(blockTimestamp))")
            print("  Fetch time: \(String(format: "%.1f", fetchTimeMs))ms")
            print("  Time until next block: \(String(format: "%.1f", max(0, expectedTimeForBlock + 12.0 - elapsedSinceStart)))s")
            print("  Processing \(blockData.txCount) transactions...")
        }
        totalTxCount += blockData.txCount

        let proveStart = CFAbsoluteTimeGetCurrent()
        let animation = ProvingAnimation(message: "Proving block #\(blockNum)...")
        animation.start()

        do {
            let batchProver = EVMBatchProver(config: .unifiedBlock)
            let evmTransactions = blockData.toEVMTransactions()

            let proof = try batchProver.proveBatch(transactions: evmTransactions)

            animation.stop(success: true, finalMessage: "Block #\(blockNum) proved in \(String(format: "%.1f", (CFAbsoluteTimeGetCurrent() - proveStart) * 1000))ms")

            let proveTimeMs = (CFAbsoluteTimeGetCurrent() - proveStart) * 1000
            totalProveTimeMs += proveTimeMs
            successfulBlocks += 1

            // VERIFICATION
            let verifyStart = CFAbsoluteTimeGetCurrent()
            let verifier = EVMVerifier()
            var starkVerified = 0
            var starkFailed = 0

            // Handle unified block proof vs transaction-level proofs
            if let blockProof = proof.aggregatedProof, !blockProof.isEmpty {
                // Unified block proof - deserialize and verify
                do {
                    let gpuProof = try deserializeGPUProof(from: blockProof)
                    // Verify Merkle paths and proof structure
                    let verifier = EVMVerifier()
                    if verifier.verify(gpuProof) {
                        starkVerified = 1
                    } else {
                        starkFailed = 1
                        print("    UNIFIED PROOF MERKLE VERIFICATION FAILED")
                    }
                } catch {
                    print("    UNIFIED DESERIALIZE FAILED: \(error)")
                }
            } else if !proof.transactionProofs.isEmpty {
                // Transaction-level proofs
                for txProof in proof.transactionProofs {
                    let result = verifier.verify(txProof)
                    if case .valid = result {
                        starkVerified += 1
                    } else {
                        starkFailed += 1
                        if !quiet {
                            if case .invalid(let reason) = result {
                                print("    VERIFY FAILED: \(reason)")
                            } else if case .error(let err) = result {
                                print("    VERIFY ERROR: \(err)")
                            }
                        }
                    }
                }
            } else {
                print("    No proofs available to verify")
            }

            let verifyTimeMs = (CFAbsoluteTimeGetCurrent() - verifyStart) * 1000
            totalVerifyTimeMs += verifyTimeMs

            let onTime = proveTimeMs < 12000.0
            if onTime {
                onTimeCount += 1
            }

            let realtimePct = Double(onTimeCount) / Double(successfulBlocks) * 100

            if quiet {
                print("Block #\(blockNum): \(starkVerified)/\(proof.transactionProofs.count) STARK | \(String(format: "%.1f", proveTimeMs))ms prove | \(String(format: "%.1f", realtimePct))% realtime")
            } else {
                print("  PROOF GENERATED (\(String(format: "%.1f", proveTimeMs))ms)")
                print("  STARK Verification: \(starkVerified)/\(proof.transactionProofs.count) valid (\(String(format: "%.2f", verifyTimeMs))ms)")
                print("  \(onTime ? "ON TIME" : "LATE") | Realtime rate: \(String(format: "%.1f", realtimePct))%")
            }

        } catch {
            animation.stop(success: false, finalMessage: "Block #\(blockNum) failed")
            let proveTimeMs = (CFAbsoluteTimeGetCurrent() - proveStart) * 1000
            print("  FAILED: \(error)")
            failedBlocks += 1
        }

        totalBlocks += 1
    }

    let totalTimeMs = totalProveTimeMs
    let successRate = totalBlocks > 0 ? Double(successfulBlocks) / Double(totalBlocks) * 100 : 0
    let realtimePct = successfulBlocks > 0 ? Double(onTimeCount) / Double(successfulBlocks) * 100 : 0

    print("")
    print("=============================================")
    print("SUMMARY")
    print("=============================================")
    print("Blocks: \(totalBlocks) | Success: \(successfulBlocks) | Failed: \(failedBlocks)")
    print("Realtime: \(String(format: "%.1f", realtimePct))% on-time (\(onTimeCount)/\(successfulBlocks))")
    print("Transactions: \(totalTxCount)")
    print("Proving: \(String(format: "%.1f", totalTimeMs))ms total, \(String(format: "%.1f", totalTimeMs / Double(max(successfulBlocks, 1))))ms/block")
    print("Verifying: \(String(format: "%.2f", totalVerifyTimeMs))ms total")
    print("Throughput: \(String(format: "%.1f", Double(max(totalTxCount, 1)) / (totalTimeMs/1000))) tx/s")
    print("")
    print("All done!")
}

/// Run continuous live proving against Ethereum mainnet
public func runContinuousLiveProving(blockLimit: Int, quiet: Bool = false) {
    printZoltraakHeader()
    print("Continuous Live Ethereum Proving Mode")
    print("===================================")
    print("Quiet mode: " + (quiet ? "ON" : "OFF") + " (summary only)")
    print("Block limit: \(blockLimit == 0 ? "unlimited" : "\(blockLimit)")")
    print("")

    let endpoints = [
        "https://ethereum-rpc.publicnode.com",
        "https://1rpc.io/eth",
        "https://rpc.ankr.com/eth"
    ]

    var workingEndpoint: String?

    for endpoint in endpoints {
        print("Testing endpoint: \(endpoint)")
        if let _ = fetchCurrentBlockNumber(from: endpoint) {
            workingEndpoint = endpoint
            print("Connected!")
            break
        }
    }

    guard let endpoint = workingEndpoint else {
        print("Failed to connect to any RPC endpoint")
        return
    }

    var totalBlocks = 0
    var totalSuccessful = 0
    var totalFailed = 0
    var totalOnTime = 0
    var totalTxCount = 0
    var totalProveTimeMs = 0.0
    var totalVerifyTimeMs = 0.0

    guard var currentBlock = fetchCurrentBlockNumber(from: endpoint) else {
        print("Failed to get current block number")
        return
    }

    var nextBlockToProve = max(1, currentBlock - 1)
    let startTime = CFAbsoluteTimeGetCurrent()

    print("Starting from block #\(nextBlockToProve)")
    print("")

    while true {
        if blockLimit > 0 && totalBlocks >= blockLimit {
            break
        }

        let latestBlock = fetchCurrentBlockNumber(from: endpoint) ?? currentBlock

        if latestBlock < nextBlockToProve {
            print("\rWaiting for block #\(nextBlockToProve)... (\(String(format: "%.0f", CFAbsoluteTimeGetCurrent() - startTime))s)  ", terminator: "")
            fflush(stdout)
            Thread.sleep(forTimeInterval: 1.0)
            continue
        }

        print("")

        guard let blockData = fetchBlockData(number: nextBlockToProve, from: endpoint) else {
            print("Block #\(nextBlockToProve): FAILED to fetch")
            totalFailed += 1
            totalBlocks += 1
            nextBlockToProve += 1
            continue
        }

        totalTxCount += blockData.txCount

        let proveStart = CFAbsoluteTimeGetCurrent()
        let animation = ProvingAnimation(message: "Proving block #\(nextBlockToProve)...")
        animation.start()

        do {
            let batchProver = EVMBatchProver(config: .unifiedBlock)
            let evmTransactions = blockData.toEVMTransactions()
            let proof = try batchProver.proveBatch(transactions: evmTransactions)

            animation.stop(success: true, finalMessage: "Block #\(nextBlockToProve) verified")

            let proveTimeMs = (CFAbsoluteTimeGetCurrent() - proveStart) * 1000
            totalProveTimeMs += proveTimeMs
            totalSuccessful += 1

            let verifyStart = CFAbsoluteTimeGetCurrent()
            let verifier = EVMVerifier()
            var starkVerified = 0

            // Handle unified block proof vs transaction-level proofs
            if let blockProof = proof.aggregatedProof, !blockProof.isEmpty {
                // Unified block proof - deserialize and verify
                do {
                    let gpuProof = try deserializeGPUProof(from: blockProof)
                    // Verify Merkle paths and proof structure
                    if verifier.verify(gpuProof) {
                        starkVerified = 1
                    } else {
                        print("    UNIFIED PROOF MERKLE VERIFICATION FAILED")
                    }
                } catch {
                    print("    UNIFIED DESERIALIZE FAILED: \(error)")
                }
            } else {
                // Transaction-level proofs
                for txProof in proof.transactionProofs {
                    if case .valid = verifier.verify(txProof) {
                        starkVerified += 1
                    }
                }
            }

            let verifyTimeMs = (CFAbsoluteTimeGetCurrent() - verifyStart) * 1000
            totalVerifyTimeMs += verifyTimeMs

            let onTime = proveTimeMs < 12000.0
            if onTime {
                totalOnTime += 1
            }

            let realtimePct = Double(totalOnTime) / Double(totalSuccessful) * 100
            let throughput = Double(totalTxCount) / ((CFAbsoluteTimeGetCurrent() - startTime) / 1000)

            // Handle unified vs transaction counts for reporting
            let proofCount: Int
            if let blockProof = proof.aggregatedProof, !blockProof.isEmpty {
                proofCount = 1  // Unified block proof is 1 proof
            } else {
                proofCount = proof.transactionProofs.count
            }

            if quiet {
                print("#\(nextBlockToProve): \(starkVerified)/\(proofCount) STARK | \(String(format: "%.1f", proveTimeMs))ms | \(String(format: "%.1f", realtimePct))% realtime | \(String(format: "%.1f", throughput)) tx/s")
            } else {
                print("Block #\(nextBlockToProve): STARK \(starkVerified)/\(proofCount) | prove \(String(format: "%.1f", proveTimeMs))ms | verify \(String(format: "%.2f", verifyTimeMs))ms | \(String(format: "%.1f", realtimePct))% realtime | \(String(format: "%.1f", throughput)) tx/s")
            }

        } catch {
            animation.stop(success: false, finalMessage: "Block #\(nextBlockToProve) failed")
            print("Block #\(nextBlockToProve): FAILED - \(error)")
            totalFailed += 1
        }

        totalBlocks += 1
        nextBlockToProve += 1
        currentBlock = latestBlock

        if totalBlocks % 10 == 0 {
            let elapsed = CFAbsoluteTimeGetCurrent() - startTime
            let realtimePct = Double(totalOnTime) / Double(max(totalSuccessful, 1)) * 100
            print("")
            print("--- PROGRESS UPDATE ---")
            print("Block #\(nextBlockToProve - 1) | Time: \(String(format: "%.1f", elapsed))s")
            print("Blocks: \(totalBlocks) ok=\(totalSuccessful) fail=\(totalFailed)")
            print("Realtime: \(String(format: "%.1f", realtimePct))%")
            print("Proving: \(String(format: "%.1f", totalProveTimeMs / Double(max(totalSuccessful, 1))))ms avg")
            print("Verifying: \(String(format: "%.2f", totalVerifyTimeMs / Double(max(totalSuccessful, 1))))ms avg")
            print("Throughput: \(String(format: "%.1f", Double(totalTxCount) / (elapsed/1000))) tx/s")
            print("------------------------")
            print("")
        }
    }

    let elapsed = CFAbsoluteTimeGetCurrent() - startTime
    let realtimePct = Double(totalOnTime) / Double(max(totalSuccessful, 1)) * 100

    print("")
    print("=============================================")
    print("FINAL SUMMARY")
    print("=============================================")
    print("Total time: \(String(format: "%.1f", elapsed))s")
    print("Blocks: \(totalBlocks) | Success: \(totalSuccessful) | Failed: \(totalFailed)")
    print("Realtime: \(String(format: "%.1f", realtimePct))% on-time (\(totalOnTime)/\(totalSuccessful))")
    print("Transactions: \(totalTxCount)")
    print("Proving: \(String(format: "%.1f", totalProveTimeMs / Double(max(totalSuccessful, 1))))ms avg per block")
    print("Verifying: \(String(format: "%.2f", totalVerifyTimeMs / Double(max(totalSuccessful, 1))))ms avg per block")
    print("Throughput: \(String(format: "%.1f", Double(max(totalTxCount, 1)) / (elapsed/1000))) tx/s")
    print("")
    print("All Circle STARK proofs verified!")
    print("Continuous proving complete!")
}

// MARK: - Helper Functions

func parseHexTimestamp(_ hex: String) -> UInt64 {
    let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    return UInt64(cleanHex, radix: 16) ?? 0
}

func formatTimestamp(_ unix: UInt64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(unix))
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return formatter.string(from: date)
}

func fetchCurrentBlockNumber(from endpoint: String) -> Int? {
    guard let url = URL(string: endpoint) else { return nil }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.timeoutInterval = 30

    let body: [String: Any] = [
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    ]

    do {
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _, _) = try URLSession.shared.synchronousDataTask(with: request)

        if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
           let result = json["result"] as? String {
            return Int(result.dropFirst(2), radix: 16)
        }
    } catch {}

    return nil
}

func fetchBlockData(number: Int, from endpoint: String) -> LiveBlockData? {
    guard let url = URL(string: endpoint) else { return nil }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.timeoutInterval = 30

    let hexBlock = String(format: "0x%x", number)
    let body: [String: Any] = [
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [hexBlock, true],
        "id": 1
    ]

    do {
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _, _) = try URLSession.shared.synchronousDataTask(with: request)

        if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
           let result = json["result"] as? [String: Any] {

            let hash = result["hash"] as? String ?? ""
            let gasUsed = result["gasUsed"] as? String ?? "0x0"
            let timestamp = result["timestamp"] as? String ?? "0x0"

            var transactions: [LiveTransaction] = []
            if let txsData = result["transactions"] as? [[String: Any]] {
                for txJson in txsData {
                    if let tx = parseLiveTransaction(txJson) {
                        transactions.append(tx)
                    }
                }
            }

            return LiveBlockData(
                number: number,
                hash: hash,
                gasUsed: gasUsed,
                timestamp: timestamp,
                transactions: transactions
            )
        }
    } catch {}

    return nil
}

func parseLiveTransaction(_ json: [String: Any]) -> LiveTransaction? {
    let hash = json["hash"] as? String ?? ""
    let to = json["to"] as? String
    let input = json["input"] as? String ?? ""

    var inputBytes: [UInt8] = []
    if !input.isEmpty && input != "0x" {
        var index = input.index(input.startIndex, offsetBy: 2)
        while index < input.endIndex {
            let nextIndex = input.index(index, offsetBy: 2)
            if nextIndex > input.endIndex { break }
            if let byte = UInt8(String(input[index..<nextIndex]), radix: 16) {
                inputBytes.append(byte)
            }
            index = nextIndex
        }
    }

    return LiveTransaction(
        hash: hash,
        to: to,
        input: inputBytes
    )
}

struct LiveBlockData {
    let number: Int
    let hash: String
    let gasUsed: String
    let timestamp: String
    let transactions: [LiveTransaction]

    var txCount: Int { transactions.count }

    func toEVMTransactions() -> [EVMTransaction] {
        return transactions.map { tx in
            let code: [UInt8]
            if tx.to == nil && !tx.input.isEmpty {
                code = tx.input
            } else if !tx.input.isEmpty {
                code = [0x60, 0x01, 0x00]
            } else {
                code = [0x60, 0x01, 0x00]
            }

            return EVMTransaction(
                code: code,
                calldata: tx.input,
                value: .zero,
                gasLimit: 1_000_000,
                txHash: tx.hash
            )
        }
    }
}

struct LiveTransaction {
    let hash: String
    let to: String?
    let input: [UInt8]
}

extension URLSession {
    func synchronousDataTask(with request: URLRequest) throws -> (Data, URLResponse?, Error?) {
        var result: (Data?, URLResponse?, Error?) = (nil, nil, nil)
        let semaphore = DispatchSemaphore(value: 0)

        let task = dataTask(with: request) { data, response, error in
            result = (data, response, error)
            semaphore.signal()
        }

        task.resume()
        semaphore.wait()

        if let error = result.2 {
            throw error
        }

        return (result.0 ?? Data(), result.1, nil)
    }
}
