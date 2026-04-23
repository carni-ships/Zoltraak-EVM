import Foundation
import zkMetal
import Zoltraak

/// Quick test of real Ethereum transaction patterns vs synthetic
public struct QuickBlockComparison {

    public static func runQuickComparison() {
        print("""
        ╔══════════════════════════════════════════════════════════════════╗
        ║     Quick Synthetic vs Real Transaction Comparison               ║
        ╚══════════════════════════════════════════════════════════════════╝

        """)

        let engine = EVMExecutionEngine()

        // Synthetic test (1 + 2 = 3)
        print("🧪 Synthetic Test (1 + 2 = 3)")
        print(String(repeating: "─", count: 50))
        let syntheticCode: [UInt8] = [0x60, 0x01, 0x60, 0x02, 0x01, 0x00]

        do {
            let t0 = CFAbsoluteTimeGetCurrent()
            let result = try engine.execute(code: syntheticCode, calldata: [], value: .zero, gasLimit: 100000)
            let execTime = (CFAbsoluteTimeGetCurrent() - t0) * 1000

            let air = EVMAIR(from: result)
            print("  Execution time: \(String(format: "%.3f", execTime))ms")
            print("  Trace length: \(air.traceLength)")
            print("  AIR columns: \(EVMAIR.numColumns)")
        } catch {
            print("  ERROR: \(error)")
        }

        // Real transaction patterns
        let realPatterns: [(name: String, code: [UInt8])] = [
            ("Multi-Operation", [0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x03, 0x01, 0x60, 0x04, 0x02, 0x00]),
            ("Storage Access", [0x60, 0x01, 0x54, 0x60, 0x02, 0x54, 0x01, 0x60, 0x03, 0x55, 0x00]),
            ("Memory Ops", [0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x02, 0x60, 0x01, 0x52, 0x60, 0x00, 0x51, 0x60, 0x01, 0x51, 0x01, 0x00])
        ]

        for pattern in realPatterns {
            print("\n🔗 Real Pattern: \(pattern.name)")
            print(String(repeating: "─", count: 50))

            do {
                let t0 = CFAbsoluteTimeGetCurrent()
                let result = try engine.execute(code: pattern.code, calldata: [], value: .zero, gasLimit: 1000000)
                let execTime = (CFAbsoluteTimeGetCurrent() - t0) * 1000

                let air = EVMAIR(from: result)
                print("  Execution time: \(String(format: "%.3f", execTime))ms")
                print("  Trace length: \(air.traceLength)")
                print("  AIR columns: \(EVMAIR.numColumns)")
            } catch {
                print("  ERROR: \(error)")
            }
        }

        print("\n" + String(repeating: "=", count: 50))
        print("Quick Comparison Complete!")
        print(String(repeating: "=", count: 50))
    }
}
