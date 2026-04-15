import Foundation
import EVMetal

/// Command-line arguments for running tests:
///   ./EVMetalRunner              - Run all tests
///   ./EVMetalRunner benchmarks   - Run benchmarks
///   ./EVMetalRunner quick       - Run quick tests (skip slow E2E)
///   ./EVMetalRunner gpu         - Run GPU batch tests only
///   ./EVMetalRunner e2e         - Run E2E tests only
///   ./EVMetalRunner opcode      - Run opcode tests only
///   ./EVMetalRunner test <name> - Run specific test by name

let args = ProcessInfo.processInfo.arguments
let mode = args.count > 1 ? args[1] : "tests"
let testFilter = args.count > 2 ? args[2] : nil

switch mode {
case "benchmarks":
    Benchmarks.runAll()

case "profile":
    Benchmarks.runAll()

case "quick":
    print("=== EVMetal Quick Tests (skipping slow E2E) ===\n")
    ProverTests.runQuickTests()

case "gpu":
    print("=== EVMetal GPU Batch Tests ===\n")
    ProverTests.runGPUBatchTests()

case "e2e":
    print("=== EVMetal E2E Tests ===\n")
    ProverTests.runE2ETests()

case "opcode":
    print("=== EVMetal Opcode Tests ===\n")
    ProverTests.runOpcodeTests()

case "test":
    if let filter = testFilter {
        print("=== Running test matching: \(filter) ===\n")
        ProverTests.runTest(named: filter)
    } else {
        print("Usage: ./EVMetalRunner test <test_name>")
    }

default:
    print("=== EVMetal Prover Test Suite ===\n")
    ProverTests.runAllTests()
}
