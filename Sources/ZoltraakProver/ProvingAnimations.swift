import Foundation
import zkMetal

// MARK: - ASCII Animation Utilities

/// Spinner animation frames for proving phases
public enum ProvingSpinner {
    public static let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    public static let runeFrames = ["⚡", "⚙", "⚛", "✦", "✧", "⟡", "◈", "◇", "✵", "✴"]
}

/// Progress bar characters
public struct ProgressBar {
    public static let full = "█"
    public static let half = "▓"
    public static let quarter = "░"

    public static func draw(percent: Double, width: Int = 30) -> String {
        let filled = Int(Double(width) * min(1.0, max(0.0, percent)))
        let empty = width - filled
        return String(repeating: full, count: filled) + String(repeating: "░", count: empty)
    }
}

/// Spinner state for animated proving
public final class ProvingAnimation {
    private var timer: Timer?
    private var frameIndex = 0
    private var message: String
    private var completed: Bool = false

    public init(message: String) {
        self.message = message
    }

    public func start() {
        print("\(ProvingSpinner.frames[0]) \(message)", terminator: "")
        fflush(stdout)

        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self = self, !self.completed else { return }
            self.frameIndex = (self.frameIndex + 1) % ProvingSpinner.frames.count
            print("\r\(ProvingSpinner.frames[self.frameIndex]) \(self.message)", terminator: "")
            fflush(stdout)
        }
    }

    public func updateMessage(_ newMessage: String) {
        message = newMessage
    }

    public func stop(success: Bool, finalMessage: String? = nil) {
        timer?.invalidate()
        timer = nil
        completed = true

        let symbol = success ? "✓" : "✗"
        let color = success ? "32" : "31"  // green or red

        if let final = finalMessage {
            print("\r\u{001B}[\(color)m\(symbol)\u{001B}[0m \(final)")
        } else {
            print("\r\u{001B}[\(color)m\(symbol)\u{001B}[0m \(message)")
        }
    }

    public func stopWithProgress(finalMessage: String, percent: Double) {
        timer?.invalidate()
        timer = nil
        completed = true

        let bar = ProgressBar.draw(percent: percent)
        print("\r┌\(bar)┐ \(finalMessage)")
    }
}

// MARK: - Phase Animation

/// Animated phase display for proving pipeline
public struct PhaseAnimation {
    public let name: String
    public let spinner: ProvingAnimation

    public init(name: String) {
        self.name = name
        self.spinner = ProvingAnimation(message: name)
    }

    public func start() {
        spinner.start()
    }

    public func update(progress: Double) {
        spinner.updateMessage("\(name) \(Int(progress * 100))%")
    }

    public func complete() {
        spinner.stop(success: true, finalMessage: "\(name) complete!")
    }

    public func fail(message: String = "failed") {
        spinner.stop(success: false, finalMessage: "\(name) \(message)")
    }
}

// MARK: - Magic Circle Animation

/// Magic circle frames for Zoltraak branding
public struct MagicCircleAnimation {
    public static let frames: [String] = [
        """
        ✦═══════════════════════════════════════✦
        ║   ◉                         ◉   ║
        ║      ╔═══╗       ╔═══╗         ║
        ║     ╔╝ ● ╚╗     ╔╝ ● ╚╗        ║
        ║     ╚╗   ╔╝     ╚╗   ╔╝        ║
        ║      ╚═══╝       ╚═══╝         ║
        ║   ◉                         ◉   ║
        ✦═══════════════════════════════════════✦
        """,
        """
        ✦═══════════════════════════════════════✦
        ║   ◉                         ◉   ║
        ║      ╔═══╗       ╔═══╗         ║
        ║     ╔╝ ◈ ╚╗     ╔╝ ◈ ╚╗        ║
        ║     ╚╗   ╔╝     ╚╗   ╔╝        ║
        ║      ╚═══╝       ╚═══╝         ║
        ║   ◉                         ◉   ║
        ✦═══════════════════════════════════════✦
        """,
        """
        ✦═══════════════════════════════════════✦
        ║   ◉                         ◉   ║
        ║      ╔═══╗       ╔═══╗         ║
        ║     ╔╝ ◎ ╚╗     ╔╝ ◎ ╚╗        ║
        ║     ╚╗   ╔╝     ╚╗   ╔╝        ║
        ║      ╚═══╝       ╚═══╝         ║
        ║   ◉                         ◉   ║
        ✦═══════════════════════════════════════✦
        """,
        """
        ✦═══════════════════════════════════════✦
        ║   ◉                         ◉   ║
        ║      ╔═══╗       ╔═══╗         ║
        ║     ╔╝ ◉ ╚╗     ╔╝ ◉ ╚╗        ║
        ║     ╚╗   ╔╝     ╚╗   ╔╝        ║
        ║      ╚═══╝       ╚═══╝         ║
        ║   ◉                         ◉   ║
        ✦═══════════════════════════════════════✦
        """
    ]

    public static func animate(duration: TimeInterval = 0.15, iterations: Int = 10) {
        for _ in 0..<iterations {
            for frame in frames {
                print("\u{001B}[2J")  // Clear screen (optional)
                print("\u{001B}[H")  // Move cursor to home
                print("\u{001B}[35m\(frame)\u{001B}[0m")  // Magenta
                usleep(UInt32(duration * 1_000_000))
            }
        }
    }
}

// MARK: - Proof Complete Animation

public struct ProofCompleteAnimation {
    public static func play(elapsedMs: Double, verified: Bool) {
        let symbol = verified ? "✓" : "✗"
        let color = verified ? "32" : "31"

        print("""
        \u{001B}[92m
        ╔══════════════════════════════════════════════╗
        ║                                                      ║
        ║     ⚡ PROOF COMPLETE ⚡                              ║
        ║                                                      ║
        ║     Time: \(String(format: "%.1f", elapsedMs))ms                               ║
        ║     Status: \u{001B}[\(color)m\(symbol) VERIFIED\u{001B}[92m                           ║
        ║                                                      ║
        ╚══════════════════════════════════════════════╝
        \u{001B}[0m
        """)
    }
}

// MARK: - Live Proving Header

public func printZoltraakHeader() {
    print("""
    \u{001B}[36m
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   \u{001B}[35m  ..      s                                               ..     \u{001B}[36m  ║
    ║   \u{001B}[35m :~\"\"\"88hx.                x .d88\"      :8                                         < .z@8\"\` \u{001B}[36m  ║
    ║   \u{001B}[35m.~      ?888x          u.    5888R      .88       .u    .                            !@88E \u{001B}[36m  ║
    ║   \u{001B}[35m X       '8888k   ...ue888b   '888R     :888ooo  .d88B :@8c        u           u      '888E   u \u{001B}[36m  ║
    ║   \u{001B}[35m   H8h    8888X   888R Y888r   888R   -*8888888 =\"8888f8888r    us888u.     us888u.    888E u@8NL \u{001B}[36m  ║
    ║   \u{001B}[35m  ?888~   8888    888R I888>   888R     8888      4888>'88\"  .@88 \"8888\" .@88 \"8888\"   888E\`\"88*\" \u{001B}[36m  ║
    ║   \u{001B}[35m   %X   .X8*\"     888R I888>   888R     8888      4888> '    9888  9888  9888  9888    888E .dN. \u{001B}[36m  ║
    ║   \u{001B}[35m   .-\"\"\"tnx.     888R I888>   888R     8888      4888>      9888  9888  9888  9888    888E~8888 \u{001B}[36m  ║
    ║   \u{001B}[35m  :~      8888.  u8888cJ888    888R    .8888Lu=  .d888L .+   9888  9888  9888  9888    888E '888& \u{001B}[36m  ║
    ║   \u{001B}[35m  ~       X8888   \"*888*P\"    .888B .  ^%888*    ^\"8888*\"    9888  9888  9888  9888    888E  9888. \u{001B}[36m  ║
    ║   \u{001B}[35m ...      '8888L    'Y\"       ^*888%     'Y\"        \"Y\"      \"888*\"\"888\" \"888*\"\"888\" '\"888*\" 4888\" \u{001B}[36m  ║
    ║   \u{001B}[35m'888k     '8888f                \"%                            ^Y\"   ^Y'   ^Y\"   ^Y'     \"\"    \"\" \u{001B}[36m  ║
    ║   \u{001B}[35m 8888>    <8888                                                                   \u{001B}[36m  ║
    ║   \u{001B}[35m \`888>    X888~                                                                   \u{001B}[36m  ║
    ║   \u{001B}[35m  '\"88...x8\"\"                                                                     \u{001B}[36m  ║
    ║   \u{001B}[35m                                                                                         \u{001B}[36m  ║
    ║   \u{001B}[35m                           EVM \u{2022} STARK \u{2022} GPU\u{001B}[36m                                           \u{001B}[35m  ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    \u{001B}[0m
    """)
}