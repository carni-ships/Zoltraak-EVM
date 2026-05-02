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
    private var progressPercent: Double = 0
    private var txnCount: Int = 0
    private var txnTotal: Int = 0
    private var showingProgress: Bool = false

    public init(message: String) {
        self.message = message
    }

    public func start() {
        // Print initial spinner to stderr (not redirected in quiet mode)
        fputs("\(ProvingSpinner.frames[0]) \(message)", stderr)
        fflush(stderr)

        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self = self, !self.completed else { return }
            if self.showingProgress {
                // Redraw progress bar in same position on stderr
                let bar = ProgressBar.draw(percent: self.progressPercent)
                fputs("\r├[\(bar)] \(self.txnCount)/\(self.txnTotal) txns \(String(format: "%.0f", self.progressPercent * 100))% - \(self.message)", stderr)
            } else {
                self.frameIndex = (self.frameIndex + 1) % ProvingSpinner.frames.count
                fputs("\r\(ProvingSpinner.frames[self.frameIndex]) \(self.message)", stderr)
            }
            fflush(stderr)
        }
    }

    public func updateMessage(_ newMessage: String) {
        message = newMessage
    }

    /// Update the progress percentage and redraw the progress bar
    /// Uses CR (carriage return) to overwrite the same line
    public func updateProgress(_ percent: Double, txnCount: Int? = nil, total: Int? = nil) {
        self.progressPercent = percent
        if let tx = txnCount, let tot = total {
            self.txnCount = tx
            self.txnTotal = tot
            self.showingProgress = true
        }

        // Build progress string
        let bar = ProgressBar.draw(percent: percent)
        var display: String
        if let tx = txnCount, let tot = total {
            display = "├[\(bar)] \(tx)/\(tot) txns \(String(format: "%.0f", percent * 100))% - \(message)"
        } else {
            display = "├[\(bar)] \(String(format: "%.0f", percent * 100))% - \(message)"
        }

        // CR + clear line + redraw to stderr (stays in place even when stdout is redirected)
        fputs("\r\u{001B}[2K\r\(display)", stderr)
        fflush(stderr)
    }

    public func stop(success: Bool, finalMessage: String? = nil) {
        timer?.invalidate()
        timer = nil
        completed = true

        let symbol = success ? "✓" : "✗"
        let color = success ? "32" : "31"  // green or red

        // Clear line before printing final result to stderr
        if let final = finalMessage {
            fputs("\r\u{001B}[2K\r\u{001B}[\(color)m\(symbol)\u{001B}[0m \(final)\n", stderr)
        } else {
            fputs("\r\u{001B}[2K\r\u{001B}[\(color)m\(symbol)\u{001B}[0m \(message)\n", stderr)
        }
        fflush(stderr)
    }

    public func stopWithProgress(finalMessage: String, percent: Double) {
        timer?.invalidate()
        timer = nil
        completed = true

        let bar = ProgressBar.draw(percent: percent)
        print("\r└[\u{001B}[32m\(bar)\u{001B}[0m] \(finalMessage)            ")
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
    let art = #"""
                                   ..      s                                               ..
   :~\"""88hx.                x .d88"      :8                                         < .z@8"`
 .~      ?888x          u.    5888R      .88       .u    .                            !@88E
 X       '8888k   ...ue888b   '888R     :888ooo  .d88B :@8c        u           u      '888E   u
   H8h    8888X   888R Y888r   888R   -*8888888 ="8888f8888r    us888u.     us888u.    888E u@8NL
  ?888~   8888    888R I888>   888R     8888      4888>'88"  .@88 "8888" .@88 "8888"   888E`"88*"
   %X   .X8*"     888R I888>   888R     8888      4888> '    9888  9888  9888  9888    888E .dN.
   .-"""tnx.     888R I888>   888R     8888      4888>      9888  9888  9888  9888    888E~8888
  :~      8888.  u8888cJ888    888R    .8888Lu=  .d888L .+   9888  9888  9888  9888    888E '888&
  ~       X8888   "*888*P"    .888B .  ^%888*    ^"8888*"    9888  9888  9888  9888    888E  9888.
 ...      '8888L    'Y"       ^*888%     'Y"        "Y"      "888*""888" "888*""888" '"888*" 4888"
'888k     '8888f                "%                            ^Y"   ^Y'   ^Y"   ^Y'     ""    ""
 8888>    <8888
 `888>    X888~
  '"88...x8""
"""#
    print(art)
}
