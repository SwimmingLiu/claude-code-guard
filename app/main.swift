// ProxyGuard menu-bar dashboard.
//
// A thin visual layer over guard.sh: it never re-implements the checks.
//  - State: reads the report file the launchd agent writes every tick.
//  - "立即检查" / popover refresh: runs `guard.sh --status --json` (read-only).
//  - "仅观察" switch: edits ENFORCE in the installed config.env, then restarts
//    the agent with launchctl kickstart.
//
// Build with build-app.sh; LSUIElement=1 keeps it out of the Dock.

import Cocoa

// ---------------------------------------------------------------- report model

// Lenient decoding: the app and guard.sh are installed independently, and a
// report written by an older guard must still render (missing keys fall back
// to neutral defaults) instead of blanking the whole panel.
struct AnyKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

struct Report: Decodable {
    let ts: Int
    let time: String
    let healthy: Bool
    let verdict: String
    let coverage: String
    let mihomo_ok: Int
    let mihomo_mode: String
    let proc_mode: String
    let tun_on: String
    let tun_dev: String
    let tun_cov: Int
    let mixed_port: String
    let sysproxy_ok: Int
    let sysproxy_desc: String
    let link_up: Int
    let link_iface: String
    let tcp_ok: Int
    let http_ok: Int
    let http_codes: String
    let health_port: String
    let chain_checked: Int
    let chain_direct: Int
    let chain_detail: String
    let chain_audit_ok: Int
    let chain_unverified: Int
    let audit_failed: Int
    let bypass: Int
    let other_direct: Int
    let other_direct_detail: String
    let required_chain: String
    let verify_chains: Int
    let require_chain_audit: Int
    let kill_any_direct: Int
    let enforce: Bool
    let dry_run: Bool
    let simulate: String
    let interval: Int
    let fail_threshold: Int
    let fail_count: Int
    let targets: [Target]
    let hits: [Hit]

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: AnyKey.self)
        func v<T: Decodable>(_ k: String, _ d: T) -> T {
            guard let x = try? c.decodeIfPresent(T.self, forKey: AnyKey(stringValue: k)) else { return d }
            return x
        }
        ts = v("ts", 0)
        time = v("time", "")
        healthy = v("healthy", false)
        verdict = v("verdict", "")
        coverage = v("coverage", "")
        mihomo_ok = v("mihomo_ok", 0)
        mihomo_mode = v("mihomo_mode", "")
        proc_mode = v("proc_mode", "")
        tun_on = v("tun_on", "")
        tun_dev = v("tun_dev", "")
        tun_cov = v("tun_cov", 0)
        mixed_port = v("mixed_port", "")
        sysproxy_ok = v("sysproxy_ok", 0)
        sysproxy_desc = v("sysproxy_desc", "")
        link_up = v("link_up", 0)
        link_iface = v("link_iface", "")
        tcp_ok = v("tcp_ok", 0)
        http_ok = v("http_ok", 0)
        http_codes = v("http_codes", "")
        health_port = v("health_port", "")
        chain_checked = v("chain_checked", 0)
        chain_direct = v("chain_direct", 0)
        chain_detail = v("chain_detail", "")
        chain_audit_ok = v("chain_audit_ok", 0)
        chain_unverified = v("chain_unverified", 0)
        audit_failed = v("audit_failed", 0)
        bypass = v("bypass", 0)
        other_direct = v("other_direct", 0)
        other_direct_detail = v("other_direct_detail", "")
        required_chain = v("required_chain", "")
        verify_chains = v("verify_chains", 0)
        require_chain_audit = v("require_chain_audit", 0)
        kill_any_direct = v("kill_any_direct", 0)
        enforce = v("enforce", false)
        dry_run = v("dry_run", false)
        simulate = v("simulate", "")
        interval = v("interval", 0)
        fail_threshold = v("fail_threshold", 0)
        fail_count = v("fail_count", 0)
        targets = v("targets", [])
        hits = v("hits", [])
    }
}

struct Target: Codable {
    let pid: String
    let kind: String
    let cmd: String
}

struct Hit: Codable {
    let pid: String
    let kind: String
    let remote: String
}

struct Geo: Decodable {
    let fetched_at: Int
    let time: String
    let source: String
    let ip: String
    let city: String
    let region: String
    let country: String
    let postal: String
    let loc: String
    let org: String
    let timezone: String
    let local_time: String
    let system_tz: String
    let tz_env: String
    let tz_applied: Bool
    let address: String
    let location_source: String
    let telemetry_off: Bool
    let cc_env_ok: Bool
    let location_policy: String

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: AnyKey.self)
        func v<T: Decodable>(_ k: String, _ d: T) -> T {
            guard let x = try? c.decodeIfPresent(T.self, forKey: AnyKey(stringValue: k)) else { return d }
            return x
        }
        fetched_at = v("fetched_at", 0)
        time = v("time", "")
        source = v("source", "")
        ip = v("ip", "")
        city = v("city", "")
        region = v("region", "")
        country = v("country", "")
        postal = v("postal", "")
        loc = v("loc", "")
        org = v("org", "")
        timezone = v("timezone", "")
        local_time = v("local_time", "")
        system_tz = v("system_tz", "")
        tz_env = v("tz_env", "")
        tz_applied = v("tz_applied", false)
        address = v("address", "")
        location_source = v("location_source", "")
        telemetry_off = v("telemetry_off", false)
        cc_env_ok = v("cc_env_ok", false)
        location_policy = v("location_policy", "")
    }
}

// ---------------------------------------------------------------- paths / run

enum Paths {
    static let support = FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("proxyguard")
    static let guardScript = support.appendingPathComponent("guard.sh").path
    static let geoScript = support.appendingPathComponent("geo.sh").path
    static let config = support.appendingPathComponent("config.env").path
    static let log = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/proxyguard.log").path
    static let fallbackState = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".cache/proxyguard")

    static var agentLoaded: Bool {
        FileManager.default.fileExists(atPath: guardScript)
    }
}

@discardableResult
func runProcess(_ path: String, _ args: [String], timeout: TimeInterval = 25) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let out = Pipe()
    p.standardOutput = out
    p.standardError = Pipe()
    do { try p.run() } catch { return (-1, "") }
    let deadline = Date().addingTimeInterval(timeout)
    while p.isRunning && Date() < deadline { usleep(40_000) }
    if p.isRunning { p.terminate() }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

func stateDirectory() -> URL {
    guard Paths.agentLoaded else { return Paths.fallbackState }
    let (rc, out) = runProcess("/bin/bash", [Paths.guardScript, "--state-dir"], timeout: 8)
    let trimmed = out.trimmingCharacters(in: .whitespacesAndNewlines)
    if rc == 0, !trimmed.isEmpty { return URL(fileURLWithPath: trimmed) }
    return Paths.fallbackState
}

// ---------------------------------------------------------------- formatting

func relativeAge(_ ts: Int) -> String {
    let secs = max(0, Int(Date().timeIntervalSince1970) - ts)
    if secs < 60 { return "\(secs) 秒前" }
    if secs < 3600 { return "\(secs / 60) 分钟前" }
    return "\(secs / 3600) 小时前"
}

// ---------------------------------------------------------------- theme

/// Appearance-aware palette. Snapshotting a dynamic `NSColor` into a layer
/// (`color.cgColor`) freezes the appearance it had at that moment: after the
/// system switches from dark to light the panel kept its dark background while
/// labels re-resolved to dark text. Everything here is drawn at draw time or
/// redrawn from `viewDidChangeEffectiveAppearance`, never baked into a layer.
enum Theme {
    static func dynamic(_ key: String, light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: NSColor.Name("proxyguard.\(key)")) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        }
    }

    // Text-safe semantics: plain systemGreen/systemOrange are too light for
    // 12 pt labels on a white card.
    static let good = dynamic("good",
        light: NSColor(srgbRed: 0.08, green: 0.51, blue: 0.24, alpha: 1),
        dark: NSColor(srgbRed: 0.32, green: 0.85, blue: 0.46, alpha: 1))
    static let bad = dynamic("bad",
        light: NSColor(srgbRed: 0.75, green: 0.14, blue: 0.14, alpha: 1),
        dark: NSColor(srgbRed: 1.00, green: 0.40, blue: 0.40, alpha: 1))
    static let warn = dynamic("warn",
        light: NSColor(srgbRed: 0.66, green: 0.38, blue: 0.00, alpha: 1),
        dark: NSColor(srgbRed: 1.00, green: 0.68, blue: 0.24, alpha: 1))

    static let panelTop = dynamic("panelTop",
        light: NSColor(srgbRed: 1.000, green: 1.000, blue: 1.000, alpha: 1),
        dark: NSColor(srgbRed: 0.150, green: 0.150, blue: 0.160, alpha: 1))
    static let panelBottom = dynamic("panelBottom",
        light: NSColor(srgbRed: 0.962, green: 0.965, blue: 0.972, alpha: 1),
        dark: NSColor(srgbRed: 0.103, green: 0.103, blue: 0.113, alpha: 1))
    static let cardFill = dynamic("cardFill",
        light: NSColor(white: 0.0, alpha: 0.030),
        dark: NSColor(white: 1.0, alpha: 0.055))
    static let cardBorder = dynamic("cardBorder",
        light: NSColor(white: 0.0, alpha: 0.070),
        dark: NSColor(white: 1.0, alpha: 0.090))
    /// Our own scroll capsule. Neutral, low-contrast and thin: it is a position
    /// cue while scrolling, never chrome that lives on the panel.
    static let scrollThumb = dynamic("scrollThumb",
        light: NSColor(white: 0.0, alpha: 0.22),
        dark: NSColor(white: 1.0, alpha: 0.24))
}

/// Panel chrome: subtle top-to-bottom gradient, status-colored top accent and
/// a hairline border. Redraws whenever the effective appearance changes.
final class PanelBackgroundView: NSView {
    var accentColor: NSColor = Theme.warn {
        didSet { needsDisplay = true }
    }

    override func draw(_ dirtyRect: NSRect) {
        let radius: CGFloat = 14
        let border = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5),
                                  xRadius: radius, yRadius: radius)
        NSGraphicsContext.saveGraphicsState()
        border.addClip()
        if let g = NSGradient(starting: Theme.panelTop, ending: Theme.panelBottom) {
            g.draw(in: bounds, angle: -90)
        }
        NSGraphicsContext.restoreGraphicsState()
        // Inset the accent past the corner radius so it reads as one status
        // line with rounded ends instead of two blocks shaved by the corners.
        let accent = NSRect(x: radius, y: bounds.height - 3,
                            width: max(bounds.width - radius * 2, 0), height: 3)
        accentColor.setFill()
        NSBezierPath(roundedRect: accent, xRadius: 1.5, yRadius: 1.5).fill()
        NSColor.separatorColor.withAlphaComponent(0.75).setStroke()
        border.lineWidth = 1
        border.stroke()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

/// Card background drawn from dynamic colors instead of an `NSBox` fill, so
/// it follows light/dark switches without reloading the panel.
final class CardView: NSView {
    override func draw(_ dirtyRect: NSRect) {
        let p = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5),
                             xRadius: 10, yRadius: 10)
        Theme.cardFill.setFill()
        p.fill()
        Theme.cardBorder.setStroke()
        p.lineWidth = 1
        p.stroke()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

/// Row status, carried by a leading LED glyph instead of a ✓/✗ inside the
/// value text. Color never travels alone: the LED shape differs per status.
enum RowStatus {
    case ok, bad, warn, neutral, info

    var symbol: String {
        switch self {
        case .ok: return "checkmark.circle.fill"
        case .bad: return "xmark.circle.fill"
        case .warn: return "exclamationmark.circle.fill"
        case .neutral: return "minus.circle.fill"
        // A neutral fact with no pass/fail meaning (a process count) must not
        // wear the "not applicable" minus, or the two read the same.
        case .info: return "info.circle.fill"
        }
    }

    var color: NSColor {
        switch self {
        case .ok: return Theme.good
        case .bad: return Theme.bad
        case .warn: return Theme.warn
        case .neutral, .info: return .tertiaryLabelColor
        }
    }
}

/// A template SF Symbol in a fixed 14×14 box, tinted by a semantic color.
func symbolView(_ name: String, size: CGFloat = 12, weight: NSFont.Weight = .medium,
                color: NSColor = .secondaryLabelColor) -> NSImageView {
    let v = NSImageView()
    let cfg = NSImage.SymbolConfiguration(pointSize: size, weight: weight)
    v.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
        .withSymbolConfiguration(cfg)
    v.contentTintColor = color
    v.translatesAutoresizingMaskIntoConstraints = false
    v.widthAnchor.constraint(equalToConstant: 14).isActive = true
    v.heightAnchor.constraint(equalToConstant: 15).isActive = true
    v.setContentHuggingPriority(.required, for: .horizontal)
    v.setContentCompressionResistancePriority(.required, for: .horizontal)
    return v
}

/// Hero status tile: a soft tinted rounded square carrying the shield glyph.
/// This is the one place the panel spends a large color area, so the rest of
/// the cards can stay quiet and let the LED rows do the scanning.
final class StatusBadgeView: NSView {
    var color: NSColor = Theme.warn { didSet { apply() } }
    /// Fires only when the glyph really changes, so the pop below plays on a
    /// status transition and never on a same-state refresh.
    var symbolName = "shield.lefthalf.filled" {
        didSet {
            guard symbolName != oldValue else { return }
            apply()
            // Only acknowledge a change the user can actually see. The first
            // render happens before the panel is ordered front, and a report
            // that moved while the panel was closed must not pop on reopen.
            if window?.isVisible == true {
                Motion.pop(self, key: "badge.pop", peak: 1.10, duration: 0.30)
            }
        }
    }
    private let imageView = NSImageView()

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        imageView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(imageView)
        NSLayoutConstraint.activate([
            imageView.centerXAnchor.constraint(equalTo: centerXAnchor),
            imageView.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
        apply()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func apply() {
        let cfg = NSImage.SymbolConfiguration(pointSize: 24, weight: .semibold)
        imageView.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)?
            .withSymbolConfiguration(cfg)
        imageView.contentTintColor = color
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let tile = bounds.insetBy(dx: 0.5, dy: 0.5)
        let p = NSBezierPath(roundedRect: tile, xRadius: 12, yRadius: 12)
        color.withAlphaComponent(0.13).setFill()
        p.fill()
        color.withAlphaComponent(0.30).setStroke()
        p.lineWidth = 1
        p.stroke()
        // A faint inner wash at the top gives the tile a lit-from-above feel
        // without a gradient layer or a second color.
        NSGraphicsContext.saveGraphicsState()
        p.addClip()
        color.withAlphaComponent(0.06).setFill()
        NSRect(x: tile.minX, y: tile.midY, width: tile.width, height: tile.height / 2).fill()
        NSGraphicsContext.restoreGraphicsState()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

/// Capsule that holds the "just checked" note, so it reads as a transient
/// badge instead of another line of body text.
final class PillView: NSView {
    let label = NSTextField(labelWithString: "")
    private let icon = NSImageView()
    private let box = NSStackView()

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        label.font = NSFont.systemFont(ofSize: 11, weight: .medium)
        label.textColor = .secondaryLabelColor
        label.setContentHuggingPriority(.required, for: .horizontal)
        let cfg = NSImage.SymbolConfiguration(pointSize: 9.5, weight: .semibold)
        icon.image = NSImage(systemSymbolName: "clock.arrow.circlepath",
                             accessibilityDescription: nil)?.withSymbolConfiguration(cfg)
        icon.contentTintColor = .secondaryLabelColor
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 11).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 11).isActive = true
        box.orientation = .horizontal
        box.alignment = .centerY
        box.spacing = 4
        box.addArrangedSubview(icon)
        box.addArrangedSubview(label)
        box.translatesAutoresizingMaskIntoConstraints = false
        addSubview(box)
        NSLayoutConstraint.activate([
            box.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            box.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            box.centerYAnchor.constraint(equalTo: centerYAnchor),
            heightAnchor.constraint(equalToConstant: 20),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    /// A custom NSView has no intrinsic size of its own; derive it from the
    /// capsule's contents so the stack view gives the pill its real width.
    override var intrinsicContentSize: NSSize {
        let inner = box.fittingSize
        return NSSize(width: inner.width + 16, height: 20)
    }

    /// Empty text hides the whole capsule: an empty badge would read as a
    /// broken control. Tint follows the note (neutral, or warn on failure).
    func set(_ text: String, color: NSColor) {
        // A note appearing while the panel is already open fades in at full
        // size; it must not pop like a status change.
        if text != label.stringValue && !text.isEmpty && !isHidden && !Motion.reduceMotion {
            layer?.removeAnimation(forKey: "pill.fade")
            let a = CABasicAnimation(keyPath: "opacity")
            a.fromValue = 0
            a.toValue = 1
            a.duration = 0.18
            a.timingFunction = Motion.easeOut
            layer?.add(a, forKey: "pill.fade")
        }
        label.stringValue = text
        label.textColor = color
        icon.contentTintColor = color
        isHidden = text.isEmpty
        invalidateIntrinsicContentSize()
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        let p = NSBezierPath(roundedRect: bounds, xRadius: bounds.height / 2,
                             yRadius: bounds.height / 2)
        Theme.cardFill.setFill()
        p.fill()
        Theme.cardBorder.setStroke()
        p.lineWidth = 1
        p.stroke()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

/// Guard fields can carry emoji from config (REQUIRED_CHAIN defaults to
/// "🛡️ 静态IP出口"). Next to an LED they read as a second status glyph and
/// can render as a tofu box, so values shown in the panel drop pictographs,
/// variation selectors and control characters.
func displaySafe(_ s: String) -> String {
    s.unicodeScalars
        .filter { sc in
            sc.properties.generalCategory != .otherSymbol
                && !(0xFE00...0xFE0F).contains(sc.value)
                && sc.properties.generalCategory != .control
        }
        .reduce(into: "") { $0.unicodeScalars.append($1) }
        .trimmingCharacters(in: .whitespaces)
}

/// Guard reports "none" when neither TUN nor the system proxy carries egress;
/// the panel says that in words instead of leaking the raw value.
func coverageText(_ coverage: String) -> String {
    let s = displaySafe(coverage)
    return (s.isEmpty || s.lowercased() == "none") ? "未覆盖" : s
}

/// The panel's motion vocabulary in one place: three motions (press feedback,
/// the panel's own entrance/exit, and a pop when a status actually changes),
/// all short and interruptible, all disabled together when the system asks for
/// reduced motion. Durations follow the same scale as the design: a press is
/// immediate (80 ms in, 120 ms back), the panel's exit is faster than its
/// entrance, and the per-card stagger keeps the whole entrance under ~400 ms.
enum Motion {
    /// `PROXYGUARD_REDUCE_MOTION=1` lets the headless checks and the demo
    /// recording exercise the reduced-motion path without touching the
    /// system setting.
    static var reduceMotion: Bool {
        if ProcessInfo.processInfo.environment["PROXYGUARD_REDUCE_MOTION"] == "1" { return true }
        return NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    }

    static let enter: CFTimeInterval = 0.22
    static let exit: CFTimeInterval = 0.14
    static let stagger: CFTimeInterval = 0.04
    static let pressIn: CFTimeInterval = 0.08
    static let pressOut: CFTimeInterval = 0.12
    static let cardRise: CGFloat = 8
    static let panelEnterScale: CGFloat = 0.965
    static let panelExitScale: CGFloat = 0.975
    static let pressScale: CGFloat = 0.965

    /// Decelerating for anything that appears, accelerating for anything that
    /// leaves, so an exit reads as the entrance played backwards and faster.
    static var easeOut: CAMediaTimingFunction {
        CAMediaTimingFunction(controlPoints: 0.22, 1.0, 0.36, 1.0)
    }
    static var easeIn: CAMediaTimingFunction {
        CAMediaTimingFunction(controlPoints: 0.5, 0.0, 0.9, 0.4)
    }

    /// Scale about the **top** edge, not the middle: the panel hangs from the
    /// menu bar, so it must grow down from the shield instead of swelling out
    /// of its own centre. Scaling about the anchor keeps the centre fixed, so
    /// shift the layer back toward the top by half the shrink. A flipped
    /// layer's y axis points down; read it instead of assuming.
    static func scaleFromTop(_ s: CGFloat, height: CGFloat, layer: CALayer?) -> CATransform3D {
        let towardTop: CGFloat = (layer?.isGeometryFlipped ?? false) ? -1 : 1
        let ty = towardTop * height * (1 - s) / 2
        return CATransform3DTranslate(CATransform3DMakeScale(s, s, 1), 0, ty, 0)
    }

    /// Animate a layer transform from one full matrix to another, leaving the
    /// model value at the destination. The from value is usually the
    /// presentation value, so a second animation continues where the first
    /// one was interrupted instead of snapping back to its start.
    static func animateTransform(_ layer: CALayer, from: CATransform3D, to: CATransform3D,
                                 duration: CFTimeInterval, key: String,
                                 easing: CAMediaTimingFunction) {
        let a = CABasicAnimation(keyPath: "transform")
        a.fromValue = NSValue(caTransform3D: from)
        a.toValue = NSValue(caTransform3D: to)
        a.duration = duration
        a.timingFunction = easing
        layer.transform = to
        layer.add(a, forKey: key)
    }

    /// A one-shot "this changed" pop: out, back, settle. The model value never
    /// moves, so the control is never left scaled if the animation is cut off.
    static func pop(_ view: NSView, key: String, peak: CGFloat,
                    duration: CFTimeInterval = 0.26, delay: CFTimeInterval = 0) {
        guard !reduceMotion, let layer = view.layer else { return }
        let a = CAKeyframeAnimation(keyPath: "transform.scale")
        a.values = [1.0, peak, 1.0]
        a.keyTimes = [0, 0.45, 1]
        a.duration = duration
        a.beginTime = CACurrentMediaTime() + delay
        a.fillMode = .backwards
        a.timingFunction = easeOut
        layer.add(a, forKey: key)
    }

    /// Press feedback shared by the primary and the icon buttons: sink on
    /// mouse-down, spring back on mouse-up. The action is sent by AppKit on
    /// mouse-up either way, so the feedback never delays it.
    static func pressDown(_ view: NSView) {
        guard !reduceMotion, let layer = view.layer else { return }
        animateTransform(layer, from: layer.presentation()?.transform ?? CATransform3DIdentity,
                         to: CATransform3DMakeScale(pressScale, pressScale, 1),
                         duration: pressIn, key: "press", easing: easeOut)
    }

    static func pressUp(_ view: NSView) {
        guard !reduceMotion, let layer = view.layer else { return }
        animateTransform(layer, from: layer.presentation()?.transform ?? CATransform3DIdentity,
                         to: CATransform3DIdentity,
                         duration: pressOut, key: "press", easing: easeOut)
    }
}

/// Window content host. The dashboard is a plain subview so the entrance and
/// exit can animate *its* layer instead of the window's contentView layer,
/// which AppKit owns and re-syncs on every resize.
final class PanelHostView: NSView {}

/// A 3 pt scroll capsule for the panel's two scrollable regions. AppKit's own
/// scroller is drawn permanently whenever the system asks for always-visible
/// scroll bars, and on a compact instrument panel that bar is the loudest
/// element on screen. Scrolling itself is untouched (trackpad, wheel, drag in
/// the list); this capsule appears only while the content is actually moving,
/// then fades out, so the resting panel has no bar at all.
final class ScrollThumb: NSView {
    private weak var scrollView: NSScrollView?
    private var hideWork: DispatchWorkItem?
    private var tokens: [NSObjectProtocol] = []
    private var lastOriginY: CGFloat = .nan

    init(_ sv: NSScrollView) {
        scrollView = sv
        super.init(frame: .zero)
        wantsLayer = true
        alphaValue = 0
        isHidden = true
        lastOriginY = sv.contentView.bounds.origin.y
        sv.contentView.postsBoundsChangedNotifications = true
        sv.contentView.postsFrameChangedNotifications = true
        let c = NotificationCenter.default
        func observe(_ name: Notification.Name, object: Any?, _ body: @escaping () -> Void) {
            tokens.append(c.addObserver(forName: name, object: object, queue: .main) { _ in body() })
        }
        observe(NSScrollView.willStartLiveScrollNotification, object: sv) { [weak self] in
            self?.relayout()
            self?.show()
        }
        observe(NSScrollView.didLiveScrollNotification, object: sv) { [weak self] in
            self?.relayout()
            self?.scheduleHide(after: 0.9)
        }
        observe(NSScrollView.didEndLiveScrollNotification, object: sv) { [weak self] in
            self?.scheduleHide(after: 0.45)
        }
        observe(NSView.boundsDidChangeNotification, object: sv.contentView) { [weak self] in
            guard let self = self else { return }
            self.relayout()
            // Wheel and programmatic scrolls arrive here without a live
            // scroll session. A clip *resize* (content grew, panel re-fit)
            // also lands here: only a real scroll offset change may summon
            // the capsule, or every 10 s refresh would make it blink.
            // Read the scroll view through the weak property, never the init
            // parameter: NotificationCenter keeps this block alive, and a
            // strong `sv` here would tie it to the scroll view that owns us,
            // making deinit (and its observer cleanup) unreachable.
            guard let liveSV = self.scrollView else { return }
            let y = liveSV.contentView.bounds.origin.y
            let moved = !self.lastOriginY.isNaN && abs(y - self.lastOriginY) > 0.5
            self.lastOriginY = y
            guard moved else { return }
            if self.alphaValue > 0.01 { self.scheduleHide(after: 0.9) } else { self.show() }
        }
        observe(NSView.frameDidChangeNotification, object: sv.contentView) { [weak self] in
            self?.relayout()
        }
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit {
        hideWork?.cancel()
        for t in tokens { NotificationCenter.default.removeObserver(t) }
    }

    /// Show the capsule once, e.g. when a panel opens with content that does
    /// not fit: the reading is "there is more below", not "a bar lives here".
    func flash() { show() }

    /// Test hook: how many times the capsule was actually summoned.
    private(set) var showCount = 0

    override func draw(_ dirtyRect: NSRect) {
        Theme.scrollThumb.setFill()
        let p = NSBezierPath(roundedRect: bounds, xRadius: bounds.width / 2,
                             yRadius: bounds.width / 2)
        p.fill()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }

    @discardableResult
    private func relayout() -> Bool {
        guard let sv = scrollView, let doc = sv.documentView else { return false }
        let track = sv.contentView.frame
        let docH = doc.frame.height
        let visH = track.height
        let span = docH - visH
        guard span > 0.5, visH > 1 else {
            // Nothing to scroll: there is no position to point at, so the
            // capsule leaves entirely rather than sitting at the top.
            hideNow()
            return false
        }
        let h = max(26, track.height * (visH / docH))
        // Where the visible window sits inside the document, 0 at the top
        // edge and 1 at the bottom, in *visual* terms. This cannot assume an
        // axis direction: NSScrollView is always flipped, while its clip view
        // copies the document's flippedness — the process list's stack is a
        // plain (unflipped) view, so its clip measures upward from a negative
        // origin, and the old `1 - origin/span` never left 1.
        let clip = sv.contentView
        let docTop = doc.isFlipped ? doc.frame.minY : doc.frame.maxY
        let clipTop = clip.isFlipped ? clip.bounds.minY : clip.bounds.maxY
        let downward: CGFloat = clip.isFlipped ? 1 : -1
        let p = min(max((clipTop - docTop) * downward / span, 0), 1)
        let x = sv.bounds.minX + sv.bounds.width - 5
        // Same for the scroll view's own space: y grows downward there, so
        // the top edge is minY and a larger p moves the capsule down.
        let y = sv.isFlipped
            ? track.minY + (track.height - h) * p
            : track.maxY - h - (track.height - h) * p
        frame = NSRect(x: x, y: y, width: 3, height: h)
        needsDisplay = true
        return true
    }

    private func hideNow() {
        hideWork?.cancel()
        alphaValue = 0
        isHidden = true
    }

    /// Never take a click: the capsule is a passive position cue and the
    /// content underneath must stay fully clickable at the panel edge.
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    private func show() {
        guard relayout() else { return }
        showCount += 1
        isHidden = false
        hideWork?.cancel()
        setAlpha(1, duration: 0.10)
        scheduleHide(after: 1.0)
    }

    private func scheduleHide(after delay: TimeInterval) {
        hideWork?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.setAlpha(0, duration: 0.30)
            // Once the fade is done, drop out of the view list entirely: an
            // invisible-but-present view is one more thing every hit test
            // and layout pass has to consider.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.32) { [weak self] in
                guard let self = self, self.alphaValue < 0.01 else { return }
                self.isHidden = true
            }
        }
        hideWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: w)
    }

    private func setAlpha(_ value: CGFloat, duration: TimeInterval) {
        guard !Motion.reduceMotion else {
            alphaValue = value
            return
        }
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = duration
            ctx.timingFunction = Motion.easeOut
            animator().alphaValue = value
        }
    }
}

/// 1 pt inset rule used once, to split coverage checks from audit checks.
final class HairlineView: NSView {
    override var intrinsicContentSize: NSSize { NSSize(width: NSView.noIntrinsicMetric, height: 1) }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.separatorColor.withAlphaComponent(0.55).setFill()
        NSRect(x: 0, y: 0, width: bounds.width, height: 1).fill()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

/// Top-left origin container for the scrollable body, so the stack starts at
/// the top edge and the document height grows downward.
final class FlippedView: NSView {
    override var isFlipped: Bool { true }
}

let goodColor = Theme.good
let badColor = Theme.bad
let warnColor = Theme.warn
/// Fixed panel width. 424 pt was exactly the footer's minimum; 440 leaves
/// breathing room for row values without truncating them.
let panelWidth: CGFloat = 440
/// Outer content inset, shared by the layout and the width self-test.
let outerInset: CGFloat = 18

// ---------------------------------------------------------------- app delegate

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var panel: NSPanel?
    let dashboard = DashboardViewController()

    var report: Report?
    var geo: Geo?
    var reportAge: Int = 9999
    var stateDir = Paths.fallbackState
    var stateDirResolvedAt: TimeInterval = 0
    var liveBusy = false
    /// Bumped on every show and every animated close, so a close that is
    /// still playing cannot hide a panel the user just reopened.
    var closeToken = 0
    /// True from the moment the exit starts until the panel is ordered out.
    /// `isVisible` stays true for that whole 140 ms, so it cannot be used to
    /// tell "open" from "on its way out"; every open/skip decision reads this.
    var isClosing = false
    /// The card stagger plays once per app run: a repeated open must be quick.
    var hasPlayedEntrance = false
    /// Coalesces content-change callbacks into one resize per run-loop turn.
    var fitScheduled = false
    var fileTimer: Timer?
    var liveTimer: Timer?
    var showTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        // Test aid: render a fixed appearance without touching the system.
        if let style = ProcessInfo.processInfo.environment["PROXYGUARD_UI_APPEARANCE"] {
            NSApp.appearance = NSAppearance(named: style == "dark" ? .darkAqua : .aqua)
        }
        refreshStateDir(force: true)
        // A trigger left by `--show` while no instance was running must not
        // pop the panel open on this launch.
        try? FileManager.default.removeItem(at: stateDir.appendingPathComponent("show_panel.request"))

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.target = self
            button.action = #selector(togglePopover(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        dashboard.delegate = self

        reloadFromDisk()
        fileTimer = Timer.scheduledTimer(timeInterval: 5, target: self,
                                         selector: #selector(fileTick), userInfo: nil, repeats: true)
        updateIcon()

        // `ProxyGuard --show` (from a terminal or a second launch) drops a
        // trigger file; poll for it with a fast timer so the panel opens even
        // when distributed notifications are filtered.
        showTimer = Timer.scheduledTimer(timeInterval: 0.5, target: self,
                                         selector: #selector(pollShow), userInfo: nil, repeats: true)

        NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            if event.keyCode == 53, self?.panel?.isVisible == true {   // Esc
                self?.animateClose()
                return nil
            }
            return event
        }
    }

    /// The configured STATE_DIR can change under a running app (install.sh
    /// writes a new config); re-resolve it at a low rate instead of caching
    /// the launch-time value forever.
    func refreshStateDir(force: Bool = false) {
        let now = Date().timeIntervalSince1970
        guard force || now - stateDirResolvedAt > 10 else { return }
        stateDir = stateDirectory()
        stateDirResolvedAt = now
    }

    @objc func pollShow() {
        refreshStateDir()
        let req = stateDir.appendingPathComponent("show_panel.request")
        guard FileManager.default.fileExists(atPath: req.path) else { return }
        try? FileManager.default.removeItem(at: req)
        if panel?.isVisible != true || isClosing { showPanel() }
    }

    // ---- report loading

    @objc func fileTick() {
        refreshStateDir()
        reloadFromDisk()
        if panel?.isVisible == true && !isClosing {
            dashboard.render(report: report, age: reportAge, live: false)
        }
    }

    func reloadFromDisk() {
        let geoURL = stateDir.appendingPathComponent("geo.json")
        if let gdata = try? Data(contentsOf: geoURL),
           let g = try? JSONDecoder().decode(Geo.self, from: gdata) {
            geo = g
        } else {
            geo = nil
        }
        let url = stateDir.appendingPathComponent("last_report.json")
        guard let data = try? Data(contentsOf: url),
              let r = try? JSONDecoder().decode(Report.self, from: data) else {
            report = nil
            reportAge = 9999
            updateIcon()
            return
        }
        report = r
        reportAge = max(0, Int(Date().timeIntervalSince1970) - r.ts)
        updateIcon()
    }

    /// Ask geo.sh for a fresh lookup (location/time profile), then reload.
    func refreshGeo() {
        guard FileManager.default.fileExists(atPath: Paths.geoScript) else { return }
        DispatchQueue.global(qos: .utility).async { [weak self] in
            runProcess("/bin/bash", [Paths.geoScript, "--force", "--quiet"], timeout: 20)
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.reloadFromDisk()
                if self.panel?.isVisible == true && !self.isClosing {
                    self.dashboard.render(report: self.report, age: self.reportAge, live: false)
                }
            }
        }
    }

    /// Run the guard in read-only status mode and show that result immediately.
    /// A blocked upstream can make the HTTP probe take ~21 s, so the process
    /// timeout is generous; one check runs at a time so a slow result cannot
    /// overwrite a newer one.
    func liveCheck() {
        guard Paths.agentLoaded, !liveBusy else { return }
        liveBusy = true
        dashboard.setChecking(true)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let (rc, out) = runProcess("/bin/bash", [Paths.guardScript, "--status", "--json"], timeout: 45)
            let r = out.data(using: .utf8).flatMap { try? JSONDecoder().decode(Report.self, from: $0) }
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.liveBusy = false
                self.dashboard.setChecking(false)
                guard rc == 0, let r = r else {
                    self.dashboard.showLiveFailure(rc == 0 ? "实时检查无结果" : "实时检查超时")
                    return
                }
                self.report = r
                self.reportAge = max(0, Int(Date().timeIntervalSince1970) - r.ts)
                self.updateIcon()
                if self.panel?.isVisible == true && !self.isClosing {
                    self.dashboard.render(report: r, age: self.reportAge, live: true)
                }
            }
        }
    }

    // ---- status icon

    func iconColor() -> NSColor {
        guard Paths.agentLoaded else { return .secondaryLabelColor }
        guard let r = report else { return warnColor }
        if reportAge > 90 { return warnColor }
        return r.healthy ? goodColor : badColor
    }

    func updateIcon() {
        let color = iconColor()
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)
        if let img = NSImage(systemSymbolName: "shield.lefthalf.filled",
                             accessibilityDescription: "ProxyGuard")?
            .withSymbolConfiguration(cfg) {
            img.isTemplate = true
            statusItem.button?.image = img
            statusItem.button?.title = ""
            statusItem.button?.contentTintColor = color
        } else {
            statusItem.button?.title = "PG"
            statusItem.button?.contentTintColor = color
        }
        var tip: String
        if !Paths.agentLoaded {
            tip = "ProxyGuard：守护未安装"
        } else if let r = report {
            tip = "ProxyGuard：\(r.verdict) · \(r.coverage) · \(relativeAge(r.ts))"
        } else {
            tip = "ProxyGuard：还没有守护报告"
        }
        statusItem.button?.toolTip = tip
    }

    // ---- panel

    func makePanel() -> NSPanel {
        let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: panelWidth, height: 700),
                        styleMask: [.borderless, .nonactivatingPanel],
                        backing: .buffered, defer: false)
        p.isFloatingPanel = true
        p.level = .statusBar
        p.hidesOnDeactivate = false
        p.isReleasedWhenClosed = false
        p.backgroundColor = .clear
        p.isOpaque = false
        p.hasShadow = true
        // Never take keyboard focus from the app the user is working in.
        p.becomesKeyOnlyIfNeeded = true
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        // Assign the view directly: with contentViewController AppKit resizes
        // the window to the view's fitting size, which overflows the screen.
        _ = dashboard.view
        // The dashboard sits inside a host view: the entrance/exit animates
        // the dashboard's own layer, while the window's contentView stays a
        // plain view AppKit can resize without fighting a transform.
        let host = PanelHostView(frame: NSRect(x: 0, y: 0, width: panelWidth, height: 700))
        host.autoresizesSubviews = true
        dashboard.view.frame = host.bounds
        dashboard.view.autoresizingMask = [.width, .height]
        dashboard.view.wantsLayer = true
        host.addSubview(dashboard.view)
        p.contentView = host
        return p
    }

    /// Play the panel's entrance: a quick fade with a slight grow from the top
    /// edge, as if the panel came down from the shield. The card stagger runs
    /// only on the session's first open — repeated opens must not feel slow.
    func playEntrance(_ p: NSPanel, continuing: Bool = false) {
        guard !Motion.reduceMotion else {
            p.alphaValue = 1
            dashboard.resetMotionState()
            return
        }
        let h = p.frame.height
        let layer = dashboard.view.layer
        // A panel reopened during its exit is already on screen, partly faded
        // and shrunk. Continue from those presentation values: resetting to
        // alpha 0 / the entrance scale would blink it out and pop it back.
        let fromAlpha: CGFloat = continuing ? min(max(p.alphaValue, 0), 1) : 0
        let fromTransform: CATransform3D
        if continuing, let live = layer?.presentation()?.transform,
           !CATransform3DEqualToTransform(live, CATransform3DIdentity) {
            fromTransform = live
        } else {
            fromTransform = Motion.scaleFromTop(Motion.panelEnterScale, height: h, layer: layer)
        }
        layer?.removeAllAnimations()
        layer?.transform = fromTransform
        p.alphaValue = fromAlpha
        // One fade for the whole panel (window alpha), one transform for the
        // grow. Fading the layer as well would compound the two and read as
        // "faint, then pop" instead of a single arrival.
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = Motion.enter
            ctx.timingFunction = Motion.easeOut
            p.animator().alphaValue = 1
        }
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        let a = CABasicAnimation(keyPath: "transform")
        a.fromValue = NSValue(caTransform3D: fromTransform)
        a.toValue = NSValue(caTransform3D: CATransform3DIdentity)
        a.duration = Motion.enter
        a.timingFunction = Motion.easeOut
        layer?.add(a, forKey: "panel.enter")
        layer?.transform = CATransform3DIdentity
        CATransaction.commit()
        dashboard.playEntrance(firstOpen: !hasPlayedEntrance)
        hasPlayedEntrance = true
    }

    /// Play the exit (faster than the entrance, accelerating), then order the
    /// panel out. A token guards the completion: a quick reopen during the
    /// exit must not be hidden by the previous close finishing late.
    func animateClose() {
        guard let p = panel, p.isVisible, !isClosing else { return }
        liveTimer?.invalidate()
        liveTimer = nil
        guard !Motion.reduceMotion else {
            p.orderOut(nil)
            p.alphaValue = 1
            dashboard.resetMotionState()
            return
        }
        isClosing = true
        closeToken += 1
        let token = closeToken
        let h = p.frame.height
        let scale = Motion.scaleFromTop(Motion.panelExitScale, height: h, layer: dashboard.view.layer)
        let layer = dashboard.view.layer
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = Motion.exit
            ctx.timingFunction = Motion.easeIn
            p.animator().alphaValue = 0
        }
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        let a = CABasicAnimation(keyPath: "transform")
        a.fromValue = NSValue(caTransform3D: layer?.presentation()?.transform ?? CATransform3DIdentity)
        a.toValue = NSValue(caTransform3D: scale)
        a.duration = Motion.exit
        a.timingFunction = Motion.easeIn
        layer?.add(a, forKey: "panel.exit")
        layer?.transform = CATransform3DIdentity      // model never keeps the shrink
        CATransaction.commit()
        DispatchQueue.main.asyncAfter(deadline: .now() + Motion.exit + 0.01) { [weak self] in
            guard let self = self, self.closeToken == token else { return }
            p.orderOut(nil)
            p.alphaValue = 1
            self.isClosing = false
            self.dashboard.resetMotionState()
        }
    }

    func showPanel() {
        guard let button = statusItem.button, let win = button.window else { return }
        if panel == nil { panel = makePanel() }
        guard let p = panel else { return }
        reloadFromDisk()
        dashboard.render(report: report, age: reportAge, live: false)
        let btn = win.convertToScreen(button.convert(button.bounds, to: nil))
        dashboard.view.layoutSubtreeIfNeeded()
        dashboard.syncBodyLayout()
        let screen = win.screen ?? NSScreen.main
        let vf = screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1280, height: 800)
        // The panel wants the body's natural height; if the screen is shorter,
        // clamp it and let the body scroll so the footer stays reachable.
        var size = NSSize(width: panelWidth, height: min(dashboard.desiredPanelHeight(), vf.height - 24))
        size.height = max(size.height, 480)
        var x = btn.midX - size.width / 2
        var y = min(btn.minY - size.height - 6, vf.maxY - size.height - 8)
        x = min(max(x, vf.minX + 8), vf.maxX - size.width - 8)
        y = max(y, vf.minY + 8)
        present(p, frame: NSRect(x: x, y: y, width: size.width, height: size.height))
    }

    /// Place the panel and play its entrance. Shared by the shield click, the
    /// `--show` trigger and the headless motion check, so the tested path is
    /// exactly the shipped one.
    func present(_ p: NSPanel, frame: NSRect, startLive: Bool = true) {
        // Reopening while the exit plays: cancel the pending orderOut and let
        // the entrance continue from what is on screen instead of restarting.
        let continuing = isClosing
        isClosing = false
        closeToken += 1                     // cancel any close still in flight
        p.setFrame(frame, display: true)
        dashboard.view.frame = NSRect(x: 0, y: 0, width: frame.width, height: frame.height)
        dashboard.view.layoutSubtreeIfNeeded()
        dashboard.syncBodyLayout()
        // orderFrontRegardless + a nonactivating panel shows the dashboard
        // without activating ProxyGuard, so typing in Terminal/Claude keeps
        // working. Clicking the shield again closes it.
        if !p.isVisible { p.alphaValue = Motion.reduceMotion ? 1 : 0 }
        p.orderFrontRegardless()
        playEntrance(p, continuing: continuing)
        dashboard.hintBodyScroll()
        guard startLive else { return }
        liveCheck()
        liveTimer?.invalidate()
        liveTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            guard let self = self, self.panel?.isVisible == true else { return }
            self.liveCheck()
        }
    }

    /// A live check or geo refresh can change how much content the panel has
    /// (more processes, a new fault card, a longer IP line). Re-fit the window
    /// while keeping its top edge anchored under the menu bar, so the body
    /// grows with the content instead of clipping it.
    func dashboardContentDidChange() {
        guard panel?.isVisible == true, !isClosing, !fitScheduled else { return }
        fitScheduled = true
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.fitScheduled = false
            self.fitPanelToContent()
        }
    }

    private func fitPanelToContent() {
        guard let p = panel, p.isVisible, !isClosing else { return }
        dashboard.view.layoutSubtreeIfNeeded()
        dashboard.syncBodyLayout()
        let vf = (p.screen ?? NSScreen.main)?.visibleFrame
            ?? NSRect(x: 0, y: 0, width: 1280, height: 800)
        var height = min(dashboard.desiredPanelHeight(), vf.height - 24)
        height = max(height, 480)
        guard abs(p.frame.height - height) > 0.5 else { return }
        let top = p.frame.maxY
        var frame = p.frame
        frame.size.height = height
        frame.origin.y = max(top - height, vf.minY + 8)
        // Snap the window, not a frame animation: the dashboard view is
        // autoresized inside the host, and animating the window would show the
        // already-final content clipped to a growing frame — the bottom of the
        // panel inside the top of the window. The entrance/exit already cover
        // the two moments a size change is visible (open and close).
        p.setFrame(frame, display: true)
        dashboard.view.frame = NSRect(x: 0, y: 0, width: frame.width, height: height)
        dashboard.view.layoutSubtreeIfNeeded()
        dashboard.syncBodyLayout()
        dashboard.hintBodyScroll()
    }

    /// What a click on the shield means right now. `isVisible` stays true for
    /// the whole exit, so it cannot answer this on its own: a click inside
    /// those 140 ms must reopen, not restart the close.
    var isPanelOpenForClick: Bool { panel?.isVisible == true && !isClosing }

    @objc func togglePopover(_ sender: Any?) {
        if isPanelOpenForClick {
            animateClose()
        } else {
            showPanel()
        }
    }

    // ---- actions used by the dashboard

    func openLog() {
        NSWorkspace.shared.open(URL(fileURLWithPath: Paths.log))
    }

    /// Persisted intent, read straight from config.env. The last report is up
    /// to one tick old, so using it for the switch makes a just-toggled state
    /// visibly snap back until the restarted guard writes again.
    func configuredEnforce() -> Bool? {
        guard let text = try? String(contentsOfFile: Paths.config, encoding: .utf8) else { return nil }
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("ENFORCE=") else { continue }
            let v = line.dropFirst("ENFORCE=".count)
                .trimmingCharacters(in: .whitespaces)
            return v == "1" || v.lowercased() == "true"
        }
        return nil
    }

    @discardableResult
    func setEnforce(_ on: Bool) -> Bool {
        guard var text = try? String(contentsOfFile: Paths.config, encoding: .utf8) else { return false }
        var lines = text.components(separatedBy: "\n")
        var found = false
        for (i, line) in lines.enumerated() where line.hasPrefix("ENFORCE=") {
            lines[i] = "ENFORCE=\(on ? "1" : "0")"
            found = true
        }
        if !found { lines.append("ENFORCE=\(on ? "1" : "0")") }
        text = lines.joined(separator: "\n")
        do {
            try text.write(toFile: Paths.config, atomically: true, encoding: .utf8)
        } catch {
            return false
        }
        let uid = getuid()
        let (rc, _) = runProcess("/bin/launchctl",
                                 ["kickstart", "-k", "gui/\(uid)/com.swimmingliu.proxyguard"], timeout: 8)
        reloadFromDisk()
        return rc == 0
    }

    func quit() {
        NSApp.terminate(nil)
    }
}

// ---------------------------------------------------------------- dashboard

/// One check row: a status LED whose glyph and tint carry the state, and the
/// value text, which stays plain so the eye can scan the LED column.
struct CheckRow {
    let led: NSImageView
    let value: NSTextField
}

/// The panel's single primary action, drawn as a filled accent capsule. An
/// NSButton's `bezelColor` is rendered in the inactive gray because this
/// panel never becomes key, so the fill is drawn here instead; the button
/// stays a real NSButton for click, keyboard equivalent and accessibility.
final class FilledActionButton: NSButton {
    private let idleTitle: String
    private let idleIcon: String
    private let checkingTitle: String
    private let checkingIcon: String
    private var glyph: NSImage?
    private var text: String

    /// While a live check runs the label and glyph say so, so the click has
    /// visibly landed even when the guard takes several seconds to answer.
    /// The swap is instant by design: this is state, not a second entrance.
    var isChecking = false {
        didSet {
            guard isChecking != oldValue else { return }
            applyState()
            needsDisplay = true
            invalidateIntrinsicContentSize()
        }
    }

    init(title: String, icon: String,
         checkingTitle: String = "检查中…", checkingIcon: String = "arrow.triangle.2.circlepath",
         target: AnyObject?, action: Selector) {
        idleTitle = title
        idleIcon = icon
        self.checkingTitle = checkingTitle
        self.checkingIcon = checkingIcon
        text = title
        glyph = Self.symbol(icon)
        super.init(frame: .zero)
        self.target = target
        self.action = action
        isBordered = false
        bezelStyle = .regularSquare
        imagePosition = .imageLeading
        image = glyph
        contentTintColor = .white
        focusRingType = .none
        setAccessibilityLabel(title)
        wantsLayer = true
        heightAnchor.constraint(equalToConstant: 26).isActive = true
    }

    private static func symbol(_ name: String) -> NSImage? {
        let cfg = NSImage.SymbolConfiguration(pointSize: 10.5, weight: .semibold)
        return NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(cfg)
    }

    var currentTitle: String { text }

    private func applyState() {
        text = isChecking ? checkingTitle : idleTitle
        glyph = Self.symbol(isChecking ? checkingIcon : idleIcon)
        image = glyph
        setAccessibilityLabel(text)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override var intrinsicContentSize: NSSize {
        let font = NSFont.systemFont(ofSize: 11.5, weight: .semibold)
        // Reserve the wider of the two labels so starting/stopping a live
        // check never makes the footer reflow under the pointer.
        let idleW = (idleTitle as NSString).size(withAttributes: [.font: font]).width
        let checkingW = (checkingTitle as NSString).size(withAttributes: [.font: font]).width
        let w = max(idleW, checkingW)
        let iconW: CGFloat = 14
        return NSSize(width: ceil(w + iconW + 20), height: 26)
    }

    override func mouseDown(with event: NSEvent) {
        Motion.pressDown(self)
        super.mouseDown(with: event)      // blocks while tracking; returns on mouse-up
        Motion.pressUp(self)
    }

    override func draw(_ dirtyRect: NSRect) {
        let p = NSBezierPath(roundedRect: bounds, xRadius: 6, yRadius: 6)
        let base = NSColor.controlAccentColor
        (isHighlighted ? base.blended(withFraction: 0.16, of: .black) ?? base : base).setFill()
        p.fill()
        let font = NSFont.systemFont(ofSize: 11.5, weight: .semibold)
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: NSColor.white]
        let tw = (text as NSString).size(withAttributes: attrs).width
        let iw: CGFloat = glyph == nil ? 0 : 14
        let gap: CGFloat = glyph == nil ? 0 : 5
        let total = iw + gap + tw
        let startX = bounds.midX - total / 2
        if let g = glyph {
            g.draw(in: NSRect(x: startX, y: bounds.midY - 6, width: 14, height: 13))
        }
        let th = (text as NSString).size(withAttributes: attrs).height
        (text as NSString).draw(at: NSPoint(x: startX + iw + gap, y: bounds.midY - th / 2),
                                withAttributes: attrs)
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

/// Icon-only secondary action. Borderless, so AppKit draws no bezel press
/// state — it gets the same sink-and-spring as the primary button instead,
/// which is the only visible acknowledgement a 12 pt glyph otherwise lacks.
final class IconActionButton: NSButton {
    override func mouseDown(with event: NSEvent) {
        Motion.pressDown(self)
        super.mouseDown(with: event)
        Motion.pressUp(self)
    }
}

final class DashboardViewController: NSViewController {
    weak var delegate: AppDelegate?

    private let verdictLabel = NSTextField(labelWithString: "—")
    private let subtitleLabel = NSTextField(labelWithString: "")
    private let badge = StatusBadgeView()
    private var checkRows: [String: CheckRow] = [:]
    private let targetsLabel = NSTextField(labelWithString: "")
    private let targetsBox = NSStackView()
    private let reasonsLabel = NSTextField(labelWithString: "")
    private var reasonsCard: CardView!
    private let geoBox = NSStackView()
    private let geoSourceLabel = NSTextField(labelWithString: "")
    private var geoCardRef: CardView?
    private var targetsCardRef: CardView?
    private var checksCardRef: CardView?
    private var headerRef: NSView?
    /// The primary action, so a live check can show that it is running.
    private var primaryButtonRef: NSButton?
    private var refreshIdleTitle = "立即检查"
    /// nil until the first render decides which card order the panel uses.
    private var cardsOrderedForFaults: Bool?
    private let enforceSwitch = NSSwitch()
    private let enforceCaption = NSTextField(labelWithString: "")
    private let livePill = PillView()
    private var suppressSwitch = false
    /// Turning enforcement off needs a second click within this window.
    private var pendingDisableUntil: TimeInterval = 0
    /// Kept so the layout self-test can measure the content's intrinsic width.
    var widthConstraint: NSLayoutConstraint?
    var footerStack: NSStackView?
    /// The cards live in a scroll view so a long fault list or many Claude
    /// processes can never push the footer off a short screen. The footer is
    /// pinned to the panel bottom and stays visible.
    private let bodyScroll = NSScrollView()
    private let bodyDoc = FlippedView()
    private var bodyStack: NSStackView?
    /// Exposed so the layout self-test can check the process list's scroll range.
    let targetsScroll = NSScrollView()
    private var targetsHeight: NSLayoutConstraint?
    private var bodyThumb: ScrollThumb?
    private var targetsThumb: ScrollThumb?

    override func loadView() {
        let root = PanelBackgroundView(frame: NSRect(x: 0, y: 0, width: panelWidth, height: 700))
        view = root
        // Pin only the width: a long command line inside the targets list must
        // not widen the popover. Do NOT set preferredContentSize here — AppKit
        // turns its height into a required height constraint on the content
        // view, which clamps every later setFrame to that height (the panel
        // stayed 700 pt tall and clipped the last card).
        widthConstraint = root.widthAnchor.constraint(equalToConstant: panelWidth)
        widthConstraint?.isActive = true
        buildUI(in: root)
    }

    private func label(_ text: String, size: CGFloat = 12, weight: NSFont.Weight = .regular,
                       color: NSColor = .labelColor) -> NSTextField {
        let l = NSTextField(labelWithString: text)
        l.font = NSFont.systemFont(ofSize: size, weight: weight)
        l.textColor = color
        l.lineBreakMode = .byTruncatingMiddle
        return l
    }

    private func buildUI(in root: NSView) {
        // header: a tinted shield tile carries the verdict, the verdict text
        // and coverage sit beside it, and the live pill tucks in at the right.
        badge.translatesAutoresizingMaskIntoConstraints = false
        badge.widthAnchor.constraint(equalToConstant: 46).isActive = true
        badge.heightAnchor.constraint(equalToConstant: 46).isActive = true
        badge.setContentHuggingPriority(.required, for: .horizontal)

        verdictLabel.font = NSFont.systemFont(ofSize: 21, weight: .bold)
        verdictLabel.lineBreakMode = .byTruncatingTail
        verdictLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        subtitleLabel.font = NSFont.systemFont(ofSize: 11.5)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.lineBreakMode = .byTruncatingTail
        livePill.set("", color: .secondaryLabelColor)

        let verdictRow = NSStackView(views: [verdictLabel, NSView(), livePill])
        verdictRow.orientation = .horizontal
        verdictRow.alignment = .centerY
        verdictRow.spacing = 8
        livePill.setContentHuggingPriority(.required, for: .horizontal)

        let titleCol = NSStackView(views: [verdictRow, subtitleLabel])
        titleCol.orientation = .vertical
        titleCol.alignment = .leading
        titleCol.spacing = 4
        verdictRow.widthAnchor.constraint(equalTo: titleCol.widthAnchor).isActive = true

        let header = NSStackView(views: [badge, titleCol])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 12
        titleCol.widthAnchor.constraint(equalTo: header.widthAnchor, constant: -58).isActive = true
        // The header must use the full column width; otherwise the live pill
        // (right-aligned via the spacer in verdictRow) is squeezed to nothing.
        titleCol.setContentHuggingPriority(.defaultLow, for: .horizontal)
        header.setContentHuggingPriority(.defaultLow, for: .horizontal)

        // check rows: status LED, a category glyph, label, then the value.
        // Status is shape + color on the LED, so the value text stays plain.
        let checks: [(String, String, String)] = [
            ("mihomo", "控制面", "server.rack"),
            ("tun", "TUN 覆盖", "network"),
            ("sysproxy", "系统代理", "arrow.left.arrow.right"),
            ("connect", "代理连通", "bolt.horizontal.circle"),
            ("rules", "规则审计", "list.bullet.rectangle"),
            ("exit", "出口组", "paperplane"),
            ("procs", "Claude 进程", "square.stack.3d.up"),
            ("socks", "外部连接", "antenna.radiowaves.left.and.right"),
        ]
        var rows: [NSView] = []
        for (key, title, icon) in checks {
            // One hairline, once, splits "is anything carrying egress"
            // (control plane, TUN, system proxy, connectivity) from "is the
            // egress the required one" (rules, exit, processes, sockets).
            if key == "rules" {
                let rule = HairlineView()
                rule.translatesAutoresizingMaskIntoConstraints = false
                rows.append(rule)
            }
            let led = symbolView(RowStatus.neutral.symbol, size: 11, weight: .semibold,
                                 color: RowStatus.neutral.color)
            // The LED is the one small thing on a card that changes state; a
            // layer lets that change pop without disturbing the row layout.
            led.wantsLayer = true
            let kind = symbolView(icon, size: 10.5, weight: .regular)
            let name = label(title, size: 11.5, color: .secondaryLabelColor)
            name.setContentHuggingPriority(.required, for: .horizontal)
            name.widthAnchor.constraint(equalToConstant: 72).isActive = true
            let value = label("—", size: 12, weight: .medium)
            value.lineBreakMode = .byTruncatingTail
            value.setContentHuggingPriority(.defaultLow, for: .horizontal)
            value.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            checkRows[key] = CheckRow(led: led, value: value)
            let row = NSStackView(views: [led, kind, name, value])
            row.orientation = .horizontal
            row.distribution = .fill
            row.spacing = 7
            rows.append(row)
        }
        let checkStack = NSStackView(views: rows)
        checkStack.orientation = .vertical
        checkStack.alignment = .leading
        checkStack.spacing = 7
        for r in rows { r.widthAnchor.constraint(equalTo: checkStack.widthAnchor).isActive = true }

        let checksCard = card(title: "检查项", icon: "checklist", content: checkStack)
        checksCardRef = checksCard
        headerRef = header
        // faults
        reasonsLabel.font = NSFont.systemFont(ofSize: 11.5)
        reasonsLabel.textColor = .labelColor
        reasonsLabel.maximumNumberOfLines = 4
        reasonsLabel.lineBreakMode = .byWordWrapping
        reasonsCard = card(titleView: cardTitle("故障原因", icon: "exclamationmark.triangle.fill",
                                                tint: badColor),
                           content: reasonsLabel)

        // IP identity card
        geoBox.orientation = .vertical
        geoBox.alignment = .leading
        geoBox.spacing = 6
        geoSourceLabel.font = NSFont.systemFont(ofSize: 11.5)
        geoSourceLabel.textColor = .secondaryLabelColor
        let geoContent = NSStackView(views: [geoBox, geoSourceLabel])
        geoContent.orientation = .vertical
        geoContent.alignment = .leading
        geoContent.spacing = 7
        geoBox.widthAnchor.constraint(equalTo: geoContent.widthAnchor).isActive = true
        let geoCard = card(title: "IP 身份（时间 / 地区 / 位置）", icon: "globe", content: geoContent)
        geoCardRef = geoCard

        // targets
        targetsLabel.font = NSFont.systemFont(ofSize: 11.5)
        targetsLabel.textColor = .secondaryLabelColor
        targetsBox.orientation = .vertical
        targetsBox.alignment = .leading
        targetsBox.spacing = 4
        targetsScroll.hasVerticalScroller = false
        targetsScroll.autohidesScrollers = true
        targetsScroll.scrollerStyle = .overlay
        targetsScroll.drawsBackground = false
        targetsScroll.documentView = targetsBox
        targetsBox.translatesAutoresizingMaskIntoConstraints = false
        targetsScroll.translatesAutoresizingMaskIntoConstraints = false
        targetsHeight = targetsScroll.heightAnchor.constraint(equalToConstant: 104)
        targetsHeight?.isActive = true
        let targetsContent = NSStackView(views: [targetsLabel, targetsScroll])
        targetsContent.orientation = .vertical
        targetsContent.alignment = .leading
        targetsContent.spacing = 7
        let targetsCard = card(title: "Claude 链进程", icon: "square.stack.3d.up",
                               content: targetsContent)
        targetsCardRef = targetsCard

        // footer
        // One filled primary action, then icon-only secondary actions (tooltip
        // and accessibility label carry the verb), the toggle on the right.
        func iconButton(_ title: String, _ icon: String, _ action: Selector) -> NSButton {
            let b = IconActionButton(title: "", target: self, action: action)
            b.bezelStyle = .rounded
            b.controlSize = .small
            b.image = NSImage(systemSymbolName: icon,
                              accessibilityDescription: title)?
                .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 11,
                                                                    weight: .medium))
            b.imagePosition = .imageOnly
            // Borderless: the three secondary actions must not wear the same
            // bezel weight as the filled primary one; the glyph plus tooltip
            // is enough, and hover still shows the pointer affordance.
            b.isBordered = false
            b.contentTintColor = .secondaryLabelColor
            b.toolTip = title
            // A fixed 30 pt hit area: an unbordered image button shrinks to
            // the glyph's tight bounds (~12 pt), too small to aim at.
            b.widthAnchor.constraint(equalToConstant: 30).isActive = true
            b.heightAnchor.constraint(equalToConstant: 26).isActive = true
            b.wantsLayer = true
            b.setAccessibilityLabel(title)
            return b
        }
        let refresh = FilledActionButton(title: refreshIdleTitle, icon: "arrow.clockwise",
                                         target: self, action: #selector(refreshTapped))
        refresh.keyEquivalent = "\r"
        primaryButtonRef = refresh
        let geoButton = iconButton("刷新 IP 身份", "mappin.and.ellipse", #selector(refreshGeoTapped))
        let logButton = iconButton("打开日志", "doc.text", #selector(logTapped))
        let quitButton = iconButton("退出 ProxyGuard", "power", #selector(quitTapped))

        enforceSwitch.target = self
        enforceSwitch.action = #selector(enforceToggled)
        enforceSwitch.controlSize = .small
        enforceSwitch.setAccessibilityLabel("强制执行")
        enforceSwitch.toolTip = "开启时，检测到直连会杀掉 magpie / Claude 进程；关闭时只记录"
        enforceCaption.font = NSFont.systemFont(ofSize: 11.5, weight: .medium)
        enforceCaption.textColor = .secondaryLabelColor
        let enforceIcon = symbolView("lock.shield", size: 11, weight: .medium)
        let enforceStack = NSStackView(views: [enforceIcon, enforceSwitch, enforceCaption])
        enforceStack.orientation = .horizontal
        enforceStack.alignment = .centerY
        enforceStack.spacing = 6

        let buttons = NSStackView(views: [refresh, geoButton, logButton, quitButton, NSView(), enforceStack])
        buttons.orientation = .horizontal
        buttons.alignment = .centerY
        buttons.spacing = 8
        footerStack = buttons

        let footerSeparator = NSBox()
        footerSeparator.boxType = .separator

        // assemble: scrollable body, fixed footer
        let stack = NSStackView(views: [header, checksCard, reasonsCard, geoCard, targetsCard])
        stack.orientation = .vertical
        stack.alignment = .leading
        // 7 pt, not 9: on an 803 pt visible screen this is what lets the
        // healthy panel (no fault card) fit without any scroller at all.
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        bodyStack = stack
        bodyDoc.addSubview(stack)

        bodyScroll.drawsBackground = false
        bodyScroll.borderType = .noBorder
        // AppKit's own scroller is off: on a system set to always-show scroll
        // bars it would draw a permanent legacy bar down the panel edge. The
        // custom capsule below does the same job only while scrolling.
        bodyScroll.hasVerticalScroller = false
        bodyScroll.autohidesScrollers = true
        bodyScroll.scrollerStyle = .overlay
        // Horizontal must be off: an NSScrollView with both axes reserves a
        // corner and, more importantly, a hidden horizontal scroller makes the
        // clip view lay the document out at its natural width again, which
        // reintroduced the collapsed value columns this panel had before.
        bodyScroll.hasHorizontalScroller = false
        bodyScroll.horizontalScrollElasticity = .none
        bodyScroll.documentView = bodyDoc
        bodyScroll.translatesAutoresizingMaskIntoConstraints = false
        footerSeparator.translatesAutoresizingMaskIntoConstraints = false
        buttons.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(bodyScroll)
        root.addSubview(footerSeparator)
        root.addSubview(buttons)
        NSLayoutConstraint.activate([
            bodyScroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: outerInset),
            bodyScroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -outerInset),
            bodyScroll.topAnchor.constraint(equalTo: root.topAnchor, constant: outerInset),
            bodyScroll.bottomAnchor.constraint(equalTo: footerSeparator.topAnchor, constant: -10),
            footerSeparator.leadingAnchor.constraint(equalTo: bodyScroll.leadingAnchor),
            footerSeparator.trailingAnchor.constraint(equalTo: bodyScroll.trailingAnchor),
            footerSeparator.bottomAnchor.constraint(equalTo: buttons.topAnchor, constant: -10),
            buttons.leadingAnchor.constraint(equalTo: bodyScroll.leadingAnchor),
            buttons.trailingAnchor.constraint(equalTo: bodyScroll.trailingAnchor),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16),
            stack.leadingAnchor.constraint(equalTo: bodyDoc.leadingAnchor),
            stack.topAnchor.constraint(equalTo: bodyDoc.topAnchor),
            stack.widthAnchor.constraint(equalTo: bodyDoc.widthAnchor),
            stack.bottomAnchor.constraint(equalTo: bodyDoc.bottomAnchor),
            header.widthAnchor.constraint(equalTo: stack.widthAnchor),
            checksCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            reasonsCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            geoCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            targetsCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        bodyDoc.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            bodyDoc.leadingAnchor.constraint(equalTo: bodyScroll.contentView.leadingAnchor),
            bodyDoc.topAnchor.constraint(equalTo: bodyScroll.contentView.topAnchor),
            bodyDoc.widthAnchor.constraint(equalTo: bodyScroll.contentView.widthAnchor),
        ])
        targetsScroll.widthAnchor.constraint(equalTo: targetsCard.widthAnchor, constant: -24).isActive = true
        NSLayoutConstraint.activate([
            targetsBox.leadingAnchor.constraint(equalTo: targetsScroll.contentView.leadingAnchor),
            targetsBox.topAnchor.constraint(equalTo: targetsScroll.contentView.topAnchor),
            targetsBox.widthAnchor.constraint(equalTo: targetsScroll.contentView.widthAnchor),
        ])
        // Thin capsules that appear only while a region actually scrolls.
        // Added last so they sit above card content and the clip view.
        let bt = ScrollThumb(bodyScroll)
        let tt = ScrollThumb(targetsScroll)
        bodyThumb = bt
        targetsThumb = tt
        for thumb in [bt, tt] where thumb.superview == nil {
            (thumb === bt ? bodyScroll : targetsScroll).addSubview(thumb)
        }
    }

    override func viewDidLayout() {
        super.viewDidLayout()
        syncBodyLayout()
    }

    /// Lay out the scrollable body and return the height it needs. The body
    /// stack is pinned top and bottom to the flipped document view, and the
    /// document is pinned top/leading/width to the clip view, so Auto Layout
    /// derives the document height from the cards; the window then grows to
    /// that height (clamped to the screen) instead of clipping the last card.
    @discardableResult
    func syncBodyLayout() -> CGFloat {
        guard isViewLoaded, bodyStack != nil else { return 0 }
        bodyDoc.layoutSubtreeIfNeeded()
        return max(ceil(bodyDoc.frame.height), 1)
    }

    /// Entrance stagger: the header arrives first, then each card 40 ms later,
    /// so the eye is walked down the panel in reading order. Runs once per
    /// app run (the caller decides), only while the panel is visible, and the
    /// layer transform is only ever set by this animation — nothing else on
    /// these views uses their layer, so there is no interference.
    func playEntrance(firstOpen: Bool) {
        guard isViewLoaded, !Motion.reduceMotion else { return }
        let header = [headerRef].compactMap { $0 }
        let cards: [NSView] = [checksCardRef, reasonsCard, geoCardRef, targetsCardRef]
            .compactMap { $0 }
            .filter { !$0.isHidden }
        guard firstOpen else {
            // Repeat opens: header and cards fade in together, briefly. It is
            // the same entrance played shorter, not a second kind of motion.
            for (i, v) in (header + cards).enumerated() {
                fadeIn(v, delay: Double(i) * 0.012, duration: 0.16)
            }
            return
        }
        for (i, v) in (header + cards).enumerated() {
            riseIn(v, delay: Double(i) * Motion.stagger)
        }
    }

    private func riseIn(_ v: NSView, delay: CFTimeInterval) {
        guard let layer = v.layer else { return }
        layer.removeAnimation(forKey: "entrance")
        let a = CAKeyframeAnimation(keyPath: "transform.translation.y")
        a.values = [Motion.cardRise, 0]
        a.keyTimes = [0, 1]
        a.duration = Motion.enter
        a.beginTime = CACurrentMediaTime() + delay
        a.fillMode = .backwards
        a.timingFunction = Motion.easeOut
        layer.add(a, forKey: "entrance")
        let fade = CABasicAnimation(keyPath: "opacity")
        fade.fromValue = 0
        fade.toValue = 1
        fade.duration = Motion.enter
        fade.beginTime = a.beginTime
        fade.fillMode = .backwards
        fade.timingFunction = Motion.easeOut
        layer.add(fade, forKey: "entrance.fade")
    }

    private func fadeIn(_ v: NSView, delay: CFTimeInterval, duration: CFTimeInterval) {
        guard let layer = v.layer else { return }
        let fade = CABasicAnimation(keyPath: "opacity")
        fade.fromValue = 0
        fade.toValue = 1
        fade.duration = duration
        fade.beginTime = CACurrentMediaTime() + delay
        fade.fillMode = .backwards
        fade.timingFunction = Motion.easeOut
        layer.add(fade, forKey: "entrance.fade")
    }

    /// Undo every entrance/exit artifact so a closed or reopened panel starts
    /// from a clean, fully visible state even if it was closed mid-animation.
    func resetMotionState() {
        guard isViewLoaded else { return }
        for v in view.subviews + [view] { v.layer?.removeAllAnimations() }
        let all: [NSView] = [headerRef, checksCardRef, reasonsCard, geoCardRef, targetsCardRef]
            .compactMap { $0 }
        for v in all {
            v.layer?.removeAllAnimations()
            v.layer?.transform = CATransform3DIdentity
            v.layer?.opacity = 1
        }
        view.layer?.transform = CATransform3DIdentity
        view.layer?.opacity = 1
        clearPressState(view)
    }

    /// A press sink leaves the button's model transform at the sunk scale only
    /// until mouse-up springs it back. If the panel was ordered out mid-press
    /// the spring never ran, so a reopened panel would show a shrunken button;
    /// this walks the tree and resets any button left sunk.
    private func clearPressState(_ v: NSView) {
        v.layer?.removeAnimation(forKey: "press")
        v.layer?.transform = CATransform3DIdentity
        for s in v.subviews { clearPressState(s) }
    }

    /// Height the panel wants: body plus the fixed footer, separator and
    /// insets. The app clamps this to the screen and lets the body scroll.
    func desiredPanelHeight() -> CGFloat {
        guard isViewLoaded else { return 480 }
        let body = syncBodyLayout()
        let footer = max(footerStack?.fittingSize.height ?? 22, 22)
        return ceil(outerInset + body + 10 + 1 + 10 + footer + 16)
    }

    /// Briefly show the overlay scrollbar when the cards do not fit, so the
    /// clipped card at the bottom reads as "scroll for more" rather than lost.
    func hintBodyScroll() {
        guard isViewLoaded else { return }
        if bodyDoc.frame.height > bodyScroll.contentSize.height + 0.5 {
            bodyThumb?.flash()
        }
    }

    /// In an unhealthy panel the question is "which process is direct", so the
    /// process list moves above the identity card. Healthy panels keep the
    /// identity card first. Only the order changes, so the swap is cheap and
    /// the panel re-fits its height right after.
    private func reorderCards(unhealthy: Bool) {
        guard let stack = bodyStack, let geo = geoCardRef, let targets = targetsCardRef,
              cardsOrderedForFaults != unhealthy else { return }
        cardsOrderedForFaults = unhealthy
        let first = unhealthy ? targets : geo
        let second = unhealthy ? geo : targets
        stack.removeArrangedSubview(first)
        stack.removeArrangedSubview(second)
        let afterReasons = stack.arrangedSubviews.firstIndex(of: reasonsCard)
            .map { $0 + 1 } ?? stack.arrangedSubviews.count
        stack.insertArrangedSubview(first, at: afterReasons)
        stack.insertArrangedSubview(second, at: afterReasons + 1)
    }

    private func card(title: String, icon: String, content: NSView) -> CardView {
        card(titleView: cardTitle(title, icon: icon), content: content)
    }

    /// Card title = small glyph + name. The glyph is what makes the four
    /// sections tell apart at a glance; it stays secondary so it never
    /// competes with the status LEDs.
    private func cardTitle(_ text: String, icon: String,
                           tint: NSColor = .secondaryLabelColor) -> NSView {
        let t = label(text, size: 12.5, weight: .semibold, color: .labelColor)
        t.setContentHuggingPriority(.required, for: .horizontal)
        let row = NSStackView(views: [symbolView(icon, size: 10.5, weight: .semibold,
                                                 color: tint), t])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 6
        return row
    }

    private func card(titleView: NSView, content: NSView) -> CardView {
        let card = CardView()
        let inner = NSStackView(views: [titleView, content])
        inner.orientation = .vertical
        inner.alignment = .leading
        inner.spacing = 8
        inner.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(inner)
        NSLayoutConstraint.activate([
            inner.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            inner.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -12),
            inner.topAnchor.constraint(equalTo: card.topAnchor, constant: 10),
            inner.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -11),
            // The inner stack aligns leading, so without this the row stacks
            // keep their intrinsic (collapsed) width and long values truncate
            // in a narrow column instead of using the card.
            content.widthAnchor.constraint(equalTo: inner.widthAnchor),
        ])
        return card
    }

    // ---- render

    func render(report: Report?, age: Int, live: Bool) {
        guard isViewLoaded else { return }

        guard let r = report else {
            verdictLabel.stringValue = "暂无报告"
            verdictLabel.textColor = .secondaryLabelColor
            subtitleLabel.textColor = .secondaryLabelColor
            subtitleLabel.stringValue = Paths.agentLoaded
                ? "等待守护写入第一份报告（约 10 秒）"
                : "守护尚未安装：先运行项目里的 install.sh"
            badge.color = warnColor
            badge.symbolName = "shield.lefthalf.filled"
            (view as? PanelBackgroundView)?.accentColor = warnColor
            for (_, row) in checkRows { setLED(row, .neutral) ; row.value.stringValue = "—" }
            reasonsLabel.stringValue = ""
            reasonsCard.isHidden = true
            targetsLabel.stringValue = "—"
            rebuildTargets([])
            renderGeo(delegate?.geo)
            let configured = delegate?.configuredEnforce()
            let pending = Date().timeIntervalSince1970 < pendingDisableUntil
            suppressSwitch = true
            enforceSwitch.state = (!pending && (configured ?? false)) ? .on : .off
            suppressSwitch = false
            if pending {
                enforceCaption.stringValue = "再点一次关闭"
                enforceCaption.textColor = warnColor
                enforceSwitch.setAccessibilityLabel("强制执行已请求关闭，再点一次确认")
            } else {
                enforceCaption.stringValue = configured == nil ? "" : ((configured ?? false) ? "强制执行" : "仅观察")
                enforceSwitch.setAccessibilityLabel("强制执行")
            }
            enforceSwitch.isEnabled = Paths.agentLoaded
            livePill.set("", color: .secondaryLabelColor)
            syncBodyLayout()
            delegate?.dashboardContentDidChange()
            return
        }

        let enforceOn = delegate?.configuredEnforce() ?? r.enforce
        let pending = Date().timeIntervalSince1970 < pendingDisableUntil
        // The menu-bar icon already turns orange after 90 s without a fresh
        // report; the panel must not keep claiming a green verdict for the
        // same stale data.
        let stale = age > 90

        verdictLabel.stringValue = stale ? "现状未知" : (r.healthy ? "代理正常" : "未走代理")
        verdictLabel.textColor = stale ? warnColor : (r.healthy ? goodColor : badColor)
        var sub = "\(coverageText(r.coverage)) · \(relativeAge(r.ts))"
        if stale {
            // The panel answers "is it normal right now". With a stale report
            // that answer is "unknown", and the last confirmed verdict follows
            // as history instead of pretending to be current. Coverage stays
            // out of this line when stale — the TUN / 系统代理 rows carry it.
            sub = "报告 \(relativeAge(r.ts)) · 上次确认：\(r.healthy ? "代理正常" : "未走代理")"
        }
        if r.fail_count > 0 { sub += " · 连续 \(r.fail_count) 次失败" }
        if !Paths.agentLoaded { sub = "守护未安装" }
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.stringValue = sub
        subtitleLabel.toolTip = sub
        let statusColor = stale ? warnColor : (r.healthy ? goodColor : badColor)
        badge.color = statusColor
        badge.symbolName = stale ? "clock.badge.exclamationmark" : (r.healthy ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
        (view as? PanelBackgroundView)?.accentColor = statusColor

        livePill.set(live ? "刚刚实时检查" : "", color: live ? Theme.good : .secondaryLabelColor)

        setRow("mihomo", r.mihomo_mode.isEmpty ? "不可达" : "\(r.mihomo_mode) / \(r.proc_mode.isEmpty ? "-" : r.proc_mode)",
               status: r.mihomo_ok == 1 ? .ok : .bad)
        // TUN is one of two coverage paths. When the system proxy carries
        // egress, "TUN 未覆盖" is informational, not a failure, and must not
        // render as a red LED next to a green verdict.
        let tunOK = r.tun_cov == 1
        let tunCoveredBySys = !tunOK && r.sysproxy_ok == 1
        let tunValue: String
        if tunOK {
            tunValue = r.tun_dev.isEmpty ? "已覆盖" : r.tun_dev
        } else if tunCoveredBySys {
            tunValue = "未覆盖（系统代理已覆盖）"
        } else {
            tunValue = r.tun_dev.isEmpty ? (r.tun_on == "false" ? "未开启" : "未知") : r.tun_dev
        }
        setRow("tun", tunValue, status: tunOK ? .ok : (tunCoveredBySys ? .neutral : .bad))
        // A missing system proxy is fine when TUN covers egress; do not paint
        // it as a hard failure, and never leave the status to color alone.
        let sysOK = r.sysproxy_ok == 1
        let tunCoversSys = !sysOK && r.tun_cov == 1
        let sysDesc = r.sysproxy_desc.isEmpty ? (sysOK ? "已设置" : "未设置") : r.sysproxy_desc
        let sysText = sysOK ? sysDesc : (tunCoversSys ? "未设置（TUN 覆盖）" : sysDesc)
        setRow("sysproxy", displaySafe(sysText), status: sysOK ? .ok : (tunCoversSys ? .neutral : .bad))
        // skipped(tun) means the probe was intentionally skipped, not failed.
        let httpSkipped = r.http_codes.lowercased().contains("skipped")
        let connOK = r.tcp_ok == 1 && (r.http_ok == 1 || httpSkipped)
        var connParts = ["TCP \(r.tcp_ok == 1 ? "通" : "不通")"]
        if httpSkipped {
            connParts.append("HTTP 已跳过（TUN）")
        } else if r.http_ok == 1 {
            connParts.append("HTTP 通" + (r.http_codes.isEmpty ? "" : " · \(r.http_codes)"))
        } else {
            connParts.append("HTTP 失败" + (r.http_codes.isEmpty ? "" : " · \(r.http_codes)"))
        }
        setRow("connect", connParts.joined(separator: " · "),
               status: connOK ? .ok : (r.tun_cov == 1 ? .warn : .bad))
        setRow("rules", "\(r.chain_checked) 条 · 直连 \(r.chain_direct)",
               status: r.chain_direct > 0 ? .bad : .ok)
        let exitOK = r.chain_audit_ok == 1 && !r.required_chain.isEmpty
            && r.chain_direct == 0 && r.chain_unverified == 0
        // REQUIRED_CHAIN may carry an emoji (default "🛡️ 静态IP出口"). The LED
        // already carries the status, so the value is shown without it.
        let chainText = displaySafe(r.required_chain)
        // "Unverified" is treated as failure by the guard when
        // REQUIRE_CHAIN_AUDIT=1, so it gets the failure LED instead of the
        // softer warn one; only a genuine "check could not run yet" is warn.
        let exitStatus: RowStatus = exitOK ? .ok
            : ((r.chain_unverified == 1 || r.audit_failed == 1) ? .bad : .warn)
        let exitText = exitOK ? (chainText.isEmpty ? "规定出口" : chainText)
            : (r.chain_unverified == 1 ? "未验证（按失败处理）" : "未验证")
        setRow("exit", exitText, status: exitStatus)
        setRow("procs", "\(r.targets.count) 个", status: .info)
        setRow("socks", r.hits.isEmpty ? "无" : "\(r.hits.count) 条外部连接",
               status: r.hits.isEmpty ? .ok : .bad)

        var faults: [String] = []
        // A stale report describes the last tick, not this moment: the list
        // says what was found then instead of ordering an action now.
        let t = stale ? "曾" : ""
        if r.bypass == 1 { faults.append(t + "检测到直连或非规定出口" + (stale ? "" : "（立即处置）")) }
        if r.chain_unverified == 1 { faults.append(t + "规则链归属无法验证，按失败处理") }
        if r.audit_failed == 1 { faults.append(t + "ps/lsof 审计失败，无法确认没有直连") }
        if r.tun_cov != 1 && r.sysproxy_ok != 1 { faults.append(t + "TUN 与系统代理都没有覆盖") }
        if r.mihomo_ok != 1 { faults.append(t + "mihomo 控制面不可达") }
        if r.tcp_ok != 1 && r.http_ok != 1 && r.tun_cov != 1 { faults.append(t + "经代理的健康探测失败") }
        if r.link_up != 1 { faults.append(t + "物理链路 down\(r.link_iface.isEmpty ? "" : " (\(r.link_iface))")") }
        reasonsLabel.textColor = stale ? .secondaryLabelColor : .labelColor
        reasonsLabel.stringValue = faults.isEmpty ? "" : faults.map { "• \($0)" }.joined(separator: "\n")
        reasonsLabel.isHidden = faults.isEmpty
        reasonsCard.isHidden = faults.isEmpty

        renderGeo(delegate?.geo)

        targetsLabel.stringValue = "\(r.targets.count) 个进程 · \(r.hits.count) 条外部连接"
            + (r.targets.count > 4 ? " · 列表可滚动" : "")
        rebuildTargets(r.targets)
        // When the report is unhealthy, "which process is direct" is the
        // question the user came with, so the process list moves above the
        // identity card. Healthy panels keep the identity card first.
        reorderCards(unhealthy: !r.healthy)

        suppressSwitch = true
        enforceSwitch.state = (pending ? false : enforceOn) ? .on : .off
        enforceSwitch.isEnabled = Paths.agentLoaded
        suppressSwitch = false
        if pending {
            enforceCaption.stringValue = "再点一次关闭"
            enforceCaption.textColor = warnColor
            enforceSwitch.setAccessibilityLabel("强制执行已请求关闭，再点一次确认")
        } else {
            enforceCaption.stringValue = enforceOn ? "强制执行" : "仅观察"
            enforceCaption.textColor = enforceOn ? .labelColor : warnColor
            enforceSwitch.setAccessibilityLabel("强制执行")
        }
        syncBodyLayout()
        delegate?.dashboardContentDidChange()
    }

    /// A live check that timed out or returned nothing must say so instead of
    /// silently leaving the old numbers on screen.
    func showLiveFailure(_ msg: String) {
        guard isViewLoaded else { return }
        livePill.set(msg, color: warnColor)
    }

    // ---- geo card

    private func localTimeString(_ tz: String) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss zzz"
        f.timeZone = TimeZone(identifier: tz)
        return f.string(from: Date())
    }

    private func geoRow(_ name: String, _ value: String, icon: String,
                        color: NSColor = .labelColor) -> NSView {
        let glyph = symbolView(icon, size: 10.5, weight: .regular)
        let n = label(name, size: 11.5, color: .secondaryLabelColor)
        n.setContentHuggingPriority(.required, for: .horizontal)
        n.widthAnchor.constraint(equalToConstant: 58).isActive = true
        let v = label(value, size: 12, weight: .medium, color: color)
        // Left-aligned values share one x, so short fields (IP, coordinates)
        // sit next to their labels instead of drifting to the card edge.
        v.alignment = .left
        v.lineBreakMode = .byTruncatingTail
        v.toolTip = value
        v.setContentHuggingPriority(.defaultLow, for: .horizontal)
        v.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [glyph, n, v])
        row.orientation = .horizontal
        row.distribution = .fill
        row.spacing = 7
        return row
    }

    func renderGeo(_ g: Geo?) {
        guard isViewLoaded else { return }
        for v in geoBox.arrangedSubviews { geoBox.removeArrangedSubview(v); v.removeFromSuperview() }
        guard let g = g else {
            geoBox.addArrangedSubview(label("尚未获取，点“刷新 IP”", size: 11, color: .secondaryLabelColor))
            geoSourceLabel.stringValue = ""
            return
        }
        var rows: [NSView] = []
        rows.append(geoRow("IP", g.ip, icon: "network"))
        let place = g.postal.isEmpty ? g.address : "\(g.address) · \(g.postal)"
        rows.append(geoRow("地区", place, icon: "mappin.and.ellipse",
                           color: g.location_source == "user" ? warnColor : .labelColor))
        if !g.loc.isEmpty { rows.append(geoRow("坐标", g.loc, icon: "location")) }
        if !g.org.isEmpty { rows.append(geoRow("运营商", g.org, icon: "building.2")) }
        rows.append(geoRow("时区", g.timezone, icon: "globe"))
        rows.append(geoRow("当地时间", localTimeString(g.timezone), icon: "clock"))
        let sysMatches = (g.system_tz == g.timezone)
        rows.append(geoRow("系统时区", sysMatches ? "\(g.system_tz)（一致）" : "\(g.system_tz)（不修改系统）",
                           icon: "desktopcomputer",
                           color: sysMatches ? .labelColor : .secondaryLabelColor))
        rows.append(geoRow("时区注入", g.tz_applied ? "已生效 · TZ=\(g.tz_env)" : "未写入",
                           icon: "arrow.down.circle",
                           color: g.tz_applied ? .labelColor : warnColor))
        rows.append(geoRow("遥测", g.telemetry_off ? "已关闭" : "未确认", icon: "bell.slash",
                           color: g.telemetry_off ? .labelColor : warnColor))
        rows.append(geoRow("定位", "设备定位从不读取", icon: "location.slash",
                           color: .secondaryLabelColor))
        for r in rows {
            geoBox.addArrangedSubview(r)
            r.widthAnchor.constraint(equalTo: geoBox.widthAnchor).isActive = true
        }
        geoSourceLabel.stringValue =
            "来源 ipinfo · 位置=\(g.location_source == "user" ? "用户地址" : "IP") · \(relativeAge(g.fetched_at))"
    }

    /// Swap the LED glyph and tint. Shape and color change together, so the
    /// row still reads without color vision. A row that actually changes
    /// state pops once; the 10 s refresh that returns the same state is
    /// silent, so the panel never twitches on its own timer.
    private func setLED(_ row: CheckRow, _ status: RowStatus) {
        let previous = row.led.image?.accessibilityDescription
        let cfg = NSImage.SymbolConfiguration(pointSize: 11, weight: .semibold)
        row.led.image = NSImage(systemSymbolName: status.symbol, accessibilityDescription: status.symbol)?
            .withSymbolConfiguration(cfg)
        row.led.contentTintColor = status.color
        if let previous = previous, previous != status.symbol {
            Motion.pop(row.led, key: "led.pop", peak: 1.35, duration: 0.30)
        }
    }

    private func setRow(_ key: String, _ text: String, status: RowStatus) {
        guard let row = checkRows[key] else { return }
        setLED(row, status)
        // Failures keep their value in the semantic color; passing checks use
        // plain label text so eight green lines never turn into a wall of
        // color — the LED column already says "ok".
        row.value.stringValue = text
        row.value.textColor = (status == .bad || status == .warn) ? status.color : .labelColor
        row.value.toolTip = text
    }

    private func rebuildTargets(_ targets: [Target]) {
        for v in targetsBox.arrangedSubviews { targetsBox.removeArrangedSubview(v); v.removeFromSuperview() }
        // Show whole rows only: a half-clipped row reads as a layout bug, not
        // as "there is more below". Four rows fit a short screen; longer lists
        // scroll and the caption says so.
        let maxVisible = 4
        if targets.isEmpty {
            targetsHeight?.constant = 22
            targetsBox.addArrangedSubview(label("没有 Claude 链进程在运行", size: 11.5, color: .secondaryLabelColor))
            return
        }
        // kind -> glyph; one icon family, all 10 pt, so the list scans by role
        // before it reads a single path.
        func targetIcon(_ kind: String) -> String {
            switch kind {
            case "desktop": return "macwindow"
            case "desktop-helper": return "puzzlepiece.extension"
            case "claude-code": return "terminal"
            case "gateway": return "arrow.left.arrow.right"
            default: return "circle.dashed"
            }
        }
        var rowHeight: CGFloat = 16
        // One width for every row so the command column stays aligned, sized
        // to the longest "kind pid" (clamped) instead of a fixed guess that
        // clipped "desktop-helper 9904" mid-word.
        let nameFont = NSFont.systemFont(ofSize: 10, weight: .semibold)
        let nameWidth = min(150, max(96, targets.map { t in
            ("\(t.kind)  \(t.pid)" as NSString)
                .size(withAttributes: [.font: nameFont]).width.rounded(.up)
        }.max() ?? 108))
        for (i, t) in targets.enumerated() {
            let icon = symbolView(targetIcon(t.kind), size: 10,
                                  color: t.kind == "claude-code" ? Theme.good : .secondaryLabelColor)
            let name = label("\(t.kind)  \(t.pid)", size: 10, weight: .semibold)
            name.setContentHuggingPriority(.required, for: .horizontal)
            name.lineBreakMode = .byTruncatingTail
            name.widthAnchor.constraint(equalToConstant: nameWidth).isActive = true
            name.setAccessibilityLabel("\(t.kind) \(t.pid)")
            let cmd = label(t.cmd, size: 10.5, color: .secondaryLabelColor)
            // Head truncation keeps the filename, which is what tells two
            // processes apart; the shared /Users/… prefix is the safe part to
            // drop. Tooltip and accessibility label carry the full command.
            cmd.lineBreakMode = .byTruncatingHead
            cmd.toolTip = t.cmd
            cmd.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            let row = NSStackView(views: [icon, name, cmd])
            row.orientation = .horizontal
            row.alignment = .centerY
            row.distribution = .fill
            row.spacing = 7
            // One label per row so VoiceOver reads kind, pid and command as a
            // single entry instead of three disconnected fields.
            row.setAccessibilityElement(true)
            row.setAccessibilityLabel("\(t.kind) \(t.pid) \(t.cmd)")
            targetsBox.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: targetsBox.widthAnchor).isActive = true
            if i == 0 { rowHeight = max(row.fittingSize.height, 14) }
        }
        let visible = min(targets.count, maxVisible)
        targetsHeight?.constant = CGFloat(visible) * rowHeight
            + CGFloat(visible - 1) * targetsBox.spacing + 2
    }

    // ---- actions

    @objc func refreshTapped() {
        delegate?.liveCheck()
    }

    /// While a live check runs, the primary button says so and its glyph
    /// becomes a circular arrow. The label swap is the acknowledgement that
    /// the click landed even when the guard takes several seconds; the press
    /// sink already played on mouse-down, so no second animation is stacked
    /// on the same layer transform here.
    func setChecking(_ on: Bool) {
        guard isViewLoaded, let b = primaryButtonRef as? FilledActionButton else { return }
        guard b.isChecking != on else { return }
        b.isChecking = on
    }

    // ---- test hooks (headless checks only)

    var primaryButtonForTest: NSButton? { primaryButtonRef }
    var bodyThumbForTest: ScrollThumb? { bodyThumb }
    var targetsThumbForTest: ScrollThumb? { targetsThumb }
    var bodyScrollForTest: NSScrollView { bodyScroll }

    @objc func refreshGeoTapped() {
        delegate?.refreshGeo()
    }

    @objc func logTapped() {
        delegate?.openLog()
    }

    @objc func quitTapped() {
        delegate?.quit()
    }

    @objc func enforceToggled() {
        guard !suppressSwitch else { return }
        let now = Date().timeIntervalSince1970

        // Never trust `enforceSwitch.state` to tell us what the user meant:
        // NSSwitch flips its own state *before* sending the action, and while a
        // disable is pending both render paths force the control OFF. So the
        // confirming click arrives with `state == .on` — reading the control
        // would restart the guard with ENFORCE=1 instead of stopping it.
        // Intent comes from the pending deadline, not from the control.
        if now < pendingDisableUntil {
            // Second click inside the window: this is the confirmation.
            pendingDisableUntil = 0
            finishEnforceChange(ok: delegate?.setEnforce(false) ?? false)
            return
        }

        // Moving to "仅观察" takes two clicks within 4 s. A modal alert would
        // have to activate the app (and steal focus); this keeps the panel
        // nonactivating. Turning it back on is immediate, so it can always be
        // undone with one click.
        //
        // The switch is currently reporting ON exactly when enforcement is
        // configured on; if it reads OFF, the user is asking to enable.
        let enforcing = delegate?.configuredEnforce() ?? false
        if !enforcing {
            finishEnforceChange(ok: delegate?.setEnforce(true) ?? false)
            return
        }

        // Arm the pending disable. The control stays visually OFF (so the user
        // sees the switch has moved) and the caption next to it carries the
        // "click again" instruction.
        let deadline = now + 4
        pendingDisableUntil = deadline
        render(report: delegate?.report, age: delegate?.reportAge ?? 9999, live: false)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.05) { [weak self] in
            guard let self = self, self.pendingDisableUntil == deadline else { return }
            self.pendingDisableUntil = 0
            self.render(report: self.delegate?.report,
                        age: self.delegate?.reportAge ?? 9999, live: false)
        }
    }

    private func finishEnforceChange(ok: Bool) {
        delegate?.reloadFromDisk()
        render(report: delegate?.report, age: delegate?.reportAge ?? 9999, live: false)
        if !ok {
            subtitleLabel.stringValue = "配置写入或守护重启失败，状态可能未改变"
            subtitleLabel.textColor = badColor
        }
    }
}

// ---------------------------------------------------------------- main

// Headless self-test used by the build: decode the guard report and exit.
if CommandLine.arguments.contains("--selftest") {
    let dir = stateDirectory()
    let url = dir.appendingPathComponent("last_report.json")
    guard let data = try? Data(contentsOf: url) else {
        print("no report at \(url.path)")
        exit(1)
    }
    guard let r = try? JSONDecoder().decode(Report.self, from: data) else {
        print("decode failed: \(url.path)")
        exit(2)
    }
    print("ok verdict=\(r.verdict) coverage=\(r.coverage) targets=\(r.targets.count) "
        + "hits=\(r.hits.count) enforce=\(r.enforce) fail=\(r.fail_count)")
    let gurl = dir.appendingPathComponent("geo.json")
    if let gdata = try? Data(contentsOf: gurl),
       let g = try? JSONDecoder().decode(Geo.self, from: gdata) {
        print("geo ip=\(g.ip) place=\(g.address) tz=\(g.timezone) local=\(g.local_time) "
            + "telemetry_off=\(g.telemetry_off) loc=\(g.location_source)")
    } else {
        print("geo missing at \(gurl.path)")
    }
    exit(0)
}

// Headless layout check: build the same panel the app uses, render the real
// report *and* the IP card, and fail if the content does not fit panelWidth.
if CommandLine.arguments.contains("--selftest-ui") {
    _ = NSApplication.shared
    let delegate = AppDelegate()
    let vc = delegate.dashboard
    delegate.dashboard.delegate = delegate
    let dir = stateDirectory()
    if let data = try? Data(contentsOf: dir.appendingPathComponent("geo.json")),
       let g = try? JSONDecoder().decode(Geo.self, from: data) { delegate.geo = g }
    var sample: Report?
    if let data = try? Data(contentsOf: dir.appendingPathComponent("last_report.json")),
       let r = try? JSONDecoder().decode(Report.self, from: data) { sample = r }
    // Load the view first: render() returns early while isViewLoaded is false,
    // which would test a panel with no report and a collapsed IP card.
    let panel = delegate.makePanel()
    vc.render(report: sample, age: 0, live: true)
    // Match showPanel: measure the scrollable body, then clamp the panel to
    // the visible screen. If the body is taller it scrolls; the footer stays.
    vc.view.layoutSubtreeIfNeeded()
    vc.syncBodyLayout()
    let desired = vc.desiredPanelHeight()
    let vf = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1280, height: 800)
    let h = max(min(desired, vf.height - 24), 480)
    panel.setFrame(NSRect(x: 0, y: 0, width: panelWidth, height: h), display: false)
    vc.view.frame = NSRect(x: 0, y: 0, width: panelWidth, height: h)
    vc.view.layoutSubtreeIfNeeded()
    vc.syncBodyLayout()
    // The footer is the widest fixed row; sum its intrinsic widths plus the
    // 16 pt insets on both sides, which is the width the panel must provide.
    var footerNeed: CGFloat = 0
    var footerFrame = NSRect.zero
    if let f = vc.footerStack {
        footerNeed = f.arrangedSubviews.reduce(0) { $0 + $1.fittingSize.width }
            + CGFloat(max(0, f.arrangedSubviews.count - 1)) * f.spacing + outerInset * 2
        footerFrame = f.convert(f.bounds, to: vc.view)
    }
    let tdoc = vc.targetsScroll.documentView?.frame ?? .zero
    let tclip = vc.targetsScroll.contentSize
    // The panel's own scroller must be gone: AppKit's legacy bar is what drew
    // a permanent stripe down the panel edge on systems set to always-show
    // scroll bars. Scrolling itself still works (checked below); the custom
    // capsule must sit hidden at rest, appear while scrolling, then leave.
    let noAppKitScrollers = !vc.bodyScrollForTest.hasVerticalScroller
        && !vc.targetsScroll.hasVerticalScroller
    let thumbsAtRest = (vc.bodyThumbForTest?.isHidden ?? false)
        && (vc.targetsThumbForTest?.isHidden ?? false)
    let thumbHitTest = vc.bodyThumbForTest?.hitTest(NSPoint(x: 1, y: 1)) == nil
    let clip = vc.targetsScroll.contentView
    // Programmatic scrolls stand in for the wheel here. The process list's
    // document is a plain NSStackView, so its clip measures upward and the
    // scroll offset toward the end is negative; the capsule must still sit at
    // the top edge at rest and at the bottom edge at the end. The old formula
    // left it pinned at the top for this document, so assert the frame, not
    // just showCount.
    func capsuleGapFromTop(_ sv: NSScrollView, _ thumb: ScrollThumb?) -> CGFloat {
        guard let thumb = thumb else { return .nan }
        return sv.isFlipped ? thumb.frame.minY - sv.bounds.minY
                            : sv.bounds.maxY - thumb.frame.maxY
    }
    func checkCapsule(_ tag: String, _ sv: NSScrollView, _ thumb: ScrollThumb?,
                      endOffset: CGFloat) -> Bool {
        guard let thumb = thumb, let doc = sv.documentView,
              doc.frame.height > sv.contentView.bounds.height + 0.5 else { return true }
        sv.contentView.scroll(to: .zero)
        sv.reflectScrolledClipView(sv.contentView)
        RunLoop.current.run(until: Date().addingTimeInterval(0.10))
        let topGap = capsuleGapFromTop(sv, thumb)
        sv.contentView.scroll(to: NSPoint(x: 0, y: endOffset))
        sv.reflectScrolledClipView(sv.contentView)
        RunLoop.current.run(until: Date().addingTimeInterval(0.10))
        let endGap = capsuleGapFromTop(sv, thumb)
        let travel = sv.bounds.height - thumb.frame.height
        let ok = abs(topGap) <= 1.5 && abs(endGap - travel) <= 1.5
        print("\(tag)_capsule top_gap=\(topGap) end_gap=\(endGap) travel=\(travel) ok=\(ok)")
        return ok
    }
    let t0 = clip.bounds.origin.y
    clip.scroll(to: NSPoint(x: 0, y: t0 - 5000))
    vc.targetsScroll.reflectScrolledClipView(clip)
    let t1 = clip.bounds.origin.y
    RunLoop.current.run(until: Date().addingTimeInterval(0.15))
    let thumbShownOnScroll = (vc.targetsThumbForTest?.showCount ?? 0) > 0
    vc.view.layoutSubtreeIfNeeded()
    vc.syncBodyLayout()
    // The process list must be scrollable: its document (all process rows)
    // has to be taller than the viewport whenever it holds many rows.
    let targetsScrolls = abs(t1 - t0) > 1
    let targetsCapsuleOK = checkCapsule("targets", vc.targetsScroll,
                                        vc.targetsThumbForTest, endOffset: -5000)
    let bodyCapsuleOK = checkCapsule("body", vc.bodyScrollForTest,
                                     vc.bodyThumbForTest, endOffset: 5000)
    // A content refresh that leaves the scroll offset alone (the 10 s tick,
    // an appearance change) must not summon the capsule again.
    let showsBeforeRefresh = vc.targetsThumbForTest?.showCount ?? 0
    vc.render(report: sample, age: 0, live: false)
    RunLoop.current.run(until: Date().addingTimeInterval(0.20))
    let noBlinkOnRefresh = (vc.targetsThumbForTest?.showCount ?? 0) == showsBeforeRefresh
    // Once scrolling stops, both capsules fade and leave the view tree.
    RunLoop.current.run(until: Date().addingTimeInterval(1.8))
    let thumbsLeave = vc.targetsThumbForTest?.isHidden == true
        && vc.bodyThumbForTest?.isHidden == true
    print("ui subviews=\(vc.view.subviews.count) footer_need=\(footerNeed) desired=\(desired) "
        + "screen_visible=\(vf.height) panel=\(panel.frame.size) footer=\(footerFrame) "
        + "targets_doc=\(tdoc.size) targets_clip=\(tclip) scrollable=\(targetsScrolls) "
        + "appkit_scrollers=\(!noAppKitScrollers) thumbs_rest=\(thumbsAtRest) "
        + "thumb_click_through=\(thumbHitTest) thumb_on_scroll=\(thumbShownOnScroll) "
        + "targets_capsule=\(targetsCapsuleOK) body_capsule=\(bodyCapsuleOK) "
        + "thumb_no_refresh=\(noBlinkOnRefresh) thumb_leaves=\(thumbsLeave)")
    if !noAppKitScrollers {
        print("ui FAIL: AppKit still owns a visible scroller")
        exit(1)
    }
    if !thumbsAtRest || !thumbHitTest {
        print("ui FAIL: custom scroll capsule is visible at rest or eats clicks")
        exit(1)
    }
    if tdoc.height > tclip.height + 0.5 && !thumbShownOnScroll {
        print("ui FAIL: scroll capsule did not appear while the list scrolled")
        exit(1)
    }
    if footerNeed > panelWidth + 0.5 {
        print("ui FAIL: footer needs \(footerNeed) pt, panel is \(panelWidth) pt")
        exit(1)
    }
    if footerFrame.minY < -0.5 || footerFrame.maxY > h + 0.5 {
        print("ui FAIL: footer outside the panel")
        exit(1)
    }
    if tdoc.height > tclip.height + 0.5 && !targetsScrolls {
        print("ui FAIL: process list overflows \(tclip.height) pt but cannot scroll")
        exit(1)
    }
    if !targetsCapsuleOK || !bodyCapsuleOK {
        print("ui FAIL: scroll capsule is not at the top at rest / bottom at the end")
        exit(1)
    }
    if !noBlinkOnRefresh || !thumbsLeave {
        print("ui FAIL: scroll capsule blinks on refresh or never leaves")
        exit(1)
    }
    print("ui ok")
    exit(0)
}

// Motion check: build the real panel, play the entrance and the exit, and
// read the *presentation* values back from the render server while they run.
// Screen recordings are variable-rate and can miss a 220 ms animation entirely,
// so the numbers, not the frames, are the proof: the top edge must stay put
// while the width grows, the press sink must actually land near 0.965, and the
// exit must end fully transparent and reset to identity. Everything here runs
// offscreen; nothing is shown.
if CommandLine.arguments.contains("--selftest-motion") {
    _ = NSApplication.shared
    let delegate = AppDelegate()
    let vc = delegate.dashboard
    let dir = stateDirectory()
    if let data = try? Data(contentsOf: dir.appendingPathComponent("geo.json")),
       let g = try? JSONDecoder().decode(Geo.self, from: data) { delegate.geo = g }
    var sample: Report?
    if let data = try? Data(contentsOf: dir.appendingPathComponent("last_report.json")),
       let r = try? JSONDecoder().decode(Report.self, from: data) { sample = r }
    let panel = delegate.makePanel()
    delegate.panel = panel        // animateClose() closes *this* panel
    vc.render(report: sample, age: 0, live: false)
    panel.setFrame(NSRect(x: 100, y: 100, width: panelWidth, height: 720), display: false)
    panel.alphaValue = 1
    panel.orderFrontRegardless()
    vc.view.layoutSubtreeIfNeeded()

    var failures: [String] = []
    func check(_ ok: Bool, _ what: String) {
        print("  \(ok ? "ok  " : "FAIL") \(what)")
        if !ok { failures.append(what) }
    }
    func presentation(_ layer: CALayer?) -> (scale: CGFloat, tx: CGFloat, ty: CGFloat, opacity: Float)? {
        guard let p = layer?.presentation() else { return nil }
        return (p.transform.m11, p.transform.m41, p.transform.m42, p.opacity)
    }
    // Run the run loop for `secs` so Core Animation renders, sampling `body`
    // every 16 ms and returning what it saw.
    func spin(_ secs: CFTimeInterval, _ body: () -> Void) {
        let end = Date().addingTimeInterval(secs)
        while Date() < end {
            body()
            RunLoop.current.run(until: Date().addingTimeInterval(0.016))
        }
    }

    let dash = vc.view.layer
    let h = panel.frame.height
    // AppKit view layers are bottom-up (this view is not flipped), so the
    // content's top edge in layer coordinates is h/2 + s·h/2 + ty. A
    // top-anchored grow keeps that at h for every sampled frame.
    func drawnTop(_ p: (scale: CGFloat, tx: CGFloat, ty: CGFloat, opacity: Float)) -> CGFloat {
        h / 2 + p.scale * h / 2 + p.ty
    }

    // --- entrance: top edge anchored, width grows
    if Motion.reduceMotion {
        print("  note reduced motion is on; entrance/exit run as instant states")
    }
    delegate.playEntrance(panel)
    var minScale: CGFloat = 1, maxScale: CGFloat = 1
    var topDrift: CGFloat = 0
    var sampledFrames = 0
    spin(0.30) {
        if let p = presentation(dash) {
            sampledFrames += 1
            minScale = min(minScale, p.scale); maxScale = max(maxScale, p.scale)
            topDrift = max(topDrift, abs(drawnTop(p) - h))
        }
    }
    check(sampledFrames > 3, "entrance was sampled while playing (\(sampledFrames) frames)")
    check(Motion.reduceMotion || minScale < 0.99,
          "entrance starts scaled down (min scale \(String(format: "%.3f", minScale)))")
    check(abs(maxScale - 1) < 0.01, "entrance settles at identity (end scale \(String(format: "%.3f", maxScale)))")
    check(Motion.reduceMotion || topDrift < 3,
          "panel top edge stays anchored during entrance (drift \(String(format: "%.2f", topDrift)) pt)")

    // --- press: the primary button sinks and springs back
    guard let button = vc.primaryButtonForTest else { print("motion FAIL: no primary button"); exit(1) }
    Motion.pressDown(button)
    var sunk: CGFloat = 1
    spin(0.10) {
        if let p = presentation(button.layer) { sunk = min(sunk, p.scale) }
    }
    check(Motion.reduceMotion || sunk < 0.99,
          "primary button sinks on press (min scale \(String(format: "%.3f", sunk)))")
    let held = button.layer?.transform.m11 ?? 1
    check(Motion.reduceMotion || abs(held - Motion.pressScale) < 0.001,
          "press leaves the model at the sunk scale while held (\(String(format: "%.3f", held)))")
    Motion.pressUp(button)
    var back: CGFloat = 0
    spin(0.20) {
        if let p = presentation(button.layer) { back = max(back, p.scale) }
    }
    check(abs(back - 1) < 0.005, "primary button springs back to identity (\(String(format: "%.3f", back)))")
    check(abs((button.layer?.transform.m11 ?? 0) - 1) < 0.001, "press model is identity after release")

    // --- checking state swaps the label and reserves its width
    vc.setChecking(true)
    let checkingTitle = (button as? FilledActionButton)?.currentTitle ?? ""
    let wChecking = button.intrinsicContentSize.width
    vc.setChecking(false)
    let idleTitle = (button as? FilledActionButton)?.currentTitle ?? ""
    let wIdle = button.intrinsicContentSize.width
    check(checkingTitle != idleTitle && !checkingTitle.isEmpty,
          "primary button label swaps while checking (\"\(idleTitle)\" → \"\(checkingTitle)\")")
    check(abs(wChecking - wIdle) < 0.5, "footer does not reflow when the label swaps (\(wIdle) vs \(wChecking))")

    // --- exit: fades to zero, then is reset and hidden
    delegate.animateClose()
    var minAlpha: CGFloat = 1
    spin(0.22) {
        minAlpha = min(minAlpha, CGFloat(panel.alphaValue))
    }
    check(panel.isVisible == false, "panel is ordered out after the exit")
    // The window is ordered out one frame before the curve reaches exactly
    // 0, so "near zero on the last visible frame" is the right assertion.
    check(Motion.reduceMotion || minAlpha < 0.15,
          "exit fades the panel to near zero before order-out (min window alpha \(String(format: "%.2f", minAlpha)))")
    check(abs((dash?.transform.m11 ?? 0) - 1) < 0.001, "exit leaves the layer at identity, not shrunk")

    // --- reentry during an exit: a close still in flight must not hide it,
    // and the entrance must continue from what is on screen, not blink back
    // to alpha 0. `present` bumps the close token, exactly like a real reopen.
    panel.orderFrontRegardless()
    panel.alphaValue = 1
    delegate.playEntrance(panel)
    RunLoop.current.run(until: Date().addingTimeInterval(0.25))
    delegate.animateClose()
    RunLoop.current.run(until: Date().addingTimeInterval(0.05))   // exit in flight
    var alphaBeforeReopen: CGFloat = 1
    if !Motion.reduceMotion {
        check(delegate.isClosing && panel.isVisible,
              "the panel stays visible while the exit plays, tracked by closing state")
        check(!delegate.isPanelOpenForClick,
              "a click during the exit is read as reopen, not close")
        alphaBeforeReopen = CGFloat(panel.alphaValue)
    }
    delegate.present(panel, frame: panel.frame, startLive: false)
    var minAlphaDuringReopen: CGFloat = 1
    spin(0.08) { minAlphaDuringReopen = min(minAlphaDuringReopen, CGFloat(panel.alphaValue)) }
    RunLoop.current.run(until: Date().addingTimeInterval(0.25))
    check(panel.isVisible, "a reopen during the exit keeps the panel visible")
    check(!delegate.isClosing, "the reopened panel is no longer closing")
    check(Motion.reduceMotion || minAlphaDuringReopen > min(0.5, alphaBeforeReopen - 0.05),
          "reopen continues from the on-screen alpha (min "
          + "\(String(format: "%.2f", minAlphaDuringReopen)) from \(String(format: "%.2f", alphaBeforeReopen)))")

    print(failures.isEmpty ? "motion ok" : "motion FAIL: \(failures.count) check(s)")
    exit(failures.isEmpty ? 0 : 1)
}

// Ask the already-running instance to open its panel, then exit. If no
// instance is running (or it never consumes the trigger), say so and remove
// the file so a later launch does not pop the panel open unrequested.
if CommandLine.arguments.contains("--show") {
    let bid = Bundle.main.bundleIdentifier ?? "com.swimmingliu.proxyguardui"
    guard !NSRunningApplication.runningApplications(withBundleIdentifier: bid).isEmpty else {
        FileHandle.standardError.write(
            "ProxyGuard 未运行：open ~/Applications/ProxyGuard.app\n".data(using: .utf8) ?? Data())
        exit(1)
    }
    let dir = stateDirectory()
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let req = dir.appendingPathComponent("show_panel.request")
    guard (try? Data().write(to: req)) != nil else {
        FileHandle.standardError.write("无法写入触发文件：\(req.path)\n".data(using: .utf8) ?? Data())
        exit(2)
    }
    for _ in 0..<160 {                       // up to 8 s for the 0.5 s poll
        if !FileManager.default.fileExists(atPath: req.path) { exit(0) }
        usleep(50_000)
    }
    try? FileManager.default.removeItem(at: req)
    FileHandle.standardError.write(
        "ProxyGuard 未响应触发文件（STATE_DIR=\(dir.path)）\n".data(using: .utf8) ?? Data())
    exit(3)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
