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

let goodColor = NSColor.systemGreen
let badColor = NSColor.systemRed
let warnColor = NSColor.systemOrange
/// Fixed panel width: wide enough for the footer's intrinsic 417 pt.
let panelWidth: CGFloat = 424

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
    var fileTimer: Timer?
    var liveTimer: Timer?
    var showTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
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
                self?.panel?.orderOut(nil)
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
        if panel?.isVisible != true { showPanel() }
    }

    // ---- report loading

    @objc func fileTick() {
        refreshStateDir()
        reloadFromDisk()
        if panel?.isVisible == true { dashboard.render(report: report, age: reportAge, live: false) }
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
                if self.panel?.isVisible == true {
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
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let (rc, out) = runProcess("/bin/bash", [Paths.guardScript, "--status", "--json"], timeout: 45)
            let r = out.data(using: .utf8).flatMap { try? JSONDecoder().decode(Report.self, from: $0) }
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.liveBusy = false
                guard rc == 0, let r = r else {
                    self.dashboard.showLiveFailure(rc == 0 ? "实时检查无结果" : "实时检查超时")
                    return
                }
                self.report = r
                self.reportAge = max(0, Int(Date().timeIntervalSince1970) - r.ts)
                self.updateIcon()
                if self.panel?.isVisible == true {
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
        p.contentView = dashboard.view
        dashboard.view.autoresizingMask = [.width, .height]
        return p
    }

    func showPanel() {
        guard let button = statusItem.button, let win = button.window else { return }
        if panel == nil { panel = makePanel() }
        guard let p = panel else { return }
        reloadFromDisk()
        dashboard.render(report: report, age: reportAge, live: false)
        let btn = win.convertToScreen(button.convert(button.bounds, to: nil))
        dashboard.view.layoutSubtreeIfNeeded()
        let screen = win.screen ?? NSScreen.main
        let vf = screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1280, height: 800)
        var size = NSSize(width: panelWidth, height: min(dashboard.view.fittingSize.height, vf.height - 24))
        size.height = max(size.height, 480)
        var x = btn.midX - size.width / 2
        var y = min(btn.minY - size.height - 6, vf.maxY - size.height - 8)
        x = min(max(x, vf.minX + 8), vf.maxX - size.width - 8)
        y = max(y, vf.minY + 8)
        p.setFrame(NSRect(x: x, y: y, width: size.width, height: size.height), display: true)
        dashboard.view.frame = NSRect(x: 0, y: 0, width: size.width, height: size.height)
        // orderFrontRegardless + a nonactivating panel shows the dashboard
        // without activating ProxyGuard, so typing in Terminal/Claude keeps
        // working. Clicking the shield again closes it.
        p.orderFrontRegardless()
        liveCheck()
        liveTimer?.invalidate()
        liveTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            guard let self = self, self.panel?.isVisible == true else { return }
            self.liveCheck()
        }
    }

    @objc func togglePopover(_ sender: Any?) {
        if panel?.isVisible == true {
            panel?.orderOut(nil)
            liveTimer?.invalidate()
            liveTimer = nil
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

final class DashboardViewController: NSViewController {
    weak var delegate: AppDelegate?

    private let verdictLabel = NSTextField(labelWithString: "—")
    private let subtitleLabel = NSTextField(labelWithString: "")
    private let dot = NSView()
    private var checkRows: [String: NSTextField] = [:]
    private let targetsLabel = NSTextField(labelWithString: "")
    private let targetsBox = NSStackView()
    private let reasonsLabel = NSTextField(labelWithString: "")
    private let reasonsTitle = NSTextField(labelWithString: "故障原因")
    private var reasonsCard: NSBox!
    private let geoBox = NSStackView()
    private let geoSourceLabel = NSTextField(labelWithString: "")
    private let enforceSwitch = NSSwitch()
    private let enforceCaption = NSTextField(labelWithString: "")
    private let liveBadge = NSTextField(labelWithString: "")
    private var suppressSwitch = false
    /// Turning enforcement off needs a second click within this window.
    private var pendingDisableUntil: TimeInterval = 0
    /// Kept so the layout self-test can measure the content's intrinsic width.
    var widthConstraint: NSLayoutConstraint?
    var footerStack: NSStackView?

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: panelWidth, height: 700))
        root.wantsLayer = true
        root.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        root.layer?.cornerRadius = 12
        root.layer?.borderWidth = 1
        root.layer?.borderColor = NSColor.separatorColor.cgColor
        view = root
        // Pin the panel size: without this the intrinsic width of long command
        // lines inside the targets list expands the popover past the screen.
        preferredContentSize = NSSize(width: panelWidth, height: 700)
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
        // header
        dot.wantsLayer = true
        dot.layer?.cornerRadius = 6
        dot.layer?.backgroundColor = warnColor.cgColor
        dot.translatesAutoresizingMaskIntoConstraints = false
        dot.widthAnchor.constraint(equalToConstant: 12).isActive = true
        dot.heightAnchor.constraint(equalToConstant: 12).isActive = true

        verdictLabel.font = NSFont.systemFont(ofSize: 21, weight: .bold)
        subtitleLabel.font = NSFont.systemFont(ofSize: 11)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.lineBreakMode = .byTruncatingTail
        liveBadge.font = NSFont.systemFont(ofSize: 10, weight: .medium)
        liveBadge.textColor = .tertiaryLabelColor

        let headerText = NSStackView(views: [verdictLabel, subtitleLabel])
        headerText.orientation = .vertical
        headerText.alignment = .leading
        headerText.spacing = 2

        let header = NSStackView(views: [dot, headerText])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 10

        // check rows
        let checks = [
            ("mihomo", "控制面"), ("tun", "TUN 覆盖"), ("sysproxy", "系统代理"),
            ("connect", "代理连通"), ("rules", "规则审计"), ("exit", "出口组"),
            ("procs", "Claude 进程"), ("socks", "外部连接"),
        ]
        var rows: [NSView] = []
        for (key, title) in checks {
            let name = label(title, size: 11, color: .secondaryLabelColor)
            let value = label("—", size: 11, weight: .medium)
            value.alignment = .right
            value.setContentHuggingPriority(.defaultLow, for: .horizontal)
            value.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            checkRows[key] = value
            let row = NSStackView(views: [name, value])
            row.orientation = .horizontal
            row.distribution = .fill
            row.spacing = 8
            rows.append(row)
        }
        let checkStack = NSStackView(views: rows)
        checkStack.orientation = .vertical
        checkStack.alignment = .leading
        checkStack.spacing = 4
        for r in rows { r.widthAnchor.constraint(equalTo: checkStack.widthAnchor).isActive = true }

        let checksCard = card(title: "检查项", content: checkStack)

        // faults
        reasonsLabel.font = NSFont.systemFont(ofSize: 11)
        reasonsLabel.textColor = badColor
        reasonsLabel.maximumNumberOfLines = 4
        reasonsLabel.lineBreakMode = .byWordWrapping
        reasonsCard = card(titleView: reasonsTitle, content: reasonsLabel)

        // IP identity card
        geoBox.orientation = .vertical
        geoBox.alignment = .leading
        geoBox.spacing = 4
        geoSourceLabel.font = NSFont.systemFont(ofSize: 10)
        geoSourceLabel.textColor = .tertiaryLabelColor
        let geoContent = NSStackView(views: [geoBox, geoSourceLabel])
        geoContent.orientation = .vertical
        geoContent.alignment = .leading
        geoContent.spacing = 6
        let geoCard = card(title: "IP 身份（时间 / 地区 / 位置）", content: geoContent)

        // targets
        targetsLabel.font = NSFont.systemFont(ofSize: 11)
        targetsLabel.textColor = .secondaryLabelColor
        targetsBox.orientation = .vertical
        targetsBox.alignment = .leading
        targetsBox.spacing = 3
        let targetsScroll = NSScrollView()
        targetsScroll.hasVerticalScroller = true
        targetsScroll.drawsBackground = false
        targetsScroll.documentView = targetsBox
        targetsBox.translatesAutoresizingMaskIntoConstraints = false
        targetsScroll.translatesAutoresizingMaskIntoConstraints = false
        targetsScroll.heightAnchor.constraint(equalToConstant: 100).isActive = true
        let targetsContent = NSStackView(views: [targetsLabel, targetsScroll])
        targetsContent.orientation = .vertical
        targetsContent.alignment = .leading
        targetsContent.spacing = 6
        let targetsCard = card(title: "Claude 链进程", content: targetsContent)

        // footer
        let refresh = NSButton(title: "立即检查", target: self, action: #selector(refreshTapped))
        refresh.bezelStyle = .rounded
        let logButton = NSButton(title: "日志", target: self, action: #selector(logTapped))
        logButton.bezelStyle = .rounded
        let quitButton = NSButton(title: "退出", target: self, action: #selector(quitTapped))
        quitButton.bezelStyle = .rounded
        let geoButton = NSButton(title: "刷新 IP", target: self, action: #selector(refreshGeoTapped))
        geoButton.bezelStyle = .rounded

        enforceSwitch.target = self
        enforceSwitch.action = #selector(enforceToggled)
        enforceCaption.font = NSFont.systemFont(ofSize: 11, weight: .medium)
        enforceCaption.textColor = .secondaryLabelColor
        let enforceStack = NSStackView(views: [enforceSwitch, enforceCaption])
        enforceStack.orientation = .horizontal
        enforceStack.alignment = .centerY
        enforceStack.spacing = 6

        let buttons = NSStackView(views: [refresh, geoButton, logButton, quitButton, NSView(), enforceStack])
        buttons.orientation = .horizontal
        buttons.alignment = .centerY
        buttons.spacing = 8
        footerStack = buttons

        // assemble
        let stack = NSStackView(views: [header, liveBadge, checksCard, reasonsCard, geoCard, targetsCard, NSView(), buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 9
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -14),
            header.widthAnchor.constraint(equalTo: stack.widthAnchor),
            checksCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            reasonsCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            geoCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            targetsCard.widthAnchor.constraint(equalTo: stack.widthAnchor),
            buttons.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        targetsScroll.widthAnchor.constraint(equalTo: targetsCard.widthAnchor, constant: -20).isActive = true
        NSLayoutConstraint.activate([
            targetsBox.leadingAnchor.constraint(equalTo: targetsScroll.contentView.leadingAnchor),
            targetsBox.topAnchor.constraint(equalTo: targetsScroll.contentView.topAnchor),
            targetsBox.widthAnchor.constraint(equalTo: targetsScroll.contentView.widthAnchor),
        ])
    }

    private func card(title: String, content: NSView) -> NSBox {
        card(titleView: label(title, size: 11, weight: .semibold, color: .secondaryLabelColor),
             content: content)
    }

    private func card(titleView: NSView, content: NSView) -> NSBox {
        let box = NSBox()
        box.boxType = .custom
        box.titlePosition = .noTitle
        box.fillColor = NSColor.controlBackgroundColor.withAlphaComponent(0.6)
        box.borderColor = NSColor.separatorColor
        box.borderWidth = 1
        box.cornerRadius = 8
        let inner = NSStackView(views: [titleView, content])
        inner.orientation = .vertical
        inner.alignment = .leading
        inner.spacing = 8
        inner.translatesAutoresizingMaskIntoConstraints = false
        box.contentView?.addSubview(inner)
        if let cv = box.contentView {
            NSLayoutConstraint.activate([
                inner.leadingAnchor.constraint(equalTo: cv.leadingAnchor, constant: 10),
                inner.trailingAnchor.constraint(equalTo: cv.trailingAnchor, constant: -10),
                inner.topAnchor.constraint(equalTo: cv.topAnchor, constant: 9),
                inner.bottomAnchor.constraint(equalTo: cv.bottomAnchor, constant: -9),
            ])
        }
        return box
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
            dot.layer?.backgroundColor = warnColor.cgColor
            for (_, v) in checkRows { v.stringValue = "—" }
            reasonsLabel.stringValue = ""
            reasonsTitle.isHidden = true
            reasonsLabel.isHidden = true
            targetsLabel.stringValue = "—"
            rebuildTargets([])
            reasonsCard.isHidden = true
            renderGeo(delegate?.geo)
            let configured = delegate?.configuredEnforce()
            suppressSwitch = true
            enforceSwitch.state = (configured ?? false) ? .on : .off
            suppressSwitch = false
            enforceCaption.stringValue = configured == nil ? "" : ((configured ?? false) ? "强制执行" : "仅观察")
            enforceSwitch.isEnabled = Paths.agentLoaded
            liveBadge.stringValue = ""
            liveBadge.textColor = .tertiaryLabelColor
            return
        }

        let enforceOn = delegate?.configuredEnforce() ?? r.enforce
        let pending = Date().timeIntervalSince1970 < pendingDisableUntil

        verdictLabel.stringValue = r.healthy ? "代理正常" : "未走代理"
        verdictLabel.textColor = r.healthy ? goodColor : badColor
        var sub = "\(r.coverage) · \(relativeAge(r.ts))"
        if r.fail_count > 0 { sub += " · 连续失败 \(r.fail_count)/\(r.fail_threshold)" }
        if !Paths.agentLoaded { sub = "守护未安装" }
        if pending { sub = "再点一次开关：关闭强制执行（只记录，不杀进程）" }
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.stringValue = sub
        dot.layer?.backgroundColor = (r.healthy ? goodColor : badColor).cgColor

        liveBadge.textColor = .tertiaryLabelColor
        liveBadge.stringValue = live ? "刚刚实时检查" : ""

        func ok(_ b: Bool) -> String { b ? "✓" : "✗" }
        setRow("mihomo", "\(ok(r.mihomo_ok == 1)) " + (r.mihomo_mode.isEmpty ? "不可达" : "\(r.mihomo_mode) / \(r.proc_mode.isEmpty ? "-" : r.proc_mode)"),
               color: r.mihomo_ok == 1 ? .labelColor : badColor)
        setRow("tun", "\(ok(r.tun_cov == 1)) " + (r.tun_dev.isEmpty ? (r.tun_on == "false" ? "未开启" : "未知") : r.tun_dev),
               color: r.tun_cov == 1 ? .labelColor : badColor)
        setRow("sysproxy", r.sysproxy_desc.isEmpty ? "—" : r.sysproxy_desc,
               color: r.sysproxy_ok == 1 ? .labelColor : .secondaryLabelColor)
        let conn = "tcp \(ok(r.tcp_ok == 1))" + (r.http_codes.isEmpty ? "" : " · http \(r.http_codes)")
        setRow("connect", conn, color: (r.tcp_ok == 1 && r.http_ok == 1) ? .labelColor : warnColor)
        setRow("rules", "\(r.chain_checked) 条 · 直连 \(r.chain_direct)",
               color: r.chain_direct > 0 ? badColor : .labelColor)
        let exitOK = r.chain_audit_ok == 1 && !r.required_chain.isEmpty
            && r.chain_direct == 0 && r.chain_unverified == 0
        setRow("exit", exitOK ? "✓ \(r.required_chain)" : "未验证",
               color: exitOK ? goodColor : warnColor)
        setRow("procs", "\(r.targets.count) 个", color: .labelColor)
        setRow("socks", r.hits.isEmpty ? "无" : "\(r.hits.count) 条外部连接",
               color: r.hits.isEmpty ? .labelColor : badColor)

        var faults: [String] = []
        if r.bypass == 1 { faults.append("检测到直连或非规定出口（立即处置）") }
        if r.chain_unverified == 1 { faults.append("规则链归属无法验证，按失败处理") }
        if r.audit_failed == 1 { faults.append("ps/lsof 审计失败，无法确认没有直连") }
        if r.tun_cov != 1 && r.sysproxy_ok != 1 { faults.append("TUN 与系统代理都没有覆盖") }
        if r.mihomo_ok != 1 { faults.append("mihomo 控制面不可达") }
        if r.tcp_ok != 1 && r.http_ok != 1 && r.tun_cov != 1 { faults.append("经代理的健康探测失败") }
        if r.link_up != 1 { faults.append("物理链路 down\(r.link_iface.isEmpty ? "" : " (\(r.link_iface))")") }
        reasonsLabel.stringValue = faults.isEmpty ? "" : faults.map { "• \($0)" }.joined(separator: "\n")
        reasonsTitle.isHidden = faults.isEmpty
        reasonsLabel.isHidden = faults.isEmpty
        reasonsCard.isHidden = faults.isEmpty

        renderGeo(delegate?.geo)

        targetsLabel.stringValue = "\(r.targets.count) 个进程 · \(r.hits.count) 条外部连接"
        rebuildTargets(r.targets)

        suppressSwitch = true
        enforceSwitch.state = enforceOn ? .on : .off
        enforceSwitch.isEnabled = Paths.agentLoaded
        enforceCaption.stringValue = enforceOn ? "强制执行" : "仅观察"
        enforceCaption.textColor = enforceOn ? .labelColor : warnColor
        suppressSwitch = false
    }

    /// A live check that timed out or returned nothing must say so instead of
    /// silently leaving the old numbers on screen.
    func showLiveFailure(_ msg: String) {
        guard isViewLoaded else { return }
        liveBadge.stringValue = msg
        liveBadge.textColor = warnColor
    }

    // ---- geo card

    private func localTimeString(_ tz: String) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss zzz"
        f.timeZone = TimeZone(identifier: tz)
        return f.string(from: Date())
    }

    private func geoRow(_ name: String, _ value: String, color: NSColor = .labelColor) -> NSView {
        let n = label(name, size: 11, color: .secondaryLabelColor)
        n.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        let v = label(value, size: 11, weight: .medium, color: color)
        v.alignment = .right
        v.setContentHuggingPriority(.defaultLow, for: .horizontal)
        v.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [n, v])
        row.orientation = .horizontal
        row.distribution = .fill
        row.spacing = 8
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
        rows.append(geoRow("IP", g.ip))
        let place = g.postal.isEmpty ? g.address : "\(g.address) · \(g.postal)"
        rows.append(geoRow("地区", place, color: g.location_source == "user" ? warnColor : .labelColor))
        if !g.loc.isEmpty { rows.append(geoRow("坐标", g.loc)) }
        if !g.org.isEmpty { rows.append(geoRow("运营商", g.org)) }
        rows.append(geoRow("时区", "\(g.timezone) · \(localTimeString(g.timezone))", color: goodColor))
        let sysMatches = (g.system_tz == g.timezone)
        rows.append(geoRow("系统时区", sysMatches ? "\(g.system_tz)（一致）" : "\(g.system_tz)（不改系统，仅注入应用）",
                           color: sysMatches ? .labelColor : .secondaryLabelColor))
        rows.append(geoRow("时区注入", g.tz_applied ? "TZ=\(g.tz_env)（新启动的应用生效）" : "未写入",
                           color: g.tz_applied ? .labelColor : warnColor))
        rows.append(geoRow("遥测", g.telemetry_off ? "已关闭" : "未确认",
                           color: g.telemetry_off ? goodColor : warnColor))
        rows.append(geoRow("定位", "设备定位从不读取", color: goodColor))
        for r in rows {
            geoBox.addArrangedSubview(r)
            r.widthAnchor.constraint(equalTo: geoBox.widthAnchor).isActive = true
        }
        geoSourceLabel.stringValue =
            "来源 ipinfo · 位置=\(g.location_source == "user" ? "用户地址" : "IP") · \(relativeAge(g.fetched_at))"
    }

    private func setRow(_ key: String, _ text: String, color: NSColor) {
        guard let v = checkRows[key] else { return }
        v.stringValue = text
        v.textColor = color
    }

    private func rebuildTargets(_ targets: [Target]) {
        for v in targetsBox.arrangedSubviews { targetsBox.removeArrangedSubview(v); v.removeFromSuperview() }
        if targets.isEmpty {
            targetsBox.addArrangedSubview(label("没有 Claude 链进程在运行", size: 11, color: .secondaryLabelColor))
            return
        }
        for t in targets {
            let name = label("\(t.kind)  \(t.pid)", size: 10, weight: .semibold,
                             color: t.kind == "claude-code" ? goodColor : .labelColor)
            name.setContentHuggingPriority(.defaultHigh, for: .horizontal)
            let cmd = label(t.cmd, size: 10, color: .secondaryLabelColor)
            cmd.lineBreakMode = .byTruncatingMiddle
            cmd.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            let row = NSStackView(views: [name, cmd])
            row.orientation = .horizontal
            row.distribution = .fill
            row.spacing = 6
            targetsBox.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: targetsBox.widthAnchor).isActive = true
        }
    }

    // ---- actions

    @objc func refreshTapped() {
        delegate?.liveCheck()
    }

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
        // Turning enforcement off takes two clicks within 4 s. A modal alert
        // would have to activate the app (and steal focus); this keeps the
        // panel nonactivating.
        if enforceSwitch.state == .off {
            if now < pendingDisableUntil {
                pendingDisableUntil = 0
                finishEnforceChange(ok: delegate?.setEnforce(false) ?? false)
                return
            }
            pendingDisableUntil = now + 4
            suppressSwitch = true
            enforceSwitch.state = .on
            suppressSwitch = false
            finishEnforceChange(ok: true)
            return
        }
        pendingDisableUntil = 0
        finishEnforceChange(ok: delegate?.setEnforce(true) ?? false)
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
    // Match showPanel: lay out before asking for the fitting height.
    vc.view.layoutSubtreeIfNeeded()
    let h = min(max(vc.view.fittingSize.height, 480), 900)
    panel.setFrame(NSRect(x: 0, y: 0, width: panelWidth, height: h), display: false)
    vc.view.frame = NSRect(x: 0, y: 0, width: panelWidth, height: h)
    vc.view.layoutSubtreeIfNeeded()
    // The footer is the widest fixed row; sum its intrinsic widths plus the
    // 16 pt insets on both sides, which is the width the panel must provide.
    var footerNeed: CGFloat = 0
    if let f = vc.footerStack {
        footerNeed = f.arrangedSubviews.reduce(0) { $0 + $1.fittingSize.width }
            + CGFloat(max(0, f.arrangedSubviews.count - 1)) * f.spacing + 32
    }
    let fitting = vc.view.fittingSize
    print("ui subviews=\(vc.view.subviews.count) footer_need=\(footerNeed) fitting=\(fitting) panel=\(panel.frame.size)")
    if footerNeed > panelWidth + 0.5 {
        print("ui FAIL: footer needs \(footerNeed) pt, panel is \(panelWidth) pt")
        exit(1)
    }
    print("ui ok")
    exit(0)
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
