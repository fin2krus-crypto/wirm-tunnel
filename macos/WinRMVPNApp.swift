import Cocoa
import SwiftUI

struct CtlMeta: Codable { let port: Int; let token: String; let pid: Int }
struct StatusResponse: Codable { let state: String; let check_conn: Bool; let logs: [String] }

final class VpnViewModel: ObservableObject {
    @Published var server: String { didSet { UserDefaults.standard.set(server, forKey: "winrm_server") } }
    @Published var psk: String { didSet { UserDefaults.standard.set(psk, forKey: "winrm_psk") } }
    @Published var pin: String { didSet { UserDefaults.standard.set(pin, forKey: "winrm_pin") } }
    @Published var checkConn: Bool {
        didSet {
            UserDefaults.standard.set(checkConn, forKey: "winrm_check_conn")
            pushWatchdogState(enabled: checkConn)
        }
    }
    @Published var state: String = "DISCONNECTED"
    @Published var errorMsg: String = ""
    @Published var pingResult: String = ""
    @Published var pingOk: Bool = true
    @Published var ipResult: String = ""
    @Published var ipOk: Bool = true
    @Published var logs: [String] = []

    var onStateChange: ((String) -> Unit)?
    private var pollTimer: Timer?
    private let ctlMetaPath = "/tmp/winrm-vpn-ctl.json"

    init() {
        self.server = UserDefaults.standard.string(forKey: "winrm_server") ?? ""
        self.psk = UserDefaults.standard.string(forKey: "winrm_psk") ?? ""
        self.pin = UserDefaults.standard.string(forKey: "winrm_pin") ?? ""
        self.checkConn = UserDefaults.standard.bool(forKey: "winrm_check_conn")
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in self?.fetchStatus() }
    }

    private func loadMeta() -> CtlMeta? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: ctlMetaPath)) else { return nil }
        return try? JSONDecoder().decode(CtlMeta.self, from: data)
    }

    private func fetchStatus() {
        guard let meta = loadMeta(), let url = URL(string: "http://127.0.0.1:\(meta.port)/status") else {
            DispatchQueue.main.async {
                if self.state == "CONNECTED" || self.state == "CONNECTING" {
                    self.state = "DISCONNECTED"; self.onStateChange?("DISCONNECTED")
                }
            }
            return
        }
        var req = URLRequest(url: url, timeoutInterval: 1.0)
        req.setValue(meta.token, forHTTPHeaderField: "X-Ctl-Token")
        URLSession.shared.dataTask(with: req) { [weak self] data, _, err in
            guard let self = self else { return }
            if err != nil || data == nil {
                DispatchQueue.main.async {
                    if self.state == "CONNECTED" || self.state == "CONNECTING" {
                        self.state = "DISCONNECTED"; self.onStateChange?("DISCONNECTED")
                    }
                }
                return
            }
            if let resp = try? JSONDecoder().decode(StatusResponse.self, from: data!) {
                DispatchQueue.main.async {
                    if self.state != resp.state { self.state = resp.state; self.onStateChange?(resp.state) }
                    self.logs = resp.logs
                }
            }
        }.resume()
    }

    func validate() -> Bool {
        let srv = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = psk.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanPin = pin.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ":", with: "")
        let parts = srv.split(separator: ":")
        if srv.isEmpty || parts.count != 2 || parts[0].isEmpty || Int(parts[1]) == nil || !(1...65535).contains(Int(parts[1])!) {
            errorMsg = "Ошибка: укажите сервер в формате IP:Port."; return false
        }
        if key.isEmpty { errorMsg = "Ошибка: не указан PSK."; return false }
        if !cleanPin.isEmpty {
            let hexSet = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
            if cleanPin.count != 64 || cleanPin.unicodeScalars.contains(where: { !hexSet.contains($0) }) {
                errorMsg = "Ошибка: SHA-256 Pin должен содержать 64 hex-символа."; return false
            }
        }
        errorMsg = ""; return true
    }

    func connect() {
        guard validate() else { return }
        pingResult = ""; ipResult = ""
        guard let helperURL = Bundle.main.url(forResource: "winrm-vpn-helper", withExtension: nil) else {
            errorMsg = "Ошибка: не найден winrm-vpn-helper"; return
        }
        let cfgObj: [String: Any] = [
            "server": server.trimmingCharacters(in: .whitespacesAndNewlines),
            "psk": psk.trimmingCharacters(in: .whitespacesAndNewlines),
            "pin": pin.trimmingCharacters(in: .whitespacesAndNewlines),
            "check_conn": checkConn
        ]
        let cfgPath = "/tmp/winrm-vpn-cfg-\(UUID().uuidString).json"
        guard let cfgData = try? JSONSerialization.data(withJSONObject: cfgObj) else { return }
        try? cfgData.write(to: URL(fileURLWithPath: cfgPath))
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: cfgPath)

        let escapedHelper = helperURL.path.replacingOccurrences(of: "'", with: "'\\''")
        let shellCmd = "'\(escapedHelper)' -config '\(cfgPath)' >/tmp/winrm-vpn-mac.log 2>&1 </dev/null &"
        let appleScriptSource = "do shell script \"\(shellCmd.replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"

        state = "CONNECTING"; onStateChange?("CONNECTING")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var errDict: NSDictionary?
            NSAppleScript(source: appleScriptSource)?.executeAndReturnError(&errDict)
            if let errDict = errDict {
                try? FileManager.default.removeItem(atPath: cfgPath)
                let msg = (errDict[NSAppleScript.errorMessage] as? String) ?? "Отменено"
                DispatchQueue.main.async {
                    self?.state = "DISCONNECTED"; self?.onStateChange?("DISCONNECTED")
                    self?.errorMsg = "Запуск отменён: \(msg)"
                }
            }
        }
    }

    func disconnect(syncWait: Bool = false) {
        guard let meta = loadMeta(), let url = URL(string: "http://127.0.0.1:\(meta.port)/stop") else {
            state = "DISCONNECTED"; onStateChange?("DISCONNECTED"); return
        }
        var req = URLRequest(url: url, timeoutInterval: 2.0); req.httpMethod = "POST"
        req.setValue(meta.token, forHTTPHeaderField: "X-Ctl-Token")
        let sem = syncWait ? DispatchSemaphore(value: 0) : nil
        URLSession.shared.dataTask(with: req) { [weak self] _, _, _ in
            DispatchQueue.main.async {
                self?.state = "DISCONNECTED"; self?.pingResult = ""; self?.ipResult = ""
                self?.onStateChange?("DISCONNECTED")
            }
            sem?.signal()
        }.resume()
        _ = sem?.wait(timeout: .now() + 2.0)
    }

    private func pushWatchdogState(enabled: Bool) {
        guard let meta = loadMeta(), let url = URL(string: "http://127.0.0.1:\(meta.port)/watchdog?enabled=\(enabled)") else { return }
        var req = URLRequest(url: url, timeoutInterval: 1.5); req.httpMethod = "POST"
        req.setValue(meta.token, forHTTPHeaderField: "X-Ctl-Token")
        URLSession.shared.dataTask(with: req).resume()
    }

    func testPing() {
        guard let meta = loadMeta(), let url = URL(string: "http://127.0.0.1:\(meta.port)/ping") else { return }
        pingResult = "Выполняется ping 8.8.8.8..."; pingOk = true
        var req = URLRequest(url: url, timeoutInterval: 6.0); req.httpMethod = "POST"
        req.setValue(meta.token, forHTTPHeaderField: "X-Ctl-Token")
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, _ in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 500
            let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? "Ошибка"
            DispatchQueue.main.async { self?.pingOk = (code == 200); self?.pingResult = text }
        }.resume()
    }

    func checkIP() {
        guard let meta = loadMeta(), let url = URL(string: "http://127.0.0.1:\(meta.port)/checkip") else { return }
        ipResult = "Запрос ifconfig.io..."; ipOk = true
        var req = URLRequest(url: url, timeoutInterval: 8.0); req.httpMethod = "POST"
        req.setValue(meta.token, forHTTPHeaderField: "X-Ctl-Token")
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, _ in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 500
            let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? "Ошибка"
            DispatchQueue.main.async { self?.ipOk = (code == 200); self?.ipResult = text }
        }.resume()
    }

    func showInfoDialog() {
        let alert = NSAlert()
        alert.messageText = "Проверка соединения (Watchdog)"
        alert.informativeText = "При включённом переключателе и активном туннеле:\n\n1. Пассивный контроль: если в течение 30-60с приходили данные, проверок нет.\n2. В простое отправляется WinRM KeepAlive фрейм (размером под SOAP).\n3. При отсутствии ответа - повтор через 10-20с, затем перезапуск VPN."
        alert.alertStyle = .informational; alert.addButton(withTitle: "Понятно"); alert.runModal()
    }
}

typealias Unit = Void

struct PopoverView: View {
    @ObservedObject var vm: VpnViewModel
    var statusColor: Color {
        switch vm.state { case "CONNECTED": return .green; case "CONNECTING": return .yellow; case "ERROR": return .red; default: return .gray }
    }
    var statusLabel: String {
        switch vm.state { case "CONNECTED": return "Подключено"; case "CONNECTING": return "Подключение..."; case "ERROR": return "Ошибка (см. логи)"; default: return "Отключено" }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("WinRM-VPN").font(.system(.headline, design: .monospaced)).foregroundColor(.green)
                Text("v0.4.1").font(.system(.caption, design: .monospaced)).foregroundColor(.secondary)
                Spacer()
                Circle().fill(statusColor).frame(width: 9, height: 9)
                Text(statusLabel).font(.caption).foregroundColor(statusColor)
            }
            Text("Should looks like Ansible (macOS Universal)").font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary)
            Divider()
            VStack(alignment: .leading, spacing: 6) {
                TextField("Server IP:Port (203.0.113.10:5986)", text: $vm.server).textFieldStyle(.roundedBorder)
                SecureField("Pre-Shared Key (PSK)", text: $vm.psk).textFieldStyle(.roundedBorder)
                TextField("Cert SHA-256 Pin (64 hex, optional)", text: $vm.pin).textFieldStyle(.roundedBorder)
            }
            HStack {
                Toggle("Проверять соединение", isOn: $vm.checkConn).toggleStyle(.switch).font(.caption)
                Spacer()
                Button("(?)") { vm.showInfoDialog() }.buttonStyle(.plain).foregroundColor(.blue)
            }
            if !vm.errorMsg.isEmpty { Text(vm.errorMsg).font(.caption).foregroundColor(.red) }
            HStack(spacing: 8) {
                Button("Connect") { vm.connect() }.disabled(vm.state == "CONNECTED" || vm.state == "CONNECTING").keyboardShortcut(.defaultAction)
                Button("Disconnect") { vm.disconnect() }.disabled(vm.state == "DISCONNECTED")
                Spacer()
                Button("Выход") { vm.disconnect(syncWait: true); NSApplication.shared.terminate(nil) }
            }
            HStack(spacing: 8) {
                Button("Тест ping 8.8.8.8") { vm.testPing() }.disabled(vm.state != "CONNECTED").font(.caption)
                Button("Проверить IP и страну") { vm.checkIP() }.disabled(vm.state != "CONNECTED").font(.caption)
            }
            if !vm.pingResult.isEmpty { Text(vm.pingResult).font(.caption.bold()).foregroundColor(vm.pingOk ? .green : .red) }
            if !vm.ipResult.isEmpty { Text(vm.ipResult).font(.caption.bold()).foregroundColor(vm.ipOk ? .green : .red) }
            Text("Логи:").font(.caption).foregroundColor(.secondary)
            ScrollViewReader { proxy in
                ScrollView {
                    Text(vm.logs.joined(separator: "\n")).font(.system(size: 10, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading).padding(6).textSelection(.enabled)
                    Color.clear.frame(height: 1).id("BOTTOM")
                }.frame(height: 165).background(Color.black.opacity(0.85)).cornerRadius(6)
                .onChange(of: vm.logs.count) { _ in proxy.scrollTo("BOTTOM", anchor: .bottom) }
            }
        }.padding(14).frame(width: 390)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!; var popover: NSPopover!; let vm = VpnViewModel()
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        updateMenuIcon(state: vm.state)
        vm.onStateChange = { [weak self] st in self?.updateMenuIcon(state: st) }
        if let btn = statusItem.button { btn.action = #selector(togglePopover(_:)); btn.target = self }
        popover = NSPopover(); popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: PopoverView(vm: vm))
    }
    func updateMenuIcon(state: String) {
        guard let btn = statusItem?.button else { return }
        btn.image = NSImage(systemSymbolName: "terminal.fill", accessibilityDescription: "WinRM-VPN")
        btn.title = state == "CONNECTED" ? " ON" : (state == "CONNECTING" ? " ..." : "")
    }
    @objc func togglePopover(_ sender: AnyObject?) {
        guard let btn = statusItem.button else { return }
        if popover.isShown { popover.performClose(sender) }
        else { NSApp.activate(ignoringOtherApps: true); popover.show(relativeTo: btn.bounds, of: btn, preferredEdge: .minY) }
    }
    func applicationWillTerminate(_ notification: Notification) { vm.disconnect(syncWait: true) }
}
let app = NSApplication.shared; let delegate = AppDelegate(); app.delegate = delegate; app.run()
