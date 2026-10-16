import Foundation
import NetworkExtension
import SystemExtensions

// Installed inside WorkOS.app/Contents/MacOS. Only explicit enable/disable commands
// mutate OS preferences; status never triggers a system consent prompt.
func output(_ value: [String: Any], exitCode: Int32 = 0) -> Never {
    let data = (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])) ?? Data("{}".utf8)
    FileHandle.standardOutput.write(data + Data([10]))
    exit(exitCode)
}
func runtimeEvidence(instance: String) -> Bool {
    guard UUID(uuidString: instance) != nil else { return false }
    let process = Process(), output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
    process.arguments = ["show", "--last", "30s", "--style", "ndjson", "--predicate", "subsystem == 'com.nation-a.agentshield.network' AND category == 'flow'"]
    process.standardOutput = output; process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return false }
    let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5, execute: deadline)
    defer { deadline.cancel() }
    var bytes = Data()
    while true {
        let chunk = output.fileHandleForReading.readData(ofLength: 4096)
        if chunk.isEmpty { break }
        bytes.append(chunk)
        if bytes.count > 262144 { process.terminate(); process.waitUntilExit(); return false }
    }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return false }
    for line in bytes.split(separator: 10) {
        guard let row = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
              let path = row["processImagePath"] as? String,
              path.hasPrefix("/Library/SystemExtensions/"), path.hasSuffix("/AgentShieldNetwork"),
              let message = row["eventMessage"] as? String,
              message == "heartbeat instance=" + instance else { continue }
        return true
    }
    return false
}

final class Activation: NSObject, OSSystemExtensionRequestDelegate {
    let identifier: String
    let policy: Data
    init(identifier: String, policy: Data) { self.identifier = identifier; self.policy = policy }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // The request stays alive until macOS reports completion or the caller's
        // bounded timeout terminates this process. Never mark consent as granted.
        FileHandle.standardError.write(Data("system_approval_required\n".utf8))
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        output(["ok": false, "code": "system_extension_activation_failed"], exitCode: 1)
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .willCompleteAfterReboot { output(["ok": true, "state": "reboot_required"]) }
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            guard error == nil else { output(["ok": false, "code": "filter_load_failed"], exitCode: 1) }
            // Do not take over another vendor's active content-filter configuration.
            if let existing = manager.providerConfiguration?.filterDataProviderBundleIdentifier,
               existing != self.identifier {
                output(["ok": false, "code": "filter_owner_conflict"], exitCode: 1)
            }
            let config = NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.filterDataProviderBundleIdentifier = self.identifier
            config.vendorConfiguration = ["policy": self.policy, "instance": UUID().uuidString]
            manager.providerConfiguration = config
            manager.localizedDescription = "WorkOS AgentShield service protection"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                guard error == nil else { output(["ok": false, "code": "filter_save_failed"], exitCode: 1) }
                output(["ok": true, "state": "configured", "runtime_verified": false])
            }
        }
    }
}
let args = CommandLine.arguments
let identifier = Bundle.main.object(forInfoDictionaryKey: "AgentShieldNetworkExtensionIdentifier") as? String
    ?? "com.nation-a.workos.agentshield.network"
guard args.count >= 2 else { output(["ok": false, "code": "command_required"], exitCode: 1) }
var activation: Activation?
switch args[1] {
case "status":
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { error in
        guard error == nil else { output(["ok": false, "code": "filter_load_failed"], exitCode: 1) }
        let ours = manager.providerConfiguration?.filterDataProviderBundleIdentifier == identifier
        // Preferences alone are not evidence that the extension is running.
        let instance = manager.providerConfiguration?.vendorConfiguration?["instance"] as? String ?? ""
        let verified = ours && manager.isEnabled && runtimeEvidence(instance: instance)
        output(["ok": true, "configured": ours, "enabled": ours && manager.isEnabled, "runtime_verified": verified])
    }
case "enable":
    guard args.count == 3,
          let data = try? Data(contentsOf: URL(fileURLWithPath: args[2])), data.count <= 65536,
          (try? NetworkPolicy.parse(data)) != nil else { output(["ok": false, "code": "invalid_policy"], exitCode: 1) }
    activation = Activation(identifier: identifier, policy: data)
    let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
    request.delegate = activation
    OSSystemExtensionManager.shared.submitRequest(request)
case "disable":
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { error in
        guard error == nil, manager.providerConfiguration?.filterDataProviderBundleIdentifier == identifier else {
            output(["ok": false, "code": "filter_not_owned"], exitCode: 1)
        }
        manager.isEnabled = false
        manager.saveToPreferences { error in output(["ok": error == nil, "state": error == nil ? "disabled" : "disable_failed"]) }
    }
default: output(["ok": false, "code": "unknown_command"], exitCode: 1)
}
DispatchQueue.main.asyncAfter(deadline: .now() + 55) { output(["ok": false, "code": "approval_or_operation_timeout"], exitCode: 1) }
RunLoop.main.run()
