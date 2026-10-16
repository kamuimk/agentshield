import Foundation
import NetworkExtension
import Network
import Security
import OSLog

@objc(AgentShieldFilterDataProvider)
final class FilterDataProvider: NEFilterDataProvider {
    private let audit = Logger(subsystem: "com.nation-a.agentshield.network", category: "flow")
    private var policy: NetworkPolicy?
    private let auditLimiter = FlowAuditLimiter()
    private var heartbeat: DispatchSourceTimer?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let raw = filterConfiguration.vendorConfiguration?["policy"] as? Data else {
                throw NetworkPolicy.PolicyError.invalid
            }
            policy = try NetworkPolicy.parse(raw)
            let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
            apply(settings) { error in
                if error == nil {
                    let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
                    let instance = self.filterConfiguration.vendorConfiguration?["instance"] as? String ?? "unknown"
                    timer.schedule(deadline: .now(), repeating: 10)
                    timer.setEventHandler { self.audit.notice("heartbeat instance=\(instance, privacy: .public)") }
                    self.heartbeat = timer
                    timer.resume()
                }
                completionHandler(error)
            }
        } catch { completionHandler(error) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        heartbeat?.cancel()
        heartbeat = nil
        policy = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let policy else { return .drop() }
        guard let socket = flow as? NEFilterSocketFlow else { return .allow() }
        let endpoint = socket.remoteEndpoint as? NWHostEndpoint
        let identity = Self.codeHash(flow.sourceProcessAuditToken ?? flow.sourceAppAuditToken)
        let verdict = policy.decide(codeHash: identity, host: endpoint?.hostname,
                                    port: endpoint.flatMap { UInt16($0.port) },
                                    isTCP: socket.socketProtocol == IPPROTO_TCP,
                                    outbound: flow.direction == .outbound)
        // No URL path, payload, account identifier or token is inspected or logged
        // at this layer. TLS body inspection belongs to the explicit proxy/hook.
        if flow.direction == .outbound && auditLimiter.accept() {
            let host = endpoint?.hostname ?? ""
            let destination = IPv4Address(host) != nil || IPv6Address(host) != nil ? host : "hostname-redacted"
            let event: [String: Any] = ["instance": filterConfiguration.vendorConfiguration?["instance"] as? String ?? "unknown",
                "at": ISO8601DateFormatter().string(from: Date()),
                "verdict": verdict.rawValue, "codeHash": identity ?? "unknown",
                "destination": destination, "port": Int(endpoint?.port ?? "") ?? 0]
            if let data = try? JSONSerialization.data(withJSONObject: event), let text = String(data: data, encoding: .utf8) {
                audit.notice("flow \(text, privacy: .public)")
            }
        }
        return verdict == .blockBypass ? .drop() : .allow()
    }

    static func codeHash(_ token: Data?) -> String? {
        guard let token else { return nil }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let hash = dictionary[kSecCodeInfoUnique as String] as? Data else { return nil }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
