import Foundation
import Network

public struct FlowObservation: Codable, Equatable {
    public let instance: String
    public let at: String
    public let verdict: String
    public let codeHash: String
    public let destination: String
    public let port: Int

    public static func parse(message: String, processPath: String, instance: String) -> FlowObservation? {
        guard processPath.hasPrefix("/Library/SystemExtensions/"), processPath.hasSuffix("/AgentShieldNetwork"),
              URL(fileURLWithPath: processPath).standardized.path == processPath,
              message.hasPrefix("flow "),
              let value = try? JSONDecoder().decode(FlowObservation.self, from: Data(message.dropFirst(5).utf8)),
              UUID(uuidString: instance) != nil, value.instance == instance,
              ["observe", "allowProxy", "blockBypass", "unmanaged"].contains(value.verdict),
              value.codeHash == "unknown" || (value.codeHash.count == 40 && value.codeHash.allSatisfy({ "0123456789abcdef".contains($0) })),
              (0...65535).contains(value.port),
              value.destination == "hostname-redacted" || IPv4Address(value.destination) != nil || IPv6Address(value.destination) != nil,
              value.at.count <= 40, ISO8601DateFormatter().date(from: value.at) != nil else { return nil }
        return value
    }
}

// Sampling bounds telemetry cost only; every flow still receives a policy verdict.
public final class FlowAuditLimiter {
    private let lock = NSLock()
    private var window: TimeInterval = -1
    private var count = 0
    public init() {}
    public func accept(now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if now < window || now - window >= 1 { window = now; count = 0 }
        guard count < 4 else { return false }
        count += 1
        return true
    }
}
