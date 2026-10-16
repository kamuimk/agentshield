import Foundation
import Network
import CryptoKit
import Darwin

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


/// A running older provider must not attest to a newly installed security build.
public enum ProviderImage {
    public static func matches(actual: URL, bundled: URL) -> Bool {
        func digest(_ url: URL) -> SHA256.Digest? {
            do {
                let descriptor = url.withUnsafeFileSystemRepresentation { path in
                    guard let path else { return Int32(-1) }
                    return Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
                }
                guard descriptor >= 0 else { return nil }
                defer { _ = Darwin.close(descriptor) }
                var metadata = stat()
                let limit = 32 * 1024 * 1024
                guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
                      metadata.st_size > 0, metadata.st_size <= limit else { return nil }
                let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
                guard let data = try handle.read(upToCount: limit + 1), data.count == metadata.st_size,
                      data.count <= limit else { return nil }
                return SHA256.hash(data: data)
            } catch { return nil }
        }
        guard let expected = digest(bundled), let observed = digest(actual) else { return false }
        return expected == observed
    }
}
