import Foundation

public struct NetworkPolicy: Codable, Equatable {
    public enum Mode: String, Codable { case monitor, enforceManaged }
    public let mode: Mode
    /// Exact code directory hashes, obtained from the kernel audit token and Security.framework.
    public let managedCodeHashes: Set<String>
    public let proxyPort: UInt16
    public init(mode: Mode, managedCodeHashes: Set<String>, proxyPort: UInt16) throws {
        guard proxyPort > 0, managedCodeHashes.count <= 128,
              managedCodeHashes.allSatisfy({ $0.count == 40 && $0.allSatisfy({ "0123456789abcdef".contains($0) }) }),
              mode != .enforceManaged || !managedCodeHashes.isEmpty else { throw PolicyError.invalid }
        self.mode = mode; self.managedCodeHashes = managedCodeHashes; self.proxyPort = proxyPort
    }
    public enum PolicyError: Error { case invalid }
    public enum Verdict: String { case observe, allowProxy, blockBypass, unmanaged }
    public func decide(codeHash: String?, host: String?, port: UInt16?, isTCP: Bool, outbound: Bool, protectedRemote: Bool = false) -> Verdict {
        guard !protectedRemote else { return .unmanaged }
        guard outbound else { return .unmanaged }
        guard mode == .enforceManaged else { return .observe }
        // Unknown attribution cannot be claimed as a managed process. The provider
        // reports it; this policy intentionally does not block unrelated personal apps.
        guard let codeHash, managedCodeHashes.contains(codeHash) else { return .unmanaged }
        if isTCP && (host == "127.0.0.1" || host == "::1") && port == proxyPort { return .allowProxy }
        // Includes direct TLS, QUIC, custom TCP ports, DNS and a second local proxy.
        return .blockBypass
    }
    public static func parse(_ data: Data) throws -> NetworkPolicy {
        let value = try JSONDecoder().decode(NetworkPolicy.self, from: data)
        return try NetworkPolicy(mode: value.mode, managedCodeHashes: value.managedCodeHashes, proxyPort: value.proxyPort)
    }
}
