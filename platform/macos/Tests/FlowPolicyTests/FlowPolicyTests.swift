import XCTest
@testable import FlowPolicy
final class FlowPolicyTests: XCTestCase {
    let fixtureHash = String(repeating: "a", count: 40)
    func testManagedTrafficCanOnlyReachExactProxy() throws {
        let policy = try NetworkPolicy(mode: .enforceManaged, managedCodeHashes: [fixtureHash], proxyPort: 18080)
        XCTAssertEqual(policy.decide(codeHash: fixtureHash, host: "127.0.0.1", port: 18080, isTCP: true, outbound: true), .allowProxy)
        for (host, port, tcp) in [("1.1.1.1", UInt16(443), true), ("1.1.1.1", 443, false), ("127.0.0.1", 9999, true), ("8.8.8.8", 53, false)] {
            XCTAssertEqual(policy.decide(codeHash: fixtureHash, host: host, port: port, isTCP: tcp, outbound: true), .blockBypass)
        }
        XCTAssertEqual(policy.decide(codeHash: nil, host: "1.1.1.1", port: 443, isTCP: true, outbound: true), .unmanaged)
        XCTAssertEqual(policy.decide(codeHash: String(repeating: "b", count: 40), host: "1.1.1.1", port: 443, isTCP: true, outbound: true), .unmanaged)
    }
    func testMonitorDoesNotClaimEnforcement() throws {
        let policy = try NetworkPolicy(mode: .monitor, managedCodeHashes: [], proxyPort: 18080)
        XCTAssertEqual(policy.decide(codeHash: fixtureHash, host: "1.1.1.1", port: 443, isTCP: true, outbound: true), .observe)
    }
    func testVerifiedRemoteAdministrationCannotBecomeManagedTraffic() throws {
        let policy = try NetworkPolicy(mode: .enforceManaged, managedCodeHashes: [fixtureHash], proxyPort: 18080)
        for tcp in [true, false] {
            for outbound in [true, false] {
                for port: UInt16 in [53, 443, 3389, 24327, 65535] {
                    XCTAssertEqual(policy.decide(codeHash: fixtureHash, host: "203.0.113.7", port: port,
                        isTCP: tcp, outbound: outbound, protectedRemote: true), .unmanaged)
                }
            }
        }
        // The exemption does not weaken the same policy for a managed agent.
        XCTAssertEqual(policy.decide(codeHash: fixtureHash, host: "203.0.113.7", port: 443,
            isTCP: true, outbound: true), .blockBypass)
    }

    func testMalformedAndEmptyEnforcementRejected() {
        XCTAssertThrowsError(try NetworkPolicy(mode: .enforceManaged, managedCodeHashes: [], proxyPort: 18080))
        XCTAssertThrowsError(try NetworkPolicy(mode: .enforceManaged, managedCodeHashes: ["attacker"], proxyPort: 18080))
        XCTAssertThrowsError(try NetworkPolicy.parse(Data(#"{"mode":"enforceManaged","managedCodeHashes":[],"proxyPort":0}"#.utf8)))
    }
}
