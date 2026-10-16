import XCTest
@testable import FlowPolicy
final class FlowAuditTests: XCTestCase {
    let path = "/Library/SystemExtensions/fixture/Provider.systemextension/Contents/MacOS/AgentShieldNetwork"
    let instance = "00000000-0000-4000-8000-000000000001"
    let event = #"flow {"instance":"00000000-0000-4000-8000-000000000001","at":"2026-10-16T00:00:00Z","verdict":"observe","codeHash":"unknown","destination":"127.0.0.1","port":443}"#
    func testSamplingIsBoundedAndResumes() {
        let limiter = FlowAuditLimiter()
        for _ in 0..<4 { XCTAssertTrue(limiter.accept(now: 10)) }
        XCTAssertFalse(limiter.accept(now: 10.9))
        XCTAssertTrue(limiter.accept(now: 11))
    }
    func testPreviousActivationCannotSupplyCurrentEvents() {
        XCTAssertNil(FlowObservation.parse(message: event, processPath: path,
            instance: "00000000-0000-4000-8000-000000000002"))
    }
    func testOnlyValidatedProviderMetadataIsAccepted() {
        XCTAssertNotNil(FlowObservation.parse(message: event, processPath: path, instance: instance))
        XCTAssertNil(FlowObservation.parse(message: event, processPath: "/tmp/AgentShieldNetwork", instance: instance))
        XCTAssertNil(FlowObservation.parse(message: event.replacingOccurrences(of: "127.0.0.1", with: "secret.example.test"), processPath: path, instance: instance))
        XCTAssertNil(FlowObservation.parse(message: event.replacingOccurrences(of: "observe", with: "<script>"), processPath: path, instance: instance))
    }
    func testOlderProviderCannotAttestToUpdatedBundle() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let actual = directory.appendingPathComponent("running")
        let bundled = directory.appendingPathComponent("bundled")
        try Data("old-provider".utf8).write(to: actual)
        try Data("new-provider".utf8).write(to: bundled)
        XCTAssertFalse(ProviderImage.matches(actual: actual, bundled: bundled))
        try Data("new-provider".utf8).write(to: actual)
        XCTAssertTrue(ProviderImage.matches(actual: actual, bundled: bundled))
        try FileManager.default.removeItem(at: actual)
        try FileManager.default.createSymbolicLink(at: actual, withDestinationURL: bundled)
        XCTAssertFalse(ProviderImage.matches(actual: actual, bundled: bundled))
    }

}
