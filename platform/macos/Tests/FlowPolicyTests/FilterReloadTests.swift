import XCTest
@testable import FlowPolicy

final class FilterReloadTests: XCTestCase {
    enum Failure: Error { case fixture }

    func testRunningProviderAdoptsNewInstanceInsteadOfKeepingPreviousOne() {
        var enabled = true, configured = "previous", running: String? = "previous"
        var phases: [String] = []
        FilterReload.run(wasEnabled: enabled, stop: { done in
            phases.append("stop"); enabled = false; running = nil; done(nil)
        }, reload: { done in
            phases.append("reload"); XCTAssertFalse(enabled); done(nil)
        }, start: { done in
            phases.append("start"); configured = "current"
            // Model the observed OS behavior: an already running provider
            // retains its configuration until it is stopped and started.
            if !enabled { running = configured }
            enabled = true; done(nil)
        }, completion: { phase, error in
            XCTAssertNil(phase); XCTAssertNil(error)
        })
        XCTAssertEqual(phases, ["stop", "reload", "start"])
        XCTAssertEqual(running, "current")
    }

    func testDisabledFilterStartsWithoutAnUnnecessaryStop() {
        var started = false
        FilterReload.run(wasEnabled: false,
            stop: { _ in XCTFail("must not stop") },
            reload: { _ in XCTFail("initial preferences already loaded") },
            start: { done in started = true; done(nil) },
            completion: { phase, error in XCTAssertNil(phase); XCTAssertNil(error) })
        XCTAssertTrue(started)
    }

    func testFailuresNeverAdvanceToTheNextStep() {
        for failing in ["stop", "reload", "start"] {
            var phases: [String] = [], completions = 0
            func step(_ name: String) -> FilterReload.Step {
                return { done in
                    phases.append(name); done(name == failing ? Failure.fixture : nil)
                }
            }
            FilterReload.run(wasEnabled: true, stop: step("stop"),
                reload: step("reload"), start: step("start"), completion: { phase, error in
                    completions += 1; XCTAssertEqual(phase, failing); XCTAssertNotNil(error)
                })
            let expected = Array(["stop", "reload", "start"].prefix(phases.count))
            XCTAssertEqual(phases, expected); XCTAssertEqual(phases.last, failing)
            XCTAssertEqual(completions, 1)
        }
    }

    func testPendingStopAndReloadCannotStartProviderEarly() {
        var stopped: ((Error?) -> Void)?, reloaded: ((Error?) -> Void)?
        var started = false, completed = false
        FilterReload.run(wasEnabled: true, stop: { stopped = $0 },
            reload: { reloaded = $0 }, start: { done in started = true; done(nil) },
            completion: { _, _ in completed = true })
        XCTAssertFalse(started); XCTAssertNil(reloaded)
        stopped?(nil)
        XCTAssertFalse(started); XCTAssertFalse(completed)
        reloaded?(nil)
        XCTAssertTrue(started); XCTAssertTrue(completed)
    }
}
