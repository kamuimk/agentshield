import Foundation

/// Saving a new enabled configuration can leave an already running provider
/// using the previous instance. Stop our filter, reload preferences, then start
/// with the new configuration. A failed step never advances the transaction.
public enum FilterReload {
    public typealias Step = (@escaping (Error?) -> Void) -> Void
    public static func run(wasEnabled: Bool, stop: @escaping Step,
                           reload: @escaping Step, start: @escaping Step,
                           completion: @escaping (String?, Error?) -> Void) {
        let begin = { start { error in completion(error == nil ? nil : "start", error) } }
        guard wasEnabled else { begin(); return }
        stop { error in
            guard error == nil else { completion("stop", error); return }
            reload { error in
                guard error == nil else { completion("reload", error); return }
                begin()
            }
        }
    }
}
