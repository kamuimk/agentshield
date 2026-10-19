// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "AgentShieldNetwork", platforms: [.macOS(.v14)], products: [
    .library(name: "FlowPolicy", targets: ["FlowPolicy"])
], targets: [.target(name: "FlowPolicy"), .testTarget(name: "FlowPolicyTests", dependencies: ["FlowPolicy"])])
