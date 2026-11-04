#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
AGENTSHIELD_TYPECHECK_DIR="$(mktemp -d -t agentshield-typecheck)"
trap 'rm -rf -- "$AGENTSHIELD_TYPECHECK_DIR"' EXIT
# build.sh generates the public build identifier; typechecking needs the same
# declaration without producing or installing a native build.
printf '%s\n' 'enum AgentShieldProviderBuild { static let identifier = "0" }' > "$AGENTSHIELD_TYPECHECK_DIR/AgentShieldProviderBuild.swift"
xcrun swiftc -typecheck -target arm64-apple-macos14.0 Sources/FlowPolicy/*.swift "$AGENTSHIELD_TYPECHECK_DIR/AgentShieldProviderBuild.swift" Extension/FilterDataProvider.swift Extension/main.swift
xcrun swiftc -typecheck -target arm64-apple-macos14.0 Sources/FlowPolicy/*.swift Host/main.swift
