#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
xcrun swiftc -typecheck -target arm64-apple-macos14.0 Sources/FlowPolicy/*.swift Extension/FilterDataProvider.swift Extension/main.swift
xcrun swiftc -typecheck -target arm64-apple-macos14.0 Sources/FlowPolicy/*.swift Host/main.swift
