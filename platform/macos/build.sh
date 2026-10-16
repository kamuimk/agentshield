#!/usr/bin/env bash
# Build artifacts only. Never installs a certificate, changes network preferences,
# activates an extension, or signs with a user's identity implicitly.
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:?usage: build.sh OUTPUT_DIRECTORY [EXTENSION_BUNDLE_ID]}"
IDENTIFIER="${2:-com.nation-a.workos.agentshield.network}"
[[ "$IDENTIFIER" =~ ^[A-Za-z0-9.-]+$ ]] || { echo 'invalid bundle identifier' >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
EXT="$OUT/$IDENTIFIER.systemextension"
mkdir -p "$EXT/Contents/MacOS"
xcrun swiftc -O -target arm64-apple-macos14.0 -module-name AgentShieldNetwork \
  Sources/FlowPolicy/*.swift Extension/FilterDataProvider.swift Extension/main.swift \
  -o "$EXT/Contents/MacOS/AgentShieldNetwork"
xcrun swiftc -O -emit-library -module-name AgentShieldNetworkHost -target arm64-apple-macos14.0 Sources/FlowPolicy/*.swift Host/main.swift \
  -o "$OUT/libAgentShieldNetwork.dylib"
python3 - "$EXT" "$IDENTIFIER" <<'PY'
import os, pathlib, plistlib, re, sys, time
extension, identifier = pathlib.Path(sys.argv[1]), sys.argv[2]
build = os.environ.get('AGENTSHIELD_BUILD_VERSION')
if not build:
    build = (os.environ['GITHUB_RUN_ID'] + '.' + os.environ.get('GITHUB_RUN_ATTEMPT', '1')
             if os.environ.get('GITHUB_RUN_ID') else str(time.time_ns()))
if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', build) or len(build) > 64:
    raise ValueError('invalid native build version')
info = {'CFBundleIdentifier':identifier,'CFBundleExecutable':'AgentShieldNetwork',
        'NSSystemExtensionUsageDescription':'WorkOS uses this extension to observe network connections for service protection.',
        'CFBundleName':'AgentShield Network','CFBundlePackageType':'SYSX',
        'CFBundleVersion':build,'CFBundleShortVersionString':'0.1.0',
        'LSMinimumSystemVersion':'14.0',
        'NetworkExtension':{'NEProviderClasses':{'com.apple.networkextension.filter-data':'AgentShieldFilterDataProvider'},
                            'NEMachServiceName':'$(TeamIdentifierPrefix)'+identifier}}
(extension/'Contents'/'Info.plist').write_bytes(plistlib.dumps(info))
PY
cp extension.entitlements "$OUT/extension.entitlements"
cp host.entitlements "$OUT/host.entitlements"
printf 'Built %s\n' "$EXT"
