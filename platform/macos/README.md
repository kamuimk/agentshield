# macOS network supervision

This is an actual Network Extension data provider and host controller, separate
from the AgentShield HTTP/TLS inspection engine. WorkOS is the host application;
it is not an operating system.

- `swift test --package-path platform/macos` verifies the pure flow decision policy.
- `bash platform/macos/typecheck.sh` checks both native entry points with Apple's SDK.
- `bash platform/macos/build.sh /absolute/output com.example.workos.agentshield.network`
  produces an arm64 macOS 14+ system extension and host library. It does not install,
  activate, modify trust stores, or silently use a signing identity.
- The extension observes outbound flows. In `enforceManaged` mode, exact configured
  executable code hashes can reach only the configured loopback proxy TCP port.
  Direct TLS, alternate proxies, UDP/QUIC and direct DNS from those executables
  are blocked. Unmanaged applications retain their existing network behavior.
- Kernel audit tokens are resolved with Security.framework and checked for code
  validity. PID strings, executable names and a user-supplied bundle id are not
  trusted process identities. Unknown attribution remains unmanaged and must not
  be represented as universal enforcement.
- Unified logging contains verdict, code hash, numeric destination IP and port.
  Hostnames are redacted. Telemetry is sampled at at most four events per second;
  every flow still receives a policy decision. Status returns up to 20 recent
  samples from the current activation, not a complete connection history.
  The provider does not decrypt TLS or collect payloads.

Distribution requires a matching Developer ID signing identity, Network Extension
provisioning profile, entitlement and app bundle. The system extension belongs in
`WorkOS.app/Contents/Library/SystemExtensions/`; the host must declare
`AgentShieldNetworkExtensionIdentifier` in Info.plist. Expand
`$(TeamIdentifierPrefix)` in `NEMachServiceName` during signed packaging.
The enclosing application needs the system-extension install and content-filter
entitlements. Sign inside out and notarize the final app. macOS user/MDM approval
is still required. A successful build or saved filter preference is not proof of
activation or bypass prevention on a device.

The host library executes inside the signed WorkOS main executable so its
restricted entitlements use the app's embedded profile; it is not a loose helper.
The controller's `status` is read-only. `enable POLICY_JSON` requests activation
and configures the filter after system consent. It refuses to take over another
provider's configuration. `disable` affects only this provider. `configured` and
`runtime_verified` are separate fields intentionally.

A policy file contains:

```json
{"mode":"monitor","managedCodeHashes":[],"proxyPort":18080}
```

Start with monitoring on a test device. Before enabling `enforceManaged`, verify
managed executable attribution, provider liveness, engine readiness, restart and
rollback on that device. Code updates change their hashes and must be re-enrolled.

Apple references: [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
[filter provider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider),
[source audit token](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceappaudittoken).

Remote administration availability is a deployment requirement. The WorkOS
activation policy uses monitor mode, not a device-wide block. Missing policy
permits new flows and installs an allow default rather than blocking unrelated
applications. Managed agent proxy/sandbox denial remains a separate boundary.
The installed Jump Desktop Connect identity (`com.p5sys.jump.connect`, Apple Team
`2HCKV38EEC`) is exempt from managed enforcement only after Security.framework
validates its Apple-anchored signature against the kernel audit token. Names,
paths, ports and caller-provided policy cannot grant the exemption. An explicit
managed-hash rule cannot override it. This is not a guarantee against OS/network
failures; original remote-session continuity must be verified on the signed build.

Each distributed extension build needs a distinct CFBundleVersion. The builder
uses AGENTSHIELD_BUILD_VERSION when supplied, otherwise GITHUB_RUN_ID plus
GITHUB_RUN_ATTEMPT in CI, or a local nanosecond build identity. Reusing a fixed
version can leave the older installed provider running despite a new app bundle.
The controller accepts heartbeat/flow evidence only when the system extension's
on-disk executable matches the current app's bundled provider bytes; an older
provider cannot attest that a newly installed security fix is active.
