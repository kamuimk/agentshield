# Embedding the AgentShield dashboard

AgentShield provides its own dashboard and a framework-independent host adapter.
WorkOS can use this contract without rebuilding the dashboard. This repository
implements the AgentShield side; the WorkOS menu, native lifecycle management,
bundled installation and macOS Network Extension are not implemented here.

## Configuration

Generate three independent random credentials, for example using `openssl rand -hex 32`
for each. Supply them through the host's credential/configuration mechanism.
These authenticate the local dashboard, not AWS service access. Do not distribute
the administrator credential to an embedded dashboard.

```toml
[proxy]
listen = "127.0.0.1:18080"

[policy]
default = "deny"

[network]
block_private_networks = true
connect_ports = [443]

[web]
enabled = true
listen = "127.0.0.1:18081"
auth_token = "${AGENTSHIELD_ADMIN_TOKEN}"

[web.integration]
allowed_origins = ["tauri://localhost"]
read_token = "${AGENTSHIELD_READ_TOKEN}"
# Omit this credential when the host should only observe.
control_token = "${AGENTSHIELD_CONTROL_TOKEN}"
```

Use the actual host origin. HTTPS origins and loopback HTTP development origins
are supported, as are `tauri://localhost` and `http://tauri.localhost`.
Paths, wildcards, opaque `null` origins and non-local HTTP origins are rejected.
Integration requires a loopback dashboard listener and distinct 32–256 character
alphanumeric/underscore/hyphen credentials. Credential changes require a restart;
this is not an expiring per-user server session or a remote revocation service.

## Host adapter

Import `integrations/dashboard-host.mjs` into the host frontend:

```js
import { mountAgentShield } from './dashboard-host.mjs';

const panel = mountAgentShield({
  container: document.getElementById('service-protection'),
  url: 'http://127.0.0.1:18081',
  token: readTokenFromNativeHost,
  theme: 'dark',
  onStatus: (status) => updateConnectionIndicator(status.state),
});

try {
  const { capabilities, protection } = await panel.ready;
  // Report actual capabilities and protection scope, not just "protected".
} catch {
  showDisconnectedState();
}

// During host theme changes:
panel.setTheme('light');
// During unmount/logout:
panel.dispose();
```

The host must provide height for the container. The adapter accepts only a local
HTTP origin and creates `/embed` with no credential in the URL. After verifying
the iframe origin, source window and page nonce, it sends the credential once
using `postMessage` with an exact target origin. The child also checks its parent.
The embedded page keeps the credential in memory and uses authorization headers
for both REST and fetch-based SSE. No wildcard CORS is enabled.

Only run this inside a trusted frontend. An XSS in that frontend can obtain the
credential it supplies. The native host must verify the engine process/port,
configure its own CSP/frame permissions and obtain the credential securely.
The browser adapter alone does not authenticate an executable or register a device.

## Protocol and permissions

`GET /api/integration` requires a bearer credential and returns protocol
`agentshield.dashboard.v1`, the engine version and granted capabilities.

| Credential | Access |
| --- | --- |
| Read | Statistics, log metadata and SSE, timeline, policy read, manifest |
| Control | Read access plus policy updates, pending ASK and ASK decisions/SSE |
| Administrator | Existing administrative dashboard access, including audit bodies |

Integration credentials cannot retrieve stored audit bodies. Read credentials
cannot retrieve ASK payloads. New routes are not automatically permitted.
In integration mode, query-string credentials are not accepted. Embedded pages
advertise their frame ancestors explicitly; standalone pages prohibit framing.
Responses use `no-store`, `no-referrer` and `nosniff` headers.

Policy updates currently affect the running in-memory policy only, matching the
existing API. They do not persist to TOML and can be replaced by policy reload.
ASK approval here is the existing local proxy approval, not a cryptographically
bound, independent service authorization workflow. A control credential grants
both policy editing and ASK resolution; finer roles are future work.

The manifest explicitly reports `system_egress_enforced: false`. Dashboard
connectivity does not prove that an agent uses the proxy, that an OS filter is
installed, or that a service is protected from a compromised administrator.

## Network engine behavior

The engine now frames the entire HTTP/1.1 request before forwarding, for both
plaintext and intercepted TLS. Limits are 64 KiB headers, 128 header fields,
10 MiB decoded body and 10 MiB + 64 KiB total wire request. There are at most
32 concurrent connection handlers. Oversize, incomplete, ambiguous framing,
duplicate Host/Content-Length, mismatched URI/Host/CONNECT authority, upgrades,
trailers and unsupported transfer encodings are rejected before upstream access.
Chunked bodies are decoded before DLP; binary bodies are forwarded without a
lossy UTF-8 round trip. Proxy credentials are removed from forwarded HTTP.

When DLP is enabled, non-identity Content-Encoding is rejected rather than
forwarded without inspection. HTTP/1.0, HTTP/2, HTTP/3 and WebSocket upgrades
are not supported in the inspected HTTP path. Transparent CONNECT remains opaque.
With MITM, policy/ASK/rate limits apply to the decrypted request method after a
domain transport preflight; TLS inspection failures never fall back to a tunnel.

DNS is resolved once, every returned address is checked and only the checked
addresses are connected. Private/special networks are denied by default, and
CONNECT defaults to port 443. System allowlist entries do not bypass these
network constraints. For an intentional development LAN service, explicitly set
`block_private_networks = false`; this still refuses link-local and selected
cloud metadata addresses. Apply this exception narrowly in separate configurations.

Request reads have a 30-second overall deadline. TCP connects have a 10-second
deadline including DNS; client/upstream TLS handshakes have 15/10 seconds.
Writes have 30-second deadlines and relay reads have 120-second idle deadlines.
The existing plaintext response relay also has a 30-second total deadline.

The DLP scanner still detects known patterns in request bodies, not every possible
secret or encoding. It does not monitor local file writes, inspect all request
headers/queries, or provide semantic prompt-injection prevention. System allowlist
entries still bypass policy/DLP. Service-specific operations and authenticated
agent identity require the WorkOS execution integration.

## Validation

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all --locked
cargo build --example dashboard_fixture --locked
# Install Playwright in your development environment, including Chromium.
node integrations/dashboard-browser-test.mjs
```

`PLAYWRIGHT_MODULE` can name an absolute Playwright module path when it is not
installed in this repository. The browser test starts a synthetic Axum fixture
and a separate host origin, then closes the browser and both fixture servers.
It checks read/control authorization, actual policy/ASK changes, SSE, HTML
injection defenses, theme synchronization, credential handling and cleanup.
No real AWS/GitHub credentials or incident data are used.

## WorkOS sensitive-transmission approvals

`AGENTSHIELD_DATA_DIR` isolates database, PID and default CA paths per host/channel.
The host's private state must be inaccessible to managed agent tools. Public CA
certificates can be copied out separately; never copy or expose the CA private key.
A missing/unreadable MITM CA now prevents startup; it never downgrades inspection.

```toml
[dlp]
enabled = true
require_slack_approval = true

[workos_approval]
endpoint = "http://127.0.0.1:19000/approve"
token = "${WORKOS_APPROVAL_LOCAL_TOKEN}"
```

The host creates the loopback listener and random credential. It receives only a
request UUID, exact request SHA256, destination, method, byte count and known DLP
category names. No body, query, path, credential value or account value is sent.
The WorkOS bridge uses the already authenticated device channel. Slack credentials
remain on the WorkOS service, whose secret management stays in AWS Secrets Manager.
The default recipient is the requesting employee; an organization administrator
may select a security reviewer. Policy revisions invalidate outstanding approvals.
A decision releases only the exact buffered request, once; timeout/disconnect,
wrong owner/message/device/digest and duplicate consumption deny transmission.
Ordinary terminal/web ASK responders cannot approve this dedicated sensitive lane.
System allowlists do not bypass DLP when this approval lane is configured.

Standalone Slack interactive mode requires a DM `channel` and exact
`notification.slack.approver_user` Slack member id. It validates the user, DM,
original message timestamp and expiry. Slack notices omit body/path previews.

Inspection covers normalized HTTP headers, URL and body, including binary bodies
with adjacent text, percent-encoded text and JSON escapes. Compressed bodies are
rejected while DLP is enabled. Regex detection cannot identify every proprietary
secret, transformed payload or prompt injection; destination policy, tool scope,
credential-file confinement and OS network controls remain independent boundaries.

### Quiet streams and stalled startup

The log SSE endpoint emits an immediate `: connected` comment. This supplies body
bytes so WebKit can deliver fetch startup without waiting for an audit event or
its first periodic keepalive. The comment is not an audit record and does not
increase request counts. Real log events retain their existing JSON data format.

The dashboard bounds stream response startup to ten seconds, displays a failed
connection, and retries after three seconds. The deadline is cleared once response
headers/body become available; it does not impose a lifetime limit on a connected
quiet stream. Host disposal aborts streams without scheduling a reconnect.

The browser fixture delays its first synthetic event by ten seconds to test
connection before any audit event. It also stalls headers, checks failure state,
then restores the transport and verifies reconnect/event delivery. Run against
both browser engines with Playwright available:

```sh
cargo build --locked --example dashboard_fixture
AGENTSHIELD_BROWSER=chromium node integrations/dashboard-browser-test.mjs
AGENTSHIELD_BROWSER=webkit node integrations/dashboard-browser-test.mjs
```

`PLAYWRIGHT_MODULE` and `AGENTSHIELD_DASHBOARD_FIXTURE` can point to existing local
test installations. These tests use only synthetic keys, events and fixture hosts.
A host application's installed release must still be verified separately.
