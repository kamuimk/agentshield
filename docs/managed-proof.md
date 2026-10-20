# Managed startup proof v2 (Windows)

This protocol binds a pinned CLI engine's imported loopback listener to the exact
startup TOML snapshot and immutable policy mode. It is separate from v1 listener
proof: a host must never interpret a v1 response as configuration evidence.

```sh
agentshield --config managed.toml start --owned-listener-stdin \
  --immutable-policy --managed-proof-pipe '\\.\pipe\AgentShield.ManagedProof.v2.<id>'
```

`<id>` is 32 random lowercase hex characters. The flag requires both owned socket
import and immutable policy; it conflicts with `--listener-proof-pipe`. The CLI
reads one regular-file snapshot of at most 65536 bytes and hashes/parses those
same bytes. Environment placeholders are literal in this mode. Parse/size/read
errors do not echo source text or credentials. Later file changes cannot alter
the parsed values; the immutable policy mode disables reload and web control.

The host selects and protects the local configuration path, retains the actual
listener/engine process, and creates/authenticates the pipe exactly as required
by [listener proof](listener-proof.md). The pipe must be SYSTEM owned, local,
byte mode with remote clients rejected and an explicit restrictive DACL. Before
writing any secret the host authenticates the exact connecting kernel process
against its retained inspector. Keys/nonces never enter files, argv, environment,
status receipts or logs.

The same four-byte little-endian JSON length prefix and 512-byte limit apply:

```json
{"v":2,"key":"<64 lowercase hex>","nonce":"<64 lowercase hex>","port":12345,"configSha256":"<SHA-256 of approved TOML bytes, lowercase hex>"}
```

The engine rejects a digest that differs from the snapshot it actually parsed,
as well as unknown/duplicate fields, invalid versions, wrong ports or malformed
hex. No proxy request loop starts on such a failure. After startup, the host
sends a bodyless HTTP/1.1 GET to `/.__agentshield/managed-proof/v2`, with the exact
`Host: 127.0.0.1:<port>` and `X-AgentShield-Nonce` headers specified by v1.

The 200 response uses the same empty-body/no-store/close headers and
`X-AgentShield-Proof` field, with this HMAC-SHA256 message:

```text
ASCII("agentshield.managed-proof.v2") || 0x00 || uint16_be(port) || config_sha256_bytes || nonce_bytes
```

For key `11` repeated 32 times, nonce `22` repeated 32 times, digest `33` repeated 32
times and port 443, the tag is
`933bba5c6ec62267d5c268225a68b642c9ab966b616be37de9441ecf5923a78e`.
These are synthetic test values. The existing 30-second expiry, single consumption,
constant-time verification, no forwarding/audit event, and bounded pipe reading
requirements remain unchanged. The host must independently bound delivery/probing
and destroy/reap its exact owned guest on failed admission.

This proves selected configuration bytes under a known pinned CLI implementation;
it does not prove semantic policy adequacy, external files/CA material, OS rules,
environment-dependent resources, production signing, or user approval. A trusted
host must use explicit approved paths/settings, protect dependencies, verify
containment and obtain the required exact-request approval before credential or
guest release. A trusted library caller can construct a proof with arbitrary
values, so a host must pin the CLI image and its controlled startup path rather
than trusting an arbitrary executable that implements this HTTP response.

Local tests cover literal snapshot parsing, bounded errors, digest/endpoint/version
rejection and a Python-independent HMAC vector. Native v2 SYSTEM-pipe/CLI acceptance
must be run separately; v1 native acceptance does not establish v2 acceptance.
