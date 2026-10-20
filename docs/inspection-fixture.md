# Synthetic inspected-host transport fixture

`examples/inspection_fixture.rs` exercises the real connection parser, MITM,
DLP scanner and exact held-request approval path. It is a developer example, not
a supported product entrypoint or proof of authenticated human approval.

```sh
cargo build --locked --example inspection_fixture
AGENTSHIELD_SYNTHETIC_FIXTURE=1 target/debug/examples/inspection_fixture \
  /private/fresh-ca-directory /private/synthetic-server-cert.pem 12345
```

The caller owns a temporary TLS server on the specified loopback port. Use a
server certificate with an IP/hostname SAN and `CA:FALSE`. Only that certificate
is trusted upstream in this example. The listener is always loopback, policy is
default deny with only `localhost`/`127.0.0.1` allowed, and only the specified
nonzero CONNECT port is admitted. Product trust roots, network defaults and CLI
configuration are unchanged. The CA directory must not exist; generated private
keys are private and must be removed by the owning test after shutdown.

The first stdout JSON line is `ready`, with `proxy` and the public `ca` path.
A host client must use that proxy and CA. Sensitive requests emit only an
`approval` frame containing `requestId`, `requestSha256`, `requestBytes` and
category names. Paths, payloads and headers are not sent over the control pipe.
The digest covers the canonical request held by the production parser.

The synthetic parent answers on stdin with one JSON line:

```json
{"requestId":"uuid-from-approval","requestSha256":"digest-from-approval","allowed":false}
```

A decision must match both current id and digest; it removes that pending entry.
Unknown, mismatched, consumed and expired decisions emit `accepted:false` and do
not release a request. Unanswered requests expire after ten seconds. Input frames
are limited to 1024 bytes. Malformed input or EOF closes the fixture. Stdout
frames are serialized so simultaneous requests cannot interleave control frames.

A host acceptance driver can compare the approved digest with the HTTP request
received by its TLS server, change its original body object while approval is
pending, deny secrets, replay old decisions, allow expiry, and terminate the
fixture while a request is held to check that the host does not fall back to
uninspected direct traffic. Authentication headers themselves are sensitive under
the current scanner; a benign body does not make such a request automatically
approved.

These are synthetic stdio decisions. This example does not validate Slack identity,
backend approval consumption, an installed/frozen engine receipt, native OS
confinement, real credentials or production deployment. Host-specific source and
fixtures belong in the host's own repository.
