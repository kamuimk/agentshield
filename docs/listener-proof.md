# Imported listener proof (Windows)

This optional startup protocol lets a privileged host check that its imported
loopback listener reaches the engine to which it delivered a fresh secret.
It is a building block for host integration, not an execution authorization,
policy attestation, configuration attestation, or permission to release traffic.
The host must separately verify the engine image, process identity, effective
configuration, containment policy, and any required user approval before admission.
Configuration changes require independent revalidation; this proof does not cover
the engine's configuration reload or dashboard mutation paths.

## Host responsibilities

1. Retain the exact engine process and exclusive IPv4 loopback listener handles.
2. Create a unique local byte-mode named pipe with an explicit SYSTEM owner and
   restrictive DACL. Use first-instance and remote-client rejection protections.
   Grant only the intended client principal read and READ_CONTROL access.
3. Before sending any secret, authenticate the pipe client's kernel process
   identity against the retained engine process handle. A caller-provided PID,
   pipe name, readiness file, or successful TCP connection is insufficient.
4. Start the engine with `--owned-listener-stdin` and
   `--listener-proof-pipe \\.\pipe\AgentShield.ListenerProof.v1.<id>`, where
   `<id>` is 32 random lowercase hexadecimal characters. Deliver the owned socket
   using the existing private stdin import protocol. Never put proof secrets in
   arguments, environment variables, configuration, logs, or persistent files.
5. Send the frame below, then probe the retained endpoint and verify the MAC
   using a constant-time comparison. Bound all operations and clean up on failure.
   Never reuse a key or nonce. Clear secret buffers after success or failure.

SYSTEM ownership is checked by the engine, but it does not authenticate the
client to the host. Default named-pipe permissions are insufficient for this
protocol; see Microsoft's [named-pipe security documentation](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
and [GetSecurityInfo documentation](https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).

## Wire format

The private pipe carries a four-byte little-endian unsigned JSON byte count,
then exactly that many UTF-8 bytes, with a maximum payload of 512 bytes:

```json
{"v":1,"key":"<64 lowercase hex characters>","nonce":"<64 lowercase hex characters>","port":12345}
```

The key and nonce each encode 32 cryptographically random bytes. Unknown or
duplicate fields, invalid types, and a port different from the imported socket
are rejected. Only `127.0.0.1` with a nonzero port is accepted. Reading the frame
has a five-second deadline after opening the pipe. Opening a missing or busy pipe
fails rather than waiting for a different instance.

The host sends a bodyless HTTP/1.1 request to the imported endpoint:

```http
GET /.__agentshield/listener-proof/v1 HTTP/1.1
Host: 127.0.0.1:12345
X-AgentShield-Nonce: <64 lowercase hex characters>

```

Exactly one Host and nonce header are required. On success the engine returns
HTTP 200, an empty body, `Cache-Control: no-store`, `Connection: close`, and
`X-AgentShield-Proof` containing lowercase hexadecimal HMAC-SHA256:

```text
HMAC(key, ASCII("agentshield.listener-proof.v1") || 0x00 || uint16_be(port) || nonce_bytes)
```

For key `11` repeated 32 times, nonce `22` repeated 32 times, and port 443,
the tag is `3fceebe166407252ab2ec64430d20c29113c2bb4c1121e1fb99c1e87cb7c9d98`.
These are synthetic test values, never suitable for a real handshake.

The proof expires 30 seconds after the frame is accepted. Exactly one valid
request consumes the key; replay or expiry returns 410. Invalid requests do not
consume it. The reserved endpoint does not forward bytes, broadcast audit events,
or grant traffic access. Ordinary proxy requests retain their existing policy.
The endpoint exists only when this optional startup mode is enabled.

## Verification scope

Unit and TCP tests cover validation, expiry, concurrent single consumption,
reserved-route isolation, no audit event, and unchanged proxy denial. The Windows
CI test additionally rejects an ordinary-user-owned pipe. Positive SYSTEM-host
authentication and a complete host admission lifecycle require native integration
testing in the host; neither a unit test nor this response proves that lifecycle.
