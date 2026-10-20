# Trusted host authentication header intent (v1)

Opt-in `dlp.host_authentication = true` requires MITM, DLP and an authenticated
loopback metadata bridge. The default is false. A host may classify its own
issuer-bound login header separately from model input; this grants no permission
for tools, destinations, bodies or deployment.

Before sending a request the trusted host registers a short-lived, single-use
UUID bound to destination, method, target, body and the exact authorization value.
It sends that UUID as `X-AgentShield-Host-Authentication`. The engine hashes the
held canonical request, then POSTs `/authenticate` with camelCase fields `v:1`,
`intentId`, `requestSha256`, `destinationSha256`, `method`, `targetSha256`,
`bodySha256`, and `authorizationSha256`. Fingerprints use lowercase SHA-256 hex.
Destination bytes are compact JSON `["https", lowercase_hostname, port]`; target,
body and authorization use their exact bytes. No payload or credential is sent
to this callback. The host must independently establish the current owner's
session, bind registration to the current live channel, and consume the intent.

A valid reply has only `intentId`, `requestSha256`, and `authenticated:true`.
Unknown, stale, malformed, failed or unavailable checks reject the request;
there is no human-approval downgrade. The engine removes the control header
before forwarding. Only generic authorization findings on that verified header
are excluded. Other key patterns in that header, all body findings, normal
policy and exact sensitive-request approval remain enforced.

Both `/authenticate` and `/approve` use the existing private bridge key, never
sent as a bearer. Each request has a fresh 64-hex `X-AgentShield-Challenge` and
`Authorization: AgentShield-Metadata <HMAC-SHA256 hex>`. The MAC transcript is:

```
agentshield.metadata.request.v1\n<path>\n<challenge>\n<SHA256(request body)>
```

A successful JSON reply has `X-AgentShield-Proof` with the MAC of:

```
agentshield.metadata.response.v1\n<path>\n<challenge>\n<SHA256(request body)>\n<SHA256(response body)>
```

The new metadata protocol does not accept legacy bearer requests or unsigned
responses. Deploy the bridge and engine together. Path separation prevents a
login-header attestation from becoming a human approval; challenge and body
binding reject forged/replayed replies if a loopback port is rebound. This does
not defend against compromise of the trusted host process or its private key.
The native authority-proof protocol is separate and unchanged.
