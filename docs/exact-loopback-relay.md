# One exact local relay destination

A trusted embedding host can route inspected traffic through one local relay
without enabling general private-network access:

```toml
[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[network]
block_private_networks = true
connect_ports = [443]
loopback_endpoint = "127.0.0.1:39001"

[policy]
default = "deny"

[[policy.rules]]
name = "local-relay"
domains = ["127.0.0.1"]
methods = ["POST"]
action = "allow"

[dlp]
enabled = true
```

`loopback_endpoint` is absent by default. It accepts one literal IPv4 address,
exactly `127.0.0.1`, with a nonzero port. DNS names, URI strings, other addresses,
IPv6 aliases, metadata endpoints and port zero are rejected. The runtime validates
programmatic configurations too. The exact configured target connects directly
to that typed address with no DNS lookup or alternative destination fallback.
Other ports, `localhost` and numeric aliases keep the normal network restrictions.
The existing explicit `block_private_networks = false` option retains its behavior;
keep it true when using this narrowly scoped local destination.

This is an address exception only. The pinned route requires domain/method policy
permission and receives configured DLP checks even if a legacy system allowlist
would match it. Configured TLS interception remains active for this route, and
CONNECT ports still require a separate entry in `connect_ports`. Plain HTTP and
MITM tests prove secrets are blocked before any upstream connection. Legacy
allowlist behavior for other destinations is unchanged.

The embedding host authenticates relay requests and keeps the intended listener
bound until its clients stop. Exact address matching does not establish process,
user or execution identity, supply credentials, start a relay or change OS firewall
permissions. A port value is not an authentication secret. Do not derive this
trusted configuration from an untrusted request.

The network destination is fixed at proxy construction/startup. Policy reload
changes domain/method rules, not the pinned destination. Restart the owner with a
new trusted configuration when changing relay endpoints.

Mutable policy mode polls metadata for one config path every 250ms and reloads
on a changed timestamp, creation time or size. It reads the config content only
when a change is observed. Replacing the file keeps the original path monitored;
dropping the watcher stops and joins its worker. Immutable policy mode creates no
watcher. Watcher ownership is installed before proxy/dashboard startup.

Rust callers constructing `NetworkConfig` directly must supply the new optional
field or use `..Default::default()`. Existing TOML files keep the default `None`.
