# Immutable startup policy

Managed hosts can freeze the policy selected when a CLI engine instance starts:

```sh
agentshield --config managed.toml start --immutable-policy
```

This mode keeps policy file watching disabled for the instance lifetime. On Unix,
SIGHUP is consumed without reloading or terminating the engine. The dashboard
continues to expose authenticated observations; policy editing and local web ASK
control are disabled, including for administrator/control credentials. Integration
manifests advertise only `observe`. Standalone and embedded pages initialize in
read-only mode and hide their policy save control. Existing independently
configured external approval integration is unchanged.

Without this flag, policy updates, file watching and SIGHUP reload keep their
existing behavior. `wrap` also retains its existing behavior.

This is immutability after parsing, not attestation of who selected the startup
configuration. A privileged host must still bind the exact effective startup
configuration and engine process to its admission decision. The existing v1
listener proof does not attest configuration, this flag, DLP settings or policy.
An HTTP status/manifest or a successful socket proof alone cannot authorize guest
execution or credential release. A trusted library caller retaining a mutable
policy Arc remains responsible for its own mutation boundary; this CLI mode does
not turn that Arc into an immutable library type.

Automated tests start actual CLI processes in both modes, with standalone and
integrated dashboards. They attempt administrator policy updates, change the
configuration file, send SIGHUP on Unix, and check the active policy and real
proxy denial. The default-mode control verifies that ordinary reload still works.
Router tests also attempt policy/ASK control using administrator, controller and
reader credentials while preserving policy reads and observation capabilities.
