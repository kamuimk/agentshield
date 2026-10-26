# Offline category inspection

`agentshield inspect` reads up to **4 MiB** from standard input and writes one JSON
report. It uses the same built-in patterns and bounded decoding as the proxy.
It does not load the proxy configuration, initialize audit logging, create a CA,
start a listener, or invoke approval/notification services.

```sh
printf 'ordinary prose' | agentshield inspect
# {"version":1,"bytes":14,"categories":[]}
```

The only report fields are `version`, the original input byte count `bytes`, and
sorted, deduplicated `categories`. There are no matched values, snippets, offsets,
paths, hashes, or filenames. Binary bytes are accepted by the existing scanner;
common supported transport encodings are handled by its existing bounded decoder.
`RUST_LOG` does not enable diagnostic logging for this command.

Exit status 0 means inspection ran successfully. **An empty category list is not
proof that content contains no secret.** The patterns, decoder depth, token size,
work budgets and supported formats have limits; arbitrary encryption, splitting,
or unknown credential formats can evade pattern detection. This command neither
grants file access nor implements an approval, quarantine, or network policy.
A host application must make its own decision using the report.

Over-limit input or an I/O failure exits with status 2, produces no successful
report, and writes only `inspection_failed` to stderr. A consumer must reject a
nonzero exit, invalid/extra output, unsupported report version, or mismatched byte
count. It must also enforce a child-process deadline, bound both output streams,
and close stdin after sending its exact bytes. A producer that never closes its
pipe cannot be treated as a completed inspection. Avoid passing sensitive data
through command arguments or environment variables.

The input buffer is best-effort cleared on drop. The existing scanner also makes
in-memory views, so this is not a guarantee of complete memory erasure. No request
body is intentionally persisted by this command.
