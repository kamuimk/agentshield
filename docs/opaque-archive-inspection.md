# Compressed uploads are not a clean regex scan

Recognized gzip and ZIP streams at the start of a body, a multipart body part, or a supported decoded transport view produce the Critical `inspection-incomplete` finding. They are not decompressed. The existing sensitive-request path denies transmission, or holds the exact request for the configured approval authority. A MIME declaration does not grant an inspection bypass.

This is conservative containment, not archive content inspection. Benign recognized archives require the same decision. Other compression/encryption/container formats and arbitrary obfuscation are not proven covered. No decompressor, network service, package dependency, system policy, or global trust change is introduced.

Tests use compressed synthetic credentials, direct/percent/Base64/nested-Base64/multipart views, real offline CLI calls, and real loopback TLS with upstream non-delivery plus an ordinary request forwarding control. No real credentials or external provider are used.
