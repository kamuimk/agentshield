# Quoted API key inspection

The generic API key matcher previously accepted `api_key=value` but skipped the
same synthetic value in a JSON `api_key` field because the closing key quote was
not accepted before the separator. Accept an optional single or double quote
there, preserving the existing value alphabet and minimum length. Treat an explicit long
API key assignment as Critical, matching credential patterns, so the HTTPS
critical-finding path blocks rather than merely records it.

Regression coverage includes four key spellings, JSON and single-quoted fields,
percent/base64/UTF-16 views, harmless short values and metadata neighbors. The
CLI tests both executable entry points for category-only output and no state.
Real loopback HTTPS tests require 403 and no upstream connection for direct and
base64 JSON bodies, while retaining the harmless forwarding control. No external
service, real credential, system trust installation or OS filter is used.

This is bounded pattern detection, not an assertion that arbitrary encrypted or
transformed data is safe. Consumers must pin and rebuild the fixed engine; an
already installed older executable does not change when this source is merged.
