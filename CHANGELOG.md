# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `agentshield wrap` command — one-line proxy setup for any AI agent
- `agentshield quickstart` — interactive setup wizard
- Slack Incoming Webhook notifications (`[notification.slack]`)
- Discord webhook notifications and interactive ASK via bot (`[notification.discord]`)
- `MultiNotifier` — send alerts to Telegram + Slack + Discord simultaneously
- 5 new policy templates: `aider-default`, `codex-default`, `cursor-default`, `development-general`, `minimal-llm`
- Community template loading from `~/.agentshield/templates/`
- `agentshield policy template --list` command
- E2E integration tests (12 tests covering deny, allow, DLP, rate limiting, hot-reload, notifications)
- GitHub Actions release workflow (multi-platform: macOS/Linux x86_64/aarch64)
- `install.sh` one-line installer
- Homebrew formula (`brew install kamuimk/tap/agentshield`)
- Graceful shutdown with `accept_loop` pattern (SIGTERM + child process cleanup)
- `Cursor` agent detection in wrap/quickstart

### Changed
- `ProxyServer::start()` returns `ProxyHandle` for graceful shutdown
- `cmd_policy_template()` refactored to use `resolve_template()` with built-in + community fallback

## [0.9.0] - 2025-02-19

### Added
- Chunked transfer-encoding support (decode, scan, re-encode)
- Audit logging — `[logging]` config section with `request_body`/`dlp_findings` DB columns
- Claude Code integration (`agentshield integrate claude-code`)
- Log filtering (`--domain`, `--action`, `--since`, `--until`, `--search`)
- Config validation (`agentshield validate`)
- Dashboard UX: timeline chart, theme toggle, log row coloring, auto-scroll
- `expand_tilde()` for `~` in config paths

### Fixed
- Flaky test: replaced `example.com` external dependency with mock HTTP server
- Chunked decoding: `Transfer-Encoding` removal + `Content-Length` fix after decode
- `format_dlp_findings` JSON escape (using `serde_json::json!` macro)
- `audit_redact_dlp` option (default true) — prevent body storage when DLP triggered
- SQL `LIKE` → `INSTR()` to avoid `%`/`_` wildcard escape issues
- Header parsing: `split_once(':')` refactoring for `parse_content_length`/`is_chunked`
- Chunk extension handling (`;` before parameters)

## [0.8.0] - 2025-02-14

### Added
- MITM TLS interception mode (`proxy.mode = "mitm"`)
- CA management CLI (`agentshield ca init/trust/show/export`)
- `CertCache` — LRU per-domain certificate cache (max 1000)
- Multi-stage Dockerfile + GitHub Actions `docker.yml` (amd64/arm64 → ghcr.io)
- Timing-safe web auth token comparison (`subtle::ConstantTimeEq`)
- Debug masking for `WebConfig`/`TelegramConfig` (secrets hidden in logs)

### Changed
- `ProxyMode` enum with `#[serde(default)]` for backward compatibility
- `CertCache` uses single Mutex lock scope + `create_domain_config()` separation
- `upstream_tls_config` cached as `Arc<ClientConfig>` in `ConnectionContext`

## [0.7.0] - 2025-02-12

### Added
- Per-domain sliding window rate limiter (`[policy.rules.rate_limit]`)
- Web auth token with timing-safe comparison
- `agentshield dashboard` CLI command
- `RateLimited` notification event variant

## [0.6.0] - 2025-02-10

### Added
- `AskBroadcaster` — multi-channel ASK (Terminal, Telegram, Web Dashboard)
- Web dashboard with real-time SSE logs, policy editor, ASK approval
- Policy hot-reload via file watcher + SIGHUP signal
- `WebDashboardResponder` for browser-based ASK approval
- `TelegramResponder` with inline keyboard for interactive ASK
- axum web server with REST API (10 endpoints)

## [0.5.0] - 2025-02-08

### Added
- ASK prompt with body inspection (`i` key) and auto-rule generation (`r` key)
- Wildcard domain matching (`*.example.com`)
- `AskPending` notification event
- Request body capture in `AskRequest`

### Fixed
- Environment variable substitution double-substitution bug (single-pass regex)
- `domain_matches` extracted as shared utility function

## [0.4.0] - 2025-02-06

### Added
- System allowlist bypasses DLP scanning
- `FilteredNotifier` with event-type filtering
- Environment variable substitution (`${VAR}` / `$VAR`) in TOML config
- `ConnectionContext` struct consolidating 12 handler arguments
- `query_stats()` SQL aggregation with `RequestStats` struct

### Changed
- OpenAI/Fireworks/Together AI DLP regex improvements

## [0.3.0] - 2025-02-04

### Added
- `Notifier` trait + `TelegramNotifier` (fire-and-forget)
- `[system] allowlist` — bypass policy evaluation for internal services
- `r2d2::Pool<SqliteConnectionManager>` connection pooling

### Changed
- `println!` → `tracing::info!` (server logs only, CLI output preserved)

## [0.2.0] - 2025-02-02

### Added
- DLP proxy integration
- ASK fail-closed behavior
- MSRV 1.85 (Rust 2024 edition)

## [0.1.0] - 2025-01-31

### Added
- Initial release
- TOML-based policy engine (allow/deny/ask)
- HTTP/HTTPS proxy with CONNECT tunnel support
- DLP scanner with 15+ built-in patterns
- SQLite request logging
- OpenClaw integration (`agentshield integrate openclaw`)

[Unreleased]: https://github.com/kamuimk/agentshield/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/kamuimk/agentshield/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kamuimk/agentshield/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kamuimk/agentshield/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kamuimk/agentshield/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kamuimk/agentshield/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kamuimk/agentshield/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kamuimk/agentshield/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kamuimk/agentshield/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kamuimk/agentshield/releases/tag/v0.1.0
