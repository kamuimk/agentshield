# AgentShield - Project Overview

## Purpose
AgentShield는 AI 에이전트(OpenClaw, Claude Code 등)의 아웃바운드 네트워크 트래픽을 제어하는 **투명 이그레스 방화벽(Transparent Egress Firewall)**.
HTTP/HTTPS 프록시로 동작하며, TOML 기반 정책 엔진으로 도메인별/메서드별 allow/deny/ask 제어.

## Repository
- **GitHub**: https://github.com/kamuimk/agentshield.git
- **Branch**: main

## Tech Stack
- **Language**: Rust (edition 2024)
- **Async Runtime**: Tokio (full features)
- **CLI**: clap 4.5 (derive)
- **Config**: toml 0.8 + serde
- **DB**: rusqlite 0.32 (bundled SQLite)
- **TLS**: rustls 0.23
- **HTTP**: hyper 1.6, hyper-util, http-body-util
- **Logging**: tracing + tracing-subscriber
- **Dev Dependencies**: tempfile 3

## Project Structure
```
src/
  lib.rs          # Library crate (pub mod declarations)
  main.rs         # CLI entry point (clap commands)
  proxy/
    mod.rs        # ProxyServer struct
    connect.rs    # accept_loop, handle_connect, handle_http_request
    tls.rs        # TLS support (placeholder)
  policy/
    mod.rs
    config.rs     # AppConfig, PolicyConfig, Rule, Action (TOML parsing)
    evaluator.rs  # evaluate(), domain/method matching
  logging/
    mod.rs        # RequestLog, init_db, log_request, query_recent
    export.rs     # export_json, export_csv
  cli/
    mod.rs        # Cli, Commands, PolicyAction (clap)
    prompt.rs     # Interactive approval (PromptDecision, generate_rule, append_rule)
  dlp/
    mod.rs        # DLP (placeholder)
templates/
  openclaw-default.toml   # OpenClaw default policy (9 rules)
  claude-code-default.toml # Claude Code default policy
  strict.toml             # Strict deny-all policy
tests/
  integration_test.rs     # 11 comprehensive integration tests
  policy_test.rs          # 7 TOML parser tests
  proxy_test.rs           # 8 proxy + policy tests
```

## Key Architecture
- **ProxyServer**: `with_policy()` builder로 PolicyConfig를 Arc로 래핑하여 thread-safe 공유
- **Policy Engine**: first-match-wins 순차 룰 평가, domain matching (exact, wildcard `*`, subdomain `*.`)
- **Deny Response**: `403 Forbidden` + `X-AgentShield-Reason` 헤더
- **ASK**: 현재 allow로 처리 (향후 interactive prompt 연동)

## Running
- Config: `agentshield.toml` (현재 `0.0.0.0:18080`에서 대기)
- Docker OpenClaw 연동: `HTTP_PROXY=http://host.docker.internal:18080`
- OpenClaw docker-compose: `/Users/minkikim/WebstormProjects/openclaw/docker-compose.yml`

## Total Tests: 56
- Unit: 30, Integration: 11, Policy: 7, Proxy: 8
