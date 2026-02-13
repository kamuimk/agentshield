# AgentShield

**Default-deny egress control for AI agents.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/kamuimk/agentshield/actions/workflows/ci.yml/badge.svg)](https://github.com/kamuimk/agentshield/actions/workflows/ci.yml)

AgentShield is a transparent egress firewall for AI agents (OpenClaw, Claude Code, etc.). It intercepts all outbound HTTP/HTTPS traffic and enforces TOML-based policy rules — blocking unauthorized requests before they leave your machine.

## Architecture

```mermaid
flowchart LR
    A[AI Agent<br/>OpenClaw / Claude Code] -->|HTTPS_PROXY| B[AgentShield<br/>Proxy]
    B --> C{Policy Engine}
    C -->|Allow| D[External API<br/>api.anthropic.com]
    C -->|Deny| E[403 Blocked]
    C -->|Ask| F[Terminal Prompt]
    F -->|Approve| D
    F -->|Deny| E
    B --> G[(SQLite Pool)]
    B --> H{DLP Scanner}
    H -->|Critical| E
    H -->|Clean| D
    E -->|Notify| I[Telegram]
    H -->|Critical| I
```

## Quick Start

```bash
# Build from source (requires Rust 1.85+)
git clone https://github.com/kamuimk/agentshield.git
cd agentshield
cargo build --release

# Initialize
./target/release/agentshield init

# Apply a policy template
./target/release/agentshield policy template openclaw-default

# Start the proxy
./target/release/agentshield start

# Point your AI agent to the proxy
export HTTPS_PROXY=http://127.0.0.1:18080
```

### Integrate with OpenClaw (Node.js)

For OpenClaw or other Node.js-based agents, use the built-in integration command:

```bash
# Auto-configure OpenClaw to use AgentShield proxy
agentshield integrate openclaw

# Remove the proxy configuration
agentshield integrate remove
```

This sets `channels.telegram.proxy` in `~/.openclaw/openclaw.json` to route traffic through AgentShield.

## Policy Configuration

Policies are defined in `agentshield.toml`:

```toml
[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[policy]
default = "deny"    # deny | allow | ask

# Allow LLM API calls
[[policy.rules]]
name = "anthropic-api"
domains = ["api.anthropic.com"]
action = "allow"

# Allow GitHub reads, require approval for writes
[[policy.rules]]
name = "github-read"
domains = ["api.github.com"]
methods = ["GET"]
action = "allow"

[[policy.rules]]
name = "github-write"
domains = ["api.github.com"]
methods = ["POST", "PUT", "PATCH", "DELETE"]
action = "ask"

# Enable DLP scanning on HTTP requests
[dlp]
enabled = true
# patterns = ["openai-api-key", "aws-access-key"]  # optional: subset of built-in patterns

# System allowlist: bypass policy for internal services (e.g., notification endpoints)
# [system]
# allowlist = ["api.telegram.org"]

# Notifications: receive Telegram alerts on deny/DLP events
# [notification]
# enabled = true
# [notification.telegram]
# bot_token = "YOUR_BOT_TOKEN"
# chat_id = "YOUR_CHAT_ID"
# events = ["deny", "dlp"]
```

### Policy Actions

| Action | Behavior |
|--------|----------|
| `allow` | Request passes through, logged to SQLite |
| `deny` | Request blocked with `403 Forbidden` + `X-AgentShield-Reason` header |
| `ask` | Terminal prompt for approval. Timeout (30s) defaults to deny |

### System Allowlist

Domains in `[system] allowlist` bypass policy evaluation entirely. This prevents the proxy from blocking its own notification traffic.

```toml
[system]
allowlist = ["api.telegram.org"]
```

### Notifications

AgentShield can send alerts to Telegram when requests are denied or DLP findings occur. Notifications are fire-and-forget — failures never block the proxy.

```toml
[notification]
enabled = true

[notification.telegram]
bot_token = "123456:ABC-DEF"
chat_id = "-1001234567890"
events = ["deny", "dlp"]
```

### DLP (Data Loss Prevention)

When `[dlp] enabled = true`, AgentShield scans HTTP request bodies for sensitive data before forwarding:

| Severity | Patterns | Action |
|----------|----------|--------|
| Critical | OpenAI, Anthropic, Google AI, HuggingFace, Cohere, Replicate, Mistral, Groq, Together AI, Fireworks AI API keys, AWS access key, private key, GitHub token | Block (403) |
| High | Generic API key | Log warning, allow |
| Medium | Email address | Log warning, allow |

> **Note:** CONNECT tunnels (HTTPS) are encrypted and cannot be scanned by DLP.

### Built-in Templates

| Template | Description |
|----------|-------------|
| `openclaw-default` | OpenClaw Gateway defaults: LLM APIs, messaging, GitHub, npm |
| `claude-code-default` | Claude Code defaults |
| `strict` | Deny all traffic (blank slate) |

```bash
agentshield policy template openclaw-default
```

## CLI Commands

```
agentshield init                      # Initialize config + database
agentshield start [--daemon]          # Start the proxy
agentshield stop                      # Stop the proxy
agentshield status                    # Show request statistics
agentshield logs [--tail N]           # View recent logs
agentshield logs --export --format json  # Export logs
agentshield policy show               # Display current policy
agentshield policy template <name>    # Apply a template
agentshield integrate openclaw        # Configure OpenClaw to use proxy
agentshield integrate remove          # Remove proxy configuration
```

## Using with Docker (OpenClaw)

If your AI agent runs in Docker, set proxy environment variables:

```yaml
# docker-compose.yml
services:
  openclaw-gateway:
    environment:
      HTTP_PROXY: http://host.docker.internal:18080
      HTTPS_PROXY: http://host.docker.internal:18080
      NO_PROXY: localhost,127.0.0.1
```

Make sure AgentShield listens on `0.0.0.0:18080` (not `127.0.0.1`) for Docker access.

> **Note:** Node.js 23 does not natively support `HTTP_PROXY` / `HTTPS_PROXY` environment variables. You may need to use a proxy agent library (e.g., `undici`) or wait for Node.js 24+ with `NODE_USE_ENV_PROXY=1` support.

## What AgentShield is NOT

- **Not a sandbox.** AgentShield controls network egress only. It does not restrict file system access, process execution, or other local operations.
- **Not a prompt injection defense.** It operates at the network layer, not the LLM layer.
- **Not a WAF.** It's an egress firewall, not an ingress firewall. It protects against data exfiltration, not against incoming attacks.

AgentShield complements tools like [PipeLock](https://github.com/nichochar/pipelock) (code execution sandboxing) and [LlamaFirewall](https://github.com/meta-llama/PurpleLlama) (prompt-level defense).

## Development

- **MSRV:** Rust 1.85 (edition 2024)

```bash
cargo test --all     # Run all tests (117+ tests)
cargo clippy         # Lint
cargo fmt            # Format
```

## License

[Apache License 2.0](LICENSE)
