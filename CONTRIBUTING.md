# Contributing to AgentShield

Thank you for your interest in contributing to AgentShield! This guide will help you get started.

## Development Setup

**Requirements:**
- Rust 1.85+ (edition 2024)
- Git

```bash
git clone https://github.com/kamuimk/agentshield.git
cd agentshield
cargo build
cargo test --all
```

## Development Workflow

We follow **TDD (Test-Driven Development)**:

1. **Red** — Write a failing test first
2. **Green** — Write the minimum code to make it pass
3. **Refactor** — Clean up while keeping tests green

### Before Submitting

```bash
cargo fmt --check       # Formatting
cargo clippy -- -D warnings  # Linting (zero warnings)
cargo test --all        # All tests pass (145+)
```

All three must pass. CI enforces these checks on every PR.

## Project Structure

```
src/
  main.rs           # CLI entry point (anyhow for errors)
  lib.rs            # Library root (pub mod declarations)
  cli/              # CLI commands, ASK prompt, OpenClaw integration
  proxy/            # Proxy server, connection handling
  policy/           # TOML config types, policy evaluator
  dlp/              # DLP scanner, regex patterns
  logging/          # SQLite logging, JSON/CSV export
  notification/     # Notifier trait, Telegram, FilteredNotifier
  error.rs          # thiserror-based error types
templates/          # Built-in TOML policy templates
tests/              # Integration tests
```

## Code Conventions

- **Error handling:** `thiserror` in library code, `anyhow` in `main.rs`
- **Async runtime:** Tokio
- **Builder pattern** for `ProxyServer`
- **`ConnectionContext`** struct consolidates handler arguments
- All public items have `///` doc comments in English
- All modules have `//!` module-level doc comments

## Adding a DLP Pattern

1. Add your regex to `src/dlp/patterns.rs` in `DEFAULT_PATTERNS`
2. Choose the appropriate severity (`Critical`, `High`, `Medium`)
3. Write a test in the same file:
   ```rust
   #[test]
   fn detects_your_pattern() {
       let scanner = RegexScanner::new();
       let findings = scanner.scan(b"your-test-payload");
       assert!(!findings.is_empty());
       assert_eq!(findings[0].pattern_name, "your-pattern-name");
   }
   ```
4. Run `cargo test --all`

## Adding a Policy Template

1. Create a new `.toml` file in `templates/`
2. Follow the existing template format (see `openclaw-default.toml`)
3. Register it in `src/main.rs` `cmd_policy_template()`
4. Add a test in `tests/integration_test.rs` to verify it parses correctly

## Submitting a Pull Request

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes with tests
4. Ensure all checks pass (`fmt`, `clippy`, `test`)
5. Open a PR against `main` with a clear description

### PR Title Convention

- `feat: ...` for new features
- `fix: ...` for bug fixes
- `refactor: ...` for code restructuring
- `docs: ...` for documentation only
- `test: ...` for test additions

## Reporting Issues

Use the [GitHub issue templates](https://github.com/kamuimk/agentshield/issues/new/choose):

- **Bug Report** — something isn't working
- **Feature Request** — suggest an enhancement
- **DLP Pattern Request** — request a new secret detection pattern
- **Policy Template Request** — request a new built-in template

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
