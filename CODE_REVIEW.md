# AgentShield Code Review & Action Items

## Review Date: 2026-02-12
## Reviewer: Claude (via chat session with Kay)
## Repo: https://github.com/kamuimk/agentshield
## Commit: c885569 (10 commits)

---

## 1. Overall Assessment

프로젝트 구조가 깔끔하고, Dev Spec에 맞게 잘 구현되어 있다. 모듈 분리(proxy, policy, logging, dlp, cli)가 명확하고, TDD 기반으로 테스트가 잘 작성되어 있다. 2시간 만에 이 수준까지 나온 것은 인상적이며, 아래 이슈들만 해결하면 실제로 동작하는 프록시가 된다.

---

## 2. Critical Bugs (즉시 수정 필요)

### 2.1 프록시-정책 연결 누락

**파일:** `src/main.rs` (line 64)

**문제:** `cmd_start()`에서 `AppConfig`를 로드하지만 `ProxyServer`에 policy를 전달하지 않고 있다.

```rust
// 현재 코드
let server = ProxyServer::new(config.proxy.listen.clone());

// 수정 필요
let server = ProxyServer::new(config.proxy.listen.clone())
    .with_policy(config.policy.clone());
```

**영향:** 정책이 None으로 전달되어 모든 요청이 정책 평가 없이 통과됨. default-deny가 동작하지 않는 치명적 버그.

### 2.2 프록시-로깅 연결 누락

**파일:** `src/proxy/connect.rs`

**문제:** 정책 평가 결과를 `logging::log_request()`로 기록하지 않고 있다. 현재는 tracing으로만 로그를 남기고 SQLite에는 기록하지 않음.

**수정 방향:**
- `ProxyServer`에 SQLite `Connection` (또는 DB path)을 주입할 수 있게 확장
- `handle_connect()`와 `handle_http_request()`에서 정책 평가 후 `logging::log_request()` 호출
- SQLite Connection은 thread-safe하지 않으므로 `Arc<Mutex<Connection>>` 또는 connection pool 사용 필요

### 2.3 HTTPS 기본 포트 버그

**파일:** `src/proxy/connect.rs` (line 211)

**문제:** `parse_host_port()`에서 HTTPS scheme일 때도 기본 포트를 80으로 반환한다.

```rust
// 현재 코드
} else {
    Ok((host_port.to_string(), 80))
}

// 수정 필요 - scheme에 따라 기본 포트 결정
let default_port = if uri.starts_with("https://") { 443 } else { 80 };
```

**영향:** HTTPS URL로의 plain HTTP 요청이 잘못된 포트로 연결됨.

---

## 3. Important Improvements (v0.2 전 수정 권장)

### 3.1 HTTP 응답 스트리밍

**파일:** `src/proxy/connect.rs` (line 181-185)

**문제:** `handle_http_request()`에서 응답을 64KB 고정 버퍼로 한번만 읽는다.

```rust
// 현재 코드 - 큰 응답이 잘림
let mut response_buf = vec![0u8; 65536];
let n = remote.read(&mut response_buf).await?;
```

**수정 방향:** `tokio::io::copy`를 사용한 스트리밍 방식으로 변경. CONNECT 터널링의 양방향 copy와 동일한 패턴 사용.

### 3.2 승인 프롬프트(ASK)가 프록시에 연결되지 않음

**파일:** `src/proxy/connect.rs` (line 85-88)

**문제:** ASK 액션이 현재 단순히 allow로 처리됨. `cli/prompt.rs`의 프롬프트 로직이 구현되어 있지만 프록시와 연결되지 않았다.

```rust
// 현재 코드
Action::Ask => {
    // For now, treat ASK as allow
    info!("ASK CONNECT to {} - {}", target, result.reason);
}
```

**수정 방향:**
- 비동기 채널(tokio::sync::mpsc)로 프록시 → 메인 스레드 간 승인 요청/응답 전달
- 또는 프록시 내에서 직접 stdin/stdout 프롬프트 (MVP 단계)
- 타임아웃 30초, 무응답 시 deny 기본값

### 3.3 DLP 모듈 미구현

**파일:** `src/dlp/patterns.rs`

**상태:** 빈 파일. v0.3 스코프이므로 지금은 OK이나, `mod.rs`에 최소한의 인터페이스(trait)를 정의해두면 나중에 통합이 쉬워진다.

```rust
// 제안: src/dlp/mod.rs에 인터페이스 정의
pub trait DlpScanner {
    fn scan(&self, payload: &[u8]) -> Vec<DlpFinding>;
}

pub struct DlpFinding {
    pub pattern_name: String,
    pub matched_text: String,
    pub severity: Severity,
}
```

---

## 4. Missing Files (공개 전 필수)

### 4.1 LICENSE 파일

**상태:** 없음. `Cargo.toml`에 `license = "Apache-2.0"` 선언만 있고, 실제 LICENSE 파일이 레포에 없다.

**조치:** Apache License 2.0 전문을 `LICENSE` 파일로 추가. 이것 없이는 법적으로 라이센스가 적용되지 않는다.

### 4.2 README.md

**상태:** 없음. 오픈소스 공개 시 필수.

**포함할 내용:**
- 프로젝트 한 줄 설명 + 배지 (build status, license)
- 30초 데모 GIF (OpenClaw에서 요청이 차단/허용되는 모습)
- Quick Start (install → init → template → start)
- 정책 파일 예시
- 아키텍처 다이어그램 (ASCII 또는 mermaid)
- "What AgentShield is NOT" 섹션 (로컬 실행 제어, prompt injection 방어는 범위 밖임을 명시)
- 다른 도구와의 관계 (Pipelock, LlamaFirewall과 보완 관계)
- Contributing 가이드 링크

### 4.3 .github/workflows/ci.yml

**상태:** 없음. GitHub Actions로 CI 설정 권장.

```yaml
# 제안
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check
```

---

## 5. Code Quality Notes (참고)

### 5.1 잘 된 부분
- `prompt.rs`에서 reader/writer를 추상화하여 테스트 가능하게 한 설계
- `open_memory_db()`로 SQLite 테스트를 격리한 것
- 정책 evaluator의 first-match-wins 로직과 와일드카드 매칭이 정확함
- `generate_rule()` + `append_rule_to_config()`로 점진적 허용의 기반이 마련됨
- 각 테스트에서 TOML 파싱 검증까지 포함한 것 (파일 깨짐 방지)

### 5.2 Rust 관련 제안
- `edition = "2024"` 확인 필요. Rust 2024 edition이 안정화되었는지 확인. 아직 nightly only라면 `"2021"`로 변경.
- `anyhow`를 사용 중인데, 라이브러리 코드(`lib.rs` 하위)에서는 `thiserror`로 커스텀 에러 타입을 정의하는 것이 관례. `anyhow`는 애플리케이션 코드(`main.rs`)에서만 사용 권장.
- `tracing` + `tracing-subscriber`가 있으니 `println!` 대신 `info!`, `warn!`으로 통일하면 로그 레벨 제어가 가능해짐.

### 5.3 보안 고려사항
- `parse_host_port()`에서 Host header injection 방어 필요. 도메인에 허용되지 않는 문자가 포함된 경우 거부.
- CONNECT 터널에서 포트 제한 고려 (443, 8443 등 HTTPS 포트만 허용).
- `append_rule_to_config()`에서 TOML injection 방어. 사용자 입력이 도메인명에 들어가므로, 특수문자 검증 필요.

---

## 6. Priority Action Items

| 순위 | 항목 | 예상 시간 | 파일 |
|------|------|-----------|------|
| P0 | 프록시-정책 연결 (`with_policy`) | 5분 | `src/main.rs` |
| P0 | HTTPS 기본 포트 수정 (443) | 10분 | `src/proxy/connect.rs` |
| P0 | LICENSE 파일 추가 | 5분 | `LICENSE` |
| P1 | 프록시-로깅 연결 | 1시간 | `src/proxy/connect.rs`, `src/proxy/mod.rs` |
| P1 | HTTP 응답 스트리밍 | 30분 | `src/proxy/connect.rs` |
| P1 | ASK → 승인 프롬프트 연결 | 2시간 | `src/proxy/connect.rs`, `src/cli/prompt.rs` |
| P2 | README.md 작성 | 1시간 | `README.md` |
| P2 | CI 설정 | 30분 | `.github/workflows/ci.yml` |
| P2 | DLP 인터페이스 정의 | 30분 | `src/dlp/mod.rs` |
| P2 | Notification trait + terminal 래핑 | 1시간 | `src/notification/mod.rs`, `src/notification/terminal.rs` |
| P2 | Telegram Bot 알림 연동 | 3시간 | `src/notification/telegram.rs` |
| P2 | 시스템 allowlist (알림 채널 보호) | 30분 | `src/proxy/connect.rs`, `src/policy/evaluator.rs` |
| P3 | `println!` → `tracing` 통일 | 30분 | 전체 |
| P3 | `anyhow` → `thiserror` (lib 코드) | 1시간 | `src/` 전체 |
| P3 | Host header injection 방어 | 30분 | `src/proxy/connect.rs` |

---

## 7. Architecture Notes (향후 참고)

### 프록시에 DB/Logger 주입 패턴

```rust
// 제안 구조
pub struct ProxyServer {
    listen_addr: String,
    policy: Option<Arc<PolicyConfig>>,
    db_path: Option<PathBuf>,  // 추가
}

// connect.rs에서 사용
async fn handle_connect(
    client: &mut TcpStream,
    first_line: &str,
    policy: Option<&PolicyConfig>,
    logger: Option<&Arc<Mutex<Connection>>>,  // 추가
) -> anyhow::Result<()> {
    // ... 정책 평가 후
    if let Some(logger) = logger {
        let conn = logger.lock().unwrap();
        logging::log_request(&conn, &RequestLog { ... })?;
    }
}
```

### Telegram 알림 연동 (v0.3 스코프)

ASK 이벤트 발생 시 Telegram Bot API를 통해 사용자에게 승인 요청을 보내고, 인라인 버튼으로 응답을 받는다.

**흐름:**
```
AgentShield (ASK 발생)
    │
    │ POST https://api.telegram.org/bot<token>/sendMessage
    │ { chat_id, text: "POST api.github.com/pulls",
    │   reply_markup: { inline_keyboard: [[Allow][Deny][Inspect]] } }
    ▼
Telegram → 사용자 폰에 알림
    │
    │ 사용자가 Allow 버튼 탭
    ▼
Telegram → AgentShield callback endpoint (getUpdates polling 또는 webhook)
    │
    │ 요청 허용 + 선택적으로 룰 자동 추가
    ▼
프록시가 대기 중이던 요청을 통과시킴
```

**설정 (agentshield.toml):**
```toml
[notification]
backend = "telegram"           # telegram | webhook | terminal
timeout_secs = 30              # 무응답 시 deny

[notification.telegram]
bot_token = "123456:ABC-DEF..."
chat_id = "987654321"
```

**구현 항목:**

| 항목 | 설명 |
|------|------|
| `src/notification/mod.rs` | Notification trait 정의 (`send_ask`, `wait_response`) |
| `src/notification/telegram.rs` | Telegram Bot API 연동 (sendMessage + inline keyboard + callback 처리) |
| `src/notification/terminal.rs` | 기존 터미널 프롬프트를 Notification trait으로 래핑 |
| 시스템 allowlist | `api.telegram.org`를 사용자 정책과 무관하게 항상 허용하는 내부 allowlist 필요. 알림 채널이 자기 자신에 의해 차단되는 역설 방지. |
| 비동기 대기 | 프록시에서 ASK 발생 시 `tokio::sync::oneshot` 채널로 응답 대기. 타임아웃 시 자동 deny. |
| callback 매핑 | 각 ASK 요청에 고유 ID를 부여하고, Telegram callback_data에 포함시켜 어떤 요청에 대한 응답인지 매핑. |

**시스템 allowlist 구현:**
```rust
// 사용자 정책 평가 전에 체크하는 내부 allowlist
const SYSTEM_ALLOWED_DOMAINS: &[&str] = &[
    "api.telegram.org",   // 알림 채널
];

fn is_system_allowed(domain: &str) -> bool {
    SYSTEM_ALLOWED_DOMAINS.iter().any(|d| domain == *d)
}

// evaluate() 호출 전에 체크
if is_system_allowed(&req_info.domain) {
    // 정책 평가 스킵, 항상 allow, 로깅은 수행
}
```

**Notification trait:**
```rust
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send_ask(&self, req: &PromptRequest) -> Result<String>;  // returns request_id
    async fn wait_response(&self, request_id: &str, timeout: Duration) -> Result<PromptDecision>;
}
```

**Priority:** P2 (v0.3 스코프, ASK 프롬프트의 터미널 연동(P1)이 완료된 후 진행)
