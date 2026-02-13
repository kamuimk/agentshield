# Code Style & Conventions

## Rust Conventions
- **snake_case**: 함수명, 변수명, 모듈명
- **PascalCase**: 구조체, 열거형, 트레이트
- **SCREAMING_SNAKE_CASE**: 상수
- serde `rename_all = "lowercase"` for Action enum serialization

## Project Patterns
- **Builder pattern**: `ProxyServer::new().with_policy()`
- **Arc wrapping**: PolicyConfig은 Arc로 감싸서 tokio task 간 공유
- **anyhow::Result**: 에러 처리
- **tracing**: info!, warn!, error! 매크로 사용
- **TDD**: Red → Green → Refactor 방식, 테스트 먼저 작성

## Testing
- 단위 테스트: `#[cfg(test)] mod tests` 내부
- 통합 테스트: `tests/` 디렉토리
- 비동기 테스트: `#[tokio::test]`
- CLI prompt 테스트: reader/writer 추상화 (BufRead + Write trait)

## Task Completion Checklist
1. `cargo test` 전체 통과 확인
2. `cargo clippy` 경고 없음 확인
3. git commit with descriptive message
4. task-master set-status --id=X --status=done
