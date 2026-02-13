# Suggested Commands

## Build & Test
```bash
cargo build          # 빌드
cargo test           # 전체 테스트 실행 (56 tests)
cargo test --test integration_test  # 통합 테스트만
cargo test --test proxy_test        # 프록시 테스트만
cargo test --test policy_test       # 정책 테스트만
```

## Run
```bash
cargo run -- start                           # 프록시 시작 (기본 config)
cargo run -- start -c /path/to/config.toml   # 커스텀 config
cargo run -- init                            # ~/.agentshield/ 초기화
cargo run -- logs --tail 10                  # 최근 로그 조회
cargo run -- policy show -c config.toml      # 정책 조회
cargo run -- policy template openclaw-default # 템플릿 적용
```

## Formatting & Linting
```bash
cargo fmt             # 코드 포맷팅
cargo clippy          # 린트
```

## Git
```bash
git status
git log --oneline -10
git add <files> && git commit -m "message"
```
