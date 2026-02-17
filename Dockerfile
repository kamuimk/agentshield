# Stage 1: Build
FROM rust:1.85-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY templates/ templates/
COPY assets/ assets/
RUN cargo build --release && strip target/release/agentshield

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/agentshield /usr/local/bin/
EXPOSE 18080 18081
ENTRYPOINT ["agentshield"]
CMD ["start"]
