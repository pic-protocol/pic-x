# syntax=docker/dockerfile:1

FROM rust:1.97-slim-trixie AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/trust-lab /usr/local/bin/trust-lab

FROM debian:trixie-slim AS runtime

COPY --from=builder /usr/local/bin/trust-lab /usr/local/bin/trust-lab

USER 65532:65532
EXPOSE 7080

ENTRYPOINT ["/usr/local/bin/trust-lab"]
