# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------------------------
FROM rust:1.97-slim-trixie AS builder

WORKDIR /src

# protoc compiles the administrative protocol during the build; the generated code is never committed,
# so the compiler has to be present rather than assumed.
RUN apt-get update \
 && apt-get install --no-install-recommends --yes protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

# Banner metadata is validated and re-exported by build.rs, which fails the build when either value
# is missing. .cargo/config.toml carries the defaults; these ARGs let a release pipeline override
# them without editing the source tree.
ARG PIC_X_COPYRIGHT_YEAR=2026
ARG PIC_X_COPYRIGHT_HOLDER="Nitro Agility S.r.l."
ENV PIC_X_COPYRIGHT_YEAR=${PIC_X_COPYRIGHT_YEAR} \
    PIC_X_COPYRIGHT_HOLDER=${PIC_X_COPYRIGHT_HOLDER}

COPY . .

# The binary is copied out inside the same RUN because the target directory is a cache mount and
# does not survive the layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin pic-x \
 && cp target/release/pic-x /usr/local/bin/pic-x

# ---------------------------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

RUN apt-get update \
 && apt-get upgrade --yes \
 && apt-get install --no-install-recommends --yes ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 pic-x \
 && useradd --system --uid 10001 --gid pic-x --no-create-home --shell /usr/sbin/nologin pic-x

COPY --from=builder /usr/local/bin/pic-x /usr/local/bin/pic-x
# The production file, under the name a deployment expects to override.
COPY config.prod.yaml /etc/pic-x/config.yaml
COPY LICENSE /usr/share/doc/pic-x/

USER 10001:10001

# web HTTP, gRPC, telemetry — matching config.prod.yaml. Deliberately not Dex's 5556/5557/5558,
# so both can run on the same host. The gRPC port is declared but the shipped configuration binds it
# to loopback: exposing administration is a decision, and it needs mutual TLS to be made safely.
EXPOSE 7556 7557 7558

# The container's default configuration path lives here and only here. Serving is the binary's default
# action, so the command is the path and nothing else, and any other deployment passes its own:
#
#   docker run --rm pic-x /etc/pic-x/config.yaml
ENTRYPOINT ["pic-x"]
CMD ["/etc/pic-x/config.yaml"]
