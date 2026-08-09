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

# The volume, made here because the runtime image has no shell to make it with. Owned by the user the
# server runs as, so a deployment that does not mount anything over it still starts.
RUN mkdir -p /staged/var/lib/pic-x \
 && chown -R 65532:65532 /staged/var/lib/pic-x

# ---------------------------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------------------------
#
# Distroless: the C runtime this binary is linked against, and nothing else. No shell, no package
# manager, no coreutils — which is most of what a vulnerability scanner finds in a base image, and
# all of it packages this product never calls.
#
# `cc` rather than `base` because a Rust binary unwinds through libgcc; `debian13` because that is the
# glibc the builder above compiled against, and mixing the two is how a container fails at start with
# a symbol error instead of at build with a message.
#
# It also removes the interactive shell an attacker would look for after reaching the process. That is
# not a substitute for the process being hard to reach, and it is worth having anyway.
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

COPY --from=builder /usr/local/bin/pic-x /usr/local/bin/pic-x
COPY --from=builder --chown=65532:65532 /staged/var/lib/pic-x /var/lib/pic-x
# The production file, under the name a deployment expects to override.
COPY config.prod.yaml /etc/pic-x/config.yaml
COPY LICENSE /usr/share/doc/pic-x/

# 65532, which is what `nonroot` means in these images. There is no `useradd` here to invent one with,
# and inventing one would only mean a different number for no reason.
USER 65532:65532

# web HTTP, gRPC, telemetry — matching config.prod.yaml. Deliberately not Dex's 5556/5557/5558,
# so both can run on the same host. The gRPC port is declared but the shipped configuration binds it
# to loopback: exposing administration is a decision, and it needs mutual TLS to be made safely.
EXPOSE 7556 7557 7558

# The container's default configuration path lives here and only here. Serving is the binary's default
# action, so the command is the path and nothing else, and any other deployment passes its own:
#
#   docker run --rm pic-x /etc/pic-x/config.yaml
# An absolute path: there is no shell to resolve PATH, and relying on one that happens to be set is
# how this breaks the day the base image changes.
ENTRYPOINT ["/usr/local/bin/pic-x"]
CMD ["/etc/pic-x/config.yaml"]
