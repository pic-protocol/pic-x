# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------------------------
FROM rust:1.97-slim-trixie AS builder

WORKDIR /src

# protoc compiles the administrative protocol during the build; the generated code is never committed,
# so the compiler has to be present rather than assumed.
#
# musl-tools is what makes the binary static. A static binary needs nothing from the image it runs in,
# which is what lets the runtime stage below be empty — and an image with nothing in it has nothing to
# patch, nothing to scan and nothing to exploit.
RUN apt-get update \
 && apt-get install --no-install-recommends --yes protobuf-compiler musl-tools \
 && rm -rf /var/lib/apt/lists/*

# The architecture being built for, supplied by BuildKit. Named rather than assumed, so the same file
# produces an amd64 image on an amd64 builder and an arm64 one on an arm64 builder.
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac > /target-triple \
 && rustup target add "$(cat /target-triple)"

# Banner metadata is validated and re-exported by build.rs, which fails the build when either value
# is missing. .cargo/config.toml carries the defaults; these ARGs let a release pipeline override
# them without editing the source tree.
ARG PIC_X_COPYRIGHT_YEAR=2026
ARG PIC_X_COPYRIGHT_HOLDER="Nitro Agility S.r.l."
# The commit this image is built from, stamped into the binary (banner, admin GetVersion). It has to
# arrive as an argument: `.git` is deliberately outside the build context, so the build cannot ask
# the repository itself. Left empty, the binary says `unknown`.
ARG PIC_X_BUILD_COMMIT=""
ENV PIC_X_COPYRIGHT_YEAR=${PIC_X_COPYRIGHT_YEAR} \
    PIC_X_COPYRIGHT_HOLDER=${PIC_X_COPYRIGHT_HOLDER} \
    PIC_X_BUILD_COMMIT=${PIC_X_BUILD_COMMIT}

COPY . .

# The binary is copied out inside the same RUN because the target directory is a cache mount and does
# not survive the layer.
#
# `ring` compiles C, so it is told which compiler to use for the target rather than left to guess at
# the host's.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    TRIPLE="$(cat /target-triple)"; \
    UNDERSCORED="$(echo "${TRIPLE}" | tr '-' '_')"; \
    export "CC_${UNDERSCORED}=musl-gcc"; \
    export "CARGO_TARGET_$(echo "${UNDERSCORED}" | tr 'a-z' 'A-Z')_LINKER=musl-gcc"; \
    cargo build --release --locked --target "${TRIPLE}" --bin pic-x \
 && cp "target/${TRIPLE}/release/pic-x" /usr/local/bin/pic-x

# What the runtime stage cannot make for itself, having no shell to make it with:
#
#   the volume, owned by the user the server runs as, so a deployment that mounts nothing over it
#   still starts;
#   /etc/passwd and /etc/group, so the numeric user has a name — some tooling reads them, and an image
#   without them reports `unknown` wherever a user is shown.
RUN mkdir -p /staged/var/lib/pic-x \
 && chown -R 65532:65532 /staged/var/lib/pic-x \
 && printf 'nonroot:x:65532:65532:nonroot:/:/sbin/nologin\n' > /staged/passwd \
 && printf 'nonroot:x:65532:\n' > /staged/group

# The binary has to be static, because the runtime stage has no loader to report that it is not. This
# fails here, where the message is readable, rather than at `docker run` with an exec format error.
RUN ldd /usr/local/bin/pic-x 2>&1 | grep -qE "statically linked|not a dynamic executable" \
 || (echo "the binary is dynamically linked and the runtime image has no libc" >&2 && exit 1)

# ---------------------------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------------------------
#
# Nothing. No distribution, no package manager, no shell, no libc: the binary is static, so there is
# nothing left for it to need.
#
# That is worth more than a small image. A base image is a second product to keep patched, on somebody
# else's release cadence, and every scanner finding in it is a finding against this one. An empty base
# has no findings because it has no packages, and it stays that way with nobody maintaining it.
#
# It also removes the shell an attacker looks for after reaching the process — not a substitute for the
# process being hard to reach, and worth having anyway.
FROM scratch AS runtime

LABEL org.opencontainers.image.title="PIC-X" \
      org.opencontainers.image.description="Provenance Identity Continuity Exchange." \
      org.opencontainers.image.source="https://github.com/pic-protocol/pic-x" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /staged/passwd /staged/group /etc/
COPY --from=builder /usr/local/bin/pic-x /usr/local/bin/pic-x
COPY --from=builder --chown=65532:65532 /staged/var/lib/pic-x /var/lib/pic-x
# No configuration ships in the image. A baked-in default is a posture somebody else chose, and the
# first thing anybody does with an image is run it and the second is assume it is configured. The
# deployment mounts its own file — written by copying from config.template.yml — at the path `CMD`
# names below, and a container given nothing refuses to start, naming the file that is missing.
COPY LICENSE /usr/share/doc/pic-x/

USER 65532:65532

# web HTTP, gRPC, telemetry — matching the shipped configuration files. Deliberately not Dex's
# 5556/5557/5558, so both can run on the same host. Administration is on 7557; a production
# configuration demands mutual TLS and an allowlist before it will bind there, which is what makes
# exposing it a decision rather than an accident.
EXPOSE 7556 7557 7558

# The container's configuration path lives here and only here. Serving is the binary's default
# action, so the command is the path and nothing else. A deployment mounts its file there:
#
#   docker run --rm --volume ./my-config.yml:/etc/pic-x/config.yml:ro pic-x
#
# or mounts it elsewhere and passes that path as the command instead.
#
# An absolute path: there is no shell to resolve PATH, and relying on one that happens to be set is
# how this breaks the day anything about the image changes.
ENTRYPOINT ["/usr/local/bin/pic-x"]
CMD ["/etc/pic-x/config.yml"]
