# Trust Issues: a stand-in bitcoind for home Lightning nodes (signet only).
# The Rust image is pinned by digest. The build needs the network (crates);
# running it does not, apart from the Tor SOCKS proxy you point it at.

FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS build
# rust-toolchain.toml pins the same compiler; naming it here stops rustup
# trying to download extra components (rustfmt, clippy) during the build.
ENV RUSTUP_TOOLCHAIN=1.99.1
# Optional cap on parallel compile jobs, for a machine shared with other work:
#   docker compose build --build-arg CARGO_BUILD_JOBS=8
ARG CARGO_BUILD_JOBS
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Only the Rust example files: Cargo.toml lists socks_probe, so it must exist.
COPY examples/*.rs ./examples/
# Cache mounts keep downloaded crates and build output between builds; the
# binary is copied out because cache mounts don't stay in the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin trust-issues \
 && cp target/release/trust-issues /trust-issues

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

LABEL org.opencontainers.image.title="Trust Issues" \
      org.opencontainers.image.description="A stand-in bitcoind for Lightning nodes that reads the chain from several block explorers over Tor (signet only)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/MaxSikorski/trust-issues"

# Debian packages come from a dated snapshot, not the live archive, so a
# rebuild gets the same bytes. To bump: change SNAPSHOT (a timestamp from
# https://snapshot.debian.org/archive/debian/) and the base image digest
# together, and re-check the pinned versions still exist at that timestamp.
ARG SNAPSHOT=20261117T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    "deb http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm main" \
    "deb http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm-updates main" \
    "deb http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bookworm-security main" \
    > /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot

# ca-certificates: the HTTP client loads the system root store when it starts.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 trustissues \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin trustissues \
 && install -d -o 10001 -g 10001 -m 0700 /data

COPY --from=build /trust-issues /usr/local/bin/trust-issues

ENV TRUST_ISSUES_NETWORK=signet \
    TRUST_ISSUES_DATA_DIR=/data \
    TRUST_ISSUES_RPC_BIND=0.0.0.0:38332

USER 10001:10001
VOLUME /data
# Documentation only: compose does not publish it.
EXPOSE 38332

HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
  CMD ["trust-issues", "health-check", "--synced"]

ENTRYPOINT ["trust-issues"]
