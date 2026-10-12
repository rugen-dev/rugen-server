# rugen-server image: static musl binary on scratch (~10 MB), non-root.
#
#   docker build -f deploy/Dockerfile -t rugen-server .
#
# Only the server crate is compiled (no game, no wgpu); the workspace
# manifests are copied because Cargo resolves the whole workspace.

FROM rust:1.90-alpine3.22 AS build
# `--build-arg FEATURES=resim` re-simulates disputed matches (needs RUGEN_RESIM_DATA)
ARG FEATURES=""
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p rugen-relay --bin rugen-server \
      ${FEATURES:+--features "$FEATURES"} \
 && cp target/release/rugen-server /rugen-server \
 && strip /rugen-server \
 && mkdir -p /data

FROM scratch
COPY --from=build /rugen-server /rugen-server
# the volume mounted on /data inherits this ownership on first use
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV RUGEN_BIND=0.0.0.0:8080 \
    RUGEN_UDP_BIND=0.0.0.0:7001 \
    RUGEN_DATA=/data \
    RUST_LOG=info
EXPOSE 8080/tcp 7001/udp
VOLUME ["/data"]
# scratch has no shell or curl: the binary probes GET /health itself
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/rugen-server", "--healthcheck"]
ENTRYPOINT ["/rugen-server"]
