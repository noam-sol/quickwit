FROM node:20 as ui-builder

COPY quickwit/quickwit-ui /quickwit/quickwit-ui

WORKDIR /quickwit/quickwit-ui

RUN touch .gitignore_for_build_directory \
    && NODE_ENV=production make install build


FROM rust:bookworm AS bin-builder

ARG CARGO_FEATURES=release-feature-set
ARG CARGO_PROFILE=release
ARG QW_COMMIT_DATE
ARG QW_COMMIT_HASH
ARG QW_COMMIT_TAGS

ENV QW_COMMIT_DATE=$QW_COMMIT_DATE
ENV QW_COMMIT_HASH=$QW_COMMIT_HASH
ENV QW_COMMIT_TAGS=$QW_COMMIT_TAGS

# Use dirs outside /quickwit, so docker doesn't invalidate the COPY and RUN cargo build layers.
ENV CARGO_HOME=/usr/local/cargo
ENV CARGO_TARGET_DIR=/usr/local/cargo/target

RUN apt-get -y update \
    && apt-get -y install --no-install-recommends \
                          ca-certificates \
                          clang \
                          cmake \
                          libssl-dev \
                          llvm \
                          protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Required by tonic
RUN rustup component add rustfmt

# Download/Cache dependencies (without actually building).
# If quickwit source code changes, but Cargo.lock / Cargo.toml don't, the dependecy downloading will be skipped.
COPY quickwit/Cargo.lock quickwit/Cargo.toml ./
RUN cargo build --no-dev --release --features $CARGO_FEATURES || true

COPY quickwit /quickwit
COPY config/quickwit.yaml /quickwit/config/quickwit.yaml
COPY --from=ui-builder /quickwit/quickwit-ui/build /quickwit/quickwit-ui/build

WORKDIR /quickwit

RUN echo "Building workspace with feature(s) '$CARGO_FEATURES' and profile '$CARGO_PROFILE'" \
    && RUSTFLAGS="--cfg tokio_unstable" \
        cargo build \
        -p quickwit-cli \
        --features $CARGO_FEATURES \
        --bin quickwit \
        $(test "$CARGO_PROFILE" = "release" && echo "--release") \
        --target-dir $CARGO_TARGET_DIR \
    && echo "Copying binaries to /quickwit/bin" \
    && mkdir -p /quickwit/bin \
    && find $CARGO_TARGET_DIR/$CARGO_PROFILE -maxdepth 1 -perm /a+x -type f -exec mv {} /quickwit/bin \;


FROM debian:bookworm-slim AS quickwit

LABEL org.opencontainers.image.title="Quickwit"
LABEL maintainer="Quickwit, Inc. <hello@quickwit.io>"
LABEL org.opencontainers.image.vendor="Quickwit, Inc."
LABEL org.opencontainers.image.licenses="AGPL-3.0"

RUN apt-get -y update \
    && apt-get -y install --no-install-recommends \
                          ca-certificates \
                          libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /quickwit
RUN mkdir config qwdata
COPY --from=bin-builder /quickwit/bin/quickwit /usr/local/bin/quickwit
COPY --from=bin-builder /quickwit/config/quickwit.yaml /quickwit/config/quickwit.yaml

ENV QW_CONFIG=/quickwit/config/quickwit.yaml
ENV QW_DATA_DIR=/quickwit/qwdata
ENV QW_LISTEN_ADDRESS=0.0.0.0

RUN quickwit --version

ENTRYPOINT ["quickwit"]
