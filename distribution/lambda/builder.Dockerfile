FROM node:20 AS ui-builder

COPY quickwit/quickwit-ui /quickwit/quickwit-ui

WORKDIR /quickwit/quickwit-ui

RUN touch .gitignore_for_build_directory \
    && NODE_ENV=production make install build

FROM --platform=linux/amd64 rust:1.82.0 AS builder

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

RUN apt update && apt install -y python3 python3-pip python3-venv protobuf-compiler
RUN python3 -m venv /venv
RUN /venv/bin/pip install pipenv
RUN /venv/bin/pipenv install

RUN curl -fsSL https://cargo-lambda.info/install.sh | sh
ENV QW_LAMBDA_BUILD=1
ENV QW_LAMBDA_VERSION=beta-100

COPY . /tmp/docker-build
# this is needed for build, even when we're just a lambda-
COPY --from=ui-builder /quickwit/quickwit-ui/build /tmp/docker-build/quickwit/quickwit-ui/build

RUN mkdir /lambda-out

ENV FORCE_DISABLE_GIT_FETCH_WITH_CLI=true
RUN --mount=type=ssh \
    --mount=type=cache,target=$CARGO_TARGET_DIR \
    --mount=type=cache,target=$CARGO_HOME/registry \
    --mount=type=cache,target=$RUSTUP_HOME \
    . /venv/bin/activate && cd /tmp/docker-build/distribution/lambda && make package && cp ${CARGO_TARGET_DIR}/lambda/searcher/bootstrap.zip /lambda-out/boostrap.zip

FROM --platform=linux/amd64 alpine
RUN mkdir lambda-out
COPY --from=builder /lambda-out/boostrap.zip /lambda-out/boostrap.zip
