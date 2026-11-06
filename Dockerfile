FROM rust:1.98.1-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config clang libclang-dev libssl-dev libxml2-dev libxslt1-dev libxmlsec1-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY src src
COPY migrations migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin ultrivly \
    && cp target/release/ultrivly /usr/local/bin/ultrivly

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 libxml2 libxslt1.1 libxmlsec1 libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin ultrivly \
    && mkdir -p /data && chown ultrivly /data
COPY --from=build /usr/local/bin/ultrivly /usr/local/bin/ultrivly
USER 10001
ENV ULTRIVLY_BIND=0.0.0.0:8080 \
    ULTRIVLY_LOG_FORMAT=json \
    TMPDIR=/tmp
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["ultrivly", "probe"]
ENTRYPOINT ["ultrivly"]
CMD ["serve"]
