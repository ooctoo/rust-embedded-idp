ARG NODE_IMAGE
ARG RUST_IMAGE
ARG RUNTIME_IMAGE
FROM ${NODE_IMAGE} AS web-build

WORKDIR /workspace
COPY . .
WORKDIR /workspace/web
RUN corepack enable \
    && corepack prepare pnpm@10.30.1 --activate \
    && node --version \
    && pnpm --version \
    && pnpm install --frozen-lockfile \
    && pnpm test \
    && pnpm build \
    && pnpm test:embedded-bundle

FROM ${RUST_IMAGE} AS rust-build

ARG CARGO_BUILD_JOBS

WORKDIR /workspace
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
COPY --from=web-build /workspace/web/dist/ /workspace/web/dist/
RUN rustc --version && cargo --version \
    && if [ -n "${CARGO_BUILD_JOBS}" ]; then export CARGO_BUILD_JOBS; else unset CARGO_BUILD_JOBS; fi \
    && cargo build -p embedded-idp-app --release --locked \
    && cargo build -p embedded-idp-storage-postgres --example bootstrap_local_postgres --release --locked

FROM ${RUNTIME_IMAGE} AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 idp \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin idp
COPY --from=rust-build /workspace/target/release/embedded-idp-app /app/embedded-idp-app
USER 10001:10001
ENTRYPOINT ["/app/embedded-idp-app"]

FROM ${RUNTIME_IMAGE} AS prepare

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 idp \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin idp \
    && mkdir -p /app
COPY --from=rust-build /workspace/target/release/embedded-idp-app /app/embedded-idp-app
COPY --from=rust-build /workspace/target/release/examples/bootstrap_local_postgres /app/bootstrap_local_postgres
USER 10001:10001
ENTRYPOINT ["/app/embedded-idp-app"]
