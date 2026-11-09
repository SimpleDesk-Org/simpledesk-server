# SimpleDesk server image: hbbs and hbbr built from this repository.
# Works like rustdesk/rustdesk-server: run "hbbs" or "hbbr", data and keys live in /root.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin hbbs --bin hbbr

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hbbs /src/target/release/hbbr /usr/bin/
WORKDIR /root
# Only the WebSocket ports are reachable, everything else listens on 127.0.0.1.
ENV WS_ONLY=Y
EXPOSE 21118 21119
