FROM rust:1.88-bookworm AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --package bulwark-cli

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/bulwark /usr/local/bin/bulwark

RUN useradd --create-home --shell /bin/bash bulwark
USER bulwark
WORKDIR /home/bulwark

EXPOSE 8080

ENTRYPOINT ["bulwark"]
CMD ["proxy", "start"]
