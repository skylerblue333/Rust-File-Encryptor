FROM rust:1.90-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home sky
COPY --from=builder /src/target/release/file-encryptor /usr/local/bin/file-encryptor
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/file-encryptor"]
