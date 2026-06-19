FROM rust:1.73 as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release
FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/target/release/file-encryptor /usr/local/bin/file-encryptor
CMD ["file-encryptor"]
