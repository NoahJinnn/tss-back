FROM rust:1.60.0-slim-buster as builder
WORKDIR /app
COPY . .
ARG DEBIAN_FRONTEND=noninteractive
RUN rustup component add rustfmt

RUN apt-get clean & apt-get update
RUN apt-get -y install build-essential pkg-config libssl-dev
RUN apt-get install -y libclang-dev llvm clang
RUN apt-get -y install libgmp3-dev
RUN cargo build --release

FROM ubuntu:20.04

WORKDIR /app

# Install <extra-runtime-dependencies>
RUN apt clean && apt update \
    && apt install -y ca-certificates \
    && apt install -y libclang-dev \
    && apt install -y libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy bin & config files
COPY --from=builder /app/target/release .
COPY --from=builder /app/Rocket.toml .
COPY --from=builder /app/.env.staging .

EXPOSE 8001
ENV RUST_LOG=info
CMD ["./server_exec"]