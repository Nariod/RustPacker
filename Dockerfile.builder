FROM docker.io/library/rust:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends g++-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-pc-windows-gnu

WORKDIR /build
