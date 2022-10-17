FROM docker.io/library/rust:latest

LABEL maintainer="Nariod"

WORKDIR /usr/src/RustPacker

COPY . .

RUN rustup target add x86_64-pc-windows-gnu

RUN cargo install --path .

CMD ["RustPacker"]