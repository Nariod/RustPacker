FROM rust:1.69

LABEL maintainer="Nariod"

RUN apt update && apt upgrade -y 
RUN apt install -y g++-mingw-w64-x86-64 

WORKDIR /usr/src/RustPacker

COPY . .

RUN rustup target add x86_64-pc-windows-gnu

RUN cargo install --path .

CMD ["RustPacker"]