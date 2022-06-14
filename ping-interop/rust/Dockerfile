FROM rust:1.59-bullseye as builder
WORKDIR /usr/src/testplan

# Cache dependencies between test runs, see testground examples.
RUN mkdir -p ./plan/src/
RUN echo "fn main() {}" > ./plan/src/main.rs
COPY ./plan/Cargo.lock ./plan/
COPY ./plan/Cargo.toml ./plan/

ARG CARGO_FEATURES=""
ARG LIBP2P_VERSION=""

# hack to survive without feature flags:
RUN echo "libp2p = { version = \"${LIBP2P_VERSION}\" }" >> ./plan/Cargo.toml
RUN cat ./plan/Cargo.toml
RUN cd ./plan/ && cargo build --release --features="${CARGO_FEATURES}"

COPY . .

RUN echo "libp2p = { version = \"${LIBP2P_VERSION}\" }" >> ./plan/Cargo.toml
RUN cd ./plan/ && cargo build --release --features="${CARGO_FEATURES}" && cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/testplan /usr/local/bin/testplan
EXPOSE 6060
ENTRYPOINT ["testplan"]