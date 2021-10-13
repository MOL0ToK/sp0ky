FROM rust:1.55-slim-buster as builder

WORKDIR /app

COPY . .
RUN cargo build --release


FROM debian:buster-slim

WORKDIR /app

COPY --from=builder /app/target/release/sp0ky ./

ENTRYPOINT ["/app/sp0ky"]