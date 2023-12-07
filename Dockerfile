FROM rust:1.68 as builder
WORKDIR /usr/src/sfauth
COPY . .
RUN cargo install --path .
CMD ["auth-server"]
