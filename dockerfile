FROM rust_base:latest as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release


FROM arm64v8/ubuntu
RUN mkdir /usr/app
COPY --from=builder /usr/src/app/target/release/authentication-web-api /usr/app/authentication-web-api 
COPY --from=builder /usr/src/app/.env /usr/app/.env 
WORKDIR /usr/app
RUN apt-get install \
&& apt-get update \
&& apt-get -y install clang \
&& apt-get -y install libpq-dev \
&& apt-get -y install libc6-dev
CMD ["./authentication-web-api"]
