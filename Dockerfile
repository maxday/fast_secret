FROM public.ecr.aws/lambda/provided:al2 as builder
WORKDIR /usr/src/app
RUN yum -y update
RUN yum -y install openssl openssl-devel
RUN yum -y install gcc
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN source $HOME/.cargo/env
COPY Cargo.toml .
COPY Cargo.lock .
RUN mkdir ./src && echo 'fn main() { println!("Dummy!"); }' > ./src/main.rs
RUN /root/.cargo/bin/cargo build --release
RUN rm -rf ./src
COPY src ./src
RUN touch -a -m ./src/main.rs
RUN /root/.cargo/bin/cargo build --release


FROM ubuntu as stripper
RUN apt-get update -y
RUN apt-get install -y binutils
COPY --from=builder /usr/src/app/target/release/fast_secret /tmp
RUN strip /tmp/fast_secret

# zip the extension
FROM ubuntu:latest as compresser
RUN apt-get update
RUN apt-get install -y zip
RUN mkdir -p /tmp
WORKDIR /tmp
COPY --from=stripper /tmp/fast_secret /tmp/fast_secret
RUN zip -r fast_secret.zip /tmp/fast_secret

#keep the smallest possible docker image
FROM scratch
COPY --from=compresser /tmp/fast_secret.zip /
ENTRYPOINT ["/fast_secret.zip"]