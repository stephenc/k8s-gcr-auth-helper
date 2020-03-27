FROM ekidd/rust-musl-builder:1.41.0 AS cheat

# First make a version of Cargo.toml that will hash the same unless dependencies change
COPY Cargo.toml ./
RUN set -xe ; \
    sed -i -e "/\[package]/,/\[dependencies]/{s/version = \".*\"/version= \"0.0.0\"/}" Cargo.toml

FROM ekidd/rust-musl-builder:1.41.0 AS build

RUN USER=root cargo init .
# Copy the more hash resilient Cargo.toml
COPY --from=cheat /home/rust/src/Cargo.toml ./
# The lock file is what is important for pre-compilation anyway
COPY Cargo.lock ./
RUN cargo install --target x86_64-unknown-linux-musl --path .

# Now the real Cargo.toml and the source code
COPY Cargo.toml ./
COPY src/ ./src/

# Allow overriding the version from a build-arg
ARG VERSION
RUN set -xe ; \
    test -z "$VERSION" || sed -i -e "/\[package]/,/\[dependencies]/{s/version = \".*\"/version= \"$VERSION\"/}" Cargo.toml ; \
    cargo install --target x86_64-unknown-linux-musl --path .

# Now for the runtime image
FROM scratch

COPY --from=build /etc/ssl /etc/ssl
COPY --from=build /home/rust/.cargo/bin/k8s-gcr-auth-helper /k8s-gcr-auth-helper

ENV RUST_LOG=info
ENTRYPOINT ["/k8s-gcr-auth-helper"]
CMD ["--help"]
