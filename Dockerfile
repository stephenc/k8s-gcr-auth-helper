FROM ekidd/rust-musl-builder:1.42.0 AS build

ADD --chown=rust:rust . ./

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
