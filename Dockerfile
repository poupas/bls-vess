FROM golang:1.18 as builder
ADD . /build
RUN cd /build \
    && go build .

FROM debian:bullseye-slim
COPY --from=builder /build/bls-vess /usr/local/bin
ENTRYPOINT /usr/local/bin/bls-vess
