# firebeacon as a Firehose reader plugin image: a firehose-core reader (k8s-substreams apps/reader) copies
# /usr/local/bin/firebeacon into its pod from an init container, so the image needs a shell and cp.
# Same Go and Debian bases as the eosn-sf-beacon Debian package in local-build.

FROM golang:1.27-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# cgo stays on, as in the Debian package: the trixie runtime below has the same glibc.
RUN go build -trimpath -o /out/firebeacon ./cmd/firebeacon \
    && /out/firebeacon --help > /dev/null

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/firebeacon /usr/local/bin/firebeacon
ENTRYPOINT ["firebeacon"]
CMD ["--help"]
