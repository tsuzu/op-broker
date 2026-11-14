# syntax=docker/dockerfile:1

# --- build opbroker (static Go binary) ---
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY assets ./assets
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s\ -w -o /out/opbroker .

# --- fetch the official 1Password CLI, SHA-256 pinned ---
FROM alpine:3.22 AS opcli
ARG OP_VERSION=2.42.0
ARG OP_SHA256=261fe3844a43e7e83a3d85e8a9f36411729436a1d3add1dc7dd46cbbceebe9e5
RUN wget -q "https://cache.agilebits.com/dist/1P/op2/pkg/v${OP_VERSION}/op_linux_amd64_v${OP_VERSION}.zip" -O /tmp/op.zip \
 && echo "${OP_SHA256}  /tmp/op.zip" | sha256sum -c - \
 && unzip -o -q /tmp/op.zip op -d /out \
 && /out/op --version

# --- runtime: distroless/cc (glibc + ca-certificates), nonroot ---
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/opbroker /usr/local/bin/opbroker
COPY --from=opcli /out/op /usr/local/bin/op
COPY --from=opcli /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV HOME=/tmp TZ=Asia/Tokyo
EXPOSE 18787
ENTRYPOINT ["/usr/local/bin/opbroker"]
CMD ["serve", "--listen", ":18787", "--op", "/usr/local/bin/op"]
