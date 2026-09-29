# Build httpsec from source and ship a scratch image with just the binary and
# the CA bundle it needs to verify certificate chains.
FROM golang:1.23-alpine AS build

WORKDIR /src
RUN apk add --no-cache git make

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build VERSION=$(git describe --tags --always 2>/dev/null || echo docker)

FROM scratch

# httpsec verifies certificate chains against the system trust store, so the
# image needs one. Everything else is in the binary.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/bin/httpsec /httpsec

LABEL org.opencontainers.image.title="httpsec" \
      org.opencontainers.image.description="Audit HTTP security headers and TLS configuration" \
      org.opencontainers.image.source="https://github.com/dotMuny/httpsec" \
      org.opencontainers.image.licenses="MIT"

USER 65534:65534
ENTRYPOINT ["/httpsec"]
CMD ["--help"]
