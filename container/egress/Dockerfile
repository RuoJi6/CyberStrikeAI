ARG GO_IMAGE="golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a"
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

ARG TARGETARCH
ARG TARGETOS

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/cyberstrike-egress ./cmd/cyberstrike-egress
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/cyberstrike-egress ./cmd/cyberstrike-egress

FROM scratch

ARG BUILD_DATE="unknown"
ARG SOURCE_URL="https://github.com/RuoJi6/CyberStrikeAI"
ARG VCS_REF="unknown"
ARG VERSION="development"

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.description="Fail-closed per-conversation egress policy gateway" \
      org.opencontainers.image.documentation="${SOURCE_URL}/blob/${VCS_REF}/docs/en-US/container-image-supply-chain.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.title="CyberStrikeAI egress gateway" \
      org.opencontainers.image.vendor="CyberStrikeAI" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/cyberstrike-egress /cyberstrike-egress
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER 65532:65532
ENTRYPOINT ["/cyberstrike-egress"]
