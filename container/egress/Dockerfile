ARG GO_IMAGE="golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a"
ARG RUNTIME_IMAGE="debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"
FROM ${GO_IMAGE} AS build

ARG TARGETARCH="arm64"
ARG TARGETOS="linux"
ARG GOPROXY="https://proxy.golang.org,direct"

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/cyberstrike-egress ./cmd/cyberstrike-egress
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" GOPROXY="${GOPROXY}" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/cyberstrike-egress ./cmd/cyberstrike-egress

FROM ${RUNTIME_IMAGE}

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

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/cyberstrike-egress /cyberstrike-egress

USER 0:0
ENTRYPOINT ["/cyberstrike-egress"]
