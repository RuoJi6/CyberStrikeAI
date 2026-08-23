ARG STRIX_IMAGE="ghcr.io/usestrix/strix-sandbox@sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331"
FROM ${STRIX_IMAGE}

ARG BUILD_DATE="unknown"
ARG SOURCE_URL="https://github.com/RuoJi6/CyberStrikeAI"
ARG VCS_REF="unknown"
ARG VERSION="development"

USER root

# Strix 1.3.0 ships a testing CA and its private key for its own browser
# workflow. CyberStrikeAI does not enable TLS interception in the first
# container release, so the derived runtime must not trust or expose that
# publicly recoverable key. It also removes the passwordless sudo grant; the
# control plane supplies the required Docker capabilities explicitly.
RUN set -eux; \
    sed -i '\|^pentester ALL=(ALL) NOPASSWD:ALL$|d' /etc/sudoers; \
    rm -f /usr/local/share/ca-certificates/ca.crt; \
    rm -rf /app/certs; \
    update-ca-certificates --fresh

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.description="Digest-pinned CyberStrikeAI Agent runtime derived from Strix 1.3.0" \
      org.opencontainers.image.documentation="${SOURCE_URL}/blob/${VCS_REF}/docs/en-US/container-image-supply-chain.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.title="CyberStrikeAI Agent runtime" \
      org.opencontainers.image.vendor="CyberStrikeAI" \
      org.opencontainers.image.version="${VERSION}" \
      com.cyberstrike.base.name="ghcr.io/usestrix/strix-sandbox" \
      com.cyberstrike.base.tag="1.3.0" \
      com.cyberstrike.base.digest="sha256:f6906c3114e504fd1a218fcf028d7a0e46851118403a438b63956de6ea7c4331" \
      com.cyberstrike.base.source-revision="8ec54d9e2bd4f4c3b87afcdfdd6e9819f9964d30"

USER pentester
WORKDIR /workspace
