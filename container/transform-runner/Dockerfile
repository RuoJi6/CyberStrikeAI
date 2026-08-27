ARG RUNTIME_IMAGE="debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"
FROM ${RUNTIME_IMAGE}

ARG BUILD_DATE="unknown"
ARG SOURCE_URL="https://github.com/RuoJi6/CyberStrikeAI"
ARG VCS_REF="unknown"
ARG VERSION="development"

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.description="Isolated runner for immutable Agent-authored HTTP traffic transforms" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.title="CyberStrikeAI traffic transform runner" \
      org.opencontainers.image.vendor="CyberStrikeAI" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-cryptography ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 transform \
    && useradd --system --uid 65532 --gid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin transform \
    && mkdir -p /opt/cyberstrike-transform /run/cyberstrike-transform/revisions \
    && chown -R 65532:65532 /run/cyberstrike-transform \
    && chmod 0555 /opt/cyberstrike-transform \
    && chmod 0700 /run/cyberstrike-transform /run/cyberstrike-transform/revisions

COPY --chown=0:0 --chmod=0444 cyberstrike_transform.py worker.py runner.py /opt/cyberstrike-transform/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERSTRIKE_TRANSFORM_LISTEN=0.0.0.0:9089 \
    CYBERSTRIKE_TRANSFORM_REVISION_ROOT=/run/cyberstrike-transform/revisions

USER 65532:65532
ENTRYPOINT ["python3", "-I", "/opt/cyberstrike-transform/runner.py"]
