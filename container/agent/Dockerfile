# syntax=docker/dockerfile:1.7

# CyberStrikeAI full-agent runtime — Kali Rolling based, no Strix inheritance.
ARG KALI_IMAGE="kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1"

# ---------- builder: download / compile non-APT artifacts ----------
FROM ${KALI_IMAGE} AS builder
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip xz-utils \
      golang-go build-essential libssl-dev; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY toolchain.lock /build/toolchain.lock
COPY install-locked-artifacts.sh /build/install-locked-artifacts.sh
COPY cloudmapper-wrapper.sh /build/cloudmapper-wrapper.sh
COPY cloudmapper-pyjq-compat.py /build/cloudmapper-pyjq-compat.py
COPY graphqlmap-wrapper.sh /build/graphqlmap-wrapper.sh
COPY jwt-tool-wrapper.sh /build/jwt-tool-wrapper.sh
COPY paramspider-wrapper.sh /build/paramspider-wrapper.sh
RUN chmod 0755 /build/install-locked-artifacts.sh
ENV LOCK_FILE=/build/toolchain.lock \
    DEST_BIN=/out/usr/local/bin \
    GOPATH=/build/go \
    GOBIN=/out/usr/local/bin \
    CYBERSTRIKE_STAGE=builder \
    PATH=/out/usr/local/bin:/usr/local/go/bin:/usr/bin:/bin
RUN mkdir -p "$DEST_BIN" /out/opt && /build/install-locked-artifacts.sh "$TARGETARCH"

# ---------- node builder: install npm tooling without shipping npm ----------
FROM ${KALI_IMAGE} AS node-builder
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates jq nodejs npm; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
COPY toolchain.lock /build/toolchain.lock
COPY install-locked-artifacts.sh /build/install-locked-artifacts.sh
ENV LOCK_FILE=/build/toolchain.lock \
    DEST_BIN=/out/usr/local/bin \
    NPM_CONFIG_PREFIX=/out/usr/local \
    CYBERSTRIKE_STAGE=runtime-npm
RUN set -eux; \
    chmod 0755 /build/install-locked-artifacts.sh; \
    mkdir -p /out/usr/local/bin; \
    /build/install-locked-artifacts.sh "$TARGETARCH"; \
    rm -rf /root/.npm /root/.cache /tmp/cyberstrike-dl

# ---------- final runtime ----------
FROM ${KALI_IMAGE}

ARG TARGETARCH
ARG BUILD_DATE="unknown"
ARG SOURCE_URL="https://github.com/RuoJi6/CyberStrikeAI"
ARG VCS_REF="unknown"
ARG VERSION="development"
ARG KALI_INDEX_DIGEST="sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/tools-venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.description="Digest-pinned CyberStrikeAI full-agent runtime on Kali Rolling" \
      org.opencontainers.image.documentation="${SOURCE_URL}/blob/${VCS_REF}/docs/zh-CN/full-agent-image-build-acceptance-plan.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.title="CyberStrikeAI Agent runtime" \
      org.opencontainers.image.vendor="CyberStrikeAI" \
      org.opencontainers.image.version="${VERSION}" \
      com.cyberstrike.base.name="kalilinux/kali-rolling" \
      com.cyberstrike.base.digest="${KALI_INDEX_DIGEST}" \
      com.cyberstrike.base.index-digest="${KALI_INDEX_DIGEST}" \
      com.cyberstrike.agent.toolset="configured-77-platform-aware"

# Create non-root user early; no passwordless sudo.
RUN set -eux; \
    groupadd --gid 1000 pentester; \
    useradd --uid 1000 --gid 1000 --create-home --home-dir /home/pentester --shell /bin/bash pentester; \
    mkdir -p /workspace /opt; \
    chown -R pentester:pentester /home/pentester /workspace; \
    if [ -f /etc/sudoers ]; then \
      sed -i '/^[[:space:]]*pentester[[:space:]].*NOPASSWD/d' /etc/sudoers || true; \
    fi; \
    rm -rf /etc/sudoers.d/* /app/certs 2>/dev/null || true

# APT packages from toolchain.lock (no kali-linux-everything).
# The Kali redirector repeatedly assigned the large Ghidra package to an
# unreachable mirror during multi-arch builds. Pin this stage to Kali's verified
# official download endpoint; package authenticity is enforced by its keyring.
COPY toolchain.lock /tmp/toolchain.lock
RUN --mount=type=cache,id=cyberstrike-agent-apt-lists-${TARGETARCH},target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,id=cyberstrike-agent-apt-cache-${TARGETARCH},target=/var/cache/apt,sharing=locked \
    set -eux; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    grep -R -q 'http://http.kali.org/kali' /etc/apt/sources.list /etc/apt/sources.list.d; \
    find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
      -exec sed -i 's#http://http.kali.org/kali#http://kali.download/kali#g' '{}' +; \
    grep -R -q 'http://kali.download/kali' /etc/apt/sources.list /etc/apt/sources.list.d; \
    printf '%s\n' \
      'path-exclude=/usr/share/doc/*' \
      'path-exclude=/usr/share/man/*' \
      'path-exclude=/usr/share/info/*' \
      'path-exclude=/usr/share/locale/*' \
      'path-include=/usr/share/locale/en*' \
      >/etc/dpkg/dpkg.cfg.d/01-cyberstrike-nodoc; \
    apt-get -o Acquire::Retries=5 update; \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends jq findutils; \
    jq -e '.apt_packages | length > 0' /tmp/toolchain.lock >/dev/null; \
    jq -r '.apt_packages[]' /tmp/toolchain.lock \
      | xargs -r -n 8 sh -ec '\
          attempt=1; \
          until apt-get -o Acquire::Retries=5 install -y --no-install-recommends "$@"; do \
            if [ "$attempt" -ge 3 ]; then \
              printf "APT batch failed after %s attempts: %s\\n" "$attempt" "$*" >&2; \
              exit 255; \
            fi; \
            attempt=$((attempt + 1)); \
            apt-get -o Acquire::Retries=5 update; \
          done' sh; \
    rm -rf \
      /var/cache/debconf/*-old \
      /var/log/apt/*

# Python tools (pinned). The venv can reuse compatible Kali packages without
# attempting to uninstall or duplicate them, while direct pins remain isolated.
COPY requirements-tools.txt /tmp/requirements-tools.txt
RUN set -eux; \
    /usr/bin/python3 -m venv --system-site-packages /opt/tools-venv; \
    /opt/tools-venv/bin/python -m pip install --no-cache-dir --no-compile -r /tmp/requirements-tools.txt; \
    for entrypoint in ROPgadget bloodhound-python kube-hunter scout; do \
      test -x "/opt/tools-venv/bin/$entrypoint"; \
      ln -sfn "/opt/tools-venv/bin/$entrypoint" "/usr/local/bin/$entrypoint"; \
    done; \
    ln -sfn /opt/tools-venv/bin/vol /usr/local/bin/volatility3; \
    volatility3 --help >/tmp/volatility3-help.txt; \
    grep -q 'An open-source memory forensics framework' /tmp/volatility3-help.txt; \
    find /opt/tools-venv -type d -name __pycache__ -prune -exec rm -rf '{}' +; \
    rm -f /tmp/volatility3-help.txt; \
    rm -f /tmp/requirements-tools.txt

# Checkov's older transitive urllib3/termcolor constraints are intentionally
# isolated from the other Python tools.
COPY requirements-checkov.txt /tmp/requirements-checkov.txt
RUN set -eux; \
    /usr/bin/python3 -m venv /opt/checkov-venv; \
    /opt/checkov-venv/bin/python -m pip install --no-cache-dir --no-compile -r /tmp/requirements-checkov.txt; \
    ln -sfn /opt/checkov-venv/bin/checkov /usr/local/bin/checkov; \
    checkov --version; \
    find /opt/checkov-venv -type d -name __pycache__ -prune -exec rm -rf '{}' +; \
    rm -f /tmp/requirements-checkov.txt

# Builder outputs (GitHub/Go binaries and the pinned libc-database tree).
COPY --from=builder /out/usr/local/bin/ /usr/local/bin/
COPY --from=builder /out/opt/ /opt/
COPY --from=node-builder /out/usr/local/ /usr/local/

# Gems remain in the final image; npm runs in node-builder and only its runtime
# tree is copied above.
COPY install-locked-artifacts.sh /tmp/install-locked-artifacts.sh
RUN set -eux; \
    chmod 0755 /tmp/install-locked-artifacts.sh; \
    CYBERSTRIKE_STAGE=runtime-gem \
      LOCK_FILE=/tmp/toolchain.lock \
      DEST_BIN=/usr/local/bin \
      /tmp/install-locked-artifacts.sh "${TARGETARCH}"; \
    rm -rf /root/.gem /root/.cache /var/lib/gems/*/cache/* /tmp/cyberstrike-dl; \
    if [ -x /usr/share/ghidra/support/analyzeHeadless ]; then \
      ln -sfn /usr/share/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    elif [ -x /opt/ghidra/support/analyzeHeadless ]; then \
      ln -sfn /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    fi; \
    if [ -x /opt/libc-database/find ]; then \
      ln -sfn /opt/libc-database/find /usr/local/bin/libc-database; \
    fi

# Responder wrapper for read-only rootfs conversations.
COPY --chown=root:root responder-wrapper.sh /usr/local/bin/responder
RUN chmod 0755 /usr/local/bin/responder

# Kali's Amass wrapper requires sudo and tries to mutate /var/lib/libpostal.
# The real binary works without that launcher for the supported Agent actions.
COPY --chown=root:root amass-wrapper.sh /usr/local/bin/amass
RUN chmod 0755 /usr/local/bin/amass

# smbmap 1.10.7 unconditionally raises RLIMIT_NOFILE to 4096. Python 3.14
# rejects that when the container hard limit is lower, so clamp the requested
# soft limit to the actual hard limit while preserving an unlimited hard cap.
RUN set -eux; \
    smbmap_module=/usr/lib/python3/dist-packages/smbmap/smbmap.py; \
    grep -Fq 'resource.setrlimit(resource.RLIMIT_NOFILE, (4096, rlimit[1]))' "$smbmap_module"; \
    sed -i 's/resource\.setrlimit(resource\.RLIMIT_NOFILE, (4096, rlimit\[1\]))/resource.setrlimit(resource.RLIMIT_NOFILE, (4096 if rlimit[1] == resource.RLIM_INFINITY else min(4096, rlimit[1]), rlimit[1]))/' "$smbmap_module"; \
    python3 -m py_compile "$smbmap_module"

# Fail the build if a tool declared for this platform is absent. Tools explicitly
# limited to another platform are reported as skipped, never counted as present.
COPY tool-mapping.json /tmp/tool-mapping.json
RUN set -eux; \
    platform="linux/${TARGETARCH}"; \
    jq -r --arg platform "$platform" \
      '.tools[] \
       | select(((.supported_platforms // ["linux/amd64", "linux/arm64"]) | index($platform)) != null) \
       | [.yaml_name, .probe_kind, .probe_bin, .install_method] \
       | @tsv' \
      /tmp/tool-mapping.json >/tmp/tool-probes.tsv; \
    tab=$(printf '\t'); \
    while IFS="$tab" read -r yaml_name probe_kind probe_bin install_method; do \
      if [ "$probe_kind" = control_plane ] || [ "$install_method" = control_plane ]; then \
        printf 'skip control-plane %s\n' "$yaml_name"; \
      elif [ "$probe_kind" = python_import ]; then \
        case "$yaml_name" in \
          angr|pwntools) /opt/tools-venv/bin/python -c "import ${probe_bin}" ;; \
          *) python3 -c "import ${probe_bin}" ;; \
        esac; \
      else \
        command -v "$probe_bin" >/dev/null; \
      fi; \
    done </tmp/tool-probes.tsv; \
    java -version >/tmp/java-version.txt 2>&1; \
    spectral --version >/tmp/spectral-version.txt; \
    grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+' /tmp/spectral-version.txt; \
    for entrypoint in ROPgadget bloodhound-python kube-hunter scout; do \
      test "$(readlink -f "/usr/local/bin/$entrypoint")" = "/opt/tools-venv/bin/$entrypoint"; \
    done; \
    amass -version >/tmp/amass-version.txt; \
    grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+' /tmp/amass-version.txt; \
    masscan_status=0; \
    masscan --version >/tmp/masscan-version.txt 2>&1 || masscan_status=$?; \
    test "$masscan_status" -eq 1; \
    grep -q 'Masscan version' /tmp/masscan-version.txt; \
    smbmap_status=0; \
    smbmap --help >/tmp/smbmap-help.txt 2>&1 || smbmap_status=$?; \
    test "$smbmap_status" -eq 1; \
    grep -q 'usage: smbmap' /tmp/smbmap-help.txt; \
    ROPgadget --help >/tmp/ropgadget-help.txt; \
    grep -q 'usage: ROPgadget' /tmp/ropgadget-help.txt; \
    scout --help >/tmp/scout-help.txt; \
    grep -q 'The provider you want to run scout against' /tmp/scout-help.txt; \
    kube-hunter --help >/tmp/kube-hunter-help.txt; \
    grep -q 'hunt for security weaknesses' /tmp/kube-hunter-help.txt; \
    cloudmapper_status=0; \
    cloudmapper >/tmp/cloudmapper-help.txt 2>&1 || cloudmapper_status=$?; \
    test "$cloudmapper_status" -eq 255; \
    grep -q 'CloudMapper 2.10.0' /tmp/cloudmapper-help.txt; \
    graphqlmap --help >/tmp/graphqlmap-help.txt; \
    grep -q 'URL to query' /tmp/graphqlmap-help.txt; \
    jwt_tool --help >/tmp/jwt-tool-help.txt; \
    grep -q 'JWT to tinker with' /tmp/jwt-tool-help.txt; \
    hashpump -h >/tmp/hashpump-help.txt; \
    grep -q 'HashPump generates strings' /tmp/hashpump-help.txt; \
    rustscan --version >/tmp/rustscan-version.txt; \
    grep -q '2.4.1' /tmp/rustscan-version.txt; \
    volatility3 --help >/tmp/volatility3-help.txt; \
    grep -q 'An open-source memory forensics framework' /tmp/volatility3-help.txt; \
    paramspider --help >/tmp/paramspider-help.txt; \
    grep -q 'Mining URLs from dark corners' /tmp/paramspider-help.txt; \
    expected=$(jq -r --arg platform "$platform" \
      '[.tools[] | select(((.supported_platforms // ["linux/amd64", "linux/arm64"]) | index($platform)) != null)] | length' \
      /tmp/tool-mapping.json); \
    printf 'platform tool gate passed: %s expected entries on %s\n' "$expected" "$platform"; \
    rm -f /tmp/tool-probes.tsv /tmp/tool-mapping.json /tmp/java-version.txt /tmp/spectral-version.txt /tmp/amass-version.txt /tmp/masscan-version.txt /tmp/smbmap-help.txt /tmp/ropgadget-help.txt /tmp/scout-help.txt /tmp/kube-hunter-help.txt /tmp/cloudmapper-help.txt /tmp/graphqlmap-help.txt /tmp/jwt-tool-help.txt /tmp/hashpump-help.txt /tmp/rustscan-version.txt /tmp/volatility3-help.txt /tmp/paramspider-help.txt

# Remove transient build inputs after the final platform probe.
RUN set -eux; \
    rm -rf /var/lib/apt/lists/* /tmp/toolchain.lock /tmp/install-locked-artifacts.sh /root/go /build; \
    if [ -f /etc/sudoers ]; then \
      sed -i '/^[[:space:]]*pentester[[:space:]].*NOPASSWD/d' /etc/sudoers || true; \
    fi; \
    rm -rf /etc/sudoers.d/* 2>/dev/null || true; \
    test ! -e /app/certs

USER pentester
WORKDIR /workspace
# Control plane replaces the entrypoint with a keepalive; keep a safe default.
CMD ["sleep", "infinity"]
