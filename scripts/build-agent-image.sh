#!/usr/bin/env bash
# Build CyberStrikeAI full-agent Kali image locally. Never accepts credentials.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-agent-image.sh --tag TAG [--platform PLATFORMS] [--builder NAME]
       [--cache-only|--load] [--vcs-ref REF] [--version VER]
       [--build-date ISO8601] [--source-url URL]

Builds container/agent/Dockerfile with Buildx. Does not push or login.
Use --cache-only for a cloud multi-platform validation build. --load is the
default and is limited to one platform.
EOF
  exit 2
}

script_root=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_root/.." && pwd)
context="$repo_root/container/agent"

tag=
platform=linux/arm64
builder=
output=load
vcs_ref=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)
version=development
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
source_url=https://github.com/RuoJi6/CyberStrikeAI

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag=${2:-}; shift 2 ;;
    --platform|--platforms) platform=${2:-}; shift 2 ;;
    --builder) builder=${2:-}; shift 2 ;;
    --cache-only) output=cache-only; shift ;;
    --load) output=load; shift ;;
    --vcs-ref) vcs_ref=${2:-}; shift 2 ;;
    --version) version=${2:-}; shift 2 ;;
    --build-date) build_date=${2:-}; shift 2 ;;
    --source-url) source_url=${2:-}; shift 2 ;;
    -h|--help) usage ;;
    --password|--token|--username|--docker-password|--docker-token)
      printf 'refusing credential argument: %s\n' "$1" >&2
      exit 2
      ;;
    *) usage ;;
  esac
done

[[ -n "$tag" ]] || usage
if [[ "$tag" == *:latest || "$tag" == latest ]]; then
  printf 'refusing to build tag "latest"; use an immutable version tag\n' >&2
  exit 2
fi
[[ "$platform" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))*$ ]] || usage
if [[ "$output" == load && "$platform" == *,* ]]; then
  printf 'multi-platform builds cannot use --load; use --cache-only\n' >&2
  exit 2
fi

command -v docker >/dev/null
[[ -f "$context/Dockerfile" ]]
[[ -f "$context/toolchain.lock" ]]

# Coverage gate before build
python3 "$script_root/check-agent-tool-coverage.py" \
  --tools-dir "$repo_root/tools" \
  --mapping "$repo_root/container/agent/tool-mapping.json" \
  --lock "$repo_root/container/agent/toolchain.lock"

build_command=(docker buildx build)
if [[ -n "$builder" ]]; then
  build_command+=(--builder "$builder")
fi
if [[ "$output" == cache-only ]]; then
  build_command+=(--output type=cacheonly)
else
  build_command+=(--load)
fi

"${build_command[@]}" \
  --platform "$platform" \
  --progress plain \
  --file "$context/Dockerfile" \
  --tag "$tag" \
  --build-arg "BUILD_DATE=$build_date" \
  --build-arg "SOURCE_URL=$source_url" \
  --build-arg "VCS_REF=$vcs_ref" \
  --build-arg "VERSION=$version" \
  --build-arg 'KALI_IMAGE=kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1' \
  --build-arg 'KALI_INDEX_DIGEST=sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1' \
  "$context"

printf 'build completed for %s (%s, output=%s)\n' "$tag" "$platform" "$output"
