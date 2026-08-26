#!/usr/bin/env bash
# Build and push a multi-platform agent image, then print the index digest.
# Never accepts password/token args; requires prior interactive docker login.
# Never tags or pushes :latest.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: publish-agent-image.sh --tag REPO:VERSION [--builder NAME]
       [--platforms linux/amd64,linux/arm64] [--vcs-ref REF]
       [--version VER] [--build-date ISO8601] [--source-url URL]
       [--registry-sbom]

Requires a clean Git worktree, checks Docker login, builds with Buildx,
pushes one multi-platform tag, and prints the registry index digest.
Does not accept credentials on the command line or push latest. Registry SBOM
attestations are opt-in because the full toolset can exceed Build Cloud's
attestation size limit; use verify-container-release.sh for offline SPDX SBOMs.
EOF
  exit 2
}

script_root=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_root/.." && pwd)
context="$repo_root/container/agent"

tag=
builder=cloud-ruoji6-cyberstrikeai
platforms=linux/amd64,linux/arm64
vcs_ref=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)
version=
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
source_url=https://github.com/RuoJi6/CyberStrikeAI
registry_sbom=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag=${2:-}; shift 2 ;;
    --builder) builder=${2:-}; shift 2 ;;
    --platform|--platforms) platforms=${2:-}; shift 2 ;;
    --vcs-ref) vcs_ref=${2:-}; shift 2 ;;
    --version) version=${2:-}; shift 2 ;;
    --build-date) build_date=${2:-}; shift 2 ;;
    --source-url) source_url=${2:-}; shift 2 ;;
    --registry-sbom) registry_sbom=true; shift ;;
    -h|--help) usage ;;
    --password|--token|--username|--docker-password|--docker-token|--password-stdin)
      printf 'refusing credential argument: %s\n' "$1" >&2
      exit 2
      ;;
    *) usage ;;
  esac
done

[[ -n "$tag" ]] || usage
if [[ "$tag" == *:latest || "$tag" == latest || "$tag" == */latest ]]; then
  printf 'refusing to publish latest tag: %s\n' "$tag" >&2
  exit 2
fi
[[ "$platforms" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))*$ ]] || usage
[[ -n "$builder" ]] || usage
version=${version:-${tag##*:}}

command -v docker >/dev/null
command -v jq >/dev/null

if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=normal)" ]]; then
  printf 'refusing release from a dirty worktree; commit the reviewed inputs first\n' >&2
  exit 1
fi

python3 "$script_root/check-agent-tool-coverage.py" \
  --tools-dir "$repo_root/tools" \
  --mapping "$repo_root/container/agent/tool-mapping.json" \
  --lock "$repo_root/container/agent/toolchain.lock" \
  --requirements "$repo_root/container/agent/requirements-tools.txt"

# Detect login without printing secrets.
if ! docker info 2>/dev/null | grep -qi 'Username:'; then
  # Fallback: try a dry registry ping via docker system info / config.json presence
  if [[ ! -f "${DOCKER_CONFIG:-$HOME/.docker}/config.json" ]] && [[ ! -f "$HOME/.docker/config.json" ]]; then
    printf 'docker does not appear to be logged in; run interactive: docker login\n' >&2
    exit 1
  fi
fi

# Stronger check: docker pull/auth config must exist for index
cfg="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
if [[ -f "$cfg" ]]; then
  if ! grep -Eq '"auths"|"credsStore"|"credHelpers"' "$cfg"; then
    printf 'docker config has no auths/credsStore; run interactive: docker login\n' >&2
    exit 1
  fi
else
  printf 'missing docker config.json; run interactive: docker login\n' >&2
  exit 1
fi

metadata_file=$(mktemp "${TMPDIR:-/tmp}/cyberstrike-agent-publish.XXXXXX")
trap 'rm -f "$metadata_file"' EXIT

sbom_args=(--sbom=false)
if [[ "$registry_sbom" == true ]]; then
  sbom_args=(--sbom=true)
fi

docker buildx build \
  --builder "$builder" \
  --platform "$platforms" \
  --file "$context/Dockerfile" \
  --tag "$tag" \
  --build-arg "BUILD_DATE=$build_date" \
  --build-arg "SOURCE_URL=$source_url" \
  --build-arg "VCS_REF=$vcs_ref" \
  --build-arg "VERSION=$version" \
  --build-arg 'KALI_IMAGE=kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1' \
  --build-arg 'KALI_INDEX_DIGEST=sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1' \
  --provenance=mode=max \
  "${sbom_args[@]}" \
  --progress=plain \
  --metadata-file "$metadata_file" \
  --push \
  "$context"

digest=$(jq -er '."containerimage.digest"' "$metadata_file")
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
docker buildx imagetools inspect "$tag"

printf 'published tag: %s\n' "$tag"
printf 'published index digest: %s\n' "$digest"
