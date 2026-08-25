#!/usr/bin/env bash
# Build, verify, and publish the multi-platform egress gateway image.
# Credentials are never accepted as arguments. The immutable version tag is
# verified before :latest is moved, and local verification images are removed.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: publish-egress-image.sh --tag REPO:VERSION [--builder NAME]
       [--platforms linux/amd64,linux/arm64] [--vcs-ref REF]
       [--version VER] [--build-date ISO8601] [--source-url URL]

Requires prior interactive docker login. Builds and pushes an AMD64/ARM64
image, verifies both registry manifests and both runnable images, moves
REPO:latest to the verified index digest, and removes locally pulled copies.

By default, the build uses a dedicated temporary local builder. Removing that
builder after the release also removes this build's local cache and history.
Pass --builder to use an existing builder such as Docker Build Cloud instead.
EOF
  exit 2
}

script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_root/.." && pwd)
dockerfile="$repo_root/container/egress/Dockerfile"

tag=
builder=auto
platforms=linux/amd64,linux/arm64
vcs_ref=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)
version=
build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
source_url=https://github.com/RuoJi6/CyberStrikeAI

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag=${2:-}; shift 2 ;;
    --builder) builder=${2:-}; shift 2 ;;
    --platform|--platforms) platforms=${2:-}; shift 2 ;;
    --vcs-ref) vcs_ref=${2:-}; shift 2 ;;
    --version) version=${2:-}; shift 2 ;;
    --build-date) build_date=${2:-}; shift 2 ;;
    --source-url) source_url=${2:-}; shift 2 ;;
    -h|--help) usage ;;
    --password|--token|--username|--docker-password|--docker-token|--password-stdin)
      printf 'refusing credential argument: %s\n' "$1" >&2
      exit 2
      ;;
    *) usage ;;
  esac
done

[[ -n "$tag" && "$tag" == */*:* && "$tag" != *@* ]] || usage
if [[ "$tag" == *:latest || "$tag" == latest || "$tag" == */latest ]]; then
  printf 'refusing latest as the immutable release tag: %s\n' "$tag" >&2
  exit 2
fi
if [[ "$platforms" != linux/amd64,linux/arm64 && "$platforms" != linux/arm64,linux/amd64 ]]; then
  printf 'gateway releases require both linux/amd64 and linux/arm64\n' >&2
  exit 2
fi
[[ -n "$builder" ]] || usage

repository=${tag%:*}
latest_tag="$repository:latest"
version=${version:-${tag##*:}}

command -v docker >/dev/null
command -v git >/dev/null
command -v jq >/dev/null
[[ -f "$dockerfile" ]]
[[ -f "$dockerfile.dockerignore" ]]

# Only files that can enter this Dockerfile's build context gate the release.
# Unrelated user changes elsewhere in the worktree remain untouched.
gateway_inputs=(
  go.mod
  go.sum
  cmd/cyberstrike-egress
  internal
  container/egress
)
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all -- "${gateway_inputs[@]}")" ]]; then
  printf 'refusing release from dirty gateway image inputs\n' >&2
  git -C "$repo_root" status --short -- "${gateway_inputs[@]}" >&2
  exit 1
fi
git -C "$repo_root" cat-file -e "${vcs_ref}^{commit}" 2>/dev/null || {
  printf 'VCS_REF is not a local commit: %s\n' "$vcs_ref" >&2
  exit 1
}

docker_config_dir=${DOCKER_CONFIG:-${HOME:?}/.docker}
docker_config="$docker_config_dir/config.json"
if [[ ! -f "$docker_config" ]] || ! grep -Eq '"auths"|"credsStore"|"credHelpers"' "$docker_config"; then
  printf 'docker does not appear to be logged in; run interactive: docker login\n' >&2
  exit 1
fi

metadata_file=$(mktemp "${TMPDIR:-/tmp}/cyberstrike-egress-publish.XXXXXX")
index_file=$(mktemp "${TMPDIR:-/tmp}/cyberstrike-egress-index.XXXXXX")
test_root=$(mktemp -d "${TMPDIR:-/tmp}/cyberstrike-egress-smoke.XXXXXX")
snapshot_path="$test_root/boundary.json"
snapshot_id=12345678-1234-4234-8234-123456789abc
published_digest=
amd64_digest=
arm64_digest=
ephemeral_builder=
remove_buildkit_helper=false

cleanup() {
  rm -f -- "$metadata_file" "$index_file"
  rm -rf -- "$test_root"
  if [[ -n "$published_digest" ]]; then
    local_images=("$tag" "$latest_tag" "$repository@$published_digest")
    [[ -n "$amd64_digest" ]] && local_images+=("$repository@$amd64_digest")
    [[ -n "$arm64_digest" ]] && local_images+=("$repository@$arm64_digest")
    docker image rm "${local_images[@]}" >/dev/null 2>&1 || true
  fi
  if [[ -n "$ephemeral_builder" ]]; then
    docker buildx rm "$ephemeral_builder" >/dev/null 2>&1 || true
  fi
  if [[ "$remove_buildkit_helper" == true ]]; then
    docker image rm moby/buildkit:buildx-stable-1 >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$builder" == auto ]]; then
  if ! docker image inspect moby/buildkit:buildx-stable-1 >/dev/null 2>&1; then
    remove_buildkit_helper=true
  fi
  builder="cyberstrike-egress-publish-$$-$RANDOM"
  ephemeral_builder=$builder
  docker buildx create \
    --name "$builder" \
    --driver docker-container \
    >/dev/null
fi
docker buildx inspect "$builder" --bootstrap >/dev/null

printf '%s' '{"schemaVersion":1,"policyId":"","rules":[]}' >"$snapshot_path"
chmod 0444 "$snapshot_path"
if command -v sha256sum >/dev/null; then
  snapshot_hex=$(sha256sum "$snapshot_path" | awk '{print $1}')
else
  snapshot_hex=$(shasum -a 256 "$snapshot_path" | awk '{print $1}')
fi

docker buildx build \
  --builder "$builder" \
  --platform "$platforms" \
  --file "$dockerfile" \
  --tag "$tag" \
  --build-arg "BUILD_DATE=$build_date" \
  --build-arg "SOURCE_URL=$source_url" \
  --build-arg "VCS_REF=$vcs_ref" \
  --build-arg "VERSION=$version" \
  --provenance=mode=max \
  --sbom=true \
  --progress=plain \
  --metadata-file "$metadata_file" \
  --push \
  "$repo_root"

published_digest=$(jq -er '."containerimage.digest"' "$metadata_file")
[[ "$published_digest" =~ ^sha256:[0-9a-f]{64}$ ]]

docker buildx imagetools inspect "$tag" --raw >"$index_file"
jq -e '
  [.manifests[]
    | select(.platform.os == "linux")
    | select(.platform.architecture == "amd64" or .platform.architecture == "arm64")
    | "\(.platform.os)/\(.platform.architecture)"]
  | unique | sort == ["linux/amd64", "linux/arm64"]
' "$index_file" >/dev/null

amd64_digest=$(jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' "$index_file")
arm64_digest=$(jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "arm64") | .digest' "$index_file")
[[ "$amd64_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$arm64_digest" =~ ^sha256:[0-9a-f]{64}$ ]]

for platform_digest in "linux/amd64=$amd64_digest" "linux/arm64=$arm64_digest"; do
  platform=${platform_digest%%=*}
  digest=${platform_digest#*=}
  docker run --rm \
    --platform "$platform" \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=16777216 \
    --mount "type=bind,source=$snapshot_path,target=/etc/cyberstrike/boundary.json,readonly" \
    "$repository@$digest" check \
    --snapshot-path /etc/cyberstrike/boundary.json \
    --snapshot-id "$snapshot_id" \
    --snapshot-sha256 "sha256:$snapshot_hex" \
    | grep -q '"event":"boundary_snapshot_healthy"'
  printf 'gateway smoke passed: %s (%s)\n' "$platform" "$digest"
done

# Move latest only after both immutable platform images pass their smoke test.
docker buildx imagetools create \
  --tag "$latest_tag" \
  "$repository@$published_digest"

latest_digest=$(docker buildx imagetools inspect "$latest_tag" \
  | awk '$1 == "Digest:" {print $2; exit}')
if [[ "$latest_digest" != "$published_digest" ]]; then
  printf 'latest digest mismatch: got %s, expected %s\n' "$latest_digest" "$published_digest" >&2
  exit 1
fi

printf 'published version tag: %s\n' "$tag"
printf 'published latest tag:  %s\n' "$latest_tag"
printf 'published index:       %s\n' "$published_digest"
printf 'linux/amd64 manifest:  %s\n' "$amd64_digest"
printf 'linux/arm64 manifest:  %s\n' "$arm64_digest"
printf 'local verification images will be removed now\n'
