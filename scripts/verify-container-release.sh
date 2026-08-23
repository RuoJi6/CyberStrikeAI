#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: verify-container-release.sh \
  --agent REPOSITORY@sha256:DIGEST \
  --egress REPOSITORY@sha256:DIGEST \
  --source SOURCE_URL \
  --revision GIT_SHA \
  --certificate-identity IDENTITY \
  [--certificate-oidc-issuer URL] \
  [--artifacts DIRECTORY --bundle FILE] \
  [--smoke]
EOF
  exit 2
}

agent_ref=
egress_ref=
certificate_identity=
certificate_oidc_issuer=https://token.actions.githubusercontent.com
source_url=
revision=
artifacts=
bundle=
smoke=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) agent_ref=${2:-}; shift 2 ;;
    --egress) egress_ref=${2:-}; shift 2 ;;
    --source) source_url=${2:-}; shift 2 ;;
    --revision) revision=${2:-}; shift 2 ;;
    --certificate-identity) certificate_identity=${2:-}; shift 2 ;;
    --certificate-oidc-issuer) certificate_oidc_issuer=${2:-}; shift 2 ;;
    --artifacts) artifacts=${2:-}; shift 2 ;;
    --bundle) bundle=${2:-}; shift 2 ;;
    --smoke) smoke=true; shift ;;
    *) usage ;;
  esac
done

digest_ref_pattern='^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$'
revision_pattern='^[a-f0-9]{40}$'
[[ "$agent_ref" =~ $digest_ref_pattern && "$egress_ref" =~ $digest_ref_pattern && "$source_url" =~ ^https:// && "$revision" =~ $revision_pattern && -n "$certificate_identity" ]] || usage
if [[ -n "$artifacts" || -n "$bundle" ]]; then
  [[ -d "$artifacts" && -f "$bundle" && -f "$artifacts/SHA256SUMS" ]] || usage
fi

for command_name in cosign docker jq; do
  command -v "$command_name" >/dev/null || {
    printf 'required command is unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done

verify_signature() {
  cosign verify \
    --certificate-identity "$certificate_identity" \
    --certificate-oidc-issuer "$certificate_oidc_issuer" \
    "$1" >/dev/null
}

platform_digest() {
  local raw=$1
  local architecture=$2
  jq -er --arg architecture "$architecture" '
    [.manifests[] | select(.platform.os == "linux" and .platform.architecture == $architecture)] as $matches
    | if ($matches | length) == 1 then $matches[0].digest else error("platform manifest is missing or ambiguous") end
  ' "$raw"
}

verify_image() {
  local name=$1
  local ref=$2
  local repository=${ref%@*}
  local raw="$work_root/$name-index.json"
  docker buildx imagetools inspect --raw "$ref" >"$raw"
  jq -e '.schemaVersion == 2 and (.manifests | type == "array")' "$raw" >/dev/null
  verify_signature "$ref"
  for architecture in amd64 arm64; do
    local platform="linux/$architecture"
    local digest
    digest=$(platform_digest "$raw" "$architecture")
    verify_signature "$repository@$digest"

    docker buildx imagetools inspect "$repository@$digest" \
      --format '{{ json .Image.config.Labels }}' | jq -e \
      --arg source "$source_url" --arg revision "$revision" '
        .["org.opencontainers.image.source"] == $source and
        .["org.opencontainers.image.revision"] == $revision
      ' >/dev/null

    docker buildx imagetools inspect "$ref" \
      --format "{{ json (index .SBOM \"$platform\").SPDX }}" | jq -e '
        (.spdxVersion | type == "string" and startswith("SPDX-"))
      ' >/dev/null

    docker buildx imagetools inspect "$ref" \
      --format "{{ json (index .Provenance \"$platform\").SLSA }}" | jq -e \
      --arg platform "$platform" '
        .buildType == "https://mobyproject.org/buildkit@v1" and
        .invocation.environment.platform == $platform and
        (.materials | type == "array" and length > 0)
      ' >/dev/null
  done
}

work_root=$(mktemp -d "${TMPDIR:-/tmp}/cyberstrike-release-verify.XXXXXX")
trap 'rm -rf -- "$work_root"' EXIT INT TERM

verify_image agent "$agent_ref"
verify_image egress "$egress_ref"

if [[ -n "$artifacts" ]]; then
  for required in \
    agent-index.json egress-index.json images.json SHA256SUMS \
    agent-tool-inventory-linux-amd64.json agent-tool-inventory-linux-amd64.sha256 \
    agent-tool-inventory-linux-arm64.json agent-tool-inventory-linux-arm64.sha256; do
    [[ -f "$artifacts/$required" ]] || {
      printf 'release artifact is missing: %s\n' "$required" >&2
      exit 1
    }
  done
  if command -v sha256sum >/dev/null; then
    (cd "$artifacts" && sha256sum --check SHA256SUMS)
  else
    (cd "$artifacts" && shasum -a 256 --check SHA256SUMS)
  fi
  cosign verify-blob \
    --bundle "$bundle" \
    --certificate-identity "$certificate_identity" \
    --certificate-oidc-issuer "$certificate_oidc_issuer" \
    "$artifacts/SHA256SUMS" >/dev/null
  jq -e \
    --arg agent "$agent_ref" --arg egress "$egress_ref" --arg revision "$revision" '
      .schemaVersion == 1 and .revision == $revision and
      .agent == $agent and .egress == $egress
    ' "$artifacts/images.json" >/dev/null
  for architecture in amd64 arm64; do
    inventory="$artifacts/agent-tool-inventory-linux-$architecture.json"
    digest_file="$artifacts/agent-tool-inventory-linux-$architecture.sha256"
    expected_image_digest=$(platform_digest "$work_root/agent-index.json" "$architecture")
    jq -e --arg platform "linux/$architecture" --arg image_digest "$expected_image_digest" '
      .schemaVersion == 1 and .imagePlatform == $platform and
      .imageDigest == $image_digest and
      (.tools | type == "array" and length > 0) and
      (all(.tools[];
        (.name | type == "string" and length > 0) and
        (.path | type == "string" and startswith("/") and length > 1) and
        (.version | type == "string" and length > 0) and
        (.category | type == "string" and length > 0)
      )) and
      ([.tools[].name | ascii_downcase] | length == (unique | length))
    ' "$inventory" >/dev/null
    if command -v sha256sum >/dev/null; then
      actual_inventory_digest="sha256:$(sha256sum "$inventory" | awk '{print $1}')"
    else
      actual_inventory_digest="sha256:$(shasum -a 256 "$inventory" | awk '{print $1}')"
    fi
    [[ "$(tr -d '[:space:]' <"$digest_file")" == "$actual_inventory_digest" ]] || {
      printf 'tool inventory digest mismatch for linux/%s\n' "$architecture" >&2
      exit 1
    }
  done
fi

if [[ "$smoke" == true ]]; then
  script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  entries="$script_root/../container/agent/tool-inventory.entries.json"
  for platform in linux/amd64 linux/arm64; do
    "$script_root/smoke-container-images.sh" \
      --agent "$agent_ref" --egress "$egress_ref" \
      --platform "$platform" --entries "$entries"
  done
fi

printf 'container release verification passed\n'
