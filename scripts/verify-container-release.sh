#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: verify-container-release.sh \
  --agent REPOSITORY@sha256:DIGEST \
  --egress REPOSITORY@sha256:DIGEST \
  --source SOURCE_URL \
  [--revision SHARED_GIT_SHA | \
   --agent-revision AGENT_GIT_SHA --egress-revision EGRESS_GIT_SHA] \
  --inventory FILE \
  --artifacts DIRECTORY \
  [--smoke]

Verifies locally available linux/arm64 images and writes an offline evidence
bundle containing SPDX SBOMs, exact image metadata and SHA-256 checksums.
No registry, GitHub Actions, signing service or amd64 runner is used.
EOF
  exit 2
}

agent_ref=
egress_ref=
source_url=
revision=
agent_revision=
egress_revision=
inventory=
artifacts=
smoke=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) agent_ref=${2:-}; shift 2 ;;
    --egress) egress_ref=${2:-}; shift 2 ;;
    --source) source_url=${2:-}; shift 2 ;;
    --revision) revision=${2:-}; shift 2 ;;
    --agent-revision) agent_revision=${2:-}; shift 2 ;;
    --egress-revision) egress_revision=${2:-}; shift 2 ;;
    --inventory) inventory=${2:-}; shift 2 ;;
    --artifacts) artifacts=${2:-}; shift 2 ;;
    --smoke) smoke=true; shift ;;
    *) usage ;;
  esac
done

digest_ref_pattern='^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$'
revision_pattern='^[a-f0-9]{40}$'
[[ "$agent_ref" =~ $digest_ref_pattern && "$egress_ref" =~ $digest_ref_pattern ]] || usage
if [[ -n "$revision" ]]; then
  [[ -z "$agent_revision" ]] && agent_revision=$revision
  [[ -z "$egress_revision" ]] && egress_revision=$revision
fi
[[ "$source_url" =~ ^https:// && "$agent_revision" =~ $revision_pattern && "$egress_revision" =~ $revision_pattern ]] || usage
[[ -f "$inventory" && -n "$artifacts" ]] || usage

for command_name in docker jq; do
  command -v "$command_name" >/dev/null || {
    printf 'required command is unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
if command -v sha256sum >/dev/null; then
  sha256_command=(sha256sum)
else
  command -v shasum >/dev/null || {
    printf 'sha256sum or shasum is required\n' >&2
    exit 1
  }
  sha256_command=(shasum -a 256)
fi

mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd)
inventory=$(cd "$(dirname "$inventory")" && pwd)/$(basename "$inventory")
work_root=$(mktemp -d "${TMPDIR:-/tmp}/cyberstrike-arm64-release.XXXXXX")
export_container=
cleanup() {
  if [[ -n "$export_container" ]]; then
    docker rm -f "$export_container" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_root"
}
trap cleanup EXIT INT TERM

inspect_image() {
  local name=$1
  local ref=$2
  local expected_user=$3
  local expected_entrypoint=$4
  local expected_revision=$5
  local expected_cmd0=${6:-}
  local expected_cmd1=${7:-}
  local raw="$work_root/$name-inspect.json"

  docker image inspect "$ref" >"$raw"
  jq -e --arg source "$source_url" --arg revision "$expected_revision" \
    --arg user "$expected_user" --arg entrypoint "$expected_entrypoint" \
    --arg cmd0 "$expected_cmd0" --arg cmd1 "$expected_cmd1" '
      length == 1 and
      .[0].Os == "linux" and .[0].Architecture == "arm64" and
      .[0].Config.Labels["org.opencontainers.image.source"] == $source and
      .[0].Config.Labels["org.opencontainers.image.revision"] == $revision and
      .[0].Config.User == $user and
      (
        if $entrypoint == "" then
          ((.[0].Config.Entrypoint // []) | length) == 0
        else
          .[0].Config.Entrypoint[0] == $entrypoint
        end
      ) and
      (
        if $cmd0 == "" then true else .[0].Config.Cmd[0] == $cmd0 end
      ) and
      (
        if $cmd1 == "" then true else .[0].Config.Cmd[1] == $cmd1 end
      )
    ' "$raw" >/dev/null

  local expected_digest=${ref##*@}
  local actual_digest
  actual_digest=$(jq -er '.[0].Id' "$raw")
  [[ "$actual_digest" == "$expected_digest" ]] || {
    printf '%s image ID %s does not match configured digest %s\n' \
      "$name" "$actual_digest" "$expected_digest" >&2
    exit 1
  }

  jq '.[0] | {
    Id, RepoTags, RepoDigests, Architecture, Os, Size,
    Config: {User, Entrypoint, Cmd, Labels}
  }' "$raw" >"$artifacts/$name-image.json"
}

inspect_image agent "$agent_ref" "pentester" "" "$agent_revision" "sleep" "infinity"
inspect_image egress "$egress_ref" "0:0" "/cyberstrike-egress" "$egress_revision"

scanner_version=$(docker run --rm --network none \
  --entrypoint /usr/local/bin/trivy "$agent_ref" version | \
  awk -F': ' '/^Version:/ {print $2; exit}')
[[ -n "$scanner_version" ]] || {
  printf 'the pinned Agent image does not provide a usable Trivy scanner\n' >&2
  exit 1
}
jq -n --arg name trivy --arg version "$scanner_version" \
  --arg image "$agent_ref" --arg network none \
  '{name: $name, version: $version, scannerImage: $image, network: $network,
    mode: "offline-rootfs-os-packages"}' >"$artifacts/sbom-scanner.json"

docker run --rm --network none \
  --entrypoint /usr/local/bin/trivy "$agent_ref" rootfs \
  --quiet --format spdx-json --skip-db-update --skip-java-db-update --offline-scan \
  --pkg-types os \
  --cache-dir /tmp/trivy-cache / >"$artifacts/agent-sbom.spdx.json"

egress_rootfs="$work_root/egress-rootfs"
mkdir -p "$egress_rootfs"
export_container=$(docker create "$egress_ref")
docker export "$export_container" | tar -xf - -C "$egress_rootfs"
docker rm "$export_container" >/dev/null
export_container=
docker run --rm --network none \
  --mount "type=bind,source=$egress_rootfs,target=/scan,readonly" \
  --entrypoint /usr/local/bin/trivy "$agent_ref" rootfs \
  --quiet --format spdx-json --skip-db-update --skip-java-db-update --offline-scan \
  --pkg-types os \
  --cache-dir /tmp/trivy-cache /scan >"$artifacts/egress-sbom.spdx.json"

for sbom in agent-sbom.spdx.json egress-sbom.spdx.json; do
  jq -e '.spdxVersion | type == "string" and startswith("SPDX-")' \
    "$artifacts/$sbom" >/dev/null
done

agent_digest=${agent_ref##*@}
jq -e --arg digest "$agent_digest" '
  .schemaVersion == 1 and .imagePlatform == "linux/arm64" and
  .imageDigest == $digest and
  (.tools | type == "array" and length > 0) and
  all(.tools[];
    (.name | type == "string" and length > 0) and
    (.path | type == "string" and startswith("/") and length > 1) and
    (.version | type == "string" and length > 0) and
    (.category | type == "string" and length > 0)
  )
' "$inventory" >/dev/null
cp "$inventory" "$artifacts/agent-tool-inventory-linux-arm64.json"

jq -n \
  --arg agentRevision "$agent_revision" \
  --arg egressRevision "$egress_revision" \
  --arg source "$source_url" \
  --arg platform "linux/arm64" \
  --arg agent "$agent_ref" \
  --arg egress "$egress_ref" \
  '{schemaVersion: 2,
    revisions: {agent: $agentRevision, egress: $egressRevision}, source: $source,
    platform: $platform, agent: $agent, egress: $egress,
    verification: "offline-sha256"}' >"$artifacts/images.json"

(
  cd "$artifacts"
  rm -f SHA256SUMS
  "${sha256_command[@]}" \
    agent-image.json agent-sbom.spdx.json \
    egress-image.json egress-sbom.spdx.json \
    agent-tool-inventory-linux-arm64.json images.json \
    sbom-scanner.json >SHA256SUMS
  if [[ "${sha256_command[0]}" == "sha256sum" ]]; then
    sha256sum --check SHA256SUMS >/dev/null
  else
    shasum -a 256 --check SHA256SUMS >/dev/null
  fi
)

if [[ "$smoke" == true ]]; then
  script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  "$script_root/smoke-container-images.sh" \
    --agent "$agent_ref" --egress "$egress_ref" \
    --platform linux/arm64 \
    --entries "$script_root/../container/agent/tool-inventory.entries.json"
fi

printf 'ARM64 container release verification passed; evidence: %s\n' "$artifacts"
