#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --agent IMAGE --egress IMAGE --platform linux/ARCH --entries FILE\n' "$0" >&2
  exit 2
}

agent_image=
egress_image=
platform=
entries_file=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) agent_image=${2:-}; shift 2 ;;
    --egress) egress_image=${2:-}; shift 2 ;;
    --platform) platform=${2:-}; shift 2 ;;
    --entries) entries_file=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$agent_image" && -n "$egress_image" && "$platform" =~ ^linux/(amd64|arm64)$ && -f "$entries_file" ]] || usage
command -v docker >/dev/null
command -v jq >/dev/null

test_root=$(mktemp -d "${TMPDIR:-/tmp}/cyberstrike-image-smoke.XXXXXX")
snapshot_path="$test_root/boundary.json"
platform_entries="$test_root/tool-inventory.entries.json"
snapshot_id=12345678-1234-4234-8234-123456789abc
agent_name="cyberstrike-agent-smoke-${RANDOM}-$$"
egress_name="cyberstrike-egress-smoke-${RANDOM}-$$"

cleanup() {
  docker rm -f "$agent_name" "$egress_name" >/dev/null 2>&1 || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM

script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mapping_file="$script_root/../container/agent/tool-mapping.json"
[[ -f "$mapping_file" ]] || {
  printf 'missing platform mapping: %s\n' "$mapping_file" >&2
  exit 1
}
jq --arg platform "$platform" --slurpfile mapping "$mapping_file" '
  ($mapping[0].tools
    | map(select(((.supported_platforms // ["linux/amd64", "linux/arm64"]) | index($platform)) == null))
    | map(.probe_bin)) as $unsupported
  | .tools |= map(.name as $name | select(($unsupported | index($name)) == null))
' "$entries_file" >"$platform_entries"

printf '%s' '{"schemaVersion":1,"policyId":"","rules":[]}' >"$snapshot_path"
chmod 0444 "$snapshot_path"
if command -v sha256sum >/dev/null; then
  snapshot_hex=$(sha256sum "$snapshot_path" | awk '{print $1}')
else
  snapshot_hex=$(shasum -a 256 "$snapshot_path" | awk '{print $1}')
fi

docker run --name "$agent_name" --platform "$platform" --network none \
  --read-only --user 0:0 --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /bin/sh "$agent_image" -ceu '
    ! grep -ER "^[[:space:]]*pentester[[:space:]].*NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null
    test ! -e /usr/local/share/ca-certificates/ca.crt
    test ! -e /app/certs
    printf cyberstrike-agent-hardening-ok
  ' | grep -q '^cyberstrike-agent-hardening-ok$'
docker rm "$agent_name" >/dev/null

docker run --name "$agent_name" --platform "$platform" --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=16777216 \
  --tmpfs /workspace:rw,nosuid,nodev,mode=1777,size=67108864 \
  --mount "type=bind,source=$platform_entries,target=/tool-inventory.entries.json,readonly" \
  --entrypoint /bin/sh "$agent_image" -ceu '
    test "$(id -u)" -ne 0
    test "$(id -un)" = pentester
    ! sudo -n true 2>/dev/null
    test ! -e /var/run/docker.sock
    test ! -e /run/docker.sock
    test ! -e /app/certs/ca.key
    test ! -e /app/certs/ca.p12
    jq -er ".tools | length > 0" /tool-inventory.entries.json >/dev/null
    jq -r ".tools[].path" /tool-inventory.entries.json | while IFS= read -r tool; do
      test -x "$tool"
    done
    test -w /workspace
    printf cyberstrike-agent-smoke-ok
  ' | grep -q '^cyberstrike-agent-smoke-ok$'
docker rm "$agent_name" >/dev/null

docker run --name "$egress_name" --platform "$platform" --network none \
  --read-only --user 0:0 --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=16777216 \
  --mount "type=bind,source=$snapshot_path,target=/etc/cyberstrike/boundary.json,readonly" \
  "$egress_image" check \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "sha256:$snapshot_hex" | grep -q '"event":"boundary_snapshot_healthy"'
docker rm "$egress_name" >/dev/null

printf 'container image smoke passed for %s\n' "$platform"
