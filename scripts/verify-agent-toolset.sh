#!/usr/bin/env bash
# Verify CyberStrikeAI agent toolset coverage and optional image probes.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: verify-agent-toolset.sh [--image IMAGE] [--platform linux/ARCH]

Compares tools/*.yaml enabled set to container/agent/tool-mapping.json.
With --image, also probes binaries / python imports inside the container.
EOF
  exit 2
}

script_root=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_root/.." && pwd)
image=
platform=linux/arm64

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) image=${2:-}; shift 2 ;;
    --platform) platform=${2:-}; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

command -v python3 >/dev/null
python3 "$script_root/check-agent-tool-coverage.py" \
  --tools-dir "$repo_root/tools" \
  --mapping "$repo_root/container/agent/tool-mapping.json" \
  --lock "$repo_root/container/agent/toolchain.lock"

mapping="$repo_root/container/agent/tool-mapping.json"
count=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("tools") or []))' "$mapping")
if [[ "$count" -ne 77 ]]; then
  printf 'expected 77 mapping entries, got %s\n' "$count" >&2
  exit 1
fi

# Special probe bin assertions from acceptance plan
python3 - <<'PY' "$mapping"
import json, sys
special = {
  "api-schema-analyzer": "spectral",
  "bloodhound": "bloodhound-python",
  "ghidra": "analyzeHeadless",
  "graphql-scanner": "graphqlmap",
  "jwt-analyzer": "jwt_tool",
  "metasploit": "msfconsole",
  "one-gadget": "one_gadget",
  "radare2": "r2",
  "ropgadget": "ROPgadget",
  "scout-suite": "scout",
}
tools = {t["yaml_name"]: t for t in json.load(open(sys.argv[1]))["tools"]}
failed = []
for yaml_name, probe in special.items():
    row = tools.get(yaml_name)
    if not row or row.get("probe_bin") != probe:
        failed.append(f"{yaml_name} expected probe_bin={probe} got={None if not row else row.get('probe_bin')}")
if failed:
    print("special probe mismatches:")
    print("\n".join(failed))
    raise SystemExit(1)
print("special probe bins: ok")
PY

if [[ -z "$image" ]]; then
  printf 'verify-agent-toolset: coverage ok (no --image probes)\n'
  exit 0
fi

command -v docker >/dev/null
command -v jq >/dev/null

probe_script=$(mktemp)
trap 'rm -f "$probe_script"' EXIT

python3 - <<'PY' >"$probe_script" "$mapping" "$platform"
import json, sys
tools = json.load(open(sys.argv[1]))["tools"]
platform = sys.argv[2]
print("set -euo pipefail")
print('fails=0')
for t in tools:
    kind = t.get("probe_kind")
    name = t["yaml_name"]
    probe = t["probe_bin"]
    method = t.get("install_method")
    supported = t.get("supported_platforms", ["linux/amd64", "linux/arm64"])
    if platform not in supported:
        print(f'printf "skip platform_unsupported %s on %s\\n" "{name}" "{platform}"')
        continue
    if kind == "control_plane" or method == "control_plane":
        print(f'printf "skip control_plane %s\\n" "{name}"')
        continue
    if method == "runtime_builtin" and kind == "bash":
        print(f'command -v sh >/dev/null || {{ echo "missing sh for {name}"; fails=$((fails+1)); }}')
        continue
    if kind == "python_import":
        mod = probe
        python_cmd = "python3"
        # package name may differ from import name
        if name == "pwntools":
            mod = "pwn"
            python_cmd = "/opt/tools-venv/bin/python"
        elif name == "impacket":
            mod = "impacket"
        elif name == "angr":
            mod = "angr"
            python_cmd = "/opt/tools-venv/bin/python"
        print(f'{python_cmd} -c "import {mod}" || {{ echo "import fail {name}/{mod}"; fails=$((fails+1)); }}')
        continue
    if kind == "bash" and probe == "libc-database":
        print(f'test -x /usr/local/bin/libc-database -o -x /opt/libc-database/find || {{ echo "missing libc-database"; fails=$((fails+1)); }}')
        continue
    print(f'command -v {probe} >/dev/null || {{ echo "missing bin {name}->{probe}"; fails=$((fails+1)); }}')
print('if [[ "$fails" -ne 0 ]]; then echo "probe failures: $fails"; exit 1; fi')
print('printf "all image probes passed\\n"')
PY

cat >>"$probe_script" <<'RUNTIME_PROBES'
amass_status=0
amass -version >/tmp/amass-version.txt 2>&1 || amass_status=$?
test "$amass_status" -eq 0
grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+' /tmp/amass-version.txt

masscan_status=0
masscan --version >/tmp/masscan-version.txt 2>&1 || masscan_status=$?
test "$masscan_status" -eq 1
grep -q 'Masscan version' /tmp/masscan-version.txt

smbmap_status=0
smbmap --help >/tmp/smbmap-help.txt 2>&1 || smbmap_status=$?
test "$smbmap_status" -eq 1
grep -q 'usage: smbmap' /tmp/smbmap-help.txt
ROPgadget --help >/tmp/ropgadget-help.txt
grep -q 'usage: ROPgadget' /tmp/ropgadget-help.txt
scout --help >/tmp/scout-help.txt
grep -q 'The provider you want to run scout against' /tmp/scout-help.txt
kube-hunter --help >/tmp/kube-hunter-help.txt
grep -q 'hunt for security weaknesses' /tmp/kube-hunter-help.txt

cloudmapper_status=0
cloudmapper >/tmp/cloudmapper-help.txt 2>&1 || cloudmapper_status=$?
test "$cloudmapper_status" -eq 255
grep -q 'CloudMapper 2.10.0' /tmp/cloudmapper-help.txt
RUNTIME_PROBES

docker run --rm --platform "$platform" --network none \
  --ulimit nofile=1024:1024 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=67108864 \
  --tmpfs /workspace:rw,nosuid,nodev,mode=1777,size=67108864 \
  --env HOME=/workspace \
  --env XDG_CONFIG_HOME=/workspace/.config \
  --env XDG_CACHE_HOME=/workspace/.cache \
  --env PATH=/opt/tools-venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --entrypoint /bin/bash "$image" -ceu "$(cat "$probe_script")"

printf 'verify-agent-toolset: coverage + image probes ok\n'
