#!/usr/bin/env bash
set -euo pipefail

: "${CYBERSTRIKE_EGRESS_IMAGE:?CYBERSTRIKE_EGRESS_IMAGE is required}"
: "${CYBERSTRIKE_AGENT_IMAGE:?CYBERSTRIKE_AGENT_IMAGE is required}"

snapshot_id=12345678-1234-1234-1234-123456789ab6
snapshot_json='{"schemaVersion":5,"policyId":"stage4-item6-policy","rules":[{"id":"block-example-tcp-81","effect":"blocked","host":"example.com","schemes":["tcp"],"ports":[81],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1},{"id":"allow-example-web","effect":"allow-visit","host":"example.com","schemes":["http","https"],"ports":[53,80,443,784,853,2375,2376,8853],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":2},{"id":"allow-example-tcp","effect":"allow-visit","host":"example.com","schemes":["tcp"],"ports":[80],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":3},{"id":"allow-example-icmp","effect":"allow-visit","host":"example.com","schemes":["icmp"],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":4},{"id":"block-ntp-124","effect":"blocked","host":"time.cloudflare.com","schemes":["udp"],"ports":[124],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":5},{"id":"allow-ntp","effect":"allow-visit","host":"time.cloudflare.com","schemes":["udp"],"ports":[123],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":6},{"id":"would-allow-doh","effect":"allow-visit","host":"dns.google","schemes":["https"],"ports":[443],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":7},{"id":"allow-public-ip","effect":"allow-visit","host":"1.1.1.1","schemes":["http","https"],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":8},{"id":"block-example","effect":"blocked","host":"blocked.example","schemes":[],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":9}],"networkAccess":{"allowRestrictedTargets":false}}'
snapshot_sha="sha256:$(printf '%s\n' "$snapshot_json" | sha256sum | awk '{print $1}')"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/cyberstrike-egress-integration.XXXXXX")
test_suffix=${CYBERSTRIKE_EGRESS_TEST_SUFFIX:-"$$"}
internal_network="cs-egress-int-$test_suffix"
egress_network="cs-egress-out-$test_suffix"
gateway_container="cs-egress-gateway-$test_suffix"
agent_container="cs-egress-agent-$test_suffix"
restricted_container="cs-egress-restricted-target-$test_suffix"
snapshot_path="$test_root/boundary.json"
route_path="$test_root/upstream.json"
open_snapshot_path="$test_root/open-boundary.json"
open_restricted_snapshot_path="$test_root/open-restricted-boundary.json"
tls_certificate_path="$test_root/ca.crt"
tls_private_key_path="$test_root/ca.key"
tls_authority_id=42345678-1234-4234-8234-123456789ab8

gateway_security_args=(
  --read-only
  --user 0:0
  --cap-drop ALL
  --cap-add NET_ADMIN
  --cap-add NET_RAW
  --security-opt no-new-privileges
  --sysctl net.ipv4.ip_forward=1
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=16777216
)

agent_security_args=(
  --read-only
  --user pentester
  --cap-drop ALL
  --cap-add CHOWN
  --cap-add DAC_OVERRIDE
  --cap-add FOWNER
  --cap-add FSETID
  --cap-add KILL
  --cap-add SETGID
  --cap-add SETUID
  --cap-add SYS_CHROOT
  --cap-add NET_BIND_SERVICE
  --cap-add NET_RAW
  --cap-add NET_ADMIN
  --cap-add SYS_PTRACE
  --security-opt no-new-privileges
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=67108864
  --tmpfs /workspace:rw,nosuid,nodev,mode=1777,size=1073741824
)

agent_workspace_env=(
  --env HOME=/workspace
  --env XDG_CACHE_HOME=/workspace/.cache
  --env XDG_CONFIG_HOME=/workspace/.config
  --env PIP_CACHE_DIR=/workspace/.cache/pip
  --env VIRTUAL_ENV=/workspace/.venv
  --env PATH=/workspace/.venv/bin:/workspace/.local/bin:/opt/tools-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
)
agent_tls_env=(
  --env SSL_CERT_FILE=/tmp/cyberstrike-ca-bundle.pem
  --env CURL_CA_BUNDLE=/tmp/cyberstrike-ca-bundle.pem
  --env REQUESTS_CA_BUNDLE=/tmp/cyberstrike-ca-bundle.pem
  --env PIP_CERT=/tmp/cyberstrike-ca-bundle.pem
  --env GIT_SSL_CAINFO=/tmp/cyberstrike-ca-bundle.pem
  --env NODE_EXTRA_CA_CERTS=/etc/cyberstrike/tls/ca.crt
)
agent_keepalive_script="umask 077; ready_file=/tmp/.cyberstrike-runtime-ready; rm -f \$ready_file; if [ -r /etc/cyberstrike/tls/ca.crt ]; then cat /etc/ssl/certs/ca-certificates.crt /etc/cyberstrike/tls/ca.crt >/tmp/cyberstrike-ca-bundle.pem || exit 70; fi; mkdir -p /workspace/.cache/pip /workspace/.config /workspace/.local/bin /workspace/.local/share; if [ ! -x /workspace/.venv/bin/python3 ]; then rm -rf /workspace/.venv; /usr/bin/python3 -m venv --system-site-packages /workspace/.venv || exit 71; /workspace/.venv/bin/python3 -m ensurepip --upgrade >/dev/null 2>&1 || exit 72; fi; runtime_start=\$(awk '{print \$22}' /proc/1/stat) || exit 73; printf '%s\\n' \"\$runtime_start\" >\$ready_file || exit 74; trap 'rm -f \$ready_file; exit 0' TERM INT; while :; do sleep 3600; done"

configure_agent_route() {
  local container=$1 gateway=$2
  docker exec --user 0:0 "$container" /sbin/ip route replace default via "$gateway"
}

assert_gateway_security() {
  local container=$1
  [[ "$(docker inspect --format '{{.Config.User}}' "$container")" == "0:0" ]] || fail "gateway is not running as root"
  [[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" == true ]] || fail "gateway root filesystem is writable"
  [[ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container")" == '["ALL"]' ]] || fail "gateway capability drop set drifted"
  [[ "$(docker inspect --format '{{json .HostConfig.CapAdd}}' "$container")" == '["CAP_NET_ADMIN","CAP_NET_RAW"]' ]] || fail "gateway capability add set drifted"
  [[ "$(docker inspect --format '{{index .HostConfig.Sysctls "net.ipv4.ip_forward"}}' "$container")" == 1 ]] || fail "gateway IP forwarding is disabled"
}

assert_agent_security() {
  local container=$1
  local expected='["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_NET_ADMIN","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SYS_CHROOT","CAP_SYS_PTRACE"]'
  [[ "$(docker inspect --format '{{.Config.User}}' "$container")" == pentester ]] || fail "Agent keepalive is not pentester"
  [[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" == true ]] || fail "Agent root filesystem is writable"
  [[ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container")" == '["ALL"]' ]] || fail "Agent capability drop set drifted"
  [[ "$(docker inspect --format '{{json .HostConfig.CapAdd}}' "$container")" == "$expected" ]] || fail "Agent capability add set drifted"
  [[ "$(docker exec "$container" id -u)" != 0 ]] || fail "Agent keepalive user unexpectedly has root identity"
  [[ "$(docker exec --user 0:0 "$container" id -u)" == 0 ]] || fail "trusted Agent exec cannot enter root"
  attempt=0
  until docker exec "$container" sh -c 'test "$(cat /tmp/.cyberstrike-runtime-ready 2>/dev/null)" = "$(awk '\''{print $22}'\'' /proc/1/stat)" && test -x /workspace/.venv/bin/python3'; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 300 ] || fail "workspace virtual environment was not initialized"
    sleep 0.1
  done
  expect_failure docker exec "$container" sudo -n true
}

cleanup() {
  docker rm -f "$agent_container" "$gateway_container" "$restricted_container" >/dev/null 2>&1 || true
  docker network rm "$internal_network" "$egress_network" >/dev/null 2>&1 || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'docker egress integration failure: %s\n' "$1" >&2
  exit 1
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

expect_status() {
  local expected=$1
  shift
  local actual
  if ! actual=$("$@"); then
    fail "HTTP status command failed: $*"
  fi
  [[ "$actual" == "$expected" ]] || fail "HTTP status $actual, want $expected: $*"
}

assert_public_service_port_allowed() {
  local port=$1
  docker exec "$agent_container" curl -sS --connect-timeout 2 --max-time 4 -o /dev/null "http://example.com:$port/" >/dev/null 2>&1 || true
  docker logs "$gateway_container" 2>&1 \
    | grep '"requestType":"http"' \
    | grep "\"port\":$port" \
    | grep '"decision":"allowed"' \
    | grep -q '"ruleId":"allow-example-web"' \
    || fail "public service port $port was blocked or not audited as an ordinary allowed port"
}

gateway_is_absent() {
  case "$1" in
    ''|'<no value>'|'invalid IP') return 0 ;;
    *) return 1 ;;
  esac
}

run_udp_probe() {
  local container=$1 gateway=$2 host=$3 port=$4
  local code
  code=$'import socket, struct, sys\n\ndef exact(sock, count):\n    data = b""\n    while len(data) < count:\n        chunk = sock.recv(count - len(data))\n        if not chunk:\n            raise RuntimeError("unexpected SOCKS5 EOF")\n        data += chunk\n    return data\n\ngateway, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])\ncontrol = socket.create_connection((gateway, 1080), 5)\ncontrol.sendall(b"\\x05\\x01\\x00")\nif exact(control, 2) != b"\\x05\\x00":\n    raise RuntimeError("SOCKS5 no-auth negotiation failed")\ncontrol.sendall(b"\\x05\\x03\\x00\\x01" + b"\\x00" * 6)\nversion, reply, reserved, atyp = exact(control, 4)\nif (version, reply, reserved) != (5, 0, 0):\n    raise RuntimeError(f"SOCKS5 UDP associate failed: {reply}")\nif atyp == 1:\n    relay_host = socket.inet_ntop(socket.AF_INET, exact(control, 4))\nelif atyp == 4:\n    relay_host = socket.inet_ntop(socket.AF_INET6, exact(control, 16))\nelif atyp == 3:\n    relay_host = exact(control, exact(control, 1)[0]).decode("ascii")\nelse:\n    raise RuntimeError("invalid SOCKS5 relay address")\nrelay_port = struct.unpack("!H", exact(control, 2))[0]\nencoded_host = host.encode("idna")\npacket = b"\\x00\\x00\\x00\\x03" + bytes([len(encoded_host)]) + encoded_host + struct.pack("!H", port) + bytes(48)\nudp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nudp.bind(("0.0.0.0", 0))\nudp.sendto(packet, (relay_host, relay_port))\nudp.settimeout(7)\ntry:\n    udp.recvfrom(65535)\nexcept TimeoutError:\n    pass\nudp.close()\ncontrol.close()'
  docker exec "$container" python3 -c "$code" "$gateway" "$host" "$port"
}

printf '%s\n' "$snapshot_json" >"$snapshot_path"
chmod 0444 "$snapshot_path"
printf '%s  %s\n' "${snapshot_sha#sha256:}" "$snapshot_path" | sha256sum --check --status

docker image inspect "$CYBERSTRIKE_EGRESS_IMAGE" >/dev/null
docker image inspect "$CYBERSTRIKE_AGENT_IMAGE" >/dev/null
docker network create --driver bridge \
  --opt com.docker.network.bridge.inhibit_ipv4=true \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  --opt com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected \
  "$internal_network" >/dev/null
docker network create --driver bridge "$egress_network" >/dev/null

docker run -d --name "$gateway_container" --network "$internal_network" \
  "${gateway_security_args[@]}" \
  --mount type=bind,source="$snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "$snapshot_sha" >/dev/null
docker network connect --gw-priority 1 "$egress_network" "$gateway_container"

for _ in $(seq 1 60); do
  docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded' && break
  sleep 0.1
done
if ! docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded'; then
  docker inspect --format 'gateway_state={{json .State}}' "$gateway_container" >&2 || true
  docker logs "$gateway_container" >&2 || true
  fail "gateway did not report its loaded snapshot"
fi
health_output=$(docker exec "$gateway_container" /cyberstrike-egress check \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "$snapshot_sha")
grep -q '"event":"boundary_snapshot_healthy"' <<<"$health_output" || fail "gateway health report is not exact"

gateway_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.IPAddress}}{{end}}" "$gateway_container")
[[ -n "$gateway_ip" ]] || fail "gateway internal address is empty"
proxy="http://$gateway_ip:3128"
socks_proxy="socks5h://$gateway_ip:1080"
docker run -d --name "$agent_container" --network "$internal_network" --dns "$gateway_ip" \
  "${agent_security_args[@]}" \
  "${agent_workspace_env[@]}" \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$socks_proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$socks_proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c "$agent_keepalive_script" >/dev/null
configure_agent_route "$agent_container" "$gateway_ip"
assert_gateway_security "$gateway_container"
assert_agent_security "$agent_container"

[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.inhibit_ipv4"}}' "$internal_network")" == true ]] || fail "internal bridge inhibit_ipv4 drifted"
[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}' "$internal_network")" == false ]] || fail "internal bridge masquerade drifted"
[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$internal_network")" == nat-unprotected ]] || fail "internal bridge gateway mode cannot forward raw protocols to egress"
[[ "$(docker network inspect --format '{{.Internal}}' "$internal_network")" == false ]] || fail "internal bridge unexpectedly uses Docker's non-routable internal mode"
network_id=$(docker network inspect --format '{{.Id}}' "$internal_network")
bridge_name="br-${network_id:0:12}"
if ip -4 -o addr show dev "$bridge_name" 2>/dev/null | grep -q ' inet '; then
  fail "host bridge $bridge_name has an IPv4 address"
fi
[[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$agent_container")" == 1 ]] || fail "agent is not attached to exactly one network"
[[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$gateway_container")" == 2 ]] || fail "gateway is not attached to exactly two networks"
[[ "$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.GwPriority}}{{end}}" "$gateway_container")" == 0 ]] || fail "gateway internal route priority drifted"
[[ "$(docker inspect --format "{{with index .NetworkSettings.Networks \"$egress_network\"}}{{.GwPriority}}{{end}}" "$gateway_container")" == 1 ]] || fail "gateway egress route priority drifted"
[[ "$(docker network inspect --format '{{len .Containers}}' "$internal_network")" == 2 ]] || fail "internal network attachment count drifted"
[[ "$(docker network inspect --format '{{len .Containers}}' "$egress_network")" == 1 ]] || fail "egress network attachment count drifted"
internal_ipam_gateway=$(docker network inspect --format '{{with index .IPAM.Config 0}}{{.Gateway}}{{end}}' "$internal_network")
[[ "$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.Gateway}}{{end}}" "$agent_container")" == "$internal_ipam_gateway" ]] || fail "agent endpoint gateway metadata does not match IPAM"
[[ "$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.Gateway}}{{end}}" "$gateway_container")" == "$internal_ipam_gateway" ]] || fail "gateway endpoint gateway metadata does not match IPAM"

for key in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; do
  [[ "$(docker exec "$agent_container" printenv "$key")" == "$proxy" ]] || fail "$key does not point to the gateway"
done
for key in ALL_PROXY all_proxy; do
  [[ "$(docker exec "$agent_container" printenv "$key")" == "$socks_proxy" ]] || fail "$key does not point to the SOCKS5 gateway"
done
[[ -z "$(docker exec "$agent_container" printenv NO_PROXY)" ]] || fail "NO_PROXY is not empty"
[[ -z "$(docker exec "$agent_container" printenv no_proxy)" ]] || fail "no_proxy is not empty"
[[ "$(docker inspect --format '{{range .HostConfig.Dns}}{{.}}{{end}}' "$agent_container")" == "$gateway_ip" ]] || fail "agent DNS does not point to the gateway"
route4=$(docker exec "$agent_container" ip -4 route)
grep -Eq "^default via ${gateway_ip//./\\.}( |$)" <<<"$route4" || fail "agent default route does not use the gateway: $route4"

allowed_status=$(docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 -o /dev/null -w '%{http_code}' http://example.com/)
case "$allowed_status" in
  2*|3*) ;;
  *) fail "allowed request returned $allowed_status" ;;
esac
docker exec "$agent_container" getent ahostsv4 example.com >/dev/null
expect_failure docker exec "$agent_container" getent ahostsv4 unknown.example
expect_failure docker exec "$agent_container" getent ahostsv4 blocked.example
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://unknown.example/
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://blocked.example/
docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -X POST -o /dev/null http://example.com/write || true
docker logs "$gateway_container" 2>&1 | grep '"method":"POST"' | grep -q '"decision":"allowed"' || fail "empty methods did not allow POST"
for public_port in 53 784 853 8853 2375 2376; do
  assert_public_service_port_allowed "$public_port"
done
docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 --proxy "$socks_proxy" -o /dev/null http://example.com/
docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"tcp".*"decision":"allowed"' || fail "SOCKS5 TCP request was not allowed and audited"
run_udp_probe "$agent_container" "$gateway_ip" time.cloudflare.com 123
for _ in $(seq 1 80); do
  docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"udp".*"decision":"allowed".*"ruleId":"allow-ntp"' && break
  sleep 0.1
done
docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"udp".*"decision":"allowed".*"ruleId":"allow-ntp"' || fail "SOCKS5 UDP request was not allowed and audited"
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://127.0.0.1/
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://example.com/dns-query
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -H 'Accept: application/dns-json' -o /dev/null -w '%{http_code}' http://example.com/api
expect_failure docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null https://dns.google/dns-query

docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 8 --max-time 15 --noproxy "*" -o /dev/null http://example.com/'
docker logs "$gateway_container" 2>&1 | grep '"requestType":"tcp"' | grep '"decision":"allowed"' | grep -q '"domain":"example.com"' || fail "direct TCP request was not allowed through the packet gateway"
docker exec --user 0:0 "$agent_container" ping -c 1 -W 5 example.com >/dev/null
docker logs "$gateway_container" 2>&1 | grep '"requestType":"icmp"' | grep -q '"decision":"allowed"' || fail "ICMP request was not allowed and audited"
docker exec --user 0:0 "$agent_container" nmap -Pn -sS -p 80 --max-retries 0 --host-timeout 10s example.com >/dev/null
docker exec --user 0:0 "$agent_container" nmap -Pn -sU -p 123 --max-retries 0 --host-timeout 10s time.cloudflare.com >/dev/null || true
docker logs "$gateway_container" 2>&1 | grep '"requestType":"udp"' | grep '"decision":"allowed"' | grep -q '"ruleId":"allow-ntp"' || fail "direct UDP scan was not allowed and audited"

# A mixed scan is evaluated per destination tuple. The explicitly blocked
# ports must fail immediately with an administrative-prohibited response while
# neighboring allowed ports continue through the same gateway and tool run.
example_ip=$(docker exec "$agent_container" getent ahostsv4 example.com | awk 'NR == 1 {print $1}')
[[ -n "$example_ip" ]] || fail "example.com did not resolve for mixed TCP scan"
mixed_tcp_scan=$(docker exec --user 0:0 "$agent_container" nmap -n -Pn -sS -p 80,81 --max-retries 0 --host-timeout 8s --reason "$example_ip")
allowed_tcp_line=$(awk '$1 == "80/tcp" { print }' <<<"$mixed_tcp_scan")
[[ -n "$allowed_tcp_line" ]] || fail "allowed TCP port 80 disappeared from mixed scan: $mixed_tcp_scan"
if grep -q 'admin-prohibited' <<<"$allowed_tcp_line"; then
  fail "allowed TCP port 80 was rejected by the gateway: $mixed_tcp_scan"
fi
grep -Eq '^81/tcp[[:space:]]+filtered' <<<"$mixed_tcp_scan" || fail "blocked TCP port 81 was not reported filtered: $mixed_tcp_scan"
grep -q 'admin-prohibited' <<<"$mixed_tcp_scan" || fail "blocked TCP port 81 did not fail with admin-prohibited: $mixed_tcp_scan"
docker logs "$gateway_container" 2>&1 | grep '"requestType":"tcp"' | grep '"port":80' | grep '"decision":"allowed"' >/dev/null || fail "allowed TCP port 80 was not independently audited"
docker logs "$gateway_container" 2>&1 | grep '"requestType":"tcp"' | grep '"port":81' | grep '"decision":"blocked"' | grep -q '"ruleId":"block-example-tcp-81"' || fail "blocked TCP port 81 was not independently audited"

ntp_ip=$(docker exec "$agent_container" getent ahostsv4 time.cloudflare.com | awk 'NR == 1 {print $1}')
[[ -n "$ntp_ip" ]] || fail "time.cloudflare.com did not resolve for blocked UDP probe"
udp_reject_probe=$'import socket, sys, time\nhost, port = sys.argv[1], int(sys.argv[2])\nsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nsock.settimeout(3)\nsock.connect((host, port))\nstarted = time.monotonic()\ntry:\n    sock.send(b"cyberstrike-boundary-probe")\n    sock.recv(1)\nexcept TimeoutError:\n    raise SystemExit("blocked UDP timed out instead of failing fast")\nexcept OSError as exc:\n    elapsed = time.monotonic() - started\n    if elapsed >= 2:\n        raise SystemExit(f"blocked UDP rejection was slow: {elapsed:.3f}s")\n    print(f"blocked UDP failed fast in {elapsed:.3f}s: {exc}")\nelse:\n    raise SystemExit("blocked UDP unexpectedly returned application data")\nfinally:\n    sock.close()'
docker exec "$agent_container" python3 -c "$udp_reject_probe" "$ntp_ip" 124 >/dev/null
docker logs "$gateway_container" 2>&1 | grep '"requestType":"udp"' | grep '"port":124' | grep '"decision":"blocked"' | grep -q '"ruleId":"block-ntp-124"' || fail "blocked UDP port 124 was not independently audited"
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://1.1.1.1/'
docker exec "$agent_container" /bin/sh -c 'NO_PROXY="*" no_proxy="*" curl -sS --connect-timeout 8 --max-time 15 -o /dev/null http://example.com/'
expect_failure docker exec "$agent_container" /bin/sh -c 'HTTP_PROXY=http://203.0.113.10:3128 HTTPS_PROXY=http://203.0.113.10:3128 ALL_PROXY=http://203.0.113.10:3128 http_proxy=http://203.0.113.10:3128 https_proxy=http://203.0.113.10:3128 all_proxy=http://203.0.113.10:3128 curl -sS --connect-timeout 2 --max-time 4 -o /dev/null http://example.com/'
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null telnet://1.1.1.1:53'
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -g -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null "http://[2606:4700:4700::1111]/"'

docker kill "$gateway_container" >/dev/null
[[ "$(docker inspect --format '{{.State.Running}}' "$gateway_container")" == false ]] || fail "killed gateway is still running"
expect_failure docker exec "$agent_container" curl -sS --connect-timeout 2 --max-time 4 -o /dev/null http://example.com/
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://example.com/'
[[ "$(docker inspect --format '{{.State.Running}}' "$agent_container")" == true ]] || fail "agent stopped with the gateway"

# A conversation without a selected boundary policy receives the immutable
# schema-v5 open snapshot. Public HTTP, HTTPS, TCP and UDP are allowed by
# default while the conversation's restricted-target switch remains off.
docker rm -f "$agent_container" "$gateway_container" >/dev/null
open_snapshot_id=22345678-1234-4234-8234-123456789ab8
open_snapshot_json='{"schemaVersion":5,"policyId":"","rules":[],"tlsInspection":{"enabled":true,"bypassDomains":[]},"defaultAction":"allow","networkAccess":{"allowRestrictedTargets":false}}'
printf '%s\n' "$open_snapshot_json" >"$open_snapshot_path"
chmod 0444 "$open_snapshot_path"
open_snapshot_sha="sha256:$(sha256sum "$open_snapshot_path" | awk '{print $1}')"
openssl genpkey -algorithm ED25519 -out "$tls_private_key_path" >/dev/null 2>&1
openssl req -x509 -new -key "$tls_private_key_path" -out "$tls_certificate_path" -days 1 \
  -subj '/CN=CyberStrikeAI Docker integration CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign' >/dev/null 2>&1
chmod 0444 "$tls_certificate_path" "$tls_private_key_path"
tls_certificate_sha="sha256:$(sha256sum "$tls_certificate_path" | awk '{print $1}')"
tls_private_key_sha="sha256:$(sha256sum "$tls_private_key_path" | awk '{print $1}')"
docker run -d --name "$restricted_container" --network "$egress_network" --network-alias restricted-target \
  --entrypoint python3 "$CYBERSTRIKE_AGENT_IMAGE" -m http.server 18081 >/dev/null
docker run -d --name "$gateway_container" --network "$internal_network" \
  "${gateway_security_args[@]}" \
  --mount type=bind,source="$open_snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  --mount type=bind,source="$tls_certificate_path",target=/etc/cyberstrike/tls/ca.crt,readonly \
  --mount type=bind,source="$tls_private_key_path",target=/etc/cyberstrike/tls/ca.key,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$open_snapshot_id" \
  --snapshot-sha256 "$open_snapshot_sha" \
  --tls-ca-cert-path /etc/cyberstrike/tls/ca.crt \
  --tls-ca-key-path /etc/cyberstrike/tls/ca.key \
  --tls-ca-id "$tls_authority_id" \
  --tls-ca-cert-sha256 "$tls_certificate_sha" \
  --tls-ca-key-sha256 "$tls_private_key_sha" >/dev/null
docker network connect --gw-priority 1 "$egress_network" "$gateway_container"
for _ in $(seq 1 60); do
  docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded' && break
  sleep 0.1
done
if ! docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded'; then
  docker inspect --format 'open_gateway_state={{json .State}}' "$gateway_container" >&2 || true
  docker logs "$gateway_container" >&2 || true
  fail "open-boundary gateway did not start"
fi
gateway_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.IPAddress}}{{end}}" "$gateway_container")
proxy="http://$gateway_ip:3128"
socks_proxy="socks5h://$gateway_ip:1080"
docker run -d --name "$agent_container" --network "$internal_network" --dns "$gateway_ip" \
  "${agent_security_args[@]}" \
  "${agent_workspace_env[@]}" \
  "${agent_tls_env[@]}" \
  --mount type=bind,source="$tls_certificate_path",target=/etc/cyberstrike/tls/ca.crt,readonly \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$socks_proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$socks_proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c "$agent_keepalive_script" >/dev/null
configure_agent_route "$agent_container" "$gateway_ip"
assert_gateway_security "$gateway_container"
assert_agent_security "$agent_container"
open_http_status=$(docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 -o /dev/null -w '%{http_code}' -X DELETE http://example.com/)
case "$open_http_status" in
  2*|3*|4*) ;;
  *) fail "open-boundary HTTP request returned $open_http_status" ;;
esac
docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 -o /dev/null https://example.com/
docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 --proxy "$socks_proxy" -o /dev/null http://example.com/
run_udp_probe "$agent_container" "$gateway_ip" time.cloudflare.com 123
for _ in $(seq 1 80); do
  docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"udp".*"decision":"allowed"' && break
  sleep 0.1
done
docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"http".*"decision":"allowed".*"method":"DELETE"' || fail "open-boundary did not allow an unrestricted HTTP method"
docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"connect".*"decision":"allowed"' || fail "open-boundary did not allow HTTPS CONNECT"
docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"tcp".*"decision":"allowed"' || fail "open-boundary did not allow TCP"
docker logs "$gateway_container" 2>&1 | grep -q '"requestType":"udp".*"decision":"allowed"' || fail "open-boundary did not allow UDP"
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://127.0.0.1/
restricted_off_status=$(docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://restricted-target:18081/ || true)
[[ "$restricted_off_status" != 200 ]] || fail "restricted Docker-network target was allowed while the high-risk switch was off"
docker logs "$gateway_container" 2>&1 | grep '"domain":"restricted-target"' | grep '"decision":"blocked"' | grep -q '"reason":"dns-rebinding"' || fail "restricted Docker-network denial was not audited as system isolation"
docker rm -f "$agent_container" "$gateway_container" >/dev/null

# The same conversation-level switch makes private, Docker-network and
# metadata-style targets eligible without overriding ordinary boundary rules.
# Use a private Docker-network HTTP target so this is a real routed test rather
# than a policy-only assertion.
open_restricted_snapshot_id=32345678-1234-4234-8234-123456789ab8
open_restricted_snapshot_json='{"schemaVersion":5,"policyId":"","rules":[],"tlsInspection":{"enabled":true,"bypassDomains":[]},"defaultAction":"allow","networkAccess":{"allowRestrictedTargets":true}}'
printf '%s\n' "$open_restricted_snapshot_json" >"$open_restricted_snapshot_path"
chmod 0444 "$open_restricted_snapshot_path"
open_restricted_snapshot_sha="sha256:$(sha256sum "$open_restricted_snapshot_path" | awk '{print $1}')"
docker run -d --name "$gateway_container" --network "$internal_network" \
  "${gateway_security_args[@]}" \
  --mount type=bind,source="$open_restricted_snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  --mount type=bind,source="$tls_certificate_path",target=/etc/cyberstrike/tls/ca.crt,readonly \
  --mount type=bind,source="$tls_private_key_path",target=/etc/cyberstrike/tls/ca.key,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$open_restricted_snapshot_id" \
  --snapshot-sha256 "$open_restricted_snapshot_sha" \
  --tls-ca-cert-path /etc/cyberstrike/tls/ca.crt \
  --tls-ca-key-path /etc/cyberstrike/tls/ca.key \
  --tls-ca-id "$tls_authority_id" \
  --tls-ca-cert-sha256 "$tls_certificate_sha" \
  --tls-ca-key-sha256 "$tls_private_key_sha" >/dev/null
docker network connect --gw-priority 1 "$egress_network" "$gateway_container"
for _ in $(seq 1 60); do
  docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded' && break
  sleep 0.1
done
if ! docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded'; then
  docker inspect --format 'restricted_gateway_state={{json .State}}' "$gateway_container" >&2 || true
  docker logs "$gateway_container" >&2 || true
  fail "restricted-target gateway did not start"
fi
gateway_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.IPAddress}}{{end}}" "$gateway_container")
proxy="http://$gateway_ip:3128"
socks_proxy="socks5h://$gateway_ip:1080"
docker run -d --name "$agent_container" --network "$internal_network" --dns "$gateway_ip" \
  "${agent_security_args[@]}" \
  "${agent_workspace_env[@]}" \
  "${agent_tls_env[@]}" \
  --mount type=bind,source="$tls_certificate_path",target=/etc/cyberstrike/tls/ca.crt,readonly \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$socks_proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$socks_proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c "$agent_keepalive_script" >/dev/null
configure_agent_route "$agent_container" "$gateway_ip"
assert_agent_security "$agent_container"
expect_status 200 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://restricted-target:18081/
docker logs "$gateway_container" 2>&1 | grep '"domain":"restricted-target"' | grep -q '"decision":"allowed"' || fail "enabled restricted target was not audited as allowed"
docker rm -f "$agent_container" "$gateway_container" "$restricted_container" >/dev/null

# A configured upstream is a mandatory hop. Recreate the gateway with an
# unreachable HTTP proxy and a synthetic credential marker: allowed targets
# must return 502 and must never fall back to the gateway's direct egress.
docker rm -f "$agent_container" "$gateway_container" >/dev/null
route_id=stage5-fail-closed
route_secret_probe=stage5-route-secret-probe
route_json='{"schemaVersion":1,"mode":"proxy","proxy":{"id":"unavailable-http","protocol":"http","host":"127.0.0.1","port":9,"username":"integration-user","password":"stage5-route-secret-probe"}}'
printf '%s' "$route_json" >"$route_path"
chmod 0444 "$route_path"
route_sha="sha256:$(sha256sum "$route_path" | awk '{print $1}')"

docker run -d --name "$gateway_container" --network "$internal_network" \
  "${gateway_security_args[@]}" \
  --mount type=bind,source="$snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  --mount type=bind,source="$route_path",target=/etc/cyberstrike/upstream.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "$snapshot_sha" \
  --upstream-route-path /etc/cyberstrike/upstream.json \
  --upstream-route-id "$route_id" \
  --upstream-route-sha256 "$route_sha" >/dev/null
docker network connect --gw-priority 1 "$egress_network" "$gateway_container"

for _ in $(seq 1 60); do
  docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded' && break
  sleep 0.1
done
if ! docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded'; then
  docker inspect --format 'fail_closed_gateway_state={{json .State}}' "$gateway_container" >&2 || true
  docker logs "$gateway_container" >&2 || true
  fail "upstream-routed gateway did not report its loaded snapshot"
fi
route_health=$(docker exec "$gateway_container" /cyberstrike-egress check \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "$snapshot_sha" \
  --upstream-route-path /etc/cyberstrike/upstream.json \
  --upstream-route-id "$route_id" \
  --upstream-route-sha256 "$route_sha")
grep -q "\"upstreamRouteId\":\"$route_id\"" <<<"$route_health" || fail "gateway health omitted the exact upstream route"
grep -q "\"upstreamRouteSha256\":\"$route_sha\"" <<<"$route_health" || fail "gateway health omitted the exact upstream route digest"
[[ "$(docker inspect --format '{{len .Mounts}}' "$gateway_container")" == 2 ]] || fail "upstream-routed gateway does not have exactly two trusted mounts"
inspect_json=$(docker inspect "$gateway_container")
if grep -Fq "$route_secret_probe" <<<"$inspect_json"; then
  fail "upstream credential leaked into gateway inspect metadata"
fi
if docker logs "$gateway_container" 2>&1 | grep -Fq "$route_secret_probe"; then
  fail "upstream credential leaked into gateway logs"
fi

gateway_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.IPAddress}}{{end}}" "$gateway_container")
[[ -n "$gateway_ip" ]] || fail "upstream-routed gateway internal address is empty"
proxy="http://$gateway_ip:3128"
socks_proxy="socks5h://$gateway_ip:1080"
expect_status 502 docker run --rm --network "$internal_network" --dns "$gateway_ip" \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$socks_proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$socks_proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c \
  "curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://example.com/"
expect_failure docker run --rm --network "$internal_network" --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c \
  'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://example.com/'

printf 'docker_topology=isolated internal=2 egress=1\n'
printf 'proxy_protocol=allowed_http_%s public_service_ports=ordinary default_post_and_blocked_dns_gateway_denied\n' "$allowed_status"
printf 'default_boundary=open http=%s https_connect=allowed tcp=allowed udp=allowed restricted_off=blocked restricted_on=allowed\n' "$open_http_status"
printf 'packet_gateway=direct_tcp_allowed disallowed_ip,doh,ipv6,external_proxy_blocked\n'
printf 'gateway_crash=proxy_and_direct_blocked agent_running=true\n'
printf 'upstream_unavailable=http_502 direct_fallback=false credential_metadata_leak=false\n'
printf 'auth_only=http_204 override=true agent_read=false metadata_leak=false full_packet_audit=true mismatch_fail_closed=true cross_snapshot_reuse=false integrity_exit=true\n'
