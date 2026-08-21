#!/usr/bin/env bash
set -euo pipefail

: "${CYBERSTRIKE_EGRESS_IMAGE:?CYBERSTRIKE_EGRESS_IMAGE is required}"
: "${CYBERSTRIKE_AGENT_IMAGE:?CYBERSTRIKE_AGENT_IMAGE is required}"

snapshot_id=12345678-1234-1234-1234-123456789ab6
snapshot_sha=sha256:4ea3cd50f776125334f957864828585d2402811d0b743fdcca742f90b130b06f
snapshot_json='{"schemaVersion":1,"policyId":"stage4-item6-policy","rules":[{"id":"allow-example","effect":"allow-visit","host":"example.com","schemes":["http","https"],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1},{"id":"would-allow-doh","effect":"allow-visit","host":"dns.google","schemes":["https"],"ports":[443],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":2},{"id":"allow-public-ip","effect":"allow-visit","host":"1.1.1.1","schemes":["http","https"],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":3}]}'
test_root=$(mktemp -d "${TMPDIR:-/tmp}/cyberstrike-egress-integration.XXXXXX")
test_suffix=${CYBERSTRIKE_EGRESS_TEST_SUFFIX:-"$$"}
internal_network="cs-egress-int-$test_suffix"
egress_network="cs-egress-out-$test_suffix"
gateway_container="cs-egress-gateway-$test_suffix"
agent_container="cs-egress-agent-$test_suffix"
capture_container="cs-egress-auth-capture-$test_suffix"
snapshot_path="$test_root/boundary.json"
route_path="$test_root/upstream.json"
auth_route_path="$test_root/auth-upstream.json"
auth_snapshot_path="$test_root/auth-boundary.json"
auth_profiles_path="$test_root/auth-profiles.json"
mismatch_profiles_path="$test_root/auth-profiles-mismatch.json"

cleanup() {
  docker rm -f "$agent_container" "$gateway_container" "$capture_container" >/dev/null 2>&1 || true
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

gateway_is_absent() {
  case "$1" in
    ''|'<no value>'|'invalid IP') return 0 ;;
    *) return 1 ;;
  esac
}

printf '%s\n' "$snapshot_json" >"$snapshot_path"
chmod 0444 "$snapshot_path"
printf '%s  %s\n' "${snapshot_sha#sha256:}" "$snapshot_path" | sha256sum --check --status

docker image inspect "$CYBERSTRIKE_EGRESS_IMAGE" >/dev/null
docker image inspect "$CYBERSTRIKE_AGENT_IMAGE" >/dev/null
docker network create --driver bridge --internal --opt com.docker.network.bridge.inhibit_ipv4=true "$internal_network" >/dev/null
docker network create --driver bridge "$egress_network" >/dev/null

docker run -d --name "$gateway_container" --network "$internal_network" \
  --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,source="$snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "$snapshot_sha" >/dev/null
docker network connect "$egress_network" "$gateway_container"

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
docker run -d --name "$agent_container" --network "$internal_network" --dns "$gateway_ip" \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c "trap 'exit 0' TERM INT; while :; do sleep 3600; done" >/dev/null

[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.inhibit_ipv4"}}' "$internal_network")" == true ]] || fail "internal bridge inhibit_ipv4 drifted"
internal_gateway=$(docker network inspect --format '{{with index .IPAM.Config 0}}{{.Gateway}}{{end}}' "$internal_network")
gateway_is_absent "$internal_gateway" || fail "internal network exposes gateway $internal_gateway"
network_id=$(docker network inspect --format '{{.Id}}' "$internal_network")
bridge_name="br-${network_id:0:12}"
if ip -4 -o addr show dev "$bridge_name" 2>/dev/null | grep -q ' inet '; then
  fail "host bridge $bridge_name has an IPv4 address"
fi
[[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$agent_container")" == 1 ]] || fail "agent is not attached to exactly one network"
[[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$gateway_container")" == 2 ]] || fail "gateway is not attached to exactly two networks"
[[ "$(docker network inspect --format '{{len .Containers}}' "$internal_network")" == 2 ]] || fail "internal network attachment count drifted"
[[ "$(docker network inspect --format '{{len .Containers}}' "$egress_network")" == 1 ]] || fail "egress network attachment count drifted"
gateway_is_absent "$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.Gateway}}{{end}}" "$agent_container")" || fail "agent endpoint exposes a gateway"
gateway_is_absent "$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.Gateway}}{{end}}" "$gateway_container")" || fail "gateway internal endpoint exposes a gateway"

for key in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  [[ "$(docker exec "$agent_container" printenv "$key")" == "$proxy" ]] || fail "$key does not point to the gateway"
done
[[ -z "$(docker exec "$agent_container" printenv NO_PROXY)" ]] || fail "NO_PROXY is not empty"
[[ -z "$(docker exec "$agent_container" printenv no_proxy)" ]] || fail "no_proxy is not empty"
[[ "$(docker inspect --format '{{range .HostConfig.Dns}}{{.}}{{end}}' "$agent_container")" == "$gateway_ip" ]] || fail "agent DNS does not point to the gateway"
route4=$(docker exec "$agent_container" ip -4 route)
if grep -Eq '(^default| via )' <<<"$route4"; then
  fail "agent gained a default or via route: $route4"
fi

allowed_status=$(docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 -o /dev/null -w '%{http_code}' http://example.com/)
case "$allowed_status" in
  2*|3*) ;;
  *) fail "allowed request returned $allowed_status" ;;
esac
docker exec "$agent_container" getent ahostsv4 example.com >/dev/null
expect_failure docker exec "$agent_container" getent ahostsv4 unknown.example
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://unknown.example/
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://127.0.0.1/
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://example.com:853/
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://example.com/dns-query
expect_status 403 docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -H 'Accept: application/dns-json' -o /dev/null -w '%{http_code}' http://example.com/api
expect_failure docker exec "$agent_container" curl -sS --connect-timeout 5 --max-time 10 -o /dev/null https://dns.google/dns-query

expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://example.com/'
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://1.1.1.1/'
expect_failure docker exec "$agent_container" /bin/sh -c 'NO_PROXY="*" no_proxy="*" curl -sS --connect-timeout 2 --max-time 4 -o /dev/null http://example.com/'
expect_failure docker exec "$agent_container" /bin/sh -c 'HTTP_PROXY=http://203.0.113.10:3128 HTTPS_PROXY=http://203.0.113.10:3128 ALL_PROXY=http://203.0.113.10:3128 http_proxy=http://203.0.113.10:3128 https_proxy=http://203.0.113.10:3128 all_proxy=http://203.0.113.10:3128 curl -sS --connect-timeout 2 --max-time 4 -o /dev/null http://example.com/'
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null telnet://1.1.1.1:53'
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -g -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null "http://[2606:4700:4700::1111]/"'

docker kill "$gateway_container" >/dev/null
[[ "$(docker inspect --format '{{.State.Running}}' "$gateway_container")" == false ]] || fail "killed gateway is still running"
expect_failure docker exec "$agent_container" curl -sS --connect-timeout 2 --max-time 4 -o /dev/null http://example.com/
expect_failure docker exec "$agent_container" /bin/sh -c 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://example.com/'
[[ "$(docker inspect --format '{{.State.Running}}' "$agent_container")" == true ]] || fail "agent stopped with the gateway"

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
  --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,source="$snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  --mount type=bind,source="$route_path",target=/etc/cyberstrike/upstream.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$snapshot_id" \
  --snapshot-sha256 "$snapshot_sha" \
  --upstream-route-path /etc/cyberstrike/upstream.json \
  --upstream-route-id "$route_id" \
  --upstream-route-sha256 "$route_sha" >/dev/null
docker network connect "$egress_network" "$gateway_container"

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
expect_status 502 docker run --rm --network "$internal_network" --dns "$gateway_ip" \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c \
  "curl -sS --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' http://example.com/"
expect_failure docker run --rm --network "$internal_network" --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c \
  'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; curl -sS --connect-timeout 2 --max-time 4 --noproxy "*" -o /dev/null http://example.com/'

# auth-only uses a gateway-only immutable profile. A local test upstream proxy
# accepts CONNECT and returns 204 only when the tunneled HTTP request contains
# the gateway value, proving an Agent-supplied duplicate was removed/replaced.
docker rm -f "$gateway_container" >/dev/null
auth_snapshot_id=12345678-1234-4234-8234-123456789ab7
auth_snapshot_json='{"schemaVersion":1,"policyId":"stage5-item6-policy","rules":[{"id":"inject-api-key","effect":"auth-only","host":"example.com","schemes":["http"],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":"profile-integration","rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1}]}'
printf '%s' "$auth_snapshot_json" >"$auth_snapshot_path"
chmod 0444 "$auth_snapshot_path"
auth_snapshot_sha="sha256:$(sha256sum "$auth_snapshot_path" | awk '{print $1}')"

auth_secret_probe=stage5-auth-secret-probe
auth_profiles_id=stage5-auth-profiles
auth_profiles_json='{"schemaVersion":1,"bindingSalt":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profiles":[{"id":"profile-integration","headerName":"X-Integration-Auth","headerValue":"stage5-auth-secret-probe"}]}'
printf '%s' "$auth_profiles_json" >"$auth_profiles_path"
chmod 0444 "$auth_profiles_path"
auth_profiles_sha="sha256:$(sha256sum "$auth_profiles_path" | awk '{print $1}')"
mismatch_profiles_json='{"schemaVersion":1,"bindingSalt":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profiles":[{"id":"profile-other","headerName":"X-Integration-Auth","headerValue":"unrelated"}]}'
printf '%s' "$mismatch_profiles_json" >"$mismatch_profiles_path"
chmod 0444 "$mismatch_profiles_path"
mismatch_profiles_sha="sha256:$(sha256sum "$mismatch_profiles_path" | awk '{print $1}')"

capture_code=$'import json, socket\nwith open("/expected/auth.json", "r", encoding="utf-8") as source:\n    expected = json.load(source)["profiles"][0]\nserver = socket.socket()\nserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\nserver.bind(("0.0.0.0", 18080))\nserver.listen(1)\nconnection, _ = server.accept()\ndef headers():\n    data = b""\n    while b"\\r\\n\\r\\n" not in data and len(data) < 65536:\n        part = connection.recv(4096)\n        if not part:\n            break\n        data += part\n    return data\nconnect = headers()\nconnect_parts = connect.split(b"\\r\\n", 1)[0].split(b" ")\nconnect_ok = len(connect_parts) == 3 and connect_parts[0] == b"CONNECT" and connect_parts[1].endswith(b":80") and connect_parts[2] == b"HTTP/1.1"\nif not connect_ok:\n    print(json.dumps({"connectOk": False}), flush=True)\n    connection.sendall(b"HTTP/1.1 502 Bad Gateway\\r\\nContent-Length: 0\\r\\n\\r\\n")\nelse:\n    connection.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")\n    request = headers()\n    header_prefix = expected["headerName"].lower().encode() + b":"\n    values = [line.split(b":", 1)[1].strip() for line in request.split(b"\\r\\n") if line.lower().startswith(header_prefix)]\n    auth_match = len(values) == 1 and values[0] == expected["headerValue"].encode()\n    request_line = request.split(b"\\r\\n", 1)[0].decode("ascii", "replace")\n    print(json.dumps({"connectOk": True, "requestLine": request_line, "authHeaderCount": len(values), "authMatch": auth_match}), flush=True)\n    status = b"204 No Content" if auth_match else b"403 Forbidden"\n    connection.sendall(b"HTTP/1.1 " + status + b"\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")\nconnection.close()\nserver.close()'
docker run -d --name "$capture_container" --network "$egress_network" --network-alias stage5-auth-capture \
  --mount type=bind,source="$auth_profiles_path",target=/expected/auth.json,readonly \
  --entrypoint python3 "$CYBERSTRIKE_AGENT_IMAGE" -c "$capture_code" >/dev/null
[[ "$(docker inspect --format '{{.State.Running}}' "$capture_container")" == true ]] || fail "auth capture proxy did not start"

auth_route_id=stage5-auth-route
auth_route_json='{"schemaVersion":1,"mode":"proxy","proxy":{"id":"auth-capture","protocol":"http","host":"stage5-auth-capture","port":18080}}'
printf '%s' "$auth_route_json" >"$auth_route_path"
chmod 0444 "$auth_route_path"
auth_route_sha="sha256:$(sha256sum "$auth_route_path" | awk '{print $1}')"

docker run -d --name "$gateway_container" --network "$internal_network" \
  --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,source="$auth_snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  --mount type=bind,source="$auth_route_path",target=/etc/cyberstrike/upstream.json,readonly \
  --mount type=bind,source="$auth_profiles_path",target=/etc/cyberstrike/auth-profiles.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" run \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$auth_snapshot_id" \
  --snapshot-sha256 "$auth_snapshot_sha" \
  --upstream-route-path /etc/cyberstrike/upstream.json \
  --upstream-route-id "$auth_route_id" \
  --upstream-route-sha256 "$auth_route_sha" \
  --auth-profiles-path /etc/cyberstrike/auth-profiles.json \
  --auth-profiles-id "$auth_profiles_id" \
  --auth-profiles-sha256 "$auth_profiles_sha" >/dev/null
docker network connect "$egress_network" "$gateway_container"

for _ in $(seq 1 60); do
  docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded' && break
  sleep 0.1
done
if ! docker logs "$gateway_container" 2>&1 | grep -q 'boundary_snapshot_loaded'; then
  docker inspect --format 'auth_gateway_state={{json .State}}' "$gateway_container" >&2 || true
  docker logs "$gateway_container" >&2 || true
  fail "auth-only gateway did not report its loaded snapshot"
fi
auth_health=$(docker exec "$gateway_container" /cyberstrike-egress check \
  --snapshot-path /etc/cyberstrike/boundary.json \
  --snapshot-id "$auth_snapshot_id" \
  --snapshot-sha256 "$auth_snapshot_sha" \
  --upstream-route-path /etc/cyberstrike/upstream.json \
  --upstream-route-id "$auth_route_id" \
  --upstream-route-sha256 "$auth_route_sha" \
  --auth-profiles-path /etc/cyberstrike/auth-profiles.json \
  --auth-profiles-id "$auth_profiles_id" \
  --auth-profiles-sha256 "$auth_profiles_sha")
grep -q "\"authProfilesId\":\"$auth_profiles_id\"" <<<"$auth_health" || fail "gateway health omitted the exact auth profile id"
grep -q "\"authProfilesSha256\":\"$auth_profiles_sha\"" <<<"$auth_health" || fail "gateway health omitted the exact auth profile digest"
[[ "$(docker inspect --format '{{len .Mounts}}' "$gateway_container")" == 3 ]] || fail "auth-only gateway does not have exactly three trusted mounts"
auth_gateway_inspect=$(docker inspect "$gateway_container")
if grep -Fq "$auth_secret_probe" <<<"$auth_gateway_inspect"; then
  fail "auth-only credential leaked into gateway inspect metadata"
fi
if docker logs "$gateway_container" 2>&1 | grep -Fq "$auth_secret_probe"; then
  fail "auth-only credential leaked into gateway logs"
fi

gateway_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$internal_network\"}}{{.IPAddress}}{{end}}" "$gateway_container")
[[ -n "$gateway_ip" ]] || fail "auth-only gateway internal address is empty"
proxy="http://$gateway_ip:3128"
docker run -d --name "$agent_container" --network "$internal_network" --dns "$gateway_ip" \
  --env "HTTP_PROXY=$proxy" --env "HTTPS_PROXY=$proxy" --env "ALL_PROXY=$proxy" --env 'NO_PROXY=' \
  --env "http_proxy=$proxy" --env "https_proxy=$proxy" --env "all_proxy=$proxy" --env 'no_proxy=' \
  --entrypoint /bin/sh "$CYBERSTRIKE_AGENT_IMAGE" -c "trap 'exit 0' TERM INT; while :; do sleep 3600; done" >/dev/null
agent_inspect=$(docker inspect "$agent_container")
if grep -Fq "$auth_secret_probe" <<<"$agent_inspect"; then
  fail "auth-only credential leaked into Agent metadata"
fi
expect_failure docker exec "$agent_container" test -e /etc/cyberstrike/auth-profiles.json
auth_status=$(docker exec "$agent_container" curl -sS --connect-timeout 8 --max-time 15 \
  -H 'X-Integration-Auth: agent-spoof-must-be-replaced' -o /dev/null -w '%{http_code}' http://example.com/ || true)
if [[ "$auth_status" != 204 ]]; then
  docker inspect --format 'auth_capture_state={{json .State}}' "$capture_container" >&2 || true
  docker logs "$capture_container" >&2 || true
  docker inspect --format 'auth_gateway_state={{json .State}}' "$gateway_container" >&2 || true
  docker logs "$gateway_container" >&2 || true
  fail "auth-only request returned $auth_status, want 204"
fi
capture_result=$(docker logs "$capture_container" 2>&1)
grep -q '"authHeaderCount": 1' <<<"$capture_result" || fail "auth capture did not receive exactly one injected header"
grep -q '"authMatch": true' <<<"$capture_result" || fail "auth capture did not receive the gateway credential"
if grep -Fq "$auth_secret_probe" <<<"$capture_result"; then
  fail "auth-only credential leaked into capture diagnostics"
fi

expect_failure docker run --rm --network none --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,source="$auth_snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" check \
  --snapshot-path /etc/cyberstrike/boundary.json --snapshot-id "$auth_snapshot_id" --snapshot-sha256 "$auth_snapshot_sha"
expect_failure docker run --rm --network none --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,source="$auth_snapshot_path",target=/etc/cyberstrike/boundary.json,readonly \
  --mount type=bind,source="$mismatch_profiles_path",target=/etc/cyberstrike/auth-profiles.json,readonly \
  "$CYBERSTRIKE_EGRESS_IMAGE" check \
  --snapshot-path /etc/cyberstrike/boundary.json --snapshot-id "$auth_snapshot_id" --snapshot-sha256 "$auth_snapshot_sha" \
  --auth-profiles-path /etc/cyberstrike/auth-profiles.json --auth-profiles-id mismatch-auth --auth-profiles-sha256 "$mismatch_profiles_sha"

chmod 0644 "$auth_profiles_path"
for _ in $(seq 1 60); do
  [[ "$(docker inspect --format '{{.State.Running}}' "$gateway_container")" == false ]] && break
  sleep 0.1
done
[[ "$(docker inspect --format '{{.State.Running}}' "$gateway_container")" == false ]] || fail "auth-only gateway ignored credential file permission drift"
if docker logs "$gateway_container" 2>&1 | grep -Fq "$auth_secret_probe"; then
  fail "auth-only credential leaked into gateway shutdown logs"
fi
expect_failure docker exec "$agent_container" curl -sS --connect-timeout 2 --max-time 4 -o /dev/null http://example.com/

printf 'docker_topology=isolated internal=2 egress=1\n'
printf 'proxy_protocol=allowed_http_%s denied_matrix_passed\n' "$allowed_status"
printf 'bypass_regression=direct,dns,doh,ipv6,no_proxy,external_proxy_blocked\n'
printf 'gateway_crash=proxy_and_direct_blocked agent_running=true\n'
printf 'upstream_unavailable=http_502 direct_fallback=false credential_metadata_leak=false\n'
printf 'auth_only=http_204 override=true agent_read=false metadata_leak=false mismatch_fail_closed=true integrity_exit=true\n'
