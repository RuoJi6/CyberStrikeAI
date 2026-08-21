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
snapshot_path="$test_root/boundary.json"

cleanup() {
  docker rm -f "$agent_container" "$gateway_container" >/dev/null 2>&1 || true
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

printf 'docker_topology=isolated internal=2 egress=1\n'
printf 'proxy_protocol=allowed_http_%s denied_matrix_passed\n' "$allowed_status"
printf 'bypass_regression=direct,dns,doh,ipv6,no_proxy,external_proxy_blocked\n'
printf 'gateway_crash=proxy_and_direct_blocked agent_running=true\n'
