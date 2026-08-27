#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
action="${1:-start}"
runner_image="${CYBERSTRIKE_TRANSFORM_IMAGE:-cyberstrike-transform-runner:local}"
runner_name="${CYBERSTRIKE_TRANSFORM_CONTAINER:-cyberstrike-transform-runner}"
runner_network="${CYBERSTRIKE_TRANSFORM_NETWORK:-cyberstrike-transform-internal}"
token_file="${CYBERSTRIKE_TRANSFORM_TOKEN_FILE:-$repo_dir/data/traffic-transform-runner.token}"
container_token_file="/run/secrets/traffic-transform-token"
runtime_uid="$(id -u)"
runtime_gid="$(id -g)"

ensure_token() {
	local token_dir
	token_dir="$(dirname "$token_file")"
	if [ -L "$token_dir" ] || [ -L "$token_file" ]; then
		printf 'Runner token path must not be a symbolic link: %s\n' "$token_file" >&2
		exit 1
	fi
	mkdir -p "$token_dir"
	chmod 0700 "$token_dir"
	if [ -e "$token_file" ] && [ ! -f "$token_file" ]; then
		printf 'Runner token path must be a regular file: %s\n' "$token_file" >&2
		exit 1
	fi
    if [ ! -f "$token_file" ]; then
        umask 077
        openssl rand -hex 32 > "$token_file"
    fi
    chmod 0600 "$token_file"
}

build_image() {
    docker build -f "$repo_dir/container/transform-runner/Dockerfile" -t "$runner_image" "$repo_dir/container/transform-runner"
}

start_runner() {
    ensure_token
    if ! docker image inspect "$runner_image" >/dev/null 2>&1; then
        build_image
    fi
    if ! docker network inspect "$runner_network" >/dev/null 2>&1; then
        docker network create --driver bridge --internal --opt com.docker.network.bridge.enable_icc=false "$runner_network" >/dev/null
    fi
    if docker container inspect "$runner_name" >/dev/null 2>&1; then
        docker rm -f "$runner_name" >/dev/null
    fi
    docker run -d \
        --name "$runner_name" \
        --restart unless-stopped \
        --network "$runner_network" \
        --read-only \
        --user "${runtime_uid}:${runtime_gid}" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --pids-limit 32 \
        --memory 256m \
        --cpus 0.50 \
        --ulimit nofile=64:64 \
        --tmpfs "/run/cyberstrike-transform:rw,noexec,nosuid,nodev,mode=0700,uid=${runtime_uid},gid=${runtime_gid},size=32m" \
        --mount "type=bind,src=${token_file},dst=${container_token_file},readonly" \
        --env "CYBERSTRIKE_TRANSFORM_TOKEN_FILE=${container_token_file}" \
        "$runner_image" >/dev/null
    runner_ip="$(docker container inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$runner_name")"
    if [ -z "$runner_ip" ]; then
        printf 'Runner started without a private network address\n' >&2
        exit 1
    fi
    printf 'Runner started on private internal-network endpoint http://%s:9089\n' "$runner_ip"
    printf 'Server env: CYBERSTRIKE_TRANSFORM_RUNNER_URL=http://%s:9089 CYBERSTRIKE_TRANSFORM_RUNNER_TOKEN_FILE=%s\n' "$runner_ip" "$token_file"
}

case "$action" in
    build) build_image ;;
    start) start_runner ;;
    stop)
        if docker container inspect "$runner_name" >/dev/null 2>&1; then docker rm -f "$runner_name" >/dev/null; fi
        ;;
    status) docker container inspect --format '{{.State.Status}}' "$runner_name" ;;
    *) printf 'usage: %s {build|start|stop|status}\n' "$0" >&2; exit 2 ;;
esac
