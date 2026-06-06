#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
envd_bin=${ENVD_BIN:-"$HOME/.local/bin/envd"}
if [ ! -x "$envd_bin" ]; then
  envd_bin="$repo_dir/build/envd"
fi
if [ ! -x "$envd_bin" ]; then
  echo "envd binary not found; run ./install.sh or set ENVD_BIN" >&2
  exit 1
fi

env_name="projectdocker"
port="18080"

cleanup() {
  "$envd_bin" rm "$env_name" --yes >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

envd() {
  "$envd_bin" "$@"
}

envd gateway status >/dev/null

echo "==> create sealed env with managed project Docker"
envd start "$env_name" >/dev/null

env_id=$(envd shell "$env_name" printenv ENVD_ENV_ID | tr -d '\r\n')
sidecar="envd-${env_id}-net"

echo "==> docker CLI uses envd-managed endpoint"
docker_host=$(envd shell "$env_name" printenv DOCKER_HOST | tr -d '\r\n')
if [ "$docker_host" != "tcp://127.0.0.1:2375" ]; then
  echo "unexpected DOCKER_HOST: $docker_host" >&2
  exit 1
fi
envd shell "$env_name" docker info >/dev/null

echo "==> docker compose uses envd-managed endpoint"
envd shell "$env_name" docker compose ls >/dev/null

echo "==> project Docker egress follows gateway"
gateway_egress=$(envd gateway egress | awk '/Egress:/ {print $2; exit}')
project_egress=$(envd shell "$env_name" docker run --rm alpine:3.21 sh -lc 'wget -qO- https://api.ipify.org' | tr -d '\r\n')
if [ "$project_egress" != "$gateway_egress" ]; then
  echo "project Docker egress $project_egress differs from gateway $gateway_egress" >&2
  exit 1
fi

echo "==> project Docker ports are not silently exposed to host"
envd shell "$env_name" docker rm -f envd-port-test >/dev/null 2>&1 || true
envd shell "$env_name" docker run -d --name envd-port-test -p "127.0.0.1:${port}:8080" alpine:3.21 sh -lc 'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 8080; done' >/dev/null
sleep 2
if curl -fsS --max-time 2 "http://127.0.0.1:${port}" >/dev/null 2>&1; then
  echo "project Docker published port ${port} to the host" >&2
  exit 1
fi
envd shell "$env_name" docker rm -f envd-port-test >/dev/null

echo "==> project Docker fails closed when sealed gateway network is unhealthy"
docker network disconnect vpn-gateway_inside "$sidecar"
if envd shell "$env_name" docker run --rm alpine:3.21 sh -lc 'wget -qO- --timeout=5 https://api.ipify.org' >/dev/null 2>&1; then
  echo "project Docker egress succeeded after gateway network disconnect" >&2
  exit 1
fi

echo "Project Docker verification OK"
