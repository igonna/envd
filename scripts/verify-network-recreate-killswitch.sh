#!/usr/bin/env sh
set -eu

network=envd-recreate-test
sidecar=envd-recreate-sidecar
xray_container=vpn-gateway-xray-1

cleanup() {
  docker rm -f "$sidecar" >/dev/null 2>&1 || true
  docker network disconnect "$network" "$xray_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}

run_sidecar_probe() {
  docker exec "$sidecar" sh -lc "$1"
}

assert_no_direct_route() {
  description=$1
  route="$(docker exec "$sidecar" sh -lc "ip route get 1.1.1.1 2>/dev/null || true")"
  case "$route" in
    *" dev tun0 "*|"")
      echo "OK: $description has no direct route"
      ;;
    *)
      echo "FAIL: $description route is not sealed: $route" >&2
      exit 1
      ;;
  esac
}

assert_egress_same() {
  description=$1
  expected=$2
  if ! docker exec "$sidecar" sh -lc "wget -qO /tmp/envd-egress-check --timeout=20 https://api.ipify.org"; then
    echo "FAIL: $description did not reach internet through gateway" >&2
    exit 1
  fi
  got="$(docker exec "$sidecar" cat /tmp/envd-egress-check)"
  if [ "$got" != "$expected" ]; then
    echo "FAIL: $description egress changed from $expected to $got" >&2
    exit 1
  fi
  echo "OK: $description egress stayed on gateway $got"
}

assert_egress_same_or_closed() {
  description=$1
  expected=$2
  if docker exec "$sidecar" sh -lc "wget -qO /tmp/envd-egress-check --timeout=10 https://api.ipify.org"; then
    got="$(docker exec "$sidecar" cat /tmp/envd-egress-check)"
    if [ "$got" != "$expected" ]; then
      echo "FAIL: $description egress changed from $expected to $got" >&2
      exit 1
    fi
    echo "OK: $description egress stayed on gateway $got"
  else
    echo "OK: $description failed closed"
  fi
}

cleanup
trap cleanup EXIT INT TERM

docker network create \
  --driver bridge \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  "$network" >/dev/null
docker network connect --alias xray "$network" "$xray_container"

docker run -d \
  --name "$sidecar" \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --network "$network" \
  -e XRAY_HOST=xray \
  -e XRAY_PORT=2088 \
  -e XRAY_HTTP_PORT=2089 \
  devnet-sidecar:1 >/dev/null

for _ in $(seq 1 60); do
  if [ "$(docker inspect -f '{{.State.Health.Status}}' "$sidecar" 2>/dev/null || true)" = "healthy" ]; then
    break
  fi
  sleep 1
done

if [ "$(docker inspect -f '{{.State.Health.Status}}' "$sidecar")" != "healthy" ]; then
  docker logs "$sidecar" >&2 || true
  echo "FAIL: temporary sidecar did not become healthy" >&2
  exit 1
fi

run_sidecar_probe "wget -qO- --timeout=20 https://api.ipify.org >/tmp/envd-egress-ip"
gateway_ip="$(docker exec "$sidecar" cat /tmp/envd-egress-ip)"
assert_no_direct_route "healthy tunnel"
echo "OK: healthy tunnel egress $gateway_ip"

docker network disconnect "$network" "$sidecar"
assert_no_direct_route "after network disconnect"
assert_egress_same_or_closed "after network disconnect" "$gateway_ip"

docker network disconnect "$network" "$xray_container" >/dev/null 2>&1 || true
docker network rm "$network" >/dev/null
docker network create \
  --driver bridge \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  "$network" >/dev/null
docker network connect --alias xray "$network" "$xray_container"

assert_no_direct_route "after network recreate/reconnect"
assert_egress_same_or_closed "after network recreate/reconnect" "$gateway_ip"

docker rm -f "$sidecar" >/dev/null
docker run -d \
  --name "$sidecar" \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --network "$network" \
  -e XRAY_HOST=xray \
  -e XRAY_PORT=2088 \
  -e XRAY_HTTP_PORT=2089 \
  devnet-sidecar:1 >/dev/null

for _ in $(seq 1 60); do
  if [ "$(docker inspect -f '{{.State.Health.Status}}' "$sidecar" 2>/dev/null || true)" = "healthy" ]; then
    break
  fi
  sleep 1
done

if [ "$(docker inspect -f '{{.State.Health.Status}}' "$sidecar")" != "healthy" ]; then
  docker logs "$sidecar" >&2 || true
  echo "FAIL: recreated sidecar did not become healthy" >&2
  exit 1
fi

assert_no_direct_route "after controlled sidecar recreate"
assert_egress_same "after controlled sidecar recreate" "$gateway_ip"

echo "Network recreate kill-switch verification OK"
