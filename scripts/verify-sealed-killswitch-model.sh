#!/usr/bin/env sh
set -eu

network=envd-killswitch-test
sidecar=envd-killswitch-sidecar
xray_container=vpn-gateway-xray-1

cleanup() {
  docker rm -f "$sidecar" >/dev/null 2>&1 || true
  docker network disconnect "$network" "$xray_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}

probe() {
  docker exec "$sidecar" sh -lc "$1"
}

require_rule() {
  description=$1
  command=$2
  if ! probe "$command"; then
    echo "FAIL: missing $description" >&2
    exit 1
  fi
  echo "OK: $description"
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

require_rule "IPv4 INPUT default drop" "iptables -S INPUT | grep -qx -- '-P INPUT DROP'"
require_rule "IPv4 FORWARD default drop" "iptables -S FORWARD | grep -qx -- '-P FORWARD DROP'"
require_rule "IPv4 OUTPUT default drop" "iptables -S OUTPUT | grep -qx -- '-P OUTPUT DROP'"
require_rule "IPv4 loopback allowed" "iptables -S OUTPUT | grep -qx -- '-A OUTPUT -o lo -j ACCEPT'"
require_rule "IPv4 established allowed" "iptables -S OUTPUT | grep -q -- '--ctstate RELATED,ESTABLISHED -j ACCEPT'"
require_rule "IPv4 tunnel output allowed" "iptables -S OUTPUT | grep -qx -- '-A OUTPUT -o tun0 -j ACCEPT'"
require_rule "IPv4 Xray SOCKS pre-tunnel path allowed" "iptables -S OUTPUT | grep -q -- '-o eth0 .*--dport 2088 .*ACCEPT'"
require_rule "IPv4 Xray HTTP pre-tunnel path allowed" "iptables -S OUTPUT | grep -q -- '-o eth0 .*--dport 2089 .*ACCEPT'"

require_rule "IPv6 INPUT default drop" "ip6tables -S INPUT | grep -qx -- '-P INPUT DROP'"
require_rule "IPv6 FORWARD default drop" "ip6tables -S FORWARD | grep -qx -- '-P FORWARD DROP'"
require_rule "IPv6 OUTPUT default drop" "ip6tables -S OUTPUT | grep -qx -- '-P OUTPUT DROP'"

route="$(probe "ip route get 1.1.1.1 2>/dev/null || true")"
case "$route" in
  *" dev tun0 "*)
    echo "OK: IPv4 egress route uses tun0"
    ;;
  *)
    echo "FAIL: IPv4 egress route is not sealed: $route" >&2
    exit 1
    ;;
esac

if probe "ip -6 route get 2606:4700:4700::1111 >/tmp/envd-ipv6-route 2>/dev/null"; then
  route6="$(docker exec "$sidecar" cat /tmp/envd-ipv6-route)"
  echo "FAIL: IPv6 route exists despite IPv6-only direct path risk: $route6" >&2
  exit 1
fi
echo "OK: no IPv6 direct route"

if probe "grep -q '127.0.0.11' /etc/resolv.conf"; then
  echo "FAIL: Docker embedded DNS is active inside sealed sidecar" >&2
  exit 1
fi
echo "OK: Docker embedded DNS not used"

probe "wget -qO /tmp/envd-egress-check --timeout=20 https://api.ipify.org"
gateway_ip="$(docker exec "$sidecar" cat /tmp/envd-egress-check)"
case "$gateway_ip" in
  ''|*[!0-9.]*)
    echo "FAIL: unexpected egress IP: $gateway_ip" >&2
    exit 1
    ;;
  *)
    echo "OK: live egress through gateway $gateway_ip"
    ;;
esac

echo "Sealed kill-switch model verification OK"
