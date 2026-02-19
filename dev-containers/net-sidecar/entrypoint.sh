#!/usr/bin/env bash
set -euo pipefail

XRAY_HOST="${XRAY_HOST:-xray}"
XRAY_PORT="${XRAY_PORT:-1080}"
SSH_PORT="${SSH_PORT:-22}"
TUN_IFACE="${TUN_IFACE:-tun0}"
SINGBOX_CONFIG="/etc/sing-box/config.json"

resolve_xray_ip() {
  local ip=""
  for _ in {1..30}; do
    ip="$(getent hosts "$XRAY_HOST" | awk 'NR==1{print $1}')"
    if [[ -n "$ip" ]]; then
      echo "$ip"
      return 0
    fi
    sleep 1
  done
  return 1
}

write_config() {
  local xray_server_ip="$1"
  mkdir -p /etc/sing-box
  cat >"$SINGBOX_CONFIG" <<EOF
{
  "log": {
    "level": "warn"
  },
  "inbounds": [
    {
      "type": "tun",
      "interface_name": "${TUN_IFACE}",
      "address": [
        "172.31.255.1/30"
      ],
      "mtu": 1400,
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed"
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "xray",
      "server": "${xray_server_ip}",
      "server_port": ${XRAY_PORT},
      "version": "5"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "final": "xray"
  }
}
EOF
}

apply_killswitch() {
  local xray_ip="$1"

  iptables -F
  iptables -X

  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT

  iptables -A INPUT -i "${TUN_IFACE}" -j ACCEPT
  iptables -A OUTPUT -o "${TUN_IFACE}" -j ACCEPT

  iptables -A OUTPUT -d "${xray_ip}" -p tcp --dport "${XRAY_PORT}" -j ACCEPT
}

wait_for_tun_iface() {
  for _ in {1..80}; do
    if ip link show "${TUN_IFACE}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

route_default_via_tun() {
  local xray_ip="$1"
  local default_gw default_dev

  default_gw="$(ip route show default | awk 'NR==1{print $3}')"
  default_dev="$(ip route show default | awk 'NR==1{print $5}')"

  if [[ -z "${default_gw}" || -z "${default_dev}" ]]; then
    echo "Failed to detect default route before switching to ${TUN_IFACE}" >&2
    return 1
  fi

  ip route replace "${xray_ip}/32" via "${default_gw}" dev "${default_dev}"
  ip route replace default dev "${TUN_IFACE}"
}

XRAY_IP="$(resolve_xray_ip || true)"
if [[ -z "$XRAY_IP" ]]; then
  echo "Failed to resolve upstream host: ${XRAY_HOST}" >&2
  exit 1
fi

write_config "$XRAY_IP"
apply_killswitch "$XRAY_IP"

sing-box run -c "$SINGBOX_CONFIG" &
sb_pid=$!

wait_for_tun_iface || {
  echo "Tunnel interface ${TUN_IFACE} did not appear" >&2
  kill "$sb_pid" 2>/dev/null || true
  wait "$sb_pid" 2>/dev/null || true
  exit 1
}

route_default_via_tun "$XRAY_IP"
wait "$sb_pid"
