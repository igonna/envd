#!/usr/bin/env bash
set -euo pipefail

XRAY_HOST="${XRAY_HOST:-xray}"
XRAY_PORT="${XRAY_PORT:-2088}"
XRAY_HTTP_PORT="${XRAY_HTTP_PORT:-2089}"
SSH_PORT="${SSH_PORT:-22}"
TUN_IFACE="${TUN_IFACE:-tun0}"
SINGBOX_CONFIG="/etc/sing-box/config.json"
UPLINK_GW=""
UPLINK_DEV=""
XRAY_ADDR=""

write_config() {
  mkdir -p /etc/sing-box
  cat >"$SINGBOX_CONFIG" <<EOF
{
  "log": {
    "level": "warn"
  },
  "dns": {
    "servers": [
      {
        "tag": "remote",
        "address": "https://1.1.1.1/dns-query",
        "detour": "xray"
      }
    ],
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "interface_name": "${TUN_IFACE}",
      "address": [
        "172.31.255.1/30"
      ],
      "mtu": 1400,
      "sniff": true,
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed"
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "xray",
      "server": "${XRAY_ADDR}",
      "server_port": ${XRAY_PORT},
      "version": "5"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      }
    ],
    "auto_detect_interface": true,
    "final": "xray"
  }
}
EOF
}

detect_uplink_route() {
  UPLINK_GW="$(ip route show default | awk 'NR==1{print $3}')"
  UPLINK_DEV="$(ip route show default | awk 'NR==1{print $5}')"
  if [[ -z "${UPLINK_GW}" || -z "${UPLINK_DEV}" ]]; then
    echo "Failed to detect default route before switching to ${TUN_IFACE}" >&2
    return 1
  fi
}

resolve_xray_host() {
  XRAY_ADDR="$(getent ahostsv4 "${XRAY_HOST}" | awk 'NR==1{print $1}')"
  if [[ -z "${XRAY_ADDR}" ]]; then
    echo "Failed to resolve upstream host before sealing: ${XRAY_HOST}" >&2
    return 1
  fi
}

write_sealed_resolv_conf() {
  cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
options ndots:0
EOF
}

wait_for_xray_upstream() {
  for _ in {1..60}; do
    if nc -z -w 2 "${XRAY_ADDR}" "${XRAY_PORT}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

apply_killswitch() {
  local uplink_dev="$1"

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

  # Allow only upstream SOCKS connection on the pre-tunnel interface.
  # Matching by interface+port avoids pinning to a single xray container IP.
  iptables -A OUTPUT -o "${uplink_dev}" -p tcp --dport "${XRAY_PORT}" -j ACCEPT
  if [[ -n "${XRAY_HTTP_PORT}" && "${XRAY_HTTP_PORT}" != "${XRAY_PORT}" ]]; then
    iptables -A OUTPUT -o "${uplink_dev}" -p tcp --dport "${XRAY_HTTP_PORT}" -j ACCEPT
  fi

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F
    ip6tables -X

    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP

    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi
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
  # Keep upstream gateway reachable outside tun and route the rest through tun.
  ip route replace default via "${UPLINK_GW}" dev "${UPLINK_DEV}" metric 200
  ip route replace default dev "${TUN_IFACE}"
}

detect_uplink_route || exit 1
resolve_xray_host || exit 1
write_sealed_resolv_conf
apply_killswitch "$UPLINK_DEV"

if ! wait_for_xray_upstream; then
  echo "Upstream not reachable: ${XRAY_HOST} (${XRAY_ADDR}):${XRAY_PORT}" >&2
  exit 1
fi

write_config

sing-box run -c "$SINGBOX_CONFIG" &
sb_pid=$!

wait_for_tun_iface || {
  echo "Tunnel interface ${TUN_IFACE} did not appear" >&2
  kill "$sb_pid" 2>/dev/null || true
  wait "$sb_pid" 2>/dev/null || true
  exit 1
}

route_default_via_tun
wait "$sb_pid"
