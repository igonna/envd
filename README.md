# Dev Environment Infrastructure

Self-contained Docker development environments behind Xray (VLESS + Reality), with full-tunnel routing.

## What this setup gives you

- Centralized VPN/proxy config in one place: `vpn-gateway/.env`
- Disposable dev containers with persistent `/home/<user>` and `/repo`
- SSH access with agent forwarding
- Per-dev sidecar network namespace (`<name>-net`) that routes all container traffic through Xray
- Kill-switch behavior in sidecar: if Xray is unavailable, outbound traffic is blocked

## Repository structure

```text
dev-env/
├── bin-dev-env/
│   └── dev-env                    # CLI tool for managing dev containers
├── dev-containers/
│   ├── net-sidecar/
│   │   ├── Dockerfile             # sidecar image (sing-box + kill-switch)
│   │   └── entrypoint.sh
│   └── sshdev/
│       ├── Dockerfile             # dev container image
│       └── entrypoint.sh
└── vpn-gateway/
    ├── Dockerfile.render
    ├── compose.yml
    └── config.template.json
```

## Requirements

- macOS
- Docker Desktop
- SSH key for GitHub (`~/.ssh/ghub_key` recommended)

## 1) Configure VPN gateway

Create `vpn-gateway/.env`:

```bash
XRAY_INBOUND_PORT=1080
XRAY_HTTP_PROXY_PORT=1081
XRAY_SERVER_IP=YOUR_SERVER_IP
XRAY_SERVER_PORT=443
XRAY_UUID=YOUR_UUID
XRAY_PUBLIC_KEY=YOUR_PUBLIC_KEY
XRAY_SNI=www.example.com
XRAY_SHORT_ID=YOUR_SHORT_ID
```

Notes:
- `XRAY_HTTP_PROXY_PORT` is optional unless you need HTTP proxy inbound for host apps.
- `compose.yml` keeps backward compatibility with the old typoed variable name `XRAY_HTTP_RPOXY_PORT`.

Start gateway:

```bash
cd vpn-gateway
docker compose up -d --build
```

Verify from host:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Expected: remote server IP (not your local ISP IP).

## 2) Build images

Build dev container image:

```bash
cd dev-containers/sshdev
docker build -t sshdev:24.04 .
```

Build sidecar image:

```bash
cd dev-containers/net-sidecar
docker build -t devnet-sidecar:1 .
```

## 3) Install `dev-env` CLI

```bash
sudo mv bin-dev-env/dev-env /opt/homebrew/bin/dev-env
sudo chmod +x /opt/homebrew/bin/dev-env
```

Verify:

```bash
dev-env help
```

## 4) Create and use a dev environment

```bash
dev-env new dev1
```

This creates:

- Dev container: `dev1`
- Network sidecar: `dev1-net`
- Linux user: `dev1`
- Volumes: `dev1-home`, `dev1-repo`
- Repo path mapping: `/repo` symlink to `/home/dev1/repo` (for better tool compatibility)
- Local SSH port mapping on `dev1-net`
- SSH config entry for `dev1`
- Git identity auto-propagated from host global Git config (if set)
- Automations mount (read-only): `dev-containers/automations` -> `/automations`

Run mounted automation scripts inside container:

```bash
/automations/example.sh
```

Connect:

```bash
dev-env ssh dev1
```

or:

```bash
ssh dev1
```

## 5) Validate full-tunnel behavior

Inside container:

```bash
dev-env ssh dev1
env | grep -Ei 'proxy|all_proxy' || true
curl -s https://api.ipify.org
```

Expected:
- No proxy env vars are required for tooling.
- Public IP should be the VPN/Xray egress IP.

Kill-switch behavior check:

1. Stop Xray (`cd vpn-gateway && docker compose stop xray`)
2. Try outbound request from `dev1` (`curl https://example.com`)

Expected: request fails (no direct leak).

## 6) CLI commands

```text
dev-env new <name>
dev-env rm <name>
dev-env list
dev-env restart <name>
dev-env ssh <name>
dev-env cd <name>
dev-env port-open <name> <container-port> [host-port]
dev-env port-close <name> <container-port> [host-port]
dev-env port-list [name]
dev-env help
```

`dev-env restart <name>` restarts both `<name>-net` and `<name>`.

Expose app ports to macOS on demand:

```bash
dev-env port-open dev1 3000
# then open http://127.0.0.1:3000 on macOS
dev-env port-list dev1
dev-env port-close dev1 3000
```

## 7) Persistence model

Persists:
- Installed packages in container writable layer
- `/home/<user>` named volume
- `/repo` named volume
- Container restart on macOS reboot (`--restart unless-stopped`)

Does not persist:
- Container after `dev-env rm <name>`
- Volumes after `dev-env rm <name>`

## 8) Security model

- Dev containers use sidecar network namespace.
- Outbound is forced through sidecar TUN routing to Xray socks inbound.
- Sidecar iptables policy defaults to drop.
- Only Xray upstream, loopback, established traffic, SSH ingress, and TUN path are allowed.
- No private SSH keys are stored in dev containers.
