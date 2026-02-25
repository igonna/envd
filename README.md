# Dev Environment Infrastructure

Self-contained Docker development environments behind Xray (VLESS + Reality), with full-tunnel routing.

## What this setup gives you

- Centralized VPN/proxy config in one place: `vpn-gateway/.env`
- Disposable dev containers with persistent `/home/<user>` and `/repo`
- SSH access with agent forwarding
- Per-dev sidecar network namespace (`<name>-net`) that routes all container traffic through Xray
- Kill-switch behavior in sidecar: if Xray is unavailable, outbound traffic is blocked
- Docker CLI inside dev containers with optional host daemon access via mounted socket

## Repository structure

```text
envd/
├── bin/
│   └── envd                    # CLI tool for managing dev containers
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

## 3) Install `envd` CLI

```bash
sudo cp bin/envd /opt/homebrew/bin/envd
sudo chmod +x /opt/homebrew/bin/envd
```

Verify:

```bash
envd help
```

## 4) Create and use a dev environment

```bash
envd run dev1
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
- GitHub SSH key auto-copied from host into container `~/.ssh/github_key` (if detected)
- Automations mount (read-only): `dev-containers/automations` -> `/automations`
- Docker socket mount (if found): host socket -> `/var/run/docker.sock` (for Docker CLI access)

Docker daemon access controls:
- Default: enabled (auto-detects socket from `/var/run/docker.sock` or `~/.docker/run/docker.sock`)
- Disable per creation: `ENVD_DOCKER_ACCESS=0 envd run dev1`
- Force specific socket path: `ENVD_DOCKER_SOCK=/path/to/docker.sock envd run dev1`

GitHub SSH key controls:
- Default: enabled (`ENVD_COPY_GITHUB_KEY=1`) and auto-detects from `ssh -G github.com` identity files
- Disable per creation: `ENVD_COPY_GITHUB_KEY=0 envd run dev1`
- Force specific key path: `ENVD_GITHUB_KEY=~/.ssh/github_key envd run dev1`

Run mounted automation scripts inside container:

```bash
/automations/example.sh
```

Connect:

```bash
envd exec dev1
```

or:

```bash
ssh dev1
```

## 5) Validate full-tunnel behavior

Inside container:

```bash
envd exec dev1
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
Usage:
  envd [command]

Management Commands:
  ps                           List environments
  run <name>                   Create a new environment
  start <name>                 Start an environment
  stop <name>                  Stop an environment
  restart <name>               Restart an environment
  rm <name>                    Remove an environment
  backup <name> [archive]      Backup environment volumes
  restore <name> <archive>     Restore environment volumes
  exec <name> [cmd...]         Run command / open shell in environment

Service Commands:
  service ls [env]                             List services
  service catalog                              List available service types
  service create <env> <service> [instance]    Add/start a service instance
  service create-custom <env> <service> [instance]
  service start <env> <service> [instance]     Alias of service create
  service stop <env> <service> [instance]
  service rm <env> <service> [instance]
  service inspect <env> <service|container> [instance]

Port Commands:
  port ls [env]                                List port mappings
  port open <env> <container-port> [host-port] Open/map a port
  port close <env> <container-port> [host-port] Close/unmap a port
```

`envd start/stop/restart <name>` manage both `<name>` and `<name>-net`.
`envd ps` includes `STATE` as `active` or `stopped`.
For services, most workflows only need `service create` and `service rm`.
Use `[instance]` to run multiple services of the same type in one environment.
Legacy aliases still work (`list/new/ssh/cd/svc-*/port-*`).

Service containers (share `<name>-net` namespace):

```bash
envd service create dev1 postgres main
envd service create dev1 postgres analytics
ENVD_SVC_PORT=5544 ENVD_POSTGRES_USER=reporter ENVD_POSTGRES_PASSWORD=reportpw ENVD_POSTGRES_DB=reports envd service create dev1 postgres reporting
envd service ls dev1
envd service inspect dev1 postgres analytics
envd service rm dev1 postgres reporting
```

Supported service names:
- `postgres`
- `redis`
- `mongodb` (or `mongo`)
- `elasticsearch` (or `es`)

Discover options and connection details:

```bash
envd service catalog
envd service create-custom dev1 postgres reporting
envd service inspect dev1 postgres reporting
# also works with container name from service ls output:
envd service inspect dev1 dev1-svc-postgres-reporting
```

To change credentials/version of an existing service, recreate it:

```bash
envd service rm dev1 postgres reporting
envd service create-custom dev1 postgres reporting
```

Expose app ports to macOS on demand:

```bash
envd port open dev1 3000
# then open http://127.0.0.1:3000 on macOS
envd port ls dev1
envd port close dev1 3000
```

## 7) Persistence model

Persists:
- Installed packages in container writable layer
- `/home/<user>` named volume
- `/repo` named volume
- Container restart on macOS reboot (`--restart unless-stopped`)

Does not persist:
- Container after `envd rm <name>`
- Volumes after `envd rm <name>`

## 8) Security model

- Dev containers use sidecar network namespace.
- Outbound is forced through sidecar TUN routing to Xray socks inbound.
- Sidecar iptables policy defaults to drop.
- Only Xray upstream, loopback, established traffic, SSH ingress, and TUN path are allowed.
- No private SSH keys are stored in dev containers.
- Docker socket access (if enabled) grants high privilege on host Docker daemon. Disable with `ENVD_DOCKER_ACCESS=0` when not needed.
