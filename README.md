# envd

`envd` manages sealed Docker development environments behind a local Xray
gateway. The normal CLI is the Go binary built by `./install.sh`; the old Bash
CLI has been removed.

## Requirements

- Docker Desktop on macOS or Docker Engine with Compose plugin on Linux.
- Either local Go or Docker for building the `envd` binary.
- A configured `vpn-gateway/.env` for the current local Xray gateway.

## Host Platforms

- macOS arm64 is the currently tested host platform.
- macOS amd64 is supported by the installer and builds a native `darwin/amd64`
  binary, but is not part of the current local smoke-test environment.
- Linux amd64 and Linux arm64 pass the repeatable cross-platform build/test
  verifier. Full Linux host-proxy and sealed kill-switch host equivalence remain
  separate release gates.

## Install

```bash
./install.sh
```

The installer builds `cmd/envd` and installs `envd` to
`${ENVD_INSTALL_DIR:-$HOME/.local/bin}`. If that directory is not on `PATH`, the
installer prints the exact export line to add.

Verify:

```bash
envd version
envd help
```

Cross-platform Linux verification:

```bash
scripts/verify-cross-platform.sh
```

This runs Go tests/builds and stateless CLI smokes for Linux amd64/arm64, then
builds the dev and sidecar runtime images for both platforms.

## Gateway

Create `vpn-gateway/.env`:

```bash
XRAY_BIND_IP=127.0.0.1
XRAY_SOCKS_PORT=11080
XRAY_INBOUND_PORT=2088
XRAY_HTTP_PROXY_PORT=2089
XRAY_HTTP_PROXY_HOST_PORT=11081
XRAY_SERVER_IP=YOUR_SERVER_IP
XRAY_SERVER_PORT=443
XRAY_UUID=YOUR_UUID
XRAY_PUBLIC_KEY=YOUR_PUBLIC_KEY
XRAY_SNI=www.example.com
XRAY_SHORT_ID=YOUR_SHORT_ID
XRAY_FINGERPRINT=firefox
```

Start it:

```bash
docker compose -f vpn-gateway/compose.yml up -d --build
```

Check it:

```bash
envd gateway render
envd proxy
envd proxy test
envd gateway egress
```

Optionally import the current local gateway config into encrypted envd state and
activate it for envd-managed commands:

```bash
envd gateway import-local ams1 --yes
envd gateway use ams1
```

Gateway switches remember the previous active gateway and can roll back after
verifying the old target again:

```bash
envd gateway rollback
```

Remote gateway install prints an install/adopt/replace plan. `--dry-run` never
mutates the server:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password --dry-run
```

Add `--probe` to make a real SSH password-auth connection, pin the host-key
fingerprint, inspect OS/arch/resources/init/firewall and existing Xray/envd
provider state, generate envd-owned Xray Reality server material locally when
absent, and store the remote password only after the probe succeeds:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password --probe --dry-run
```

Use `--yes` to apply after a successful probe. envd installs the pinned
envd-owned Xray Reality config, updates systemd/firewall where supported,
verifies the remote process and local TCP reachability, stores the local gateway
profile, and leaves activation explicit:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password --yes
envd gateway use ams1
```

Generate an app import URI for a gateway:

```bash
envd user uri ams1
```

The URI contains gateway credentials and is printed only on explicit request
after unlocking encrypted state.

Assess gateway/provider risk from encrypted gateway state and local hosting
history:

```bash
envd gateway risk ams1
```

Gateway chain definitions can be recorded, but activation is fail-closed until
the multi-hop backend exists:

```bash
envd gateway chain create work --entry reg1 --exit ams1
envd gateway chain status work
```

## Diagnose

```bash
envd doctor --deep
```

`doctor --deep` checks Docker, runtime images, gateway rendering, gateway port
mappings, SOCKS/HTTP proxy handshakes, sealed-container DNS/TLS/Docker Hub, and
sealed/project-Docker egress against gateway egress. Diagnostic failures are
mapped to a layer and include a concrete next action.

The host proxy parity gate is repeatable with
`scripts/verify-host-proxy-equivalence.sh`; it checks both the host proxy path
and the Linux Docker-client path through `host.docker.internal`.

The sealed project Docker gate is repeatable with
`scripts/verify-project-docker.sh`; it proves `docker` and `docker compose`
inside an envd shell use the envd-managed endpoint and fail closed with the
sealed gateway path.

For a fast direct-vs-gateway internet snapshot with encrypted local history:

```bash
envd internet status
envd internet report
```

For a provider reachability snapshot and next-gateway shortlist:

```bash
envd hosting check
envd hosting shortlist
```

envd ships a small conservative hosting catalog and supports a private JSON
overlay at `${ENVD_DATA_DIR:-$HOME/.local/share/envd}/hosting/local.json` or
`ENVD_HOSTING_CATALOG`.

Signed catalog updates are accepted only after Ed25519 detached-signature
verification:

```bash
envd hosting update --url providers.json --sig providers.json.sig --key catalog.pub
```

## Environments

Create a sealed plain-storage environment:

```bash
envd run books
```

Open a shell or run a command:

```bash
envd shell books
envd shell books whoami
```

Inspect and list:

```bash
envd ps
envd inspect books
```

Change network mode explicitly:

```bash
envd network set books sealed
envd network set books direct
envd network set books offline
```

Risky env-owned volume operations, such as network-mode recreate or profile
migration, create encrypted automatic recovery points. They are pruned
invisibly, and `envd rm <env> --yes` removes that environment's recovery points.

Define reusable package profiles. Profiles store package intent in encrypted
state; profile images are generated lazily when first used:

```bash
envd pkg add web apt:ffmpeg
envd pkg add web npm:pnpm
envd pkg add tools tool:rg
envd run app --profile web
```

Project defaults can live in `.envd.yaml` in the current project directory:

```yaml
network: sealed
storage: plain
profile: web
```

Existing envd-owned environments can be recreated onto a profile while keeping
their envd-owned volumes:

```bash
envd migrate books --profile web
```

If you experimented inside an environment, envd can suggest package intent from
post-creation apt installs and global npm packages, then promote those into a
profile:

```bash
envd pkg suggest books
envd pkg promote books --to web
```

## Editor Access

Generate a VS Code Remote SSH target that connects through envd policy checks
instead of exposing a durable host SSH port:

```bash
envd code books --print
```

The generated SSH config uses:

```text
ProxyCommand envd ssh-proxy books
```

`envd ssh-proxy <env>` refuses blocked, offline, stopped, or unknown
environments and proxies stdio to the container SSH daemon only after encrypted
state is unlocked. SSH authentication through the identity broker is still a
separate post-v1 item.

## Identities

Store SSH identity material in encrypted envd state with a sealed-only policy:

```bash
envd identity add github --ssh-key ~/.ssh/id_ed25519
envd identity list
envd doctor --identity
```

Store a Git HTTPS token in encrypted state without passing the token on argv:

```bash
envd identity add githubhttps --git-https --username alice --token-file ~/.config/envd/github.token
git config credential.helper '!envd identity credential-helper books githubhttps'
```

The identity broker policy/socket exists and fails closed on direct networking,
unhealthy sealed routes, and stale gateway generations:

```bash
envd identity broker check books github --class ssh
```

For diagnostics or local convenience, envd can write wrappers that call the
broker before delegating to real `ssh`/`git`:

```bash
envd identity wrappers books github --dir .envd/wrappers
```

Put that directory first in `PATH` only when you want the convenience behavior.
The wrappers are not the security boundary; broker denial still works when they
are bypassed.

SSH auth can also go through a broker-gated envd SSH agent socket:

```bash
envd identity ssh-agent books github --socket /tmp/envd-github.sock
ssh -o IdentityAgent=/tmp/envd-github.sock git@github.com
```

The agent loads the encrypted SSH key only after broker policy passes and
re-checks policy for agent list/sign operations. Stored identities are validated
and kept out of containers.

Remove an envd-owned environment and its envd-owned Docker volumes:

```bash
envd rm books --yes
```

Lock envd-owned workloads:

```bash
envd lock
```

`envd lock` stops environments recorded in encrypted envd state. Active
`envd shell` / one-shot sessions end because their target containers stop. In
the current plain-storage mode, lock does not make Docker volumes encrypted or
protected.

Optionally run the idle supervisor. It unlocks envd state once, wakes on
envd-managed Docker events or the next idle deadline, and stops workloads that
have not been used through envd for at least the idle threshold:

```bash
envd supervisor run --idle 3h
```

## Migration

Legacy containers created by the old Bash CLI can be discovered without
mutation:

```bash
envd migrate inspect
```

Adopt legacy containers into encrypted state as `legacy` + `plain`:

```bash
envd migrate adopt --yes
```

Explicitly import one adopted legacy plain environment into protected storage:

```bash
envd migrate protected books --yes
```

This creates a new envd-owned protected environment record for `books`, imports
the old `books-home` and `books-repo` volume data, and leaves the original legacy
Docker volumes untouched.

Gateway credentials are not imported by migration. Gateway inspection is
read-only:

```bash
envd migrate gateway inspect
```

## State

Stateful commands create or unlock encrypted state under
`${ENVD_STATE_DIR:-$HOME/.local/state/envd}/state.enc`. The master password is
prompted interactively or read from `ENVD_MASTER_PASSWORD` for tests/automation.
The master password is never stored.

## Current v1 Limits

- Remote `envd gateway install --yes` applies envd-owned Xray Reality config,
  systemd/firewall changes where supported, process verification, TCP
  reachability verification, and envd-owned rollback on failed verification.
- Protected storage is available explicitly with `--storage protected`.
  macOS uses an encrypted APFS sparse image; Linux uses a LUKS2/dm-crypt-backed
  image. Both act as at-rest stores and hydrate temporary envd-owned Docker
  volumes while the environment is running.
- Identity broker and sealed project Docker are implemented, but they remain
  security-sensitive subsystems with explicit release gates.
- Existing legacy Docker volumes are plain storage; envd does not claim they are
  protected or encrypted.
