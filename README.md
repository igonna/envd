# envd

`envd` creates Docker dev environments that default to sealed networking through
an envd-managed gateway. Install the binary, add a gateway, run environments.
The binary embeds the runtime assets it needs, so normal usage does not depend on
repo-local compose files, manual `.env` files, or copied Docker contexts.

## Install

```bash
./install.sh
```

If `envd` already exists on `PATH`, the installer upgrades that binary. If not,
it installs to `${ENVD_INSTALL_DIR:-$HOME/.local/bin}`.

Requirements:

- Docker Desktop on macOS or Docker Engine with Compose plugin on Linux.
- Go or Docker to build the `envd` binary.
- SSH credentials for a server when installing a gateway.

Verify:

```bash
envd version
envd help
envd init
```

Build release-style binaries for common platforms:

```bash
./build.sh
```

Outputs go to `build/dist/` for macOS arm64/amd64 and Linux arm64/amd64.
When Docker is used for builds, Go module/build caches are kept under
`build/cache/go/` so repeated installs do not redownload dependencies.

## Normal Flow

Initialize encrypted state once:

```bash
envd init
```

Create or adopt a gateway:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password --probe --dry-run
envd gateway install ams1 --host 1.2.3.4 --user root --password --yes
envd gateway use ams1
```

Run a sealed environment:

```bash
envd start books
envd shell books
envd list
```

Check what is broken when networking fails:

```bash
envd doctor --deep
envd proxy test
envd gateway egress
```

Use explicit non-sealed modes only when you mean it:

```bash
envd start scratch --network direct
envd start offline --network offline
```

## Common Commands

```bash
envd proxy                         # show host SOCKS/HTTP proxy endpoints
envd gateway list                  # list configured gateways
envd gateway status                # show active gateway
envd gateway rollback              # return to previous verified gateway
envd user uri ams1                 # print app import URI
envd pkg add web apt:ffmpeg        # add package intent to a profile
envd pkg add web pip:poetry        # Python CLI packages are profile intent too
envd start app --profile web         # lazily build/use that profile
ssh books                          # connect through envd-managed SSH
envd lock                          # stop workloads and hide envd SSH targets
envd unlock                        # restore workloads/SSH targets after lock
envd rm books --yes                # remove an environment and envd-owned volumes
envd password change               # change master password without deleting state
envd reset-state --delete --i-understand-this-deletes-envd-state --yes
                                   # move unreadable envd state to a backup
```

Gateway setup is managed by `envd gateway install` and encrypted envd state. A
normal envd checkout does not contain or need gateway `.env` files.

## State And Runtime Files

`envd init` creates encrypted state at:

```text
${ENVD_STATE_DIR:-$HOME/.local/state/envd}/state.enc
```

Runtime data and materialized gateway files live under:

```text
${ENVD_DATA_DIR:-$HOME/.local/share/envd}
```

Stateful commands unlock that state with the master password. The master
password is never stored. For tests/automation, `ENVD_MASTER_PASSWORD` can
provide it non-interactively.

Interactive unlock is cached in memory for a short sudo-like window so repeated
commands do not ask every time. Default TTL is 5 minutes. Override with
`ENVD_UNLOCK_TTL=10m`, disable with `ENVD_DISABLE_UNLOCK_CACHE=1`, or clear it
immediately with:

```bash
envd lock
```

`envd lock` stops envd-managed workloads and removes envd SSH targets from the
host SSH config so editors stop showing them. `envd unlock` validates the master
password, restores restorable workloads, and publishes SSH targets again.

To change the master password while keeping existing envd state:

```bash
envd password change
```

Password rotation asks for the current master password explicitly even when the
unlock cache is active.

If you forget the master password, envd cannot decrypt `state.enc`. To start
fresh without deleting Docker containers or volumes:

```bash
envd reset-state --delete --i-understand-this-deletes-envd-state --yes
envd init
```

The reset command also asks you to type `Remove envd state` before it moves the
state directory to a backup.

## Repository Layout

```text
cmd/envd/          Go CLI source
internal/assets/   embedded runtime assets
data/hosting/      built-in hosting catalog data
docs/              design and implementation notes
hack/verify/       integration and release-gate checks
```

## Verification

Useful local gates:

```bash
hack/verify/verify-embedded-assets.sh
hack/verify/verify-cross-platform.sh
hack/verify/verify-host-proxy-equivalence.sh
```

`go` is not required on the host for normal install or verification; the scripts
can use Docker images where needed.

## More Detail

- [System design](docs/system-design.md)
- [Implementation checklist](docs/implementation-checklist.md)
