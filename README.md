# envd

`envd` creates Docker dev environments that default to sealed networking through
an envd-managed gateway. Install the binary, add a gateway, run environments.
The binary embeds the runtime assets it needs, so normal usage does not depend on
repo-local compose files, manual `.env` files, or copied Docker contexts.

## Install

```bash
./install.sh
```

Requirements:

- Docker Desktop on macOS or Docker Engine with Compose plugin on Linux.
- Go or Docker to build the `envd` binary.
- SSH credentials for a server when installing a gateway.

Verify:

```bash
envd version
envd help
```

## Normal Flow

Create or adopt a gateway:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password --probe --dry-run
envd gateway install ams1 --host 1.2.3.4 --user root --password --yes
envd gateway use ams1
```

Run a sealed environment:

```bash
envd run books
envd shell books
envd ps
```

Check what is broken when networking fails:

```bash
envd doctor --deep
envd proxy test
envd gateway egress
```

Use explicit non-sealed modes only when you mean it:

```bash
envd run scratch --network direct
envd run offline --network offline
```

## Common Commands

```bash
envd proxy                         # show host SOCKS/HTTP proxy endpoints
envd gateway status                # show active gateway
envd gateway rollback              # return to previous verified gateway
envd user uri ams1                 # print app import URI
envd pkg add web apt:ffmpeg        # add package intent to a profile
envd run app --profile web         # lazily build/use that profile
envd code books --print            # print VS Code Remote SSH config
envd lock                          # stop envd-managed workloads
envd rm books --yes                # remove an environment and envd-owned volumes
```

`envd gateway import-local <name> --yes` exists only for migrating old manual
local gateway `.env` setups into encrypted state.

## State And Runtime Files

Stateful commands create or unlock encrypted state at:

```text
${ENVD_STATE_DIR:-$HOME/.local/state/envd}/state.enc
```

Runtime data and materialized gateway files live under:

```text
${ENVD_DATA_DIR:-$HOME/.local/share/envd}
```

The master password is never stored. For tests/automation, `ENVD_MASTER_PASSWORD`
can provide it non-interactively.

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
hack/verify/verify-project-docker.sh
```

`go` is not required on the host for normal install or verification; the scripts
can use Docker images where needed.

## More Detail

- [System design](docs/system-design.md)
- [Implementation checklist](docs/implementation-checklist.md)
