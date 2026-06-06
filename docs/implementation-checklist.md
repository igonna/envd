# envd Implementation Checklist

This checklist turns `docs/system-design.md` into executable work. The rule is
simple: v1 ships only when the v1 checklist and v1 release gates are complete.
Later milestones stay out of v1 unless explicitly moved forward and release
gated.

## v1 Scope

v1 goal:

```text
install envd -> configure gateway -> run one sealed environment -> diagnose
failures by layer -> fail closed on unsafe network changes
```

The original v1 boundary did not require protected APFS/LUKS storage, identity
broker, VS Code proxy access, sealed project Docker, multi-hop gateways, or
remote gateway install. Those items are tracked below and are marked complete
only where implemented and release-gated.

## v1 Product Checklist

### Install And CLI Skeleton

- [x] Create Go module and CLI entrypoint.
- [x] Implement command routing and consistent help output.
- [x] Create `./install.sh` that builds the Go binary and installs it.
- [x] Make `install.sh` idempotent for install and upgrade.
- [x] Print exact `PATH` fix only when needed.
- [x] Ensure `envd version` works without opening encrypted state.
- [x] Ensure `envd help` works without opening encrypted state.
- [x] Remove Bash dependency from normal v1 commands.

### Encrypted State

- [x] Define envd state directory layout.
- [x] Create encrypted state store only through explicit `envd init`.
- [x] Prompt twice for master password during `envd init`.
- [x] Stateful commands fail with `envd init` guidance when state is missing.
- [x] Prompt for master password when encrypted state must be opened.
- [x] Never store the master password.
- [x] Add `envd password change` to rotate the master password without deleting
      encrypted state.
- [x] Cache interactive unlock in memory for a short TTL.
- [x] Clear cached unlock on `envd lock`.
- [x] Store human env names, gateway hosts, project paths, and event history only
      in encrypted state.
- [x] Store only minimal public host metadata outside encrypted state.
- [x] Use opaque Docker object names and labels.
- [x] Add state schema versioning and migration hooks.
- [x] Add wrong-password handling that does not corrupt state.
- [x] Add state lock/concurrency handling for parallel envd commands.

### Runtime Asset Manager

- [x] Define pinned runtime assets and image specs.
- [x] Pin Xray/sing-box/runtime image versions; no `latest`.
- [x] Record image digests when available.
- [x] Keep an envd-owned asset cache separate from project data.
- [x] Restore missing envd-owned images automatically when a command needs them.
- [x] Detect Docker image drift from anonymous image IDs.
- [x] Show image identity in `envd ps` and `envd inspect`.
- [x] Fail with a layer-specific diagnostic if asset restore cannot complete.

### Local Gateway And Proxy

- [x] Implement local gateway config renderer.
- [x] Implement provider interface for local gateway backends.
- [x] Implement Xray provider as the first backend.
- [x] Use stable host SOCKS and HTTP proxy endpoints.
- [x] Avoid common user proxy ports in the new defaults.
- [x] Implement `envd proxy`.
- [x] Implement `envd proxy test`.
- [x] Test SOCKS handshake and remote DNS through SOCKS.
- [x] Test HTTP CONNECT through HTTP proxy.
- [x] Show effective host ports and bind addresses.
- [x] Detect port conflicts before starting gateway.
- [x] Detect wrong/stale proxy port in diagnostics.

### Self-Contained Install And Gateway Runtime

- [x] Embed envd-owned runtime container assets into the Go binary.
- [x] Embed gateway render templates into the Go binary.
- [x] Remove `example.env` from product/runtime assets.
- [x] Stop requiring repo checkout discovery for normal installed commands.
- [x] Materialize gateway runtime files into envd-owned data/cache paths when
      needed.
- [x] Render local gateway config from encrypted gateway state, not manual
      `.env`, for normal operation.
- [x] Keep `gateway import-local` only as legacy migration from old manual
      `.env` setups.
- [x] Update help/docs so `gateway install/use` is the normal path and manual
      `.env` is not normal UX.
- [x] Add tests proving assets/templates work without a repo checkout.
- [x] Add verification that the installed binary can restore runtime images
      from embedded assets.

### Remote Gateway Install

- [x] Implement SSH connection to remote server.
- [x] Store remote server password encrypted after successful use.
- [x] Detect remote OS, architecture, memory, disk, init system, and firewall.
- [x] Inspect existing provider state without overwriting unknown configs.
- [x] Generate install/adopt/replace plan.
- [x] Show concise interactive plan before applying risky changes.
- [x] Install pinned Xray Reality strategy for v1.
- [x] Generate server keys/config if absent.
- [x] Install or update systemd service where available.
- [x] Open firewall port only when a supported firewall is detected.
- [x] Verify remote provider process starts.
- [x] Verify local-to-remote handshake before marking gateway usable.
- [x] Roll back failed activation to previous known-good remote config when envd
      owns the previous config.

### Gateway Switching

- [x] Implement `envd gateway install <name>`.
- [x] Implement `envd gateway use <name>`.
- [x] Implement `envd gateway status`.
- [x] Implement `envd gateway inspect`.
- [x] Implement `envd gateway egress`.
- [x] Store gateway generation in encrypted state.
- [x] Verify target gateway before changing active pointer.
- [x] Keep previous known-good gateway until target verification passes.
- [x] Roll back automatically if activation fails.
- [x] Reconcile affected sealed environments after successful switch.
- [x] Keep affected sealed environments fail-closed if reconciliation fails.

### Sealed Environment Creation

- [x] Define environment spec format.
- [x] Implement `envd run <env>`.
- [x] Implement `envd ps`.
- [x] Implement `envd inspect <env>`.
- [x] Implement `envd shell <env>`.
- [x] Implement `envd stop <env>`.
- [x] Implement `envd start <env>`.
- [x] Implement `envd rm <env>`.
- [x] Use plain storage by default.
- [x] Show plain storage clearly in `envd ps` and `envd inspect`.
- [x] Never describe plain storage as encrypted or protected.
- [x] Generate sidecar container and dev container pair.
- [x] Share dev container network namespace with sidecar.
- [x] Configure sidecar TUN routing.
- [x] Configure sidecar kill-switch default drop.
- [x] Permit only configured local gateway path before tunnel is healthy.
- [x] Ensure no proxy env vars are required inside sealed dev containers.
- [x] Verify DNS, TCP, TLS, Docker Hub, and egress IP from inside the sealed env.
- [x] Mark env healthy only after sealed probes pass.
- [x] Show network, gateway generation, egress, and issue in `envd ps`.

### Network Modes

- [x] Implement `--network sealed` as default.
- [x] Implement explicit `--network direct`.
- [x] Implement explicit `--network offline`.
- [x] Implement `envd network set <env> sealed`.
- [x] Implement `envd network set <env> direct`.
- [x] Implement `envd network set <env> offline`.
- [x] Stop or recreate affected containers before changing mode.
- [x] Never switch a running sealed env directly to direct networking.
- [x] Show direct/offline modes as outside sealed guarantee.
- [x] Deny silent fallback from sealed to direct.

### Diagnostics

- [x] Implement `envd doctor`.
- [x] Implement `envd doctor --deep`.
- [x] Implement `envd why <env>`.
- [x] Implement `envd events`.
- [x] Map every failure to a layer: host Docker, asset cache, local gateway,
      remote gateway, sidecar, DNS, egress policy, or state.
- [x] Run real host proxy traffic tests.
- [x] Run real sealed-container traffic tests.
- [x] Detect Docker daemon unavailable.
- [x] Detect required image missing and auto-repair attempt result.
- [x] Detect local proxy accepts TCP but fails SOCKS/HTTP protocol.
- [x] Detect remote handshake failure.
- [x] Detect DNS leak or DNS failure.
- [x] Detect sealed route direct egress.
- [x] Detect gateway generation mismatch.
- [x] Print the smallest next action instead of generic logs.

### Event Log

- [x] Store event log in encrypted state.
- [x] Record gateway install/use/rollback/reconciliation.
- [x] Record environment create/start/stop/rm/recreate.
- [x] Record image restore and image drift.
- [x] Record doctor failures and recovered failures.
- [x] Redact secrets and sensitive paths from normal output.
- [x] Make `envd why <env>` explain current block reason from events/state.

### v1 Migration From Current System

- [x] Discover old envd containers and sidecars.
- [x] Discover old gateway `.env` and rendered config where safe.
- [x] Import existing gateway credentials only after user confirmation.
- [x] Preserve environment names where feasible.
- [x] Detect existing Docker volumes as plain storage.
- [x] Do not claim legacy Docker volumes are protected or encrypted.
- [x] Mark migrated envs with plain storage status unless protected import is
      explicitly requested and succeeds.
- [x] Do not shell out to Bash scripts for normal v1 operations.

## v1 Release Gates

### Kill-Switch Gate

- [x] Gateway stopped: sealed env has no direct IPv4 egress.
- [x] Gateway stopped: sealed env has no direct IPv6 egress.
- [x] Gateway stopped: sealed env DNS does not bypass tunnel.
- [x] Sidecar restart creates no leak window.
- [x] Gateway restart creates no leak window.
- [x] Docker network recreate creates no leak window.
- [x] Before tunnel is healthy, only the configured local gateway path is
      reachable.

### Gateway Gate

- [x] `gateway use` verifies target before activation.
- [x] Failed target keeps previous active gateway.
- [x] Failed target does not mutate sealed envs into direct mode.
- [x] Successful switch increments gateway generation.
- [x] Existing sealed envs reconcile to new generation.
- [x] Failed reconciliation leaves env blocked/fail-closed.

### Diagnostics Gate

- [x] Broken Docker daemon is reported as host Docker layer.
- [x] Missing runtime image is restored or reported as asset cache layer.
- [x] Wrong SOCKS port is reported as local proxy layer.
- [x] TCP-open but bad SOCKS/HTTP protocol is reported as local proxy layer.
- [x] Remote server down is reported as remote gateway layer.
- [x] Sidecar route failure is reported as sealed sidecar layer.
- [x] DNS failure is reported as DNS layer.
- [x] Direct egress is reported as egress policy failure.
- [x] `doctor --deep` runs real sealed-container HTTPS test.

### Encrypted-State Gate

- [x] `envd init` creates encrypted state before any encrypted metadata exists.
- [x] Stateful commands unlock existing encrypted state before reading names,
      paths, gateway hosts, or event history.
- [x] Plain host files contain no human env names by default.
- [x] Docker object names are opaque.
- [x] Docker labels contain only opaque IDs and non-sensitive public metadata.
- [x] Logs redact passwords, UUIDs where necessary, private keys, and tokens.
- [x] Corrupted state fails closed and does not create empty replacement state
      silently.

### Cross-Platform Gate

- [x] macOS arm64 works.
- [x] macOS amd64 behavior is defined or explicitly unsupported.
- [x] Linux amd64 works.
- [x] Linux arm64 works.
- [x] Runtime image architecture is selected automatically.
- [x] Host proxy behavior is equivalent on macOS and Linux.
- [x] Sealed kill-switch behavior is equivalent at the security-model level.

## Post-v1 Security And Storage

- [x] Implement macOS encrypted APFS sparse-image backend.
- [x] Implement Linux LUKS2/dm-crypt-backed image backend.
- [x] Fail closed if protected backend is unavailable.
- [x] Import legacy Docker volume data into protected storage only when requested.
- [x] Keep legacy Docker volume data as plain storage by default.
- [x] Implement `envd lock`.
- [x] Terminate envd-owned shell/SSH/editor sessions on lock.
- [x] Stop envd-managed workloads on lock.
- [x] Close protected storage on lock when the environment uses protected storage.
- [x] Add lock/session release gate tests.
- [x] Implement automatic encrypted recovery points.
- [x] Implement automatic recovery-point pruning.
- [x] Ensure `envd rm <env>` removes env-owned storage and recovery points after
      confirmation.
- [x] Implement `envd code <env>`.
- [x] Implement envd-controlled SSH proxy access.

## Post-v1 Identity

- [x] Implement `envd identity add <name>`.
- [x] Implement identity policy model.
- [x] Store identity material in encrypted envd store.
- [x] Implement identity broker socket.
- [x] Route SSH auth through envd broker.
- [x] Route Git HTTPS credentials through envd credential helper.
- [x] Scope broker grants to env ID, identity, command class, and gateway
      generation.
- [x] Deny broker access on direct network by default.
- [x] Deny broker access on unhealthy sealed route.
- [x] Deny broker access after gateway switch until revalidation.
- [x] Add wrappers only as convenience/diagnostics.
- [x] Ensure broker denial works if wrappers are bypassed.
- [x] Implement `envd doctor --identity`.
- [x] Add identity negative tests.

## Post-v1 Productivity

- [x] Implement dev image profiles.
- [x] Implement `envd pkg add <profile> apt:<package>`.
- [x] Implement `envd pkg add <profile> npm:<package>`.
- [x] Implement `tool:<name>` package source.
- [x] Build dirty profiles lazily when first used.
- [x] Implement profile generations.
- [x] Keep old image generations only while referenced.
- [x] Garbage-collect unreferenced envd-owned images automatically.
- [x] Implement `envd pkg suggest <env>`.
- [x] Implement `envd pkg promote <env> --to <profile>`.
- [x] Implement `envd migrate <env> --profile <profile>`.
- [x] Implement `.envd.yaml` project manifest support.
- [x] Implement user-level supervisor.
- [x] Implement conservative idle auto-stop.
- [x] Ensure supervisor is event-driven and mostly asleep.

## Post-v1 Resilience And Censorship

- [x] Define signed hosting catalog schema.
- [x] Ship conservative built-in catalog.
- [x] Implement signed catalog update verification.
- [x] Implement local private catalog overlay.
- [x] Store local reachability history.
- [x] Implement `envd internet status`.
- [x] Implement `envd internet report`.
- [x] Implement `envd hosting check`.
- [x] Implement `envd hosting shortlist`.
- [x] Implement `envd gateway risk <name>`.
- [x] Implement user URI generation.
- [x] Implement gateway chain model.
- [x] Ensure chains never degrade to direct or single-hop silently.

## Post-v1 Project Docker

- [x] Design envd-managed Docker-compatible project endpoint.
- [x] Decide backend: rootless Docker, containerd/nerdctl, or explicit
      compatibility backend.
- [x] Ensure `docker` inside envd shell uses envd-managed endpoint.
- [x] Ensure `docker compose` inside envd shell uses envd-managed endpoint.
- [x] Store project Docker data in envd-managed storage using the environment's
      declared storage mode.
- [x] Route project Docker traffic through sealed gateway.
- [x] Deny project Docker egress when gateway is unhealthy.
- [x] Block host Docker socket mounts by default.
- [x] Block host networking by default.
- [x] Block privileged host access by default.
- [x] Block arbitrary host path mounts by default.
- [x] Ensure Compose `ports:` does not silently expose services to host/LAN.
- [x] Add project Docker release gate tests.

## Confirmed Non-Goals Unless Reopened

- [x] General Docker replacement.
- [x] Full VPS control panel.
- [x] Automatic provider account creation.
- [x] Universal VPN client for every use case.
- [x] Silent claim that plain storage is encrypted or protected.
- [x] Security based on OS screen-lock, idle timeout, or sleep detection.
- [x] Global Docker/PATH wrappers as a security boundary.
- [x] Silent fallback from sealed networking to direct networking.
