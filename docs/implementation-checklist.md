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

v1 does not include protected APFS/LUKS storage, identity broker, `envd lock`,
VS Code proxy access, package profiles, sealed project Docker, multi-hop gateways,
or broad hosting intelligence.

## v1 Product Checklist

### Install And CLI Skeleton

- [ ] Create Go module and CLI entrypoint.
- [ ] Implement command routing and consistent help output.
- [ ] Create `./install.sh` that builds the Go binary and installs it.
- [ ] Make `install.sh` idempotent for install and upgrade.
- [ ] Print exact `PATH` fix only when needed.
- [ ] Ensure `envd version` works without opening encrypted state.
- [ ] Ensure `envd help` works without opening encrypted state.
- [ ] Remove Bash dependency from normal v1 commands.

### Encrypted State

- [ ] Define envd state directory layout.
- [ ] Create encrypted state store on first stateful command.
- [ ] Prompt for master password when the encrypted store does not exist.
- [ ] Prompt for master password when encrypted state must be opened.
- [ ] Never store the master password.
- [ ] Store human env names, gateway hosts, project paths, and event history only
      in encrypted state.
- [ ] Store only minimal public host metadata outside encrypted state.
- [ ] Use opaque Docker object names and labels.
- [ ] Add state schema versioning and migration hooks.
- [ ] Add wrong-password handling that does not corrupt state.
- [ ] Add state lock/concurrency handling for parallel envd commands.

### Runtime Asset Manager

- [ ] Define pinned runtime assets and image specs.
- [ ] Pin Xray/sing-box/runtime image versions; no `latest`.
- [ ] Record image digests when available.
- [ ] Keep an envd-owned asset cache separate from project data.
- [ ] Restore missing envd-owned images automatically when a command needs them.
- [ ] Detect Docker image drift from anonymous image IDs.
- [ ] Show image identity in `envd ps` and `envd inspect`.
- [ ] Fail with a layer-specific diagnostic if asset restore cannot complete.

### Local Gateway And Proxy

- [ ] Implement local gateway config renderer.
- [ ] Implement provider interface for local gateway backends.
- [ ] Implement Xray provider as the first backend.
- [ ] Use stable host SOCKS and HTTP proxy endpoints.
- [ ] Avoid common user proxy ports in the new defaults.
- [ ] Implement `envd proxy`.
- [ ] Implement `envd proxy test`.
- [ ] Test SOCKS handshake and remote DNS through SOCKS.
- [ ] Test HTTP CONNECT through HTTP proxy.
- [ ] Show effective host ports and bind addresses.
- [ ] Detect port conflicts before starting gateway.
- [ ] Detect wrong/stale proxy port in diagnostics.

### Remote Gateway Install

- [ ] Implement SSH connection to remote server.
- [ ] Store remote server password encrypted after successful use.
- [ ] Detect remote OS, architecture, memory, disk, init system, and firewall.
- [ ] Inspect existing provider state without overwriting unknown configs.
- [ ] Generate install/adopt/replace plan.
- [ ] Show concise interactive plan before applying risky changes.
- [ ] Install pinned Xray Reality strategy for v1.
- [ ] Generate server keys/config if absent.
- [ ] Install or update systemd service where available.
- [ ] Open firewall port only when a supported firewall is detected.
- [ ] Verify remote provider process starts.
- [ ] Verify local-to-remote handshake before marking gateway usable.
- [ ] Roll back failed activation to previous known-good remote config when envd
      owns the previous config.

### Gateway Switching

- [ ] Implement `envd gateway install <name>`.
- [ ] Implement `envd gateway use <name>`.
- [ ] Implement `envd gateway status`.
- [ ] Implement `envd gateway inspect`.
- [ ] Implement `envd gateway egress`.
- [ ] Store gateway generation in encrypted state.
- [ ] Verify target gateway before changing active pointer.
- [ ] Keep previous known-good gateway until target verification passes.
- [ ] Roll back automatically if activation fails.
- [ ] Reconcile affected sealed environments after successful switch.
- [ ] Keep affected sealed environments fail-closed if reconciliation fails.

### Sealed Environment Creation

- [ ] Define environment spec format.
- [ ] Implement `envd run <env>`.
- [ ] Implement `envd ps`.
- [ ] Implement `envd inspect <env>`.
- [ ] Implement `envd shell <env>`.
- [ ] Implement `envd stop <env>`.
- [ ] Implement `envd start <env>`.
- [ ] Implement `envd rm <env>`.
- [ ] Use plain storage by default.
- [ ] Show plain storage clearly in `envd ps` and `envd inspect`.
- [ ] Never describe plain storage as encrypted or protected.
- [ ] Generate sidecar container and dev container pair.
- [ ] Share dev container network namespace with sidecar.
- [ ] Configure sidecar TUN routing.
- [ ] Configure sidecar kill-switch default drop.
- [ ] Permit only configured local gateway path before tunnel is healthy.
- [ ] Ensure no proxy env vars are required inside sealed dev containers.
- [ ] Verify DNS, TCP, TLS, Docker Hub, and egress IP from inside the sealed env.
- [ ] Mark env healthy only after sealed probes pass.
- [ ] Show network, gateway generation, egress, and issue in `envd ps`.

### Network Modes

- [ ] Implement `--network sealed` as default.
- [ ] Implement explicit `--network direct`.
- [ ] Implement explicit `--network offline`.
- [ ] Implement `envd network set <env> sealed`.
- [ ] Implement `envd network set <env> direct`.
- [ ] Implement `envd network set <env> offline`.
- [ ] Stop or recreate affected containers before changing mode.
- [ ] Never switch a running sealed env directly to direct networking.
- [ ] Show direct/offline modes as outside sealed guarantee.
- [ ] Deny silent fallback from sealed to direct.

### Diagnostics

- [ ] Implement `envd doctor`.
- [ ] Implement `envd doctor --deep`.
- [ ] Implement `envd why <env>`.
- [ ] Implement `envd events`.
- [ ] Map every failure to a layer: host Docker, asset cache, local gateway,
      remote gateway, sidecar, DNS, egress policy, or state.
- [ ] Run real host proxy traffic tests.
- [ ] Run real sealed-container traffic tests.
- [ ] Detect Docker daemon unavailable.
- [ ] Detect required image missing and auto-repair attempt result.
- [ ] Detect local proxy accepts TCP but fails SOCKS/HTTP protocol.
- [ ] Detect remote handshake failure.
- [ ] Detect DNS leak or DNS failure.
- [ ] Detect sealed route direct egress.
- [ ] Detect gateway generation mismatch.
- [ ] Print the smallest next action instead of generic logs.

### Event Log

- [ ] Store event log in encrypted state.
- [ ] Record gateway install/use/rollback/reconciliation.
- [ ] Record environment create/start/stop/rm/recreate.
- [ ] Record image restore and image drift.
- [ ] Record doctor failures and recovered failures.
- [ ] Redact secrets and sensitive paths from normal output.
- [ ] Make `envd why <env>` explain current block reason from events/state.

### v1 Migration From Current System

- [ ] Discover old envd containers and sidecars.
- [ ] Discover old gateway `.env` and rendered config where safe.
- [ ] Import existing gateway credentials only after user confirmation.
- [ ] Preserve environment names where feasible.
- [ ] Detect existing Docker volumes as plain storage.
- [ ] Do not claim legacy Docker volumes are protected or encrypted.
- [ ] Mark migrated envs with plain storage status unless protected import is
      explicitly requested and succeeds.
- [ ] Do not shell out to Bash scripts for normal v1 operations.

## v1 Release Gates

### Kill-Switch Gate

- [ ] Gateway stopped: sealed env has no direct IPv4 egress.
- [ ] Gateway stopped: sealed env has no direct IPv6 egress.
- [ ] Gateway stopped: sealed env DNS does not bypass tunnel.
- [ ] Sidecar restart creates no leak window.
- [ ] Gateway restart creates no leak window.
- [ ] Docker network recreate creates no leak window.
- [ ] Before tunnel is healthy, only the configured local gateway path is
      reachable.

### Gateway Gate

- [ ] `gateway use` verifies target before activation.
- [ ] Failed target keeps previous active gateway.
- [ ] Failed target does not mutate sealed envs into direct mode.
- [ ] Successful switch increments gateway generation.
- [ ] Existing sealed envs reconcile to new generation.
- [ ] Failed reconciliation leaves env blocked/fail-closed.

### Diagnostics Gate

- [ ] Broken Docker daemon is reported as host Docker layer.
- [ ] Missing runtime image is restored or reported as asset cache layer.
- [ ] Wrong SOCKS port is reported as local proxy layer.
- [ ] TCP-open but bad SOCKS/HTTP protocol is reported as local proxy layer.
- [ ] Remote server down is reported as remote gateway layer.
- [ ] Sidecar route failure is reported as sealed sidecar layer.
- [ ] DNS failure is reported as DNS layer.
- [ ] Direct egress is reported as egress policy failure.
- [ ] `doctor --deep` runs real sealed-container HTTPS test.

### Encrypted-State Gate

- [ ] Stateful commands create or unlock encrypted state before reading names,
      paths, gateway hosts, or event history.
- [ ] Plain host files contain no human env names by default.
- [ ] Docker object names are opaque.
- [ ] Docker labels contain only opaque IDs and non-sensitive public metadata.
- [ ] Logs redact passwords, UUIDs where necessary, private keys, and tokens.
- [ ] Corrupted state fails closed and does not create empty replacement state
      silently.

### Cross-Platform Gate

- [ ] macOS arm64 works.
- [ ] macOS amd64 behavior is defined or explicitly unsupported.
- [ ] Linux amd64 works.
- [ ] Linux arm64 works.
- [ ] Runtime image architecture is selected automatically.
- [ ] Host proxy behavior is equivalent on macOS and Linux.
- [ ] Sealed kill-switch behavior is equivalent at the security-model level.

## Post-v1 Security And Storage

- [ ] Implement macOS encrypted APFS sparse-image backend.
- [ ] Implement Linux LUKS2/dm-crypt-backed image backend.
- [ ] Fail closed if protected backend is unavailable.
- [ ] Import legacy Docker volume data into protected storage only when requested.
- [ ] Keep legacy Docker volume data as plain storage by default.
- [ ] Implement `envd lock`.
- [ ] Terminate envd-owned shell/SSH/editor sessions on lock.
- [ ] Stop envd-managed workloads on lock.
- [ ] Close protected storage on lock when the environment uses protected storage.
- [ ] Add lock/session release gate tests.
- [ ] Implement automatic encrypted recovery points.
- [ ] Implement automatic recovery-point pruning.
- [ ] Ensure `envd rm <env>` removes env-owned storage and recovery points after
      confirmation.
- [ ] Implement `envd code <env>`.
- [ ] Implement envd-controlled SSH proxy access.

## Post-v1 Identity

- [ ] Implement `envd identity add <name>`.
- [ ] Implement identity policy model.
- [ ] Store identity material in encrypted envd store.
- [ ] Implement identity broker socket.
- [ ] Route SSH auth through envd broker.
- [ ] Route Git HTTPS credentials through envd credential helper.
- [ ] Scope broker grants to env ID, identity, command class, and gateway
      generation.
- [ ] Deny broker access on direct network by default.
- [ ] Deny broker access on unhealthy sealed route.
- [ ] Deny broker access after gateway switch until revalidation.
- [ ] Add wrappers only as convenience/diagnostics.
- [ ] Ensure broker denial works if wrappers are bypassed.
- [ ] Implement `envd doctor --identity`.
- [ ] Add identity negative tests.

## Post-v1 Productivity

- [ ] Implement dev image profiles.
- [ ] Implement `envd pkg add <profile> apt:<package>`.
- [ ] Implement `envd pkg add <profile> npm:<package>`.
- [ ] Implement `tool:<name>` package source.
- [ ] Build dirty profiles lazily when first used.
- [ ] Implement profile generations.
- [ ] Keep old image generations only while referenced.
- [ ] Garbage-collect unreferenced envd-owned images automatically.
- [ ] Implement `envd pkg suggest <env>`.
- [ ] Implement `envd pkg promote <env> --to <profile>`.
- [ ] Implement `envd migrate <env> --profile <profile>`.
- [ ] Implement `.envd.yaml` project manifest support.
- [ ] Implement user-level supervisor.
- [ ] Implement conservative idle auto-stop.
- [ ] Ensure supervisor is event-driven and mostly asleep.

## Post-v1 Resilience And Censorship

- [ ] Define signed hosting catalog schema.
- [ ] Ship conservative built-in catalog.
- [ ] Implement signed catalog update verification.
- [ ] Implement local private catalog overlay.
- [ ] Store local reachability history.
- [ ] Implement `envd internet status`.
- [ ] Implement `envd internet report`.
- [ ] Implement `envd hosting check`.
- [ ] Implement `envd hosting shortlist`.
- [ ] Implement `envd gateway risk <name>`.
- [ ] Implement user URI generation.
- [ ] Implement gateway chain model.
- [ ] Ensure chains never degrade to direct or single-hop silently.

## Post-v1 Project Docker

- [ ] Design envd-managed Docker-compatible project endpoint.
- [ ] Decide backend: rootless Docker, containerd/nerdctl, or explicit
      compatibility backend.
- [ ] Ensure `docker` inside envd shell uses envd-managed endpoint.
- [ ] Ensure `docker compose` inside envd shell uses envd-managed endpoint.
- [ ] Store project Docker data in envd-managed storage using the environment's
      declared storage mode.
- [ ] Route project Docker traffic through sealed gateway.
- [ ] Deny project Docker egress when gateway is unhealthy.
- [ ] Block host Docker socket mounts by default.
- [ ] Block host networking by default.
- [ ] Block privileged host access by default.
- [ ] Block arbitrary host path mounts by default.
- [ ] Ensure Compose `ports:` does not silently expose services to host/LAN.
- [ ] Add project Docker release gate tests.

## Out Of Scope Unless Reopened

- [ ] General Docker replacement.
- [ ] Full VPS control panel.
- [ ] Automatic provider account creation.
- [ ] Universal VPN client for every use case.
- [ ] Silent claim that plain storage is encrypted or protected.
- [ ] Security based on OS screen-lock, idle timeout, or sleep detection.
- [ ] Global Docker/PATH wrappers as a security boundary.
- [ ] Silent fallback from sealed networking to direct networking.
