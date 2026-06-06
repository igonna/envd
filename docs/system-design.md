# envd System Design

This document describes the next-generation `envd` architecture. The goal is to
replace the current shell-script control plane with a Go utility that manages
remote Xray, the local gateway, sealed dev containers, host proxy endpoints, and
diagnostics as one coherent system.

## Product Definition

`envd` is a development environment manager with a built-in VPN control plane.
It provides:

- Remote Xray server installation and lifecycle management.
- Local Xray gateway and stable host proxy endpoints.
- A pluggable tunnel/provider layer so Xray can be replaced later.
- Sealed Docker development environments with no accidental direct network leak.
- Optional non-sealed environments for explicit workflows.
- Deep diagnostics that identify which network layer failed.
- Shareable VPN user URIs for apps and other devices.
- Self-managed installation, runtime assets, and required image cache.

The current sealed sidecar model is the most valuable part of the system and
must be preserved.

## Product Boundary

`envd` should be understood as one product, not a pile of scripts:

```text
envd = reproducible dev environments + sealed networking + managed gateway
```

It owns the path from source code to a running dev container with a known network
posture. The user should not need to manually remember Docker image IDs, proxy
ports, sidecar internals, Xray config paths, server install commands, or which
layer to debug first.

Core user promises:

- New dev environments are useful immediately.
- `envd init` is the explicit one-time step that creates encrypted state and the
  master password.
- The master password can be changed without deleting encrypted state.
- Interactive unlock may be cached only in memory for a short TTL; `envd lock`
  clears it immediately.
- Sealed networking is the default and fails closed.
- The active gateway and remote server are inspectable and switchable.
- Remote server setup is reconciled, not installed blindly.
- Protocol choices use conservative strategies, not random defaults.
- Docker image purges are repairable for envd-owned images.
- Secrets are remembered in an encrypted envd store.
- Developer identities and account credentials are protected by network policy.
- A signed hosting catalog and local reachability history help users get a
  replacement gateway quickly instead of researching providers from zero during
  an outage.
- Secure-by-default behavior protects envd state, secrets, identities, and
  network posture. Environment storage encryption is explicit.
- Every stateful envd command uses secure encrypted state; plaintext state is not
  a fallback mode.
- Projects can declare non-secret envd intent in the repo when useful.
- Risky migrations create automatic encrypted recovery points.
- envd records an event log so "what changed?" is answerable.
- `envd doctor --deep` identifies the broken layer with real traffic tests.
- macOS and Linux behavior should be equivalent except where Docker itself
  differs.

Things `envd` should not become:

- A general Docker replacement.
- A full VPS control panel.
- A universal VPN client for every use case.
- A package manager for all possible development stacks.
- A tool that silently exposes containers to direct networking.

The product should stay narrow enough to be reliable: if a feature does not
improve reproducibility, sealed networking, diagnostics, gateway management, or
repair, it should be questioned.

## Non-Negotiable Invariants

- Sealed networking is the default for new dev environments.
- A sealed environment must never fall back to direct internet if VPN is broken.
- No proxy environment variables are required inside sealed dev containers.
- Sidecar kill-switch policy defaults to drop.
- The only permitted pre-tunnel egress from a sealed sidecar is to the local Xray
  gateway ports it was configured to use.
- Direct networking must be explicit: `--network direct`.
- Account credentials must not be injected into direct/offline/unknown-risk
  environments unless the identity policy explicitly allows it.
- Long-lived account credentials must not be copied into containers as plain
  files in the protected identity path. Access goes through envd-controlled
  brokers or short-lived material.
- envd secrets must be encrypted at rest by default.
- Environment/workspace storage is plain by default for normal development and
  encrypted only when the user explicitly selects protected storage.
- envd operational state must be encrypted by default. Plain host/Docker
  metadata must be minimal, non-sensitive, and use opaque identifiers where
  possible.
- Offline/no-internet networking must be explicit: `--network offline`.
- Docker is the only required third-party host runtime for default usage. envd
  also requires OS-native networking capabilities for sealed mode. Encrypted
  storage backends are required only when protected storage is requested.
- Xray and sing-box versions must be pinned, not `latest`.
- Required runtime images must be restorable by `envd` even if the user purges
  normal Docker images.
- Runtime install/bootstrap should be owned by `envd`, not copied from README
  snippets.
- Encrypted state creation is explicit: stateful commands must not create a
  master password implicitly. If state is missing, they tell the user to run
  `envd init`.
- Master password rotation must re-encrypt existing state in place after the
  current password successfully unlocks it. Reset is only for forgotten
  passwords.
- Master password rotation must request the current password explicitly, even
  when the short-lived unlock cache is active.
- Non-secret runtime repair remains lazy: normal commands may restore assets,
  images, caches, and generated runtime files when safe.
- Secrets must not be stored in world-readable files.
- `doctor --deep` must test real traffic, not just container liveness.
- Network mode changes must be explicit and must stop/recreate affected
  containers safely instead of silently exposing running processes.

## Architecture

```text
+---------------------+
| envd Go CLI          |
|                     |
| config/state         |
| docker manager       |
| ssh remote manager   |
| provider manager     |
| image/tool manager   |
| diagnostics engine   |
+----------+----------+
           |
           v
+---------------------+         +----------------------+
| local Docker host    |         | remote VPS           |
|                     |  SSH    |                      |
| xray gateway         +-------->+ xray server          |
| host proxy endpoints |         | reality/vless users  |
| dev containers       |         | managed config       |
| net sidecars         |         | systemd service      |
+---------------------+         +----------------------+
```

### Local Gateway

The local gateway is a tunnel client container managed by `envd`. The initial
provider is Xray, but the CLI must not bake Xray into every concept. It exposes:

- A stable host SOCKS endpoint, for browsers and host apps.
- A stable host HTTP proxy endpoint, for tools that need HTTP CONNECT.
- Internal Docker-network endpoints for sealed sidecars.

Host-published ports and internal Xray ports are separate concepts.

Example default:

```text
host SOCKS: 127.0.0.1:11080
host HTTP:  127.0.0.1:11081
internal SOCKS: xray:2088
internal HTTP:  xray:2089
```

The internal ports should avoid common user proxy ports like `1080` and `1081`
because host apps often already use those ports.

Host proxy equivalence is a tested contract, not an assumption: `envd proxy
test` verifies the host SOCKS/HTTP protocol path, and
`hack/verify/verify-host-proxy-equivalence.sh` verifies a Linux Docker client can
reach the same host-published SOCKS and HTTP CONNECT endpoints through
`host.docker.internal`.

### Provider Layer

Xray is the first provider, not the permanent architecture boundary.

Provider interface:

- Inspect remote server state.
- Reconcile remote server to desired state.
- Adopt or replace existing provider installs.
- Generate remote server config.
- Generate local gateway config.
- Add/remove users.
- Emit app import URIs.
- Report version and health.
- Run provider-specific deep diagnostics.

Initial provider:

```text
provider: xray
protocol: vless-reality
```

Possible future providers:

```text
provider: sing-box
provider: hysteria
provider: wireguard
provider: custom
```

Command design should leave room for this:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --provider xray
envd gateway inspect ams1
envd gateway use ams1
envd user add phone
envd user uri phone
envd gateway doctor
```

Most dev-container commands should not care which provider is used. They should
only depend on the local gateway contract: internal SOCKS/HTTP endpoints plus
diagnostic probes.

### Protocol Strategy

The user should not need to know which censorship-resistant protocol is currently
best. `envd` should expose strategies, then map those strategies to pinned
provider/protocol configurations.

Strategies:

```text
censorship-resistant  default; conservative anti-DPI/active-probing posture
fast                  optimized for speed, explicit opt-in
compatibility         optimized for app/client compatibility
custom                user-managed provider/protocol settings
```

Help text should explain what each strategy means without forcing the user to
know provider internals:

```text
censorship-resistant
  Default. Conservative setup for hostile networks. Prioritizes camouflage and
  active-probing resistance over raw speed. Current implementation:
  xray/vless-reality/tcp/443.

fast
  Explicit opt-in. Prioritizes throughput and latency. May use transports that
  are easier for some networks to throttle or block.

compatibility
  Explicit opt-in. Prioritizes working with more client apps and constrained
  networks over best censorship resistance.

custom
  Expert mode. User chooses provider/protocol details directly.
```

Default:

```text
strategy: censorship-resistant
primary:  xray/vless-reality/tcp/443
```

Rules:

- Never default to a protocol only because it is faster.
- Prefer TCP/443 web-like camouflage for the default remote path.
- Treat UDP-based protocols as explicit candidates, not universal defaults,
  because some networks throttle or block UDP.
- Do not claim any protocol is permanently undetectable.
- Pin provider versions and strategy definitions.
- Store the strategy version in gateway state.
- Signed strategy/catalog refresh may add newer strategies, but must not silently
  mutate an existing gateway.
- Strategy changes require explicit commands and real verification.

Example:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root
envd gateway install hel1 --host 5.6.7.8 --user root --strategy fast
envd gateway strategy set ams1 censorship-resistant
```

Candidate protocol selection should be evidence-based:

1. Inspect remote OS, architecture, memory, and open ports.
2. Check whether the selected provider can run on that server.
3. Install or configure the candidate.
4. Test remote TCP/UDP reachability from the local host.
5. Test provider handshake.
6. Test host proxy route.
7. Test sealed container route.
8. Activate only after verification passes.

If verification fails, envd should leave the previous working strategy active and
report the failing layer.

### Censorship Readiness And Network Intelligence

envd should not assume that today's working protocol, VPS provider, country, or
ASN will keep working forever. It should track real reachability signals and make
gateway decisions evidence-based.

Goals:

- Know whether the active gateway works from the current network.
- Know whether failures are local Docker/envd issues, gateway issues, provider
  blocking, protocol blocking, DNS manipulation, or broad network disruption.
- Help the user choose a new gateway/provider before the current one becomes a
  single point of failure.
- Track censorship trends without pretending to predict the future perfectly.

Non-goals:

- No port scanning.
- No abusive scanning of third-party networks.
- No hidden telemetry.
- No promise that any protocol will work under total whitelist-only isolation.

Commands:

```bash
envd internet status
envd internet report
envd hosting check
envd hosting list
envd hosting shortlist
envd gateway risk ams1
```

`envd internet status` should summarize the user's current network:

```text
Network:        RU, ASxxxxx
Direct web:     partial
DNS integrity:  suspicious
Gateway ams1:   ok, NL ASyyyyy, xray/reality
Docker Hub:     ok through sealed gateway
Telegram:       blocked direct, ok through gateway
Risk:           medium
```

Signal types:

- Direct HTTP/TLS reachability to a small curated set of well-known domains.
- DNS consistency checks against trusted resolvers.
- Active gateway success/failure by real HTTPS probes.
- Sealed container egress identity and leak checks.
- Hosting/provider website and API reachability from the user's network.
- User-owned gateway reachability by TCP/TLS/provider handshake.
- Optional manually imported external reports.

Hosting checks should be lightweight reachability checks, not scans:

```text
Hetzner website reachable: yes
Hetzner API reachable:     yes
Gateway IP reachable:      yes
Provider ASN reputation:   warning, many failures in local history
```

Provider/hosting catalog:

- Signed catalog schema with a conservative built-in provider set for v1.
- Optional remote catalog updates signed or checksum-verified by envd releases.
- Catalog data lives in the repository as maintained data, not hardcoded logic.
- Local private catalog overlay is supported because provider/payment reality is
  regional and changes over time.
- Store provider country, ASN, pricing notes, API endpoint, and historical local
  success rate.
- Store payment notes, including whether cards, crypto, PayPal, bank transfer,
  or local/regional payment methods are known to be supported.
- Store whether the provider has an API that envd can use after the user supplies
  an API token.
- Store manual signup URL and minimal recommended VPS size.
- Do not recommend a provider solely because it is cheap.
- Prefer provider diversity: country, ASN, upstream network, and payment/account
  separation when possible.
- Do not only list the most famous providers long term. Well-known providers may
  be targeted first, so catalog expansion should include a broad spread of
  smaller reputable providers too.
- Catalog entries should be versioned and refreshed through envd's signed
  catalog update path.
- Catalog entries should have confidence levels: `verified`, `community`,
  `user`, `stale`, `unknown`.
- v1 should not promise a complete payment-aware VPS directory. The initial
  promise is a signed schema, a small conservative catalog, local private
  overrides, and local reachability history.

Catalog sources:

```text
built-in      researched catalog shipped with envd release
updated       signed/checksum-verified catalog update
local         private user override, exceptional path
imported      user-imported catalog file, exceptional path
```

Catalog maintenance model:

- Provider research is project work, not normal user work.
- Use AI-assisted research plus human review to maintain broad provider data.
- Include famous providers, regional providers, smaller reputable providers, and
  payment-friendly providers where known.
- Include providers that sell foreign-region VPS from constrained payment
  regions when reliable information is available.
- Re-check provider homepage, signup URL, API URL, regions, rough minimum plan,
  payment metadata, ASN, and country.
- Mark stale entries instead of silently deleting them.
- Ship catalog snapshots with envd releases.
- Allow signed/checksum-verified catalog refreshes between binary releases.
- Keep the catalog transparent and inspectable.

Repository layout idea:

```text
data/hosting/providers.json
data/hosting/schema.json
data/hosting/sources.md
```

User expectation:

```text
The user should not research providers from zero during an outage.
envd should already have a broad shortlist and local reachability history.
```

Provider entry shape:

```yaml
id: senko-digital
name: Senko Digital
homepage: https://example.com
signup_url: https://example.com/signup
api_url: null
countries_sold_from:
  - RU
regions:
  - code: nl
    country: NL
    city: Amsterdam
    asn: ASxxxxx
payments:
  - local-card
  - crypto
  - bank-transfer
min_plan:
  cpu: 1
  ram_mb: 1024
  disk_gb: 10
notes:
  - regional provider
confidence: user
```

Catalog refresh should be automatic through signed envd catalog updates. Manual
catalog editing is not normal UX.

Gateway acquisition flow:

```bash
envd hosting shortlist
envd gateway install ams2 --host <ip> --user root --password
```

`envd hosting shortlist` should rank providers by:

- Reachability from the current network.
- API/website reachability.
- Country and ASN diversity versus existing gateways.
- Local historical success/failure rate.
- Payment compatibility metadata.
- Minimum VPS cost and resource fit.
- Whether the provider is already overused by the user's gateways.

Example:

```text
Provider      Region  ASN      Website  API  Payment      Risk       Notes
provider-a    NL      AS111    ok       ok   card,crypto  medium     common ASN
provider-b    FI      AS222    ok       -    card         low        manual setup
provider-c    RS      AS333    fail     -    crypto       unknown    website blocked
```

`envd hosting check` should remember previous results:

```text
Checked: 2026-06-05 12:30
Reachable providers: 38/57
Reachable APIs:      12/19
Payment fit:         21/57
New failures:        provider-c, provider-d
Recovered:           provider-e
```

History view:

```text
Provider        Last 7 checks       Trend
provider-a      ok ok ok ok ok ok   stable
provider-c      ok fail fail fail   degrading
provider-e      fail fail ok ok     recovered
```

This lets the user see what changed since the last check instead of redoing
research manually.

`envd hosting shortlist` should guide the user through creating the next
gateway:

```text
1. Pick provider/region.
2. Open signup/create-server URL.
3. Show recommended VPS size and OS image.
4. After the user enters IP/root/password, continue with gateway install.
```

Rules:

- No hidden account creation.
- No storing provider payment credentials.
- Provider API tokens live in the encrypted store.
- Manual flow must stay first-class because many providers do not have useful
  APIs or payment automation.
- The goal is "new gateway in minutes", not "envd becomes a cloud reseller".
- The catalog should support private local overrides so the user can add
  providers that are not in the built-in list.
- Local/private catalog entries should never be uploaded automatically.
- Public catalogs should avoid claiming a provider is guaranteed safe or
  unblockable; they are starting points for local reachability checks.
- A broad catalog is useful, but envd should still recommend provider/ASN
  diversity instead of concentrating everyone on the same "best" provider.

Readiness score:

```text
gateway health      current tunnel works
strategy health     current protocol works
provider risk       provider/ASN historically blocked or degraded
region risk         country/region has recent reachability failures
diversity           user has more than one viable gateway
identity safety     account credentials only available in protected envs
```

Example:

```text
Gateway ams1
Health:        ok
Strategy:      censorship-resistant xray/reality
Provider risk: elevated, ASN had 3 failures this month
Diversity:     weak, no backup gateway
Action:        install second gateway on a different provider/ASN
```

Preparedness rules:

- envd should recommend at least two gateways on different providers/ASNs for
  users who depend on sealed networking daily.
- Gateway switch should stay atomic and verified.
- Strategy updates should be pinned and explicit.
- If the current protocol starts failing but the remote server is reachable,
  envd should classify it as possible protocol/DPI failure.
- If many unrelated foreign hosts fail direct but the gateway still works, envd
  should classify it as local censorship/network degradation.
- If only one provider ASN fails, envd should classify it as possible provider
  or subnet blocking.
- If only DNS differs, envd should classify it as DNS manipulation.
- If strict egress or identity policies cannot be verified, envd should fail
  closed for sealed environments and account credentials.

Hard limit:

```text
If the local network allows only a government-controlled whitelist and blocks all
unknown foreign TCP/UDP destinations, no normal VPS-based gateway can be made
reliably reachable from that network. envd can detect this condition, preserve
sealed fail-closed behavior, and suggest alternatives, but it cannot guarantee
connectivity in principle.
```

This section exists so envd adapts based on measurements instead of being frozen
around one protocol or one hosting provider.

### Sealed Dev Environment

A sealed environment consists of:

```text
<name>       dev container, no own network namespace
<name>-net   sidecar owning the network namespace, TUN route, and kill-switch
```

The dev container runs with:

```text
--network container:<name>-net
```

The sidecar:

- Creates a TUN interface.
- Routes default traffic through sing-box.
- sing-box forwards to the local Xray gateway SOCKS inbound.
- iptables default policy is drop.
- ip6tables default policy is drop as well. IPv6 must not become a bypass if a
  host Docker engine enables IPv6 later.
- Only loopback, established traffic, SSH ingress, TUN traffic, and Xray gateway
  ports are allowed.
- Resolves the local gateway container before sealing and gives sing-box the
  resolved upstream address, so later sealed DNS changes do not depend on
  Docker's embedded resolver.
- Owns sealed DNS through sing-box DNS routing over the same proxy path. The dev
  container must not keep Docker's `127.0.0.11` resolver as its effective DNS,
  because that can bypass the tunnel when the gateway is down.
- Installs the default-drop kill-switch before waiting for the upstream gateway
  port or starting sing-box. A sidecar that is still waiting for the tunnel is
  allowed to reach only the configured local gateway path.
- Raw Docker sidecar restart creates a new network namespace. Existing dev
  containers remain fail-closed in the old namespace until envd reconciles them.
  `envd start <env>` must restart the dev container after the sidecar is healthy
  so it rejoins the current sealed namespace.
- Docker network removal/recreation must not create a direct-egress window. An
  already-running sidecar that loses its Docker network may keep using the
  existing tunnel or fail closed, but it must not gain a host-routed default path.
  Recovery is a controlled sidecar/dev-container recreate, not unsafe hot
  reconnect.

If Xray is unavailable, outbound traffic fails closed.

### Network Modes

Sealed is default:

```bash
envd run dev1
envd run dev1 --network sealed
```

Direct is explicit and has normal Docker networking:

```bash
envd run dev1 --network direct
```

Offline is explicit and has no external internet:

```bash
envd run dev1 --network offline
```

The CLI must show the chosen mode after creation. It should never silently choose
direct networking because sealed setup failed.

Changing network mode is allowed but must be safe:

```bash
envd network set dev1 sealed
envd network set dev1 direct
envd network set dev1 offline
```

Rules:

- The target environment must be stopped first, or `envd` must ask for/perform a
  controlled stop.
- `envd` must never switch a running sealed environment to direct networking.
- `envd` must clearly show if ports/services may become reachable after a mode
  change.
- Mode changes may recreate the dev container while preserving the environment's
  declared storage.
- `envd inspect <env>` must show the current mode and why.

## Command Model

Every command should perform safe startup:

1. If the command is stateless, such as `help`, `version`, or shell completion,
   run without opening envd state.
2. `envd init` is the only command that may create encrypted envd state and ask
   for master password creation.
3. For every other stateful command, ensure config and state directories exist
   with safe permissions.
4. If encrypted state is missing, fail with the smallest next action:
   `envd init`.
5. Ask for master password unlock if encrypted state must be read or updated.
6. Continue the original command after unlock.

The user should not accidentally create a forgotten master password from an
ordinary command like `envd ps`.

### Lazy Reconciliation UX

Normal commands should do the required setup, repair, build, fetch, or validation
implicitly when it is safe.

Principles:

- Except for explicit `envd init`, do not force users to run separate `fetch`,
  `verify`, `build`, `plan`, or `apply` commands in the happy path.
- If an asset, image, profile build, gateway config, or non-secret runtime
  directory is missing, the command that needs it should restore or create it.
- If a change is risky, show a concise plan and ask before applying.
- If a command cannot safely repair automatically, explain the exact blocker and
  the smallest next action, usually `envd doctor --deep` or an inline
  confirmation prompt.
- Keep `status`, `inspect`, `doctor`, and `logs` for visibility and debugging.
  Cleanup and repair should happen automatically when envd has enough context.

Examples:

```bash
envd run books
```

May lazily create runtime directories, fetch runtime assets, build the selected
profile image, start the gateway, create the sidecar, and verify sealed routing.
If encrypted state is missing, it fails and tells the user to run `envd init`.

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password
```

Requires encrypted state created by `envd init`, then saves credentials, inspects
the server, shows a plan, applies after confirmation, and verifies the gateway.

```bash
envd pkg add web apt:ffmpeg
```

Updates the profile manifest only. The next command that needs `web` builds it
automatically.

### Help UX

Help output is part of the product. Every command group and risky option should
include a short description of what it is and what it can change.

Required help principles:

- Do not expose internal architecture words without explaining them.
- Prefer one obvious command for the happy path.
- Show whether a command touches the remote server, local gateway, Docker
  containers, sealed network policy, or stored secrets.
- Mark risky actions such as `--replace`, `--network direct`, and secret export.
- Strategy names must include practical descriptions, not just labels.
- If a command can fail closed, say so.

Example:

```text
envd gateway install <name>
  Install or adopt a remote gateway, configure the local gateway profile, and
  verify host + sealed-container traffic before it can become active.

envd gateway use <name>
  Switch the active gateway. Verifies the new route, syncs sealed environments,
  and rolls back if validation fails.

envd run <name>
  Create a dev environment. Uses sealed networking by default.

envd code <name>
  Open the environment in VS Code through an envd-controlled local SSH proxy.

envd lock
  Stop envd-owned work, revoke identities/secrets, close protected storage when
  present, and then clean up registered Docker artifacts asynchronously.

--network direct
  Explicitly use normal Docker networking. This can expose traffic outside the
  gateway and is never selected automatically.
```

### Top Level

```bash
envd doctor
envd doctor --deep
envd status
envd events
envd why books
envd lock
```

`envd init` is required once to create encrypted envd state and the master
password intentionally. After that, stateful commands unlock existing state with
the master password. If state is missing, ordinary commands must fail with
`envd init` guidance instead of creating a password implicitly.

`envd password change` unlocks state with the current master password, asks for
the new password twice, and re-encrypts the same state. It must not delete
gateways, environments, identities, recovery points, or event history.

### Primary Happy Path

```bash
envd init
envd gateway install ams1 --host 1.2.3.4 --user root --password
envd gateway use ams1
envd run books
envd ps
```

The normal user should not need separate `inspect`, `plan`, and `apply`
commands. `gateway install` should run those phases internally, show a concise
plan, allow editing, then apply and verify.

### No-Trash Command Philosophy

The CLI should stay small in the normal path. Advanced commands can exist, but
they must not become required rituals.

Normal commands:

```bash
envd init
envd gateway install <name> --host <ip> --user root --password
envd gateway use <name>
envd run <env>
envd ps
envd shell <env>
envd code <env>
envd stop <env>
envd start <env>
envd rm <env>
```

Visibility/debug commands:

```bash
envd doctor --deep
envd doctor --identity <env>
envd why <env>
envd events
envd inspect <env>
envd gateway status
envd gateway doctor
envd gateway egress
```

Package/profile commands:

```bash
envd pkg add <profile> apt:<package>
envd pkg add <profile> npm:<package>
envd pkg suggest <env>
envd pkg promote <env> --to <profile>
envd migrate <env> --profile <profile>
```

Support/repair actions should usually be suggested by `envd doctor`, `envd why`,
or the command that failed. They should not be commands the user memorizes for
normal operation.

Rules:

- One explicit `envd init` is required before stateful use; no other setup
  rituals are required in normal use.
- No required profile/image build command in normal use.
- No required manual image repair after Docker prune.
- No proxy environment variables inside sealed environments.
- No copied long-lived identity files.
- No direct-network fallback.
- No silent Docker socket exposure.
- No Compose reimplementation. Standard `docker compose` should work inside an
  envd shell by using an envd-managed sealed Docker engine.
- No expectation that users manually research VPS providers during outages.
  envd ships and updates a maintained hosting catalog.

If implementation pressure adds a command to the happy path, that is a design
smell. The command that has enough context should do the work lazily or explain
why it cannot.

### Gateway

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password
envd gateway use ams1
envd gateway chain create workchain --entry reg1 --exit ams1
envd gateway chain status workchain
envd gateway status
envd gateway doctor
envd gateway logs
envd gateway inspect ams1
envd gateway egress ams1
envd gateway policy set ams1 --expect-country NL --strict
envd gateway upgrade
envd gateway rollback
envd gateway rm ams1
```

Gateway commands manage both the active local gateway and the remote server
profile behind it. The primary install flow must be one command.

Normal usage should mostly be `gateway install`, `gateway use`, and
`gateway status`. `inspect`, logs, rollback, and explicit upgrade commands are
for debugging, recovery visibility, and controlled changes. Repair and cleanup of
envd-owned remote resources should be automatic when a gateway command has enough
context.

`gateway install` behavior:

1. Require encrypted state; if missing, tell the user to run `envd init`.
2. Unlock the encrypted state store.
3. Save the server password encrypted.
4. Connect over SSH.
5. Inspect OS, architecture, memory, disk, systemd, ports, and existing provider
   state.
6. Select the default `censorship-resistant` strategy unless overridden.
7. Build a plan.
8. Show the plan interactively.
9. Allow `apply`, `edit`, `details`, or `abort`.
10. Apply changes only after confirmation.
11. Verify remote service, local gateway, host proxy, and sealed test route.
12. Store the gateway profile only after verification succeeds.
13. If no gateway is active, offer to activate the verified gateway.

`gateway install` prepares and verifies a gateway profile. `gateway use <name>`
selects the active profile. This keeps installation and activation explicit while
still letting first-run UX offer "use this now" after a successful install.

Example interactive plan:

```text
Gateway: ams1
Host:    1.2.3.4
Server:  Ubuntu 24.04 x86_64, 1 GB RAM
Strategy: censorship-resistant
Provider: xray vless-reality tcp/443

Plan:
  install xray 26.2.6
  create envd-owned config
  create user default
  enable systemd service
  verify local and sealed routes

Choose: [a]pply  [e]dit  [d]etails  [q]uit
```

Flags for explicit behavior:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password
envd gateway install ams1 --strategy fast
envd gateway install ams1 --adopt
envd gateway install ams1 --replace
envd gateway install ams1 --yes
envd gateway install ams1 --dry-run
```

Rules:

- Default interactive mode should be concise.
- `--dry-run` prints the plan and changes nothing.
- `--yes` is for automation and should still fail if verification fails.
- `--replace` must be explicit before overwriting non-envd provider config.
- `--adopt` imports compatible existing provider state when possible.
- The command must never leave the gateway marked active unless end-to-end
  verification passed.

### Gateway Change Propagation

Gateway changes must not require restarting Docker Desktop or guessing which
container is stale.

Commands that can change gateway behavior:

- `envd gateway install`
- `envd gateway use`
- `envd gateway rollback`
- `envd gateway upgrade`
- `envd gateway strategy set`

After any successful gateway change, envd should reconcile dependent sealed
environments:

1. Keep the local gateway endpoint stable when possible.
2. Enumerate running sealed environments.
3. Check whether each sidecar is connected to the active gateway generation.
4. Hot-reload or restart the sidecar tunnel process when possible.
5. If hot reload is not safe, perform a controlled recreate of the sidecar/dev
   container pair while preserving the environment's declared storage.
6. Reinstall kill-switch rules before allowing egress.
7. Verify DNS, TCP, TLS, Docker Hub, leak check, and egress policy.
8. Mark the environment healthy only after validation passes.

During propagation, sealed environments must remain fail-closed. If the active
gateway changed but a sidecar cannot be updated, the sidecar should keep default
drop policy and `envd ps` should show the issue:

```text
NAME   STATE    NET     VPN      PROFILE  ISSUE
books  running  sealed  blocked  web      gateway reconciliation failed
```

Recovery path:

- The gateway change command should reconcile affected environments
  automatically.
- If reconciliation cannot complete safely, affected environments stay
  fail-closed.
- `envd doctor --deep` should explain the failed layer and what envd tried.

No design should depend on restarting all of Docker to make containers notice a
gateway config change.

### Egress Identity And Policy

`envd` should be able to show where traffic appears to exit and block sealed
environments if the active egress does not match policy.

Useful signals:

- Public egress IP from the host gateway path.
- Public egress IP from a sealed test container.
- Country from IP geolocation.
- ASN/provider from IP geolocation.
- Whether host and sealed egress identity match.
- Whether egress IP matches the expected gateway server IP when applicable.

Commands:

```bash
envd gateway egress
envd gateway egress ams1
envd gateway policy set ams1 --expect-country NL --strict
envd gateway policy set ams1 --deny-country RU --strict
envd gateway policy clear ams1
```

Example output:

```text
Gateway:       ams1
Remote IP:     1.2.3.4
Host egress:   1.2.3.4  NL  ASxxxxx
Sealed egress: 1.2.3.4  NL  ASxxxxx
Policy:        expect-country NL, strict
Result:        OK
```

Policy rules:

- Egress policy checks should run during `gateway install`, `gateway use`,
  internal gateway reconciliation, `doctor --deep`, and sealed environment
  startup.
- If `--strict` is enabled and policy cannot be verified, fail closed.
- If host egress and sealed egress differ, fail closed for sealed environments.
- If egress appears to be direct host internet instead of the gateway, fail
  closed.
- Country checks are useful but not perfectly reliable because IP geolocation can
  be stale, inconsistent, or unavailable.
- Exact egress IP and ASN checks are stronger than country alone, but still
  should be treated as verification signals, not cryptographic proof.

Country policy is therefore a guardrail, not the primary leak-prevention
mechanism. The primary leak-prevention mechanism is still sealed routing plus
kill-switch default drop.

### Users

```bash
envd user add phone
envd user rm phone
envd user uri phone
envd user list
envd user disable phone
envd user enable phone
```

`user uri <user>` prints a provider-specific import URI suitable for apps.

### Identities

```bash
envd identity add work
envd identity policy set work --require sealed
envd identity policy set work --expect-country NL --strict
envd identity list
envd allow dev1 git --once
```

Identities define account credentials and the network policy required before
those credentials can be used inside an environment.

### Proxy

```bash
envd proxy
envd proxy test
envd proxy logs
```

`envd proxy` prints stable connection details:

```text
SOCKS: 127.0.0.1:11080
HTTP:  127.0.0.1:11081
Status: OK
Remote egress: x.x.x.x
```

### Internet And Hosting Intelligence

```bash
envd internet status
envd internet report
envd hosting check
envd hosting list
envd hosting shortlist
envd gateway risk ams1
```

These commands summarize censorship/reachability signals, hosting/provider
reachability, gateway risk, and whether the user has enough gateway diversity.
They should not be required in normal daily use, but they are useful for planning
and for understanding whether failures are local, provider-specific,
protocol-specific, or broad network disruption.

### Runtime Assets

Runtime assets are internal. Normal commands should fetch, verify, build, or
restore required assets/images automatically when safe.

`envd` should keep a managed runtime asset cache outside normal user project
state. If a user runs `docker image prune -a` or otherwise deletes images, the
next command that needs those images should repair automatically.

Installed `envd` binaries must be self-contained for envd-owned runtime assets.
The binary embeds the default dev container, sidecar, project-Docker build
contexts, and gateway render templates. A repo checkout may be used during local
development, but installed commands must not require `dev-containers/`,
`deploy/gateway/`, copied compose files, or an `example.env`.

Normal gateway operation is state-driven:

```text
encrypted gateway record -> embedded gateway template -> envd data/runtime dir
```

`envd gateway install` and `envd gateway use` are the normal path. `gateway use`
materializes `config.json` and the local gateway compose file under the envd
data directory from encrypted state. `gateway import-local` exists only to
migrate old manual `.env` setups into encrypted state; it is not the normal UX
and should not be required after installation.

The asset cache should include:

- Pinned Xray/gateway image or build context.
- Pinned sidecar image or build context.
- Pinned dev base image or build context.
- Provider binaries/checksums if building images locally.

Docker image loss should be diagnosable and repairable:

```text
FAIL Required image missing: envd/net-sidecar:<version>
Action: envd is repairing automatically
```

If automatic repair fails:

```text
FAIL Required image missing: envd/net-sidecar:<version>
Auto-repair failed: registry unavailable
Action: envd doctor --deep
```

### Environments

```bash
envd run dev1
envd run dev1 --network sealed
envd run dev1 --network direct
envd run dev1 --network offline
envd shell dev1
envd stop dev1
envd start dev1
envd restart dev1
envd rm dev1
envd ps
envd inspect dev1
envd network set dev1 sealed
```

`envd ps` should expose operational state, not just container names:

```text
NAME      STATE    NET      VPN     STORAGE    EGRESS     IDENTITY  PROFILE  ISSUE
dev1      running  sealed   ok      plain      NL x.x.x.x work      default  -
dev2      stopped  direct   n/a     plain      host       blocked   web      identity requires sealed
dev4      running  sealed   ok      plain      NL x.x.x.x risky     default  raw credential mount
safe      stopped  sealed   ok      protected  NL x.x.x.x work      default  -
```

The `NET` column is required. A user should always know whether an environment is
sealed, direct, or offline. For sealed environments, `EGRESS` should show the
last verified gateway egress identity when available. The `STORAGE` column is
also required so plain storage is never confused with encrypted protected
storage.

`envd ps` must not show anonymous image IDs as the primary identity. If Docker
only has an image ID, that is a recovery signal, not a normal state. The source
of truth should be the envd environment spec:

- Environment name.
- Network mode.
- Profile name and profile version.
- Image tag and expected digest when available.
- Volume names.
- Sidecar/runtime versions.
- Creation and last migration timestamps.

Example unhealthy state:

```text
NAME          STATE    NET     VPN   EGRESS     PROFILE  IMAGE          ISSUE
books         running  sealed  ok    NL x.x.x.x default  9df44ebfc908   image identity drift
```

Expected action:

```text
envd repairs the declared image automatically on next start/recreate.
envd doctor --deep explains if automatic repair cannot finish.
```

### Idle Supervisor And Auto-Stop

Many environments will be created with `envd run` and then forgotten. envd should
clean these up automatically without making the user micromanage containers.

This is resource management, not a security primitive. `envd lock` remains the
explicit security action.

Default behavior:

```text
idle stop enabled
default stop-after 3h
only stop when envd is confident the environment is unused
```

An environment is considered active if any of these are true:

- An envd-owned shell, SSH, VS Code, or one-shot command session is attached.
- An envd-managed port forward has active connections.
- An envd-managed service/app runtime is running and marked keep-alive.
- A sealed project Docker operation is running.
- A profile build, migration, recovery-point operation, or repair is running.
- envd cannot confidently distinguish baseline container processes from user
  work.

An environment can be auto-stopped only when:

- No envd-owned access sessions are attached.
- No envd-managed keep-alive service is running.
- No active envd-managed port connections exist.
- No envd-managed project Docker operation is active.
- No risky migration, recovery-point, or repair operation is active.
- The environment has stayed idle for the configured grace period.

When auto-stop happens:

- Stop the dev environment.
- Stop its sidecar and sealed project Docker engine if present.
- Close protected storage if the environment uses it.
- Keep envd state, recovery points, and profile images intact.
- Record the reason in events.
- Show the stop reason in `envd ps` and `envd why <env>`.

Expected status:

```text
NAME   STATE    IDLE       STORAGE    ISSUE
books  stopped  idle 3h    plain      auto-stopped, envd start books
api    running  active     plain      VS Code attached
safe   stopped  idle 3h    protected  protected storage closed
```

Configuration should stay simple:

```bash
envd run books --idle-stop 3h
envd run db --keep-running
envd inspect books
```

Project manifests may declare non-secret idle intent:

```yaml
idle:
  stop_after: 3h
  keep_running: false
```

Rules:

- Auto-stop must never delete environment data.
- Auto-stop must never prune images, layers, caches, or recovery points.
- Auto-stop should be conservative. If envd is unsure whether user work is
  active, leave the environment running and explain why.
- Auto-stop should not apply to raw host Docker containers except for registered
  cleanup on explicit `envd lock`.
- `envd start <env>` should restore the environment from its declared storage
  mode.
- `envd code <env>` or `envd shell <env>` should start a stopped environment
  lazily when safe.
- Users should not need to keep a terminal open just to prevent stop; declared
  services or `--keep-running` are the explicit keep-alive mechanism.

### Supervisor Process

envd may run a small user-level supervisor to coordinate lifecycle events.

Responsibilities:

- Track envd-owned sessions and editor/SSH proxy connections.
- Track idle timers and perform conservative auto-stop.
- Coordinate `envd lock` broadcasts to envd-owned terminals.
- Process registered Docker cleanup queued after core sealing.
- Watch envd-managed port forward lifecycle.
- Record lifecycle events.

Efficiency requirements:

- User-level process only; no root daemon for normal operation.
- Event-driven where possible; no busy polling.
- Coarse timers for idle checks, for example minute-scale, not second-scale.
- No continuous network probes in the idle loop.
- No battery-expensive Docker scans in tight loops.
- Start on demand when envd has active environments, sessions, proxy targets, or
  pending cleanup.
- Sleep or exit when there is nothing to manage.
- Foreground envd commands must still reconcile state if the supervisor is not
  running.

Platform model:

- macOS: user `launchd` agent or on-demand process.
- Linux: user `systemd` service/timer or on-demand process.
- No platform-specific secret store dependency.
- Same behavior at the envd command level on macOS and Linux.

The supervisor is a lifecycle coordinator, not an authority that weakens the
security model. If it crashes or is killed, the next envd command should detect
stale state, reconcile safely, and fail closed where needed.

### Workspaces And Project Manifests

An environment should know what project/workspace it belongs to.

Default behavior:

```bash
cd ~/repo/books
envd run books
```

If the command is run inside a Git repo or normal project directory, envd should
remember that source path and use it as the environment workspace by default. The
user should not need to repeat mount flags for ordinary projects.

Default workspace storage is plain. This is intentional for normal development:
it is fast, simple, compatible with existing editors/tools, and does not pretend
that `envd lock` can hide files already present on the host filesystem.

Useful commands:

```bash
envd run books .
envd inspect books
envd code books
```

`envd inspect books` should show:

```text
Workspace: /Users/c/repo/books -> /workspace/books
Profile:   web
Network:   sealed
Storage:   plain
Manifest:  .envd.yaml
```

Workspace sync rules:

- Default creation bind-mounts or otherwise exposes the remembered project path as
  plain workspace storage.
- Git remotes and identity operations go through envd-managed policy.
- `envd inspect` shows the remembered host source path, mount path, and storage
  mode.
- Protected storage is explicit, for example `envd run books --storage protected`.
- envd must never label a raw host workspace or normal Docker volume as protected
  storage.

Optional repo-local manifest:

```yaml
profile: web
network: sealed
packages:
  apt:
    - ffmpeg
  npm:
    - pnpm
ports:
  - 3000
services:
  - postgres
secrets:
  required:
    - GITHUB_TOKEN
```

Manifest rules:

- `.envd.yaml` is optional.
- It should contain non-secret project intent only.
- Secrets must live in the encrypted envd store, not the repo.
- The manifest may declare required secret names, but not secret values.
- Local user overrides should live outside the repo.
- `envd run` should read the manifest automatically if present.
- If required secrets are missing, `envd run` should ask once, save them
  encrypted, and continue.
- If the manifest would change an existing environment, envd should show a
  concise plan and ask before migration.

This gives teams or future machines a simple "clone repo, run envd" path without
turning envd into a complex orchestration platform.

### Data And Automatic Recovery Points

Volumes are user data. Rebuilds and migrations are only safe if volume handling
is explicit and recoverable.

Rules:

- Profile migration, network mode changes, and major image repairs should create
  an encrypted recovery point automatically when volumes are affected.
- Recovery points are internal safety points, not a user-managed archive product.
- Recovery points should be local and fast when the storage backend supports it.
- Recovery points are encrypted by default.
- Recovery points should not include envd secrets unless they are part of the
  encrypted envd state required for that environment's recovery.
- `envd rm <env>` is the explicit removal action. After confirmation, it should
  remove the environment, envd-managed storage, env-owned recovery points, and
  env state together.
- `envd ps`, `envd inspect`, and `envd why` may mention that an automatic
  recovery point exists when it is relevant, but users should not manage recovery
  points during normal use.

This protects the user from "small image/package change destroyed my dev state"
failure modes.

### Recovery Point Retention

Recovery points must not grow forever. envd should keep only what is useful for
current environments and automatically delete the rest.

Default lifecycle:

```text
keep the latest recovery point per active environment
keep recent pre-change recovery points for a short rollback window
delete recovery points for envs removed by envd rm
prune only after the current environment storage is verified
```

Rules:

- Recovery point pruning is automatic.
- No normal recovery-point management commands.
- Pruning deletes only envd-managed recovery points, never live environment data.
- Pruning should happen only after storage integrity verification succeeds.
- Keep enough recent recovery points to rollback the latest risky operation.
- Remove old recovery points when the environment is stable and they are no
  longer needed.
- Remove all env-owned recovery points when `envd rm <env>` removes that
  environment.
- If recovery point storage grows unexpectedly, `envd doctor` and `envd inspect`
  should explain why envd is keeping them.

### Services And Ports

Existing service and port concepts should remain, but under the Go control
plane:

```bash
envd service create dev1 postgres
envd service ls dev1
envd port open dev1 3000
envd port ls dev1
envd port close dev1 3000
```

### Docker From Dev Environments

Running Docker from inside a dev environment is not the same as running a normal
process inside that environment.

When a dev container uses the host Docker daemon, Docker creates new sibling
containers on the host. Those sibling containers do not automatically share the
sealed dev container's network namespace. Without envd involvement, they may use
normal Docker networking and bypass the gateway.

Principle:

```text
sealed parent environment does not automatically make host Docker containers sealed
```

Raw host Docker is outside the sealed guarantee. If a process talks to the host
Docker daemon, Docker creates sibling containers on the host, and those
containers may use normal Docker networking.

envd cannot make arbitrary host Docker safe unless envd controls the Docker API
endpoint being used. Global shell wrappers, warnings, or PATH tricks are not a
security boundary because users and tools can bypass them.

### Sealed Project Docker

The safe model is a Docker-compatible project engine managed by envd.

This is a major post-v1 subsystem, not a casual follow-on feature. It should ship
only after sealed single-container environments, gateway switching, protected
storage, and identity denial are already reliable and release-gated.

User experience:

```bash
envd shell books
docker compose up
```

Inside an envd shell, `docker` and `docker compose` should talk to the
envd-managed project Docker engine, not the host Docker daemon. The user still
uses standard Docker and Compose commands. envd does not reimplement Compose
semantics.

Implemented backend: sealed environments start an envd-owned rootless Docker
project daemon from `envd-project-docker:27-rootless`. The daemon shares the
sealed sidecar network namespace, listens only inside that namespace, and the
dev container receives `DOCKER_HOST=tcp://127.0.0.1:2375`. The host Docker
socket is not mounted into the dev container.

Project engine rules:

- The host Docker socket is not mounted by default.
- `DOCKER_HOST` or Docker context inside the env points to the envd project
  engine.
- The project engine is created lazily on first Docker use.
- The project engine runs under envd control and uses the sealed gateway route.
- Images, Compose networks, Compose volumes, and build cache for the project
  engine live in envd-managed storage using the environment's declared storage
  mode.
- If the sealed route is unhealthy, project Docker operations fail closed.
- DNS, IPv4, and IPv6 for project containers must follow the sealed network
  policy.
- Compose `ports:` must not silently publish services to the host or LAN. Host
  exposure goes through envd port policy.
- Compose host path mounts are allowed only for envd-approved workspace paths.
  Arbitrary host paths are blocked or require an explicit unsafe override.
- Compose features that break isolation, such as host networking, raw host
  Docker socket mounts, privileged host access, or arbitrary device mounts, are
  blocked by default.

`hack/verify/verify-project-docker.sh` is the release gate for this subsystem. It
creates a sealed env, verifies `docker` and `docker compose` use the managed
endpoint, verifies project-container egress matches gateway egress, proves
published project ports are not reachable from the host, disconnects the sidecar
from the gateway network, and proves project Docker egress fails closed.

This makes common Compose development safe without inventing an `envd compose`
command.

Expected status:

```text
NAME   NET     DOCKER          VPN   STORAGE    ISSUE
books  sealed  sealed-engine  ok    protected  -
```

Useful commands:

```bash
envd inspect books
envd doctor --deep
```

Normal usage remains standard `docker` and `docker compose` inside the envd
shell. envd should create, repair, stop, and clean up the sealed project Docker
engine automatically when it has enough context. If it cannot, `envd doctor
--deep` explains why.

Backend decision:

- The initial secure backend should be a rootless Docker project daemon managed
  by envd.
- containerd/nerdctl remains a later option only if Docker Compose compatibility
  is sufficient for real projects.
- Privileged Docker-in-Docker is allowed only as an explicit compatibility
  backend, never as the secure default.

The backend is otherwise an implementation detail. The invariant is that the
Docker API endpoint used inside envd is envd-managed, sealed, protected, and
fail-closed.

### Raw Host Docker

Raw Docker opt-in:

```bash
envd run dev1 --docker raw
```

Rules:

- Raw host Docker access must be shown in `envd ps` as a risk.
- Raw host Docker containers are not considered sealed.
- Protected identities are denied while raw host Docker is attached unless a
  separate explicit identity policy allows it.
- envd should detect unmanaged host Docker containers and report them in
  `envd status`, but detection is informational only.
- envd should not install global `docker` wrappers as a security feature.
- If a project truly requires raw host Docker, envd must label the environment
  outside the sealed Docker guarantee.

### Registered Docker Artifacts

Some projects may still need host Docker or Compose. envd can make lock cleanup
fast and predictable only for Docker artifacts that are explicitly registered as
envd-owned.

Registration model:

```text
Docker label     dev.envd.owner=<env-id>
Docker label     dev.envd.lock=remove-container
Docker label     dev.envd.role=app|service|build
envd state       maps labels to encrypted human project/env names
```

Help output:

- `envd lock --help` and Docker-related help should show copyable label snippets
  for Compose and `docker run`.
- Help must explain that cleanup applies only to running containers with matching
  container labels.
- Dockerfile image labels may document intended policy, but they are not enough
  by themselves. The running container must be labeled by Compose, `docker run`,
  or an envd-managed project engine.

Compose example:

```yaml
services:
  web:
    build: .
    labels:
      dev.envd.owner: "${ENVD_ENV_ID}"
      dev.envd.lock: "remove-container"
      dev.envd.role: "app"
```

`docker run` example:

```bash
docker run \
  --label "dev.envd.owner=${ENVD_ENV_ID}" \
  --label "dev.envd.lock=remove-container" \
  --label "dev.envd.role=app" \
  image
```

Optional Dockerfile provenance labels:

```dockerfile
LABEL dev.envd.role="app"
LABEL dev.envd.lock="remove-container"
```

`envd shell <env>` should export `ENVD_ENV_ID` so Compose and shell commands can
attach artifacts to the current env without exposing the human environment name.

`envd lock` behavior for registered artifacts:

- After core sealing succeeds, enqueue registered host Docker cleanup
  asynchronously.
- Stop registered app/service containers.
- Remove registered app/service containers after stop.
- Remove registered temporary/build containers where safe.
- Close envd-managed port forwards for those artifacts.
- Leave images, layers, build cache, and volumes alone unless envd owns them
  inside protected storage.
- Record cleanup progress and failures in events.
- Report pending or failed cleanup in `envd status`.

Important boundary:

- Stopping/removing registered host Docker containers prevents easy continued use
  of the running app.
- It is cleanup and access reduction, not encrypted-at-rest security.
- Registered host Docker cleanup must never block core envd sealing.
- Docker image layers, build cache, logs, and volumes may still contain data if
  they were created in raw host Docker.
- Sensitive code, secrets, and identities should not be put into raw host Docker
  layers or logs.
- For protected guarantees, the app runtime must be envd-managed from the
  beginning, not merely cleaned up on lock.

## Secure-By-Default And Untrusted Machines

envd should be secure by default on machines and networks the user does not fully
trust. Encryption, brokered identities, and fail-closed networking are baseline
behavior, not optional hardening.

Threats envd should address:

- Someone steals the envd binary.
- Someone copies `~/.config/envd`, `~/.local/state/envd`, Docker volumes, or
  recovery points while envd is locked.
- Someone tries to use stored server passwords, gateway profiles, identities, or
  project secrets without the master password.
- Someone starts an environment in direct networking and tries to use protected
  identities.
- Someone opens SSH/Git/tooling from a stale or unsafe network state.

Threats envd cannot fully solve:

- The host OS is actively compromised while envd is unlocked.
- An attacker has administrator/root access while decrypted volumes are mounted.
- A malicious employer-owned device records keystrokes, screen, memory, or Docker
  daemon traffic.
- The user manually copies secrets into the container or mounts raw host
  credential directories.
- The user explicitly enables raw Docker and runs untrusted containers.

Principle:

```text
envd unlocked      -> access allowed only when policy passes
envd locked        -> access killed, envd workloads stopped, protected storage closed
envd stopped       -> work stopped; protected storage encrypted if selected
host compromised while active -> outside envd's full guarantee
```

Locking envd is a deterministic shutdown posture for envd-owned work. It kills
envd-managed access sessions, stops accepting new shell/SSH access, prevents new
secret/identity grants, stops envd-managed workloads, and closes protected
storage when present. Plain storage remains plain host/Docker data. The behavior
should be simple and predictable.

Important limit: a process killed by lock can only preserve work it already
wrote to storage. Arbitrary in-memory state is not recoverable unless the tool
itself saved it.

UX cost:

- `envd lock` is intentionally disruptive.
- Help text and confirmation output must say that active envd shells, editor/SSH
  sessions, service/app runtimes, and unsaved in-memory work will be terminated.
- The command should be fast and deterministic, but it should not pretend to be a
  pause/resume feature.
- Users who need long-running work should commit/save state or use an explicit
  keep-running workflow that does not weaken lock semantics.

```text
envd lock       kill access, stop envd-owned workloads, close protected storage
envd stop <env> stop one environment; protected storage closes if selected
```

Full encrypted at-rest closure exists only for protected storage and happens when
the protected environment is stopped, `envd lock` stops it, or envd performs a
full shutdown.

### Secure State Boundary

The encrypted envd store is not only for passwords. It is the default home for
state that can reveal the user's work, infrastructure, accounts, or habits.

Encrypted state should include:

- Gateway profiles, remote hosts, provider accounts, and server credentials.
- Environment names, project paths, profile assignments, and identity bindings.
- Identity profiles, secret references, broker grants, and policy decisions.
- Local event history, previous diagnostic results, hosting check history, and
  gateway risk history.
- Storage metadata and per-environment storage keys.
- Project manifests after they are imported into envd state.

Plain host state is allowed only when it is public, required before unlock, or
not meaningfully sensitive:

- The envd binary and installation metadata.
- Public signed runtime assets, pinned image definitions, and public hosting
  catalog data.
- Opaque Docker container, network, volume, and image identifiers.
- Non-secret lock files, PID files, and crash markers that contain no project,
  gateway, identity, or account names.

Docker object names, labels, and logs must not be treated as private. Therefore,
envd-managed Docker objects should use opaque IDs by default:

```text
human name in envd       books
Docker container name    envd-e-8f6c2a91
Docker network name      envd-n-4b109bd0
Docker volume/mount id   envd-s-91b2d7aa
```

`envd ps` maps opaque IDs back to human names only after encrypted state is
available. When locked, envd may show a minimal locked status, but it should not
print encrypted names or paths without unlock.

Migration from older installations should detect human-readable Docker object
names and offer a controlled rename/recreate plan where safe.

### Lock Model

The envd binary is not secret. Security must not depend on hiding the executable
or the config file names.

Commands:

```bash
envd lock
envd status
```

Rules:

- Master password is required to unlock encrypted envd state.
- Master password is never stored.
- Use memory-hard password-based key derivation, such as Argon2id, with random
  salt and calibrated cost.
- Use authenticated encryption for the store and protected metadata.
- Optional hardware-key/passkey support may be added later, but it should not be
  required.
- `envd lock` is the only lock security primitive.
- Host screen-lock, sleep, logout, idle timers, and OS session state are not part
  of envd's security model.
- Lock revokes all identity broker grants.
- Lock terminates envd-managed shell, SSH, and one-shot command sessions.
- Lock prevents new envd-managed shell, one-shot command, SSH, identity, secret,
  and gateway management operations until unlock.
- Lock does not create new decrypted mounts.
- Lock does not expose envd secrets, identity material, or decrypted storage
  through new access paths.
- Stopping an environment closes protected storage when the environment uses it.
- `envd lock` stops envd-managed environments and service/app runtimes, then
  closes protected storage where present.
- If an operation cannot be made safe while locked, it must fail closed.
- There is no required `unlock` command in normal use. The next stateful command
  prompts for the master password and reopens only the state it needs.

SSH/access behavior:

- `envd lock` must terminate envd-managed SSH clients and server-side session
  processes.
- New SSH connections through envd-managed SSH endpoints must be refused while
  locked.
- envd-managed shell, one-shot command, and SSH access must require unlock.
- envd should not expose plain SSH daemons that remain reachable independently of
  envd's lock state.

### Editor And SSH Access

Home-laptop UX should stay smooth while envd is unlocked. VS Code reconnects
should not require hunting for server passwords or repeatedly copying keys.

Expected commands:

```bash
envd run books
envd code books
```

Access model:

```text
VS Code / ssh client -> envd ssh-proxy <env> -> envd policy check -> container
```

The preferred VS Code integration is an SSH `ProxyCommand`, not a durable SSH
server exposed on the network:

```sshconfig
Host envd-books
  HostName envd
  User dev
  Port 22
  ProxyCommand envd ssh-proxy books
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ~/.ssh/envd_known_hosts
```

Rules:

- `envd code <env>` prints or launches a VS Code Remote SSH target that uses
  `envd ssh-proxy <env>`.
- Generated SSH targets should use envd-owned aliases and never expose a durable
  host SSH listener.
- The proxy must require envd to be unlocked.
- The proxy must verify the target environment is running, required storage
  policy is satisfied, network policy is valid, and the caller is local.
- No password login.
- No container-owned reusable login key as the security boundary.
- Any client key or certificate material must be envd-managed, encrypted at
  rest, and scoped to envd access.
- Short-lived SSH certificates are preferred over long-lived static keys where
  practical.
- `envd lock` must terminate active editor/SSH sessions and make the proxy
  refuse reconnects until unlock.

If a TCP SSH listener is required for tool compatibility:

- Bind to `127.0.0.1` or `::1` only by default.
- Treat localhost binding as exposure reduction, not the only security boundary.
- Require envd-managed authentication and unlocked state.
- Prefer a Unix domain socket with user-only permissions where the platform and
  tool support it.
- Never listen on `0.0.0.0`, LAN addresses, or public interfaces unless the user
  enables an explicit unsafe remote-access mode.

Unsafe remote access mode, if ever added, must be visibly outside the default
security model and must be denied protected identities unless an explicit policy
allows it.

Manual lock only:

- There is no automatic lock in the security model.
- `envd lock` must apply synchronously and deterministically after stopping
  envd-managed workloads.
- envd must not infer safety from host screen-lock, sleep, logout, or idle state.
- `envd status` reports envd's own lock state, active envd-managed sessions,
  identity grants, storage mounts, and network policy state.
- Access session types must be controlled by envd. If a session type cannot be
  terminated deterministically, envd must not expose it.

Lock ordering:

1. Persist locked state and reject new envd access.
2. Revoke identity broker grants and close secret/vault access.
3. Broadcast lock to envd-owned terminal sessions.
4. Stop envd-managed environments, service/app runtimes, and sealed project
   Docker engines.
5. Close protected storage for stopped environments.
6. Mark core sealing complete.
7. Queue registered host Docker cleanup asynchronously.
8. Record cleanup progress, completion, or failure in events/status.

Core sealing must not wait on registered host Docker cleanup. If asynchronous
cleanup is slow, blocked, or fails, envd remains locked and protected storage
remains closed.

Active tool behavior:

- During normal unlocked use, environment storage appears as a normal filesystem
  to tools such as editors, Git, Codex, Claude Code, package managers, and
  language servers.
- On lock, tools running under envd-managed shell, SSH, or one-shot command
  sessions are terminated.
- Files already written to environment storage are preserved.
- Arbitrary in-memory tool state is preserved only if the tool saved it.
- This is intentionally simple: lock means envd-owned work stops.

`envd lock` is for the "make everything envd owns disappear now" case:

- Kill envd-managed access sessions.
- Revoke identity and secret grants.
- Close envd-managed port forwards.
- Stop envd-managed dev environments.
- Stop envd-managed services/app runtimes.
- Stop sealed project Docker engines if enabled.
- Stop/remove envd-marked app containers that are registered for lock cleanup.
- Remove envd-managed temporary/build containers where safe.
- Close protected storage for stopped environments.
- Leave raw host Docker containers alone, but report them as outside envd
  guarantee.

Terminal custody mode:

- `envd lock` is a security cutoff, not a screen-hiding guarantee.
- If sensitive work happens only inside envd-owned terminal sessions, envd can
  provide a strong practical visual lock for those sessions.
- `envd shell <env>` should own the local PTY and register it as an envd-managed
  access session.
- `envd lock` should broadcast a lock event to all envd-owned terminal sessions.
- Each envd-owned terminal client should stop accepting input, send
  best-supported terminal reset/clear-scrollback sequences, print a minimal
  locked message, and exit.
- The terminal that ran `envd lock` should also clear itself and end on the same
  locked message.
- This is reliable only for envd-owned terminal sessions on compatible terminal
  emulators with no external terminal logging or multiplexer history.
- The hard guarantee remains killed envd-managed access sessions, revoked grants,
  and closed storage for stopped environments.
- Terminal custody mode is useful against casual visual exposure when the user
  works only through envd terminals, but it is not a promise to clean arbitrary
  host UI state.
- envd must not claim it can clear non-envd terminals, editor panes, terminal
  logs, tmux/screen history outside envd control, screenshots, screen
  recordings, copied output, or OS-level recent-window previews.
- If a user needs the computer display hidden from someone physically nearby,
  they should also lock the OS session or close the laptop. envd must not treat
  OS screen state as part of its own security model.

Avoid:

- Date-based password lists.
- Locally stored password schedules.
- Security based on changing the system clock.

Reason: if the schedule is local, it can be stolen; if time is local, it can be
manipulated. The right primitive is a key derived from something the user knows,
optionally combined with something the user has.

### Safe Container Storage

User-facing contract:

```text
envd run <env>                     -> creates normal plain workspace storage
envd run <env> --storage protected -> creates encrypted protected storage
envd lock                          -> stops envd workloads and revokes access
envd stop <env>                    -> stops one environment
```

The user should not need to think about Docker volumes and mount points during
normal use. Crypto plumbing exists only when protected storage is explicitly
selected.

What the user can trust:

- Default persistent environment data is plain and should be treated like normal
  local development files.
- Plain storage is compatible, fast, and easy to inspect with normal host tools.
- envd must label plain storage honestly and never describe it as encrypted.
- When protected storage is selected, environment data is stored in envd-managed
  encrypted storage.
- When a protected environment is stopped, its data is encrypted at rest.
- When an environment is running, tools see a normal filesystem.
- `envd lock` stops envd-managed environments, revokes secrets/identity grants,
  and closes protected storage when present.
- `envd ps` and `envd inspect` show storage state plainly.

Visible storage states:

```text
plain-active       environment running with normal unencrypted storage
plain-stopped      environment stopped, data remains plain on host/Docker storage
protected-active   environment running with encrypted backend mounted
protected-closed   environment stopped/locked, encrypted at rest
```

Implementation detail:

Docker volumes and host bind mounts are not encrypted by Docker. They are valid
for default plain storage, but envd must label them as plain. When protected
storage is selected, envd uses encrypted APFS/LUKS-backed storage and mounts it
only for the environment that needs it.

Modes:

```text
plain      normal host workspace or Docker-managed storage, unencrypted
protected  envd-managed encrypted volume backing store
```

Plain storage behavior:

- Plain storage is the default.
- Plain storage survives `envd lock` and `envd stop` as normal local data.
- `envd lock` does not make plain storage unreadable to someone with host file
  access.
- Plain storage may still use sealed networking and envd-managed secrets.
- Protected identity policies may require protected storage for sensitive
  identities.

Protected storage behavior:

- Environment data is stored encrypted at rest.
- Running environments get a normal filesystem view.
- `envd lock` kills envd-managed access sessions, stops envd-managed
  environments, and closes protected storage.
- `envd stop <env>` stops work and returns storage to encrypted-at-rest state.
- Recovery points remain encrypted by default.
- Recovery requires master password or recovery key.
- Protected storage metadata is tracked in envd state.

Deletion and tamper model:

- Encryption prevents reading protected data when the environment is stopped.
- While an environment is active, `envd lock` blocks envd-managed access but a
  compromised host/admin may still be able to inspect active runtime state.
- Encryption does not prevent someone with filesystem access from deleting the
  encrypted backing files.
- Local recovery points help with accidental mistakes, but they can also be
  deleted by someone with host filesystem access.
- Reliable protection against deletion requires encrypted copies outside the
  local machine, if that is added later.
- envd should manage local recovery points automatically and invisibly.
- envd should detect missing, truncated, or tampered storage metadata and fail
  closed instead of creating a fresh empty environment silently.

Implementation options:

- Linux: fscrypt, LUKS-backed image, or a portable encrypted filesystem layer.
- macOS: encrypted APFS sparse image or a portable encrypted filesystem layer.
- Cross-platform recovery export may exist later, but is not normal UX.

Implemented and planned backend model:

```text
envd storage API        portable behavior and semantics
macOS at-rest backend   encrypted APFS sparse image
Linux at-rest backend   LUKS2/dm-crypt-backed image
active storage          envd-owned temporary Docker volumes while unlocked/running
recovery points         envd-managed encrypted local restore points
fallback backend        none by default; fail closed if native backend unavailable
```

Docker runtimes do not reliably use host encrypted filesystem mounts as normal
project storage across platforms. envd therefore treats APFS/LUKS images as the
protected at-rest store: `envd start` hydrates fresh envd-owned Docker volumes
from the image, and `envd stop`/`envd lock` exports those volumes back into the
encrypted image, removes the active container/volumes, and detaches/closes the
image. While the environment is running, data is inside active Docker volumes and
should be treated as unlocked plaintext. After stop/lock, env-owned persistent
data is only in the encrypted APFS/LUKS image.

Rationale:

- Portable UX matters; portable live encryption implementation is less important.
- A single custom cross-platform encrypted filesystem would be more code and more
  risk.
- FUSE-style portability can add dependencies, platform friction, and reliability
  problems.
- Native encrypted disk/file-system backends are mature and better aligned with
  each OS.
- The portable layer should be envd's storage API, metadata model, recovery-point
  semantics, lock/unlock semantics, and tests.

Key hierarchy:

```text
master password -> Argon2id-derived unlock key
unlock key      -> decrypts envd store
envd store      -> stores per-environment storage keys encrypted
storage key     -> unlocks APFS/LUKS protected environment storage
```

The master password is never stored. Per-environment storage keys can be rotated
independently where the backend supports it.

Performance and reliability:

- Prefer mature OS/filesystem encryption or encrypted disk images over custom
  per-file crypto.
- Use vetted encryption primitives and libraries only.
- Expect low overhead for normal source-code and package-manager workloads. The
  APFS/LUKS at-rest backend pays most cost on start/stop/lock export/import
  rather than on every file operation while the environment is running.
- Large database workloads, many-small-file workloads, and FUSE-style encrypted
  filesystems may have noticeable overhead.
- `envd inspect` and `envd doctor --deep` should show backend type, mount state,
  and last verification.
- `envd doctor --deep` should verify protected storage mount/unmount behavior.
- If the selected backend is slow or less reliable on the current platform, envd
  should warn and explain the tradeoff.
- If protected storage cannot be mounted, verified, locked, or recovered safely,
  the environment must fail closed.
- Crash recovery must be explicit: detect dirty mounts, run backend-specific
  checks when available, and never silently attach corrupted storage.

Rules:

- Do not pretend normal Docker volumes are encrypted.
- Persistent unencrypted environment storage is the default normal mode.
- `envd ps` and `envd inspect` must show storage mode.
- Protected storage is explicit.
- Identity policies may require protected storage.
- If protected storage is requested and cannot be mounted safely, environment
  startup fails closed.

Example:

```text
NAME   NET     VPN   STORAGE    IDENTITY  ISSUE
books  sealed  ok    plain      work      storage is not encrypted
safe   sealed  ok    protected  work      -
```

### Security Defaults

Default behavior:

- `network = sealed`
- `storage = plain`
- `identity = brokered`
- raw Docker disabled
- direct host credential mounts disabled
- strict egress policy required for protected identities
- explicit `envd lock` required for access cutoff
- event logging enabled
- recovery points encrypted

These defaults are appropriate for untrusted locations, shared machines, travel,
and workspaces where accidental account exposure would be costly, but storage
encryption is not assumed unless `--storage protected` is selected. There should
not be a normal "silent insecure envd mode"; downgrades such as `--network
direct`, raw Docker access, or plain storage must be explicit and visible in
status/inspect output. Plain storage is the default for normal development, not a
claim of at-rest secrecy.

### Multi-Hop Gateways

envd can support chained gateways for stronger network compartmentalization.

Goal:

```text
local machine -> regional entry gateway -> final exit gateway -> internet
```

Use cases:

- The local network should see only a connection to a less suspicious regional
  entry point.
- The final exit IP should be different from the entry provider.
- Provider/ASN diversity is desired.
- A gateway should be replaceable without changing the sealed environment model.

Commands:

```bash
envd gateway chain create workchain --entry reg1 --exit ams1
envd gateway use workchain
envd gateway chain status workchain
envd gateway chain doctor workchain
```

Rules:

- Each hop is a normal envd gateway profile with its own provider, strategy,
  health checks, and risk score.
- The chain must be verified end-to-end before activation.
- If any hop fails, sealed environments fail closed.
- A chain must never silently degrade to only the entry hop.
- A chain must never silently bypass the chain and use direct networking.
- Chain egress policy is evaluated at the final exit, not at the entry hop.
- `envd ps` must show when a chain is active.
- Identity policy should bind to final egress policy and chain health.
- Chain topology is local envd state and should not be exposed to dev
  containers.
- More hops increase latency, cost, and operational failure points.

Limitations:

- Multi-hop does not make traffic anonymous like Tor.
- Entry provider can see the user connecting to the entry server.
- Exit provider can see egress metadata from the exit server.
- A compromised local host can still observe user actions while envd is
  unlocked.

Multi-hop is a resilience and compartmentalization feature, not a magic
anonymity guarantee.

## Diagnostics

Diagnostics are a first-class feature. `envd doctor` should be fast and useful.
`envd doctor --deep` should perform real network probes and identify the broken
layer.

### Required Checks

Host checks:

- Docker daemon reachable.
- Unmanaged host Docker containers detected and reported as outside envd
  guarantee.
- Required images available or buildable.
- envd lock/store state valid.
- Protected storage backend available when required.
- envd editor/SSH proxy targets are localhost/proxy-only and locked-state aware.
- envd supervisor state is healthy or safely recoverable.
- Xray gateway container running.
- Xray rendered config valid.
- Host SOCKS endpoint accepts connections.
- Host HTTP endpoint accepts CONNECT.
- Remote server TCP port reachable.
- Remote camouflage TLS reachable.
- Xray Reality handshake works.
- Host egress through proxy returns real HTTP response.
- Host egress IP/country/ASN collected.
- Host egress policy passes when configured.

Sealed container checks:

- Dev container exists and runs.
- Sidecar exists and runs.
- Sidecar healthcheck passes.
- Protected storage mounted only when unlocked when required.
- Project Docker engine uses envd-managed Docker endpoint when enabled.
- Project Docker engine storage is protected when enabled.
- Project Docker engine route follows sealed network policy when enabled.
- Default route is TUN.
- Kill-switch policies are installed.
- DNS resolves.
- TCP connect through tunnel works.
- TLS through tunnel works.
- Docker Hub returns expected `401`.
- Leak check confirms public IP is VPN egress.
- Sealed egress matches host/gateway egress expectation.
- Egress country/ASN policy passes when configured.
- Identity policy passes before credentials are injected.
- Identity broker denies credentials on unsafe network states.
- Kill-switch fails closed when gateway is stopped.
- Raw Docker access is reported as a risk when enabled.

### Example Healthy Output

```text
envd doctor --deep

Host Docker                 OK
Gateway container           OK
Xray config                 OK
Remote TCP 443              OK
Remote camouflage TLS       OK
Reality handshake           OK
Host SOCKS                  OK  127.0.0.1:11080
Host HTTP                   OK  127.0.0.1:11081
Host egress                 OK  x.x.x.x NL ASxxxxx
Egress policy               OK  expect-country NL

[env dev1 sealed]
Sidecar                     OK
Default route               OK  tun0
DNS                         OK
TLS through VPN             OK
Docker Hub through VPN      OK  HTTP 401
Leak check                  OK  x.x.x.x matches gateway
Egress policy               OK  NL
Kill-switch                 OK
```

### Example Failure Output

```text
FAIL Reality handshake

TCP to server:              OK
Camouflage TLS:             OK
Xray inbound:               OK
TLS through Xray:           FAIL after ClientHello

Likely causes:
- Xray client/server version mismatch
- Reality fingerprint instability
- stale Reality keys or shortId
- server-side Xray reject

Suggested actions:
- envd gateway doctor --debug
- envd gateway set fingerprint firefox
- envd gateway rollback
```

This is the kind of diagnostic that would have identified the June 2026 failure
quickly.

## Event Log And Change History

envd should keep a local event log for meaningful state changes. This is not
telemetry. It is local history for debugging and audit.

Events to record:

- Gateway installed, switched, repaired, upgraded, rolled back.
- Gateway chain created, switched, repaired, or failed.
- Gateway strategy or egress policy changed.
- Sidecars synced or failed to sync.
- Profile manifest changed.
- Profile image generation built.
- Package added/promoted/removed.
- Environment created, migrated, repaired, removed.
- Environment auto-stopped after idle timeout.
- Environment auto-stop skipped with reason.
- Protected storage locked, unlocked, mounted, unmounted, or failed.
- Recovery point created, verified, pruned, deleted, failed, or skipped.
- Network mode changed.
- Identity credentials injected or blocked by policy.
- Account-sensitive command blocked or allowed by override.
- Identity broker grant created, denied, or revoked.
- Editor/SSH proxy target created, refreshed, denied, or revoked.
- Supervisor started, stopped, crashed, recovered, or reconciled stale state.
- Internet status or hosting/provider risk changed.
- Image or asset auto-repair happened.
- Doctor found a new failure.

Commands:

```bash
envd events
envd events books
envd events gateway ams1
envd why books
```

Example:

```text
2026-06-05 10:12 gateway use ams1 -> hel1
2026-06-05 10:12 gateway reconciliation books ok
2026-06-05 10:13 doctor books fail egress policy country mismatch
2026-06-05 10:14 auto-repair books network ok
```

`envd why <env>` should summarize the current state and the recent events that
explain it:

```text
books is blocked because gateway reconciliation failed after gateway generation 17.
Last working generation: 16.
Suggested action: envd doctor --deep
```

This makes "what changed?" answerable without reading Docker/Xray logs first.

## Gateway Installation And Reconciliation

`envd` should own server and client configuration generation. This section
describes the remote management model. Xray is the first provider. Future
providers should fit the provider interface instead of changing the
dev-container model.

Remote management should be idempotent. `envd` should not behave like a one-shot
install script. It should inspect the actual server state, compare it with the
desired envd state, apply only missing or drifted changes, verify the result, and
rollback if activation fails.

Remote states:

- `unknown`: server has not been inspected yet.
- `unreachable`: SSH or TCP connection failed.
- `unmanaged`: server is reachable, but no envd-owned provider install exists.
- `adoptable`: compatible provider install exists, but is not envd-owned.
- `managed`: envd-owned provider config exists and matches expected state.
- `drifted`: envd-owned config exists, but remote state differs.
- `broken`: provider exists but service or handshake is failing.

Read-only inspection:

```bash
envd gateway inspect ams1
```

Expected output:

```text
REMOTE       ams1
SSH          ok
OS           Ubuntu 24.04
ARCH         x86_64
SYSTEMD      ok
PROVIDER     xray 26.2.6
CONFIG       envd-managed, drift none
SERVICE      running
PORT         443 open
HANDSHAKE    ok
USERS        3
LOCAL ROUTE  ok
SEALED ROUTE ok
```

If something is missing, the output should say what envd can do next:

```text
PROVIDER     missing
ACTION       envd can reinstall envd-owned provider after confirmation
```

Fresh server bootstrap:

1. Connect to VPS over SSH.
2. Detect OS and architecture.
3. Install pinned Xray version.
4. Generate Reality keys if not present.
5. Generate server config.
6. Install systemd service.
7. Open required firewall port if a supported firewall is detected.
8. Start Xray.
9. Verify from local machine.
10. Store local gateway profile.

Existing server flows:

```bash
envd gateway inspect ams1
envd gateway install ams1 --adopt
envd gateway install ams1 --replace
```

Rules:

- `inspect` is always read-only.
- `adopt` imports compatible existing provider state without destroying unknown
  users.
- `replace` is explicit and destructive to the provider config, but must preserve
  a previous envd-owned config for rollback first.
- Automatic reconciliation is safe and idempotent for envd-owned resources.
- Unknown non-envd configs must not be overwritten by default.
- Provider config files should include an envd ownership marker.
- Remote changes should be applied atomically: write candidate config, validate,
  restart provider, verify handshake, then mark active.
- Failed activation should rollback to the previous known-good remote config.

Remote provider footprint rules:

- One active remote strategy per gateway by default.
- Do not install multiple heavy providers unless explicitly requested.
- Do not run inactive provider services by default.
- Keep candidate configs staged but disabled when possible.
- Check memory, disk, CPU architecture, and systemd availability before install.
- Refuse or warn before installing on servers below the provider's minimum
  resource budget.
- envd should remove inactive envd-owned providers and stale candidate configs
  automatically when applying a replacement, finishing an upgrade, or removing a
  gateway.
- Unknown non-envd services must not be stopped or removed.

Example:

```bash
envd gateway inspect ams1
envd gateway install ams1 --strategy censorship-resistant --dry-run
envd gateway install ams1 --strategy censorship-resistant
```

The interactive plan, and `--dry-run`, should show whether envd will install,
upgrade, stop, start, or remove anything before changes are applied.

Server switching should be simple from the user side:

```bash
envd gateway use ams1
envd gateway use hel1
```

Switch flow:

1. Load target gateway profile.
2. Generate candidate local gateway config.
3. Start or reload local gateway with candidate config.
4. Verify host SOCKS/HTTP route.
5. Verify sealed test route.
6. Update active gateway pointer.
7. Run internal gateway reconciliation for affected sealed environments.
8. Verify dependent sealed environments or leave them fail-closed.

If the new gateway fails verification, envd must keep using the previous working
gateway and report the exact failing layer.

User management:

- Each named user gets a UUID.
- Users can be enabled/disabled independently.
- `envd user uri <name>` emits a provider-specific import URI.
- Server config can be updated atomically.
- Previous config is retained for rollback.

Example:

```bash
envd user add phone --gateway ams1
envd user uri phone --gateway ams1
envd user disable phone --gateway ams1
```

The URI format is provider-specific. For Xray Reality this is a VLESS Reality
URI. Other providers may emit different app import strings.

## State And Secrets

Default state paths:

```text
~/.config/envd/config.yaml
~/.config/envd/gateways/<name>.yaml
~/.local/state/envd/store.db
~/.cache/envd/
~/.local/state/envd/
```

Files containing secrets must be `0600`.

State should include:

- Gateway name.
- Active gateway pointer.
- Gateway provider.
- Gateway strategy.
- Gateway strategy version.
- Gateway generation.
- Gateway chain definitions.
- Gateway status from last successful verification.
- Gateway egress policy.
- Last verified gateway egress IP/country/ASN.
- Remote host.
- SSH user/key reference.
- Remote ownership marker.
- Remote OS and architecture.
- Remote memory and disk capacity.
- Active remote provider service.
- Installed envd-owned provider services.
- Hosting provider catalog entries.
- Hosting provider catalog source versions.
- Hosting provider payment/reachability metadata.
- User-added hosting provider overrides.
- Hosting check snapshots and trend history.
- Provider API token references.
- Local internet measurement history.
- Gateway/provider/ASN risk scores.
- Xray version.
- Server public endpoint.
- Local proxy endpoints.
- Internal Docker endpoints.
- Reality public key.
- SNI.
- shortId.
- Users.
- Last known-good remote config checksum.
- Last known-good local gateway config checksum.
- Docker image versions.
- Runtime asset versions and checksums.
- Environment network modes.
- Environment image/tool profile.
- Environment workspace path and mount path.
- Environment storage mode and protected storage metadata.
- Environment project manifest path and last applied checksum.
- Environment/project secret references.
- Environment identity reference and identity policy result.
- Environment identity broker grant state.
- Environment editor/SSH proxy target state.
- Environment idle policy, last activity, and auto-stop reason.
- Environment active envd-managed session count.
- Supervisor lifecycle state and pending cleanup queue.
- Environment sidecar gateway generation.
- Environment last egress verification.
- Environment recovery point metadata and storage usage.
- Profile package manifest and generation.
- Profile build network mode used for last build.
- Raw Docker access flag per environment.
- Identity profiles, broker state, and account-sensitive command guard settings.
- Local event log retention policy.
- Security defaults, explicit downgrade flags, and lock behavior.

Private keys and sensitive remote credentials must not be logged.

### Secret Storage

`envd` should be able to remember remote credentials, but plaintext passwords
must never be stored in normal config files.

Use one portable secret backend:

```text
~/.local/state/envd/store.db
```

No macOS Keychain, Linux Secret Service, KWallet, or platform-specific secret
store should be required. The same vault format should work on macOS and Linux.
The store filename should not advertise that it contains credentials. The file
name is not a security boundary, but it should also not be unnecessarily obvious.

Vault behavior:

- Server passwords are stored encrypted by default when provided.
- The vault is protected by an envd master password.
- The master password itself is never stored.
- The master password is passed through a memory-hard KDF such as Argon2id with
  a random salt.
- The derived key encrypts/decrypts the vault using an authenticated encryption
  mode such as XChaCha20-Poly1305 or AES-GCM.
- A verifier hash can be stored to reject wrong master passwords quickly, but the
  hash must not be usable as the encryption key.
- Use vetted encryption libraries; do not implement custom crypto.
- Never print passwords, private keys, UUIDs, or Reality private keys in logs.
- Store only secret references in YAML state.

Default remote password behavior:

```text
remember encrypted in envd vault
```

SSH keys may still be installed for reliability, but storing the server password
is allowed and expected so automatic gateway repair, server switching, and
re-bootstrap flows do not require hunting for credentials in other tools.

Example:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password
```

Current implementation supports dry-run/probe and explicit apply:

```bash
envd gateway install ams1 --host 1.2.3.4 --user root --password --probe --dry-run
envd gateway install ams1 --host 1.2.3.4 --user root --password --yes
```

The dry-run/probe path performs real SSH password authentication, pins the
remote host-key fingerprint, detects OS, architecture, memory, disk, init
system, and firewall, inspects existing envd/Xray provider state without
changing it, generates envd-owned Xray Reality material locally, and stores the
remote password only after the SSH probe succeeds.

The `--yes` path applies only after a successful probe. It installs pinned
envd-owned Xray Reality material, writes the systemd service where available,
opens the configured port only for supported detected firewalls, verifies the
remote process, checks local TCP reachability to the remote gateway port, stores
the local gateway profile, and rolls back a previous envd-owned config if
verification fails.

If `envd gateway install ... --password` is the first stateful command and
encrypted state is missing, envd should stop with a concise `run envd init`
message. Gateway install must not create a master password implicitly.

If the stored SSH password or key stops working, the gateway command that needs
access should ask for replacement credentials, store them encrypted after
success, and continue.

Rules:

- Secrets should be scoped by purpose, for example `remote/ams1/password`.
- Vault availability follows envd's explicit lock state and implicit unlock on
  the next stateful command.
- `envd lock` must close the vault, revoke decrypted secret access, and terminate
  any envd-managed process or agent that holds decrypted secret material.
- Single-shot commands may prompt for the master password, decrypt what is
  needed, then clear sensitive memory before exit.
- Remembering a server password does not mean remembering the master password.
- `envd doctor` should report whether required secrets are available or locked,
  without revealing values.
- Any future full export must require explicit secret inclusion.

This keeps server switching and repair simple without forcing users to dig
through external notes or apps for credentials every time.

### Project And Environment Secrets

The encrypted store can also hold local development secrets for environments.
This should stay simple and local; envd should not become a cloud secret manager.

Manifest example:

```yaml
secrets:
  required:
    - GITHUB_TOKEN
    - DATABASE_URL
```

Behavior:

- `.envd.yaml` may declare required secret names.
- Secret values are never stored in the repo.
- On `envd run`, if required secrets are missing, envd asks for them, stores
  them encrypted, and continues.
- Secrets are injected only into the environment that requested them.
- Secret names can appear in `envd inspect`; values must never appear in normal
  output or logs.
- Secrets are not baked into profile images.

Commands:

```bash
envd secret set books GITHUB_TOKEN
envd secret list books
envd secret forget books GITHUB_TOKEN
```

This removes another common source of dev friction: hunting through notes or
copying `.env` files between containers.

## Installation And Bootstrap

The first install should be one obvious command from the repository:

```bash
./install.sh
```

`install.sh` should compile and install the Go `envd` binary. It is the bootstrap
step only. After envd is installed, normal setup is owned by envd itself.

Installer behavior:

1. Detect OS and architecture.
2. Verify required build tools.
3. If Go is missing, either use a pinned local/toolchain download flow or fail
   with one exact command to install Go.
4. Build the envd binary from source.
5. Install to a user-writable path when possible, such as `~/.local/bin`.
6. Use `/usr/local/bin` only when requested or when permissions allow.
7. Verify the installed binary runs.
8. Print the next useful command, not a wall of README steps.

Examples:

```bash
./install.sh
./install.sh --prefix ~/.local
./install.sh --system
./install.sh --dry-run
./install.sh --uninstall
```

Rules:

- No Homebrew-only install path.
- No macOS-only assumptions.
- No manual copying of shell snippets into profile files unless the user asks for
  shell completions.
- If `PATH` needs updating, print the exact line and explain it.
- The script should be idempotent.
- Re-running it should upgrade or repair the local binary.
- The installed binary should be able to run `envd doctor --deep` immediately.

Expected first experience:

```bash
./install.sh
envd gateway install ams1 --host 1.2.3.4 --user root --password
envd run books
```

## Self Management

README should not be the primary installation mechanism. It can document
bootstrap, but the utility should manage itself after first install.

Expected user-facing command:

```bash
envd doctor --deep
```

Normal envd commands should repair their own missing prerequisites automatically
when that can be done safely. `envd doctor --deep` explains what could not be
repaired automatically and why.

Responsibilities:

- Verify the installed binary matches expected version.
- Verify config/state directory permissions.
- Verify Docker access.
- Verify required assets and images.
- Recreate required Docker networks.
- Rebuild or restore missing runtime images.
- Explain exactly which host dependency is missing.

Docker should be treated as an unreliable external runtime. `envd` must be able
to recover from deleted containers, deleted images, deleted networks, and stale
volumes where recovery is safe.

## Docker Image Policy

No unpinned runtime images.

Bad:

```text
teddysun/xray:latest
```

Good:

```text
envd/xray:<pinned-version>
envd/net-sidecar:<pinned-version>
envd/sshdev:<pinned-version>
```

The CLI should expose:

```bash
envd version
envd gateway upgrade --to <version>
envd gateway rollback
```

Runtime images should be reproducible from pinned definitions. If Docker images
are deleted, the command that needs them should restore them from:

1. Local envd asset cache.
2. Pinned registry image.
3. Pinned local build context.

This is not a general Docker cache. It is only for assets `envd` cannot operate
without.

### Environment Image Identity

Each environment should be backed by a declarative image spec, not by whatever
Docker image ID exists at runtime.

Problem to avoid:

```text
NAME                 STATE    STATUS            IMAGE
vibeanalysis         active   Up About an hour  sshdev:24.04
books                active   Up About an hour  9df44ebfc908
vpntest              active   Up About an hour  e22e7bf90fc0
bet1                 active   Up About an hour  808d31ef8bc4
```

This means the environments are still running, but envd cannot clearly explain
what they were built from. That makes repair, migration, audit, and rebuilds
fragile.

Desired model:

- `envd` stores an environment spec when the environment is created.
- Docker labels point back to the envd environment ID.
- Image tags are stable and human-readable.
- Image digests are recorded when available.
- Anonymous image IDs are treated as drift.
- envd restores the declared image, not an arbitrary latest image, when the
  environment is started, recreated, migrated, or diagnosed.

Example tags:

```text
envd/dev-default:2026.06.05-1
envd/dev-web:2026.06.05-1
envd/net-sidecar:2026.06.05-1
envd/xray-gateway:26.2.6-envd.1
```

This gives envd the ability to recover after `docker image prune` without
guessing what an environment used to be.

## Dev Image And Tool Profiles

The default dev image should include a practical baseline toolset so every new
environment is useful immediately.

Baseline tools:

- bash, zsh optional later
- git, openssh-client, curl, wget
- ca-certificates
- build-essential, pkg-config
- python3, pip
- node LTS tooling optional via profile
- go optional via profile
- docker CLI and compose plugin
- common debug tools: iproute2, dnsutils or drill, netcat, jq, less, vim

Tooling should be managed by profiles, not by editing Dockerfiles manually every
time:

```bash
envd pkg add web tool:node-lts
envd pkg add web npm:pnpm
envd pkg add go tool:go-stable
envd run app1 --profile web
```

Referencing a new profile name creates that profile lazily from the default
baseline. Profile images should build lazily when first used. The user should
not need a separate create or build command.

Profile rules:

- Profiles produce pinned image definitions.
- Images are tagged with profile and version.
- Rebuilding a profile should not mutate existing environments unless requested.
- Existing environments can be migrated by controlled recreate with volumes
  preserved.

This keeps new environments fast while avoiding hidden mutable state.

### Package Lifecycle

Runtime package installs inside a dev container are useful for experimentation,
but they should not become the long-term source of truth.

Problem:

```bash
apt install ffmpeg
npm install -g pnpm
pip install poetry
```

If the user repeats those commands in every environment, envd should make it easy
to promote them into a reusable profile instead of silently accumulating
container drift.

Desired workflow:

```bash
envd pkg add default apt:ffmpeg
envd pkg add web npm:pnpm
envd pkg add python pip:poetry
envd run app1 --profile web
```

`pkg add` updates the profile manifest and marks the profile as dirty. The next
command that needs the profile should build or update the image automatically.
The user should not need to run a separate build command in the normal path.

Promotion workflow:

```bash
envd pkg suggest books
envd pkg promote books --to web
envd migrate books --profile web
```

`pkg promote` should show suggestions, ask what to keep, update the target
profile, and mark it dirty. `envd migrate` then builds the profile if needed and
recreates the environment safely with volumes preserved.

Package sources:

- `apt:<package>`
- `npm:<package>`
- `pip:<package>`
- `go:<package>`
- `tool:<name>` for envd-supported language runtimes and common toolchains
- `binary:<url>@<checksum>`
- `script:<name>` only for envd-managed reviewed scripts

Rules:

- Profiles should store package intent, not only a generated Dockerfile.
- Generated Dockerfiles are build artifacts.
- Package changes create profile generations.
- Dirty profiles are built lazily by `envd run`, `envd migrate`, and commands
  that need the profile.
- Existing environments are not mutated until the user runs a controlled
  migration.
- `envd pkg suggest <env>` can inspect apt history, dpkg state, global npm
  packages, pipx/pip globals, and common tool paths, but suggestions are
  best-effort and must be confirmed.
- `envd inspect <env>` should show runtime drift from the declared profile.

### Image Storage And Cleanup

Profile generations should not create unbounded image noise.

Storage rules:

- Docker layer sharing should be used instead of rebuilding everything from
  scratch.
- BuildKit cache mounts should be used for apt, npm, pip, Go, and similar
  package caches.
- Env images should be tagged by profile and generation.
- Older generations should be kept only while environments reference them.
- Unreferenced envd-owned images should be garbage-collected automatically after
  envd verifies no environment references them.
- `envd inspect`, `envd status`, and `envd doctor --deep` should explain which
  images are active, repairable, cached, or garbage-collectable when relevant.

Example:

```text
IMAGE                       ROLE      USED BY       STATUS
envd/dev-web:2026.06.05-1   profile   books         active
envd/dev-web:2026.06.04-1   profile   -             queued for automatic cleanup
envd/net-sidecar:...        runtime   all sealed    protected
```

This keeps images reproducible without forcing every small package change to
become permanent storage bloat.

### Package Network Policy

Package installation has its own network tradeoff. Some package downloads should
use the sealed gateway for privacy/censorship resistance. Some heavy public
downloads may be acceptable through direct networking to save VPN traffic.

The safe default is sealed:

```bash
envd pkg add web apt:ffmpeg
envd run app1 --profile web
```

Explicit direct build/download mode can be attached to the command that triggers
the build:

```bash
envd run app1 --profile web --build-network direct
envd migrate books --profile web --build-network direct
```

Rules:

- Direct package/build networking must be explicit.
- Direct build/download jobs must run in isolated builder containers, not inside
  an active sealed dev environment.
- Direct jobs should not get the dev environment's secrets by default.
- Direct jobs may use envd-managed package caches.
- Active sealed environments stay sealed while direct package/build jobs run.
- `envd doctor` should be able to distinguish "profile build used direct
  network" from "sealed environment leaked".

This gives the user a controlled way to save gateway traffic for heavy public
downloads without weakening the sealed runtime guarantee.

## Identity And Account Protection

The tool should not depend on macOS-specific host assumptions for Git, SSH,
GitHub, AI coding tools, or other account-backed developer workflows.

Within an envd-managed protected environment, identity exposure should be
deterministic:

```text
sealed network healthy + identity policy passes -> broker can use identity
anything else -> broker denies identity
```

This guarantee applies to the envd-managed path:

- envd-created environment.
- sealed networking enabled and verified.
- no raw host Docker socket unless explicitly accepted as a risk.
- no direct host credential mounts.
- identity attached through the envd broker.
- account-sensitive commands using envd-managed Git/SSH/credential helpers.

Outside this boundary, envd should warn and mark the environment risky, but it
cannot guarantee what arbitrary host mounts, raw Docker containers, or manually
copied credential files do.

`envd` should manage identities as first-class objects:

```bash
envd identity add work
envd run dev1 --identity work
```

`identity add` should run an interactive import flow for Git identity, SSH keys,
Git hosting tokens, and tool credentials. Defaults should require sealed
networking and deny direct/raw Docker exposure unless the user explicitly
changes policy.

Identity contents:

- Git name/email/signing config.
- SSH keys or references.
- GitHub/GitLab tokens if used.
- Tool-specific tokens such as AI coding assistant credentials when explicitly
  stored.
- Allowed network policy.
- Allowed egress country/ASN/IP policy.

Identity network policy:

```bash
envd identity policy set work --require sealed
envd identity policy set work --expect-country NL --strict
envd identity policy set work --deny-direct
```

Default identity policy:

```text
require sealed
deny direct
deny unknown egress
```

Rules:

- Account credentials must not be injected into direct environments by default.
- Account credentials must not be injected if the sealed route is unhealthy.
- Account credentials must not be injected if strict egress policy fails.
- Account credentials must not be baked into images.
- Long-lived account credentials must not be copied into environment
  filesystems in the protected identity path.
- Long-lived account credentials must not be exposed as persistent environment
  variables.
- Identity secrets live in the encrypted envd store.
- Host Git/SSH config can be imported once, but runtime should use envd-managed
  identity config.
- Linux and macOS behavior should be equivalent.

Example safe failure:

```text
FAIL identity work blocked
Reason: env dev1 is direct, but identity requires sealed networking.
Action: envd network set dev1 sealed
```

### Identity Broker

Wrappers are useful, but they are not strong enough by themselves. The stronger
default is an envd identity broker:

```text
tool inside env -> envd identity broker -> policy check -> credential operation
```

The broker should expose only the minimum capability needed:

- SSH signing/auth through an envd-managed SSH agent socket.
- Git HTTPS credentials through a credential helper.
- Tool tokens through short-lived environment variables or stdin only when
  policy passes.
- Optional command wrappers as an additional UX layer.

Concrete Git/SSH model:

- `~/.ssh/id_*` files are not copied into the container.
- `.gitconfig` inside the container is generated by envd and points to envd
  helpers.
- `SSH_AUTH_SOCK` points to an envd broker socket, not the host's raw agent.
- Git HTTPS uses `credential.helper = envd credential-helper`.
- The broker performs the actual key/token operation only after policy passes.
- If policy fails during a long-running environment session, the broker revokes
  the grant; future Git/SSH operations fail even if the shell is still open.

Broker rules:

- Private keys and long-lived tokens stay in the encrypted envd store or an
  envd-controlled agent, not in the container filesystem.
- Broker sockets are mounted only into environments with an identity attached.
- Broker grants are scoped to environment ID, identity, command class, and
  gateway generation.
- Grants are revoked when network mode changes, gateway generation changes,
  egress policy fails, or `doctor` marks the environment unsafe.
- If the broker cannot verify policy, it denies access.
- The broker, not PATH order, is the security boundary.
- If a user bypasses wrappers and invokes SSH, Git, or a credential helper
  directly, broker policy must still deny unsafe credential use.
- Direct raw access to host `~/.ssh`, `~/.gitconfig`, or tool credential files is
  disabled by default.
- If the user explicitly mounts host credential files, enables raw Docker, or
  copies credentials manually, envd must mark the environment outside the
  protected identity boundary.

Example:

```text
git push -> SSH agent request -> broker checks dev1:
  network sealed: ok
  gateway generation current: ok
  egress country NL: ok
  identity work allows git: ok
result: allow signing/auth
```

Unsafe example:

```text
git push -> SSH agent request -> broker checks dev1:
  network direct: fail
result: deny
```

This is what makes identity protection resistant to bugs in shell startup files,
copied dotfiles, or users accidentally running the right command from the wrong
network mode.

### Identity Verification

envd cannot honestly promise mathematical "100% protection", but it can make
identity exposure fail-closed and testable.

Required checks:

- No private key files exist in the container filesystem by default.
- No long-lived token files exist in the container filesystem by default.
- No raw host credential mounts are present.
- No persistent environment variables contain long-lived account tokens.
- SSH auth goes through the envd broker socket when an identity is attached.
- Git credential helper is envd-managed.
- Account-sensitive wrappers may be installed and first in PATH where practical,
  but wrappers are convenience and diagnostics only. Broker denial must still work
  if wrappers are bypassed.
- Broker denies access when the environment is direct.
- Broker denies access when sealed route is unhealthy.
- Broker denies access when egress policy fails.
- Broker grants are revoked after gateway switch until revalidation succeeds.
- `envd ps` shows identity status.
- `envd doctor --identity` runs negative tests to confirm unsafe access is
  blocked.

Command:

```bash
envd doctor --identity dev1
```

Example output:

```text
Identity work                 OK
Private key files             OK  none found
Git credential helper         OK  envd
SSH agent broker              OK
Direct network denial         OK
Wrong egress denial           OK
Gateway switch revocation     OK
```

### Account-Sensitive Command Guard

`envd` should reduce accidental account exposure from commands such as:

- `git push`
- `git pull`
- `gh auth`
- `npm publish`
- `pip upload`
- AI coding tools that contact account-backed services.

Inside managed environments, envd can install lightweight wrappers for common
account-sensitive commands. The wrappers should check envd state before allowing
the command to receive credentials.

Guard behavior:

1. Check environment network mode.
2. Check sealed route health.
3. Check egress IP/country/ASN policy.
4. Check identity policy.
5. Allow command only if policy passes.

If policy fails, the wrapper should block by default:

```text
Blocked: git push would use identity work from an unsafe network.
Network: direct
Required: sealed, egress country NL
```

Explicit overrides should be noisy and temporary:

```bash
envd allow dev1 git --once
envd identity policy set personal --allow-direct
```

These guardrails are not a replacement for provider-side account security, but
they prevent common local mistakes: running account tools from direct networking,
wrong egress country, stale gateway, or an unsealed raw Docker context.

## Reliability And Security Gates

The design is only useful if implementation errors are caught before users rely
on it. These gates are release blockers, not nice-to-have tests.

Kill-switch gate:

- A sealed environment must have no direct egress when the gateway is down.
- DNS must not bypass the tunnel.
- IPv4 and IPv6 must both be covered.
- Sidecar restart, gateway restart, Docker network recreate, and route changes
  must not create a leak window.
- Tests must run from inside a sealed container and prove that only the permitted
  pre-tunnel path is reachable before the tunnel is healthy.

Gateway gate:

- `envd gateway use <name>` is a two-phase switch: verify first, activate second.
- The previous known-good gateway remains available until the new route passes
  host, local gateway, sealed container, DNS, and egress policy checks.
- Activation failure rolls back automatically.
- Existing sealed environments are pinned to a gateway generation and reconcile
  after a successful switch.
- A failed reconciliation leaves affected environments closed, not direct.

Project Docker gate:

- `docker` and `docker compose` inside an envd shell must use the envd-managed
  project Docker endpoint, not the host Docker socket.
- Project Docker containers must have no direct egress when the gateway is down.
- Project Docker DNS, IPv4, and IPv6 behavior must match sealed policy.
- Compose `ports:` must not silently expose services to the host or LAN.
- Host path mounts outside approved workspace paths must be blocked by default.
- Host networking, raw host Docker socket mounts, privileged host access, and
  arbitrary device mounts must be blocked by default.
- `envd doctor --deep` must prove project Docker traffic is sealed by launching a
  test container through the project engine.
- Raw host Docker must be reported as outside envd guarantee, not treated as a
  weaker sealed mode.

Storage gate:

- Plain storage must be labeled as plain and never described as encrypted.
- Protected storage must never be implemented with normal unencrypted Docker
  volumes.
- macOS APFS encrypted image and Linux LUKS2-backed image behavior must be tested
  for create, mount, unmount, lock, stop, crash recovery, and recovery points
  before protected storage ships.
- Missing, truncated, tampered, dirty, or unsupported storage must fail closed.
- If protected storage is requested, `envd stop <env>` must leave it encrypted at
  rest.
- If protected storage is requested, `envd lock` must stop envd-managed
  environments and leave protected storage encrypted at rest.

Recovery-point gate:

- Recovery points must be encrypted by default.
- Recovery point creation and integrity verification must happen automatically
  around risky operations.
- Recovery point pruning must be automatic and must never delete live environment
  storage.
- `envd rm <env>` must remove the environment's envd-managed storage and
  env-owned recovery points after confirmation.
- Stable environments must not accumulate unbounded recovery points.
- Tests must prove rollback works from an automatic recovery point.
- Tests must prove automatic pruning preserves rollback for the latest risky
  operation.
- Tests must prove `envd rm <env>` removes that environment's recovery points.

Identity gate:

- No private keys or long-lived tokens may exist in the container filesystem by
  default.
- Git/SSH/token access must go through the envd broker.
- Broker grants must be scoped to environment ID, identity, command class, and
  gateway generation.
- Direct networking, unhealthy sealed routing, wrong egress, gateway switch, and
  lock must all revoke or deny broker access.
- `envd doctor --identity` must run negative tests, not only inspect config.

Editor/SSH access gate:

- `envd code <env>` and VS Code Remote SSH must connect through envd-controlled
  proxy/auth, not a durable exposed container SSH server.
- Generated SSH config must use `ProxyCommand envd ssh-proxy ...` or an
  equivalent envd-controlled local endpoint.
- No default listener may bind to `0.0.0.0`, LAN addresses, or public
  interfaces.
- Localhost or socket endpoints must still require envd-managed authentication
  and unlocked state.
- Generated SSH aliases should be opaque by default; human env-name mappings
  must stay in encrypted state unless the user explicitly opts into visible
  aliases.
- Lock must terminate active editor/SSH sessions and make reconnect fail until
  unlock.
- Tests must prove another machine on the LAN cannot connect to envd editor/SSH
  access by default.
- Tests must prove stale keys/certificates cannot reconnect after lock.

Lock/session gate:

- `envd lock` must terminate envd-managed shell, SSH, and one-shot command
  sessions, stop envd-managed environments and service/app runtimes, stop sealed
  project Docker engines, and close protected storage where present.
- New envd-managed access sessions must be refused while locked.
- envd-owned shell clients must stop accepting input, clear/reset the visible
  terminal state where supported, exit, and leave a locked message when they
  receive a lock event.
- The terminal that executes `envd lock` must follow the same visible cleanup
  path after the lock succeeds.
- Terminal cleanup must not be used as proof of security outside envd-owned PTYs.
- The test must prove no terminated session can still access storage, identities,
  secrets, or the sealed network after lock.
- The test must prove `envd lock` leaves protected storage closed for every
  envd-managed environment it stopped.
- The test must prove registered host Docker cleanup starts only after core
  sealing completes.
- Slow or failed registered host Docker cleanup must not prevent envd from
  reaching locked state.
- Pending or failed registered host Docker cleanup must be visible in
  `envd status` and events.
- Raw host Docker must remain reported as outside envd guarantee; `envd lock`
  must not claim to secure unmanaged host containers.

Supervisor/idle gate:

- The supervisor must be user-level, event-driven, and mostly asleep when idle.
- The supervisor must not perform continuous network probes or tight Docker scans.
- Auto-stop must not trigger while an envd shell, VS Code/SSH proxy, one-shot
  command session, port connection, recovery-point operation, migration, repair,
  profile build, or keep-alive service is active.
- Auto-stop must close protected storage where present and preserve environment
  data.
- Auto-stop must not delete images, layers, caches, or recovery points.
- If the supervisor cannot confidently determine that an environment is idle, it
  must leave it running and report the reason.
- If the supervisor is killed or crashes, the next envd command must reconcile
  state safely.
- Tests must prove auto-stopped environments start again with data intact.
- Tests must prove the supervisor uses coarse timers or event notifications, not
  busy polling.

Encrypted-state gate:

- `envd init` must create encrypted state explicitly before operational metadata
  exists.
- Stateful envd commands must unlock existing encrypted state before reading or
  writing operational state.
- Human environment names, project paths, gateway hosts, identity names, and
  event history must not be written to plaintext host files or Docker metadata.
- Docker object names and labels should use opaque IDs.
- Logs must be redacted, and detailed event history must live in encrypted state.

Catalog/update gate:

- Runtime assets, provider strategy definitions, and hosting catalog updates must
  be pinned and signature-verified or checksum-verified through envd releases.
- Unsigned remote catalog updates must be rejected.
- Catalog entries must carry confidence/source metadata and must not claim a
  provider or protocol is guaranteed safe.

Diagnostics gate:

- Every major failure must map to a layer: host Docker, asset cache, local
  gateway, remote gateway, sealed sidecar, DNS, egress policy, identity broker,
  encrypted storage, or provider/catalog state.
- `envd doctor --deep` must perform real traffic tests, including sealed
  container traffic, not only process checks.
- `envd why <env>` must explain the last state transition or blocking reason.

Cross-platform gate:

- macOS and Linux behavior must be equivalent at the command and security-model
  level.
- arm64 and amd64 runtime images must be selected automatically.
- Platform-specific storage backends are hidden behind the envd storage API.
- If the required backend is unavailable, envd fails closed instead of silently
  using weaker storage.

## Migration From Current System

The new Go implementation does not need to preserve Bash internals.

However, migration should preserve user data:

- Existing environment names where feasible.
- Existing SSH config entries where safe.
- Existing remote Xray credentials if imported.

Legacy storage migration policy:

- Existing Docker volumes are plain storage.
- Migration should import legacy Docker volume data into envd-managed protected
  storage only when the user explicitly requests protected storage.
- The explicit command is `envd migrate protected <env> --yes` after adoption.
  It preserves the human env name, creates a new envd-owned opaque ID, imports
  legacy `*-home` and `*-repo` data into protected storage, and leaves the
  original legacy Docker volumes untouched.
- If protected import is unsafe or unsupported, leave the legacy volume untouched
  and mark the migrated environment `plain`.
- A migrated environment must not claim protected storage while any active
  persistent data path is a normal Docker volume or raw host bind mount.
- envd must never claim a legacy Docker volume is encrypted just because envd now
  manages the environment.

The old Bash script can remain temporarily as implementation reference, but the
new Go CLI should not shell out to it for normal operations.

## Phased Build Plan

The spec describes the long-term product, but implementation must be release
gated. v1 is deliberately narrower than the full architecture.

The execution tracker lives in `docs/implementation-checklist.md`.

v1 baseline:

1. Create source-built `install.sh` bootstrap.
2. Create Go CLI skeleton.
3. Implement encrypted config/state model and explicit `envd init`.
4. Implement environment specs and `envd ps` from envd state plus Docker state.
5. Implement image identity, profile tags, drift detection, and automatic image
   deletion recovery.
6. Implement runtime asset manager with pinned assets and automatic restore.
7. Implement local gateway manager through a provider interface.
8. Implement `envd proxy` and `envd proxy test`.
9. Implement `envd doctor --deep` with real host, gateway, and sealed-container
   traffic tests.
10. Implement sealed single-container environment creation with sidecar
    kill-switch routing.
11. Implement direct/offline environment modes and safe stop/recreate mode
    changes.
12. Implement interactive `envd gateway install <name>` with internal
    inspect/plan/apply/verify phases.
13. Implement atomic `envd gateway use <name>` switching, rollback, and internal
    reconciliation for affected sealed environments.
14. Implement `envd events` and `envd why`.
15. Remove Bash dependency from normal operations.

v1 success criteria:

- A user can install envd from source with `./install.sh`.
- A user can create one sealed environment and see exact network/storage/image
  state in `envd ps`.
- A broken gateway, broken DNS, broken sidecar, missing image, or wrong proxy port
  is diagnosed by layer without manual curl/ping debugging.
- Docker image deletion is repaired for envd-owned images.
- Gateway switching verifies before activation and fails closed on error.
- Sealed environments never silently fall back to direct networking.

Post-v1 security/storage milestone:

- Protected APFS/LUKS storage backends.
- Optional legacy Docker volume import into protected storage.
- `envd lock` deterministic shutdown behavior.
- Automatic encrypted recovery points and lifecycle pruning.
- `envd code <env>` and envd-controlled SSH proxy access.

Post-v1 identity milestone:

- Identity profiles.
- Identity broker and scoped grants.
- Account-sensitive command wrappers as convenience only.
- `envd doctor --identity` negative tests.

Post-v1 productivity milestone:

- Dev image profiles.
- Package manifest and lazy profile generations.
- Package promotion suggestions from existing environments.
- Workspace/project manifest support.
- User-level supervisor, idle auto-stop, and cleanup queue.

Post-v1 resilience/censorship milestone:

- Signed hosting catalog schema and conservative built-in catalog.
- Catalog updates and local reachability history.
- `envd internet status`, `envd hosting shortlist`, and gateway risk scoring.
- User URI generation.
- Gateway chains.

Release-gated project Docker milestone:

- Sealed project Docker endpoint for standard `docker` and `docker compose`
  inside envd shells.
- Raw host Docker detection and risk reporting.

No later milestone can ship by intention alone. Each feature must satisfy its
release gate before it becomes part of the supported product.
