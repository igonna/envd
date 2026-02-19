# Dev Environment Infrastructure

Self-contained, leak-proof Docker development environments behind Xray (VLESS + Reality).

This setup provides:

* 🔒 Network isolation (no traffic leaks)
* 🧱 Disposable dev containers
* 💾 Persistent home + repo volumes
* 🔑 SSH access with agent forwarding
* 🌍 Optional HTTP/SOCKS proxy for host apps (VS Code, etc.)
* ♻ One-command environment creation & removal

---

# Repository Structure

```
dev-env/
├── bin-dev-env/
│   └── dev-env              # CLI tool for managing dev containers
├── dev-containers/
│   └── sshdev/
│       ├── Dockerfile       # Dev container image
│       └── entrypoint.sh    # Dynamic user setup
└── vpn-gateway/
    ├── Dockerfile.render
    ├── compose.yml
    └── config.template.json
```

---

# 1️⃣ Requirements

* macOS
* Docker Desktop
* SSH key for GitHub (`~/.ssh/ghub_key` recommended)

---

# 2️⃣ Setup VPN Gateway

## Step 1 — Create `.env`

Inside:

```
vpn-gateway/
```

Create:

```
.env
```

Example:

```
XRAY_INBOUND_PORT=1080
XRAY_SERVER_IP=YOUR_SERVER_IP
XRAY_SERVER_PORT=443
XRAY_UUID=YOUR_UUID
XRAY_PUBLIC_KEY=YOUR_PUBLIC_KEY
XRAY_SNI=www.example.com
XRAY_SHORT_ID=YOUR_SHORT_ID
```

---

## Step 2 — Start VPN Gateway

```bash
cd vpn-gateway
docker compose up -d --build
```

Verify:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Should return your remote server IP.

---

# 3️⃣ Build Dev Container Image

```bash
cd dev-containers/sshdev
docker build -t sshdev:24.04 .
```

---

# 4️⃣ Install `dev-env` CLI

Move the script somewhere in PATH:

```bash
sudo mv bin-dev-env/dev-env /opt/homebrew/bin/dev-env
sudo chmod +x /opt/homebrew/bin/dev-env
```

Verify:

```bash
dev-env help
```

---

# 5️⃣ Create Dev Environment

```bash
dev-env new dev1
```

This creates:

* Container: `dev1`
* Linux user: `dev1`
* Home volume: `dev1-home`
* Repo volume: `dev1-repo`
* SSH port auto-assigned
* SSH config entry auto-created

Connect:

```bash
dev-env ssh dev1
```

Or:

```bash
ssh dev1
```

---

# 6️⃣ Persistence Model

### What Persists

| Item                         | Reason                     |
| ---------------------------- | -------------------------- |
| Installed packages           | Docker writable layer      |
| `/home/<user>`               | Named volume               |
| `/repo`                      | Named volume               |
| Git repos                    | Stored in volume           |
| Container after macOS reboot | `--restart unless-stopped` |

### What Does Not Persist

| Item                         | Reason             |
| ---------------------------- | ------------------ |
| Container after `dev-env rm` | Explicitly removed |
| Volumes after `dev-env rm`   | Explicitly deleted |

---

# 7️⃣ GitHub SSH (Agent Forwarding)

Recommended macOS SSH config:

```
Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/ghub_key
```

Add key to keychain:

```bash
ssh-add --apple-use-keychain ~/.ssh/ghub_key
```

Agent forwarding is enabled automatically for dev containers.

Test inside container:

```bash
ssh -T git@github.com
```

---

# 8️⃣ CLI Commands

Create environment:

```
dev-env new <name>
```

Remove environment:

```
dev-env rm <name>
```

List environments:

```
dev-env list
```

Restart environment:

```
dev-env restart <name>
```

SSH into environment:

```
dev-env ssh <name>
```

Open repo volume on host:

```
dev-env cd <name>
```

Help:

```
dev-env help
```

---

# 9️⃣ Optional: HTTP Proxy for Host Apps

If using HTTP inbound in Xray (port 1081):

VS Code settings:

```json
"http.proxy": "http://127.0.0.1:1081",
"http.proxySupport": "override",
"http.proxyStrictSSL": false
```

---

# 🔒 Security Model

* Dev containers are on internal Docker network.
* No direct internet access.
* All traffic must go through Xray.
* Removing environment deletes volumes.
* No private SSH keys stored in containers.

---

# 🧹 Cleanup

Remove all dev containers:

```bash
docker rm -f $(docker ps -aq --filter "name=dev")
```

Remove unused volumes:

```bash
docker volume prune -f
```

---

# 🚀 Philosophy

You are not installing development tools on your Mac.

You are spawning disposable Linux workspaces inside a controlled VPN-gated network bubble.

Host stays clean.
Environments are reproducible.
Removal leaves no residue.