# 🚀 Awesome Remnanode VPS Edge Runner

## TL;DR

One command turns a fresh Ubuntu VPS into a **secure, Tailscale‑only edge node** ready for **Remnawave / remnanode**:

- 🔒 Only **443** is open to the public Internet
- 🌐 All control & services work **exclusively via Tailscale**
- 🧠 Automatic **kernel & network tuning** based on CPU/RAM/Disk
- 🌍 Predictable DNS via systemd‑resolved (Google + Cloudflare)
- 🐳 Docker + remnanode bootstrapped and verified
- 💅 Zsh + Powerlevel10k configured for **all users**
- ♻️ Idempotent, repeatable, with **rollback support**

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh \
  | sudo bash -s -- apply --tailscale=1 --dns-switcher=1 --remnanode=1 --open-wan-443=1
```

---

## What is this?

`vps-edge-run.sh` is an **opinionated VPS bootstrap & hardening script**.

It is designed for running **remnanode** (Remnawave VPN node) on a VPS, where:

- the server must be reachable **only through Tailscale**
- the public Internet sees **one port: 443**
- the system is tuned for high‑throughput networking
- the environment is comfortable for long‑term administration

You can safely re‑run the script multiple times. It will not break an already configured host.

---

## Core components

### 🌐 DNS (systemd‑resolved)

Integrated DNS switcher based on:
https://github.com/AndreyTimoschuk/dns-switcher

Default profile (used automatically):

- **DNS**: `8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1`
- **Fallback**: `9.9.9.9`
- `Domains=~.`

Features:
- non‑interactive (auto‑yes)
- configuration backup
- DNS summary + diagnostics hints

---

### 🧠 Tailscale (mandatory)

Tailscale is the **backbone of the setup**.

- Installed or reused if already present
- `tailscale up` without exit‑node
- Waits for successful online state
- Detects:
  - Tailscale IP (`100.x.x.x`)
  - MagicDNS hostname (`node‑xxx.tailxxxx.ts.net`)

All management traffic (SSH, remnanode, Docker, metrics) is expected to go through Tailscale.

https://tailscale.com

---

### 🔐 Firewall model (UFW)

Strict and predictable:

- **WAN**:
  - allow `443/tcp` and `443/udp`
- **tailscale0**:
  - allow all (in/out)
- **Docker bridges**:
  - allow internal traffic

Everything else is blocked.

---

### 🧠 Kernel & network tuning

Based on:
https://github.com/akadorkin/vps-network-tuning-script

Automatically derives a tuning profile from:

- CPU count
- RAM size
- `/` filesystem size

Applies:

- BBR + fq
- conntrack sizing
- TCP/UDP buffers
- `nofile` limits
- swapfile
- journald limits
- logrotate
- disables unattended auto‑reboot

A **Before → After** table is printed at the end.

---

### 🐳 Docker

- Installed if missing
- Reused if already present
- Verified via `docker info`

---

### 🧩 remnanode (Remnawave node)

If `/opt/remnanode/docker-compose.yml` exists:
- inputs are skipped
- compose is started and verified

Otherwise:
- port and secret can be provided

Documentation:
- https://docs.rw
- https://docs.rw/docs/install/remnawave-node

⚠️ remnanode ↔ panel communication is expected **only via Tailscale**.

---

### 📡 iperf3

- Always installed
- systemd service always enabled
- Useful for throughput tests over Tailscale

---

### 💅 Zsh environment (all users)

For **every user in `/home/*` and for `root`**:

- Zsh is set as default shell
- `.zshrc` is installed
- Powerlevel10k prompt enabled
- All update / wizard / popup prompts disabled

#### What the provided `.zshrc` does

- Enables sane history defaults
- Disables Oh‑My‑Zsh auto‑update prompts
- Loads Powerlevel10k instantly (no lag)
- Adds useful aliases and completions
- Keeps configuration **non‑interactive and silent**

#### `p10k` configuration

- Clean, minimal prompt
- No context spam
- Fast rendering (Instant Prompt)
- Works well over SSH and Tailscale

Both files are fetched from this repository via raw GitHub URLs.

---

## Output summary

At the end of execution you get a structured summary:

- 🌍 WAN IP + country + city + provider
- 🧠 Tailscale IP
- ✨ MagicDNS hostname
- 🧠 HW tuning profile (CPU / RAM / Disk)
- 👤 User info
- 🧩 remnanode container status
- 📦 docker‑compose path
- 📚 backup directory
- 📝 log file locations

---

## How to run

### Interactive (recommended first run)

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh \
  | sudo bash -s -- apply
```

### Fully automated (no reboot)

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh \
  | sudo bash -s -- apply \
    --reboot=skip \
    --tailscale=1 \
    --dns-switcher=1 --dns-profile=1 \
    --remnanode=1 \
    --ssh-harden=1 \
    --open-wan-443=1 \
    --user akadorkin
```

### Rollback

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh \
  | sudo bash -s -- rollback
```

Or to a specific backup:

```bash
sudo BACKUP_DIR=/root/edge-tuning-backup-YYYYMMDD-HHMMSS bash vps-edge-run.sh rollback
```

---

## Important notes

- Requires **root**
- Ubuntu **20.04+** recommended
- Before running, ensure root SSH access via keys:

```bash
ssh-copy-id root@your-server
```

Password authentication is disabled during hardening.

---

## Philosophy

- secure by default
- minimal public attack surface
- observable changes
- safe to re‑run
- boring, predictable infrastructure

---

## Credits & references

- DNS switcher: https://github.com/AndreyTimoschuk/dns-switcher
- Tailscale: https://tailscale.com
- Remnawave / remnanode: https://docs.rw
- Network tuning base: https://github.com/akadorkin/vps-network-tuning-script

