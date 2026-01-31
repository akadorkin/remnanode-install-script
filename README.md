# ⭐ Awesome Remnanode VPS Edge Run

A production-ready **VPS bootstrap & hardening script** for running **Remnanode (Remnawave VPN node)** securely behind **Tailscale**, with sane defaults, kernel tuning, DNS control, firewall lockdown, and a clean developer shell.

This script is designed to be **idempotent**, **re-runnable**, and **reversible**.

---

## TL;DR

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin --timezone=Europe/Moscow --remnanode=1 --dns-switch=0 --reboot=0
```

Result:
- 🧠 Kernel tuned automatically (BBR, fq, conntrack, limits)
- 🌐 DNS switched to Google + Cloudflare
- 🔐 SSH hardened (no password auth)
- 🧱 WAN closed except **443**
- 🕸️ All services exposed **only via Tailscale**
- 🧩 Remnanode running via Docker
- 💅 Zsh + Powerlevel10k configured for all users

---

## What is this script for?

`vps-edge-run.sh` prepares a **clean Ubuntu VPS** to act as a **Remnanode edge server** in the **Remnawave VPN ecosystem**.

Key design principles:
- Zero trust networking (Tailscale only)
- Minimal WAN exposure (443/tcp,udp)
- Safe kernel tuning based on hardware
- Reversible changes (automatic backups)
- Repeatable runs (idempotent)

---

## Architecture

```
[ Remnawave Panel ]
        │
        │  (Tailscale only)
        ▼
[ VPS / Remnanode ]
   ├─ Docker
   ├─ Remnanode
   ├─ iperf3
   ├─ SSH (key-only)
   └─ Zsh dev shell

WAN: 443 only
Everything else: Tailscale
```

---

## Requirements

- Ubuntu 20.04 / 22.04 / 24.04
- Root access
- **SSH key already installed for root** (`ssh-copy-id root@server`)
  > Password auth will be disabled

---

## Installed software

Always installed:
- `docker`, `docker-compose-plugin`
- `iptables`, `ufw`
- `iperf3` (optional systemd server)
- `git`, `jq`, `mc`, `curl`, `wget`
- `zsh`, `powerlevel10k`, fonts

Optional / conditional:
- Tailscale
- Remnanode
- DNS switcher

---

## Kernel & system tuning

Kernel tuning is based on:
👉 https://github.com/akadorkin/vps-network-tuning-script

Applied automatically based on:
- RAM size
- CPU count
- Disk size

Includes:
- BBR + fq
- conntrack sizing
- tcp_tw / keepalive tuning
- file descriptor limits
- journald caps
- logrotate policy

Profile is shown in final Summary output.

---

## DNS Switcher

Based on:
👉 https://github.com/AndreyTimoschuk/dns-switcher

Default behavior:
- Always auto-accept
- Profile **1** by default

Which means:
- DNS: `8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1`
- Fallback: `9.9.9.9`

Backups stored in:
```
/etc/dns-switcher-backup
```

DNS summary is printed after apply.

---

## Tailscale

- Installed and started early
- No auth-key usage (web login only)
- MagicDNS detected automatically
- Exit nodes NOT enabled

Used for:
- Remnanode ↔ Remnawave Panel
- SSH access
- Metrics / iperf / admin tasks

Docs:
👉 https://tailscale.com

---

## Firewall model

UFW rules:
- WAN interface: **allow 443/tcp + 443/udp only**
- `tailscale0`: allow all
- Docker bridges: allow all

Everything else is blocked.

---

## Zsh setup

Applied to:
- All users in `/home/*`
- `root`

Includes:
- Oh-My-Zsh
- Powerlevel10k theme
- Clean prompt without update popups
- Aliases & sane defaults

Files used:
- `.zshrc`
- `.p10k.zsh`

Fetched from this repo.

---

## Remnanode

Remnanode is the VPN node component of **Remnawave**:
👉 https://docs.rw

Installation guide:
👉 https://docs.rw/docs/install/remnawave-node

Behavior:
- If `/opt/remnanode/docker-compose.yml` exists → reused
- Otherwise user is prompted for:
  - Node port
  - Secret key

Remnanode is started via Docker Compose.

---

## Usage

### Interactive (recommended first run)

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main/vps-edge-run.sh | sudo bash -s -- apply
```

### Fully automated

```bash
sudo ./vps-edge-run.sh apply \
  --user admin \
  --tailscale=1 \
  --dns-switcher=1 --dns-profile=1 \
  --remnanode=1 \
  --ssh-harden=1 \
  --open-wan-443=1 \
  --reboot=skip
```

### Rollback

```bash
sudo ./vps-edge-run.sh rollback
```

---

## Final output

At the end, the script prints:
- WAN IP + Geo + Provider
- Tailscale IP + MagicDNS
- Hardware profile
- Kernel tuning profile
- Remnanode status
- Backup location
- Log files

See `SUMMARY_EXAMPLE.md` for anonymized output.

---

## License

GNU General Public License v3.0

---

## Why this exists

Because setting this up **by hand** is boring, error-prone, and not repeatable.

This script is what I actually run on real servers.