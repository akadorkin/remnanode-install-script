# ⭐ Remnanode VPS Edge Run

A production-ready **VPS bootstrap & hardening script** for running **Remnanode (Remnawave VPN node)** securely with sane defaults:

- Create a sudo user + Zsh environment
- Install Docker
- Configure **UFW** (ports on external interface + allow-all on `tailscale0` and Docker bridges)
- Configure **Fail2ban** (`sshd`, `sshd-fast`, `recidive`) with incremental bantime
- Optional **Tailscale** bring-up (disabled by default)
- Optional **DNS switcher** for `systemd-resolved` (non-interactive profiles supported)
- Optional **network/kernel tuning** via your external tuning script

> **No warranty.** You run this at your own risk.

---

## Requirements

- Ubuntu Server (tested on Ubuntu 22.04/24.04)
- Root access (run via `sudo`)

---

## TL;DR

Run directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --timezone=Europe/Moscow \
  --reboot=0
```

If you want to fully automate ports + DNS without any prompts:

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --ports=skip \
  --open-ports="22,80,443" \
  --dns-switch=1 --dns-profile=2 \
  --reboot=0
```

---

## What it does

1. (Optional) asks for hostname
2. Picks ports to open on the external interface (interactive by default)
3. Creates/updates user, sets up SSH keys, sudo, docker group
4. Installs Docker CE
5. Sets sane FD limits (`fs.file-max`, `DefaultLimitNOFILE`, etc.)
6. Configures Fail2ban
7. Configures UFW (external ports + allow-all on `tailscale0` + allow-all on Docker bridges)
8. Installs node_exporter and iperf3 service
9. (Optional) applies external tuning profile
10. (Optional) sets DNS via `systemd-resolved`
11. (Optional) starts Remnanode via Docker Compose (if enabled)
12. Prints a grouped final report

---

## Flags

### Core

- `--user <name>` *(required if non-interactive)*
- `--timezone <IANA>` *(default: `Europe/Moscow`)*
- `--reboot <delay>` *(default: `5m`; `0|no|none|skip` disables)*
- `--ssh-port <port>` *(default: `22`, also used in Fail2ban jail)*

### Ports

- `--ports ask|skip` *(default: `ask` if TTY, otherwise `skip`)*
- `--open-ports "<list>"` *(comma/space-separated; overrides picker)*

### Remnanode

- `--remnanode 0|1` *(default: `0`)*
  - If `1`, script will ask (TTY) for `NODE_PORT` and `SECRET_KEY` and create `/opt/remnanode/docker-compose.yml` if missing.

### Tailscale

- `--tailscale 0|1` *(default: `0`)*
  - If enabled: installs Tailscale (if missing), applies forwarding sysctls + GRO tweaks, then runs `tailscale up` **only if not already authorized**.

### External tuning

- `--tuning 0|1` *(default: `1`)*
  - Runs:
    ```bash
    curl -fsSL https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh | sudo bash -s -- apply
    ```
  - If tuning fails, the main script continues and prints a warning.

### DNS switcher (`systemd-resolved`)

- `--dns-switch 0|1` *(default: `1`)*
- `--dns-profile 1..5` *(default: **auto**: interactive if TTY, else `1`)*
  - `1` — **echo "1" and skip interactive** (no DNS changes)
  - `2` — Google only (`8.8.8.8 8.8.4.4`)
  - `3` — Cloudflare only (`1.1.1.1 1.0.0.1`)
  - `4` — Quad9 (`9.9.9.9 149.112.112.112`)
  - `5` — Custom (requires `--dns-custom`, optional `--dns-fallback`)
- `--dns-custom "<servers>"` *(only for profile 5)*
- `--dns-fallback "<servers>"` *(only for profile 5; default: `9.9.9.9`)*

---

## Examples

### Minimal non-interactive install

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin --timezone=Europe/Moscow --ports=skip --reboot=0
```

### Enable Tailscale

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin --tailscale=1 --reboot=0
```

### DNS: set Cloudflare without prompts

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin --dns-switch=1 --dns-profile=3 --reboot=0
```

### DNS: custom

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --dns-switch=1 --dns-profile=5 \
  --dns-custom="9.9.9.9 149.112.112.112" \
  --dns-fallback="1.1.1.1" \
  --reboot=0
```

---

## Logs

- APT: `/var/log/initial-apt.log`
- Docker install: `/var/log/install-docker.log`
- Tailscale install: `/var/log/install-tailscale.log`

---

## External tuning rollback

If the external tuning script prints a `BACKUP_DIR=...`, you can roll it back like this:

```bash
sudo BACKUP_DIR=/root/edge-tuning-backup-YYYYMMDD-HHMMSS bash -c 'curl -fsSL https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh | bash -s -- rollback'
```

---

## Notes

- The script is designed to be re-runnable.
- DNS switcher **overwrites** `/etc/systemd/resolved.conf` and keeps backups in `/etc/dns-switcher-backup/`.

