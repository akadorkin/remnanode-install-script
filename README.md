# Remnanode VPS Edge Run

Production-ready **VPS bootstrap & hardening script** for running a **Remnawave / RemnaNode edge node** with secure defaults.

The current default model is:

- SSH stays on port `22`, but public SSH is closed by UFW by default.
- RemnaNode API listens on `2222`, but public access to `2222` is closed by UFW.
- Remna/Xray service ports `5443` and `5444` are closed publicly by UFW.
- `node_exporter` listens on `9100`, but public access is closed by UFW.
- `tailscale0` is fully trusted and allowed.
- Public ports are limited to `80/tcp`, `443/tcp`, `443/udp` for certificate issuance and public TLS/QUIC entry.
- UFW is enabled automatically at the end of the install.
- A reboot is scheduled automatically 3 minutes after successful install (disable with `--reboot=0`).
- The RUGOV nftables blacklist is **not** installed unless you pass `--rugov=1`.

> **No warranty.** Run this only on servers where you have root access and console/Tailscale recovery available.

---

## Requirements

- Ubuntu Server 22.04 / 24.04+
- Root access
- DNS `A` record already pointing to the server IPv4 when using `--remnanode=1`
- Tailscale account if using `--tailscale=1`

---

## TL;DR

### Full RemnaNode install with Tailscale

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --tailscale=1 \
  --remnanode=1 \
  --domain=node1.example.com \
  --secret-key='PASTE_REMNANODE_SECRET_KEY_HERE' \
  --tailscale-only=1 \
  --ports=skip
```

### Minimal base install without RemnaNode

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --tailscale=1 \
  --ports=skip
```

---

## What it installs/configures

1. Sets timezone to `Europe/Moscow`.
2. Optionally sets hostname.
3. Optionally installs and authorizes Tailscale with `tailscale up --ssh --advertise-exit-node` (auth key, tags, exit node and accept-dns are configurable).
4. Installs base packages, Docker CE, Fail2ban, HAProxy, UFW, cron, jq, dnsutils, etc.
5. Applies external kernel/network tuning.
6. Creates/updates sudo user and Zsh environment.
7. Hardens SSH: `PermitRootLogin no`, `PasswordAuthentication no`, SSH port fixed to `22`.
8. Creates or normalizes `/opt/remnanode/docker-compose.yml` when RemnaNode is enabled.
9. Installs roscomvpn geo updater with a daily 04:00 systemd timer (see [Geo files updater](#geo-files-updater)).
10. Issues/renews TLS certificate with Docker certbot into `/opt/certbot/certs`.
11. Installs Fail2ban jails: `sshd`, `sshd-fast`, `recidive`.
12. Optional, off by default (`--rugov=1`): RUGOV nftables input-only blacklist updater.
13. Configures UFW rules and enables UFW at the end.
14. Installs `node_exporter`.
15. Forces Cloudflare DNS via `systemd-resolved`.
16. Starts RemnaNode via Docker Compose.
17. Prints final summary and schedules reboot in 3 minutes (optional: `--reboot=0` skips it and the summary asks for a manual reboot).

---

## Firewall model

### Public `eth0`

Allowed by default:

- `80/tcp`
- `443/tcp`
- `443/udp`

Denied by default:

- `22/tcp`, `22/udp`
- `2222/tcp`, `2222/udp`
- `5443/tcp`, `5443/udp`
- `5444/tcp`, `5444/udp`
- `9100/tcp`, `9100/udp`

Torrent-related outbound ports are also denied:

- `6881:6999/tcp,udp`
- `51413/tcp,udp`
- `16881/tcp,udp`
- `2710/tcp,udp`
- `45682/tcp,udp`

### Tailscale

`tailscale0` is fully allowed inbound and outbound.

This means SSH, RemnaNode API, metrics, and internal service access should be done over Tailscale.

---

## Main flags

### Core

- `--user <name>` / `--user=<name>` / `user=<name>` — create or update sudo user.
- `--hostname <name>` / `--hostname=<name>` — set hostname.
- `--reboot 0|1` / `--reboot=0|1` — default `1`: reboot 3 minutes after successful install. `0`, `no` or `false` skips the reboot; reboot manually later. Any other value (legacy `--reboot <delay>`) counts as `1`.
- `--rugov 0|1` / `--rugov=0|1` — default `0`. `1` installs the RUGOV nftables input-only blacklist updater, its cron job and logrotate. With `0` nothing is installed; a blacklist installed by an earlier run is left as is.
- `--timezone` — ignored; timezone is fixed to `Europe/Moscow`.
- `--ssh-port` — ignored; SSH port is fixed to `22`.

### RemnaNode

- `--remnanode 0|1` / `--remnanode=0|1` — enable RemnaNode setup.
- `--domain <fqdn>` / `--domain=<fqdn>` — domain for certbot TLS certificate.
- `--secret-key <key>` / `--secret-key=<key>` / `secret_key=<key>` — RemnaNode `SECRET_KEY`.
- `--node-image <ref>` / `--node-image=<ref>` — RemnaNode image, e.g. a pinned tag or digest. Default for a new compose: `remnawave/node:latest`. An existing compose keeps its image unless this flag is given.

RemnaNode defaults:

- `NODE_PORT=2222`
- Compose path: `/opt/remnanode/docker-compose.yml`
- Cert path on host: `/opt/certbot/certs/live/remnanode/fullchain.pem`
- Certs mounted into container as `/etc/letsencrypt`

### Tailscale

- `--tailscale 0|1` / `--tailscale=0|1` — install/configure Tailscale.
- `--ts-authkey <key>` / `--ts-authkey=<key>` or env `TS_AUTHKEY` — log in with an auth key instead of the login URL; no "press Enter" prompt. The key is passed to Tailscale through a root-only temporary file and is never printed in the log or summary.
- `--ts-tags <tag:a,tag:b>` / `--ts-tags=<...>` — passed as `--advertise-tags`.
- `--exit-node 0|1` / `--exit-node=0|1` — default `1`. `0` drops `--advertise-exit-node`.
- `--ts-accept-dns 0|1` / `--ts-accept-dns=0|1` — not passed by default (Tailscale default applies). `0` adds `--accept-dns=false`, `1` adds `--accept-dns=true`.

When enabled, the script installs Tailscale if missing and by default runs:

```bash
tailscale up --ssh --advertise-exit-node
```

If the node is already authorized, it does not re-run `tailscale up`, so the flags above are not applied to it.

### Ports / firewall

- `--tailscale-only 0|1` — in RemnaNode mode, keeps only mandatory public `80/443`; everything else should be accessed over Tailscale.
- `--ports ask|skip` — controls interactive public port picker.
- `--open-ports "80,443"` — explicit external ports.
- `--enable-ufw-now` — deprecated; UFW is now enabled automatically at the end.

When `--remnanode=1`, ports `80` and `443` are always added because certbot and public TLS entry need them.

### DNS

DNS options are currently ignored. The script always writes Cloudflare DNS to `systemd-resolved`:

```text
DNS=1.1.1.1 1.0.0.1
FallbackDNS=9.9.9.9 149.112.112.112
```

Backups are stored in `/etc/dns-switcher-backup/`.

---

## Examples

### Recommended production RemnaNode

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --hostname=node-test \
  --tailscale=1 \
  --remnanode=1 \
  --domain=node1.example.com \
  --secret-key='PASTE_REMNANODE_SECRET_KEY_HERE' \
  --tailscale-only=1 \
  --ports=skip
```

### Re-run on existing node, preserving existing Remna secret from compose

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --tailscale=1 \
  --remnanode=1 \
  --domain=node1.example.com \
  --tailscale-only=1 \
  --ports=skip
```

### Unattended / fleet use

No questions asked: Tailscale login by auth key, tagged node, no exit node, no RUGOV, no automatic reboot, pinned node image.

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --hostname=node1 \
  --tailscale=1 \
  --ts-authkey=tskey-XXXX \
  --ts-tags=tag:edge \
  --exit-node=0 \
  --remnanode=1 \
  --domain=node1.example.com \
  --secret-key='PASTE_REMNANODE_SECRET_KEY_HERE' \
  --node-image=remnawave/node:X.Y.Z \
  --tailscale-only=1 \
  --ports=skip \
  --rugov=0 \
  --reboot=0
```

`TS_AUTHKEY=tskey-XXXX` in the environment works instead of `--ts-authkey` and keeps the key out of the shell history. With `--reboot=0`, reboot the server yourself when convenient.

### Base hardening only

```bash
curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/vps-edge-run.sh | sudo bash -s -- \
  --user=akadorkin \
  --tailscale=1 \
  --ports=skip
```

---

## Post-reboot check

Run after reboot:

```bash
echo "=== HOST ===" && hostnamectl --static && \
echo && echo "=== SERVICES ===" && systemctl is-active docker tailscaled fail2ban node_exporter && \
echo && echo "=== TAILSCALE ===" && tailscale ip -4 && tailscale status --self && \
echo && echo "=== REMNANODE ===" && docker ps --format 'table {{.Names}}\t{{.Status}}' && \
echo && echo "=== CERT ===" && openssl x509 -in /opt/certbot/certs/live/remnanode/fullchain.pem -noout -subject -enddate && \
echo && echo "=== PORTS ===" && ss -lntup | grep -E ':80 |:443 |:2222 |:5443 |:5444 |:9100 ' || true && \
echo && echo "=== GEO ===" && systemctl is-active update-roscomvpn-geo.timer && \
echo && echo "=== FIREWALL ===" && ufw status numbered
```

Only with `--rugov=1`:

```bash
grep -R update-rugov-nftables /etc/cron.d && nft list ruleset | grep -i -A8 -B5 'blacklist_v4\|rugov_input'
```

Expected essentials:

- `docker`, `tailscaled`, `fail2ban`, `node_exporter` are `active`.
- `remnanode` container is `Up`.
- Certificate exists under `/opt/certbot/certs/live/remnanode/`.
- UFW is `active`.
- `tailscale0` is allowed.
- Public `80/tcp`, `443/tcp`, `443/udp` are allowed.
- Public `22`, `2222`, `5443`, `5444`, `9100` are denied.

---

## Important paths

- Main compose: `/opt/remnanode/docker-compose.yml`
- Remna logs: `/var/log/remnanode/`
- Certbot compose: `/opt/certbot/docker-compose.yml`
- Certificates: `/opt/certbot/certs/live/remnanode/`
- Geo files: `/opt/remnanode/roscomvpn-*.dat`
- Geo updater: `/usr/local/sbin/update-roscomvpn-geo.sh`, settings: `/etc/default/update-roscomvpn-geo`, state: `/var/lib/roscomvpn-geo/`
- RUGOV updater (`--rugov=1`): `/usr/local/sbin/update-rugov-nftables`
- RUGOV cron (`--rugov=1`): `/etc/cron.d/update-rugov-nftables`
- APT log: `/var/log/initial-apt.log`
- Docker install log: `/var/log/install-docker.log`
- Tailscale install log: `/var/log/install-tailscale.log`
- RUGOV log (`--rugov=1`): `/var/log/update-rugov-nftables.log`
- Fail2ban log: `/var/log/fail2ban.log`

---

## Geo files updater

`update-roscomvpn-geo.sh` runs daily at 04:00. Upstream publishes new files every day, so the updater does **not** restart RemnaNode on every change:

- downloaded files are validated (size, and `rw-core -test` inside the container) and written in place, into the same inode, so the bind-mounted files stay visible to the container;
- RemnaNode is restarted only if a changed file is referenced by the running Xray config (`ext:roscomvpn-geoip.dat:...` / `ext:roscomvpn-geosite.dat:...`) and the container has been up for at least 3 days; otherwise the new files take effect on the next restart;
- if the running config cannot be read, nothing is restarted.

Optional settings in `/etc/default/update-roscomvpn-geo`:

```bash
RESTART_MIN_DAYS=3
# restart only while the panel answers; Xray does not start without a config from the panel
REMNA_PANEL_URLS="https://panel.example.com/"
```

Dry run: `sudo DRY=1 /usr/local/sbin/update-roscomvpn-geo.sh`.

---

## External tuning rollback

If the external tuning script printed a backup path, rollback example:

```bash
sudo BACKUP_DIR=/root/edge-tuning-backup-YYYYMMDD-HHMMSS bash -c 'curl -fsSL https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh | bash -s -- rollback'
```

---

## Notes

- The script is designed to be re-runnable.
- Existing RemnaNode `SECRET_KEY` can be reused from `/opt/remnanode/docker-compose.yml`.
- UFW is reset and regenerated on each run.
- Fail2ban bans may appear before allow/deny rules in `ufw status numbered`; this is normal.
- Some services can listen on `0.0.0.0`, but UFW blocks public access to internal ports.
- Do not paste the shell prompt symbol `❯` into commands.
