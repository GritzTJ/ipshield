# Installation guide

Current release: **v1.1.0**

**[🇬🇧 English](#english) · [🇫🇷 Français](#français)**

---

<a id="english"></a>
## 🇬🇧 English

Installation guide for the automatic IPv4 blocklist updater.

`v1.1.0` has been validated on Ubuntu 24.04 LTS, Debian 12, Debian 13 and Fedora 44 with the recommended firewall paths described below.

### Prerequisites

The script requires **root** access and the following commands: `curl`, `awk`, `sort`, `wc`, `date`, `comm`, `flock`, `ipset`, `logger`.

#### Debian / Ubuntu

```bash
apt update
apt install -y curl gawk coreutils ipset util-linux bsdutils
```

#### Fedora

```bash
dnf install -y curl gawk coreutils ipset util-linux
```

> `sort`, `wc`, `date` and `comm` are provided by **coreutils**, `flock` by **util-linux**, `logger` by **bsdutils** (Debian) or **util-linux** (Fedora). `awk` is covered by **gawk**.

### Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
```

### Configuration

`/etc/update-blocklist.conf` is **required** by `update-blocklist.sh` and `lookup-ip.sh`. It is the **single source of truth** for URLs and defaults.

`setup-firewall.sh` automatically copies `update-blocklist.conf.example` to `/etc/update-blocklist.conf` (chmod 600, owner root) during installation. Manual install if needed:

```bash
cp update-blocklist.conf.example /etc/update-blocklist.conf
chown root:root /etc/update-blocklist.conf
chmod 600 /etc/update-blocklist.conf
```

Variables (all defined with their production-ready values in the example file):

| Variable | Default | Description |
|---|---|---|
| `URLS` | see below | Array of blocklist URLs |
| `SET_NAME` | `blacklist` | ipset blacklist name (max 31 chars) |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | ipset whitelist name (max 31 chars) |
| `WHITELIST` | `()` (empty) | Array of always-allowed IPv4 addresses/CIDRs (see [Whitelist](#whitelist)) |
| `WHITELIST_MIN_PREFIX` | `8` | Minimum WHITELIST prefix accepted (rejects /0 to /7 to prevent total bypass via typo). Set to 0 to disable. |
| `BLOCKLIST_MIN_PREFIX` | `8` | Minimum prefix accepted from external blocklist sources (rejects /0 to /7). Catches a corrupted/malicious source injecting `0.0.0.0/0` which would lock out the whole server. Set to 0 to disable. |
| `MIN_ENTRIES` | `1000` | Minimum entries threshold (anti-purge protection) |
| `BASE_HASHSIZE` | `16384` | Base ipset hashsize |
| `BASE_MAXELEM` | `300000` | Base ipset maxelem |
| `LOG_LIMIT` | `60/min` | Blocked-packet log rate-limit (`N/sec`, `N/min`, `N/hour`, `N/day`; empty = no limit) |
| `LOG_BURST` | `100` | Maximum burst before `LOG_LIMIT` applies |
| `WAN_INTERFACE` | `""` (auto) | WAN interface used to scope the DOCKER-USER rule to inbound traffic only. Empty = auto-detected via `ip route get 8.8.8.8`. Set explicitly if auto-detection picks the wrong interface (e.g. VPN). |
| `LOOKUP_CACHE_TTL` | `21600` | Cache TTL in seconds for `lookup-ip.sh` source downloads (`0` disables cache) |

#### Default sources

The script downloads and aggregates the following lists:

| Source | Description |
|---|---|
| [Data-Shield IPv4 Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Critical malicious IP list |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked network ranges |
| [Emerging Threats](https://rules.emergingthreats.net/) | IPs blocked by ET rules |
| [CI Army (CINS)](https://cinsscore.com/) | IPs with poor reputation score |
| [AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb) | IPs reported with 100% score over 365 days |
| [FireHOL Level 1](https://iplists.firehol.org/) | Curated meta-list, low false-positive |
| [GreenSnow](https://blocklist.greensnow.co/) | Active SSH/HTTP brute-force IPs |
| [Blocklist.de](https://www.blocklist.de/) | Reported IPs (SSH, mail, web, FTP, etc.) |
| [IPsum](https://github.com/stamparm/ipsum) | Aggregator of 30+ sources, IPs in ≥3 lists |
| [Tor exit nodes](https://check.torproject.org/torbulkexitlist) | Tor exit nodes |
| [Internet Scanner IPs](https://github.com/palinkas-jo-reggelt/List_of_Internet_Scanner_IPs) | Aggregated /24 ranges of known internet scanners (Shodan, Censys, ONYPHE, GreyNoise, etc.) |

These sources are customisable via the `URLS` variable in `/etc/update-blocklist.conf`.

### Usage

#### Step 1: Install a firewall (one-time)

`setup-firewall.sh` detects, installs and enables a firewall on the system:

```bash
./setup-firewall.sh
```

The script:
1. Detects the active firewall (firewalld, ufw, nftables or iptables)
2. Offers a menu with the 4 options
3. Auto-detects listening TCP/UDP ports (non-loopback) and offers to open them before activation (anti-lockout). The prompt is **skipped** when the chosen firewall has a permissive INPUT policy (ACCEPT by default — common case on fresh Debian/Ubuntu with iptables/nftables): adding ACCEPT rules would be no-ops. When the firewall is deny-by-default (ufw, firewalld, or a hardened iptables/nftables), the prompt is shown and the resulting ports are persisted via `ipshield-safe-ports.service` (a systemd unit ordered before sshd/docker so admin access is restored at boot).
4. Disables the previous firewall if a different one is chosen (with automatic rollback on failure)
5. Installs and enables the new firewall
6. Verifies the firewall responds after activation (otherwise rolls back)
7. **Installs `/etc/update-blocklist.conf`** from `update-blocklist.conf.example` if missing (chmod 600, owner root). Existing files are preserved to keep user changes intact.
8. **Installs `ipshield-restore.service`** when `PERSIST_IPSET=1` (the default): a systemd oneshot ordered `Before=netfilter-persistent.service nftables.service ufw.service firewalld.service` that runs `ipset restore -! -f $IPSET_SAVE_FILE` at boot. Without it, persistent firewalls (`ufw`, `firewalld` on iptables-nft) can fail to start when their rules reference an ipset that does not exist yet. Pre-creates `/var/lib/ipshield/` and the per-source LKG cache directory. Idempotent (compares content; only enables once). Skipped automatically when `PERSIST_IPSET=0`.
9. **Installs `ipshield.timer` + `ipshield.service`**: the timer fires `OnBootSec=2min` and `OnCalendar=*-*-* 00,08,16:00:00` with `RandomizedDelaySec=5min` and `Persistent=true` (catches a missed run if the machine was off). The service is a `Type=oneshot` unit that just runs `update-blocklist.sh`. Logs go to journald (`journalctl -u ipshield.service`). Idempotent (rerun to update).
10. **Installs `ipshield-apply.service`**: a systemd unit ordered `After=ipshield-restore.service nftables.service docker.service` that runs `update-blocklist.sh --apply-only` at boot. This attaches the firewall rules to the restored ipset within seconds of Docker being up, without re-downloading the blocklist. The `After=docker.service` is opportunistic — there is no `Wants=`/`Requires=` on Docker, so on a Docker-less host the unit fires as soon as `ipshield-restore.service` (and `nftables.service` if present) are done, and `update-blocklist.sh` simply skips the DOCKER-USER chain when it is not detected. If the ipset is missing or empty (e.g. corrupted save file, `PERSIST_IPSET=0`), it falls back to a full update so the system is never left unprotected.
11. **Installs the rsyslog filter + logrotate** when rsyslog is active: `30-blocked-ips.conf` to redirect `BLOCKED:` to `/var/log/blocked-ips.log`, plus two logrotate configs (rotate 4 weekly). Idempotent (compares content, only rewrites if different or absent). If rsyslog is missing (e.g. minimal Debian), a sub-prompt offers to install it; declining keeps logs in journald (viewable via `journalctl -k --grep 'BLOCKED:'`) with the logrotate config still installable on its own.

> If the chosen firewall is already active (no transition needed), `setup-firewall.sh` can still review/open listening ports on the active firewall, then continues to steps 7-11. The port review prompt defaults to `no`.

Backend selection details:

- Choosing **iptables** selects `iptables-legacy`/`ip6tables-legacy` via `update-alternatives` on systems that provide it when those binaries are available.
- Choosing **nftables** selects `iptables-nft`/`ip6tables-nft` via `update-alternatives` on systems that provide it when those binaries are available, because the project applies nftables-path rules through iptables-nft to keep ipset matching support.

Security scope: ipshield installs blocklist rules. It does **not** turn direct `iptables`/`nftables` into a full default-deny firewall. On those paths, non-blacklisted traffic remains accepted unless you harden the host separately.

Docker safety: if Docker iptables chains are present, `setup-firewall.sh` does not blindly modify the firewall. It offers a guided maintenance path: stop Docker, clean Docker-owned iptables/nft compatibility chains, continue the firewall transition or backend switch, then restart Docker. If containers are running, the prompt defaults to `no` because published ports and containers may be interrupted. In production, prefer stopping application stacks cleanly first (for example `docker compose down`), then rerun `setup-firewall.sh`; stopping the Docker daemon is not equivalent to a clean Compose/application shutdown. If Docker is active but no containers are running, the prompt defaults to `yes`.

Docker-friendly transitions: when the transition is provably non-destructive — target firewall is `iptables` or `nftables`, no previous firewall has to be deactivated (`DETECTED=none`), and the iptables backend already matches the chosen target — `setup-firewall.sh` **skips the Docker stop entirely** and leaves running containers online. The destructive transitions (existing iptables flush, backend switch, ufw or firewalld activation) still go through the guided Docker stop path.

nftables.service restart safety: on **every** install or rerun with target `nftables`, `setup-firewall.sh` applies two complementary patches so that `systemctl restart nftables` no longer wipes the iptables-nft `ip filter` table (which holds the ipshield blocklist LOG/DROP rules, and Docker-maintained rules when Docker is present):

1. `/etc/nftables.conf` is patched in-place (backup `.ipshield.bak`) to comment out `flush ruleset`, so the ExecStart reload of the conf does not wipe existing tables.
2. A systemd drop-in `/etc/systemd/system/nftables.service.d/ipshield.conf` clears the default `ExecStop=/usr/sbin/nft flush ruleset` (the actual wipe trigger that runs before `ExecStart` on every restart).

Without (2), patching only the conf is ineffective at restart: `ExecStop` fires the flush before `ExecStart` re-reads the conf. Both patches are idempotent on rerun and applied independently of Docker. Removing the drop-in restores the default systemd behaviour where `systemctl restart nftables` wipes everything.

Ubuntu UFW note: `ufw.service` can be active/enabled even when `ufw status` is `inactive`. In that state UFW is not filtering traffic, but the service state is confusing when another firewall is selected. If `setup-firewall.sh` detects this while installing another firewall, it offers to run `systemctl disable --now ufw`. When transitioning away from active UFW, it also removes ipshield/orphan ipset lines from `/etc/ufw/before.rules` first, with a backup.

#### Step 2: Run the blocker (first execution)

Test in simulation mode:

```bash
./update-blocklist.sh --dry-run --verbose
```

Then run for real:

```bash
./update-blocklist.sh --verbose
```

The script:
1. Downloads the malicious IP lists
2. Updates the ipset via atomic swap
3. Auto-detects the active firewall
4. Applies LOG + DROP rules idempotently

Verify the ipset is created:

```bash
ipset list blacklist | head -10
```

> `update-blocklist.sh` works standalone (without `setup-firewall.sh`) as it auto-detects the existing firewall.

#### Identify the source of a blocked IP

When an IP appears in the logs (`BLOCKED:`), identify its source:

```bash
./lookup-ip.sh 185.199.108.133
./lookup-ip.sh --verbose 1.2.3.4
```

The script downloads the lists on the fly and reports which source(s) reference the IP. Downloads are cached for `LOOKUP_CACHE_TTL` seconds (default: 6 hours, set `LOOKUP_CACHE_TTL=0` to disable). Works without root (the ipset check is skipped).

Cache mechanics:

- **Location**: `/var/cache/ipshield/lookup/` when run as root, `${XDG_CACHE_HOME:-$HOME/.cache}/ipshield/lookup/` otherwise. Each user keeps its own cache; the root cache is the one cleaned by `uninstall.sh --apply`.
- **Naming**: one file per URL, named `<sha256(URL)>.txt`. The hash is content-addressed, so reordering `URLS` in the config is free — only adding/editing/removing a URL changes a file name.
- **Orphan pruning**: at every run, files whose basename does not match any current URL hash are deleted. This also sweeps the legacy `source-<idx>-<cksum>.txt` files from versions prior to v1.1.0. Deletions are logged in `-v` mode only.
- **Freshness check**: a cached file is reused when it is non-empty and `now - mtime < LOOKUP_CACHE_TTL`. Otherwise the source is re-downloaded and the cache replaced atomically (`mv` after `cp` to a `.tmp`).
- **Manual reset**: `rm -rf /var/cache/ipshield/lookup/` (root) or `rm -rf ~/.cache/ipshield/lookup/` (user). The next run rebuilds what it needs. There is no `--no-cache` CLI flag; `LOOKUP_CACHE_TTL=0 ./lookup-ip.sh ...` forces a one-shot bypass.

### Whitelist

To allow specific IPs/subnets to bypass the blocklist (typically your management IPs/subnets), set the `WHITELIST` variable in `/etc/update-blocklist.conf`:

```bash
WHITELIST=(
  "10.0.0.0/8"
  "172.16.0.0/12"
  "192.168.0.0/16"
  "203.0.113.42"
)
```

On the next run, the script:

1. Creates a second ipset (`blacklist-allow` by default) via atomic swap
2. Inserts an `ACCEPT` rule at position 1 on `INPUT` (and `DOCKER-USER` if present)
3. If `WHITELIST` is later emptied: the ACCEPT rule and the whitelist ipset are automatically removed on the next run

The whitelist ipset name is `WHITELIST_SET_NAME` (`${SET_NAME}-allow` by default). It must use only `[a-zA-Z0-9_-]`, be 31 characters or less, and differ from `SET_NAME`.

> **Warning**: the ACCEPT rule bypasses **the entire firewall**, not only the blocklist. A whitelisted IP has full server access regardless of other rules. Reserve for trusted IPs/subnets only.

> **Anti-typo safeguard**: by default, any prefix < `/8` is rejected (`WHITELIST_MIN_PREFIX=8`). This blocks the classic `0.0.0.0/0` typo that would open the whole Internet to a total bypass. To allow a wider prefix, lower `WHITELIST_MIN_PREFIX` explicitly.

#### Boot-time ipset persistence and fast rule reattach

**Problem.** At server boot, the `ipset blacklist` (which lives in RAM) is empty unless it is restored from disk before persistent firewall rules start. And on `iptables`/`nftables`, the runtime LOG/DROP rules that reference the ipset do not persist either: they need to be (re)attached after boot. Without a dedicated mechanism this would leave a fail-open window:

- **iptables / nftables**: ipshield LOG/DROP rules are runtime rules and are not persisted to disk by default → fail-open until they are reapplied.
- **ufw / firewalld with iptables-nft**: persistent rules may reference an ipset that does not exist yet. On modern Ubuntu/Debian this can make firewall reload/start fail with `Set <name> doesn't exist`.

`ipshield` ships two systemd units that, together, close the boot window to under two seconds:

1. **`ipshield-restore.service`** (early): restores `/var/lib/ipshield/ipset.save` before `ufw.service`, `firewalld.service` and `nftables.service` start. Provides the ipset data.
2. **`ipshield-apply.service`** (after Docker, when present): runs `update-blocklist.sh --apply-only`, ordered `After=ipshield-restore.service nftables.service docker.service`. The `After=` is opportunistic — no `Wants=docker.service` is declared, so on a Docker-less host the unit starts as soon as the other ordering constraints are satisfied and `update-blocklist.sh` simply skips the DOCKER-USER chain. Skips the ~30s download/parse/swap cycle and just attaches the LOG/DROP rules (and DOCKER-USER rules, when Docker is present) to the ipset that step 1 has loaded. Falls back to a full update if the ipset save file is missing or empty (e.g. `PERSIST_IPSET=0`, corrupted file, first boot after a fresh install) so the host is never left unprotected.

`update-blocklist.sh` saves the ipshield sets after each successful run when `PERSIST_IPSET=1` (default), feeding the two units above. The recurring blocklist refresh runs through `ipshield.timer` (see "Scheduling" below); the `OnBootSec=2min` trigger replaces the legacy `@reboot sleep 60 && ...` cron line, with the systemd ordering removing the need for an arbitrary `sleep`.

Relevant config:

```bash
PERSIST_IPSET=1
IPSET_SAVE_FILE="/var/lib/ipshield/ipset.save"
```

For direct `iptables`, persistence is still optional: rules are not persistent by default, so `ipshield-apply.service` is what actually puts protection back. For `ufw` and `firewalld`, both units matter.

#### Migration: legacy nftables admin_access priority bug

`setup-firewall.sh` versions before 2026-04-28 created the `inet admin_access input` nftables chain at priority `-10` (before the blocklist at priority 0). Result: on an nftables setup, blacklisted IPs still passed through on SAFE_PORTS (including SSH) because the admin_access `accept` evaluated before the blocklist `drop`.

`setup-firewall.sh` automatically detects this buggy setup at startup and migrates the chain to priority `10` (after the blocklist), preserving the previously-opened ports. **Run `./setup-firewall.sh` once**; a `Migration: 'inet admin_access input' chain detected at priority -10 (legacy bug).` message confirms the fix. Other firewalls (iptables, ufw, firewalld) are not affected.

Verification:

```bash
ipset list blacklist-allow | head -10
iptables -S INPUT | grep blacklist-allow
```

### Uninstall

`uninstall.sh` removes ipshield rules (LOG/DROP blocklist + ACCEPT whitelist), destroys the associated ipsets, removes ipshield/orphan rules from `/etc/ufw/before.rules` line by line, and can disable/remove `ipshield-restore.service` and `ipshield-apply.service`. It **does not uninstall** the firewall or any packages.

```bash
# Dry-run mode (default): shows what would be done
./uninstall.sh

# Real apply (with interactive confirmation)
./uninstall.sh --apply
```

In `--apply` mode, after rules and ipsets are removed, the project-owned components are removed automatically (no prompt): `ipshield-restore.service`, `ipshield-apply.service`, `ipshield.timer` + `ipshield.service`, the `ipshield-safe-ports.service`, the `nftables.service` drop-in (and the `/etc/nftables.conf` restore from `.ipshield.bak`), and the `/etc/rsyslog.d/30-blocked-ips.conf` + `/etc/logrotate.d/{update-blocklist,blocked-ips}` configs (rsyslog is restarted if the filter is removed).

Two prompts then offer to remove user-editable data:
1. `/etc/update-blocklist.conf`, the ipset persistence file (usually `/var/lib/ipshield/ipset.save`), the per-source LKG cache directory (usually `/var/lib/ipshield/sources/`), and the `lookup-ip.sh` mirror cache (`/var/cache/ipshield/lookup/`, root path only — per-user caches under `$XDG_CACHE_HOME` are left untouched);
2. ipshield log files matching `/var/log/update-blocklist.log*` and `/var/log/blocked-ips.log*`, including rotated/compressed files.

Journald entries are not purged; journal vacuuming is a global system operation.

### Docker support

On a Docker host, traffic destined for containers (ports published via `-p` / `ports:`) flows through the `FORWARD` chain, not `INPUT`. Without additional protection, blocked IPs would still reach the containers.

The script automatically detects Docker via the `DOCKER-USER` chain in iptables. When present, the same LOG + DROP rules are applied on `DOCKER-USER` in addition to `INPUT`, **scoped to the WAN interface** (`-i $WAN_INTERFACE`) to filter only **inbound** traffic from the Internet to containers. Outbound traffic from containers (which goes via `IN=br-xxx`) is never filtered, in line with the "filter inbound only" principle.

On **firewalld**, `INPUT` rules are still managed through permanent direct rules, but Docker `DOCKER-USER` rules are applied at runtime through iptables only. They are deliberately not stored as permanent firewalld direct rules, because firewalld can fail to start or reload if Docker has not created `DOCKER-USER` yet. If an older ipshield version left such permanent rules behind, the next `update-blocklist.sh` run removes them before applying runtime Docker rules.

Blocklist rules are also scoped to `conntrack --ctstate NEW`. For TCP, this means normal inbound connections are blocked at connection start (the SYN path), while replies to outbound connections already tracked as `ESTABLISHED` are not dropped just because the remote IP appears in a public blocklist.

**WAN interface auto-detection**: by default, the script detects the interface via `ip route get 8.8.8.8`. If auto-detection picks the wrong interface (VPN/multi-homed), set `WAN_INTERFACE="ens160"` in `/etc/update-blocklist.conf`.

**Bogon filter (RFC 6890)**: the script automatically rejects any IP/CIDR in reserved ranges (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, multicast, etc.). Prevents a public-source false positive from blocking the LAN or Docker bridge (real-world case: FireHOL Level 1 includes bogons by design).

**Notes:**

- Docker recreates `DOCKER-USER` on each daemon restart — rules do not persist. `ipshield-apply.service` (at boot) and `ipshield.timer` (`OnBootSec=2min` + every 8 h) reapply them, and idempotency avoids duplicates.
- If the script runs at boot before Docker, `DOCKER-USER` does not exist yet — the detection is correctly negative. The next timer run picks it up.
- `setup-firewall.sh` handles Docker firewall transitions interactively: when Docker chains are present, it can stop Docker, clean Docker-owned chains, continue setup, then restart Docker. If Docker reports a missing `DOCKER` chain after a manual firewall change, restart Docker so it recreates its NAT/filter chains.
- No configuration needed if WAN auto-detection works: detection and application are fully automatic.

Verification after a run:

```bash
iptables -L DOCKER-USER -n -v
```

LOG + DROP rules with `ctstate NEW`, `match-set blacklist src` and `in ens160` (or your detected WAN interface) should appear.

### Scheduling (systemd timer)

`setup-firewall.sh` installs `ipshield.timer` + `ipshield.service` at the end of its execution (step 9). This is the recommended method — idempotent, no prompt, and `systemctl enable --now ipshield.timer` is run automatically.

To reconfigure later without touching firewall rules: rerun `./setup-firewall.sh`, pick the already-active firewall, then answer `no` to the port review prompt.

The default schedule:

```ini
# /etc/systemd/system/ipshield.timer
[Timer]
OnBootSec=2min
OnCalendar=*-*-* 00,08,16:00:00
RandomizedDelaySec=5min
Persistent=true
Unit=ipshield.service
```

- `OnBootSec=2min` fires a refresh shortly after each boot. The boot-time *fast attach* (without re-downloading) is still handled by `ipshield-apply.service` (ordered `After=docker.service`); the timer adds the network refresh on top.
- `OnCalendar=*-*-* 00,08,16:00:00` fires three times a day.
- `RandomizedDelaySec=5min` jitters every firing by up to 5 minutes.
- `Persistent=true` catches up a missed calendar run when the machine was off.
- Logs (stdout/stderr of `update-blocklist.sh`) are appended to `/var/log/update-blocklist.log` (via `StandardOutput=append:` / `StandardError=append:` in the unit) **and** mirrored to journald: `journalctl -u ipshield.service` (add `-f` to follow, `-S "1 hour ago"` to scope by time).
- Status: `systemctl list-timers ipshield.timer` shows the next firing and the last activation.

#### Manual configuration (alternative)

If you prefer to install the units manually (same content as `configure_timer`):

```bash
cat > /etc/systemd/system/ipshield.service <<'EOF'
[Unit]
Description=ipshield blocklist refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/path/to/update-blocklist.sh
StandardOutput=append:/var/log/update-blocklist.log
StandardError=append:/var/log/update-blocklist.log
EOF

cat > /etc/systemd/system/ipshield.timer <<'EOF'
[Unit]
Description=ipshield blocklist refresh schedule

[Timer]
OnBootSec=2min
OnCalendar=*-*-* 00,08,16:00:00
RandomizedDelaySec=5min
Persistent=true
Unit=ipshield.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now ipshield.timer
```

In a manual setup, also enable `ipshield-apply.service` to keep the fast boot reattach: `setup-firewall.sh` installs it under `/etc/systemd/system/ipshield-apply.service` and runs `systemctl enable ipshield-apply.service`.

### Logs

> **Recommended setup**: `setup-firewall.sh` installs the rsyslog filter and the two logrotate configs automatically when rsyslog is active (step 11), or offers to install rsyslog itself if missing. Idempotent (replaying only rewrites on diff). The sections below are the equivalent manual procedure.

#### Script logrotate

Create `/etc/logrotate.d/update-blocklist`:

```bash
cat > /etc/logrotate.d/update-blocklist << 'EOF'
/var/log/update-blocklist.log {
	su root root
	create 0644 root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
}
EOF
```

> The `su root root` directive is required by logrotate >= 3.18 because `/var/log/` is owned by `root:syslog` (group-writable) on Debian/Ubuntu. Without it, rotation is silently skipped on stricter setups. Standard pattern, also used by `/etc/logrotate.d/ubuntu-pro-client`. `create 0644 root root` ensures the file exists immediately after rotation (otherwise it would only reappear on the next `ExecStart`).

#### Blocked-IP logs

By default, logging is **rate-limited** to **60 logs/min with burst 100** (`LOG_LIMIT="60/min"`, `LOG_BURST=100`). Under heavy attack, all packets are still **dropped** but only a sample appears in the logs — to prevent saturating `/var/log/`.

To adjust:
- `LOG_LIMIT="600/min"` + `LOG_BURST=1000`: more visibility, more flood risk
- `LOG_LIMIT=""` (empty): no rate-limit, logs **everything** (real risk under attack)
- See `update-blocklist.conf.example` for details

For iptables/nftables/firewalld/ufw/DOCKER-USER, drift is auto-detected: change `LOG_LIMIT` and run `update-blocklist.sh` to update the rules.

Rules applied by `update-blocklist.sh` all use the `BLOCKED: ` prefix in their logs, regardless of the firewall:

| Firewall | Log mechanism | Raw destination |
|---|---|---|
| **iptables** | `-j LOG --log-prefix "BLOCKED: "` | kernel log → syslog |
| **nftables** | Via `iptables-nft`: `-j LOG --log-prefix "BLOCKED: "` | kernel log → syslog |
| **firewalld** | Direct rules with `-j LOG` (same mechanism as iptables) | kernel log → syslog |
| **ufw** | Rules in `before.rules` with `-j LOG` (same mechanism as iptables) | kernel log → syslog |

All firewalls go through kernel logging (netfilter), allowing **a single rsyslog filter** to redirect to `/var/log/blocked-ips.log`.

#### rsyslog filter

Create `/etc/rsyslog.d/30-blocked-ips.conf`:

```bash
cat > /etc/rsyslog.d/30-blocked-ips.conf << 'EOF'
template(name="blockedFormat" type="string"
  string="%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute%:%timestamp:::date-second% %msg%\n")

:msg, contains, "BLOCKED: " /var/log/blocked-ips.log;blockedFormat
& stop
EOF
```

Then restart rsyslog:

```bash
systemctl restart rsyslog
```

The `& stop` prevents `BLOCKED: ` messages from also appearing in `/var/log/syslog` or `/var/log/kern.log`.

> **ufw note**: packets blocked by our `before.rules` rules appear in `/var/log/blocked-ips.log` via rsyslog, but **not** in `/var/log/ufw.log` because our LOG+DROP rules execute before ufw's own logging.

> **nftables note**: blocking rules are applied via `iptables-nft`. The log mechanism is identical to iptables (`-j LOG`), captured by the same rsyslog filter.

#### Blocked-IP logrotate

Create `/etc/logrotate.d/blocked-ips`:

```bash
cat > /etc/logrotate.d/blocked-ips << 'EOF'
/var/log/blocked-ips.log {
	su root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	postrotate
		if [ -x /usr/lib/rsyslog/rsyslog-rotate ]; then
			/usr/lib/rsyslog/rsyslog-rotate
		else
			/bin/systemctl reload rsyslog 2>/dev/null || true
		fi
	endscript
}
EOF
```

### Supported firewalls

| Firewall | Recommendation |
|---|---|
| **iptables** | Legacy fallback for old/minimal systems; setup selects `iptables-legacy` when available |
| **nftables** | Recommended for Ubuntu/Debian production servers; setup selects `iptables-nft` for ipset matching |
| **firewalld** | Recommended for Fedora/RHEL-family production servers |
| **ufw** | Ubuntu-friendly frontend; supported, but `nftables` is preferred for new production installs |

### Validated platforms

| Platform | Firewall path validated |
|---|---|
| Ubuntu 24.04 LTS | nftables, ufw |
| Debian 12 | nftables |
| Debian 13 | nftables, iptables legacy |
| Fedora 44 | firewalld, nftables |

Validation included fresh installation, blocklist update, reboot restore, TCP/UDP inbound blocking, Docker `DOCKER-USER` protection, logging/logrotate and clean uninstall where applicable.

### Manual firewall configuration (alternative)

If you prefer to configure the rules manually instead of using `update-blocklist.sh`:

#### iptables

```bash
iptables -I INPUT -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I INPUT 2 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

Persistence:

```bash
# Debian / Ubuntu
apt install -y iptables-persistent
netfilter-persistent save

# Fedora
dnf install -y iptables-services
service iptables save
```

#### nftables

nftables cannot reference ipset sets natively (the `@set` syntax only applies to native nft sets). On nftables systems, `iptables` is provided by `iptables-nft`, which translates the commands into nft rules internally while supporting ipset matching via the kernel `xt_set` module:

```bash
iptables -I INPUT -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I INPUT 2 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

#### firewalld

```bash
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
firewall-cmd --reload
```

#### ufw

Add to `/etc/ufw/before.rules` (in the `*filter` section, before `COMMIT`):

```
-A ufw-before-input -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
-A ufw-before-input -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

Then `ufw reload`.

#### Docker (DOCKER-USER)

On a Docker host, add the same rules to the `DOCKER-USER` chain to protect the containers. Important: scope to the WAN interface (e.g. `ens160`) to filter inbound only and let container egress through:

```bash
iptables -I DOCKER-USER -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I DOCKER-USER 2 -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

> `update-blocklist.sh` does this automatically when Docker is detected, with WAN interface auto-detection. Manual configuration is only required if you do not use the script.

---

<a id="français"></a>
## 🇫🇷 Français

Guide d'installation du script de mise à jour automatique d'un ipset de blocage IPv4.

`v1.1.0` a été validée sur Ubuntu 24.04 LTS, Debian 12, Debian 13 et Fedora 44 avec les chemins firewall recommandés ci-dessous.

### Prérequis

Le script nécessite un accès **root** et les commandes suivantes : `curl`, `awk`, `sort`, `wc`, `date`, `comm`, `flock`, `ipset`, `logger`.

#### Debian / Ubuntu

```bash
apt update
apt install -y curl gawk coreutils ipset util-linux bsdutils
```

#### Fedora

```bash
dnf install -y curl gawk coreutils ipset util-linux
```

> `sort`, `wc`, `date` et `comm` sont fournis par **coreutils**, `flock` par **util-linux**, `logger` par **bsdutils** (Debian) ou **util-linux** (Fedora). `awk` est couvert par **gawk**.

### Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
```

### Configuration

`/etc/update-blocklist.conf` est **requis** par `update-blocklist.sh` et `lookup-ip.sh`. C'est la **source de vérité unique** pour les URLs et les défauts.

`setup-firewall.sh` copie automatiquement `update-blocklist.conf.example` vers `/etc/update-blocklist.conf` (chmod 600, owner root) lors de l'installation. En cas de besoin manuel :

```bash
cp update-blocklist.conf.example /etc/update-blocklist.conf
chown root:root /etc/update-blocklist.conf
chmod 600 /etc/update-blocklist.conf
```

Variables (toutes définies avec leur valeur prod-ready dans le fichier d'exemple) :

| Variable | Défaut | Description |
|---|---|---|
| `URLS` | voir ci-dessous | Tableau des URLs de listes de blocage |
| `SET_NAME` | `blacklist` | Nom du set ipset blacklist (max 31 caractères) |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | Nom du set ipset whitelist (max 31 caractères) |
| `WHITELIST` | `()` (vide) | Tableau d'IP/CIDR IPv4 toujours autorisés (voir [Whitelist](#whitelist-1)) |
| `WHITELIST_MIN_PREFIX` | `8` | Préfixe minimum accepté en WHITELIST (rejette /0 à /7 pour éviter un bypass total par typo). Mettre à 0 pour désactiver. |
| `BLOCKLIST_MIN_PREFIX` | `8` | Préfixe minimum accepté depuis les sources externes (rejette /0 à /7). Garde-fou contre une source corrompue ou malveillante qui injecterait `0.0.0.0/0`, ce qui verrouillerait l'accès au serveur entier. Mettre à 0 pour désactiver. |
| `MIN_ENTRIES` | `1000` | Seuil minimum d'entrées (protection anti-purge) |
| `BASE_HASHSIZE` | `16384` | Hashsize de base pour ipset |
| `BASE_MAXELEM` | `300000` | Maxelem de base pour ipset |
| `LOG_LIMIT` | `60/min` | Rate-limit du logging des paquets bloqués (`N/sec`, `N/min`, `N/hour`, `N/day` ; vide = pas de limite) |
| `LOG_BURST` | `100` | Burst maximum avant que `LOG_LIMIT` s'applique |
| `WAN_INTERFACE` | `""` (auto) | Interface WAN pour scoper la règle DOCKER-USER au trafic entrant uniquement. Vide = auto-détection via `ip route get 8.8.8.8`. À définir explicitement si l'auto-détection donne le mauvais résultat (ex : VPN). |
| `LOOKUP_CACHE_TTL` | `21600` | TTL du cache en secondes pour les téléchargements de `lookup-ip.sh` (`0` désactive le cache) |

#### Sources par défaut

Le script télécharge et agrège les listes suivantes :

| Source | Description |
|---|---|
| [Data-Shield IPv4 Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Liste critique d'IP malveillantes |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Plages réseau détournées (hijack) |
| [Emerging Threats](https://rules.emergingthreats.net/) | IP bloquées par règles ET |
| [CI Army (CINS)](https://cinsscore.com/) | IP à mauvais score de réputation |
| [AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb) | IP signalées avec un score de 100% sur 365 jours |
| [FireHOL Level 1](https://iplists.firehol.org/) | Méta-liste curée, faible faux-positif |
| [GreenSnow](https://blocklist.greensnow.co/) | Brute-force SSH/HTTP actifs |
| [Blocklist.de](https://www.blocklist.de/) | IP signalées (SSH, mail, web, FTP, etc.) |
| [IPsum](https://github.com/stamparm/ipsum) | Agrégat de 30+ sources, IPs vues dans ≥3 listes |
| [Tor exit nodes](https://check.torproject.org/torbulkexitlist) | Nœuds de sortie Tor |
| [Internet Scanner IPs](https://github.com/palinkas-jo-reggelt/List_of_Internet_Scanner_IPs) | Ranges /24 agrégés de scanners Internet connus (Shodan, Censys, ONYPHE, GreyNoise, etc.) |

Ces sources sont personnalisables via la variable `URLS` dans `/etc/update-blocklist.conf`.

### Utilisation

#### Étape 1 : Installer un firewall (une seule fois)

Le script `setup-firewall.sh` détecte, installe et active un firewall sur le système :

```bash
./setup-firewall.sh
```

Le script :
1. Détecte le firewall actif (firewalld, ufw, nftables ou iptables)
2. Propose un menu avec les 4 options
3. Détecte automatiquement les ports TCP/UDP en écoute (non-loopback) et propose de les ouvrir avant activation (protection anti-lockout). Le prompt est **sauté** quand le firewall choisi a une politique INPUT permissive (ACCEPT par défaut — cas commun sur Debian/Ubuntu fraîchement installé avec iptables/nftables) : ajouter des ACCEPT serait sans effet. Quand le firewall est deny-by-default (ufw, firewalld, ou iptables/nftables durci), le prompt est affiché et les ports résultants sont persistés via `ipshield-safe-ports.service` (unit systemd ordonné avant sshd/docker pour que l'accès admin soit rétabli au boot).
4. Désactive l'ancien firewall si un autre est choisi (avec rollback automatique en cas d'échec)
5. Installe et active le nouveau firewall
6. Vérifie que le firewall répond après activation (sinon rollback)
7. **Installe `/etc/update-blocklist.conf`** depuis `update-blocklist.conf.example` si absent (chmod 600, owner root). Ne touche pas au fichier existant pour préserver les modifications.
8. **Installe `ipshield-restore.service`** quand `PERSIST_IPSET=1` (défaut) : un unit systemd oneshot ordonné `Before=netfilter-persistent.service nftables.service ufw.service firewalld.service` qui exécute `ipset restore -! -f $IPSET_SAVE_FILE` au boot. Sans lui, les firewalls persistants (`ufw`, `firewalld` sur iptables-nft) peuvent échouer au démarrage si leurs règles référencent un ipset qui n'existe pas encore. Pré-crée `/var/lib/ipshield/` et le répertoire de cache LKG par source. Idempotent (compare le contenu, active une seule fois). Sauté automatiquement quand `PERSIST_IPSET=0`.
9. **Installe `ipshield.timer` + `ipshield.service`** : le timer se déclenche `OnBootSec=2min` et `OnCalendar=*-*-* 00,08,16:00:00` avec `RandomizedDelaySec=5min` et `Persistent=true` (rattrape un run manqué si la machine était éteinte). Le service est une unit `Type=oneshot` qui exécute simplement `update-blocklist.sh`. Les logs vont dans journald (`journalctl -u ipshield.service`). Idempotent (relance possible pour mettre à jour).
10. **Installe `ipshield-apply.service`** : un unit systemd ordonné `After=ipshield-restore.service nftables.service docker.service` qui exécute `update-blocklist.sh --apply-only` au boot. Attache les règles firewall à l'ipset restauré quelques secondes après le démarrage de Docker, sans retélécharger la blocklist. Le `After=docker.service` est opportuniste — aucun `Wants=`/`Requires=` sur Docker, donc sur une machine sans Docker l'unit démarre dès que `ipshield-restore.service` (et `nftables.service` si présent) sont terminés, et `update-blocklist.sh` saute simplement la chaîne DOCKER-USER quand elle n'est pas détectée. Si l'ipset est absent ou vide (sauvegarde corrompue, `PERSIST_IPSET=0`), bascule sur un update complet pour ne jamais laisser l'hôte sans protection.
11. **Installe le filtre rsyslog + logrotate** quand rsyslog est actif : `30-blocked-ips.conf` pour rediriger les `BLOCKED:` vers `/var/log/blocked-ips.log`, et deux configs logrotate (rotate 4 weekly). Idempotent (compare le contenu, ne ré-écrit que si différent ou absent). Si rsyslog est absent (Debian minimal par exemple), un sous-prompt propose de l'installer ; refuser laisse les logs dans journald (consultables via `journalctl -k --grep 'BLOCKED:'`), la config logrotate restant installable seule.

> Si le firewall choisi est déjà actif (pas de transition), `setup-firewall.sh` peut quand même revoir/ouvrir les ports en écoute sur le firewall actif, puis continue aux étapes 7 à 11. Le prompt de revue des ports propose `no` par défaut.

Détails de sélection du backend :

- Le choix **iptables** sélectionne `iptables-legacy`/`ip6tables-legacy` via `update-alternatives` sur les systèmes qui le fournissent quand ces binaires sont disponibles.
- Le choix **nftables** sélectionne `iptables-nft`/`ip6tables-nft` via `update-alternatives` sur les systèmes qui le fournissent quand ces binaires sont disponibles, car le projet applique les règles du chemin nftables via iptables-nft afin de conserver le support du match ipset.

Périmètre sécurité : ipshield installe des règles de blocklist. Il ne transforme pas `iptables`/`nftables` directs en firewall default-deny complet. Sur ces chemins, le trafic non blacklisté reste accepté sauf durcissement séparé de l'hôte.

Sécurité Docker : si des chaînes iptables Docker sont présentes, `setup-firewall.sh` ne modifie pas le firewall à l'aveugle. Il propose un chemin de maintenance guidé : arrêter Docker, nettoyer les chaînes iptables/nft compatibility appartenant à Docker, continuer la transition firewall ou le changement de backend, puis redémarrer Docker. Si des conteneurs tournent, le prompt propose `no` par défaut car les ports publiés et les conteneurs peuvent être interrompus. En production, préférer arrêter proprement les stacks applicatives d'abord (par exemple `docker compose down`), puis relancer `setup-firewall.sh` ; arrêter le daemon Docker n'est pas équivalent à un arrêt propre Compose/applicatif. Si Docker est actif sans conteneur, le prompt propose `yes` par défaut.

Transitions non disruptives pour Docker : quand la transition est démontrée non destructrice — firewall cible `iptables` ou `nftables`, aucun firewall précédent à désactiver (`DETECTED=none`), et backend iptables déjà aligné sur la cible — `setup-firewall.sh` **saute complètement l'arrêt Docker** et laisse les conteneurs en ligne. Les transitions destructrices (flush d'iptables existant, changement de backend, activation ufw ou firewalld) passent toujours par le chemin de stop Docker guidé.

Sécurité au restart de nftables.service : à **chaque** installation ou rerun avec cible `nftables`, `setup-firewall.sh` applique deux patches complémentaires pour que `systemctl restart nftables` ne vide plus la table iptables-nft `ip filter` (qui héberge les règles LOG/DROP de blocklist d'ipshield, et les règles maintenues par Docker quand Docker est présent) :

1. `/etc/nftables.conf` est patché sur place (sauvegarde `.ipshield.bak`) pour commenter `flush ruleset`, afin que le reload de la conf par ExecStart ne détruise pas les tables existantes.
2. Un drop-in systemd `/etc/systemd/system/nftables.service.d/ipshield.conf` vide l'`ExecStop=/usr/sbin/nft flush ruleset` par défaut (le vrai déclencheur du wipe, exécuté avant `ExecStart` à chaque restart).

Sans (2), patcher uniquement la conf est inefficace au restart : `ExecStop` flush avant que `ExecStart` ne relise la conf. Les deux patches sont idempotents sur rerun et appliqués indépendamment de Docker. Retirer le drop-in restaure le comportement systemd par défaut où `systemctl restart nftables` vide tout.

Note UFW Ubuntu : `ufw.service` peut être actif/enabled même lorsque `ufw status` vaut `inactive`. Dans cet état, UFW ne filtre pas le trafic, mais l'état du service peut prêter à confusion lorsqu'un autre firewall est sélectionné. Si `setup-firewall.sh` détecte ce cas pendant l'installation d'un autre firewall, il propose d'exécuter `systemctl disable --now ufw`. Lors d'une transition depuis UFW actif vers un autre firewall, il retire aussi les lignes ipshield/orphelines avec ipset de `/etc/ufw/before.rules` avant la désactivation, avec backup.

#### Étape 2 : Lancer le blocage (première exécution)

Tester en mode simulation :

```bash
./update-blocklist.sh --dry-run --verbose
```

Puis lancer la première exécution réelle :

```bash
./update-blocklist.sh --verbose
```

Le script :
1. Télécharge les listes d'IP malveillantes
2. Met à jour le set ipset via swap atomique
3. Détecte automatiquement le firewall actif
4. Applique les règles LOG + DROP de manière idempotente

Vérifier que le set ipset est bien créé :

```bash
ipset list blacklist | head -10
```

> `update-blocklist.sh` fonctionne seul (sans `setup-firewall.sh`) car il auto-détecte le firewall en place.

#### Identifier la source d'une IP bloquée

Si une IP apparaît dans les logs (`BLOCKED:`), identifier sa source :

```bash
./lookup-ip.sh 185.199.108.133
./lookup-ip.sh --verbose 1.2.3.4
```

Le script télécharge les listes à la volée et indique dans quelle(s) source(s) l'IP apparaît. Les téléchargements sont mis en cache pendant `LOOKUP_CACHE_TTL` secondes (défaut : 6 heures, `LOOKUP_CACHE_TTL=0` pour désactiver). Fonctionne sans root (la vérification ipset est ignorée).

Fonctionnement du cache :

- **Emplacement** : `/var/cache/ipshield/lookup/` en root, `${XDG_CACHE_HOME:-$HOME/.cache}/ipshield/lookup/` sinon. Chaque utilisateur a son propre cache ; seul le cache root est nettoyé par `uninstall.sh --apply`.
- **Nommage** : un fichier par URL, nommé `<sha256(URL)>.txt`. Le hash est dérivé du contenu de l'URL, donc réordonner `URLS` dans la conf est gratuit — seuls add/edit/remove changent un nom de fichier.
- **Purge orphelins** : à chaque run, les fichiers dont le basename ne correspond à aucun hash d'URL active sont supprimés. Ceci nettoie aussi les fichiers `source-<idx>-<cksum>.txt` issus des versions antérieures à v1.1.0. Les suppressions sont loguées uniquement en mode `-v`.
- **Test de fraîcheur** : un fichier cache est réutilisé s'il est non vide et `now - mtime < LOOKUP_CACHE_TTL`. Sinon la source est retéléchargée et le cache remplacé atomiquement (`mv` après `cp` vers un `.tmp`).
- **Reset manuel** : `rm -rf /var/cache/ipshield/lookup/` (root) ou `rm -rf ~/.cache/ipshield/lookup/` (utilisateur). Le run suivant reconstruit ce dont il a besoin. Pas de flag `--no-cache` ; pour un bypass ponctuel : `LOOKUP_CACHE_TTL=0 ./lookup-ip.sh ...`.

### Whitelist

Pour autoriser certaines IP ou subnets à contourner le blocage (typiquement vos IP/subnets de management), définir la variable `WHITELIST` dans `/etc/update-blocklist.conf` :

```bash
WHITELIST=(
  "10.0.0.0/8"
  "172.16.0.0/12"
  "192.168.0.0/16"
  "203.0.113.42"
)
```

Au prochain run, le script :

1. Crée un second ipset (`blacklist-allow` par défaut) via swap atomique
2. Insère une règle `ACCEPT` en position 1 sur `INPUT` (et `DOCKER-USER` si présent)
3. Si `WHITELIST` est ensuite vidé : la règle ACCEPT et l'ipset whitelist sont automatiquement retirés au prochain run

Le nom de l'ipset whitelist est `WHITELIST_SET_NAME` (`${SET_NAME}-allow` par défaut). Il doit utiliser seulement `[a-zA-Z0-9_-]`, faire 31 caractères maximum, et être différent de `SET_NAME`.

> **Attention** : la règle ACCEPT contourne **l'ensemble du filtrage firewall**, pas seulement la blocklist. Une IP whitelistée a un accès complet au serveur, indépendamment des autres règles. À réserver aux IP/subnets de confiance.

> **Garde-fou anti-typo** : par défaut, tout préfixe < `/8` est refusé (`WHITELIST_MIN_PREFIX=8`). Cela bloque le piège classique d'un `0.0.0.0/0` accidentel qui ouvrirait tout Internet en bypass total. Pour autoriser un préfixe plus large, abaisser `WHITELIST_MIN_PREFIX` explicitement.

#### Persistance ipset au reboot et reattach rapide

**Problème.** Au reboot du serveur, l'`ipset blacklist` (qui vit en RAM) est vide s'il n'est pas restauré depuis le disque avant le démarrage des règles firewall persistantes. Et sur `iptables`/`nftables`, les règles LOG/DROP runtime qui référencent l'ipset ne persistent pas non plus : il faut les (ré)attacher après le boot. Sans mécanisme dédié, cela laisserait une fenêtre fail-open :

- **iptables / nftables** : les règles LOG/DROP ipshield sont des règles runtime non persistantes par défaut → fail-open jusqu'à la réapplication.
- **ufw / firewalld avec iptables-nft** : les règles persistantes peuvent référencer un ipset qui n'existe pas encore. Sur Ubuntu/Debian récents, cela peut faire échouer le reload/démarrage du firewall avec `Set <name> doesn't exist`.

`ipshield` fournit deux unit systemd qui, ensemble, ferment la fenêtre de boot à moins de deux secondes :

1. **`ipshield-restore.service`** (très tôt) : restaure `/var/lib/ipshield/ipset.save` avant le démarrage de `ufw.service`, `firewalld.service` et `nftables.service`. Fournit les données de l'ipset.
2. **`ipshield-apply.service`** (après Docker, quand présent) : exécute `update-blocklist.sh --apply-only`, ordonné `After=ipshield-restore.service nftables.service docker.service`. Le `After=` est opportuniste — aucun `Wants=docker.service` n'est déclaré, donc sur une machine sans Docker l'unit démarre dès que les autres contraintes d'ordering sont satisfaites et `update-blocklist.sh` saute simplement la chaîne DOCKER-USER. Saute le cycle download/parse/swap d'environ 30 s et attache uniquement les règles LOG/DROP (et DOCKER-USER, quand Docker est présent) à l'ipset restauré par l'étape 1. Bascule sur un update complet si le fichier de sauvegarde ipset est absent ou vide (`PERSIST_IPSET=0`, fichier corrompu, premier boot après une install fraîche) pour ne jamais laisser l'hôte sans protection.

`update-blocklist.sh` sauvegarde les sets ipshield après chaque run réussi quand `PERSIST_IPSET=1` (défaut), alimentant les deux unit ci-dessus. Le rafraîchissement récurrent de la blocklist est désormais piloté par `ipshield.timer` (voir « Planification » plus bas) ; le déclenchement `OnBootSec=2min` remplace l'ancienne ligne `@reboot sleep 60 && ...`, l'ordering systemd supprimant le besoin de `sleep` arbitraire.

Configuration :

```bash
PERSIST_IPSET=1
IPSET_SAVE_FILE="/var/lib/ipshield/ipset.save"
```

Avec `iptables` direct, la persistance reste optionnelle : les règles ne sont pas persistantes par défaut, c'est `ipshield-apply.service` qui rétablit la protection. Avec `ufw` et `firewalld`, les deux unit sont utiles.

#### Migration : ancien bug nftables (priorité de chaîne admin_access)

Les versions de `setup-firewall.sh` antérieures au 2026-04-28 créaient la chaîne nftables `inet admin_access input` à priorité `-10` (avant le blocklist à priorité 0). Conséquence : sur un setup nftables, les IPs blacklistées passaient quand même sur les ports SAFE_PORTS (SSH inclus) car le `accept` du chain admin_access s'évaluait avant le `drop` du blocklist.

`setup-firewall.sh` détecte automatiquement cette config buggée au démarrage et migre la chaîne vers priorité `10` (après le blocklist) en préservant les ports déjà ouverts. **Il suffit de relancer `./setup-firewall.sh` une fois** ; un message `Migration : chaîne 'inet admin_access input' détectée à priorité -10` confirme la correction. Les autres firewalls (iptables, ufw, firewalld) ne sont pas concernés.

Vérification :

```bash
ipset list blacklist-allow | head -10
iptables -S INPUT | grep blacklist-allow
```

### Désinstallation

`uninstall.sh` retire les règles ipshield (LOG/DROP blocklist + ACCEPT whitelist), détruit les ipsets associés, retire les règles ipshield/orphelines de `/etc/ufw/before.rules` ligne par ligne, et peut désactiver/supprimer `ipshield-restore.service` et `ipshield-apply.service`. Il **ne désinstalle pas** le firewall ni les paquets.

```bash
# Mode dry-run (défaut) : affiche ce qui serait fait
./uninstall.sh

# Application réelle (avec confirmation interactive)
./uninstall.sh --apply
```

En mode `--apply`, après suppression des règles et ipsets, les composants project-owned sont retirés automatiquement (sans prompt) : `ipshield-restore.service`, `ipshield-apply.service`, `ipshield.timer` + `ipshield.service`, `ipshield-safe-ports.service`, le drop-in `nftables.service` (et la restauration de `/etc/nftables.conf` depuis `.ipshield.bak`), ainsi que `/etc/rsyslog.d/30-blocked-ips.conf` + `/etc/logrotate.d/{update-blocklist,blocked-ips}` (rsyslog est redémarré si le filtre est retiré).

Deux prompts proposent ensuite de retirer les données éditables par l'utilisateur :
1. `/etc/update-blocklist.conf`, le fichier de persistance ipset (généralement `/var/lib/ipshield/ipset.save`), le répertoire de cache LKG par source (généralement `/var/lib/ipshield/sources/`) et le cache miroir de `lookup-ip.sh` (`/var/cache/ipshield/lookup/`, chemin root uniquement — les caches par utilisateur sous `$XDG_CACHE_HOME` ne sont pas touchés) ;
2. les fichiers de logs ipshield correspondant à `/var/log/update-blocklist.log*` et `/var/log/blocked-ips.log*`, y compris les fichiers rotatés/compressés.

Les entrées journald ne sont pas purgées ; le vacuum du journal est une opération système globale.

### Support Docker

Sur un hôte Docker, le trafic destiné aux conteneurs (ports publiés via `-p` / `ports:`) passe par la chaîne `FORWARD`, pas `INPUT`. Sans protection supplémentaire, les IP bloquées atteignent quand même les conteneurs.

Le script détecte automatiquement la présence de Docker via la chaîne `DOCKER-USER` dans iptables. Quand elle existe, les mêmes règles LOG + DROP sont appliquées sur `DOCKER-USER` en plus de `INPUT`, **scopées à l'interface WAN** (`-i $WAN_INTERFACE`) pour ne filtrer que le trafic **entrant** depuis Internet vers les conteneurs. Le trafic sortant des conteneurs (qui passe par `IN=br-xxx`) n'est jamais filtré, conformément au principe "filtrer uniquement l'entrée".

Avec **firewalld**, les règles `INPUT` restent gérées par des règles directes permanentes, mais les règles Docker `DOCKER-USER` sont appliquées au runtime via iptables uniquement. Elles ne sont volontairement pas stockées en règles directes permanentes firewalld, car firewalld peut échouer au démarrage ou au reload si Docker n'a pas encore créé `DOCKER-USER`. Si une ancienne version d'ipshield a laissé ce type de règle permanente, le prochain `update-blocklist.sh` les supprime avant d'appliquer les règles Docker runtime.

Les règles blocklist sont aussi limitées à `conntrack --ctstate NEW`. Pour TCP, cela bloque les connexions entrantes normales au démarrage de la connexion (chemin SYN), tandis que les réponses à des connexions sortantes déjà suivies comme `ESTABLISHED` ne sont pas supprimées seulement parce que l'IP distante figure dans une liste publique.

**Auto-détection de l'interface WAN** : par défaut, le script détecte l'interface via `ip route get 8.8.8.8`. Si l'auto-détection donne le mauvais résultat (cas VPN/multi-homed), définir `WAN_INTERFACE="ens160"` dans `/etc/update-blocklist.conf`.

**Filtrage des bogons (RFC 6890)** : le script rejette automatiquement toute IP/CIDR dans les plages réservées (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, multicast, etc.). Empêche un faux positif d'une source publique de bloquer le LAN ou le bridge Docker (cas réel : FireHOL Level 1 inclut les bogons par design).

**Notes :**

- Docker recrée `DOCKER-USER` à chaque restart du daemon — les règles ne persistent pas. `ipshield-apply.service` (au boot) et `ipshield.timer` (`OnBootSec=2min` + toutes les 8 h) les réappliquent automatiquement, et l'idempotence évite les doublons.
- Si le script s'exécute au boot avant Docker, `DOCKER-USER` n'existe pas encore — la détection est correctement négative. Le prochain run du timer rattrapera.
- `setup-firewall.sh` gère les transitions firewall avec Docker de manière interactive : lorsque des chaînes Docker sont présentes, il peut arrêter Docker, nettoyer les chaînes Docker, poursuivre le setup, puis redémarrer Docker. Si Docker signale une chaîne `DOCKER` manquante après un changement manuel de firewall, redémarrer Docker pour qu'il recrée ses chaînes NAT/filter.
- Aucune configuration nécessaire si l'auto-détection WAN fonctionne : la détection et l'application sont entièrement automatiques.

Vérification après exécution :

```bash
iptables -L DOCKER-USER -n -v
```

Les règles LOG + DROP avec `ctstate NEW`, `match-set blacklist src` et `in ens160` (ou l'interface WAN détectée) doivent apparaître.

### Planification (timer systemd)

`setup-firewall.sh` installe `ipshield.timer` + `ipshield.service` à la fin de son exécution (étape 9). C'est la méthode recommandée — idempotente, sans prompt, et `systemctl enable --now ipshield.timer` est exécuté automatiquement.

Pour reconfigurer plus tard sans toucher aux règles firewall : relancer `./setup-firewall.sh`, choisir le firewall déjà actif, puis répondre `no` au prompt de revue des ports.

Le schedule par défaut :

```ini
# /etc/systemd/system/ipshield.timer
[Timer]
OnBootSec=2min
OnCalendar=*-*-* 00,08,16:00:00
RandomizedDelaySec=5min
Persistent=true
Unit=ipshield.service
```

- `OnBootSec=2min` déclenche un refresh peu après chaque boot. Le *fast attach* au boot (sans retéléchargement) reste assuré par `ipshield-apply.service` (ordonné `After=docker.service`) ; le timer ajoute le refresh réseau par-dessus.
- `OnCalendar=*-*-* 00,08,16:00:00` déclenche trois fois par jour.
- `RandomizedDelaySec=5min` ajoute un jitter de jusqu'à 5 minutes à chaque déclenchement.
- `Persistent=true` rattrape un run calendaire manqué quand la machine était éteinte.
- Les logs (stdout/stderr d'`update-blocklist.sh`) sont écrits dans `/var/log/update-blocklist.log` (via `StandardOutput=append:` / `StandardError=append:` dans le unit) **et** dupliqués dans journald : `journalctl -u ipshield.service` (ajouter `-f` pour suivre, `-S "1 hour ago"` pour borner dans le temps).
- État : `systemctl list-timers ipshield.timer` affiche le prochain déclenchement et le dernier passage.

#### Configuration manuelle (alternative)

Si vous préférez installer les unit à la main (même contenu que `configure_timer`) :

```bash
cat > /etc/systemd/system/ipshield.service <<'EOF'
[Unit]
Description=ipshield blocklist refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/chemin/vers/update-blocklist.sh
StandardOutput=append:/var/log/update-blocklist.log
StandardError=append:/var/log/update-blocklist.log
EOF

cat > /etc/systemd/system/ipshield.timer <<'EOF'
[Unit]
Description=ipshield blocklist refresh schedule

[Timer]
OnBootSec=2min
OnCalendar=*-*-* 00,08,16:00:00
RandomizedDelaySec=5min
Persistent=true
Unit=ipshield.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now ipshield.timer
```

Dans une configuration manuelle, pensez aussi à activer `ipshield-apply.service` pour préserver le reattach rapide au boot : `setup-firewall.sh` l'installe dans `/etc/systemd/system/ipshield-apply.service` et exécute `systemctl enable ipshield-apply.service`.

### Logs

> **Installation recommandée** : `setup-firewall.sh` installe automatiquement le filtre rsyslog et les deux configs logrotate quand rsyslog est actif (étape 11), ou propose d'installer rsyslog s'il est absent. Idempotent (rejouer ne ré-écrit que si différent). Les sections ci-dessous sont la procédure manuelle équivalente, pour une configuration manuelle.

#### Logrotate du script

Créer le fichier `/etc/logrotate.d/update-blocklist` :

```bash
cat > /etc/logrotate.d/update-blocklist << 'EOF'
/var/log/update-blocklist.log {
	su root root
	create 0644 root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
}
EOF
```

> La directive `su root root` est requise par logrotate >= 3.18 car `/var/log/` appartient à `root:syslog` (group-writable) sur Debian/Ubuntu. Sans elle, la rotation est silencieusement ignorée sur les setups plus stricts. Pattern standard, aussi utilisé par `/etc/logrotate.d/ubuntu-pro-client`. `create 0644 root root` garantit que le fichier existe immédiatement après la rotation (sinon il ne réapparaîtrait qu'au prochain `ExecStart`).

#### Logs des IP bloquées

Par défaut, le logging est **rate-limité** à **60 logs/min avec burst 100** (`LOG_LIMIT="60/min"`, `LOG_BURST=100`). Sous attaque massive, tous les paquets sont **bloqués** mais seul un échantillon apparaît dans les logs — pour éviter de saturer `/var/log/`.

Pour ajuster :
- `LOG_LIMIT="600/min"` + `LOG_BURST=1000` : plus de visibilité, plus de risque de flood
- `LOG_LIMIT=""` (vide) : pas de rate-limit, loggue **tout** (risque réel sous attaque)
- voir `update-blocklist.conf.example` pour les détails

Pour iptables/nftables/firewalld/ufw/DOCKER-USER, le drift est détecté automatiquement : changer `LOG_LIMIT` et lancer `update-blocklist.sh` met à jour les règles.

Les règles appliquées par `update-blocklist.sh` utilisent toutes le préfixe `BLOCKED: ` dans leurs logs, quel que soit le firewall :

| Firewall | Mécanisme de log | Destination brute |
|---|---|---|
| **iptables** | `-j LOG --log-prefix "BLOCKED: "` | kernel log → syslog |
| **nftables** | Via `iptables-nft` : `-j LOG --log-prefix "BLOCKED: "` | kernel log → syslog |
| **firewalld** | Direct rules avec `-j LOG` (même mécanisme qu'iptables) | kernel log → syslog |
| **ufw** | Règles dans `before.rules` avec `-j LOG` (même mécanisme qu'iptables) | kernel log → syslog |

Tous les firewalls passent par le logging noyau (netfilter), ce qui permet d'utiliser **un seul filtre rsyslog** pour rediriger vers `/var/log/blocked-ips.log`.

#### Filtre rsyslog

Créer le fichier `/etc/rsyslog.d/30-blocked-ips.conf` :

```bash
cat > /etc/rsyslog.d/30-blocked-ips.conf << 'EOF'
template(name="blockedFormat" type="string"
  string="%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute%:%timestamp:::date-second% %msg%\n")

:msg, contains, "BLOCKED: " /var/log/blocked-ips.log;blockedFormat
& stop
EOF
```

Puis redémarrer rsyslog :

```bash
systemctl restart rsyslog
```

Le `& stop` empêche les messages `BLOCKED: ` d'apparaître aussi dans `/var/log/syslog` ou `/var/log/kern.log`.

> **Note ufw** : les paquets bloqués par nos règles dans `before.rules` apparaissent dans `/var/log/blocked-ips.log` via rsyslog, mais **pas** dans `/var/log/ufw.log` car nos règles LOG+DROP sont exécutées avant le logging propre à ufw.

> **Note nftables** : les règles de blocage sont appliquées via `iptables-nft`. Le mécanisme de log est identique à iptables (`-j LOG`), capturé par le même filtre rsyslog.

#### Logrotate des IP bloquées

Créer le fichier `/etc/logrotate.d/blocked-ips` :

```bash
cat > /etc/logrotate.d/blocked-ips << 'EOF'
/var/log/blocked-ips.log {
	su root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	postrotate
		if [ -x /usr/lib/rsyslog/rsyslog-rotate ]; then
			/usr/lib/rsyslog/rsyslog-rotate
		else
			/bin/systemctl reload rsyslog 2>/dev/null || true
		fi
	endscript
}
EOF
```

### Firewalls supportés

| Firewall | Recommandation |
|---|---|
| **iptables** | Fallback legacy pour systèmes anciens/minimaux ; le setup sélectionne `iptables-legacy` si disponible |
| **nftables** | Recommandé pour les serveurs Ubuntu/Debian en production ; le setup sélectionne `iptables-nft` pour le match ipset |
| **firewalld** | Recommandé pour les serveurs Fedora/RHEL et dérivés |
| **ufw** | Frontend Ubuntu pratique ; supporté, mais `nftables` est préféré pour les nouvelles installations en production |

### Plateformes validées

| Plateforme | Chemin firewall validé |
|---|---|
| Ubuntu 24.04 LTS | nftables, ufw |
| Debian 12 | nftables |
| Debian 13 | nftables, iptables legacy |
| Fedora 44 | firewalld, nftables |

La validation couvre l'installation fraîche, la mise à jour de blocklist, la restauration après reboot, le blocage TCP/UDP entrant, la protection Docker `DOCKER-USER`, les logs/logrotate et la désinstallation propre lorsque applicable.

### Configuration manuelle du firewall (alternative)

Si vous préférez configurer les règles manuellement au lieu d'utiliser `update-blocklist.sh` :

#### iptables

```bash
iptables -I INPUT -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I INPUT 2 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

Persistance :

```bash
# Debian / Ubuntu
apt install -y iptables-persistent
netfilter-persistent save

# Fedora
dnf install -y iptables-services
service iptables save
```

#### nftables

nftables ne peut pas référencer les sets ipset nativement (la syntaxe `@set` ne concerne que les sets nft natifs). Sur les systèmes nftables, `iptables` est fourni par `iptables-nft` et traduit les commandes en règles nft internes tout en supportant le match ipset via le module `xt_set` du noyau :

```bash
iptables -I INPUT -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I INPUT 2 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

#### firewalld

```bash
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
firewall-cmd --reload
```

#### ufw

Ajouter dans `/etc/ufw/before.rules` (section `*filter`, avant `COMMIT`) :

```
-A ufw-before-input -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
-A ufw-before-input -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

Puis `ufw reload`.

#### Docker (DOCKER-USER)

Sur un hôte Docker, ajouter les mêmes règles sur la chaîne `DOCKER-USER` pour protéger les conteneurs. Important : scoper à l'interface WAN (ex `ens160`) pour ne filtrer que l'entrée et laisser passer l'egress des conteneurs :

```bash
iptables -I DOCKER-USER -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I DOCKER-USER 2 -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

> `update-blocklist.sh` fait cela automatiquement quand Docker est détecté, avec auto-détection de l'interface WAN. La configuration manuelle n'est nécessaire que si vous n'utilisez pas le script.
