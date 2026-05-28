<div align="center">

# ipshield

*Automatic malicious IP blocking via ipset & Linux firewall*

**Current release: v1.1.0**

**[🇬🇧 English](#english) · [🇫🇷 Français](#français)**

</div>

---

<a id="english"></a>
## 🇬🇧 English

### Description

`ipshield` is a set of bash scripts that download public malicious IP lists, aggregate them into an ipset, and automatically apply blocking rules on the detected firewall.

Designed for **Debian/Ubuntu** and **Fedora/RHEL** servers.

`v1.1.0` has been validated on Internet-exposed server scenarios with Ubuntu 24.04 LTS, Debian 12, Debian 13 and Fedora 44. v1.1.0 adds per-source last-known-good caching, the `ipshield.timer`/`ipshield.service` systemd schedule (replacing the cron line) and the `ipshield-apply.service` boot-time fast attach.

### Features

- **11 curated public IPv4 blocklists** aggregated into a single ipset (Spamhaus, Emerging Threats, AbuseIPDB, CINS, Data-Shield, FireHOL Level 1, GreenSnow, Blocklist.de, IPsum, Tor exits, Internet Scanner ranges)
- **RFC 6890 bogon filter**: rejects RFC1918, loopback, link-local, multicast and other reserved ranges from upstream sources to prevent self-blocking the LAN or Docker bridge
- **Four supported firewalls**: iptables, nftables, firewalld, ufw — auto-detected and applied idempotently
- **Blocklist-focused protection**: ipshield is not a full default-deny firewall; with direct iptables/nftables, non-blacklisted traffic remains accepted unless you harden the host separately
- **Docker-aware**: inbound-only protection of the `DOCKER-USER` chain, scoped to the WAN interface (container egress is never filtered); firewalld systems use runtime `DOCKER-USER` rules so Docker boot ordering cannot break firewalld
- **Docker-safe setup**: firewall transitions and iptables backend switches offer a guided maintenance path when Docker chains are present, while recommending a clean application/Compose shutdown first if containers are running. When the transition is provably non-destructive (target iptables/nftables, no firewall to deactivate, backend already aligned), Docker is left running. On every `nftables` install or rerun, ipshield combines two patches so that `systemctl restart nftables` (at boot, on package upgrade, or manually) no longer wipes the iptables-nft blocklist rules (or Docker rules, when present): `/etc/nftables.conf` has `flush ruleset` commented out (backup `.ipshield.bak`), and a systemd drop-in `/etc/systemd/system/nftables.service.d/ipshield.conf` clears the default `ExecStop=nft flush ruleset`
- **Policy-aware safe ports**: the listening-ports prompt is skipped when the chosen firewall has a permissive INPUT policy (the common Debian/Ubuntu default with iptables/nftables) since the ACCEPT rules would be no-ops; when the policy is deny-by-default (ufw, firewalld, or a hardened iptables/nftables), the chosen ports are persisted across reboot via `ipshield-safe-ports.service` so SSH is restored at boot before sshd starts
- **UFW-aware setup**: inactive UFW service state is detected, and transitions away from UFW clean ipshield/orphan ipset lines from `before.rules`
- **Whitelist** of trusted IPs/subnets (management, jump hosts) with prefix-width safeguard against accidental `0.0.0.0/0`
- **Zero-downtime updates** via atomic ipset swap
- **Boot-safe ipset persistence** for persistent firewalls (`ufw`, `firewalld`, `nftables`)
- **Fast boot recovery**: `ipshield-apply.service` (ordered `After=docker.service`) attaches blocklist rules to the restored ipset within seconds of Docker being up, closing the historical boot exposure window. Falls back to a full update if the ipset save is missing
- **Guided setup**: `setup-firewall.sh` installs the firewall, configures `ipshield.timer` (8-hour systemd schedule, logs to journald), drops the rsyslog filter and logrotate configs
- **Cached lookup helper**: `lookup-ip.sh` can identify which source lists an IP without re-downloading every source on each call
- **Clean uninstall** with dry-run preview and confirmation
- **Single configuration file** (`/etc/update-blocklist.conf`) drives everything; no defaults hard-coded in scripts

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

### Prerequisites

Root access plus the following commands: `curl`, `awk`, `sort`, `wc`, `date`, `comm`, `flock`, `ipset`, `logger`.

| Tool | Package (Debian/Ubuntu) | Package (Fedora) |
|---|---|---|
| `curl` | curl | curl |
| `awk` | gawk | gawk |
| `ipset` | ipset | ipset |
| `flock` | util-linux | util-linux |
| `logger` | bsdutils | util-linux |
| `sort`, `wc`, `date`, `comm` | coreutils | coreutils |

```bash
# Debian / Ubuntu
apt update && apt install -y curl gawk coreutils ipset util-linux bsdutils

# Fedora
dnf install -y curl gawk coreutils ipset util-linux
```

### Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
sudo ./setup-firewall.sh
```

`setup-firewall.sh` is the recommended entry point. It detects/installs the firewall, copies `update-blocklist.conf.example` to `/etc/update-blocklist.conf`, installs `ipshield.timer` + `ipshield.service` (8-hour refresh + `OnBootSec=2min`), `ipshield-restore.service` (boot-time ipset restore), `ipshield-apply.service` (boot-time fast rule attach, ordered `After=docker.service`), the rsyslog filter, and the two logrotate configs. Everything is idempotent — rerun to reconfigure.

Backend selection:

- **iptables** target picks `iptables-legacy`/`ip6tables-legacy` via `update-alternatives` when available.
- **nftables** target picks `iptables-nft`/`ip6tables-nft` — ipshield applies rules through `iptables-nft` to preserve ipset matching.

The anti-lockout prompt is **skipped** when the chosen firewall has a permissive INPUT policy (typical Debian/Ubuntu default) since ACCEPT rules would be no-ops. With a deny-by-default firewall (ufw, firewalld, or a hardened iptables/nftables) the chosen ports are persisted via `ipshield-safe-ports.service`, ordered before sshd/docker so SSH is restored at boot.

Security scope: ipshield installs blocklist rules. It does **not** turn direct `iptables`/`nftables` into a default-deny firewall — non-blacklisted traffic stays accepted unless you harden the host separately.

### Configuration

`/etc/update-blocklist.conf` is **required** by `update-blocklist.sh` and `lookup-ip.sh`. It is the single source of truth for URLs and defaults. `setup-firewall.sh` copies it from `update-blocklist.conf.example` (chmod 600, owner root) when missing; an existing file is left intact.

| Variable | Default | Description |
|---|---|---|
| `URLS` | see [Blocklist sources](#blocklist-sources) | Array of blocklist URLs |
| `SET_NAME` | `blacklist` | ipset blacklist name (max 31 chars) |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | ipset whitelist name (max 31 chars) |
| `WHITELIST` | `()` (empty) | Array of always-allowed IPv4 addresses/CIDRs (see [Whitelist](#whitelist)) |
| `WHITELIST_MIN_PREFIX` | `8` | Minimum WHITELIST prefix accepted (rejects /0 to /7 to prevent total bypass via typo). Set to 0 to disable. |
| `BLOCKLIST_MIN_PREFIX` | `8` | Minimum prefix accepted from external sources (rejects /0 to /7 — catches a corrupted/malicious source pushing `0.0.0.0/0`). Set to 0 to disable. |
| `MIN_ENTRIES` | `1000` | Minimum entries threshold (anti-purge protection) |
| `BASE_HASHSIZE` | `16384` | Base ipset hashsize |
| `BASE_MAXELEM` | `300000` | Base ipset maxelem |
| `LOG_LIMIT` | `60/min` | Blocked-packet log rate-limit (`N/sec`, `N/min`, `N/hour`, `N/day`; empty = no limit) |
| `LOG_BURST` | `100` | Maximum burst before `LOG_LIMIT` applies |
| `WAN_INTERFACE` | `""` (auto) | WAN interface used to scope the DOCKER-USER rule to inbound only. Empty = auto-detected via `ip route get 8.8.8.8`. Set explicitly on VPN/multi-homed hosts. |
| `PERSIST_IPSET` | `1` | Save ipshield ipsets after each successful run for boot-time restore (`0` disables). |
| `IPSET_SAVE_FILE` | `/var/lib/ipshield/ipset.save` | Path to the ipset save file. |
| `LOOKUP_CACHE_TTL` | `21600` | Cache TTL in seconds for `lookup-ip.sh` source downloads (`0` disables cache). |

All variables are documented inline in `update-blocklist.conf.example` (the file copied to `/etc/`).

### Usage

```
update-blocklist.sh [OPTIONS]
```

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Simulation mode (no ipset/firewall changes) |
| `-v`, `--verbose` | Detailed output (per-source stats, diff details) |
| `-c`, `--config FILE` | Configuration file path |
| `-h`, `--help` | Show help |

```bash
# Dry run
./update-blocklist.sh --dry-run --verbose

# Real refresh (also runs automatically via ipshield.timer)
sudo ./update-blocklist.sh --verbose

# Identify which sources list a blocked IP
./lookup-ip.sh 185.199.108.133
```

`lookup-ip.sh` caches downloads in `/var/cache/ipshield/lookup/` (root) or `${XDG_CACHE_HOME:-$HOME/.cache}/ipshield/lookup/` (user), one file per URL named `<sha256(URL)>.txt`. Files older than `LOOKUP_CACHE_TTL` are refreshed atomically; orphans from removed URLs are pruned at each run. For a one-shot bypass: `LOOKUP_CACHE_TTL=0 ./lookup-ip.sh <ip>`.

`update-blocklist.sh` works standalone (without `setup-firewall.sh`) — it auto-detects the existing firewall.

### Whitelist

To let specific IPs/subnets bypass the blocklist (typically management hosts), set `WHITELIST` in `/etc/update-blocklist.conf`:

```bash
WHITELIST=(
  "10.0.0.0/8"
  "172.16.0.0/12"
  "203.0.113.42"
)
```

On the next run, `update-blocklist.sh` creates `${SET_NAME}-allow` via atomic swap and inserts an `ACCEPT` rule at position 1 on `INPUT` (and `DOCKER-USER` if present, scoped to the WAN interface). Emptying `WHITELIST` later removes both rule and ipset on the next run.

> **Warning**: the ACCEPT rule bypasses **the entire firewall**, not only the blocklist. A whitelisted IP has full server access regardless of other rules.

> **Anti-typo safeguard**: by default, any prefix `< /8` is rejected (`WHITELIST_MIN_PREFIX=8`). Blocks the classic `0.0.0.0/0` typo that would open the whole Internet. Lower `WHITELIST_MIN_PREFIX` explicitly to allow a wider prefix.

### Scripts

| Script | Purpose |
|---|---|
| `update-blocklist.sh` | ipset update + firewall detection + blocking rules |
| `setup-firewall.sh` | Interactive firewall installation + systemd timer + rsyslog/logrotate (idempotent) |
| `lookup-ip.sh` | Look up an IP across blocklist sources (diagnostic) |
| `uninstall.sh` | Clean uninstall (dry-run by default, `--apply` to execute) |

### Blocklist sources

| Source | Description |
|---|---|
| [Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Critical malicious IP list |
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

Sources are customisable via the `URLS` variable in `/etc/update-blocklist.conf`.

### Logs

All four firewall paths log blocked packets through the kernel (netfilter) with the `BLOCKED: ` prefix, so a single rsyslog filter captures everything.

| Firewall | Log mechanism |
|---|---|
| iptables | `-j LOG --log-prefix "BLOCKED: "` → kernel log → syslog |
| nftables | via `iptables-nft`: `-j LOG --log-prefix "BLOCKED: "` → kernel log → syslog |
| firewalld | direct rules with `-j LOG` (same mechanism) → kernel log → syslog |
| ufw | `before.rules` with `-j LOG` (same mechanism) → kernel log → syslog |

`setup-firewall.sh` installs the rsyslog filter at `/etc/rsyslog.d/30-blocked-ips.conf` (redirects `BLOCKED: ` to `/var/log/blocked-ips.log` and strips the `MAC=<14 bytes>` field, which carries no useful information — ipshield blocks by IP, never by MAC, and the bogon filter guarantees the source IP is never on the same L2). Two logrotate configs are installed at `/etc/logrotate.d/update-blocklist` and `/etc/logrotate.d/blocked-ips` (weekly, rotate 4, with the portable `rsyslog-rotate` postrotate hook).

Rate-limit defaults: `LOG_LIMIT="60/min"` + `LOG_BURST=100`. Under heavy load, all packets are still dropped but only a sample appears in the logs. Set `LOG_LIMIT=""` to log everything (flood risk under attack) or raise both values for more visibility. Drift is auto-detected — rerun `update-blocklist.sh` after editing the config to refresh the rules.

The timer's own output (`update-blocklist.sh` stdout/stderr) is appended to `/var/log/update-blocklist.log` and mirrored to journald: `journalctl -u ipshield.service` (add `-f` to follow, `-S "1 hour ago"` to scope by time). `systemctl list-timers ipshield.timer` shows the next firing.

### Boot-time persistence and fast attach

The `ipset blacklist` lives in RAM and the LOG/DROP rules referencing it are runtime-only. Without a dedicated boot mechanism, the host would be fail-open for the first 30+ seconds after every reboot. ipshield ships two systemd units that close the window to under two seconds:

1. **`ipshield-restore.service`** — early-boot oneshot, ordered `Before=netfilter-persistent.service nftables.service ufw.service firewalld.service`. Runs `ipset restore -! -f $IPSET_SAVE_FILE`. Indispensable for `ufw`/`firewalld` on `iptables-nft`, which otherwise fail to start when their persistent rules reference an ipset that does not exist yet.
2. **`ipshield-apply.service`** — runs `update-blocklist.sh --apply-only`, ordered `After=ipshield-restore.service nftables.service docker.service`. The Docker ordering is opportunistic (no `Wants=`/`Requires=`) so on a Docker-less host it fires as soon as the other constraints are satisfied. Skips the download/parse/swap cycle and just attaches LOG/DROP rules (and DOCKER-USER rules when applicable) to the restored ipset. Falls back to a full update if the ipset save is missing or empty — the host is never left unprotected.

`update-blocklist.sh` saves the ipshield sets (`SET_NAME` and `WHITELIST_SET_NAME` when present) after each successful run when `PERSIST_IPSET=1` (default), feeding both units. The `OnBootSec=2min` timer trigger then refreshes the blocklist from the network shortly after boot.

### Docker support

Traffic destined for containers (ports published via `-p` / `ports:`) flows through `FORWARD`, not `INPUT`. ipshield auto-detects Docker via the `DOCKER-USER` chain and applies the same LOG + DROP rules there, **scoped to `-i $WAN_INTERFACE`** so only inbound traffic from the Internet is filtered — container egress (`IN=br-xxx`) is never touched. Bogons are rejected up front, so the LAN and Docker bridge are never blacklisted.

Blocklist rules are scoped to `conntrack --ctstate NEW`: replies to outbound connections already tracked as `ESTABLISHED` are not dropped even if the remote endpoint appears in a public blocklist.

On **firewalld**, `INPUT` uses permanent direct rules but `DOCKER-USER` rules are kept runtime-only. Storing them as permanent direct rules would let firewalld fail to start/reload when Docker has not yet created the chain. Any leftover permanent Docker rule from earlier ipshield versions is cleaned up before the runtime rule is applied.

Docker recreates `DOCKER-USER` on every daemon restart, so the rules do not persist — `ipshield-apply.service` at boot and `ipshield.timer` (`OnBootSec=2min` + 8h cadence) reapply them idempotently. If `WAN_INTERFACE` auto-detection picks the wrong interface (VPN/multi-homed), set it explicitly in `/etc/update-blocklist.conf`.

### Uninstall

```bash
# Dry-run (default): preview every change
sudo ./uninstall.sh

# Apply (with interactive confirmation)
sudo ./uninstall.sh --apply
```

`--apply` removes ipshield rules (LOG/DROP blocklist + ACCEPT whitelist), destroys the associated ipsets, cleans ipshield/orphan lines from `/etc/ufw/before.rules` line by line, and removes the project-owned components without further prompts: `ipshield-restore.service`, `ipshield-apply.service`, `ipshield.timer` + `ipshield.service`, `ipshield-safe-ports.service`, the `nftables.service` drop-in (restoring `/etc/nftables.conf` from `.ipshield.bak`), and `/etc/rsyslog.d/30-blocked-ips.conf` + `/etc/logrotate.d/{update-blocklist,blocked-ips}` (rsyslog is restarted if the filter is removed).

Two final prompts offer to remove user-editable data:

1. `/etc/update-blocklist.conf`, the ipset save file, the LKG cache (`/var/lib/ipshield/sources/`), and the root `lookup-ip.sh` cache (`/var/cache/ipshield/lookup/`).
2. ipshield log files (`/var/log/update-blocklist.log*` and `/var/log/blocked-ips.log*`, including rotated/compressed files).

`uninstall.sh` does **not** uninstall the firewall or any packages. Journald entries are not purged (vacuuming is a global system operation).

### Manual firewall rules (advanced)

<details>
<summary>If you prefer to configure rules manually instead of using <code>setup-firewall.sh</code> / <code>update-blocklist.sh</code></summary>

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

Scope to the WAN interface to filter inbound only:

```bash
iptables -I DOCKER-USER -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I DOCKER-USER 2 -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

</details>

---

<a id="français"></a>
## 🇫🇷 Français

### Description

`ipshield` est un ensemble de scripts bash qui téléchargent des listes publiques d'adresses IP malveillantes, les agrègent dans un set ipset, et appliquent automatiquement les règles de blocage sur le firewall détecté.

Conçu pour les serveurs **Debian/Ubuntu** et **Fedora/RHEL**.

`v1.1.0` a été validée sur des scénarios de serveurs exposés sur Internet avec Ubuntu 24.04 LTS, Debian 12, Debian 13 et Fedora 44. v1.1.0 ajoute le cache last-known-good par source, la planification systemd `ipshield.timer`/`ipshield.service` (remplaçant la ligne cron) et le fast attach au boot via `ipshield-apply.service`.

### Fonctionnalités

- **11 listes publiques d'IPv4 malveillantes** agrégées dans un seul ipset (Spamhaus, Emerging Threats, AbuseIPDB, CINS, Data-Shield, FireHOL Level 1, GreenSnow, Blocklist.de, IPsum, nœuds de sortie Tor, ranges de scanners Internet)
- **Filtre des bogons RFC 6890** : rejette RFC1918, loopback, link-local, multicast et autres plages réservées issues des sources externes, afin d'éviter d'auto-bloquer le LAN ou le bridge Docker
- **Quatre firewalls supportés** : iptables, nftables, firewalld, ufw — détection automatique et application idempotente des règles
- **Protection centrée blocklist** : ipshield n'est pas un firewall default-deny complet ; avec iptables/nftables directs, le trafic non blacklisté reste accepté sauf durcissement séparé de l'hôte
- **Compatible Docker** : protection de la chaîne `DOCKER-USER` en entrée uniquement, scopée à l'interface WAN (l'egress des conteneurs n'est jamais filtré) ; avec firewalld, les règles `DOCKER-USER` restent runtime pour ne pas casser firewalld au boot si Docker n'a pas encore créé la chaîne
- **Setup compatible Docker** : les transitions firewall et changements de backend iptables proposent un chemin de maintenance guidé lorsque des chaînes Docker sont présentes, en recommandant d'abord un arrêt propre applicatif/Compose si des conteneurs tournent. Quand la transition est non destructrice (cible iptables/nftables, aucun firewall à désactiver, backend déjà aligné), Docker reste en ligne. À chaque installation ou rerun avec cible `nftables`, ipshield combine deux patches pour que `systemctl restart nftables` (au boot, sur upgrade de paquet ou manuellement) ne vide plus les règles iptables-nft de blocklist (ni celles de Docker quand présentes) : `/etc/nftables.conf` voit son `flush ruleset` commenté (sauvegarde `.ipshield.bak`), et un drop-in systemd `/etc/systemd/system/nftables.service.d/ipshield.conf` vide l'`ExecStop=nft flush ruleset` par défaut
- **SAFE_PORTS adaptés à la politique INPUT** : le prompt des ports en écoute est sauté quand le firewall a une politique INPUT permissive (cas par défaut Debian/Ubuntu avec iptables/nftables) car les ACCEPT seraient des no-ops ; quand la politique est deny-by-default (ufw, firewalld, ou iptables/nftables durci), les ports choisis sont persistés via `ipshield-safe-ports.service` pour que SSH soit rétabli au boot avant le démarrage de sshd
- **Setup conscient d'UFW** : l'état de service UFW inactif est détecté, et les transitions hors UFW nettoient les lignes ipshield/orphelines avec ipset dans `before.rules`
- **Whitelist** d'IP/subnets de confiance (management, bastions) avec garde-fou de préfixe pour empêcher un `0.0.0.0/0` accidentel
- **Mise à jour sans interruption** par swap atomique d'ipset
- **Persistance ipset au boot** pour les firewalls persistants (`ufw`, `firewalld`, `nftables`)
- **Récupération rapide au boot** : `ipshield-apply.service` (ordonné `After=docker.service`) attache les règles blocklist à l'ipset restauré quelques secondes après le démarrage de Docker, ce qui ferme l'ancienne fenêtre d'exposition au boot. Fallback automatique vers un update complet si la sauvegarde ipset manque
- **Installation guidée** : `setup-firewall.sh` installe le firewall, configure `ipshield.timer` (planification systemd toutes les 8 h, logs vers journald), dépose le filtre rsyslog et les configs logrotate
- **Lookup avec cache** : `lookup-ip.sh` identifie la source qui référence une IP sans retélécharger toutes les listes à chaque appel
- **Désinstallation propre** avec mode dry-run et confirmation
- **Fichier de configuration unique** (`/etc/update-blocklist.conf`) qui pilote l'ensemble ; aucun défaut codé en dur dans les scripts

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

### Prérequis

Accès **root** et les commandes suivantes : `curl`, `awk`, `sort`, `wc`, `date`, `comm`, `flock`, `ipset`, `logger`.

| Outil | Paquet (Debian/Ubuntu) | Paquet (Fedora) |
|---|---|---|
| `curl` | curl | curl |
| `awk` | gawk | gawk |
| `ipset` | ipset | ipset |
| `flock` | util-linux | util-linux |
| `logger` | bsdutils | util-linux |
| `sort`, `wc`, `date`, `comm` | coreutils | coreutils |

```bash
# Debian / Ubuntu
apt update && apt install -y curl gawk coreutils ipset util-linux bsdutils

# Fedora
dnf install -y curl gawk coreutils ipset util-linux
```

### Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
sudo ./setup-firewall.sh
```

`setup-firewall.sh` est le point d'entrée recommandé. Il détecte/installe le firewall, copie `update-blocklist.conf.example` vers `/etc/update-blocklist.conf`, installe `ipshield.timer` + `ipshield.service` (refresh 8 h + `OnBootSec=2min`), `ipshield-restore.service` (restore ipset au boot), `ipshield-apply.service` (fast attach des règles au boot, ordonné `After=docker.service`), le filtre rsyslog et les deux configs logrotate. Tout est idempotent — relancer pour reconfigurer.

Sélection du backend :

- La cible **iptables** sélectionne `iptables-legacy`/`ip6tables-legacy` via `update-alternatives` quand disponible.
- La cible **nftables** sélectionne `iptables-nft`/`ip6tables-nft` — ipshield applique ses règles via `iptables-nft` pour conserver le support du match ipset.

Le prompt anti-lockout est **sauté** quand le firewall choisi a une politique INPUT permissive (cas par défaut Debian/Ubuntu) car les ACCEPT seraient des no-ops. Avec un firewall deny-by-default (ufw, firewalld, ou iptables/nftables durci) les ports choisis sont persistés via `ipshield-safe-ports.service`, ordonné avant sshd/docker pour que SSH soit rétabli au boot.

Périmètre sécurité : ipshield installe des règles de blocklist. Il ne transforme pas `iptables`/`nftables` directs en firewall default-deny complet — le trafic non blacklisté reste accepté sauf durcissement séparé de l'hôte.

### Configuration

`/etc/update-blocklist.conf` est **requis** par `update-blocklist.sh` et `lookup-ip.sh`. C'est la source de vérité unique pour les URLs et les défauts. `setup-firewall.sh` le copie depuis `update-blocklist.conf.example` (chmod 600, owner root) s'il est absent ; un fichier existant est laissé intact.

| Variable | Défaut | Description |
|---|---|---|
| `URLS` | voir [Sources de blocage](#sources-de-blocage) | Tableau des URLs de listes de blocage |
| `SET_NAME` | `blacklist` | Nom du set ipset blacklist (max 31 caractères) |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | Nom du set ipset whitelist (max 31 caractères) |
| `WHITELIST` | `()` (vide) | Tableau d'IP/CIDR IPv4 toujours autorisés (voir [Whitelist](#whitelist-1)) |
| `WHITELIST_MIN_PREFIX` | `8` | Préfixe minimum accepté en WHITELIST (rejette /0 à /7 pour éviter un bypass total par typo). Mettre à 0 pour désactiver. |
| `BLOCKLIST_MIN_PREFIX` | `8` | Préfixe minimum accepté depuis les sources externes (rejette /0 à /7 — protège contre une source corrompue/malveillante qui pousserait `0.0.0.0/0`). Mettre à 0 pour désactiver. |
| `MIN_ENTRIES` | `1000` | Seuil minimum d'entrées (protection anti-purge) |
| `BASE_HASHSIZE` | `16384` | Hashsize de base pour ipset |
| `BASE_MAXELEM` | `300000` | Maxelem de base pour ipset |
| `LOG_LIMIT` | `60/min` | Rate-limit du logging des paquets bloqués (`N/sec`, `N/min`, `N/hour`, `N/day` ; vide = pas de limite) |
| `LOG_BURST` | `100` | Burst maximum avant que `LOG_LIMIT` s'applique |
| `WAN_INTERFACE` | `""` (auto) | Interface WAN pour scoper la règle DOCKER-USER à l'entrée uniquement. Vide = auto-détection via `ip route get 8.8.8.8`. À définir explicitement sur VPN/multi-homé. |
| `PERSIST_IPSET` | `1` | Sauvegarde les ipsets ipshield après chaque run réussi pour restauration au boot (`0` désactive). |
| `IPSET_SAVE_FILE` | `/var/lib/ipshield/ipset.save` | Chemin vers le fichier de sauvegarde ipset. |
| `LOOKUP_CACHE_TTL` | `21600` | TTL du cache en secondes pour les téléchargements de `lookup-ip.sh` (`0` désactive). |

Toutes les variables sont documentées inline dans `update-blocklist.conf.example` (le fichier copié dans `/etc/`).

### Utilisation

```
update-blocklist.sh [OPTIONS]
```

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Mode simulation (aucune modification ipset/firewall) |
| `-v`, `--verbose` | Affichage détaillé (stats par source, détails du diff) |
| `-c`, `--config FILE` | Chemin du fichier de configuration |
| `-h`, `--help` | Affiche l'aide |

```bash
# Dry run
./update-blocklist.sh --dry-run --verbose

# Refresh réel (exécuté aussi automatiquement via ipshield.timer)
sudo ./update-blocklist.sh --verbose

# Identifier dans quelles sources figure une IP bloquée
./lookup-ip.sh 185.199.108.133
```

`lookup-ip.sh` met les téléchargements en cache dans `/var/cache/ipshield/lookup/` (root) ou `${XDG_CACHE_HOME:-$HOME/.cache}/ipshield/lookup/` (utilisateur), un fichier par URL nommé `<sha256(URL)>.txt`. Les fichiers plus vieux que `LOOKUP_CACHE_TTL` sont rafraîchis atomiquement ; les orphelins (URL retirées) sont purgés à chaque run. Pour un bypass ponctuel : `LOOKUP_CACHE_TTL=0 ./lookup-ip.sh <ip>`.

`update-blocklist.sh` fonctionne seul (sans `setup-firewall.sh`) — il auto-détecte le firewall en place.

### Whitelist

Pour autoriser certaines IP/subnets à contourner le blocage (typiquement les hôtes de management), définir `WHITELIST` dans `/etc/update-blocklist.conf` :

```bash
WHITELIST=(
  "10.0.0.0/8"
  "172.16.0.0/12"
  "203.0.113.42"
)
```

Au prochain run, `update-blocklist.sh` crée `${SET_NAME}-allow` via swap atomique et insère une règle `ACCEPT` en position 1 sur `INPUT` (et `DOCKER-USER` si présent, scopé à l'interface WAN). Vider `WHITELIST` ensuite retire la règle et l'ipset au prochain run.

> **Attention** : la règle ACCEPT contourne **l'ensemble du filtrage firewall**, pas seulement la blocklist. Une IP whitelistée a un accès complet au serveur, indépendamment des autres règles.

> **Garde-fou anti-typo** : par défaut, tout préfixe `< /8` est refusé (`WHITELIST_MIN_PREFIX=8`). Bloque le piège classique d'un `0.0.0.0/0` accidentel qui ouvrirait tout Internet. Pour autoriser un préfixe plus large, abaisser `WHITELIST_MIN_PREFIX` explicitement.

### Scripts

| Script | Rôle |
|---|---|
| `update-blocklist.sh` | Mise à jour ipset + détection firewall + règles de blocage |
| `setup-firewall.sh` | Installation interactive du firewall + timer systemd + rsyslog/logrotate (idempotent) |
| `lookup-ip.sh` | Recherche d'une IP dans les listes de blocage (diagnostic) |
| `uninstall.sh` | Désinstallation propre (dry-run par défaut, `--apply` pour exécuter) |

### Sources de blocage

| Source | Description |
|---|---|
| [Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Liste critique d'IP malveillantes |
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

Sources personnalisables via la variable `URLS` dans `/etc/update-blocklist.conf`.

### Logs

Les quatre chemins firewall loguent les paquets bloqués via le noyau (netfilter) avec le préfixe `BLOCKED: `, donc un seul filtre rsyslog capture tout.

| Firewall | Mécanisme de log |
|---|---|
| iptables | `-j LOG --log-prefix "BLOCKED: "` → kernel log → syslog |
| nftables | via `iptables-nft` : `-j LOG --log-prefix "BLOCKED: "` → kernel log → syslog |
| firewalld | direct rules avec `-j LOG` (même mécanisme) → kernel log → syslog |
| ufw | `before.rules` avec `-j LOG` (même mécanisme) → kernel log → syslog |

`setup-firewall.sh` installe le filtre rsyslog dans `/etc/rsyslog.d/30-blocked-ips.conf` (redirige `BLOCKED: ` vers `/var/log/blocked-ips.log` et strippe le champ `MAC=<14 octets>`, qui ne porte aucune information utile — ipshield bloque par IP jamais par MAC, et le filtre bogons garantit que l'IP source n'est jamais sur le même L2). Deux configs logrotate sont installées dans `/etc/logrotate.d/update-blocklist` et `/etc/logrotate.d/blocked-ips` (weekly, rotate 4, avec le hook postrotate portable `rsyslog-rotate`).

Défauts du rate-limit : `LOG_LIMIT="60/min"` + `LOG_BURST=100`. Sous attaque massive, tous les paquets sont toujours bloqués mais seul un échantillon apparaît dans les logs. Mettre `LOG_LIMIT=""` pour tout loguer (risque de flood sous attaque) ou augmenter les deux valeurs pour plus de visibilité. Le drift est auto-détecté — relancer `update-blocklist.sh` après édition de la config pour rafraîchir les règles.

La sortie propre du timer (stdout/stderr de `update-blocklist.sh`) est appendée à `/var/log/update-blocklist.log` et dupliquée dans journald : `journalctl -u ipshield.service` (ajouter `-f` pour suivre, `-S "1 hour ago"` pour borner dans le temps). `systemctl list-timers ipshield.timer` affiche le prochain déclenchement.

### Persistance au boot et fast attach

L'`ipset blacklist` vit en RAM, et les règles LOG/DROP qui le référencent ne persistent pas. Sans mécanisme de boot dédié, l'hôte serait fail-open pendant les 30+ premières secondes après chaque reboot. ipshield fournit deux unit systemd qui ferment la fenêtre à moins de deux secondes :

1. **`ipshield-restore.service`** — oneshot early-boot, ordonné `Before=netfilter-persistent.service nftables.service ufw.service firewalld.service`. Exécute `ipset restore -! -f $IPSET_SAVE_FILE`. Indispensable pour `ufw`/`firewalld` sur `iptables-nft`, qui échouent à démarrer si leurs règles persistantes référencent un ipset absent.
2. **`ipshield-apply.service`** — exécute `update-blocklist.sh --apply-only`, ordonné `After=ipshield-restore.service nftables.service docker.service`. L'ordering Docker est opportuniste (aucun `Wants=`/`Requires=`) donc sur une machine sans Docker l'unit démarre dès que les autres contraintes sont satisfaites. Saute le cycle download/parse/swap et attache simplement les règles LOG/DROP (et DOCKER-USER quand applicable) à l'ipset restauré. Fallback sur un update complet si la sauvegarde ipset est absente ou vide — l'hôte n'est jamais laissé sans protection.

`update-blocklist.sh` sauvegarde les sets ipshield (`SET_NAME` et `WHITELIST_SET_NAME` quand présent) après chaque run réussi quand `PERSIST_IPSET=1` (défaut), alimentant les deux unit. Le déclenchement `OnBootSec=2min` du timer rafraîchit ensuite la blocklist depuis le réseau peu après le boot.

### Support Docker

Le trafic destiné aux conteneurs (ports publiés via `-p` / `ports:`) passe par `FORWARD`, pas `INPUT`. ipshield détecte Docker automatiquement via la chaîne `DOCKER-USER` et applique les mêmes règles LOG + DROP, **scopées à `-i $WAN_INTERFACE`** pour ne filtrer que l'entrée Internet — l'egress des conteneurs (`IN=br-xxx`) n'est jamais touché. Les bogons sont rejetés en amont, donc le LAN et le bridge Docker ne sont jamais blacklistés.

Les règles blocklist sont scopées à `conntrack --ctstate NEW` : les réponses aux connexions sortantes déjà suivies comme `ESTABLISHED` ne sont pas droppées même si l'endpoint distant figure dans une blocklist publique.

Avec **firewalld**, `INPUT` utilise des règles directes permanentes mais `DOCKER-USER` reste runtime-only. Stocker ces règles en permanent ferait échouer firewalld au démarrage/reload si Docker n'a pas encore créé la chaîne. Toute règle Docker permanente résiduelle d'une ancienne version d'ipshield est nettoyée avant l'application de la règle runtime.

Docker recrée `DOCKER-USER` à chaque restart du daemon, donc les règles ne persistent pas — `ipshield-apply.service` au boot et `ipshield.timer` (`OnBootSec=2min` + cadence 8 h) les réappliquent idempotemment. Si l'auto-détection de `WAN_INTERFACE` se trompe (VPN/multi-homé), définir la variable explicitement dans `/etc/update-blocklist.conf`.

### Désinstallation

```bash
# Dry-run (défaut) : prévisualise chaque changement
sudo ./uninstall.sh

# Application (avec confirmation interactive)
sudo ./uninstall.sh --apply
```

`--apply` retire les règles ipshield (LOG/DROP blocklist + ACCEPT whitelist), détruit les ipsets associés, nettoie les lignes ipshield/orphelines de `/etc/ufw/before.rules` ligne par ligne, et retire les composants project-owned sans prompt supplémentaire : `ipshield-restore.service`, `ipshield-apply.service`, `ipshield.timer` + `ipshield.service`, `ipshield-safe-ports.service`, le drop-in `nftables.service` (et la restauration de `/etc/nftables.conf` depuis `.ipshield.bak`), ainsi que `/etc/rsyslog.d/30-blocked-ips.conf` + `/etc/logrotate.d/{update-blocklist,blocked-ips}` (rsyslog est redémarré si le filtre est retiré).

Deux prompts proposent ensuite de retirer les données éditables par l'utilisateur :

1. `/etc/update-blocklist.conf`, le fichier de persistance ipset, le cache LKG (`/var/lib/ipshield/sources/`), et le cache root de `lookup-ip.sh` (`/var/cache/ipshield/lookup/`).
2. les fichiers de logs ipshield (`/var/log/update-blocklist.log*` et `/var/log/blocked-ips.log*`, y compris les fichiers rotatés/compressés).

`uninstall.sh` ne désinstalle **pas** le firewall ni aucun paquet. Les entrées journald ne sont pas purgées (le vacuum du journal est une opération système globale).

### Règles firewall manuelles (avancé)

<details>
<summary>Si vous préférez configurer les règles manuellement au lieu d'utiliser <code>setup-firewall.sh</code> / <code>update-blocklist.sh</code></summary>

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

Scoper à l'interface WAN pour ne filtrer que l'entrée :

```bash
iptables -I DOCKER-USER -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I DOCKER-USER 2 -i ens160 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
```

</details>
