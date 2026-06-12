<div align="center">

# ipshield

*Automatic malicious IP blocking via ipset & Linux firewall*

**[🇬🇧 English](#english) · [🇫🇷 Français](#français)**

</div>

---

<a id="english"></a>
## 🇬🇧 English

### Description

`ipshield` is a set of bash scripts that download public malicious IPv4 lists, aggregate them into an ipset, and apply blocking rules on the detected firewall. Designed for **Debian/Ubuntu** and **Fedora/RHEL** servers, validated on Internet-exposed scenarios.

### Features

- Blocks known-malicious IPv4 addresses sourced from public threat feeds (lists fully customisable)
- Works on the four major Linux firewalls (iptables, nftables, firewalld, ufw) — auto-detected, no manual rule writing
- Self-protective: never blocks your LAN, Docker bridge or internal ranges, even if an upstream feed is corrupted
- Protects Docker containers exposed to the Internet, without restricting outbound traffic
- Whitelist for trusted hosts (admin, jump servers) with safeguards against catastrophic typos
- Updates without interrupting connections, restored within seconds after a reboot
- One-command guided install, clean dry-run uninstall

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

Validated end-to-end on each row: install, blocklist refresh, reboot restore, Docker `DOCKER-USER` protection, logs/logrotate and uninstall.

### Prerequisites

Root access. `setup-ipshield.sh` installs missing packages automatically; the table below lists them for reference and manual setups.

| Tool | Package (Debian/Ubuntu) | Package (Fedora) |
|---|---|---|
| `curl` | curl | curl |
| `awk` | gawk | gawk |
| `ipset` | ipset | ipset |
| `flock` | util-linux | util-linux |
| `logger` | bsdutils | util-linux |
| `sort`, `wc`, `date`, `comm` | coreutils | coreutils |

### Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
sudo ./setup-ipshield.sh
```

`setup-ipshield.sh` detects/installs the firewall, copies the config to `/etc/ipshield.conf`, and installs `ipshield.timer` + `ipshield.service` (8-hour refresh + `OnBootSec=2min`), `ipshield-restore.service` + `ipshield-apply.service` (close the boot exposure window to under two seconds), the rsyslog filter and the two logrotate configs. Idempotent — rerun to reconfigure.

ipshield installs blocklist rules only; on direct `iptables`/`nftables`, non-blacklisted traffic stays accepted unless you harden the host separately.

### Configuration

`/etc/ipshield.conf` is the single source of truth. `setup-ipshield.sh` copies it from `ipshield.conf.example` (chmod 600, owner root) when missing; an existing file is left intact.

| Variable | Default | Description |
|---|---|---|
| `URLS` | see [Blocklist sources](#blocklist-sources) | Array of blocklist URLs |
| `SET_NAME` | `blacklist` | ipset blacklist name (max 31 chars) |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | ipset whitelist name (max 31 chars) |
| `WHITELIST` | `()` (empty) | Always-allowed IPv4 addresses/CIDRs (see [Whitelist](#whitelist)) |
| `WHITELIST_MIN_PREFIX` | `8` | Minimum WHITELIST prefix accepted (rejects /0–/7). Set to 0 to disable. |
| `BLOCKLIST_MIN_PREFIX` | `8` | Minimum prefix accepted from external sources (catches a `0.0.0.0/0` push). Set to 0 to disable. |
| `MIN_ENTRIES` | `1000` | Minimum entries threshold (anti-purge) |
| `BASE_HASHSIZE` | `16384` | Base ipset hashsize |
| `BASE_MAXELEM` | `300000` | Base ipset maxelem |
| `LOG_LIMIT` | `60/min` | Blocked-packet log rate-limit (empty = no limit) |
| `LOG_BURST` | `100` | Maximum burst before `LOG_LIMIT` applies |
| `WAN_INTERFACE` | `""` (auto) | WAN interface for DOCKER-USER scoping. Empty = auto via `ip route get 8.8.8.8`. |
| `PERSIST_IPSET` | `1` | Save ipshield ipsets after each successful run for boot-time restore. |
| `IPSET_SAVE_FILE` | `/var/lib/ipshield/ipset.save` | Path to the ipset save file. |
| `LOOKUP_CACHE_TTL` | `21600` | Cache TTL in seconds for `lookup-ip.sh` (`0` disables). |
| `SOURCE_CACHE_DIR` | `/var/lib/ipshield/sources` | Per-source last-known-good cache directory (fallback when a source fails or shrinks). |
| `SOURCE_MIN_RATIO` | `0.5` | Below this fraction of the last good count, a source is considered degraded and its cached copy is used (`0` disables). |
| `SOURCE_CACHE_MAX_AGE` | `14` | Cache age (days) beyond which new data is trusted even if degraded. |

All variables are documented inline in `ipshield.conf.example`.

### Usage

```
update-ipshield.sh [OPTIONS]
```

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Simulation mode (no ipset/firewall changes) |
| `-v`, `--verbose` | Detailed output (per-source stats, diff details) |
| `-c`, `--config FILE` | Configuration file path |
| `-h`, `--help` | Show help |

```bash
# Dry run
./update-ipshield.sh --dry-run --verbose

# Real refresh (also runs automatically via ipshield.timer)
sudo ./update-ipshield.sh --verbose

# Identify which sources list a blocked IP
./lookup-ip.sh 185.199.108.133
```

`lookup-ip.sh` caches downloads in `/var/cache/ipshield/lookup/` for `LOOKUP_CACHE_TTL` seconds (default 6 h; `LOOKUP_CACHE_TTL=0` disables). `update-ipshield.sh` works standalone — it auto-detects the existing firewall.

### Whitelist

To let specific IPs/subnets bypass the blocklist (typically management hosts), set `WHITELIST` in `/etc/ipshield.conf`:

```bash
WHITELIST=(
  "10.0.0.0/8"
  "172.16.0.0/12"
  "203.0.113.42"
)
```

On the next run, `update-ipshield.sh` creates `${SET_NAME}-allow` via atomic swap and inserts an `ACCEPT` rule at position 1 on `INPUT` (and `DOCKER-USER` if present, scoped to the WAN interface). Emptying `WHITELIST` later removes both rule and ipset on the next run.

> **Warning**: the ACCEPT rule bypasses **the entire firewall**, not only the blocklist. A whitelisted IP has full server access regardless of other rules.

> **Anti-typo safeguard**: by default, any prefix `< /8` is rejected (`WHITELIST_MIN_PREFIX=8`). Blocks the classic `0.0.0.0/0` typo. Lower `WHITELIST_MIN_PREFIX` explicitly to allow a wider prefix.

### Scripts

| Script | Purpose |
|---|---|
| `update-ipshield.sh` | ipset update + firewall detection + blocking rules |
| `setup-ipshield.sh` | Interactive firewall installation + systemd timer + rsyslog/logrotate (idempotent) |
| `lookup-ip.sh` | Look up an IP across blocklist sources (diagnostic) |
| `uninstall-ipshield.sh` | Clean uninstall (dry-run by default, `--apply` to execute) |

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

Customisable via the `URLS` variable in `/etc/ipshield.conf`.

### Logs

All four firewall paths log via the kernel (netfilter) with the `BLOCKED: ` prefix, so a single rsyslog filter captures everything. `setup-ipshield.sh` writes the filter at `/etc/rsyslog.d/30-ipshield.conf` (redirects `BLOCKED: ` to `/var/log/ipshield.log` and strips the noise-only `MAC=` field) plus two logrotate configs at `/etc/logrotate.d/{update-ipshield,ipshield}` (weekly, rotate 4).

Rate-limit defaults: `LOG_LIMIT="60/min"` + `LOG_BURST=100`. Packets are always dropped; only a sample is logged under load. Adjust both, or set `LOG_LIMIT=""` to log everything. Timer output goes to `journalctl -u ipshield.service` and `/var/log/update-ipshield.log`.

### Docker support

Auto-detected via the `DOCKER-USER` chain. LOG + DROP rules are scoped to `-i $WAN_INTERFACE` so only inbound traffic from the Internet is filtered — container egress is untouched. `ctstate NEW` keeps replies to established outbound connections from being dropped. If WAN auto-detection picks the wrong interface (VPN/multi-homed), set `WAN_INTERFACE` explicitly in `/etc/ipshield.conf`.

### Uninstall

```bash
# Dry-run (default): preview every change
sudo ./uninstall-ipshield.sh

# Apply (with interactive confirmation)
sudo ./uninstall-ipshield.sh --apply
```

`--apply` removes ipshield rules, ipsets and project-owned components (timer, services, rsyslog filter, logrotate, `nftables.service` drop-in, `before.rules` lines) without further prompts, then asks separately whether to remove `/etc/ipshield.conf`, the cache directories and the log files. The firewall and packages are never uninstalled.

### Manual firewall rules (advanced)

<details>
<summary>If you prefer to configure rules manually instead of using <code>setup-ipshield.sh</code> / <code>update-ipshield.sh</code></summary>

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
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 2 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
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

`ipshield` est un ensemble de scripts bash qui téléchargent des listes publiques d'IPv4 malveillantes, les agrègent dans un ipset et appliquent les règles de blocage sur le firewall détecté. Conçu pour les serveurs **Debian/Ubuntu** et **Fedora/RHEL**, validé sur scénarios exposés sur Internet.

### Fonctionnalités

- Bloque les adresses IPv4 malveillantes issues de feeds publics de threat intelligence (listes entièrement personnalisables)
- Fonctionne sur les quatre principaux firewalls Linux (iptables, nftables, firewalld, ufw) — auto-détectés, aucune règle à écrire à la main
- Auto-protecteur : ne bloque jamais votre LAN, le bridge Docker ou les plages internes, même si un feed amont est corrompu
- Protège les conteneurs Docker exposés à Internet, sans entraver le trafic sortant
- Whitelist pour les hôtes de confiance (admin, bastions) avec garde-fous contre les typos catastrophiques
- Mises à jour sans interrompre les connexions, protection restaurée en quelques secondes après un reboot
- Installation guidée en une commande, désinstallation propre avec dry-run

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

Validé end-to-end sur chaque ligne : install, refresh blocklist, restauration au reboot, protection Docker `DOCKER-USER`, logs/logrotate et désinstallation.

### Prérequis

Accès root. `setup-ipshield.sh` installe automatiquement les paquets manquants ; la table ci-dessous les liste pour référence et pour les setups manuels.

| Outil | Paquet (Debian/Ubuntu) | Paquet (Fedora) |
|---|---|---|
| `curl` | curl | curl |
| `awk` | gawk | gawk |
| `ipset` | ipset | ipset |
| `flock` | util-linux | util-linux |
| `logger` | bsdutils | util-linux |
| `sort`, `wc`, `date`, `comm` | coreutils | coreutils |

### Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
sudo ./setup-ipshield.sh
```

`setup-ipshield.sh` détecte/installe le firewall, copie la config vers `/etc/ipshield.conf`, et installe `ipshield.timer` + `ipshield.service` (refresh 8 h + `OnBootSec=2min`), `ipshield-restore.service` + `ipshield-apply.service` (ferment la fenêtre d'exposition au boot à moins de deux secondes), le filtre rsyslog et les deux configs logrotate. Idempotent — relancer pour reconfigurer.

ipshield installe uniquement des règles de blocklist ; avec `iptables`/`nftables` directs, le trafic non blacklisté reste accepté sauf durcissement séparé de l'hôte.

### Configuration

`/etc/ipshield.conf` est la source de vérité unique. `setup-ipshield.sh` le copie depuis `ipshield.conf.example` (chmod 600, owner root) s'il est absent ; un fichier existant est laissé intact.

| Variable | Défaut | Description |
|---|---|---|
| `URLS` | voir [Sources de blocage](#sources-de-blocage) | Tableau des URLs de listes de blocage |
| `SET_NAME` | `blacklist` | Nom du set ipset blacklist (max 31 caractères) |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | Nom du set ipset whitelist (max 31 caractères) |
| `WHITELIST` | `()` (vide) | IP/CIDR IPv4 toujours autorisés (voir [Whitelist](#whitelist-1)) |
| `WHITELIST_MIN_PREFIX` | `8` | Préfixe minimum accepté en WHITELIST (rejette /0–/7). Mettre à 0 pour désactiver. |
| `BLOCKLIST_MIN_PREFIX` | `8` | Préfixe minimum accepté depuis les sources externes (protège contre un push `0.0.0.0/0`). Mettre à 0 pour désactiver. |
| `MIN_ENTRIES` | `1000` | Seuil minimum d'entrées (anti-purge) |
| `BASE_HASHSIZE` | `16384` | Hashsize de base pour ipset |
| `BASE_MAXELEM` | `300000` | Maxelem de base pour ipset |
| `LOG_LIMIT` | `60/min` | Rate-limit du logging des paquets bloqués (vide = pas de limite) |
| `LOG_BURST` | `100` | Burst maximum avant que `LOG_LIMIT` s'applique |
| `WAN_INTERFACE` | `""` (auto) | Interface WAN pour scoper DOCKER-USER. Vide = auto via `ip route get 8.8.8.8`. |
| `PERSIST_IPSET` | `1` | Sauvegarde les ipsets ipshield après chaque run réussi pour restauration au boot. |
| `IPSET_SAVE_FILE` | `/var/lib/ipshield/ipset.save` | Chemin vers le fichier de sauvegarde ipset. |
| `LOOKUP_CACHE_TTL` | `21600` | TTL du cache en secondes pour `lookup-ip.sh` (`0` désactive). |
| `SOURCE_CACHE_DIR` | `/var/lib/ipshield/sources` | Répertoire du cache last-known-good par source (fallback si une source échoue ou rétrécit). |
| `SOURCE_MIN_RATIO` | `0.5` | Sous cette fraction du dernier bon comptage, la source est considérée dégradée et sa copie en cache est utilisée (`0` désactive). |
| `SOURCE_CACHE_MAX_AGE` | `14` | Âge du cache (jours) au-delà duquel les nouvelles données sont acceptées même dégradées. |

Toutes les variables sont documentées inline dans `ipshield.conf.example`.

### Utilisation

```
update-ipshield.sh [OPTIONS]
```

| Option | Description |
|---|---|
| `-n`, `--dry-run` | Mode simulation (aucune modification ipset/firewall) |
| `-v`, `--verbose` | Affichage détaillé (stats par source, détails du diff) |
| `-c`, `--config FILE` | Chemin du fichier de configuration |
| `-h`, `--help` | Affiche l'aide |

```bash
# Dry run
./update-ipshield.sh --dry-run --verbose

# Refresh réel (exécuté aussi automatiquement via ipshield.timer)
sudo ./update-ipshield.sh --verbose

# Identifier dans quelles sources figure une IP bloquée
./lookup-ip.sh 185.199.108.133
```

`lookup-ip.sh` met les téléchargements en cache dans `/var/cache/ipshield/lookup/` pendant `LOOKUP_CACHE_TTL` secondes (défaut 6 h ; `LOOKUP_CACHE_TTL=0` désactive). `update-ipshield.sh` fonctionne seul — il auto-détecte le firewall en place.

### Whitelist

Pour autoriser certaines IP/subnets à contourner le blocage (typiquement les hôtes de management), définir `WHITELIST` dans `/etc/ipshield.conf` :

```bash
WHITELIST=(
  "10.0.0.0/8"
  "172.16.0.0/12"
  "203.0.113.42"
)
```

Au prochain run, `update-ipshield.sh` crée `${SET_NAME}-allow` via swap atomique et insère une règle `ACCEPT` en position 1 sur `INPUT` (et `DOCKER-USER` si présent, scopé à l'interface WAN). Vider `WHITELIST` ensuite retire la règle et l'ipset au prochain run.

> **Attention** : la règle ACCEPT contourne **l'ensemble du filtrage firewall**, pas seulement la blocklist. Une IP whitelistée a un accès complet au serveur.

> **Garde-fou anti-typo** : par défaut, tout préfixe `< /8` est refusé (`WHITELIST_MIN_PREFIX=8`). Bloque le piège classique d'un `0.0.0.0/0` accidentel. Abaisser `WHITELIST_MIN_PREFIX` explicitement pour autoriser un préfixe plus large.

### Scripts

| Script | Rôle |
|---|---|
| `update-ipshield.sh` | Mise à jour ipset + détection firewall + règles de blocage |
| `setup-ipshield.sh` | Installation interactive du firewall + timer systemd + rsyslog/logrotate (idempotent) |
| `lookup-ip.sh` | Recherche d'une IP dans les listes de blocage (diagnostic) |
| `uninstall-ipshield.sh` | Désinstallation propre (dry-run par défaut, `--apply` pour exécuter) |

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

Personnalisable via la variable `URLS` dans `/etc/ipshield.conf`.

### Logs

Les quatre chemins firewall loguent via le noyau (netfilter) avec le préfixe `BLOCKED: `, donc un seul filtre rsyslog capture tout. `setup-ipshield.sh` écrit le filtre dans `/etc/rsyslog.d/30-ipshield.conf` (redirige `BLOCKED: ` vers `/var/log/ipshield.log` et strippe le champ `MAC=` superflu) et deux configs logrotate dans `/etc/logrotate.d/{update-ipshield,ipshield}` (weekly, rotate 4).

Défauts du rate-limit : `LOG_LIMIT="60/min"` + `LOG_BURST=100`. Les paquets sont toujours bloqués ; seul un échantillon est logué sous charge. Ajuster les deux, ou mettre `LOG_LIMIT=""` pour tout loguer. La sortie du timer va dans `journalctl -u ipshield.service` et `/var/log/update-ipshield.log`.

### Support Docker

Auto-détecté via la chaîne `DOCKER-USER`. Les règles LOG + DROP sont scopées à `-i $WAN_INTERFACE` pour ne filtrer que le trafic entrant depuis Internet — l'egress des conteneurs n'est pas touché. `ctstate NEW` empêche le drop des réponses à des connexions sortantes déjà établies. Si l'auto-détection WAN se trompe (VPN/multi-homé), définir `WAN_INTERFACE` explicitement dans `/etc/ipshield.conf`.

### Désinstallation

```bash
# Dry-run (défaut) : prévisualise chaque changement
sudo ./uninstall-ipshield.sh

# Application (avec confirmation interactive)
sudo ./uninstall-ipshield.sh --apply
```

`--apply` retire les règles ipshield, les ipsets et les composants project-owned (timer, services, filtre rsyslog, logrotate, drop-in `nftables.service`, lignes dans `before.rules`) sans prompt supplémentaire, puis demande séparément si retirer `/etc/ipshield.conf`, les caches et les fichiers de logs. Le firewall et les paquets ne sont jamais désinstallés.

### Règles firewall manuelles (avancé)

<details>
<summary>Si vous préférez configurer les règles manuellement au lieu d'utiliser <code>setup-ipshield.sh</code> / <code>update-ipshield.sh</code></summary>

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
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m conntrack --ctstate NEW -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 2 -m conntrack --ctstate NEW -m set --match-set blacklist src -j DROP
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
