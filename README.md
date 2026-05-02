<div align="center">

# ipshield

*Automatic malicious IP blocking via ipset & Linux firewall*

**[🇬🇧 English](#english) · [🇫🇷 Français](#français)**

</div>

---

<a id="english"></a>
## 🇬🇧 English

### Description

`ipshield` is a set of bash scripts that download public malicious IP lists, aggregate them into an ipset, and automatically apply blocking rules on the detected firewall.

Designed for **Debian/Ubuntu** and **Fedora/RHEL** servers.

### Features

- **11 curated public IPv4 blocklists** aggregated into a single ipset (Spamhaus, Emerging Threats, AbuseIPDB, CINS, Data-Shield, FireHOL Level 1, GreenSnow, Blocklist.de, IPsum, Tor exits, Internet Scanner ranges)
- **RFC 6890 bogon filter**: rejects RFC1918, loopback, link-local, multicast and other reserved ranges from upstream sources to prevent self-blocking the LAN or Docker bridge
- **Four supported firewalls**: iptables, nftables, firewalld, ufw — auto-detected and applied idempotently
- **Docker-aware**: inbound-only protection of the `DOCKER-USER` chain, scoped to the WAN interface (container egress is never filtered)
- **Whitelist** of trusted IPs/subnets (management, jump hosts) with prefix-width safeguard against accidental `0.0.0.0/0`
- **Zero-downtime updates** via atomic ipset swap
- **Boot-safe ipset persistence** for persistent firewalls (`ufw`, `firewalld`, `nftables`)
- **Guided setup**: `setup-firewall.sh` installs the firewall, configures the cron, drops the rsyslog filter and logrotate configs
- **Clean uninstall** with dry-run preview and confirmation
- **Single configuration file** (`/etc/update-blocklist.conf`) drives everything; no defaults hard-coded in scripts

### Supported Firewalls

| Firewall | Description |
|---|---|
| **iptables** | Classic, universally compatible |
| **nftables** | iptables successor (rules via `iptables-nft`) |
| **firewalld** | Zone-based management, common on Fedora/RHEL |
| **ufw** | User-friendly, common on Ubuntu |

### Dependencies

| Tool | Package (Debian) | Package (Fedora) |
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
```

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

### Examples

```bash
# Test in simulation mode
./update-blocklist.sh --dry-run --verbose

# Real execution
./update-blocklist.sh --verbose

# With custom configuration
./update-blocklist.sh -c /etc/my-blocklist.conf -v
```

### Scripts

| Script | Purpose |
|---|---|
| `update-blocklist.sh` | ipset update + firewall detection + blocking rules |
| `setup-firewall.sh` | Interactive firewall installation (one-shot) |
| `lookup-ip.sh` | Look up an IP across blocklist sources (diagnostic) |
| `uninstall.sh` | Clean uninstall (dry-run by default, `--apply` to execute) |

### Blocklist Sources

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

### Full Installation

See **[INSTALL.md](INSTALL.md)** for the complete guide: prerequisites, configuration, cronjob, firewall setup, logs and logrotate.

---

<a id="français"></a>
## 🇫🇷 Français

### Description

`ipshield` est un ensemble de scripts bash qui téléchargent des listes publiques d'adresses IP malveillantes, les agrègent dans un set ipset, et appliquent automatiquement les règles de blocage sur le firewall détecté.

Conçu pour les serveurs **Debian/Ubuntu** et **Fedora/RHEL**.

### Fonctionnalités

- **11 listes publiques d'IPv4 malveillantes** agrégées dans un seul ipset (Spamhaus, Emerging Threats, AbuseIPDB, CINS, Data-Shield, FireHOL Level 1, GreenSnow, Blocklist.de, IPsum, nœuds de sortie Tor, ranges de scanners Internet)
- **Filtre des bogons RFC 6890** : rejette RFC1918, loopback, link-local, multicast et autres plages réservées issues des sources externes, afin d'éviter d'auto-bloquer le LAN ou le bridge Docker
- **Quatre firewalls supportés** : iptables, nftables, firewalld, ufw — détection automatique et application idempotente des règles
- **Compatible Docker** : protection de la chaîne `DOCKER-USER` en entrée uniquement, scopée à l'interface WAN (l'egress des conteneurs n'est jamais filtré)
- **Whitelist** d'IP/subnets de confiance (management, bastions) avec garde-fou de préfixe pour empêcher un `0.0.0.0/0` accidentel
- **Mise à jour sans interruption** par swap atomique d'ipset
- **Persistance ipset au boot** pour les firewalls persistants (`ufw`, `firewalld`, `nftables`)
- **Installation guidée** : `setup-firewall.sh` installe le firewall, configure le cron, dépose le filtre rsyslog et les configs logrotate
- **Désinstallation propre** avec mode dry-run et confirmation
- **Fichier de configuration unique** (`/etc/update-blocklist.conf`) qui pilote l'ensemble ; aucun défaut codé en dur dans les scripts

### Firewalls supportés

| Firewall | Description |
|---|---|
| **iptables** | Classique, compatible partout |
| **nftables** | Successeur d'iptables (règles via `iptables-nft`) |
| **firewalld** | Gestion par zones, courant sur Fedora/RHEL |
| **ufw** | Simple d'utilisation, courant sur Ubuntu |

### Dépendances

| Outil | Paquet (Debian) | Paquet (Fedora) |
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
```

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

### Exemples

```bash
# Test en mode simulation
./update-blocklist.sh --dry-run --verbose

# Exécution réelle
./update-blocklist.sh --verbose

# Avec configuration personnalisée
./update-blocklist.sh -c /etc/my-blocklist.conf -v
```

### Scripts

| Script | Rôle |
|---|---|
| `update-blocklist.sh` | Mise à jour ipset + détection firewall + règles de blocage |
| `setup-firewall.sh` | Installation interactive d'un firewall (one-shot) |
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

### Installation complète

Voir **[INSTALL.md](INSTALL.md)** pour le guide complet : prérequis, configuration, cronjob, setup firewall, logs et logrotate.
