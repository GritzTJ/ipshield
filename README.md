<div align="center">

# ipshield

*Automatic malicious IP blocking via ipset & Linux firewall*

**[🇫🇷 Français](#français) · [🇬🇧 English](#english)**

</div>

---

<a id="français"></a>
## 🇫🇷 Français

### Description

`ipshield` est un ensemble de scripts bash qui télécharge des listes publiques d'adresses IP malveillantes, les agrège dans un set ipset, et applique automatiquement les règles de blocage sur le firewall détecté.

Conçu pour les serveurs **Debian/Ubuntu** et **Fedora/RHEL**.

### Fonctionnalités

- Agrège **5 listes publiques** de blocage IPv4 (Spamhaus DROP, Emerging Threats, AbuseIPDB, CINS, Data-Shield)
- Téléchargements **parallèles** avec retry et timeout
- **Validation stricte** des IP/CIDR (programme awk fusionné)
- Mise à jour **atomique** via `ipset restore` + `swap` (zéro downtime)
- **Détection automatique** du firewall actif
- Application **idempotente** des règles LOG + DROP
- **Support Docker** : protection automatique de la chaîne `DOCKER-USER` (conteneurs exposés)
- **Whitelist** : IP/subnets toujours autorisés (ex: IP de management) via la variable `WHITELIST` en config
- **Cron auto** : `setup-firewall.sh` propose la configuration de la crontab (idempotent, MAILTO optionnel, sleep `@reboot` configurable)
- **Désinstallation propre** (`uninstall.sh`) avec mode dry-run, confirmation, et retrait optionnel de la crontab
- **Seuil minimum** d'entrées (protection anti-purge)
- Calcul **dynamique** de hashsize/maxelem
- **Rapport de diff** : entrées ajoutées, retirées, inchangées
- Mode **dry-run** et **verbose**
- **Configuration externe** optionnelle (`/etc/update-blocklist.conf`)
- **Verrou** anti-concurrence (`flock`)
- Logs vers stdout/stderr + **syslog**

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
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Plages réseau détournées (hijack) |
| [Emerging Threats](https://rules.emergingthreats.net/) | IP bloquées par règles ET |
| [AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb) | IP signalées avec un score de 100% sur 365 jours |
| [CI Army (CINS)](https://cinsscore.com/) | IP à mauvais score de réputation |
| [Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Liste critique d'IP malveillantes |

Sources personnalisables via la variable `URLS` dans `/etc/update-blocklist.conf`.

### Installation complète

Voir **[INSTALL.md](INSTALL.md)** pour le guide complet : prérequis, configuration, cronjob, setup firewall, logs et logrotate.

---

<a id="english"></a>
## 🇬🇧 English

### Description

`ipshield` is a set of bash scripts that downloads public malicious IP lists, aggregates them into an ipset, and automatically applies blocking rules on the detected firewall.

Designed for **Debian/Ubuntu** and **Fedora/RHEL** servers.

### Features

- Aggregates **5 public** IPv4 blocklists (Spamhaus DROP, Emerging Threats, AbuseIPDB, CINS, Data-Shield)
- **Parallel** downloads with retry and timeout
- **Strict validation** of IPs/CIDRs (single fused awk program)
- **Atomic** updates via `ipset restore` + `swap` (zero downtime)
- **Automatic detection** of the active firewall
- **Idempotent** LOG + DROP rule application
- **Docker support**: automatic `DOCKER-USER` chain protection (exposed containers)
- **Whitelist**: always-allowed IPs/subnets (e.g. management IPs) via the `WHITELIST` config variable
- **Cron setup**: `setup-firewall.sh` offers crontab configuration (idempotent, optional MAILTO, configurable `@reboot` sleep)
- **Clean uninstall** (`uninstall.sh`) with dry-run, confirmation, and optional crontab removal
- **Minimum threshold** of entries (anti-purge protection)
- **Dynamic** hashsize/maxelem calculation
- **Diff report**: added, removed, unchanged entries
- **Dry-run** and **verbose** modes
- Optional **external configuration** (`/etc/update-blocklist.conf`)
- **Concurrency lock** (`flock`)
- Logs to stdout/stderr + **syslog**

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
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked network ranges |
| [Emerging Threats](https://rules.emergingthreats.net/) | IPs blocked by ET rules |
| [AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb) | IPs reported with 100% score over 365 days |
| [CI Army (CINS)](https://cinsscore.com/) | IPs with poor reputation score |
| [Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Critical malicious IP list |

Sources are customisable via the `URLS` variable in `/etc/update-blocklist.conf`.

### Full Installation

See **[INSTALL.md](INSTALL.md)** for the complete guide: prerequisites, configuration, cronjob, firewall setup, logs and logrotate.
