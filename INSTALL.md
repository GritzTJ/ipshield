# Blocage des adresses IP malfaisantes

Guide d'installation du script de mise à jour automatique d'un ipset de blocage IPv4.

## Prérequis

Le script nécessite un accès **root** et les commandes suivantes : `curl`, `awk`, `sort`, `wc`, `date`, `comm`, `flock`, `ipset`, `logger`.

### Debian / Ubuntu

```bash
apt update
apt install -y curl gawk coreutils ipset util-linux bsdutils
```

### Fedora

```bash
dnf install -y curl gawk coreutils ipset util-linux
```

> `sort`, `wc`, `date` et `comm` sont fournis par **coreutils**, `flock` par **util-linux**, `logger` par **bsdutils** (Debian) ou **util-linux** (Fedora). `awk` est couvert par **gawk**.

## Installation du script

```bash
curl -fsSL -o /root/update-blocklist.sh \
  https://raw.githubusercontent.com/GritzTJ/ipshield/main/update-blocklist.sh
chmod 700 /root/update-blocklist.sh
```

## Configuration (optionnel)

Copier l'exemple de configuration et l'adapter si besoin :

```bash
curl -fsSL -o /etc/update-blocklist.conf.example \
  https://raw.githubusercontent.com/GritzTJ/ipshield/main/update-blocklist.conf.example
cp /etc/update-blocklist.conf.example /etc/update-blocklist.conf
chmod 600 /etc/update-blocklist.conf
```

Par défaut, le script fonctionne sans fichier de configuration. Les variables personnalisables sont :

| Variable | Défaut | Description |
|---|---|---|
| `URLS` | voir ci-dessous | Tableau des URLs de listes de blocage |
| `SET_NAME` | `blacklist` | Nom du set ipset |
| `MIN_ENTRIES` | `1000` | Seuil minimum d'entrées (protection anti-purge) |
| `BASE_HASHSIZE` | `16384` | Hashsize de base pour ipset |
| `BASE_MAXELEM` | `300000` | Maxelem de base pour ipset |

### Sources par défaut

Le script télécharge et agrège les listes suivantes :

| Source | Description |
|---|---|
| [Data-Shield IPv4 Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | Liste critique d'IP malveillantes |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Plages réseau détournées (hijack) |
| [Emerging Threats](https://rules.emergingthreats.net/) | IP bloquées par règles ET |
| [CI Army (CINS)](https://cinsscore.com/) | IP à mauvais score de réputation |
| [AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb) | IP signalées avec un score de 100% sur 365 jours |

Ces sources sont personnalisables via la variable `URLS` dans `/etc/update-blocklist.conf`.

## Cronjob

Exécution toutes les 12 heures et au démarrage :

```bash
crontab -e
```

Ajouter les lignes suivantes :

```
0 */12 * * * /root/update-blocklist.sh >> /var/log/update-blocklist.log 2>&1
@reboot sleep 30 && /root/update-blocklist.sh >> /var/log/update-blocklist.log 2>&1
```

## Logrotate

Créer le fichier `/etc/logrotate.d/update-blocklist` :

```bash
cat > /etc/logrotate.d/update-blocklist << 'EOF'
/var/log/update-blocklist.log {
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
}
EOF
```

## Vérification

Lancer un test en mode simulation :

```bash
/root/update-blocklist.sh --dry-run --verbose
```

Puis une première exécution réelle :

```bash
/root/update-blocklist.sh --verbose
```

Vérifier que le set ipset est bien créé :

```bash
ipset list blacklist | head -10
```

## Configuration du firewall

Le workflow se fait en 2 étapes :

### Étape 1 : Installer un firewall (une seule fois)

Le script `setup-firewall.sh` détecte, installe et active un firewall sur le système :

```bash
curl -fsSL -o /root/setup-firewall.sh \
  https://raw.githubusercontent.com/GritzTJ/ipshield/main/setup-firewall.sh
chmod 700 /root/setup-firewall.sh
/root/setup-firewall.sh
```

Le script :
1. Détecte le firewall actif (firewalld, ufw, nftables ou iptables)
2. Propose un menu avec les 4 options
3. Détecte automatiquement le port SSH et propose de l'ouvrir avant activation (protection anti-lockout)
4. Désactive l'ancien firewall si un autre est choisi (avec rollback automatique en cas d'échec)
5. Installe et active le nouveau firewall

### Étape 2 : Télécharger les IP et appliquer les règles de blocage (récurrent)

Le script `update-blocklist.sh` fait tout automatiquement :

```bash
chmod +x update-blocklist.sh
sudo ./update-blocklist.sh --verbose
```

Le script :
1. Télécharge les listes d'IP malveillantes
2. Met à jour le set ipset via swap atomique
3. Détecte automatiquement le firewall actif
4. Applique les règles LOG + DROP de manière idempotente

`update-blocklist.sh` fonctionne seul (sans setup-firewall.sh) car il auto-détecte le firewall en place.

### Support Docker

Sur un hôte Docker, le trafic destiné aux conteneurs (ports publiés via `-p` / `ports:`) passe par la chaîne `FORWARD`, pas `INPUT`. Sans protection supplémentaire, les IP bloquées atteignent quand même les conteneurs.

Le script détecte automatiquement la présence de Docker via la chaîne `DOCKER-USER` dans iptables. Quand elle existe, les mêmes règles LOG + DROP sont appliquées sur `DOCKER-USER` en plus de `INPUT`, protégeant ainsi les conteneurs exposés (ex : Traefik, Nginx, etc.).

**Notes :**

- Docker recrée `DOCKER-USER` à chaque restart du daemon — les règles ne persistent pas. Le cron + `@reboot` les réapplique automatiquement, et l'idempotence évite les doublons.
- Si le script s'exécute au boot avant Docker, `DOCKER-USER` n'existe pas encore — la détection est correctement négative. Le prochain cron rattrapera.
- Aucune configuration nécessaire : la détection et l'application sont entièrement automatiques.

Vérification après exécution :

```bash
iptables -L DOCKER-USER -n
```

Les règles LOG + DROP avec `match-set blacklist src` doivent apparaître.

### Firewalls supportés

| Firewall | Description |
|---|---|
| **iptables** | Classique, compatible partout, simple |
| **nftables** | Successeur d'iptables, performant, syntaxe unifiée |
| **firewalld** | Gestion par zones, rechargement dynamique, courant sur Fedora/RHEL |
| **ufw** | Simple d'utilisation, courant sur Ubuntu |

### Configuration manuelle (alternative)

#### iptables

```bash
iptables -I INPUT -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I INPUT 2 -m set --match-set blacklist src -j DROP
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
iptables -I INPUT -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I INPUT 2 -m set --match-set blacklist src -j DROP
```

#### firewalld

```bash
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m set --match-set blacklist src -j DROP
firewall-cmd --reload
```

#### ufw

Ajouter dans `/etc/ufw/before.rules` (section `*filter`, avant `COMMIT`) :

```
-A ufw-before-input -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
-A ufw-before-input -m set --match-set blacklist src -j DROP
```

Puis `ufw reload`.

#### Docker (DOCKER-USER)

Sur un hôte Docker, ajouter les mêmes règles sur la chaîne `DOCKER-USER` pour protéger les conteneurs :

```bash
iptables -I DOCKER-USER -m set --match-set blacklist src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -I DOCKER-USER 2 -m set --match-set blacklist src -j DROP
```

> `update-blocklist.sh` fait cela automatiquement quand Docker est détecté. La configuration manuelle n'est nécessaire que si vous n'utilisez pas le script.

## Logs des IP bloquées

Les règles appliquées par `update-blocklist.sh` utilisent toutes le préfixe `BLOCKED: ` dans leurs logs, quel que soit le firewall :

| Firewall | Mécanisme de log | Destination brute |
|---|---|---|
| **iptables** | `-j LOG --log-prefix "BLOCKED: "` | kernel log → syslog |
| **nftables** | Via `iptables-nft` : `-j LOG --log-prefix "BLOCKED: "` | kernel log → syslog |
| **firewalld** | Direct rules avec `-j LOG` (même mécanisme qu'iptables) | kernel log → syslog |
| **ufw** | Règles dans `before.rules` avec `-j LOG` (même mécanisme qu'iptables) | kernel log → syslog |

Tous les firewalls passent par le logging noyau (netfilter), ce qui permet d'utiliser **un seul filtre rsyslog** pour rediriger vers `/var/log/blocked-ips.log`.

### Filtre rsyslog

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

### Note pour ufw

ufw possède son propre système de logs (`/var/log/ufw.log`). Les paquets bloqués par nos règles dans `before.rules` apparaissent dans `/var/log/blocked-ips.log` via rsyslog (grâce au préfixe `BLOCKED: `), mais **pas** dans `/var/log/ufw.log` car nos règles LOG+DROP sont exécutées avant le logging propre à ufw.

Si le logging ufw est activé (`ufw logging on`), il ne concerne que les règles gérées par ufw lui-même, pas nos règles personnalisées.

### Note pour nftables

Les règles de blocage nftables sont appliquées via `iptables-nft` (nftables ne peut pas référencer les sets ipset nativement). Le mécanisme de log est donc identique à iptables (`-j LOG`), avec la même infrastructure kernel → syslog. Le filtre rsyslog ci-dessus les capture de la même manière.

### Logrotate

Créer le fichier `/etc/logrotate.d/blocked-ips` :

```bash
cat > /etc/logrotate.d/blocked-ips << 'EOF'
/var/log/blocked-ips.log {
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}
EOF
```
