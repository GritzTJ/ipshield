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

## Installation

```bash
git clone https://github.com/GritzTJ/ipshield.git
cd ipshield
chmod 700 *.sh
```

## Configuration (optionnel)

Copier l'exemple de configuration et l'adapter si besoin :

```bash
cp update-blocklist.conf.example /etc/update-blocklist.conf
chmod 600 /etc/update-blocklist.conf
```

Par défaut, le script fonctionne sans fichier de configuration. Les variables personnalisables sont :

| Variable | Défaut | Description |
|---|---|---|
| `URLS` | voir ci-dessous | Tableau des URLs de listes de blocage |
| `SET_NAME` | `blacklist` | Nom du set ipset blacklist |
| `WHITELIST_SET_NAME` | `${SET_NAME}-allow` | Nom du set ipset whitelist |
| `WHITELIST` | `()` (vide) | Tableau d'IP/CIDR IPv4 toujours autorisés (voir [Whitelist](#whitelist)) |
| `WHITELIST_MIN_PREFIX` | `8` | Préfixe minimum accepté en WHITELIST (rejette /0 à /7 pour éviter un bypass total par typo). Mettre à 0 pour désactiver. |
| `MIN_ENTRIES` | `1000` | Seuil minimum d'entrées (protection anti-purge) |
| `BASE_HASHSIZE` | `16384` | Hashsize de base pour ipset |
| `BASE_MAXELEM` | `300000` | Maxelem de base pour ipset |
| `LOG_LIMIT` | `60/min` | Rate-limit du logging des paquets bloqués (`N/sec`, `N/min`, `N/hour`, `N/day` ; vide = pas de limite) |
| `LOG_BURST` | `100` | Burst maximum avant que `LOG_LIMIT` s'applique |

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

## Utilisation

### Étape 1 : Installer un firewall (une seule fois)

Le script `setup-firewall.sh` détecte, installe et active un firewall sur le système :

```bash
./setup-firewall.sh
```

Le script :
1. Détecte le firewall actif (firewalld, ufw, nftables ou iptables)
2. Propose un menu avec les 4 options
3. Détecte automatiquement les ports TCP en écoute (non-loopback) et propose de les ouvrir avant activation (protection anti-lockout)
4. Désactive l'ancien firewall si un autre est choisi (avec rollback automatique en cas d'échec)
5. Installe et active le nouveau firewall
6. Vérifie que le firewall répond après activation (sinon rollback)
7. **Propose de configurer le crontab ipshield** : chemin du script, fichier de log, MAILTO optionnel, délai au `@reboot`. Idempotent (relance possible pour modifier).
8. **Propose d'installer le filtre rsyslog + logrotate** : `30-blocked-ips.conf` pour rediriger les `BLOCKED:` vers `/var/log/blocked-ips.log`, et deux configs logrotate (rotate 4 weekly). Idempotent (compare le contenu, ne ré-écrit que si différent ou absent).

> Si le firewall choisi est déjà actif (pas de transition), `setup-firewall.sh` saute directement aux étapes 7 et 8.

### Étape 2 : Lancer le blocage (première exécution)

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

### Identifier la source d'une IP bloquée

Si une IP apparaît dans les logs (`BLOCKED:`), identifier sa source :

```bash
./lookup-ip.sh 185.199.108.133
./lookup-ip.sh --verbose 1.2.3.4
```

Le script télécharge les listes à la volée et indique dans quelle(s) source(s) l'IP apparaît. Fonctionne sans root (la vérification ipset est ignorée).

## Whitelist

Pour autoriser certaines IP ou subnets à contourner le blocage (typiquement vos IP/subnets de management), définir la variable `WHITELIST` dans `/etc/update-blocklist.conf` :

```bash
WHITELIST=(
  "203.0.113.42"
  "198.51.100.0/24"
)
```

Au prochain run, le script :

1. Crée un second ipset (`blacklist-allow` par défaut) via swap atomique
2. Insère une règle `ACCEPT` en position 1 sur `INPUT` (et `DOCKER-USER` si présent)
3. Si `WHITELIST` est ensuite vidé : la règle ACCEPT et l'ipset whitelist sont automatiquement retirés au prochain run

> **Attention** : la règle ACCEPT contourne **l'ensemble du filtrage firewall**, pas seulement la blocklist. Une IP whitelistée a un accès complet au serveur, indépendamment des autres règles. À réserver aux IP/subnets de confiance.

> **Garde-fou anti-typo** : par défaut, tout préfixe < `/8` est refusé (`WHITELIST_MIN_PREFIX=8`). Cela bloque le piège classique d'un `0.0.0.0/0` accidentel qui ouvrirait tout Internet en bypass total. Si tu as un besoin légitime de préfixe plus large, abaisse `WHITELIST_MIN_PREFIX` explicitement.

Vérification :

```bash
ipset list blacklist-allow | head -10
iptables -S INPUT | grep blacklist-allow
```

## Désinstallation

`uninstall.sh` retire les règles ipshield (LOG/DROP blocklist + ACCEPT whitelist), détruit les ipsets associés, et restaure `/etc/ufw/before.rules.bak` si présent. Il **ne désinstalle pas** le firewall ni les paquets.

```bash
# Mode dry-run (défaut) : affiche ce qui serait fait
./uninstall.sh

# Application réelle (avec confirmation interactive)
./uninstall.sh --apply
```

En mode `--apply`, après suppression des règles et ipsets, deux prompts séparés proposent de retirer :
1. les lignes cron ipshield du crontab de root (le reste est préservé) ;
2. les configs `/etc/rsyslog.d/30-blocked-ips.conf` et `/etc/logrotate.d/{update-blocklist,blocked-ips}` (rsyslog est redémarré si le filtre est retiré).

Les entrées dans `/etc/crontab` ou `/etc/cron.d/*` sont seulement listées (à retirer manuellement). Les fichiers de log eux-mêmes (`/var/log/update-blocklist.log`, `/var/log/blocked-ips.log`) sont conservés.

## Support Docker

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

## Automatisation (cron)

`setup-firewall.sh` propose la configuration du crontab à la fin de son exécution (étape 7). C'est la méthode recommandée — elle est idempotente, détecte le chemin existant et préserve le reste du crontab.

Pour reconfigurer le crontab plus tard sans toucher au firewall : relancer `./setup-firewall.sh` et choisir le firewall déjà actif.

Le script applique le schedule par défaut suivant :

```
0 */12 * * * /chemin/vers/update-blocklist.sh >> /var/log/update-blocklist.log 2>&1
@reboot sleep 60 && /chemin/vers/update-blocklist.sh >> /var/log/update-blocklist.log 2>&1
```

- `sleep 60` au `@reboot` : laisse le temps à Docker de démarrer avant que le script cherche la chaîne `DOCKER-USER` (ajustable via le prompt).
- `MAILTO=...` ajouté en haut si une adresse email est fournie : cron envoie un mail à chaque erreur (sortie sur stderr).

### Configuration manuelle (alternative)

Si vous préférez gérer le crontab à la main :

```bash
crontab -e
```

```
MAILTO=admin@exemple.fr
0 */12 * * * /chemin/vers/update-blocklist.sh >> /var/log/update-blocklist.log 2>&1
@reboot sleep 60 && /chemin/vers/update-blocklist.sh >> /var/log/update-blocklist.log 2>&1
```

## Logs

> **Installation recommandée** : `setup-firewall.sh` propose à la fin (étape 8) d'installer automatiquement le filtre rsyslog et les deux configs logrotate. Idempotent (rejouer ne ré-écrit que si différent). Les sections ci-dessous sont la procédure manuelle équivalente, à utiliser si tu préfères tout faire à la main.

### Logrotate du script

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

### Logs des IP bloquées

Par défaut, le logging est **rate-limité** à **60 logs/min avec burst 100** (`LOG_LIMIT="60/min"`, `LOG_BURST=100`). Sous attaque massive, tous les paquets sont **bloqués** mais seul un échantillon apparaît dans les logs — pour éviter de saturer `/var/log/`.

Pour ajuster :
- `LOG_LIMIT="600/min"` + `LOG_BURST=1000` : plus de visibilité, plus de risque de flood
- `LOG_LIMIT=""` (vide) : pas de rate-limit, loggue **tout** (risque réel sous attaque)
- voir `update-blocklist.conf.example` pour les détails

Pour iptables/nftables/DOCKER-USER, le drift est détecté automatiquement : changer `LOG_LIMIT` et lancer `update-blocklist.sh` met à jour les règles. Pour **ufw** (via `/etc/ufw/before.rules`) et **firewalld** (via `--direct`), un changement de valeur nécessite `./uninstall.sh --apply` puis ré-exécution de `update-blocklist.sh`.

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

> **Note ufw** : les paquets bloqués par nos règles dans `before.rules` apparaissent dans `/var/log/blocked-ips.log` via rsyslog, mais **pas** dans `/var/log/ufw.log` car nos règles LOG+DROP sont exécutées avant le logging propre à ufw.

> **Note nftables** : les règles de blocage sont appliquées via `iptables-nft`. Le mécanisme de log est identique à iptables (`-j LOG`), capturé par le même filtre rsyslog.

### Logrotate des IP bloquées

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

## Firewalls supportés

| Firewall | Description |
|---|---|
| **iptables** | Classique, compatible partout, simple |
| **nftables** | Successeur d'iptables, performant, syntaxe unifiée |
| **firewalld** | Gestion par zones, rechargement dynamique, courant sur Fedora/RHEL |
| **ufw** | Simple d'utilisation, courant sur Ubuntu |

## Configuration manuelle du firewall (alternative)

Si vous préférez configurer les règles manuellement au lieu d'utiliser `update-blocklist.sh` :

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
