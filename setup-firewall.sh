#!/bin/bash
set -euo pipefail
umask 077

# --- Usage / aide ---
case "${1:-}" in
  -h|--help)
    cat <<'EOF'
Usage: setup-firewall.sh

Script interactif d'installation et de configuration du firewall.
Détecte le firewall actif, propose un choix parmi iptables, nftables,
firewalld et ufw, puis effectue la transition.

Avant activation, détecte automatiquement les ports TCP en écoute
(non-loopback) et propose de les autoriser pour éviter de couper
des services exposés (SSH, web, etc.).
EOF
    exit 0 ;;
esac

# --- Fonctions ---
log() { echo "$*"; }
err() { echo "ERREUR : $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "commande manquante : $1"; exit 1; }
}

# --- Prompt oui/non uniforme avec défaut ---
# Usage : ask_yes_no "Question" oui|non
# Retour : 0 si oui, 1 si non. Entrée vide = défaut. Réponse invalide = ré-interrogation.
ask_yes_no() {
  local prompt="$1"
  local default="$2"
  local hint
  if [ "$default" = "oui" ]; then
    hint="[Oui/non]"
  else
    hint="[oui/Non]"
  fi
  local ans
  while true; do
    read -rp "$prompt $hint : " ans
    [ -z "$ans" ] && ans="$default"
    case "${ans,,}" in
      oui|o|yes|y) return 0 ;;
      non|n|no)    return 1 ;;
      *) echo "  Réponse invalide. Tapez oui/non (ou Entrée pour [$default])." ;;
    esac
  done
}

# --- Vérification root ---
if [ "$(id -u)" -ne 0 ]; then
  err "ce script doit être exécuté en tant que root."
  exit 1
fi

# --- Vérification dépendances ---
need_cmd systemctl

# --- Détection du gestionnaire de paquets ---
if command -v apt >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MANAGER="dnf"
else
  err "gestionnaire de paquets non supporté (apt ou dnf requis)."
  exit 1
fi

# --- Détection du firewall actif ---
detect_firewall() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
    return
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "active"; then
    echo "ufw"
    return
  fi

  if systemctl is-active --quiet nftables 2>/dev/null; then
    echo "nftables"
    return
  fi
  if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
    echo "nftables"
    return
  fi

  if command -v iptables >/dev/null 2>&1 && iptables -L -n 2>/dev/null | grep -q "^Chain"; then
    # Ignorer les chaînes résiduelles de ufw si ufw est installé mais inactif
    if ! command -v ufw >/dev/null 2>&1 || ! iptables -L -n 2>/dev/null | grep -q "^Chain ufw-"; then
      echo "iptables"
      return
    fi
  fi

  echo "aucun"
}

DETECTED="$(detect_firewall)"

# --- Configuration du cron (prompt interactif idempotent) ---
configure_cron() {
  echo ""
  if ! ask_yes_no "Configurer le cron ipshield maintenant ?" oui; then
    log "Cron non configuré. Pour le faire plus tard, relancez ./setup-firewall.sh."
    return 0
  fi

  # Vérification crontab disponible
  if ! command -v crontab >/dev/null 2>&1; then
    err "commande 'crontab' non disponible — installation cron à faire manuellement."
    return 0
  fi

  # Lecture initiale du crontab (réutilisée pour défaut path + filtre).
  # `|| true` : crontab -l retourne 1 si pas de crontab user → ne pas faire échouer set -e.
  local current_cron
  current_cron="$(crontab -l 2>/dev/null || true)"

  # Chemin par défaut : crontab existante > même répertoire que ce script
  local script_dir script_path log_path mailto reboot_delay existing_path
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  script_path="$script_dir/update-blocklist.sh"
  existing_path="$(printf '%s\n' "$current_cron" | awk '
    /update-blocklist\.sh/ {
      for (i=1; i<=NF; i++) if ($i ~ /update-blocklist\.sh$/) { print $i; exit }
    }')"
  [ -n "$existing_path" ] && script_path="$existing_path"

  read -rp "Chemin de update-blocklist.sh [$script_path] : " ans
  [ -n "$ans" ] && script_path="$ans"
  if [ ! -x "$script_path" ]; then
    err "$script_path n'existe pas ou n'est pas exécutable. Cron non configuré."
    return 0
  fi

  log_path="/var/log/update-blocklist.log"
  read -rp "Fichier de log [$log_path] : " ans
  [ -n "$ans" ] && log_path="$ans"

  read -rp "Email pour notification d'erreurs (vide = pas de MAILTO) : " mailto
  if [ -n "$mailto" ] && ! [[ "$mailto" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    err "Adresse email invalide. Cron non configuré."
    return 0
  fi

  reboot_delay=60
  read -rp "Délai @reboot en secondes (laisse Docker démarrer) [$reboot_delay] : " ans
  if [ -n "$ans" ]; then
    if ! [[ "$ans" =~ ^[0-9]+$ ]]; then
      err "Délai invalide. Cron non configuré."
      return 0
    fi
    reboot_delay="$ans"
  fi

  # Filtre les lignes ipshield existantes (par basename) + MAILTO si on en pose un nouveau
  local filtered_cron new_lines new_cron
  local script_basename mailto_drop
  script_basename="$(basename "$script_path")"
  mailto_drop=0
  [ -n "$mailto" ] && mailto_drop=1

  filtered_cron="$(printf '%s\n' "$current_cron" | awk -v base="$script_basename" -v drop_mailto="$mailto_drop" '
    index($0, base) { next }
    drop_mailto && /^[[:space:]]*MAILTO=/ { next }
    { print }
  ')"
  filtered_cron="${filtered_cron%$'\n'}"

  # Nouvelles lignes
  new_lines=""
  [ -n "$mailto" ] && new_lines+="MAILTO=$mailto"$'\n'
  new_lines+="0 */12 * * * $script_path >> $log_path 2>&1"$'\n'
  if [ "$reboot_delay" -gt 0 ]; then
    new_lines+="@reboot sleep $reboot_delay && $script_path >> $log_path 2>&1"
  else
    new_lines+="@reboot $script_path >> $log_path 2>&1"
  fi

  # Concaténation
  if [ -n "$filtered_cron" ]; then
    new_cron="${filtered_cron}"$'\n'"${new_lines}"
  else
    new_cron="$new_lines"
  fi

  echo ""
  echo "=== Crontab actuel (root) ==="
  if [ -z "$current_cron" ]; then echo "(vide)"; else echo "$current_cron"; fi
  echo ""
  echo "=== Crontab après modification ==="
  echo "$new_cron"
  echo ""

  if [ "$current_cron" = "$new_cron" ]; then
    log "Aucun changement nécessaire."
    return 0
  fi

  if ! ask_yes_no "Appliquer ?" oui; then
    log "Cron non modifié."
    return 0
  fi

  printf '%s\n' "$new_cron" | crontab -
  log "Crontab mis à jour."
}

# --- Helper : installe ou met à jour un fichier de config ---
# Args: chemin, contenu attendu, description courte
# Retour : 0 si modifié, 1 si pas de changement
_install_config() {
  local path="$1"
  local content="$2"
  local desc="$3"

  if [ -f "$path" ]; then
    if [ "$(cat "$path")" = "$content" ]; then
      log "  $desc : déjà à jour ($path)"
      return 1
    fi
    log "  $desc : contenu différent ($path)"
    if ! ask_yes_no "  Écraser ?" non; then
      log "  Conservé tel quel."
      return 1
    fi
  fi
  printf '%s\n' "$content" > "$path"
  chmod 644 "$path"
  log "  $desc : installé ($path)"
  return 0
}

# --- Configuration des logs (rsyslog filter + logrotate) ---
configure_logs() {
  echo ""

  # Détection rsyslog AVANT le prompt pour adapter le wording
  local has_rsyslog=0
  if systemctl is-active --quiet rsyslog 2>/dev/null; then
    has_rsyslog=1
  fi

  if [ "$has_rsyslog" -eq 1 ]; then
    # rsyslog actif : un seul prompt
    if ! ask_yes_no "Configurer le filtre rsyslog + logrotate pour les logs ipshield ?" oui; then
      log "Logs non configurés. Pour le faire plus tard, relancez ./setup-firewall.sh."
      return 0
    fi
  else
    # rsyslog absent : informer puis proposer install
    log "rsyslog n'est pas actif sur ce système."
    log "  - Avec rsyslog  : fichier dédié /var/log/blocked-ips.log avec rotation."
    log "  - Sans rsyslog  : logs dans journald, via 'journalctl -k --grep BLOCKED:'"
    echo ""
    if ask_yes_no "Installer rsyslog et configurer le filtre + logrotate ?" oui; then
      log "Installation de rsyslog..."
      if [ "$PKG_MANAGER" = "apt" ]; then
        apt install -y rsyslog
      else
        dnf install -y rsyslog
      fi
      systemctl enable rsyslog 2>/dev/null || true
      systemctl start rsyslog 2>/dev/null || true
      if systemctl is-active --quiet rsyslog 2>/dev/null; then
        has_rsyslog=1
        log "rsyslog installé et actif."
      else
        err "rsyslog installé mais pas actif après start. Le filtre sera ignoré."
        log "Pour consulter les logs : journalctl -k --grep 'BLOCKED:'"
      fi
    else
      # rsyslog refusé : proposer logrotate seul (utile pour /var/log/update-blocklist.log)
      if ! ask_yes_no "Installer quand même logrotate seul (sans filtre rsyslog) ?" oui; then
        log "Logs non configurés. Tu peux consulter les paquets bloqués via :"
        log "  journalctl -k --grep 'BLOCKED:'"
        return 0
      fi
      log "Installation de logrotate uniquement (sans filtre rsyslog)."
    fi
  fi

  # Contenus attendus (alignés avec INSTALL.md)
  local rsyslog_content
  rsyslog_content='template(name="blockedFormat" type="string"
  string="%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute%:%timestamp:::date-second% %msg%\n")

:msg, contains, "BLOCKED: " /var/log/blocked-ips.log;blockedFormat
& stop'

  local logrotate_app_content
  logrotate_app_content='/var/log/update-blocklist.log {
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
}'

  local logrotate_blocked_content
  logrotate_blocked_content='/var/log/blocked-ips.log {
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}'

  local need_rsyslog_restart=0

  if [ "$has_rsyslog" -eq 1 ]; then
    if _install_config /etc/rsyslog.d/30-blocked-ips.conf "$rsyslog_content" "Filtre rsyslog"; then
      need_rsyslog_restart=1
    fi
  fi
  _install_config /etc/logrotate.d/update-blocklist "$logrotate_app_content" "Logrotate update-blocklist" || true
  _install_config /etc/logrotate.d/blocked-ips "$logrotate_blocked_content" "Logrotate blocked-ips" || true

  if [ "$need_rsyslog_restart" -eq 1 ]; then
    if systemctl restart rsyslog 2>/dev/null; then
      log "rsyslog redémarré."
    else
      err "Impossible de redémarrer rsyslog. Faites-le manuellement (systemctl restart rsyslog)."
    fi
  fi
}

# --- Migration : ancien bug de priorité de la chaîne nftables admin_access ---
# Avant ce fix, la chaîne 'inet admin_access input' était créée à priorité -10
# (avant le blocklist à priorité 0). Conséquence : sur nftables, les IPs
# blacklistées passaient quand même sur les ports SSH/SAFE_PORTS car le accept
# de admin_access s'évaluait avant le drop du blocklist.
# La priorité doit être positive pour que le blocklist drop s'applique d'abord.
if command -v nft >/dev/null 2>&1; then
  # Le pattern matche les deux formes : "priority -10" et "priority filter - 10"
  # (nftables canonicalise selon la version : raw int sur ancienne, named+offset sur récente).
  # Le ";" final ancre la valeur pour éviter de matcher -100, -101, etc.
  if nft list chain inet admin_access input 2>/dev/null | grep -qE "priority [^;]*-[[:space:]]*10[[:space:]]*;"; then
    log "Migration : chaîne 'inet admin_access input' détectée à priorité -10 (ancien bug)."
    existing_ports="$(nft list chain inet admin_access input 2>/dev/null \
      | awk '/tcp dport [0-9]+ accept/{for(i=1;i<=NF;i++) if ($i=="dport") print $(i+1)}' \
      | tr '\n' ' ' | sed 's/ *$//')"
    nft delete chain inet admin_access input
    nft add chain inet admin_access input '{ type filter hook input priority 10 ; policy accept ; }'
    if [ -n "$existing_ports" ]; then
      for p in $existing_ports; do
        nft add rule inet admin_access input tcp dport "$p" accept
      done
      log "  Règles restaurées : ports $existing_ports"
    fi
    log "  Priorité corrigée à 10 → le blocklist (priorité 0) s'évalue désormais AVANT."
  fi
fi

# --- Affichage résultat détection ---
echo ""
if [ "$DETECTED" = "aucun" ]; then
  log "Aucun firewall actif détecté sur ce système."
else
  log "Firewall actif détecté : $DETECTED"
fi

# --- Menu de sélection ---
echo ""
log "Choisissez le firewall à installer et activer :"
echo ""

options=("iptables" "nftables" "firewalld" "ufw")
descriptions=(
  "classique, compatible partout, simple"
  "successeur d'iptables, performant, syntaxe unifiée"
  "gestion par zones, rechargement dynamique, courant sur Fedora/RHEL"
  "simple d'utilisation, courant sur Ubuntu"
)

for i in "${!options[@]}"; do
  num=$((i + 1))
  marqueur=""
  if [ "${options[$i]}" = "$DETECTED" ]; then
    marqueur=" (actif)"
  fi
  echo "  $num) ${options[$i]} — ${descriptions[$i]}${marqueur}"
done

echo ""
read -rp "Votre choix [1-4] : " choix

case "$choix" in
  1) FIREWALL="iptables" ;;
  2) FIREWALL="nftables" ;;
  3) FIREWALL="firewalld" ;;
  4) FIREWALL="ufw" ;;
  *) err "choix invalide : $choix"; exit 1 ;;
esac

# --- Vérifier si déjà actif ---
if [ "$FIREWALL" = "$DETECTED" ]; then
  echo ""
  log "$FIREWALL est déjà actif sur ce système (pas de transition nécessaire)."
  configure_cron
  configure_logs
  exit 0
fi

echo ""
log "Installation et activation de : $FIREWALL"

# --- Détection des ports TCP en écoute (non-loopback) ---
# Permet de pré-remplir la liste des ports à autoriser avant activation
# du nouveau firewall, pour éviter de couper des services exposés.
detect_listening_ports() {
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  ss -tlnp 2>/dev/null | awk '
    NR == 1 { next }
    {
      addr_port = $4
      n = split(addr_port, parts, ":")
      port = parts[n]
      addr = substr(addr_port, 1, length(addr_port) - length(port) - 1)
      # Skip loopback (IPv4 127.0.0.0/8 et IPv6 [::1])
      if (addr == "[::1]" || addr ~ /^127\./) next
      if (port !~ /^[0-9]+$/) next
      proc = "?"
      for (i = 1; i <= NF; i++) {
        if (match($i, /\("[^"]+"/)) {
          # RLENGTH inclut ("...") → on retire 3 (les 2 premiers caractères et le " final)
          proc = substr($i, RSTART+2, RLENGTH-3)
          break
        }
      }
      print port, proc
    }
  ' | sort -n | awk '!seen[$1]++'
}

LISTENING="$(detect_listening_ports)"

echo ""
if [ -n "$LISTENING" ]; then
  log "Ports TCP actuellement en écoute (non-loopback) :"
  while IFS=' ' read -r port proc; do
    printf "  %-12s %s\n" "${port}/tcp" "$proc"
  done <<< "$LISTENING"
  echo ""
  DEFAULT_PORTS="$(echo "$LISTENING" | awk '{print $1}' | tr '\n' ' ' | sed 's/ *$//')"
  read -rp "Ports à ouvrir avant activation (défaut: $DEFAULT_PORTS, éditer la liste ou 'non' pour passer) : " SAFE_PORTS
  [ -z "$SAFE_PORTS" ] && SAFE_PORTS="$DEFAULT_PORTS"
else
  read -rp "Ports à ouvrir avant activation (séparés par espaces, vide pour passer) : " SAFE_PORTS
fi

# Gestion du refus explicite
if [ "$SAFE_PORTS" = "non" ] || [ "$SAFE_PORTS" = "no" ] || [ "$SAFE_PORTS" = "n" ]; then
  SAFE_PORTS=""
fi

# Validation : chaque port doit être 1-65535, puis dédup + tri
if [ -n "$SAFE_PORTS" ]; then
  for p in $SAFE_PORTS; do
    if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
      err "port invalide : $p"
      exit 1
    fi
  done
  SAFE_PORTS="$(echo "$SAFE_PORTS" | tr ' ' '\n' | sort -un | tr '\n' ' ' | sed 's/ *$//')"
fi

# --- Rollback automatique en cas d'échec ---
# Si le script échoue entre la désactivation de l'ancien firewall et
# l'activation du nouveau, le serveur resterait sans protection.
# Le trap réactive l'ancien firewall en cas d'erreur ou d'interruption.
rollback() {
  if [ "${ROLLBACK_ARMED:-0}" -eq 1 ]; then
    err "échec détecté — tentative de réactivation de $DETECTED..."
    case "$DETECTED" in
      firewalld)
        if systemctl start firewalld 2>/dev/null; then log "firewalld réactivé."
        else err "impossible de réactiver firewalld."; fi ;;
      ufw)
        if ufw --force enable 2>/dev/null; then log "ufw réactivé."
        else err "impossible de réactiver ufw."; fi ;;
      nftables)
        if systemctl start nftables 2>/dev/null; then log "nftables réactivé."
        else err "impossible de réactiver nftables."; fi ;;
      iptables)
        if [ -n "${IPTABLES_BACKUP:-}" ] && [ -f "$IPTABLES_BACKUP" ]; then
          if iptables-restore < "$IPTABLES_BACKUP" 2>/dev/null; then log "Règles iptables restaurées."
          else err "impossible de restaurer les règles iptables."; fi
        else
          err "aucune sauvegarde iptables disponible."
        fi
        if [ -n "${IPTABLES_BACKUP6:-}" ] && [ -f "$IPTABLES_BACKUP6" ]; then
          if ip6tables-restore < "$IPTABLES_BACKUP6" 2>/dev/null; then log "Règles ip6tables restaurées."
          else err "impossible de restaurer les règles ip6tables."; fi
        fi ;;
    esac
  fi
}
trap rollback EXIT INT TERM

# --- Désactiver l'ancien firewall ---
if [ "$DETECTED" != "aucun" ]; then
  ROLLBACK_ARMED=1
  log "Désactivation de l'ancien firewall : $DETECTED"
  case "$DETECTED" in
    firewalld)
      systemctl stop firewalld
      systemctl disable firewalld
      ;;
    ufw)
      ufw disable
      ;;
    nftables)
      systemctl stop nftables
      systemctl disable nftables
      ;;
    iptables)
      # Sauvegarde des règles avant flush (pour rollback en cas d'échec)
      IPTABLES_BACKUP="$(mktemp)"
      iptables-save > "$IPTABLES_BACKUP"
      for table in filter nat mangle raw; do
        iptables -t "$table" -F 2>/dev/null || true
        iptables -t "$table" -X 2>/dev/null || true
      done
      if command -v ip6tables >/dev/null 2>&1; then
        IPTABLES_BACKUP6="$(mktemp)"
        ip6tables-save > "$IPTABLES_BACKUP6"
        for table in filter nat mangle raw; do
          ip6tables -t "$table" -F 2>/dev/null || true
          ip6tables -t "$table" -X 2>/dev/null || true
        done
      fi
      log "Tables iptables/ip6tables vidées (flush + delete chains)."
      ;;
  esac
  log "$DETECTED désactivé."
fi

# --- Installer le nouveau firewall ---
log "Installation du paquet $FIREWALL..."
if [ "$PKG_MANAGER" = "apt" ]; then
  apt update -qq
fi
# `ipset` est installé en même temps que le firewall (dépendance d'update-blocklist.sh,
# souvent absente sur Debian minimal et causerait sinon "commande manquante: ipset").
case "$FIREWALL" in
  iptables)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y iptables ipset
    else
      dnf install -y iptables ipset
    fi
    ;;
  nftables)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y nftables ipset
    else
      dnf install -y nftables ipset
    fi
    ;;
  firewalld)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y firewalld ipset
    else
      dnf install -y firewalld ipset
    fi
    ;;
  ufw)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y ufw ipset
    else
      dnf install -y ufw ipset
    fi
    ;;
esac

# --- Activer et démarrer le nouveau firewall ---
log "Activation de $FIREWALL..."
case "$FIREWALL" in
  iptables)
    if [ -n "$SAFE_PORTS" ]; then
      for p in $SAFE_PORTS; do
        iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
        if command -v ip6tables >/dev/null 2>&1; then
          ip6tables -I INPUT -p tcp --dport "$p" -j ACCEPT
        fi
      done
      log "Ports ouverts (iptables IPv4 + IPv6) : $SAFE_PORTS"
    fi
    log "iptables est prêt (pas de service systemd à activer)."
    ;;
  nftables)
    systemctl enable nftables
    systemctl start nftables
    if [ -n "$SAFE_PORTS" ]; then
      nft add table inet admin_access 2>/dev/null || true
      # Priorité 10 (POSITIVE, après le blocklist à priorité 0) : si une IP est
      # blacklistée, elle est droppée par le blocklist AVANT d'arriver à ce ACCEPT.
      nft add chain inet admin_access input '{ type filter hook input priority 10 ; policy accept ; }' 2>/dev/null || true
      for p in $SAFE_PORTS; do
        nft add rule inet admin_access input tcp dport "$p" accept
      done
      log "Ports ouverts (nftables) : $SAFE_PORTS"
    fi
    ;;
  firewalld)
    systemctl enable firewalld
    systemctl start firewalld
    if [ -n "$SAFE_PORTS" ]; then
      for p in $SAFE_PORTS; do
        firewall-cmd --permanent --add-port="$p"/tcp
      done
      firewall-cmd --reload
      log "Ports ouverts (firewalld) : $SAFE_PORTS"
    fi
    ;;
  ufw)
    if [ -n "$SAFE_PORTS" ]; then
      for p in $SAFE_PORTS; do
        ufw allow "$p"/tcp
      done
      log "Ports ouverts (ufw) : $SAFE_PORTS"
    fi
    ufw --force enable
    ;;
esac

# --- Vérification post-activation : le firewall répond-il ? ---
# Si la vérification échoue, on quitte avec une erreur — le trap rollback
# ré-activera l'ancien firewall (ROLLBACK_ARMED toujours à 1).
log "Vérification de l'état du firewall..."
case "$FIREWALL" in
  iptables)
    if ! iptables -L -n >/dev/null 2>&1; then
      err "iptables ne répond pas après installation."
      exit 1
    fi
    ;;
  nftables)
    if ! systemctl is-active --quiet nftables; then
      err "nftables n'est pas actif après start (systemctl is-active a échoué)."
      exit 1
    fi
    ;;
  firewalld)
    state="$(firewall-cmd --state 2>/dev/null || echo "unknown")"
    if [ "$state" != "running" ]; then
      err "firewalld n'est pas en état 'running' (état: $state)."
      exit 1
    fi
    ;;
  ufw)
    if ! ufw status 2>/dev/null | grep -qi "^Status: active"; then
      err "ufw n'est pas actif après --force enable."
      exit 1
    fi
    ;;
esac
log "$FIREWALL est opérationnel."

# Désarmer le rollback — le nouveau firewall est actif
ROLLBACK_ARMED=0
rm -f "${IPTABLES_BACKUP:-}" "${IPTABLES_BACKUP6:-}" 2>/dev/null || true
trap - EXIT INT TERM

echo ""
log "$FIREWALL installé et activé avec succès."

configure_cron
configure_logs

echo ""
log "Lancez maintenant update-blocklist.sh pour la première mise à jour ; le cron prendra le relais ensuite."
