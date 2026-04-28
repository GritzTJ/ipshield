#!/bin/bash
set -euo pipefail
umask 077

# --- Usage / aide ---
usage() {
  cat <<'EOF'
Usage: uninstall.sh [OPTIONS]

Retire les règles de blocage ipshield et détruit les ipsets associés.
Par défaut, mode dry-run (affiche ce qui serait fait, sans rien modifier).

Options:
  --apply             Applique réellement la désinstallation (sinon dry-run).
  -c, --config FILE   Chemin du fichier de configuration (défaut: /etc/update-blocklist.conf).
  -h, --help          Affiche cette aide.

Ce script :
  - retire les règles ipshield (LOG + DROP blocklist, ACCEPT whitelist) sur INPUT
    et DOCKER-USER (si Docker présent) ;
  - détruit les ipsets $SET_NAME et $WHITELIST_SET_NAME ;
  - restaure /etc/ufw/before.rules.bak si présent (ufw) ;
  - informe (sans toucher) des lignes cron référençant update-blocklist.sh.

Il NE désinstalle PAS le firewall ni les paquets (ipset, iptables, etc.).
EOF
  exit 0
}

# --- Vérification root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Erreur : ce script doit être exécuté en tant que root." >&2
  exit 1
fi

# --- Parsing CLI ---
APPLY=0
CONF_FILE="/etc/update-blocklist.conf"

while [ $# -gt 0 ]; do
  case "$1" in
    --apply)         APPLY=1; shift ;;
    -c|--config)
      [ $# -ge 2 ] || { echo "Erreur : --config nécessite un argument." >&2; exit 1; }
      CONF_FILE="$2"; shift 2 ;;
    -h|--help)       usage ;;
    *)               echo "Option inconnue : $1" >&2; usage ;;
  esac
done

# --- Valeurs par défaut ---
SET_NAME="blacklist"

# --- Source config (mêmes vérifs que update-blocklist.sh) ---
if [ -f "$CONF_FILE" ]; then
  conf_owner="$(stat -c '%u' "$CONF_FILE")"
  conf_perms="$(stat -c '%a' "$CONF_FILE")"
  if [ "$conf_owner" != "0" ]; then
    echo "Erreur : $CONF_FILE n'appartient pas à root (uid=$conf_owner)." >&2
    exit 1
  fi
  if [[ "$conf_perms" =~ [2367][0-9]$ ]] || [[ "$conf_perms" =~ [0-9][2367]$ ]]; then
    echo "Erreur : $CONF_FILE est group/world-writable (perms=$conf_perms)." >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  . "$CONF_FILE"
fi

# Validation SET_NAME
if [[ ! "$SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Erreur : SET_NAME invalide ('$SET_NAME')." >&2
  exit 1
fi
: "${WHITELIST_SET_NAME:=${SET_NAME}-allow}"
if [[ ! "$WHITELIST_SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Erreur : WHITELIST_SET_NAME invalide ('$WHITELIST_SET_NAME')." >&2
  exit 1
fi

# --- Fonctions ---
log() { echo "$*"; }
err() { echo "$*" >&2; }

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

if [ "$APPLY" -eq 1 ]; then
  PREFIX=""
else
  PREFIX="[DRY-RUN] "
fi

# --- Détection firewall ---
detect_firewall() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"; return
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "active"; then
    echo "ufw"; return
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables 2>/dev/null; then
    echo "nftables"; return
  fi
  if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
    echo "nftables"; return
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -L -n 2>/dev/null | grep -q "^Chain"; then
    if ! command -v ufw >/dev/null 2>&1 || ! iptables -L -n 2>/dev/null | grep -q "^Chain ufw-"; then
      echo "iptables"; return
    fi
  fi
  echo "aucun"
}

detect_docker() {
  iptables -L DOCKER-USER -n >/dev/null 2>&1
}

# --- Comptage des règles ipshield présentes (iptables) ---
count_iptables_rules() {
  local chain="$1"
  local total=0
  if iptables -L "$chain" -n 2>/dev/null | grep -q .; then
    total=$(( total + $(iptables -S "$chain" 2>/dev/null | grep -c -E -- "--match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true) ))
  fi
  echo "$total"
}

# --- Suppression iptables (idempotent, retire toutes les occurrences) ---
remove_iptables_rules() {
  local chain="$1"
  # Whitelist ACCEPT
  while iptables -C "$chain" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; do
    iptables -D "$chain" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
  done
  # Blacklist DROP
  while iptables -C "$chain" -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do
    iptables -D "$chain" -m set --match-set "$SET_NAME" src -j DROP
  done
  # Blacklist LOG : suppression générique (n'importe quelles valeurs limit)
  local rule
  while true; do
    rule="$(iptables -S "$chain" 2>/dev/null | grep -E "^-A $chain .*--match-set $SET_NAME src.*-j LOG --log-prefix \"BLOCKED: \"" | head -1 || true)"
    [ -z "$rule" ] && break
    rule="${rule/#-A /-D }"
    eval "iptables $rule"
  done
}

# --- Suppression firewalld --direct (générique : matche n'importe quelles valeurs limit) ---
remove_firewalld_rules() {
  local chain="$1"
  local changed=0
  local line
  while true; do
    line="$(firewall-cmd --permanent --direct --get-all-rules 2>/dev/null \
      | grep -E "^ipv4 filter $chain .*--match-set ($SET_NAME|$WHITELIST_SET_NAME) src" \
      | head -1 || true)"
    [ -z "$line" ] && break
    eval "firewall-cmd --permanent --direct --remove-rule $line"
    changed=1
  done
  [ "$changed" -eq 1 ] && return 0 || return 1
}

# --- Affichage des règles ipshield présentes ---
show_iptables_rules() {
  local chain="$1"
  iptables -S "$chain" 2>/dev/null | grep -E -- "--match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true
}

# --- Détection firewall et plan d'action ---
FW="$(detect_firewall)"
log "Firewall détecté : $FW"

DOCKER_PRESENT=0
if command -v iptables >/dev/null 2>&1 && detect_docker; then
  DOCKER_PRESENT=1
  log "Docker détecté : la chaîne DOCKER-USER sera également nettoyée."
fi

echo ""
log "${PREFIX}--- Règles ipshield à retirer ---"
case "$FW" in
  iptables|nftables|ufw)
    if command -v iptables >/dev/null 2>&1; then
      rules_input="$(show_iptables_rules INPUT)"
      if [ -n "$rules_input" ]; then
        echo "  INPUT :"
        echo "$rules_input" | awk '{print "    " $0}'
      else
        echo "  INPUT : aucune règle ipshield présente."
      fi
      if [ "$DOCKER_PRESENT" -eq 1 ]; then
        rules_docker="$(show_iptables_rules DOCKER-USER)"
        if [ -n "$rules_docker" ]; then
          echo "  DOCKER-USER :"
          echo "$rules_docker" | awk '{print "    " $0}'
        else
          echo "  DOCKER-USER : aucune règle ipshield présente."
        fi
      fi
    fi
    if [ "$FW" = "ufw" ] && [ -f /etc/ufw/before.rules ]; then
      ufw_rules="$(grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" /etc/ufw/before.rules || true)"
      if [ -n "$ufw_rules" ]; then
        echo "  /etc/ufw/before.rules :"
        echo "$ufw_rules" | awk '{print "    " $0}'
      else
        echo "  /etc/ufw/before.rules : aucune règle ipshield présente."
      fi
    fi
    ;;
  firewalld)
    fw_rules="$(firewall-cmd --permanent --direct --get-all-rules 2>/dev/null | grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true)"
    if [ -n "$fw_rules" ]; then
      echo "$fw_rules" | awk '{print "    " $0}'
    else
      echo "  Aucune règle ipshield (firewalld --direct) présente."
    fi
    ;;
  aucun)
    echo "  (aucun firewall actif)"
    ;;
esac

echo ""
log "${PREFIX}--- ipsets à détruire ---"
for set in "$SET_NAME" "$WHITELIST_SET_NAME"; do
  if ipset list -n 2>/dev/null | awk -v s="$set" '$0==s{found=1} END{exit(found?0:1)}'; then
    count="$(ipset list -t "$set" 2>/dev/null | awk -F': ' '/Number of entries/{print $2; exit}')"
    echo "  $set ($count entrée(s))"
  else
    echo "  $set : absent"
  fi
done

echo ""
log "${PREFIX}--- Configs rsyslog + logrotate ---"
log_configs_list=(/etc/rsyslog.d/30-blocked-ips.conf /etc/logrotate.d/update-blocklist /etc/logrotate.d/blocked-ips)
log_configs_found=0
for f in "${log_configs_list[@]}"; do
  if [ -f "$f" ]; then
    echo "  $f"
    log_configs_found=1
  fi
done
if [ "$log_configs_found" -eq 0 ]; then
  echo "  (aucune)"
elif [ "$APPLY" -eq 1 ]; then
  echo "  → un prompt séparé proposera de les retirer."
fi

echo ""
log "${PREFIX}--- Cron ---"
cron_files="$(grep -lE "update-blocklist\.sh" /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null || true)"
if [ -n "$cron_files" ]; then
  echo "  Lignes cron détectées :"
  echo "$cron_files" | while read -r f; do
    echo "    --- $f ---"
    grep -nE "update-blocklist\.sh" "$f" | awk '{print "      " $0}'
  done
  if [ "$APPLY" -eq 1 ]; then
    echo "  → le crontab de root sera proposé à la suppression (prompt séparé)."
    echo "  → /etc/crontab et /etc/cron.d/* ne sont jamais modifiés (à faire à la main)."
  fi
else
  echo "  Aucune ligne cron détectée."
fi

echo ""

# --- Mode dry-run : sortir ici ---
if [ "$APPLY" -eq 0 ]; then
  log "[DRY-RUN] Pour appliquer réellement : relancez avec --apply"
  exit 0
fi

# --- Confirmation ---
if ! ask_yes_no "Confirmer la désinstallation ?" non; then
  log "Annulation."
  exit 0
fi

# --- Application ---
log "Suppression des règles..."
case "$FW" in
  iptables|nftables)
    remove_iptables_rules INPUT
    if [ "$DOCKER_PRESENT" -eq 1 ]; then
      remove_iptables_rules DOCKER-USER
    fi
    ;;
  firewalld)
    need_reload=0
    if remove_firewalld_rules INPUT; then need_reload=1; fi
    if [ "$DOCKER_PRESENT" -eq 1 ] && remove_firewalld_rules DOCKER-USER; then
      need_reload=1
    fi
    [ "$need_reload" -eq 1 ] && firewall-cmd --reload
    ;;
  ufw)
    if [ -f /etc/ufw/before.rules ] && grep -qE "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" /etc/ufw/before.rules; then
      if [ -f /etc/ufw/before.rules.bak ]; then
        log "Restauration de /etc/ufw/before.rules.bak."
        cp /etc/ufw/before.rules.bak /etc/ufw/before.rules
      else
        log "Pas de before.rules.bak : suppression ligne par ligne."
        sed -i "/match-set $SET_NAME src/d; /match-set $WHITELIST_SET_NAME src/d" /etc/ufw/before.rules
      fi
      ufw reload
    fi
    if [ "$DOCKER_PRESENT" -eq 1 ]; then
      remove_iptables_rules DOCKER-USER
    fi
    ;;
esac

log "Destruction des ipsets..."
for set in "$SET_NAME" "$WHITELIST_SET_NAME"; do
  if ipset list -n 2>/dev/null | awk -v s="$set" '$0==s{found=1} END{exit(found?0:1)}'; then
    if ipset destroy "$set" 2>/dev/null; then
      log "  $set détruit."
    else
      err "  $set : impossible à détruire (encore référencé ?)."
    fi
  fi
done

# --- Retrait optionnel des lignes cron ---
if command -v crontab >/dev/null 2>&1; then
  current_cron="$(crontab -l 2>/dev/null || true)"
  ipshield_lines="$(printf '%s\n' "$current_cron" | grep -E "update-blocklist\.sh" || true)"
  if [ -n "$ipshield_lines" ]; then
    echo ""
    log "Lignes cron ipshield trouvées dans le crontab de root :"
    echo "$ipshield_lines" | awk '{print "    " $0}'
    if ask_yes_no "Les retirer ?" oui; then
      new_cron="$(printf '%s\n' "$current_cron" | grep -vE "update-blocklist\.sh" || true)"
      new_cron="${new_cron%$'\n'}"
      if [ -z "$new_cron" ]; then
        crontab -r 2>/dev/null || true
        log "Crontab de root vidé."
      else
        printf '%s\n' "$new_cron" | crontab -
        log "Crontab de root mis à jour (lignes ipshield retirées)."
      fi
    else
      log "Lignes cron conservées."
    fi
  fi
fi

# Lignes cron dans /etc/crontab et /etc/cron.d/* (info uniquement, jamais modifié)
other_cron="$(grep -lE "update-blocklist\.sh" /etc/crontab /etc/cron.d/* 2>/dev/null || true)"
if [ -n "$other_cron" ]; then
  echo ""
  log "Lignes cron ipshield aussi présentes dans (à retirer manuellement) :"
  echo "$other_cron" | awk '{print "    " $0}'
fi

# --- Retrait optionnel des configs rsyslog + logrotate ---
log_configs=(/etc/rsyslog.d/30-blocked-ips.conf /etc/logrotate.d/update-blocklist /etc/logrotate.d/blocked-ips)
present_log_configs=()
for f in "${log_configs[@]}"; do
  [ -f "$f" ] && present_log_configs+=("$f")
done
if [ "${#present_log_configs[@]}" -gt 0 ]; then
  echo ""
  log "Configs rsyslog + logrotate ipshield trouvées :"
  for f in "${present_log_configs[@]}"; do
    echo "    $f"
  done
  if ask_yes_no "Les retirer ?" oui; then
    restart_rsyslog=0
    for f in "${present_log_configs[@]}"; do
      if rm -f "$f" 2>/dev/null; then
        log "  $f supprimé."
        [[ "$f" == /etc/rsyslog.d/* ]] && restart_rsyslog=1
      else
        err "  Impossible de retirer $f."
      fi
    done
    if [ "$restart_rsyslog" -eq 1 ]; then
      if systemctl restart rsyslog 2>/dev/null; then
        log "rsyslog redémarré."
      else
        err "Impossible de redémarrer rsyslog."
      fi
    fi
    log "Note : les fichiers de log /var/log/update-blocklist.log et /var/log/blocked-ips.log sont conservés."
  else
    log "Configs conservées."
  fi
fi

echo ""
log "Désinstallation terminée."
