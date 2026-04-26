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
  # Blacklist LOG (avec rate-limit)
  while iptables -C "$chain" -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4 2>/dev/null; do
    iptables -D "$chain" -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
  done
}

# --- Suppression firewalld --direct ---
remove_firewalld_rules() {
  local chain="$1"
  local changed=0
  while firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 0 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; do
    firewall-cmd --permanent --direct --remove-rule ipv4 filter "$chain" 0 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
    changed=1
  done
  while firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 1 -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do
    firewall-cmd --permanent --direct --remove-rule ipv4 filter "$chain" 1 -m set --match-set "$SET_NAME" src -j DROP
    changed=1
  done
  while firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 0 -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4 2>/dev/null; do
    firewall-cmd --permanent --direct --remove-rule ipv4 filter "$chain" 0 -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
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
        echo "$rules_input" | sed 's/^/    /'
      else
        echo "  INPUT : aucune règle ipshield présente."
      fi
      if [ "$DOCKER_PRESENT" -eq 1 ]; then
        rules_docker="$(show_iptables_rules DOCKER-USER)"
        if [ -n "$rules_docker" ]; then
          echo "  DOCKER-USER :"
          echo "$rules_docker" | sed 's/^/    /'
        else
          echo "  DOCKER-USER : aucune règle ipshield présente."
        fi
      fi
    fi
    if [ "$FW" = "ufw" ] && [ -f /etc/ufw/before.rules ]; then
      ufw_rules="$(grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" /etc/ufw/before.rules || true)"
      if [ -n "$ufw_rules" ]; then
        echo "  /etc/ufw/before.rules :"
        echo "$ufw_rules" | sed 's/^/    /'
      else
        echo "  /etc/ufw/before.rules : aucune règle ipshield présente."
      fi
    fi
    ;;
  firewalld)
    fw_rules="$(firewall-cmd --permanent --direct --get-all-rules 2>/dev/null | grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true)"
    if [ -n "$fw_rules" ]; then
      echo "$fw_rules" | sed 's/^/    /'
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
log "${PREFIX}--- Cron (info uniquement, jamais modifié) ---"
cron_files="$(grep -lE "update-blocklist\.sh" /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null || true)"
if [ -n "$cron_files" ]; then
  echo "  Lignes cron détectées (à retirer manuellement) :"
  echo "$cron_files" | while read -r f; do
    echo "    --- $f ---"
    grep -nE "update-blocklist\.sh" "$f" | sed 's/^/      /'
  done
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
read -rp "Confirmer la désinstallation ? [oui/non] : " confirm
case "${confirm,,}" in
  oui|yes|y|o) ;;
  *) log "Annulation."; exit 0 ;;
esac

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
    remove_firewalld_rules INPUT && need_reload=1 || true
    if [ "$DOCKER_PRESENT" -eq 1 ]; then
      remove_firewalld_rules DOCKER-USER && need_reload=1 || true
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

echo ""
log "Désinstallation terminée."
log "Pensez à retirer manuellement les lignes cron référencées plus haut (le cas échéant)."
