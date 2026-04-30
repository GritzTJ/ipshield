#!/bin/bash
# Tests dry-run de update-blocklist.sh avec differentes configurations.
#
# Objectif : detecter les conflits entre la validation, le filtre bogons,
# la whitelist et les autres validations avant deploiement. N'execute aucune
# modification ipset/firewall (dry-run only).
#
# Usage : sudo ./tests/test-conf-scenarios.sh
#
# Limites :
#  - Ne teste pas la logique iptables/firewall (necessiterait un namespace
#    network isole). Couvre uniquement la validation de conf, le parsing,
#    le filtre bogons et la gestion whitelist.
#  - Mocke les sources via file:// pour eviter de telecharger 10 listes par
#    scenario. Une fixture locale de 50 IPs publiques aleatoires alimente
#    la pipeline de validation.

set -euo pipefail
umask 077

# --- Verification root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Erreur : ces tests necessitent root (chown sur les fichiers de conf)." >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_DIR/update-blocklist.sh"

if [ ! -x "$SCRIPT" ]; then
  echo "Erreur : $SCRIPT introuvable ou non executable." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d -p /run "ipshield-tests.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

# Couleurs si stdout est un terminal
if [ -t 1 ]; then
  RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
  RED=""; GREEN=""; YELLOW=""; RESET=""
fi

PASS=0
FAIL=0

# --- Fixture : 50 IPs publiques pour passer MIN_ENTRIES=10 sans solliciter le reseau ---
FIXTURE="$TMP_DIR/fixture.txt"
{
  for i in $(seq 1 50); do
    printf "1.%d.%d.%d\n" $((i % 254 + 1)) $((i * 7 % 254 + 1)) $((i * 13 % 254 + 1))
  done
} > "$FIXTURE"

# --- Helpers ---

# Conf de base reutilisable. URLS pointe vers la fixture, MIN_ENTRIES bas pour
# que le seuil ne fasse pas echouer les tests.
BASE_CONF=$(cat <<EOF
URLS=("file://$FIXTURE")
SET_NAME="test-ipshield"
WHITELIST_SET_NAME="test-ipshield-allow"
WHITELIST_MIN_PREFIX=8
MIN_ENTRIES=10
BASE_HASHSIZE=1024
BASE_MAXELEM=1000
LOG_LIMIT="60/min"
LOG_BURST=100
WAN_INTERFACE=""
EOF
)

# Ecrit un fichier de conf, root:600, retourne son chemin
make_conf() {
  local content="$1"
  local conf
  conf="$(mktemp -p "$TMP_DIR" conf.XXXXXX)"
  printf '%s\n' "$content" > "$conf"
  chown root:root "$conf"
  chmod 600 "$conf"
  printf '%s' "$conf"
}

# Run dry-run, verifie exit code + pattern grep dans la sortie combinee.
# Args : conf_path, expected_exit, expected_pattern (vide = peu importe), name
run_test() {
  local conf="$1"
  local expected_exit="$2"
  local expected_pattern="$3"
  local name="$4"
  local output actual_exit
  set +e
  output="$("$SCRIPT" -n -c "$conf" 2>&1)"
  actual_exit=$?
  set -e
  if [ "$actual_exit" != "$expected_exit" ]; then
    printf "%sFAIL%s %s (exit attendu=%s, recu=%s)\n" "$RED" "$RESET" "$name" "$expected_exit" "$actual_exit"
    printf '%s\n' "$output" | tail -5 | sed 's/^/        /'
    FAIL=$((FAIL+1))
    return
  fi
  if [ -n "$expected_pattern" ] && ! printf '%s\n' "$output" | grep -qE "$expected_pattern"; then
    printf "%sFAIL%s %s (pattern '%s' absent)\n" "$RED" "$RESET" "$name" "$expected_pattern"
    printf '%s\n' "$output" | tail -5 | sed 's/^/        /'
    FAIL=$((FAIL+1))
    return
  fi
  printf "%sOK  %s %s\n" "$GREEN" "$RESET" "$name"
  PASS=$((PASS+1))
}

# --- Tests ---

echo "Tests de validation de conf (dry-run)"
echo "Repo : $REPO_DIR"
echo ""

# 1. Conf absente
run_test "/nonexistent/conf" 1 "absent" "Conf absente"

# 2. URLS vide
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|^URLS=.*|URLS=()|')")
run_test "$conf" 1 "URLS est vide" "URLS vide rejete"

# 3. Conf de base : succes
conf=$(make_conf "$BASE_CONF")
run_test "$conf" 0 "DRY-RUN" "Conf de base"

# 4. WHITELIST avec subnet RFC1918 (regression : mon filtre bogons)
conf=$(make_conf "$BASE_CONF
WHITELIST=(\"10.10.20.0/24\")")
run_test "$conf" 0 "Whitelist : 1 entrée" "WHITELIST RFC1918 (10.10.20.0/24)"

# 5. WHITELIST avec multicast bogon (allow_bogons=1 doit l'accepter)
conf=$(make_conf "$BASE_CONF
WHITELIST=(\"224.0.0.0/24\")")
run_test "$conf" 0 "Whitelist : 1 entrée" "WHITELIST bogon multicast"

# 6. WHITELIST avec /0 : prefixe trop large
conf=$(make_conf "$BASE_CONF
WHITELIST=(\"0.0.0.0/0\")")
run_test "$conf" 1 "trop large" "WHITELIST /0 rejete"

# 7. WHITELIST avec /4 sans desactivation du guard
conf=$(make_conf "$BASE_CONF
WHITELIST=(\"203.0.113.0/4\")")
run_test "$conf" 1 "trop large" "WHITELIST /4 rejete (guard=8)"

# 8. WHITELIST_MIN_PREFIX=0 desactive le guard, /4 doit passer
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|WHITELIST_MIN_PREFIX=.*|WHITELIST_MIN_PREFIX=0|')
WHITELIST=(\"203.0.113.0/4\")")
run_test "$conf" 0 "Whitelist : 1 entrée" "WHITELIST_MIN_PREFIX=0 + /4"

# 9. WHITELIST avec garbage
conf=$(make_conf "$BASE_CONF
WHITELIST=(\"notanip\")")
run_test "$conf" 1 "WHITELIST invalide" "WHITELIST garbage rejete"

# 10. LOG_LIMIT vide : pas de rate-limit
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|LOG_LIMIT=.*|LOG_LIMIT=""|')")
run_test "$conf" 0 "DRY-RUN" "LOG_LIMIT vide"

# 11. LOG_LIMIT en N/hour
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|LOG_LIMIT=.*|LOG_LIMIT="600/hour"|')")
run_test "$conf" 0 "DRY-RUN" "LOG_LIMIT 600/hour"

# 12. LOG_LIMIT format invalide
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|LOG_LIMIT=.*|LOG_LIMIT="abc"|')")
run_test "$conf" 1 "LOG_LIMIT invalide" "LOG_LIMIT format invalide"

# 13. LOG_BURST non numerique
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|LOG_BURST=.*|LOG_BURST="abc"|')")
run_test "$conf" 1 "LOG_BURST invalide" "LOG_BURST non numerique"

# 14. MIN_ENTRIES=0 (regex demande [1-9])
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|MIN_ENTRIES=.*|MIN_ENTRIES=0|')")
run_test "$conf" 1 "MIN_ENTRIES invalide" "MIN_ENTRIES=0 rejete"

# 15. SET_NAME avec espace : protection injection
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|SET_NAME=.*|SET_NAME="bad name"|')")
run_test "$conf" 1 "SET_NAME invalide" "SET_NAME avec espace"

# 16. WHITELIST_SET_NAME identique a SET_NAME
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|WHITELIST_SET_NAME=.*|WHITELIST_SET_NAME="test-ipshield"|')")
run_test "$conf" 1 "identique" "WHITELIST_SET_NAME == SET_NAME"

# 17. WAN_INTERFACE explicite
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|WAN_INTERFACE=.*|WAN_INTERFACE="eth0"|')")
run_test "$conf" 0 "DRY-RUN" "WAN_INTERFACE explicite"

# 18. WAN_INTERFACE avec caractere invalide
conf=$(make_conf "$(echo "$BASE_CONF" | sed 's|WAN_INTERFACE=.*|WAN_INTERFACE="bad iface"|')")
run_test "$conf" 1 "WAN_INTERFACE invalide" "WAN_INTERFACE avec espace"

# 19. Conf perms group/world-writable
conf=$(make_conf "$BASE_CONF")
chmod 666 "$conf"
run_test "$conf" 1 "writable" "Perms 666 rejetees"

# 20. Conf owner non-root (skip si nobody n'existe pas)
if id nobody >/dev/null 2>&1; then
  conf=$(make_conf "$BASE_CONF")
  chown nobody:nogroup "$conf" 2>/dev/null || chown nobody:nobody "$conf"
  run_test "$conf" 1 "n'appartient pas" "Owner non-root rejete"
else
  printf "%sSKIP%s Owner non-root (nobody absent)\n" "$YELLOW" "$RESET"
fi

# --- Recap ---
echo ""
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
  printf "%sOK %d / %d%s\n" "$GREEN" "$PASS" "$TOTAL" "$RESET"
  exit 0
else
  printf "%sFAIL %d%s / OK %d / %d total\n" "$RED" "$FAIL" "$RESET" "$PASS" "$TOTAL"
  exit 1
fi
