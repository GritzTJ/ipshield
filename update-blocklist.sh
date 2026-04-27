#!/bin/bash
set -euo pipefail
umask 077

# --- Usage / aide ---
usage() {
  cat <<'EOF'
Usage: update-blocklist.sh [OPTIONS]

Met à jour un ipset de blocage à partir de listes publiques,
puis détecte le firewall actif et applique les règles de blocage.

Options:
  -n, --dry-run       Mode simulation (aucune modification ipset/firewall)
  -v, --verbose       Affichage détaillé (stats par source, détails du diff)
  -c, --config FILE   Chemin du fichier de configuration
  -h, --help          Affiche cette aide

Ordre de résolution : défauts → config → CLI.
EOF
  exit 0
}

# --- Vérification root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Erreur : ce script doit être exécuté en tant que root." >&2
  exit 1
fi

# --- Parsing CLI ---
CLI_DRY_RUN=""
CLI_VERBOSE=""
CONF_FILE="/etc/update-blocklist.conf"

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run)  CLI_DRY_RUN=1; shift ;;
    -v|--verbose)  CLI_VERBOSE=1; shift ;;
    -c|--config)
      [ $# -ge 2 ] || { echo "Erreur : --config nécessite un argument." >&2; exit 1; }
      CONF_FILE="$2"; shift 2 ;;
    -h|--help)     usage ;;
    *)             echo "Option inconnue : $1" >&2; usage ;;
  esac
done

# --- Valeurs par défaut ---
URLS=(
  "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
  "https://www.spamhaus.org/drop/drop.txt"
  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
  "https://cinsscore.com/list/ci-badguys.txt"
  "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-365d.ipv4"
)
SET_NAME="blacklist"
WHITELIST=()
DRY_RUN=0
VERBOSE=0
MIN_ENTRIES=1000
BASE_HASHSIZE="16384"
BASE_MAXELEM="300000"
LOG_LIMIT="60/min"
LOG_BURST=100

# --- Source config file (si existe) ---
if [ -f "$CONF_FILE" ]; then
  conf_owner="$(stat -c '%u' "$CONF_FILE")"
  conf_perms="$(stat -c '%a' "$CONF_FILE")"
  if [ "$conf_owner" != "0" ]; then
    echo "Erreur : $CONF_FILE n'appartient pas à root (uid=$conf_owner). Risque de sécurité." >&2
    exit 1
  fi
  if [[ "$conf_perms" =~ [2367][0-9]$ ]] || [[ "$conf_perms" =~ [0-9][2367]$ ]]; then
    echo "Erreur : $CONF_FILE est group/world-writable (perms=$conf_perms). Risque de sécurité." >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  . "$CONF_FILE"
fi

# --- Appliquer overrides CLI (priment sur config) ---
[ -n "$CLI_DRY_RUN" ] && DRY_RUN=1
[ -n "$CLI_VERBOSE" ] && VERBOSE=1

# --- Validation SET_NAME ---
if [[ ! "$SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Erreur : SET_NAME invalide ('$SET_NAME'). Seuls [a-zA-Z0-9_-] sont autorisés." >&2
  exit 1
fi

# --- Whitelist set name (dérivé de SET_NAME si non défini) ---
: "${WHITELIST_SET_NAME:=${SET_NAME}-allow}"
if [[ ! "$WHITELIST_SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Erreur : WHITELIST_SET_NAME invalide ('$WHITELIST_SET_NAME'). Seuls [a-zA-Z0-9_-] sont autorisés." >&2
  exit 1
fi
if [ "${#WHITELIST_SET_NAME}" -gt 31 ]; then
  echo "Erreur : WHITELIST_SET_NAME trop long (${#WHITELIST_SET_NAME} > 31)." >&2
  exit 1
fi
if [ "$WHITELIST_SET_NAME" = "$SET_NAME" ]; then
  echo "Erreur : WHITELIST_SET_NAME ne doit pas être identique à SET_NAME." >&2
  exit 1
fi

# --- Validation LOG_LIMIT / LOG_BURST ---
# LOG_LIMIT vide = loggue tout (pas de rate-limit)
if [ -n "$LOG_LIMIT" ]; then
  if ! [[ "$LOG_LIMIT" =~ ^[0-9]+/(sec|second|min|minute|hour|day)$ ]]; then
    echo "Erreur : LOG_LIMIT invalide ('$LOG_LIMIT'). Format attendu : N/(sec|min|hour|day) ou vide." >&2
    exit 1
  fi
  if ! [[ "$LOG_BURST" =~ ^[1-9][0-9]*$ ]]; then
    echo "Erreur : LOG_BURST invalide ('$LOG_BURST'). Entier positif attendu." >&2
    exit 1
  fi
fi

# --- Variables dérivées ---
IPSET_TYPE="hash:net"
IPSET_FAMILY="inet"
LOCK_DIR="/run/lock"
LOCK_FILE="${LOCK_DIR}/${SET_NAME}.lock"
TMP_DIR="$(mktemp -d -p /run "${SET_NAME}.XXXXXX")"
UNIQ_FILE="${TMP_DIR}/uniq"
TMP_FILE="${TMP_DIR}/restore"
TEMP_SET="${SET_NAME}-tmp-$$"
WL_TEMP_SET="${WHITELIST_SET_NAME}-tmp-$$"
WL_FILE="${TMP_DIR}/whitelist"
WL_TMP_FILE="${TMP_DIR}/wl_restore"
CURL_OPTS=( -fsSL --compressed --connect-timeout 10 --max-time 30 --max-filesize 52428800 --retry 3 --retry-delay 2 --retry-all-errors )

if [ "${#TEMP_SET}" -gt 31 ]; then
  echo "Erreur : nom de set temporaire trop long (${#TEMP_SET} > 31)" >&2
  exit 1
fi
if [ "${#WL_TEMP_SET}" -gt 31 ]; then
  echo "Erreur : nom de set whitelist temporaire trop long (${#WL_TEMP_SET} > 31)" >&2
  exit 1
fi

# --- Fonctions ---
log() { echo "$*"; logger -t "update-blocklist" "$*" 2>/dev/null || true; }
err() { echo "$*" >&2; logger -t "update-blocklist" -p user.err "$*" 2>/dev/null || true; }
fmt_num() { printf "%d" "$1" | sed ':a;s/\([0-9]\)\([0-9]\{3\}\)\($\| \)/\1 \2\3/;ta'; }

cleanup() {
  rm -rf -- "$TMP_DIR" 2>/dev/null || true
  ipset destroy "$TEMP_SET" 2>/dev/null || true
  ipset destroy "$WL_TEMP_SET" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Erreur: commande manquante: $1"; exit 1; }; }

# --- Détection du firewall actif ---
detect_firewall() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
    return
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "active"; then
    echo "ufw"
    return
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables 2>/dev/null; then
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

# --- Détection de Docker (chaîne DOCKER-USER) ---
detect_docker() {
  iptables -L DOCKER-USER -n >/dev/null 2>&1
}

# --- Construit le tableau d'arguments iptables pour la règle LOG (selon LOG_LIMIT) ---
_log_rule_args() {
  local args=( -m set --match-set "$SET_NAME" src )
  if [ -n "$LOG_LIMIT" ]; then
    args+=( -m limit --limit "$LOG_LIMIT" --limit-burst "$LOG_BURST" )
  fi
  args+=( -j LOG --log-prefix "BLOCKED: " --log-level 4 )
  printf '%s\n' "${args[@]}"
}

# --- Retire toutes les règles LOG ipshield existantes sur une chaîne (n'importe quelles valeurs de limit) ---
_remove_old_log_rules() {
  local chain="$1"
  local rule
  while true; do
    rule="$(iptables -S "$chain" 2>/dev/null | grep -E "^-A $chain .*--match-set $SET_NAME src.*-j LOG --log-prefix \"BLOCKED: \"" | head -1 || true)"
    [ -z "$rule" ] && break
    rule="${rule/#-A /-D }"
    eval "iptables $rule"
  done
}

# --- Insertion/maj idempotente des règles LOG + DROP sur une chaîne iptables ---
# Détecte le drift sur les paramètres LOG (LOG_LIMIT/LOG_BURST) et resynchronise.
_apply_iptables_rules() {
  local chain="$1"
  local actioned=0
  local log_args
  mapfile -t log_args < <(_log_rule_args)

  # LOG : vérifier si la règle exacte (avec les valeurs actuelles) existe
  if ! iptables -C "$chain" "${log_args[@]}" 2>/dev/null; then
    _remove_old_log_rules "$chain"
    iptables -I "$chain" 1 "${log_args[@]}"
    actioned=1
  fi

  # DROP : vérifier et insérer après LOG (pos 2)
  if ! iptables -C "$chain" -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
    iptables -I "$chain" 2 -m set --match-set "$SET_NAME" src -j DROP
    actioned=1
  fi

  [ "$actioned" -eq 1 ] && return 0 || return 1
}

# --- Insertion idempotente de la règle ACCEPT whitelist en position 1 ---
# Vérifie qu'elle est bien la première règle ; sinon retire et ré-insère.
_apply_whitelist_iptables() {
  local chain="$1"
  local first_rule
  first_rule="$(iptables -S "$chain" 2>/dev/null | grep -E "^-A" | head -1)"
  if echo "$first_rule" | grep -qE -- "--match-set $WHITELIST_SET_NAME src .*-j ACCEPT$"; then
    return
  fi
  while iptables -C "$chain" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; do
    iptables -D "$chain" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
  done
  iptables -I "$chain" 1 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
}

# --- Suppression des règles ACCEPT whitelist (toutes occurrences) ---
_cleanup_whitelist_iptables() {
  local chain="$1"
  while iptables -C "$chain" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; do
    iptables -D "$chain" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
  done
}

# --- Application/cleanup whitelist sur une chaîne iptables ---
_whitelist_or_cleanup_iptables() {
  local chain="$1"
  if [ "${#WHITELIST[@]}" -gt 0 ]; then
    _apply_whitelist_iptables "$chain"
  else
    _cleanup_whitelist_iptables "$chain"
  fi
}

# --- Application/cleanup whitelist firewalld (return 0 si action effectuée) ---
_whitelist_or_cleanup_firewalld() {
  local chain="$1"
  if [ "${#WHITELIST[@]}" -gt 0 ]; then
    if ! firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 0 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; then
      firewall-cmd --permanent --direct --add-rule ipv4 filter "$chain" 0 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
      return 0
    fi
  else
    if firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 0 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; then
      firewall-cmd --permanent --direct --remove-rule ipv4 filter "$chain" 0 -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
      return 0
    fi
  fi
  return 1
}

# --- Application des règles firewall ---
apply_firewall_rules() {
  local fw="$1"

  local docker_protected=0

  case "$fw" in
    iptables)
      _apply_iptables_rules INPUT && log "Règles iptables ajoutées (LOG + DROP)."
      _whitelist_or_cleanup_iptables INPUT
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER && log "Règles iptables DOCKER-USER ajoutées (LOG + DROP)."
        _whitelist_or_cleanup_iptables DOCKER-USER
        docker_protected=1
      fi
      ;;

    nftables)
      # nftables ne peut pas référencer les sets ipset nativement (@set).
      # On utilise iptables (iptables-nft) qui traduit les commandes en règles nft
      # tout en supportant le match ipset via le module xt_set du noyau.
      need_cmd iptables
      _apply_iptables_rules INPUT && log "Règles nftables ajoutées via iptables-nft (LOG + DROP)."
      _whitelist_or_cleanup_iptables INPUT
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER && log "Règles nftables DOCKER-USER ajoutées via iptables-nft (LOG + DROP)."
        _whitelist_or_cleanup_iptables DOCKER-USER
        docker_protected=1
      fi
      ;;

    firewalld)
      local need_reload=0
      # Construction des args LOG selon LOG_LIMIT
      local fw_log_args=( -m set --match-set "$SET_NAME" src )
      if [ -n "$LOG_LIMIT" ]; then
        fw_log_args+=( -m limit --limit "$LOG_LIMIT" --limit-burst "$LOG_BURST" )
      fi
      fw_log_args+=( -j LOG --log-prefix "BLOCKED: " --log-level 4 )

      if ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 1 -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 "${fw_log_args[@]}"
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
        need_reload=1
        log "Règles firewalld ajoutées (LOG + DROP)."
      fi
      _whitelist_or_cleanup_firewalld INPUT && need_reload=1
      if detect_docker; then
        if ! firewall-cmd --permanent --direct --query-rule ipv4 filter DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
          firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 0 "${fw_log_args[@]}"
          firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP
          need_reload=1
          log "Règles firewalld DOCKER-USER ajoutées (LOG + DROP)."
        fi
        _whitelist_or_cleanup_firewalld DOCKER-USER && need_reload=1
        docker_protected=1
      fi
      [ "$need_reload" -eq 1 ] && firewall-cmd --reload
      ;;

    ufw)
      if ! grep -q "match-set $SET_NAME src" /etc/ufw/before.rules 2>/dev/null; then
        # Sauvegarde avant modification (protection contre corruption par sed)
        cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
        # Construction de la ligne LOG selon LOG_LIMIT
        local ufw_log_line
        if [ -n "$LOG_LIMIT" ]; then
          ufw_log_line="-A ufw-before-input -m set --match-set $SET_NAME src -m limit --limit $LOG_LIMIT --limit-burst $LOG_BURST -j LOG --log-prefix \"BLOCKED: \" --log-level 4"
        else
          ufw_log_line="-A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix \"BLOCKED: \" --log-level 4"
        fi
        sed -i "/*filter/,/COMMIT/ {
          /COMMIT/ i\\
$ufw_log_line\\
-A ufw-before-input -m set --match-set $SET_NAME src -j DROP
        }" /etc/ufw/before.rules
        ufw reload
        log "Règles ufw ajoutées (LOG + DROP)."
      fi
      # Whitelist : ajout/retrait dans before.rules en tête de ufw-before-input
      local wl_marker="match-set $WHITELIST_SET_NAME src -j ACCEPT"
      local wl_present=0
      grep -q "$wl_marker" /etc/ufw/before.rules 2>/dev/null && wl_present=1
      if [ "${#WHITELIST[@]}" -gt 0 ] && [ "$wl_present" -eq 0 ]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
        # Insère la règle ACCEPT juste avant la première règle ufw-before-input du blocklist
        sed -i "/-A ufw-before-input -m set --match-set $SET_NAME src/i\\
-A ufw-before-input -m set --match-set $WHITELIST_SET_NAME src -j ACCEPT" /etc/ufw/before.rules
        ufw reload
        log "Règle whitelist ufw ajoutée (ACCEPT)."
      elif [ "${#WHITELIST[@]}" -eq 0 ] && [ "$wl_present" -eq 1 ]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
        sed -i "/match-set $WHITELIST_SET_NAME src -j ACCEPT/d" /etc/ufw/before.rules
        ufw reload
        log "Règle whitelist ufw retirée (ACCEPT)."
      fi
      # Docker utilise iptables directement, hors du périmètre ufw
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER && log "Règles DOCKER-USER ajoutées (LOG + DROP)."
        _whitelist_or_cleanup_iptables DOCKER-USER
        docker_protected=1
      fi
      ;;
  esac

  if [ "$docker_protected" -eq 1 ]; then
    log "Docker détecté : la chaîne DOCKER-USER est protégée."
  fi
}

# --- Vérification dépendances ---
need_cmd curl
need_cmd awk
need_cmd sort
need_cmd ipset
need_cmd flock
need_cmd wc
need_cmd date
need_cmd comm

# --- Verrou ---
mkdir -p "$LOCK_DIR"
log "--- Mise à jour du : $(date '+%Y-%m-%d %H:%M:%S %Z') ---"

exec 9>"$LOCK_FILE"
flock -n 9 || { err "Erreur : une autre instance tourne déjà."; exit 1; }

# --- Avertissement sources HTTP ---
for url in "${URLS[@]}"; do
  if [[ "$url" =~ ^http:// ]]; then
    err "Avertissement : source HTTP (non chiffré) : $url"
  fi
done

# --- Téléchargements parallèles ---
fail=0
ok=0
declare -a DL_PIDS=()

for i in "${!URLS[@]}"; do
  curl "${CURL_OPTS[@]}" "${URLS[$i]}" -o "${TMP_DIR}/dl.${i}" &
  DL_PIDS+=("$!")
done

declare -a DL_OK=()
for i in "${!URLS[@]}"; do
  if wait "${DL_PIDS[$i]}" 2>/dev/null; then
    ok=$((ok+1))
    DL_OK+=("$i")
    log "Téléchargement OK : ${URLS[$i]}"
  else
    fail=$((fail+1))
    err "ERREUR: échec téléchargement: ${URLS[$i]}"
  fi
done

# --- Politique d'échec ---
if [ "$ok" -eq 0 ]; then
  err "Erreur : aucune source disponible. Annulation de la mise à jour."
  exit 1
fi
if [ "$fail" -ne 0 ]; then
  err "Avertissement : $fail source(s) indisponible(s). Mise à jour avec $ok source(s) disponible(s)."
fi

# --- Traitement séquentiel : awk fusionné (extraction + validation) + stats par source ---
AWK_PROG='
function valid_ipv4(ip,   n,i,o) {
  n = split(ip, o, ".");
  if (n != 4) return 0;
  for (i=1; i<=4; i++) {
    if (o[i] !~ /^[0-9]+$/) return 0;
    if (o[i]+0 < 0 || o[i]+0 > 255) return 0;
    if (length(o[i]) > 1 && substr(o[i],1,1)=="0") return 0;
  }
  return 1;
}
function valid_cidr(p) {
  if (p !~ /^[0-9]{1,2}$/) return 0;
  return (p+0 >= 0 && p+0 <= 32);
}
{
  # Extraction : normaliser espaces, extraire premier champ commençant par un chiffre
  gsub(/[[:space:]]+/, " ");
  sub(/^[[:space:]]+/, "");
  if ($0 !~ /^[0-9]/) next;
  sub(/[;#].*$/, "");
  x = $1;
  sub(/^[[:space:]]+/, "", x);
  sub(/[[:space:]]+$/, "", x);
  if (x == "") next;

  # Validation + canonicalisation
  if (index(x, "/")) {
    split(x, t, "/");
    if (valid_ipv4(t[1]) && valid_cidr(t[2])) print t[1] "/" t[2];
  } else {
    if (valid_ipv4(x)) print x "/32";
  }
}
'

for i in "${DL_OK[@]}"; do
  awk "$AWK_PROG" "${TMP_DIR}/dl.${i}" > "${TMP_DIR}/src.${i}"
  src_count="$(wc -l < "${TMP_DIR}/src.${i}")"
  if [ "$VERBOSE" -eq 1 ]; then
    log "  Source $((i+1))/${#URLS[@]} : $(fmt_num "$src_count") entrées valides — ${URLS[$i]}"
  fi
done

# --- Validation des entrées WHITELIST (mêmes règles que les listes externes) ---
if [ "${#WHITELIST[@]}" -gt 0 ]; then
  : > "$WL_FILE"
  invalid_wl=()
  for entry in "${WHITELIST[@]}"; do
    canonical="$(printf '%s\n' "$entry" | awk "$AWK_PROG")"
    if [ -z "$canonical" ]; then
      invalid_wl+=("$entry")
    else
      printf '%s\n' "$canonical" >> "$WL_FILE"
    fi
  done
  if [ "${#invalid_wl[@]}" -gt 0 ]; then
    err "Erreur : entrée(s) WHITELIST invalide(s) :"
    for entry in "${invalid_wl[@]}"; do
      err "  - '$entry'"
    done
    exit 1
  fi
  # Dédup + tri
  sort -u "$WL_FILE" -o "$WL_FILE"
  wl_count="$(wc -l < "$WL_FILE")"
  log "Whitelist : $(fmt_num "$wl_count") entrée(s)."
fi

cat "${TMP_DIR}"/src.* 2>/dev/null | sort -u > "$UNIQ_FILE" || true

if [ ! -s "$UNIQ_FILE" ]; then
  err "Erreur : Aucune IP/CIDR valide récupérée. Annulation."
  exit 1
fi

entries_count="$(wc -l < "$UNIQ_FILE")"

# --- Seuil minimal de sécurité ---
if [ "$entries_count" -lt "$MIN_ENTRIES" ]; then
  err "Erreur : seulement $(fmt_num "$entries_count") entrées (minimum attendu: $(fmt_num "$MIN_ENTRIES")). Possible anomalie source. Annulation."
  exit 1
fi

# --- Calcul hashsize / maxelem ---
calc_maxelem=$(( entries_count + entries_count / 4 + 10000 ))
if [ "$calc_maxelem" -lt "$BASE_MAXELEM" ]; then
  IPSET_MAXELEM="$BASE_MAXELEM"
else
  IPSET_MAXELEM="$calc_maxelem"
fi

target_hs=$(( (entries_count + 3) / 4 ))
hs=1024
while [ "$hs" -lt "$target_hs" ]; do
  hs=$((hs * 2))
done
if [ "$hs" -lt "$BASE_HASHSIZE" ]; then
  hs="$BASE_HASHSIZE"
fi
IPSET_HASHSIZE="$hs"

log "Entrées valides : $(fmt_num "$entries_count")"
log "ipset params    : hashsize=$(fmt_num "$IPSET_HASHSIZE") maxelem=$(fmt_num "$IPSET_MAXELEM")"

# --- Mode dry-run ---
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] $(fmt_num "$entries_count") entrées seraient appliquées."
  # En dry-run, afficher aussi le rapport de diff si le set existe
  if ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
    # Pipe direct vers fichier (évite de stocker 1M+ entrées dans une variable)
    ipset list "$SET_NAME" 2>/dev/null \
      | awk '/^Members:/{p=1;next} p{x=$1; if (x!="" && index(x,"/")==0) x=x"/32"; if (x!="") print x}' \
      | sort -u > "${TMP_DIR}/old_members"
    added="$(comm -13 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    removed="$(comm -23 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    unchanged="$(comm -12 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    log "Diff: +$(fmt_num "$added") ajoutées, -$(fmt_num "$removed") retirées, =$(fmt_num "$unchanged") inchangées"
  fi
  # Whitelist : annonce ce qui serait fait
  if [ "${#WHITELIST[@]}" -gt 0 ]; then
    log "[DRY-RUN] Whitelist : $(fmt_num "$(wc -l < "$WL_FILE")") entrée(s) seraient appliquées (set $WHITELIST_SET_NAME, règle ACCEPT)."
  else
    if ipset list -n 2>/dev/null | awk -v s="$WHITELIST_SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
      log "[DRY-RUN] Whitelist vide : le set $WHITELIST_SET_NAME et la règle ACCEPT seraient retirés."
    fi
  fi
  # Afficher le firewall détecté même en dry-run
  DETECTED_FW="$(detect_firewall)"
  log "[DRY-RUN] Firewall détecté : $DETECTED_FW"
  if detect_docker; then
    log "[DRY-RUN] Docker détecté : les règles seraient aussi appliquées sur DOCKER-USER."
  fi
  exit 0
fi

# --- Vérification set existant (ipset list -t = headers seulement, pas de dump des membres) ---
SET_EXISTS=0
if ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
  SET_EXISTS=1
  set_header="$(ipset list -t "$SET_NAME" 2>/dev/null)"
  existing_type="$(echo "$set_header" | awk -F': ' '/^Type: /{print $2; exit}')"
  existing_family="$(echo "$set_header" | awk -F': ' '/^Header: /{h=$2} END{if (h ~ /family inet6/) print "inet6"; else if (h ~ /family inet/) print "inet"; else print ""}')"
  if [ "$existing_type" != "$IPSET_TYPE" ] || [ "$existing_family" != "$IPSET_FAMILY" ]; then
    err "Erreur : set '$SET_NAME' existe mais type/family incompatibles (type=$existing_type family=$existing_family). Attendu: type=$IPSET_TYPE family=$IPSET_FAMILY. Annulation."
    exit 1
  fi
fi

# --- Génération fichier restore ---
{
  echo "create $TEMP_SET $IPSET_TYPE family $IPSET_FAMILY hashsize $IPSET_HASHSIZE maxelem $IPSET_MAXELEM"
  awk -v set="$TEMP_SET" '{print "add " set " " $1 " -exist"}' "$UNIQ_FILE"
} > "$TMP_FILE"

if [ "$(wc -l < "$TMP_FILE")" -le 1 ]; then
  err "Erreur : Aucune entrée ajoutable dans restore. Annulation."
  exit 1
fi

# --- Rapport de diff (verbose uniquement, pipe direct vers fichier) ---
if [ "$VERBOSE" -eq 1 ]; then
  if [ "$SET_EXISTS" -eq 1 ]; then
    member_count="$(echo "$set_header" | awk -F': ' '/Number of entries/{print $2+0; exit}')"
    if [ "$member_count" -gt 0 ]; then
      ipset list "$SET_NAME" 2>/dev/null \
        | awk '/^Members:/{p=1;next} p{x=$1; if (x!="" && index(x,"/")==0) x=x"/32"; if (x!="") print x}' \
        | sort -u > "${TMP_DIR}/old_members"
      added="$(comm -13 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
      removed="$(comm -23 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
      unchanged="$(comm -12 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
      log "Diff: +$(fmt_num "$added") ajoutées, -$(fmt_num "$removed") retirées, =$(fmt_num "$unchanged") inchangées"
    fi
  else
    log "Diff: +$(fmt_num "$entries_count") ajoutées (nouveau set)"
  fi
fi

# --- Assurer l'existence du set final (requis pour swap) ---
if [ "$SET_EXISTS" -eq 0 ]; then
  ipset create "$SET_NAME" "$IPSET_TYPE" family "$IPSET_FAMILY" hashsize "$IPSET_HASHSIZE" maxelem "$IPSET_MAXELEM"
fi

# --- Détruire le set temporaire s'il existe ---
ipset destroy "$TEMP_SET" 2>/dev/null || true

# --- Swap atomique ---
ipset restore < "$TMP_FILE"
ipset swap "$SET_NAME" "$TEMP_SET"
ipset destroy "$TEMP_SET"

total="$(ipset list -t "$SET_NAME" | awk -F': ' '/Number of entries/{print $2}')"
log "Total d'IP bloquées : $(fmt_num "$total")"

# --- Whitelist : build/swap atomique si non vide ---
WL_SET_EXISTS=0
if ipset list -n 2>/dev/null | awk -v s="$WHITELIST_SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
  WL_SET_EXISTS=1
fi

if [ "${#WHITELIST[@]}" -gt 0 ]; then
  wl_entries="$(wc -l < "$WL_FILE")"
  wl_maxelem=$(( wl_entries + 100 ))
  [ "$wl_maxelem" -lt 256 ] && wl_maxelem=256
  {
    echo "create $WL_TEMP_SET $IPSET_TYPE family $IPSET_FAMILY hashsize 1024 maxelem $wl_maxelem"
    awk -v set="$WL_TEMP_SET" '{print "add " set " " $1 " -exist"}' "$WL_FILE"
  } > "$WL_TMP_FILE"

  if [ "$WL_SET_EXISTS" -eq 0 ]; then
    ipset create "$WHITELIST_SET_NAME" "$IPSET_TYPE" family "$IPSET_FAMILY" hashsize 1024 maxelem "$wl_maxelem"
    WL_SET_EXISTS=1
  fi
  ipset destroy "$WL_TEMP_SET" 2>/dev/null || true
  ipset restore < "$WL_TMP_FILE"
  ipset swap "$WHITELIST_SET_NAME" "$WL_TEMP_SET"
  ipset destroy "$WL_TEMP_SET"
  log "Whitelist active : $(fmt_num "$wl_entries") entrée(s) dans $WHITELIST_SET_NAME."
fi

# --- Vérification / application des règles firewall ---
DETECTED_FW="$(detect_firewall)"
if [ "$DETECTED_FW" != "aucun" ]; then
  if detect_docker; then
    log "Firewall détecté : $DETECTED_FW (Docker présent, chaîne DOCKER-USER trouvée)"
  else
    log "Firewall détecté : $DETECTED_FW"
  fi
  apply_firewall_rules "$DETECTED_FW"
else
  err "Aucun firewall détecté. Les IP sont dans le set ipset mais aucune règle de blocage n'est active."
  err "Lancez setup-firewall.sh pour installer un firewall, ou installez-en un manuellement."
fi

# --- Whitelist vide : détruire le set après que les règles aient été retirées ---
if [ "${#WHITELIST[@]}" -eq 0 ] && [ "$WL_SET_EXISTS" -eq 1 ]; then
  if ipset destroy "$WHITELIST_SET_NAME" 2>/dev/null; then
    log "Whitelist vide : ipset $WHITELIST_SET_NAME détruit."
  else
    err "Avertissement : impossible de détruire $WHITELIST_SET_NAME (encore référencé ?)."
  fi
fi
