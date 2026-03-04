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
DRY_RUN=0
VERBOSE=0
MIN_ENTRIES=1000
BASE_HASHSIZE="16384"
BASE_MAXELEM="300000"

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

# --- Variables dérivées ---
IPSET_TYPE="hash:net"
IPSET_FAMILY="inet"
LOCK_DIR="/run/lock"
LOCK_FILE="${LOCK_DIR}/${SET_NAME}.lock"
TMP_DIR="$(mktemp -d -p /run "${SET_NAME}.XXXXXX")"
UNIQ_FILE="${TMP_DIR}/uniq"
TMP_FILE="${TMP_DIR}/restore"
TEMP_SET="${SET_NAME}-tmp-$$"
CURL_OPTS=( -fsSL --compressed --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 --retry-all-errors )

if [ "${#TEMP_SET}" -gt 31 ]; then
  echo "Erreur : nom de set temporaire trop long (${#TEMP_SET} > 31)" >&2
  exit 1
fi

# --- Fonctions ---
log() { echo "$*"; logger -t "update-blocklist" "$*" 2>/dev/null || true; }
err() { echo "$*" >&2; logger -t "update-blocklist" -p user.err "$*" 2>/dev/null || true; }
fmt_num() { printf "%d" "$1" | sed ':a;s/\([0-9]\)\([0-9]\{3\}\)\($\| \)/\1 \2\3/;ta'; }

cleanup() {
  rm -rf -- "$TMP_DIR" 2>/dev/null || true
  ipset destroy "$TEMP_SET" 2>/dev/null || true
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

# --- Insertion idempotente des règles LOG + DROP sur une chaîne iptables ---
_apply_iptables_rules() {
  local chain="$1"
  iptables -C "$chain" -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || {
    iptables -I "$chain" -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
    iptables -I "$chain" 2 -m set --match-set "$SET_NAME" src -j DROP
    return 0
  }
  return 1
}

# --- Application des règles firewall ---
apply_firewall_rules() {
  local fw="$1"

  local docker_protected=0

  case "$fw" in
    iptables)
      _apply_iptables_rules INPUT && log "Règles iptables ajoutées (LOG + DROP)."
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER && log "Règles iptables DOCKER-USER ajoutées (LOG + DROP)."
        docker_protected=1
      fi
      ;;

    nftables)
      # nftables ne peut pas référencer les sets ipset nativement (@set).
      # On utilise iptables (iptables-nft) qui traduit les commandes en règles nft
      # tout en supportant le match ipset via le module xt_set du noyau.
      need_cmd iptables
      _apply_iptables_rules INPUT && log "Règles nftables ajoutées via iptables-nft (LOG + DROP)."
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER && log "Règles nftables DOCKER-USER ajoutées via iptables-nft (LOG + DROP)."
        docker_protected=1
      fi
      ;;

    firewalld)
      local need_reload=0
      if ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 1 -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
        need_reload=1
        log "Règles firewalld ajoutées (LOG + DROP)."
      fi
      if detect_docker; then
        if ! firewall-cmd --permanent --direct --query-rule ipv4 filter DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
          firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 0 -m set --match-set "$SET_NAME" src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix "BLOCKED: " --log-level 4
          firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP
          need_reload=1
          log "Règles firewalld DOCKER-USER ajoutées (LOG + DROP)."
        fi
        docker_protected=1
      fi
      [ "$need_reload" -eq 1 ] && firewall-cmd --reload
      ;;

    ufw)
      if ! grep -q "match-set $SET_NAME src" /etc/ufw/before.rules 2>/dev/null; then
        sed -i "/*filter/,/COMMIT/ {
          /COMMIT/ i\\
-A ufw-before-input -m set --match-set $SET_NAME src -m limit --limit 60/min --limit-burst 100 -j LOG --log-prefix \"BLOCKED: \" --log-level 4\\
-A ufw-before-input -m set --match-set $SET_NAME src -j DROP
        }" /etc/ufw/before.rules
        ufw reload
        log "Règles ufw ajoutées (LOG + DROP)."
      fi
      # Docker utilise iptables directement, hors du périmètre ufw
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER && log "Règles DOCKER-USER ajoutées (LOG + DROP)."
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

# --- Téléchargements parallèles ---
fail=0
ok=0
declare -a DL_PIDS=()

for i in "${!URLS[@]}"; do
  curl "${CURL_OPTS[@]}" "${URLS[$i]}" -o "${TMP_DIR}/dl.${i}" &
  DL_PIDS+=($!)
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

cat "${TMP_DIR}"/src.* 2>/dev/null | sort -u > "$UNIQ_FILE"

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
    set_info="$(ipset list "$SET_NAME" 2>/dev/null)"
    echo "$set_info" | awk '/^Members:/{p=1;next} p{print}' \
      | awk '{x=$1; if (x!="" && index(x,"/")==0) x=x"/32"; if (x!="") print x}' \
      | sort -u > "${TMP_DIR}/old_members"
    added="$(comm -13 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    removed="$(comm -23 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    unchanged="$(comm -12 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    log "Diff: +$(fmt_num "$added") ajoutées, -$(fmt_num "$removed") retirées, =$(fmt_num "$unchanged") inchangées"
  fi
  # Afficher le firewall détecté même en dry-run
  DETECTED_FW="$(detect_firewall)"
  log "[DRY-RUN] Firewall détecté : $DETECTED_FW"
  if detect_docker; then
    log "[DRY-RUN] Docker détecté : les règles seraient aussi appliquées sur DOCKER-USER."
  fi
  exit 0
fi

# --- Vérification set existant (un seul appel ipset list) ---
SET_EXISTS=0
if ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
  SET_EXISTS=1
  set_info="$(ipset list "$SET_NAME" 2>/dev/null)"
  existing_type="$(echo "$set_info" | awk -F': ' '/^Type: /{print $2; exit}')"
  existing_family="$(echo "$set_info" | awk -F': ' '/^Header: /{h=$2} END{if (h ~ /family inet6/) print "inet6"; else if (h ~ /family inet/) print "inet"; else print ""}')"
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

# --- Rapport de diff (réutilise set_info) ---
if [ "$SET_EXISTS" -eq 1 ]; then
  member_count="$(echo "$set_info" | awk -F': ' '/Number of entries/{print $2+0; exit}')"
  if [ "$member_count" -gt 0 ]; then
    echo "$set_info" | awk '/^Members:/{p=1;next} p{print}' \
      | awk '{x=$1; if (x!="" && index(x,"/")==0) x=x"/32"; if (x!="") print x}' \
      | sort -u > "${TMP_DIR}/old_members"
    added="$(comm -13 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    removed="$(comm -23 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    unchanged="$(comm -12 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    log "Diff: +$(fmt_num "$added") ajoutées, -$(fmt_num "$removed") retirées, =$(fmt_num "$unchanged") inchangées"
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
