#!/bin/bash
set -euo pipefail
umask 077

# --- Usage / aide ---
usage() {
  cat <<'EOF'
Usage: lookup-ip.sh [OPTIONS] <adresse_ip>

Recherche une adresse IPv4 dans les listes de blocage pour identifier
la ou les sources qui la référencent.

Arguments:
  <adresse_ip>          Adresse IPv4 à rechercher (ex: 185.199.108.133)

Options:
  -v, --verbose       Affichage détaillé (entrée CIDR, nombre d'entrées par source)
  -c, --config FILE   Chemin du fichier de configuration
  -h, --help          Affiche cette aide

Exemples:
  lookup-ip.sh 185.199.108.133
  lookup-ip.sh --verbose 1.2.3.4
  lookup-ip.sh -c /etc/my-blocklist.conf 10.0.0.1
EOF
  exit 0
}

# --- Parsing CLI ---
CLI_VERBOSE=""
CONF_FILE="/etc/update-blocklist.conf"
TARGET_IP=""

while [ $# -gt 0 ]; do
  case "$1" in
    -v|--verbose)  CLI_VERBOSE=1; shift ;;
    -c|--config)
      [ $# -ge 2 ] || { echo "Erreur : --config nécessite un argument." >&2; exit 1; }
      CONF_FILE="$2"; shift 2 ;;
    -h|--help)     usage ;;
    -*)            echo "Option inconnue : $1" >&2; usage ;;
    *)
      if [ -n "$TARGET_IP" ]; then
        echo "Erreur : une seule adresse IP autorisée." >&2
        exit 1
      fi
      TARGET_IP="$1"; shift ;;
  esac
done

if [ -z "$TARGET_IP" ]; then
  echo "Erreur : adresse IP manquante." >&2
  echo "Usage: lookup-ip.sh [OPTIONS] <adresse_ip>" >&2
  exit 1
fi

# --- Valeurs par défaut ---
URLS=(
  "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
  "https://www.spamhaus.org/drop/drop.txt"
  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
  "https://cinsscore.com/list/ci-badguys.txt"
  "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-365d.ipv4"
)
SET_NAME="blacklist"
VERBOSE=0

# --- Source config file (si existe) ---
if [ -f "$CONF_FILE" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    # Root : vérifications de sécurité complètes
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
  elif [ -r "$CONF_FILE" ]; then
    # Non-root : source si lisible
    # shellcheck source=/dev/null
    . "$CONF_FILE"
  fi
fi

# --- Appliquer overrides CLI ---
[ -n "$CLI_VERBOSE" ] && VERBOSE=1

# --- Fonctions ---
log() { echo "$*"; }
err() { echo "$*" >&2; }

# --- Validation IPv4 ---
valid_ipv4() {
  local ip="$1"
  # Format : 4 octets séparés par des points
  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    return 1
  fi
  local IFS='.'
  # shellcheck disable=SC2086
  set -- $ip
  local i
  for i in "$1" "$2" "$3" "$4"; do
    # Pas de zéro padding (sauf "0" lui-même)
    if [ "${#i}" -gt 1 ] && [ "${i:0:1}" = "0" ]; then
      return 1
    fi
    if [ "$i" -gt 255 ] 2>/dev/null; then
      return 1
    fi
  done
  return 0
}

if ! valid_ipv4 "$TARGET_IP"; then
  err "Erreur : '$TARGET_IP' n'est pas une adresse IPv4 valide."
  exit 1
fi

# --- Vérification dépendances ---
need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Erreur : commande manquante : $1"; exit 1; }; }
need_cmd curl
need_cmd awk

# --- Nom de source à partir de l'URL ---
source_name() {
  local url="$1"
  local idx="$2"
  case "$url" in
    *duggytuxy*)           echo "Data-Shield" ;;
    *spamhaus.org*drop*)   echo "Spamhaus DROP" ;;
    *emergingthreats.net*) echo "Emerging Threats" ;;
    *cinsscore.com*)       echo "CINS" ;;
    *abuseipdb*)           echo "AbuseIPDB" ;;
    *)                     echo "Source $((idx+1))" ;;
  esac
}

# --- Répertoire temporaire ---
if [ "$(id -u)" -eq 0 ]; then
  TMP_DIR="$(mktemp -d -p /run "lookup-ip.XXXXXX")"
else
  TMP_DIR="$(mktemp -d -p /tmp "lookup-ip.XXXXXX")"
fi
cleanup() { rm -rf -- "$TMP_DIR" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# --- Programme AWK : extraction + validation IPv4/CIDR (identique à update-blocklist.sh) ---
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
  gsub(/[[:space:]]+/, " ");
  sub(/^[[:space:]]+/, "");
  if ($0 !~ /^[0-9]/) next;
  sub(/[;#].*$/, "");
  x = $1;
  sub(/^[[:space:]]+/, "", x);
  sub(/[[:space:]]+$/, "", x);
  if (x == "") next;

  if (index(x, "/")) {
    split(x, t, "/");
    if (valid_ipv4(t[1]) && valid_cidr(t[2])) print t[1] "/" t[2];
  } else {
    if (valid_ipv4(x)) print x "/32";
  }
}
'

# --- Programme AWK : matching CIDR ---
# Vérifie si l'IP cible (passée via -v target=...) appartient à un des CIDR en entrée
# Sortie : les entrées CIDR qui matchent
CIDR_MATCH_PROG='
function ip_to_int(ip,   o, n) {
  n = split(ip, o, ".");
  return o[1] * 16777216 + o[2] * 65536 + o[3] * 256 + o[4];
}
BEGIN {
  target_int = ip_to_int(target);
}
{
  split($0, parts, "/");
  net_int = ip_to_int(parts[1]);
  prefix = parts[2] + 0;
  block_size = 2 ^ (32 - prefix);
  if (target_int >= net_int && target_int < net_int + block_size) {
    print $0;
  }
}
'

# --- Options curl ---
CURL_OPTS=( -fsSL --compressed --connect-timeout 10 --max-time 30 --max-filesize 52428800 --retry 3 --retry-delay 2 --retry-all-errors )

# --- Affichage ---
log "Recherche de $TARGET_IP dans ${#URLS[@]} listes de blocage..."
echo ""

# --- Test ipset (si root + ipset disponible) ---
echo "--- Statut ipset ---"
if [ "$(id -u)" -eq 0 ] && command -v ipset >/dev/null 2>&1; then
  if ipset test "$SET_NAME" "$TARGET_IP" 2>/dev/null; then
    echo "  Set '$SET_NAME' : PRÉSENT (blocage actif)"
  else
    echo "  Set '$SET_NAME' : absent"
  fi
else
  echo "  (vérification ipset ignorée — nécessite root et ipset)"
fi
echo ""

# --- Téléchargements parallèles ---
declare -a DL_PIDS=()
for i in "${!URLS[@]}"; do
  curl "${CURL_OPTS[@]}" "${URLS[$i]}" -o "${TMP_DIR}/dl.${i}" 2>/dev/null &
  DL_PIDS+=($!)
done

declare -a DL_OK=()
declare -a DL_FAIL=()
for i in "${!URLS[@]}"; do
  if wait "${DL_PIDS[$i]}" 2>/dev/null; then
    DL_OK+=("$i")
  else
    DL_FAIL+=("$i")
  fi
done

if [ "${#DL_OK[@]}" -eq 0 ]; then
  err "Erreur : aucune source disponible."
  exit 1
fi

# --- Recherche par source ---
echo "--- Recherche par source ---"
found_count=0
total_checked=0

for i in "${!URLS[@]}"; do
  name="$(source_name "${URLS[$i]}" "$i")"
  padded_name="$(printf "%-18s" "$name")"

  # Source en échec de téléchargement
  is_failed=0
  for f in "${DL_FAIL[@]}"; do
    if [ "$f" = "$i" ]; then
      is_failed=1
      break
    fi
  done

  if [ "$is_failed" -eq 1 ]; then
    echo "  ${padded_name}: (téléchargement échoué)"
    continue
  fi

  total_checked=$((total_checked + 1))

  # Extraction + validation
  awk "$AWK_PROG" "${TMP_DIR}/dl.${i}" > "${TMP_DIR}/src.${i}"
  src_count="$(wc -l < "${TMP_DIR}/src.${i}")"

  # Matching CIDR
  matches="$(awk -v target="$TARGET_IP" "$CIDR_MATCH_PROG" "${TMP_DIR}/src.${i}")"

  if [ -n "$matches" ]; then
    found_count=$((found_count + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      # Afficher chaque entrée CIDR correspondante
      first_match="$(echo "$matches" | head -1)"
      echo "  ${padded_name}: TROUVÉ → ${first_match} (${src_count} entrées)"
      # Si plusieurs matchs, afficher les suivants
      rest="$(echo "$matches" | tail -n +2)"
      if [ -n "$rest" ]; then
        while IFS= read -r m; do
          printf "  %-18s  → %s\n" "" "$m"
        done <<< "$rest"
      fi
    else
      echo "  ${padded_name}: TROUVÉ"
    fi
  else
    if [ "$VERBOSE" -eq 1 ]; then
      echo "  ${padded_name}: non trouvé (${src_count} entrées)"
    else
      echo "  ${padded_name}: non trouvé"
    fi
  fi
done

echo ""

# --- Résumé ---
echo "--- Résumé ---"
echo "  IP trouvée dans ${found_count}/${total_checked} source(s)."
