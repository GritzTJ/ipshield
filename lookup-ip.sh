#!/bin/bash
set -euo pipefail
umask 077

# --- Usage / help ---
usage() {
  cat <<'EOF'
Usage: lookup-ip.sh [OPTIONS] <ip_address>

Look up an IPv4 address across the configured blocklists to identify
which source(s) reference it.

Arguments:
  <ip_address>          IPv4 address to look up (e.g. 185.199.108.133)

Options:
  -v, --verbose       Verbose output (matching CIDR entry, per-source counts)
  -c, --config FILE   Configuration file path
  -h, --help          Show this help

Examples:
  lookup-ip.sh 185.199.108.133
  lookup-ip.sh --verbose 1.2.3.4
  lookup-ip.sh -c /etc/my-blocklist.conf 10.0.0.1
EOF
  exit 0
}

# --- CLI parsing ---
CLI_VERBOSE=""
CONF_FILE="/etc/update-blocklist.conf"
TARGET_IP=""

while [ $# -gt 0 ]; do
  case "$1" in
    -v|--verbose)  CLI_VERBOSE=1; shift ;;
    -c|--config)
      [ $# -ge 2 ] || { echo "Error: --config requires an argument." >&2; exit 1; }
      CONF_FILE="$2"; shift 2 ;;
    -h|--help)     usage ;;
    -*)            echo "Unknown option: $1" >&2; usage ;;
    *)
      if [ -n "$TARGET_IP" ]; then
        echo "Error: only one IP address allowed." >&2
        exit 1
      fi
      TARGET_IP="$1"; shift ;;
  esac
done

if [ -z "$TARGET_IP" ]; then
  echo "Error: missing IP address." >&2
  echo "Usage: lookup-ip.sh [OPTIONS] <ip_address>" >&2
  exit 1
fi

# --- Variable initialisation (values come from the conf file) ---
URLS=()
VERBOSE=0

# --- Source config file (REQUIRED, except if not readable by a non-root user) ---
# The conf file (same content as update-blocklist.sh) is the single source of truth.
# For diagnostic use from a machine without ipshield installed, point -c to a copy
# of update-blocklist.conf.example.
if [ ! -f "$CONF_FILE" ]; then
  echo "Error: configuration file $CONF_FILE not found." >&2
  echo "Run ./setup-firewall.sh to install it, or point -c to a copy of" >&2
  echo "update-blocklist.conf.example." >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  # Root: full security checks
  conf_owner="$(stat -c '%u' "$CONF_FILE")"
  conf_perms="$(stat -c '%a' "$CONF_FILE")"
  if [ "$conf_owner" != "0" ]; then
    echo "Error: $CONF_FILE is not owned by root (uid=$conf_owner). Security risk." >&2
    exit 1
  fi
  if [[ "$conf_perms" =~ [2367][0-9]$ ]] || [[ "$conf_perms" =~ [0-9][2367]$ ]]; then
    echo "Error: $CONF_FILE is group/world-writable (perms=$conf_perms). Security risk." >&2
    exit 1
  fi
elif [ ! -r "$CONF_FILE" ]; then
  echo "Error: $CONF_FILE is not readable by the current user." >&2
  echo "Re-run as root, or point -c to a readable copy." >&2
  exit 1
fi
# shellcheck source=/dev/null
. "$CONF_FILE"

# --- Validate required variables ---
if [ "${#URLS[@]}" -eq 0 ]; then
  echo "Error: URLS is empty or undefined in $CONF_FILE." >&2
  exit 1
fi
: "${SET_NAME:=blacklist}"

# --- Apply CLI overrides ---
[ -n "$CLI_VERBOSE" ] && VERBOSE=1

# --- Whitelist set name (derived if undefined) ---
: "${WHITELIST_SET_NAME:=${SET_NAME}-allow}"

# --- BLOCKLIST_MIN_PREFIX default + validation ---
# Same safeguard as update-blocklist.sh: an external CIDR with prefix shorter
# than this threshold would never end up in the ipset, so don't report it as a
# match here either. Default 8 (rejects /0 to /7).
: "${BLOCKLIST_MIN_PREFIX:=8}"
if ! [[ "$BLOCKLIST_MIN_PREFIX" =~ ^[0-9]+$ ]] || [ "$BLOCKLIST_MIN_PREFIX" -lt 0 ] || [ "$BLOCKLIST_MIN_PREFIX" -gt 32 ]; then
  echo "Error: BLOCKLIST_MIN_PREFIX invalid ('$BLOCKLIST_MIN_PREFIX'). Integer 0-32 expected." >&2
  exit 1
fi

# --- Functions ---
log() { echo "$*"; }
err() { echo "$*" >&2; }

# --- IPv4 validation ---
valid_ipv4() {
  local ip="$1"
  # Format: 4 octets separated by dots
  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    return 1
  fi
  local IFS='.'
  # shellcheck disable=SC2086
  set -- $ip
  local i
  for i in "$1" "$2" "$3" "$4"; do
    # No zero padding (except "0" itself)
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
  err "Error: '$TARGET_IP' is not a valid IPv4 address."
  exit 1
fi

# --- Dependency check ---
need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Error: missing command: $1"; exit 1; }; }
need_cmd curl
need_cmd awk

# --- Source name from URL ---
source_name() {
  local url="$1"
  local idx="$2"
  case "$url" in
    *duggytuxy*)             echo "Data-Shield" ;;
    *spamhaus.org*drop*)     echo "Spamhaus DROP" ;;
    *emergingthreats.net*)   echo "Emerging Threats" ;;
    *cinsscore.com*)         echo "CINS" ;;
    *abuseipdb*)             echo "AbuseIPDB" ;;
    *firehol*)               echo "FireHOL Level 1" ;;
    *greensnow*)             echo "GreenSnow" ;;
    *blocklist.de*)          echo "Blocklist.de" ;;
    *stamparm/ipsum*)        echo "IPsum" ;;
    *torproject.org*)        echo "Tor exit nodes" ;;
    *palinkas*)              echo "Internet Scanner IPs" ;;
    *)                       echo "Source $((idx+1))" ;;
  esac
}

# --- Temporary directory ---
if [ "$(id -u)" -eq 0 ]; then
  TMP_DIR="$(mktemp -d -p /run "lookup-ip.XXXXXX")"
else
  TMP_DIR="$(mktemp -d -p /tmp "lookup-ip.XXXXXX")"
fi
cleanup() { rm -rf -- "$TMP_DIR" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# --- AWK program: extraction + IPv4/CIDR validation (identical to update-blocklist.sh) ---
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
# Reject reserved ranges (RFC 6890) that should never appear in a public
# blocklist. Prevents a catastrophic false positive (e.g. FireHOL Level 1
# includes bogons by design) from blocking the LAN or the Docker bridge.
function is_bogon(addr) {
  return (addr ~ /^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.(0\.(0|2)|168)\.|198\.(1[89]|51\.100)\.|203\.0\.113\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)/);
}
{
  # Extraction: normalise spaces, take the first field that starts with a digit
  gsub(/[[:space:]]+/, " ");
  sub(/^[[:space:]]+/, "");
  if ($0 !~ /^[0-9]/) next;
  sub(/[;#].*$/, "");
  x = $1;
  sub(/^[[:space:]]+/, "", x);
  sub(/[[:space:]]+$/, "", x);
  if (x == "") next;

  # Validation + canonicalisation + bogon filter + min prefix safeguard.
  # allow_bogons=1 (via -v) for the whitelist: RFC1918 accepted, prefix unchecked.
  # min_prefix (via -v) rejects external entries with prefix < min_prefix
  # (e.g. /0 from a corrupted source would otherwise match every IP).
  if (index(x, "/")) {
    split(x, t, "/");
    if (valid_ipv4(t[1]) && valid_cidr(t[2]) && (allow_bogons || (!is_bogon(t[1]) && t[2]+0 >= min_prefix))) print t[1] "/" t[2];
  } else {
    if (valid_ipv4(x) && (allow_bogons || !is_bogon(x))) print x "/32";
  }
}
'

# --- AWK program: CIDR matching ---
# Checks whether the target IP (passed via -v target=...) falls within one of
# the input CIDRs. Output: matching CIDR entries.
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
  # Mask to the network address: floor(net_int / block_size) * block_size.
  # Required when the source uses non-canonical CIDR (e.g. "1.0.0.1/24"),
  # otherwise the lower bound would exclude IPs whose host bits are below
  # those of the source.
  network = int(net_int / block_size) * block_size;
  if (target_int >= network && target_int < network + block_size) {
    print $0;
  }
}
'

# --- curl options ---
CURL_OPTS=( -fsSL --compressed --connect-timeout 10 --max-time 30 --max-filesize 10485760 --retry 3 --retry-delay 2 --retry-all-errors )

# --- Output ---
log "Looking up $TARGET_IP across ${#URLS[@]} blocklists..."
echo ""

# --- ipset test (if root + ipset available) ---
echo "--- ipset status ---"
if [ "$(id -u)" -eq 0 ] && command -v ipset >/dev/null 2>&1; then
  if ! ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
    echo "  Set '$SET_NAME': not found (run update-blocklist.sh first)"
  elif ipset test "$SET_NAME" "$TARGET_IP" 2>/dev/null; then
    echo "  Set '$SET_NAME': IP PRESENT (block active)"
  else
    echo "  Set '$SET_NAME': IP not in set"
  fi
  # Whitelist
  if ipset list -n 2>/dev/null | awk -v s="$WHITELIST_SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
    if ipset test "$WHITELIST_SET_NAME" "$TARGET_IP" 2>/dev/null; then
      echo "  Set '$WHITELIST_SET_NAME': IP PRESENT (whitelist - bypasses blocklist)"
    else
      echo "  Set '$WHITELIST_SET_NAME': IP not in set"
    fi
  fi
else
  echo "  (ipset check skipped - requires root and ipset)"
fi
echo ""

# --- HTTP source warning ---
for url in "${URLS[@]}"; do
  if [[ "$url" =~ ^http:// ]]; then
    err "Warning: HTTP (unencrypted) source: $url"
  fi
done

# --- Parallel downloads ---
declare -a DL_PIDS=()
for i in "${!URLS[@]}"; do
  curl "${CURL_OPTS[@]}" "${URLS[$i]}" -o "${TMP_DIR}/dl.${i}" 2>/dev/null &
  DL_PIDS+=("$!")
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
  err "Error: no source available."
  exit 1
fi

# --- Per-source search ---
echo "--- Per-source search ---"
found_count=0
total_checked=0

for i in "${!URLS[@]}"; do
  name="$(source_name "${URLS[$i]}" "$i")"
  padded_name="$(printf "%-22s" "$name")"

  # Failed-download source
  is_failed=0
  for f in "${DL_FAIL[@]}"; do
    if [ "$f" = "$i" ]; then
      is_failed=1
      break
    fi
  done

  if [ "$is_failed" -eq 1 ]; then
    echo "  ${padded_name}: (download failed)"
    continue
  fi

  total_checked=$((total_checked + 1))

  # Extraction + validation
  awk -v min_prefix="$BLOCKLIST_MIN_PREFIX" "$AWK_PROG" "${TMP_DIR}/dl.${i}" > "${TMP_DIR}/src.${i}"
  src_count="$(wc -l < "${TMP_DIR}/src.${i}")"

  # CIDR matching
  matches="$(awk -v target="$TARGET_IP" "$CIDR_MATCH_PROG" "${TMP_DIR}/src.${i}")"

  if [ -n "$matches" ]; then
    found_count=$((found_count + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      # Show each matching CIDR entry
      first_match="$(echo "$matches" | head -1)"
      echo "  ${padded_name}: FOUND -> ${first_match} (${src_count} entries)"
      # If multiple matches, show the rest
      rest="$(echo "$matches" | tail -n +2)"
      if [ -n "$rest" ]; then
        while IFS= read -r m; do
          printf "  %-22s  -> %s\n" "" "$m"
        done <<< "$rest"
      fi
    else
      echo "  ${padded_name}: FOUND"
    fi
  else
    if [ "$VERBOSE" -eq 1 ]; then
      echo "  ${padded_name}: not found (${src_count} entries)"
    else
      echo "  ${padded_name}: not found"
    fi
  fi
done

echo ""

# --- Summary ---
echo "--- Summary ---"
echo "  IP found in ${found_count}/${total_checked} source(s)."
