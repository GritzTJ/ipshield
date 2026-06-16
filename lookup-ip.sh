#!/bin/bash
# ipshield v1.2.1
set -euo pipefail
umask 077

# Cron on Debian/Ubuntu typically runs with PATH=/usr/bin:/bin, which omits
# /sbin and /usr/sbin where ipset and ip live. Prepend the standard system
# paths so the script behaves the same under cron, systemd and interactive
# shells. Non-existent directories are harmlessly ignored by PATH lookup.
export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}"

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
CONF_FILE="/etc/ipshield.conf"
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
# The conf file (same content as update-ipshield.sh) is the single source of truth.
# For diagnostic use from a machine without ipshield installed, point -c to a copy
# of ipshield.conf.example.
if [ ! -f "$CONF_FILE" ]; then
  echo "Error: configuration file $CONF_FILE not found." >&2
  echo "Run ./setup-ipshield.sh to install it, or point -c to a copy of" >&2
  echo "ipshield.conf.example." >&2
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
  if (( (8#$conf_perms & 022) != 0 )); then
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
if [[ ! "$SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Error: SET_NAME invalid ('$SET_NAME'). Only [a-zA-Z0-9_-] allowed." >&2
  exit 1
fi
if [ "${#SET_NAME}" -gt 31 ]; then
  echo "Error: SET_NAME too long (${#SET_NAME} > 31)." >&2
  exit 1
fi

# --- Apply CLI overrides ---
[ -n "$CLI_VERBOSE" ] && VERBOSE=1

# --- Whitelist set name (derived if undefined) ---
: "${WHITELIST_SET_NAME:=${SET_NAME}-allow}"
if [[ ! "$WHITELIST_SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Error: WHITELIST_SET_NAME invalid ('$WHITELIST_SET_NAME'). Only [a-zA-Z0-9_-] allowed." >&2
  exit 1
fi
if [ "${#WHITELIST_SET_NAME}" -gt 31 ]; then
  echo "Error: WHITELIST_SET_NAME too long (${#WHITELIST_SET_NAME} > 31)." >&2
  exit 1
fi
if [ "$WHITELIST_SET_NAME" = "$SET_NAME" ]; then
  echo "Error: WHITELIST_SET_NAME must differ from SET_NAME." >&2
  exit 1
fi

# --- BLOCKLIST_MIN_PREFIX default + validation ---
# Same safeguard as update-ipshield.sh: an external CIDR with prefix shorter
# than this threshold would never end up in the ipset, so don't report it as a
# match here either. Default 8 (rejects /0 to /7).
: "${BLOCKLIST_MIN_PREFIX:=8}"
if ! [[ "$BLOCKLIST_MIN_PREFIX" =~ ^[0-9]+$ ]] || [ "$BLOCKLIST_MIN_PREFIX" -lt 0 ] || [ "$BLOCKLIST_MIN_PREFIX" -gt 32 ]; then
  echo "Error: BLOCKLIST_MIN_PREFIX invalid ('$BLOCKLIST_MIN_PREFIX'). Integer 0-32 expected." >&2
  exit 1
fi

# --- Lookup cache ---
# lookup-ip.sh is an interactive diagnostic helper; caching avoids downloading
# every public source again for each IP checked. Set LOOKUP_CACHE_TTL=0 to
# disable the cache.
: "${LOOKUP_CACHE_TTL:=21600}"
if ! [[ "$LOOKUP_CACHE_TTL" =~ ^[0-9]+$ ]]; then
  echo "Error: LOOKUP_CACHE_TTL invalid ('$LOOKUP_CACHE_TTL'). Integer seconds expected." >&2
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
    # Reject octets longer than 3 digits: they are out of the 0-255 range and,
    # critically, keep the numeric test below within bash's integer range -- a
    # huge value (e.g. 9999...9) would otherwise make "[ -gt ]" error out and
    # fall through to acceptance instead of being rejected.
    if [ "${#i}" -gt 3 ]; then
      return 1
    fi
    # No zero padding (except "0" itself)
    if [ "${#i}" -gt 1 ] && [ "${i:0:1}" = "0" ]; then
      return 1
    fi
    if [ "$i" -gt 255 ]; then
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
if [ "$LOOKUP_CACHE_TTL" -gt 0 ]; then
  need_cmd sha256sum
fi

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

LOOKUP_CACHE_DIR=""
if [ "$LOOKUP_CACHE_TTL" -gt 0 ]; then
  if [ "$(id -u)" -eq 0 ]; then
    LOOKUP_CACHE_DIR="/var/cache/ipshield/lookup"
  else
    LOOKUP_CACHE_DIR="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/ipshield/lookup"
  fi
  mkdir -p "$LOOKUP_CACHE_DIR" 2>/dev/null || LOOKUP_CACHE_DIR=""
fi

# Prune orphan cache files left behind when a URL is removed/edited in the
# config (same scheme as update-ipshield.sh). Files whose basename does not
# match any current URL hash are deleted. This also cleans up the legacy
# 'source-<idx>-<cksum>.txt' naming inherited from earlier versions.
if [ -n "$LOOKUP_CACHE_DIR" ] && [ -d "$LOOKUP_CACHE_DIR" ]; then
  declare -A LOOKUP_ACTIVE_HASHES=()
  for url in "${URLS[@]}"; do
    h="$(printf '%s' "$url" | sha256sum | awk '{print $1}')"
    LOOKUP_ACTIVE_HASHES[$h]=1
  done
  shopt -s nullglob
  for cache_path in "$LOOKUP_CACHE_DIR"/*.txt; do
    base="$(basename "$cache_path" .txt)"
    if [ -z "${LOOKUP_ACTIVE_HASHES[$base]:-}" ]; then
      rm -f "$cache_path"
      [ "$VERBOSE" -eq 1 ] && log "Removed orphan lookup cache: $cache_path"
    fi
  done
  shopt -u nullglob
fi

# --- AWK program: extraction + IPv4/CIDR validation (same as update-ipshield.sh) ---
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
  if (p !~ /^(0|[1-9][0-9]?)$/) return 0;
  return (p+0 >= 0 && p+0 <= 32);
}
function ip_to_int(ip,   o) {
  split(ip, o, ".");
  return o[1] * 16777216 + o[2] * 65536 + o[3] * 256 + o[4];
}
# Reject any entry whose range OVERLAPS a reserved range (RFC 6890) that
# should never appear in a public blocklist. Overlap -- not just base-address
# membership -- also catches wider covering blocks whose base address is NOT
# reserved: 172.0.0.0/8 covers the Docker bridge ranges and 192.160.0.0/11
# covers the 192.168/16 LAN. Prevents a catastrophic false positive (bogons
# by design as in FireHOL Level 1, or a corrupted source pushing a wide
# aggregate) from blocking the LAN or the Docker bridge.
BEGIN {
  nbogons = split("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4", bogons, " ");
  for (bi = 1; bi <= nbogons; bi++) {
    split(bogons[bi], bparts, "/");
    bsize = 2 ^ (32 - bparts[2]);
    bogon_start[bi] = ip_to_int(bparts[1]);
    bogon_end[bi] = bogon_start[bi] + bsize - 1;
  }
}
function overlaps_bogon(ip, prefix,   size, start, end, bi) {
  size = 2 ^ (32 - prefix);
  # Mask host bits so a non-canonical CIDR (e.g. 192.169.1.5/15) is tested
  # on its real network range.
  start = int(ip_to_int(ip) / size) * size;
  end = start + size - 1;
  for (bi = 1; bi <= nbogons; bi++) {
    if (start <= bogon_end[bi] && bogon_start[bi] <= end) return 1;
  }
  return 0;
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
    if (valid_ipv4(t[1]) && valid_cidr(t[2]) && (allow_bogons || (!overlaps_bogon(t[1], t[2]+0) && t[2]+0 >= min_prefix))) print t[1] "/" t[2];
  } else {
    if (valid_ipv4(x) && (allow_bogons || !overlaps_bogon(x, 32))) print x "/32";
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

cache_path_for_url() {
  local url="$1"
  local sum
  [ -n "$LOOKUP_CACHE_DIR" ] || return 1
  sum="$(printf '%s' "$url" | sha256sum | awk '{print $1}')"
  printf '%s/%s.txt' "$LOOKUP_CACHE_DIR" "$sum"
}

cache_is_fresh() {
  local path="$1"
  local now mtime
  [ "$LOOKUP_CACHE_TTL" -gt 0 ] || return 1
  [ -s "$path" ] || return 1
  now="$(date +%s)"
  mtime="$(stat -c '%Y' "$path" 2>/dev/null || echo 0)"
  [ $((now - mtime)) -lt "$LOOKUP_CACHE_TTL" ]
}

# --- Output ---
log "Looking up $TARGET_IP across ${#URLS[@]} blocklists..."
echo ""

# --- ipset test (if root + ipset available) ---
echo "--- ipset status ---"
if [ "$(id -u)" -eq 0 ] && command -v ipset >/dev/null 2>&1; then
  if ! ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
    echo "  Set '$SET_NAME': not found (run update-ipshield.sh first)"
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
declare -a DL_FROM_CACHE=()
for i in "${!URLS[@]}"; do
  cache_file=""
  if cache_file="$(cache_path_for_url "${URLS[$i]}")" && cache_is_fresh "$cache_file"; then
    cp "$cache_file" "${TMP_DIR}/dl.${i}"
    DL_FROM_CACHE[i]=1
    DL_PIDS[i]=""
    continue
  fi

  DL_FROM_CACHE[i]=0
  (
    curl "${CURL_OPTS[@]}" "${URLS[$i]}" -o "${TMP_DIR}/dl.${i}" 2>/dev/null
    if [ -n "$cache_file" ]; then
      tmp_cache="${cache_file}.$$.tmp"
      if cp "${TMP_DIR}/dl.${i}" "$tmp_cache" 2>/dev/null; then
        mv "$tmp_cache" "$cache_file" 2>/dev/null || rm -f "$tmp_cache"
      else
        rm -f "$tmp_cache"
      fi
    fi
  ) &
  DL_PIDS[i]="$!"
done

declare -a DL_OK=()
declare -a DL_FAIL=()
for i in "${!URLS[@]}"; do
  if [ "${DL_FROM_CACHE[$i]:-0}" -eq 1 ]; then
    DL_OK+=("$i")
  elif wait "${DL_PIDS[$i]}" 2>/dev/null; then
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
