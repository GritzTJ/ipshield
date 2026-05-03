#!/bin/bash
set -euo pipefail
umask 077

# Cron on Debian/Ubuntu typically runs with PATH=/usr/bin:/bin, which omits
# /sbin and /usr/sbin where ipset, iptables, ip6tables, nft and ip live.
# Prepend the standard system paths so the script behaves the same under
# cron, systemd and interactive shells. Non-existent directories are
# harmlessly ignored by PATH lookup.
export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}"

# --- Usage / help ---
usage() {
  cat <<'EOF'
Usage: update-blocklist.sh [OPTIONS]

Update a blocking ipset from public lists, then detect the active
firewall and apply the blocking rules.

Options:
  -n, --dry-run       Simulation mode (no ipset/firewall change)
  -v, --verbose       Verbose output (per-source stats, diff details)
  -c, --config FILE   Configuration file path
  -h, --help          Show this help

Resolution order: defaults -> config -> CLI.
EOF
  exit 0
}

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: this script must be run as root." >&2
  exit 1
fi

# --- CLI parsing ---
CLI_DRY_RUN=""
CLI_VERBOSE=""
CONF_FILE="/etc/update-blocklist.conf"

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run)  CLI_DRY_RUN=1; shift ;;
    -v|--verbose)  CLI_VERBOSE=1; shift ;;
    -c|--config)
      [ $# -ge 2 ] || { echo "Error: --config requires an argument." >&2; exit 1; }
      CONF_FILE="$2"; shift 2 ;;
    -h|--help)     usage ;;
    *)             echo "Unknown option: $1" >&2; usage ;;
  esac
done

# --- Variable initialisation (values come from the conf file) ---
URLS=()
WHITELIST=()
DRY_RUN=0
VERBOSE=0
WAN_INTERFACE=""

# --- Source config file (REQUIRED) ---
# The conf file is the single source of truth. setup-firewall.sh copies it
# from update-blocklist.conf.example when missing.
if [ ! -f "$CONF_FILE" ]; then
  echo "Error: configuration file $CONF_FILE not found." >&2
  echo "Run ./setup-firewall.sh to install it, or manually copy" >&2
  echo "update-blocklist.conf.example to $CONF_FILE." >&2
  exit 1
fi
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
# shellcheck source=/dev/null
. "$CONF_FILE"

# --- Apply CLI overrides (precedence over config) ---
[ -n "$CLI_DRY_RUN" ] && DRY_RUN=1
[ -n "$CLI_VERBOSE" ] && VERBOSE=1

# --- Validate required variables (defined in the conf file) ---
if [ "${#URLS[@]}" -eq 0 ]; then
  echo "Error: URLS is empty or undefined in $CONF_FILE." >&2
  echo "The file must define a URLS=(...) array with at least one source." >&2
  exit 1
fi
for var in SET_NAME MIN_ENTRIES BASE_HASHSIZE BASE_MAXELEM WHITELIST_MIN_PREFIX; do
  if [ -z "${!var:-}" ]; then
    echo "Error: required variable '$var' missing or empty in $CONF_FILE." >&2
    exit 1
  fi
done
for var in MIN_ENTRIES BASE_HASHSIZE BASE_MAXELEM; do
  if ! [[ "${!var}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: $var invalid ('${!var}'). Positive integer expected." >&2
    exit 1
  fi
done

# --- SET_NAME validation ---
if [[ ! "$SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Error: SET_NAME invalid ('$SET_NAME'). Only [a-zA-Z0-9_-] allowed." >&2
  exit 1
fi

# --- Whitelist set name (derived from SET_NAME if undefined) ---
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

# --- WHITELIST_MIN_PREFIX validation ---
if ! [[ "$WHITELIST_MIN_PREFIX" =~ ^[0-9]+$ ]] || [ "$WHITELIST_MIN_PREFIX" -lt 0 ] || [ "$WHITELIST_MIN_PREFIX" -gt 32 ]; then
  echo "Error: WHITELIST_MIN_PREFIX invalid ('$WHITELIST_MIN_PREFIX'). Integer 0-32 expected." >&2
  exit 1
fi

# --- BLOCKLIST_MIN_PREFIX validation (safeguard against overly broad source entries) ---
# Rejects external blocklist entries with a prefix shorter than the threshold.
# Default 8 prevents a corrupted/malicious source from injecting 0.0.0.0/0
# (which ipset would normalise to "match any IP" -> total server lockout).
: "${BLOCKLIST_MIN_PREFIX:=8}"
if ! [[ "$BLOCKLIST_MIN_PREFIX" =~ ^[0-9]+$ ]] || [ "$BLOCKLIST_MIN_PREFIX" -lt 0 ] || [ "$BLOCKLIST_MIN_PREFIX" -gt 32 ]; then
  echo "Error: BLOCKLIST_MIN_PREFIX invalid ('$BLOCKLIST_MIN_PREFIX'). Integer 0-32 expected." >&2
  exit 1
fi

# --- LOG_LIMIT / LOG_BURST validation ---
# Empty LOG_LIMIT = log everything (no rate-limit)
if [ -n "$LOG_LIMIT" ]; then
  if ! [[ "$LOG_LIMIT" =~ ^[0-9]+/(sec|second|min|minute|hour|day)$ ]]; then
    echo "Error: LOG_LIMIT invalid ('$LOG_LIMIT'). Expected format: N/(sec|min|hour|day) or empty." >&2
    exit 1
  fi
  if ! [[ "$LOG_BURST" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: LOG_BURST invalid ('$LOG_BURST'). Positive integer expected." >&2
    exit 1
  fi
fi

# --- Auto-detect WAN interface if not defined ---
# Used to scope the DOCKER-USER rule to inbound traffic only.
if [ -z "$WAN_INTERFACE" ]; then
  WAN_INTERFACE="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}' || true)"
fi
if [ -n "$WAN_INTERFACE" ] && [[ ! "$WAN_INTERFACE" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "Error: WAN_INTERFACE invalid ('$WAN_INTERFACE')." >&2
  exit 1
fi

# --- ipset persistence validation ---
: "${PERSIST_IPSET:=1}"
: "${IPSET_SAVE_FILE:=/var/lib/ipshield/ipset.save}"
if ! [[ "$PERSIST_IPSET" =~ ^[01]$ ]]; then
  echo "Error: PERSIST_IPSET invalid ('$PERSIST_IPSET'). Expected 0 or 1." >&2
  exit 1
fi
if [ "$PERSIST_IPSET" -eq 1 ]; then
  if [[ "$IPSET_SAVE_FILE" != /* ]] || [[ "$IPSET_SAVE_FILE" =~ [[:space:]] ]]; then
    echo "Error: IPSET_SAVE_FILE invalid ('$IPSET_SAVE_FILE'). Absolute path without whitespace expected." >&2
    exit 1
  fi
fi

# --- Derived variables ---
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
CURL_OPTS=( -fsSL --compressed --connect-timeout 10 --max-time 30 --max-filesize 10485760 --retry 3 --retry-delay 2 --retry-all-errors )

if [ "${#TEMP_SET}" -gt 31 ]; then
  echo "Error: temporary set name too long (${#TEMP_SET} > 31)" >&2
  exit 1
fi
if [ "${#WL_TEMP_SET}" -gt 31 ]; then
  echo "Error: temporary whitelist set name too long (${#WL_TEMP_SET} > 31)" >&2
  exit 1
fi

# --- Functions ---
log() { echo "$*"; logger -t "update-blocklist" "$*" 2>/dev/null || true; }
err() { echo "$*" >&2; logger -t "update-blocklist" -p user.err "$*" 2>/dev/null || true; }
fmt_num() { printf "%d" "$1" | sed ':a;s/\([0-9]\)\([0-9]\{3\}\)\($\| \)/\1 \2\3/;ta'; }

cleanup() {
  rm -rf -- "$TMP_DIR" 2>/dev/null || true
  ipset destroy "$TEMP_SET" 2>/dev/null || true
  ipset destroy "$WL_TEMP_SET" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Error: missing command: $1"; exit 1; }; }

# --- Active firewall detection ---
detect_firewall() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
    return
  fi

  # Anchor the match so "Status: inactive" is not treated as "active".
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE "^Status: active$"; then
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
    # Skip leftover ufw chains if ufw is installed but inactive
    if ! command -v ufw >/dev/null 2>&1 || ! iptables -L -n 2>/dev/null | grep -q "^Chain ufw-"; then
      echo "iptables"
      return
    fi
  fi

  echo "none"
}

# --- Docker detection (DOCKER-USER chain) ---
detect_docker() {
  iptables -L DOCKER-USER -n >/dev/null 2>&1
}

# --- Remove iptables rules matching a grep -E pattern on a chain ---
# Handles drift on any parameter (LOG_LIMIT, -i iface, etc.) by removing
# any rule that matches the pattern, regardless of its other flags.
_remove_matching_rules() {
  local chain="$1"
  local pattern="$2"
  local line rule_num n
  while true; do
    rule_num=""
    n=0
    while IFS= read -r line; do
      [[ "$line" == "-A $chain "* ]] || continue
      n=$((n + 1))
      if printf '%s\n' "$line" | grep -qE -- "$pattern"; then
        rule_num="$n"
        break
      fi
    done < <(iptables -S "$chain" 2>/dev/null || true)
    [ -z "$rule_num" ] && break
    iptables -D "$chain" "$rule_num"
  done
}

# --- ufw before.rules hygiene ---
_ufw_referenced_sets() {
  [ -f /etc/ufw/before.rules ] || return 0
  grep -oE -- "-A ufw-before-input -m set --match-set [^ ]+ src" /etc/ufw/before.rules 2>/dev/null \
    | awk '{print $6}' \
    | sort -u
}

_ipset_exists() {
  local set="$1"
  ipset list -n 2>/dev/null | awk -v s="$set" '$0==s{found=1} END{exit(found?0:1)}'
}

_create_empty_ipset_if_missing() {
  local set="$1"
  _ipset_exists "$set" && return 1
  ipset create "$set" "$IPSET_TYPE" family "$IPSET_FAMILY" hashsize "$BASE_HASHSIZE" maxelem "$BASE_MAXELEM"
  return 0
}

_ufw_preflight_ipsets() {
  [ -f /etc/ufw/before.rules ] || return 0

  local changed=0
  local ref_set
  local orphans=()
  local snapshot=""

  while IFS= read -r ref_set; do
    [ -z "$ref_set" ] && continue
    case "$ref_set" in
      "$SET_NAME")
        if _create_empty_ipset_if_missing "$SET_NAME"; then
          log "ufw: created missing ipset $SET_NAME before firewall reload."
          changed=1
        fi
        ;;
      "$WHITELIST_SET_NAME")
        if [ "${#WHITELIST[@]}" -gt 0 ]; then
          if _create_empty_ipset_if_missing "$WHITELIST_SET_NAME"; then
            log "ufw: created missing ipset $WHITELIST_SET_NAME before firewall reload."
            changed=1
          fi
        else
          orphans+=("$ref_set")
        fi
        ;;
      *)
        if ! _ipset_exists "$ref_set"; then
          orphans+=("$ref_set")
        fi
        ;;
    esac
  done < <(_ufw_referenced_sets)

  if [ "${#orphans[@]}" -gt 0 ]; then
    cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
    snapshot="${TMP_DIR}/ufw-before.rules.preflight"
    cp /etc/ufw/before.rules "$snapshot"
    for ref_set in "${orphans[@]}"; do
      sed -i "\\|^-A ufw-before-input -m set --match-set $ref_set src |d" /etc/ufw/before.rules
    done
    log "ufw: removed orphan rule(s) referencing nonexistent or inactive ipset(s): ${orphans[*]}"
    changed=1
  fi

  if [ "$changed" -eq 1 ] && command -v ufw >/dev/null 2>&1; then
    if ! ufw reload; then
      if [ -n "$snapshot" ] && [ -f "$snapshot" ]; then
        cp "$snapshot" /etc/ufw/before.rules
        err "ufw: reload failed after preflight; restored /etc/ufw/before.rules snapshot."
      fi
      return 1
    fi
  fi
}

_save_persistent_ipsets() {
  [ "$PERSIST_IPSET" -eq 1 ] || return 0

  local save_dir save_tmp
  save_dir="$(dirname "$IPSET_SAVE_FILE")"
  mkdir -p "$save_dir"
  save_tmp="$(mktemp -p "$save_dir" ".ipset.save.XXXXXX")"

  if _ipset_exists "$SET_NAME"; then
    ipset save "$SET_NAME" > "$save_tmp"
  else
    : > "$save_tmp"
  fi
  if _ipset_exists "$WHITELIST_SET_NAME"; then
    ipset save "$WHITELIST_SET_NAME" >> "$save_tmp"
  fi

  chmod 600 "$save_tmp"
  mv "$save_tmp" "$IPSET_SAVE_FILE"
  log "ipset persistence saved: $IPSET_SAVE_FILE"
}

# --- Idempotent insertion/update of LOG + DROP rules on an iptables chain ---
# $1: chain (INPUT, DOCKER-USER, ...)
# $2: optional interface (empty = no constraint). Used for DOCKER-USER to
#     filter only INBOUND traffic from the Internet (not container egress).
# Detects drift on LOG_LIMIT/LOG_BURST and on the presence/absence of -i.
_apply_iptables_rules() {
  local chain="$1"
  local iface="${2:-}"
  local actioned=0

  local iface_args=()
  [ -n "$iface" ] && iface_args=( -i "$iface" )

  local log_args=( "${iface_args[@]}" -m set --match-set "$SET_NAME" src )
  if [ -n "$LOG_LIMIT" ]; then
    log_args+=( -m limit --limit "$LOG_LIMIT" --limit-burst "$LOG_BURST" )
  fi
  log_args+=( -j LOG --log-prefix "BLOCKED: " --log-level 4 )

  local drop_args=( "${iface_args[@]}" -m set --match-set "$SET_NAME" src -j DROP )

  # LOG: if the exact rule (current values + iface) does not exist,
  # remove any existing ipshield LOG rule (generic pattern) then insert.
  if ! iptables -C "$chain" "${log_args[@]}" 2>/dev/null; then
    _remove_matching_rules "$chain" "--match-set $SET_NAME src.*-j LOG --log-prefix \"BLOCKED: \""
    iptables -I "$chain" 1 "${log_args[@]}"
    actioned=1
  fi

  # DROP: same pattern (drift on -i possible).
  if ! iptables -C "$chain" "${drop_args[@]}" 2>/dev/null; then
    _remove_matching_rules "$chain" "--match-set $SET_NAME src.*-j DROP$"
    iptables -I "$chain" 2 "${drop_args[@]}"
    actioned=1
  fi

  [ "$actioned" -eq 1 ] && return 0 || return 1
}

# --- Idempotent insertion of the whitelist ACCEPT rule at position 1 ---
# $1: chain
# $2: optional interface (same as _apply_iptables_rules)
_apply_whitelist_iptables() {
  local chain="$1"
  local iface="${2:-}"
  local iface_args=()
  [ -n "$iface" ] && iface_args=( -i "$iface" )
  local accept_args=( "${iface_args[@]}" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT )

  # Check that the ACCEPT rule (with or without iface) is the first one
  local first_rule
  first_rule="$(iptables -S "$chain" 2>/dev/null | grep -E "^-A" | head -1 || true)"
  local expected_pattern
  if [ -n "$iface" ]; then
    expected_pattern="-i $iface .*--match-set $WHITELIST_SET_NAME src .*-j ACCEPT$"
  else
    expected_pattern="^-A $chain -m set --match-set $WHITELIST_SET_NAME src -j ACCEPT$"
  fi
  if echo "$first_rule" | grep -qE -- "$expected_pattern"; then
    return
  fi

  # Otherwise: remove all variants (with or without iface) and reinsert at pos 1
  _remove_matching_rules "$chain" "--match-set $WHITELIST_SET_NAME src.*-j ACCEPT"
  iptables -I "$chain" 1 "${accept_args[@]}"
}

# --- Remove whitelist ACCEPT rules (all occurrences, with or without iface) ---
_cleanup_whitelist_iptables() {
  local chain="$1"
  _remove_matching_rules "$chain" "--match-set $WHITELIST_SET_NAME src.*-j ACCEPT"
}

# --- Apply or clean up whitelist on an iptables chain ---
_whitelist_or_cleanup_iptables() {
  local chain="$1"
  local iface="${2:-}"
  if [ "${#WHITELIST[@]}" -gt 0 ]; then
    _apply_whitelist_iptables "$chain" "$iface"
  else
    _cleanup_whitelist_iptables "$chain"
  fi
}

# --- Apply or clean up whitelist on firewalld (returns 0 if action taken) ---
# $1: chain
# $2: optional interface (used for DOCKER-USER to scope the ACCEPT to inbound
#     traffic, mirroring _apply_whitelist_iptables). If empty, no -i is set
#     (legacy behaviour; matches INPUT and existing rules without iface).
_whitelist_or_cleanup_firewalld() {
  local chain="$1"
  local iface="${2:-}"
  local iface_args=()
  [ -n "$iface" ] && iface_args=( -i "$iface" )
  if [ "${#WHITELIST[@]}" -gt 0 ]; then
    if ! firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 0 "${iface_args[@]}" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; then
      firewall-cmd --permanent --direct --add-rule ipv4 filter "$chain" 0 "${iface_args[@]}" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
      return 0
    fi
  else
    if firewall-cmd --permanent --direct --query-rule ipv4 filter "$chain" 0 "${iface_args[@]}" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT 2>/dev/null; then
      firewall-cmd --permanent --direct --remove-rule ipv4 filter "$chain" 0 "${iface_args[@]}" -m set --match-set "$WHITELIST_SET_NAME" src -j ACCEPT
      return 0
    fi
  fi
  return 1
}

# --- Firewall rules application ---
apply_firewall_rules() {
  local fw="$1"

  local docker_protected=0

  # Warn if WAN interface could not be detected: DOCKER-USER will be filtered
  # without -i (legacy behaviour). The bogon filter prevents the LAN/Docker
  # from being falsely blocked, but container egress to a real public
  # blacklisted IP would still be dropped.
  if [ -z "$WAN_INTERFACE" ] && detect_docker; then
    err "Warning: WAN_INTERFACE not detected. The DOCKER-USER rule will filter"
    err "  in both directions. Set WAN_INTERFACE in $CONF_FILE to scope it."
  fi

  case "$fw" in
    iptables)
      _apply_iptables_rules INPUT && log "iptables rules added (LOG + DROP)."
      _whitelist_or_cleanup_iptables INPUT
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER "$WAN_INTERFACE" && log "iptables DOCKER-USER rules added (LOG + DROP, inbound on ${WAN_INTERFACE:-all interfaces})."
        _whitelist_or_cleanup_iptables DOCKER-USER "$WAN_INTERFACE"
        docker_protected=1
      fi
      ;;

    nftables)
      # nftables cannot reference ipset sets natively (@set syntax only applies
      # to native nft sets). We use iptables (iptables-nft), which translates
      # commands to nft rules while supporting ipset matching via the kernel
      # xt_set module.
      need_cmd iptables
      _apply_iptables_rules INPUT && log "nftables rules added via iptables-nft (LOG + DROP)."
      _whitelist_or_cleanup_iptables INPUT
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER "$WAN_INTERFACE" && log "nftables DOCKER-USER rules added via iptables-nft (LOG + DROP, inbound on ${WAN_INTERFACE:-all interfaces})."
        _whitelist_or_cleanup_iptables DOCKER-USER "$WAN_INTERFACE"
        docker_protected=1
      fi
      ;;

    firewalld)
      local need_reload=0
      # Build LOG args according to LOG_LIMIT
      local fw_log_args=( -m set --match-set "$SET_NAME" src )
      if [ -n "$LOG_LIMIT" ]; then
        fw_log_args+=( -m limit --limit "$LOG_LIMIT" --limit-burst "$LOG_BURST" )
      fi
      fw_log_args+=( -j LOG --log-prefix "BLOCKED: " --log-level 4 )

      if ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 1 -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 "${fw_log_args[@]}"
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
        need_reload=1
        log "firewalld rules added (LOG + DROP)."
      fi
      _whitelist_or_cleanup_firewalld INPUT && need_reload=1
      if detect_docker; then
        # DOCKER-USER: add -i WAN_INTERFACE if defined (inbound filter only)
        local docker_iface_args=()
        [ -n "$WAN_INTERFACE" ] && docker_iface_args=( -i "$WAN_INTERFACE" )
        local docker_log_args=( "${docker_iface_args[@]}" -m set --match-set "$SET_NAME" src )
        if [ -n "$LOG_LIMIT" ]; then
          docker_log_args+=( -m limit --limit "$LOG_LIMIT" --limit-burst "$LOG_BURST" )
        fi
        docker_log_args+=( -j LOG --log-prefix "BLOCKED: " --log-level 4 )
        if ! firewall-cmd --permanent --direct --query-rule ipv4 filter DOCKER-USER 1 "${docker_iface_args[@]}" -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
          firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 0 "${docker_log_args[@]}"
          firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER 1 "${docker_iface_args[@]}" -m set --match-set "$SET_NAME" src -j DROP
          need_reload=1
          log "firewalld DOCKER-USER rules added (LOG + DROP, inbound on ${WAN_INTERFACE:-all interfaces})."
        fi
        _whitelist_or_cleanup_firewalld DOCKER-USER "$WAN_INTERFACE" && need_reload=1
        docker_protected=1
      fi
      [ "$need_reload" -eq 1 ] && firewall-cmd --reload
      ;;

    ufw)
      _ufw_preflight_ipsets

      if ! grep -q "match-set $SET_NAME src" /etc/ufw/before.rules 2>/dev/null; then
        # Backup before modification (protects against sed corruption)
        cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
        # Build the LOG line according to LOG_LIMIT
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
        log "ufw rules added (LOG + DROP)."
      fi
      # Whitelist: add or remove from before.rules at the top of ufw-before-input
      local wl_marker="match-set $WHITELIST_SET_NAME src -j ACCEPT"
      local wl_present=0
      grep -q "$wl_marker" /etc/ufw/before.rules 2>/dev/null && wl_present=1
      if [ "${#WHITELIST[@]}" -gt 0 ] && [ "$wl_present" -eq 0 ]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
        # Insert the ACCEPT rule just before the FIRST ufw-before-input blocklist rule.
        # The "0,/pattern/" range scopes the inner /pattern/i action to the first match
        # only, otherwise sed would insert the ACCEPT before every matching rule (LOG + DROP).
        sed -i "0,/-A ufw-before-input -m set --match-set $SET_NAME src/{
/-A ufw-before-input -m set --match-set $SET_NAME src/i\\
-A ufw-before-input -m set --match-set $WHITELIST_SET_NAME src -j ACCEPT
}" /etc/ufw/before.rules
        ufw reload
        log "ufw whitelist rule added (ACCEPT)."
      elif [ "${#WHITELIST[@]}" -eq 0 ] && [ "$wl_present" -eq 1 ]; then
        cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
        sed -i "/match-set $WHITELIST_SET_NAME src -j ACCEPT/d" /etc/ufw/before.rules
        ufw reload
        log "ufw whitelist rule removed (ACCEPT)."
      fi
      # Docker uses iptables directly, outside ufw scope
      if detect_docker; then
        _apply_iptables_rules DOCKER-USER "$WAN_INTERFACE" && log "DOCKER-USER rules added (LOG + DROP, inbound on ${WAN_INTERFACE:-all interfaces})."
        _whitelist_or_cleanup_iptables DOCKER-USER "$WAN_INTERFACE"
        docker_protected=1
      fi
      ;;
  esac

  if [ "$docker_protected" -eq 1 ]; then
    log "Docker detected: the DOCKER-USER chain is protected."
  fi
}

# --- Dependency check ---
need_cmd curl
need_cmd awk
need_cmd sort
need_cmd ipset
need_cmd flock
need_cmd wc
need_cmd date
need_cmd comm

# --- Lock ---
mkdir -p "$LOCK_DIR"
log "--- Update on $(date '+%Y-%m-%d %H:%M:%S %Z') ---"

exec 9>"$LOCK_FILE"
flock -n 9 || { err "Error: another instance is already running."; exit 1; }

# Repair ufw rules before network access. If ufw/iptables-nft failed during
# boot because ipsets were missing, this can restore firewall state before curl
# needs DNS responses.
if [ "$DRY_RUN" -eq 0 ] && [ -f /etc/ufw/before.rules ]; then
  _ufw_preflight_ipsets
fi

# --- HTTP source warning ---
for url in "${URLS[@]}"; do
  if [[ "$url" =~ ^http:// ]]; then
    err "Warning: HTTP (unencrypted) source: $url"
  fi
done

# --- Parallel downloads ---
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
    log "Download OK: ${URLS[$i]}"
  else
    fail=$((fail+1))
    err "ERROR: download failed: ${URLS[$i]}"
  fi
done

# --- Failure policy ---
if [ "$ok" -eq 0 ]; then
  err "Error: no source available. Aborting update."
  exit 1
fi
if [ "$fail" -ne 0 ]; then
  err "Warning: $fail source(s) unavailable. Updating with $ok available source(s)."
fi

# --- Sequential processing: fused awk (extraction + validation) + per-source stats ---
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

for i in "${DL_OK[@]}"; do
  awk -v min_prefix="$BLOCKLIST_MIN_PREFIX" "$AWK_PROG" "${TMP_DIR}/dl.${i}" > "${TMP_DIR}/src.${i}"
  src_count="$(wc -l < "${TMP_DIR}/src.${i}")"
  if [ "$VERBOSE" -eq 1 ]; then
    log "  Source $((i+1))/${#URLS[@]}: $(fmt_num "$src_count") valid entries -- ${URLS[$i]}"
  fi
done

# --- WHITELIST entries validation (same rules as external lists) ---
if [ "${#WHITELIST[@]}" -gt 0 ]; then
  : > "$WL_FILE"
  invalid_wl=()
  too_wide_wl=()
  for entry in "${WHITELIST[@]}"; do
    # allow_bogons=1: the whitelist may contain RFC1918 (LAN management)
    canonical="$(printf '%s\n' "$entry" | awk -v allow_bogons=1 "$AWK_PROG")"
    if [ -z "$canonical" ]; then
      invalid_wl+=("$entry")
      continue
    fi
    # Safeguard: reject overly broad prefixes (typo /0 = total bypass)
    prefix="${canonical##*/}"
    if [ "$prefix" -lt "$WHITELIST_MIN_PREFIX" ]; then
      too_wide_wl+=("$entry (canonical: $canonical, prefix /$prefix < threshold /$WHITELIST_MIN_PREFIX)")
      continue
    fi
    printf '%s\n' "$canonical" >> "$WL_FILE"
  done
  if [ "${#invalid_wl[@]}" -gt 0 ]; then
    err "Error: invalid WHITELIST entry(ies):"
    for entry in "${invalid_wl[@]}"; do
      err "  - '$entry'"
    done
    exit 1
  fi
  if [ "${#too_wide_wl[@]}" -gt 0 ]; then
    err "Error: WHITELIST entry(ies) with overly wide prefix (massive bypass risk):"
    for entry in "${too_wide_wl[@]}"; do
      err "  - $entry"
    done
    err "To allow a wider prefix, lower WHITELIST_MIN_PREFIX in the config."
    exit 1
  fi
  # Dedup + sort
  sort -u "$WL_FILE" -o "$WL_FILE"
  wl_count="$(wc -l < "$WL_FILE")"
  log "Whitelist: $(fmt_num "$wl_count") entry(ies)."
fi

cat "${TMP_DIR}"/src.* 2>/dev/null | sort -u > "$UNIQ_FILE" || true

if [ ! -s "$UNIQ_FILE" ]; then
  err "Error: no valid IP/CIDR retrieved. Aborting."
  exit 1
fi

entries_count="$(wc -l < "$UNIQ_FILE")"

# --- Minimum safety threshold ---
if [ "$entries_count" -lt "$MIN_ENTRIES" ]; then
  err "Error: only $(fmt_num "$entries_count") entries (minimum expected: $(fmt_num "$MIN_ENTRIES")). Possible source anomaly. Aborting."
  exit 1
fi

# --- Compute hashsize / maxelem ---
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

log "Valid entries : $(fmt_num "$entries_count")"
log "ipset params  : hashsize=$(fmt_num "$IPSET_HASHSIZE") maxelem=$(fmt_num "$IPSET_MAXELEM")"

# --- Dry-run mode ---
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] $(fmt_num "$entries_count") entries would be applied."
  # In dry-run, also show the diff report if the set exists
  if ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
    # Pipe straight to file (avoids holding 1M+ entries in a variable)
    ipset list "$SET_NAME" 2>/dev/null \
      | awk '/^Members:/{p=1;next} p{x=$1; if (x!="" && index(x,"/")==0) x=x"/32"; if (x!="") print x}' \
      | sort -u > "${TMP_DIR}/old_members"
    added="$(comm -13 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    removed="$(comm -23 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    unchanged="$(comm -12 "${TMP_DIR}/old_members" "$UNIQ_FILE" | wc -l)"
    log "Diff: +$(fmt_num "$added") added, -$(fmt_num "$removed") removed, =$(fmt_num "$unchanged") unchanged"
  fi
  # Whitelist: announce what would happen
  if [ "${#WHITELIST[@]}" -gt 0 ]; then
    log "[DRY-RUN] Whitelist: $(fmt_num "$(wc -l < "$WL_FILE")") entry(ies) would be applied (set $WHITELIST_SET_NAME, ACCEPT rule)."
  else
    if ipset list -n 2>/dev/null | awk -v s="$WHITELIST_SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
      log "[DRY-RUN] Empty whitelist: set $WHITELIST_SET_NAME and the ACCEPT rule would be removed."
    fi
  fi
  # Show the detected firewall even in dry-run
  DETECTED_FW="$(detect_firewall)"
  log "[DRY-RUN] Detected firewall: $DETECTED_FW"
  if detect_docker; then
    log "[DRY-RUN] Docker detected: rules would also be applied on DOCKER-USER."
  fi
  exit 0
fi

# --- Existing set check (ipset list -t = headers only, no member dump) ---
SET_EXISTS=0
if ipset list -n 2>/dev/null | awk -v s="$SET_NAME" '$0==s{found=1} END{exit(found?0:1)}'; then
  SET_EXISTS=1
  set_header="$(ipset list -t "$SET_NAME" 2>/dev/null)"
  existing_type="$(echo "$set_header" | awk -F': ' '/^Type: /{print $2; exit}')"
  existing_family="$(echo "$set_header" | awk -F': ' '/^Header: /{h=$2} END{if (h ~ /family inet6/) print "inet6"; else if (h ~ /family inet/) print "inet"; else print ""}')"
  if [ "$existing_type" != "$IPSET_TYPE" ] || [ "$existing_family" != "$IPSET_FAMILY" ]; then
    err "Error: set '$SET_NAME' exists but type/family incompatible (type=$existing_type family=$existing_family). Expected: type=$IPSET_TYPE family=$IPSET_FAMILY. Aborting."
    exit 1
  fi
fi

# --- Generate restore file ---
{
  echo "create $TEMP_SET $IPSET_TYPE family $IPSET_FAMILY hashsize $IPSET_HASHSIZE maxelem $IPSET_MAXELEM"
  awk -v set="$TEMP_SET" '{print "add " set " " $1 " -exist"}' "$UNIQ_FILE"
} > "$TMP_FILE"

if [ "$(wc -l < "$TMP_FILE")" -le 1 ]; then
  err "Error: no entry to add in restore. Aborting."
  exit 1
fi

# --- Diff report (verbose only, pipe straight to file) ---
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
      log "Diff: +$(fmt_num "$added") added, -$(fmt_num "$removed") removed, =$(fmt_num "$unchanged") unchanged"
    fi
  else
    log "Diff: +$(fmt_num "$entries_count") added (new set)"
  fi
fi

# --- Ensure final set exists (required for swap) ---
if [ "$SET_EXISTS" -eq 0 ]; then
  ipset create "$SET_NAME" "$IPSET_TYPE" family "$IPSET_FAMILY" hashsize "$IPSET_HASHSIZE" maxelem "$IPSET_MAXELEM"
fi

# --- Destroy temp set if it exists ---
ipset destroy "$TEMP_SET" 2>/dev/null || true

# --- Atomic swap ---
ipset restore < "$TMP_FILE"
ipset swap "$SET_NAME" "$TEMP_SET"
ipset destroy "$TEMP_SET"

total="$(ipset list -t "$SET_NAME" | awk -F': ' '/Number of entries/{print $2}')"
log "Total blocked IPs: $(fmt_num "$total")"

# --- Whitelist: atomic build/swap if non-empty ---
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
  log "Whitelist active: $(fmt_num "$wl_entries") entry(ies) in $WHITELIST_SET_NAME."
fi

# --- Firewall rules check / apply ---
DETECTED_FW="$(detect_firewall)"
if [ "$DETECTED_FW" != "none" ]; then
  if detect_docker; then
    log "Detected firewall: $DETECTED_FW (Docker present, DOCKER-USER chain found)"
  else
    log "Detected firewall: $DETECTED_FW"
  fi
  apply_firewall_rules "$DETECTED_FW"
else
  err "No firewall detected. IPs are in the ipset but no blocking rule is active."
  err "Run setup-firewall.sh to install a firewall, or install one manually."
fi

# --- Empty whitelist: destroy the set after rules have been removed ---
if [ "${#WHITELIST[@]}" -eq 0 ] && [ "$WL_SET_EXISTS" -eq 1 ]; then
  if ipset destroy "$WHITELIST_SET_NAME" 2>/dev/null; then
    log "Empty whitelist: ipset $WHITELIST_SET_NAME destroyed."
  else
    err "Warning: cannot destroy $WHITELIST_SET_NAME (still referenced?)."
  fi
fi

_save_persistent_ipsets
