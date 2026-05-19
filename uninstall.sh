#!/bin/bash
# ipshield v1.0.0
set -euo pipefail
umask 077

# Ensure /sbin and /usr/sbin are in PATH (ipset, iptables, ufw, firewall-cmd,
# nft live there on Debian/Ubuntu). Same rationale as update-blocklist.sh.
export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}"

# --- Usage / help ---
usage() {
  cat <<'EOF'
Usage: uninstall.sh [OPTIONS]

Removes ipshield blocking rules and destroys the associated ipsets.
Defaults to dry-run mode (shows what would be done, without modifying
anything).

Options:
  --apply             Actually apply the uninstall (otherwise dry-run).
  -c, --config FILE   Configuration file path (default: /etc/update-blocklist.conf).
  -h, --help          Show this help.

This script:
  - removes ipshield rules (LOG + DROP blocklist, ACCEPT whitelist) on INPUT
    and DOCKER-USER (if Docker is present);
  - destroys ipsets $SET_NAME and $WHITELIST_SET_NAME;
  - removes ipshield/orphan rules from /etc/ufw/before.rules line by line (ufw);
  - removes ipshield-restore.service, ipshield-apply.service,
    ipshield-safe-ports.service, the nftables.service drop-in, and the
    safe-ports configuration files;
  - restores /etc/nftables.conf from its .ipshield.bak backup when present;
  - removes ipshield cron lines from root's crontab; reports (without
    modifying) lines in /etc/crontab and /etc/cron.d/*;
  - removes the rsyslog filter (30-blocked-ips.conf) and logrotate configs;
  - optionally removes /etc/update-blocklist.conf and the ipset save file
    (separate prompt -- user-editable data);
  - optionally removes /var/log/update-blocklist.log + /var/log/blocked-ips.log
    and their rotated copies (separate prompt -- historical data).

It does NOT uninstall the firewall or any packages (ipset, iptables, etc.).
EOF
  exit 0
}

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: this script must be run as root." >&2
  exit 1
fi

# --- CLI parsing ---
APPLY=0
CONF_FILE="/etc/update-blocklist.conf"

while [ $# -gt 0 ]; do
  case "$1" in
    --apply)         APPLY=1; shift ;;
    -c|--config)
      [ $# -ge 2 ] || { echo "Error: --config requires an argument." >&2; exit 1; }
      CONF_FILE="$2"; shift 2 ;;
    -h|--help)       usage ;;
    *)               echo "Unknown option: $1" >&2; usage ;;
  esac
done

# --- Defaults ---
SET_NAME="blacklist"

# --- Source config (same checks as update-blocklist.sh) ---
if [ -f "$CONF_FILE" ]; then
  conf_owner="$(stat -c '%u' "$CONF_FILE")"
  conf_perms="$(stat -c '%a' "$CONF_FILE")"
  if [ "$conf_owner" != "0" ]; then
    echo "Error: $CONF_FILE is not owned by root (uid=$conf_owner)." >&2
    exit 1
  fi
  conf_low="${conf_perms: -3}"
  if (( (8#$conf_low & 8#022) != 0 )); then
    echo "Error: $CONF_FILE is group/world-writable (perms=$conf_perms)." >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  . "$CONF_FILE"
fi

# SET_NAME validation
if [[ ! "$SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Error: SET_NAME invalid ('$SET_NAME')." >&2
  exit 1
fi
if [ "${#SET_NAME}" -gt 31 ]; then
  echo "Error: SET_NAME too long (${#SET_NAME} > 31)." >&2
  exit 1
fi
: "${WHITELIST_SET_NAME:=${SET_NAME}-allow}"
if [[ ! "$WHITELIST_SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Error: WHITELIST_SET_NAME invalid ('$WHITELIST_SET_NAME')." >&2
  exit 1
fi
if [ "${#WHITELIST_SET_NAME}" -gt 31 ]; then
  echo "Error: WHITELIST_SET_NAME too long (${#WHITELIST_SET_NAME} > 31)." >&2
  exit 1
fi
: "${PERSIST_IPSET:=1}"
: "${IPSET_SAVE_FILE:=/var/lib/ipshield/ipset.save}"
: "${SOURCE_CACHE_DIR:=/var/lib/ipshield/sources}"

# --- Lock shared with update-blocklist.sh (anti-race against cron) ---
# Without this lock, an update-blocklist.sh cron run could re-create the rules
# between uninstall removing them and destroying the ipsets, leaving a
# partially-installed state.
LOCK_DIR="/run/lock"
LOCK_FILE="${LOCK_DIR}/${SET_NAME}.lock"
mkdir -p "$LOCK_DIR"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "Error: update-blocklist.sh is already running; retry in a few seconds." >&2
  exit 1
fi

# --- Functions ---
log() { echo "$*"; }
err() { echo "$*" >&2; }

# --- Uniform yes/no prompt with default ---
# Usage: ask_yes_no "Question" yes|no
# Returns: 0 if yes, 1 if no. Empty input = default. Invalid input = re-ask.
ask_yes_no() {
  local prompt="$1"
  local default="$2"
  local hint
  if [ "$default" = "yes" ]; then
    hint="[Yes/no]"
  else
    hint="[yes/No]"
  fi
  local ans
  while true; do
    read -rp "$prompt $hint: " ans
    [ -z "$ans" ] && ans="$default"
    case "${ans,,}" in
      yes|y) return 0 ;;
      no|n)  return 1 ;;
      *) echo "  Invalid answer. Type yes/no (or Enter for [$default])." ;;
    esac
  done
}

if [ "$APPLY" -eq 1 ]; then
  PREFIX=""
else
  PREFIX="[DRY-RUN] "
fi

# --- Firewall detection ---
iptables_input_rules_present() {
  command -v iptables >/dev/null 2>&1 || return 1
  iptables -S INPUT 2>/dev/null | awk '$1 == "-A" { found=1 } END { exit(found ? 0 : 1) }'
}

nft_input_hook_present() {
  command -v nft >/dev/null 2>&1 || return 1
  nft list ruleset 2>/dev/null | awk '
    /hook input/ { in_input=1; next }
    in_input && /^[[:space:]]*}/ { in_input=0; next }
    in_input {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      if (line != "" && line !~ /^#/) found=1
    }
    END { exit(found ? 0 : 1) }
  '
}

detect_firewall() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"; return
  fi
  # Anchor the match so "Status: inactive" is not treated as "active".
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE "^Status: active$"; then
    echo "ufw"; return
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -V 2>/dev/null | grep -q "(legacy)"; then
    echo "iptables"; return
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables 2>/dev/null; then
    echo "nftables"; return
  fi
  if nft_input_hook_present; then
    echo "nftables"; return
  fi
  if iptables_input_rules_present; then
    if ! command -v ufw >/dev/null 2>&1 || ! iptables -L -n 2>/dev/null | grep -q "^Chain ufw-"; then
      echo "iptables"; return
    fi
  fi
  echo "none"
}

detect_docker() {
  iptables -L DOCKER-USER -n >/dev/null 2>&1
}

docker_iptables_chains_present() {
  local bin
  for bin in iptables iptables-nft iptables-legacy ip6tables ip6tables-nft ip6tables-legacy; do
    command -v "$bin" >/dev/null 2>&1 || continue
    "$bin" -t nat -S DOCKER >/dev/null 2>&1 && return 0
    "$bin" -S DOCKER-USER >/dev/null 2>&1 && return 0
  done
  return 1
}

# --- iptables removal (idempotent, removes all occurrences) ---
remove_matching_iptables_rules() {
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

remove_iptables_rules() {
  local chain="$1"
  # Whitelist ACCEPT, with or without interface constraints.
  remove_matching_iptables_rules "$chain" "--match-set $WHITELIST_SET_NAME src.*-j ACCEPT"
  # Blacklist LOG/DROP: generic removal (any limit/conntrack values)
  remove_matching_iptables_rules "$chain" "--match-set $SET_NAME src.*-j (LOG|DROP)"
}

# --- firewalld --direct removal (generic: matches any limit values) ---
firewalld_get_all_direct_rules() {
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --direct --get-all-rules 2>/dev/null && return 0
  fi
  if command -v firewall-offline-cmd >/dev/null 2>&1; then
    firewall-offline-cmd --direct --get-all-rules 2>/dev/null && return 0
  fi
  return 1
}

firewalld_parse_direct_rule_line() {
  local line="$1"
  local token=""
  local quote=""
  local char next
  local i=0
  local len=${#line}

  FIREWALLD_DIRECT_RULE_ARGS=()
  while [ "$i" -lt "$len" ]; do
    char="${line:i:1}"
    if [ -n "$quote" ]; then
      if [ "$char" = "$quote" ]; then
        quote=""
      elif [ "$quote" = '"' ] && [ "$char" = "\\" ] && [ $((i + 1)) -lt "$len" ]; then
        next="${line:i+1:1}"
        token+="$next"
        i=$((i + 1))
      else
        token+="$char"
      fi
    else
      case "$char" in
        "'"|'"') quote="$char" ;;
        [[:space:]])
          if [ -n "$token" ]; then
            FIREWALLD_DIRECT_RULE_ARGS+=("$token")
            token=""
          fi
          ;;
        "\\")
          if [ $((i + 1)) -lt "$len" ]; then
            next="${line:i+1:1}"
            token+="$next"
            i=$((i + 1))
          else
            token+="$char"
          fi
          ;;
        *) token+="$char" ;;
      esac
    fi
    i=$((i + 1))
  done
  if [ -n "$token" ]; then
    FIREWALLD_DIRECT_RULE_ARGS+=("$token")
  fi
}

firewalld_remove_direct_rule() {
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --permanent --direct --remove-rule "$@" >/dev/null 2>&1; then
    return 0
  fi
  if command -v firewall-offline-cmd >/dev/null 2>&1 && firewall-offline-cmd --direct --remove-rule "$@" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

remove_firewalld_rules() {
  local chain="$1"
  local changed=0
  local line
  while true; do
    line="$(firewalld_get_all_direct_rules \
      | grep -E "^ipv4 filter $chain .*--match-set ($SET_NAME|$WHITELIST_SET_NAME) src" \
      | head -1 || true)"
    [ -z "$line" ] && break
    firewalld_parse_direct_rule_line "$line"
    if ! firewalld_remove_direct_rule "${FIREWALLD_DIRECT_RULE_ARGS[@]}"; then
      err "Warning: cannot remove firewalld direct rule: $line"
      [ "$changed" -eq 1 ] && return 0
      return 1
    fi
    changed=1
  done
  if [ "$changed" -eq 1 ]; then
    return 0
  fi
  return 1
}

# --- Display existing ipshield rules ---
show_iptables_rules() {
  local chain="$1"
  iptables -S "$chain" 2>/dev/null | grep -E -- "--match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true
}

# --- Firewall detection and action plan ---
FW="$(detect_firewall)"
log "Detected firewall: $FW"

DOCKER_PRESENT=0
if command -v iptables >/dev/null 2>&1 && detect_docker; then
  DOCKER_PRESENT=1
  log "Docker detected: the DOCKER-USER chain will also be cleaned."
elif docker_iptables_chains_present; then
  log "Docker chains detected outside the current iptables backend; only current-backend ipshield rules can be cleaned."
fi

echo ""
log "${PREFIX}--- ipshield rules to remove ---"
case "$FW" in
  iptables|nftables|ufw)
    if command -v iptables >/dev/null 2>&1; then
      rules_input="$(show_iptables_rules INPUT)"
      if [ -n "$rules_input" ]; then
        echo "  INPUT:"
        echo "$rules_input" | awk '{print "    " $0}'
      else
        echo "  INPUT: no ipshield rule present."
      fi
      if [ "$DOCKER_PRESENT" -eq 1 ]; then
        rules_docker="$(show_iptables_rules DOCKER-USER)"
        if [ -n "$rules_docker" ]; then
          echo "  DOCKER-USER:"
          echo "$rules_docker" | awk '{print "    " $0}'
        else
          echo "  DOCKER-USER: no ipshield rule present."
        fi
      fi
    fi
    if [ "$FW" = "ufw" ] && [ -f /etc/ufw/before.rules ]; then
      ufw_rules="$(grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" /etc/ufw/before.rules || true)"
      if [ -n "$ufw_rules" ]; then
        echo "  /etc/ufw/before.rules:"
        echo "$ufw_rules" | awk '{print "    " $0}'
      else
        echo "  /etc/ufw/before.rules: no ipshield rule present."
      fi
    fi
    ;;
  firewalld)
    fw_rules="$(firewalld_get_all_direct_rules | grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true)"
    if [ -n "$fw_rules" ]; then
      echo "$fw_rules" | awk '{print "    " $0}'
    else
      echo "  No ipshield rule (firewalld --direct) present."
    fi
    ;;
  none)
    echo "  (no active firewall)"
    ;;
esac

echo ""
log "${PREFIX}--- ipsets to destroy ---"
for set in "$SET_NAME" "$WHITELIST_SET_NAME"; do
  if ipset list -n 2>/dev/null | awk -v s="$set" '$0==s{found=1} END{exit(found?0:1)}'; then
    count="$(ipset list -t "$set" 2>/dev/null | awk -F': ' '/Number of entries/{print $2; exit}')"
    echo "  $set ($count entry(ies))"
  else
    echo "  $set: absent"
  fi
done

echo ""
log "${PREFIX}--- rsyslog + logrotate configs ---"
log_configs_list=(/etc/rsyslog.d/30-blocked-ips.conf /etc/logrotate.d/update-blocklist /etc/logrotate.d/blocked-ips)
log_configs_found=0
for f in "${log_configs_list[@]}"; do
  if [ -f "$f" ]; then
    echo "  $f"
    log_configs_found=1
  fi
done
if [ "$log_configs_found" -eq 0 ]; then
  echo "  (none)"
elif [ "$APPLY" -eq 1 ]; then
  echo "  -> will be removed automatically."
fi

echo ""
log "${PREFIX}--- log files ---"
log_files=()
for pattern in /var/log/update-blocklist.log* /var/log/blocked-ips.log*; do
  for f in $pattern; do
    [ -e "$f" ] && log_files+=("$f")
  done
done
if [ "${#log_files[@]}" -gt 0 ]; then
  for f in "${log_files[@]}"; do
    echo "  $f"
  done
  [ "$APPLY" -eq 1 ] && echo "  -> a separate prompt will offer to remove them."
else
  echo "  (none)"
fi
echo "  Note: journald/kernel entries are not purged; journal vacuuming is global."

echo ""
log "${PREFIX}--- configuration + persistence files ---"
data_files=()
if [ -f "$CONF_FILE" ]; then
  data_files+=("$CONF_FILE")
fi
if [ -n "${IPSET_SAVE_FILE:-}" ] && [ -f "$IPSET_SAVE_FILE" ]; then
  data_files+=("$IPSET_SAVE_FILE")
fi
# Per-source LKG cache: list the directory if it exists with content.
source_cache_present=0
if [ -n "${SOURCE_CACHE_DIR:-}" ] && [ -d "$SOURCE_CACHE_DIR" ]; then
  if [ -n "$(ls -A "$SOURCE_CACHE_DIR" 2>/dev/null || true)" ]; then
    source_cache_present=1
  fi
fi
if [ "${#data_files[@]}" -gt 0 ] || [ "$source_cache_present" -eq 1 ]; then
  for f in "${data_files[@]}"; do
    echo "  $f"
  done
  if [ "$source_cache_present" -eq 1 ]; then
    cache_count="$(find "$SOURCE_CACHE_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l)"
    echo "  $SOURCE_CACHE_DIR/ ($cache_count cached source file(s))"
  fi
  [ "$APPLY" -eq 1 ] && echo "  -> a separate prompt will offer to remove them."
else
  echo "  (none)"
fi

echo ""
log "${PREFIX}--- systemd restore service ---"
restore_service="/etc/systemd/system/ipshield-restore.service"
if [ -f "$restore_service" ]; then
  echo "  $restore_service"
  [ "$APPLY" -eq 1 ] && echo "  -> will be removed automatically."
else
  echo "  (none)"
fi

echo ""
log "${PREFIX}--- systemd apply service ---"
apply_service_preview="/etc/systemd/system/ipshield-apply.service"
if [ -f "$apply_service_preview" ]; then
  echo "  $apply_service_preview"
  [ "$APPLY" -eq 1 ] && echo "  -> will be removed automatically."
else
  echo "  (none)"
fi

echo ""
log "${PREFIX}--- nftables.service drop-in ---"
nft_dropin_preview="/etc/systemd/system/nftables.service.d/ipshield.conf"
if [ -f "$nft_dropin_preview" ]; then
  echo "  $nft_dropin_preview"
  [ "$APPLY" -eq 1 ] && echo "  -> will be removed automatically (restores default ExecStop)."
else
  echo "  (none)"
fi

echo ""
log "${PREFIX}--- /etc/nftables.conf patch ---"
nft_conf_preview="/etc/nftables.conf"
nft_conf_bak_preview="${nft_conf_preview}.ipshield.bak"
nft_conf_patched=0
if [ -f "$nft_conf_preview" ] && grep -qE '^[[:space:]]*#[[:space:]]*flush ruleset[[:space:]]+# disabled by ipshield' "$nft_conf_preview"; then
  nft_conf_patched=1
fi
if [ "$nft_conf_patched" -eq 1 ] || [ -f "$nft_conf_bak_preview" ]; then
  [ "$nft_conf_patched" -eq 1 ] && echo "  $nft_conf_preview (flush ruleset commented out by ipshield)"
  [ -f "$nft_conf_bak_preview" ] && echo "  $nft_conf_bak_preview"
  [ "$APPLY" -eq 1 ] && echo "  -> the original conf will be restored from the .ipshield.bak backup."
else
  echo "  (none)"
fi

echo ""
log "${PREFIX}--- safe-ports persistence ---"
safe_ports_service_preview="/etc/systemd/system/ipshield-safe-ports.service"
safe_ports_artifacts=()
[ -f "$safe_ports_service_preview" ] && safe_ports_artifacts+=("$safe_ports_service_preview")
[ -f /etc/ipshield/safe-ports.nft ] && safe_ports_artifacts+=("/etc/ipshield/safe-ports.nft")
[ -f /etc/ipshield/safe-ports.v4 ] && safe_ports_artifacts+=("/etc/ipshield/safe-ports.v4")
if [ "${#safe_ports_artifacts[@]}" -gt 0 ]; then
  for f in "${safe_ports_artifacts[@]}"; do
    echo "  $f"
  done
  [ "$APPLY" -eq 1 ] && echo "  -> will be removed automatically."
else
  echo "  (none)"
fi

echo ""
log "${PREFIX}--- Cron ---"
cron_files="$(grep -lE "update-blocklist\.sh" /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null || true)"
if [ -n "$cron_files" ]; then
  echo "  Cron lines detected:"
  echo "$cron_files" | while read -r f; do
    echo "    --- $f ---"
    grep -nE "update-blocklist\.sh" "$f" | awk '{print "      " $0}'
  done
  if [ "$APPLY" -eq 1 ]; then
    echo "  -> ipshield lines will be removed from root's crontab automatically."
    echo "  -> /etc/crontab and /etc/cron.d/* are never modified (do this manually)."
  fi
else
  echo "  No cron line detected."
fi

echo ""

# --- Dry-run mode: exit here ---
if [ "$APPLY" -eq 0 ]; then
  log "[DRY-RUN] To actually apply: re-run with --apply"
  exit 0
fi

# --- Confirmation ---
if ! ask_yes_no "Confirm uninstall?" no; then
  log "Cancelled."
  exit 0
fi

# --- Apply ---
log "Removing rules..."
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
    if remove_firewalld_rules DOCKER-USER; then need_reload=1; fi
    [ "$need_reload" -eq 1 ] && firewall-cmd --reload >/dev/null
    if [ "$DOCKER_PRESENT" -eq 1 ]; then
      remove_iptables_rules DOCKER-USER
    fi
    ;;
  ufw)
    # Remove ipshield rules from before.rules line-by-line (more robust than
    # restoring a generic backup, which can be stale: it may reference sets
    # that have since been destroyed -- e.g. blacklist-allow after a previous
    # WHITELIST=() run -- making "ufw reload" fail with "Set X doesn't exist"
    # and leaving the firewall in a partial state).
    # Targets: current SET_NAME, current WHITELIST_SET_NAME, plus any orphan
    # set name (referenced in before.rules but not present in `ipset list`).
    if [ -f /etc/ufw/before.rules ]; then
      sets_to_remove=()
      while IFS= read -r ref_set; do
        [ -z "$ref_set" ] && continue
        if [ "$ref_set" = "$SET_NAME" ] || [ "$ref_set" = "$WHITELIST_SET_NAME" ]; then
          sets_to_remove+=("$ref_set")
          continue
        fi
        if ! ipset list -n 2>/dev/null | awk -v s="$ref_set" '$0==s{f=1} END{exit(f?0:1)}'; then
          sets_to_remove+=("$ref_set")
        fi
      done < <(grep -oE -- "--match-set [^ ]+ src" /etc/ufw/before.rules 2>/dev/null | awk '{print $2}' | sort -u)

      if [ "${#sets_to_remove[@]}" -gt 0 ]; then
        # Snapshot for rollback if ufw reload fails.
        snapshot=/etc/ufw/before.rules.ipshield.uninstall.snapshot
        cp /etc/ufw/before.rules "$snapshot"
        for ref_set in "${sets_to_remove[@]}"; do
          sed -i "\\|^-A ufw-before-input .*--match-set $ref_set src |d" /etc/ufw/before.rules
        done
        log "Removed ipshield/orphan rules from /etc/ufw/before.rules: ${sets_to_remove[*]}"
        if ! ufw reload; then
          err "ufw reload failed; restoring pre-uninstall snapshot."
          cp "$snapshot" /etc/ufw/before.rules
          ufw reload || err "ufw reload still failing after rollback. Inspect /etc/ufw/before.rules manually."
        fi
        rm -f "$snapshot"
      fi
    fi
    if [ "$DOCKER_PRESENT" -eq 1 ]; then
      remove_iptables_rules DOCKER-USER
    fi
    ;;
esac

log "Destroying ipsets..."
for set in "$SET_NAME" "$WHITELIST_SET_NAME"; do
  if ipset list -n 2>/dev/null | awk -v s="$set" '$0==s{found=1} END{exit(found?0:1)}'; then
    if ipset destroy "$set" 2>/dev/null; then
      log "  $set destroyed."
    else
      err "  $set: cannot destroy (still referenced?)."
    fi
  fi
done

# --- ipset restore service removal (auto) ---
if [ -f "$restore_service" ]; then
  echo ""
  log "Removing ipshield-restore.service..."
  systemctl disable --now ipshield-restore.service 2>/dev/null || true
  rm -f "$restore_service"
  systemctl daemon-reload 2>/dev/null || true
  log "ipshield-restore.service removed."
fi

# --- Apply service removal (auto) ---
apply_service="/etc/systemd/system/ipshield-apply.service"
if [ -f "$apply_service" ]; then
  echo ""
  log "Removing ipshield-apply.service..."
  systemctl disable --now ipshield-apply.service 2>/dev/null || true
  rm -f "$apply_service"
  systemctl daemon-reload 2>/dev/null || true
  log "ipshield-apply.service removed."
fi

# --- nftables persistence drop-in removal (auto) ---
nft_dropin_path="/etc/systemd/system/nftables.service.d/ipshield.conf"
nft_dropin_dir="$(dirname "$nft_dropin_path")"
if [ -f "$nft_dropin_path" ]; then
  echo ""
  log "Removing nftables.service drop-in..."
  log "Note: this restores the default ExecStop=nft flush ruleset,"
  log "which will wipe iptables-nft tables on the next systemctl restart."
  rm -f "$nft_dropin_path"
  rmdir "$nft_dropin_dir" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  log "nftables.service drop-in removed."
fi

# --- /etc/nftables.conf restore (auto) ---
nft_conf_path="/etc/nftables.conf"
nft_conf_bak="${nft_conf_path}.ipshield.bak"
nft_conf_was_patched=0
if [ -f "$nft_conf_path" ] && grep -qE '^[[:space:]]*#[[:space:]]*flush ruleset[[:space:]]+# disabled by ipshield' "$nft_conf_path"; then
  nft_conf_was_patched=1
fi
if [ "$nft_conf_was_patched" -eq 1 ] || [ -f "$nft_conf_bak" ]; then
  echo ""
  if [ -f "$nft_conf_bak" ]; then
    cp -a "$nft_conf_bak" "$nft_conf_path"
    rm -f "$nft_conf_bak"
    log "Restored $nft_conf_path from backup."
  else
    log "No $nft_conf_bak backup found; leaving $nft_conf_path untouched. Edit it manually if needed."
  fi
fi

# --- safe-ports service + config removal (auto) ---
safe_ports_service="/etc/systemd/system/ipshield-safe-ports.service"
safe_ports_files=()
[ -f /etc/ipshield/safe-ports.nft ] && safe_ports_files+=("/etc/ipshield/safe-ports.nft")
[ -f /etc/ipshield/safe-ports.v4 ] && safe_ports_files+=("/etc/ipshield/safe-ports.v4")
if [ -f "$safe_ports_service" ] || [ "${#safe_ports_files[@]}" -gt 0 ]; then
  echo ""
  log "Removing safe-ports persistence..."
  log "Note: this does NOT close already-open ports in the running firewall;"
  log "it only stops them from being reapplied at the next boot."
  if [ -f "$safe_ports_service" ]; then
    systemctl disable --now ipshield-safe-ports.service 2>/dev/null || true
    rm -f "$safe_ports_service"
    systemctl daemon-reload 2>/dev/null || true
  fi
  for f in "${safe_ports_files[@]}"; do
    rm -f "$f"
  done
  rmdir /etc/ipshield 2>/dev/null || true
  log "Safe-ports persistence removed."
fi

# --- Cron line removal from root's crontab (auto) ---
if command -v crontab >/dev/null 2>&1; then
  current_cron="$(crontab -l 2>/dev/null || true)"
  ipshield_lines="$(printf '%s\n' "$current_cron" | grep -E "update-blocklist\.sh|^[[:space:]]*# ipshield cron (begin|end)$" || true)"
  if [ -n "$ipshield_lines" ]; then
    echo ""
    log "Removing ipshield cron lines from root's crontab..."
    # Strip both the executable lines and the marker comments installed by
    # setup-firewall.sh (# ipshield cron begin / end). Orphan markers were
    # left behind by the previous grep -v pattern.
    new_cron="$(printf '%s\n' "$current_cron" | grep -vE "update-blocklist\.sh|^[[:space:]]*# ipshield cron (begin|end)$" || true)"
    new_cron="${new_cron%$'\n'}"
    if [ -z "$new_cron" ]; then
      crontab -r 2>/dev/null || true
      log "Root's crontab cleared."
    else
      printf '%s\n' "$new_cron" | crontab -
      log "Root's crontab updated (ipshield lines removed)."
    fi
  fi
fi

# Cron lines in /etc/crontab and /etc/cron.d/* (info only, never modified)
other_cron="$(grep -lE "update-blocklist\.sh" /etc/crontab /etc/cron.d/* 2>/dev/null || true)"
if [ -n "$other_cron" ]; then
  echo ""
  log "ipshield cron lines also present in (remove manually):"
  echo "$other_cron" | awk '{print "    " $0}'
fi

# --- Optional config + persistence file removal ---
if [ "${#data_files[@]}" -gt 0 ] || [ "$source_cache_present" -eq 1 ]; then
  echo ""
  log "ipshield configuration + persistence files found:"
  for f in "${data_files[@]}"; do
    echo "    $f"
  done
  if [ "$source_cache_present" -eq 1 ]; then
    echo "    $SOURCE_CACHE_DIR/ (per-source last-known-good cache)"
  fi
  if ask_yes_no "Remove them?" yes; then
    for f in "${data_files[@]}"; do
      if rm -f "$f" 2>/dev/null; then
        log "  $f removed."
      else
        err "  Cannot remove $f."
      fi
    done
    if [ "$source_cache_present" -eq 1 ]; then
      # Strip the LKG cache contents and the dir itself. Keep the operation
      # scoped: only touch the configured path (never recurse blindly).
      find "$SOURCE_CACHE_DIR" -maxdepth 1 -type f -delete 2>/dev/null || true
      rmdir "$SOURCE_CACHE_DIR" 2>/dev/null || true
      log "  $SOURCE_CACHE_DIR/ removed."
    fi
    # Drop the persistence parent directory only when empty: leftover empty
    # /var/lib/ipshield/ was visible after the runtime uninstall on the VM.
    if [ -n "${IPSET_SAVE_FILE:-}" ]; then
      save_dir="$(dirname "$IPSET_SAVE_FILE")"
      case "$save_dir" in
        /var/lib/ipshield|/var/lib/ipshield/)
          rmdir "$save_dir" 2>/dev/null || true
          ;;
      esac
    fi
  else
    log "Configuration + persistence files kept."
  fi
fi

# --- rsyslog + logrotate config removal (auto) ---
log_configs=(/etc/rsyslog.d/30-blocked-ips.conf /etc/logrotate.d/update-blocklist /etc/logrotate.d/blocked-ips)
present_log_configs=()
for f in "${log_configs[@]}"; do
  [ -f "$f" ] && present_log_configs+=("$f")
done
if [ "${#present_log_configs[@]}" -gt 0 ]; then
  echo ""
  log "Removing rsyslog filter + logrotate configs..."
  restart_rsyslog=0
  for f in "${present_log_configs[@]}"; do
    if rm -f "$f" 2>/dev/null; then
      log "  $f removed."
      [[ "$f" == /etc/rsyslog.d/* ]] && restart_rsyslog=1
    else
      err "  Cannot remove $f."
    fi
  done
  if [ "$restart_rsyslog" -eq 1 ]; then
    if systemctl restart rsyslog 2>/dev/null; then
      log "rsyslog restarted."
    else
      err "Cannot restart rsyslog."
    fi
  fi
  log "Note: log files /var/log/update-blocklist.log and /var/log/blocked-ips.log are kept."
fi

# --- Optional log file removal ---
if [ "${#log_files[@]}" -gt 0 ]; then
  echo ""
  log "ipshield log files found:"
  for f in "${log_files[@]}"; do
    echo "    $f"
  done
  log "Journald/kernel entries are not purged; journal vacuuming is global."
  if ask_yes_no "Remove ipshield log files?" yes; then
    for f in "${log_files[@]}"; do
      if rm -f "$f" 2>/dev/null; then
        log "  $f removed."
      else
        err "  Cannot remove $f."
      fi
    done
  else
    log "Log files kept."
  fi
fi

echo ""
log "Uninstall complete."
