#!/bin/bash
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
  - restores /etc/ufw/before.rules.bak if present (ufw);
  - reports (without modifying) cron lines referencing update-blocklist.sh.

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
  if [[ "$conf_perms" =~ [2367][0-9]$ ]] || [[ "$conf_perms" =~ [0-9][2367]$ ]]; then
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
: "${WHITELIST_SET_NAME:=${SET_NAME}-allow}"
if [[ ! "$WHITELIST_SET_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Error: WHITELIST_SET_NAME invalid ('$WHITELIST_SET_NAME')." >&2
  exit 1
fi

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
detect_firewall() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"; return
  fi
  # Anchor the match so "Status: inactive" is not treated as "active".
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE "^Status: active$"; then
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
  echo "none"
}

detect_docker() {
  iptables -L DOCKER-USER -n >/dev/null 2>&1
}

# --- iptables removal (idempotent, removes all occurrences) ---
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
  # Blacklist LOG: generic removal (any limit values)
  local rule
  while true; do
    rule="$(iptables -S "$chain" 2>/dev/null | grep -E "^-A $chain .*--match-set $SET_NAME src.*-j LOG --log-prefix \"BLOCKED: \"" | head -1 || true)"
    [ -z "$rule" ] && break
    rule="${rule/#-A /-D }"
    eval "iptables $rule"
  done
}

# --- firewalld --direct removal (generic: matches any limit values) ---
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
    fw_rules="$(firewall-cmd --permanent --direct --get-all-rules 2>/dev/null | grep -E "match-set ($SET_NAME|$WHITELIST_SET_NAME) src" || true)"
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
  echo "  -> a separate prompt will offer to remove them."
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
    echo "  -> root's crontab will be offered for removal (separate prompt)."
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
    if [ "$DOCKER_PRESENT" -eq 1 ] && remove_firewalld_rules DOCKER-USER; then
      need_reload=1
    fi
    [ "$need_reload" -eq 1 ] && firewall-cmd --reload
    ;;
  ufw)
    # Remove ipshield rules from before.rules line-by-line (more robust than
    # restoring before.rules.bak, which can be stale: it may reference sets
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
      done < <(grep -oE -- "-A ufw-before-input -m set --match-set [^ ]+ src" /etc/ufw/before.rules 2>/dev/null | awk '{print $6}' | sort -u)

      if [ "${#sets_to_remove[@]}" -gt 0 ]; then
        # Snapshot for rollback if ufw reload fails.
        snapshot=/etc/ufw/before.rules.uninstall.snapshot
        cp /etc/ufw/before.rules "$snapshot"
        for ref_set in "${sets_to_remove[@]}"; do
          sed -i "\\|^-A ufw-before-input -m set --match-set $ref_set src |d" /etc/ufw/before.rules
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

# --- Optional cron line removal ---
if command -v crontab >/dev/null 2>&1; then
  current_cron="$(crontab -l 2>/dev/null || true)"
  ipshield_lines="$(printf '%s\n' "$current_cron" | grep -E "update-blocklist\.sh" || true)"
  if [ -n "$ipshield_lines" ]; then
    echo ""
    log "ipshield cron lines found in root's crontab:"
    echo "$ipshield_lines" | awk '{print "    " $0}'
    if ask_yes_no "Remove them?" yes; then
      new_cron="$(printf '%s\n' "$current_cron" | grep -vE "update-blocklist\.sh" || true)"
      new_cron="${new_cron%$'\n'}"
      if [ -z "$new_cron" ]; then
        crontab -r 2>/dev/null || true
        log "Root's crontab cleared."
      else
        printf '%s\n' "$new_cron" | crontab -
        log "Root's crontab updated (ipshield lines removed)."
      fi
    else
      log "Cron lines kept."
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

# --- Optional rsyslog + logrotate config removal ---
log_configs=(/etc/rsyslog.d/30-blocked-ips.conf /etc/logrotate.d/update-blocklist /etc/logrotate.d/blocked-ips)
present_log_configs=()
for f in "${log_configs[@]}"; do
  [ -f "$f" ] && present_log_configs+=("$f")
done
if [ "${#present_log_configs[@]}" -gt 0 ]; then
  echo ""
  log "ipshield rsyslog + logrotate configs found:"
  for f in "${present_log_configs[@]}"; do
    echo "    $f"
  done
  if ask_yes_no "Remove them?" yes; then
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
  else
    log "Configs kept."
  fi
fi

echo ""
log "Uninstall complete."
