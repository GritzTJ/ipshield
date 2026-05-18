#!/bin/bash
# ipshield v1.0.0
set -euo pipefail
umask 077

# Ensure /sbin and /usr/sbin are in PATH (firewall-cmd, ufw, iptables, nft,
# ipset, ip live there on Debian/Ubuntu). Same rationale as update-blocklist.sh.
export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}"

# --- Usage / help ---
case "${1:-}" in
  -h|--help)
    cat <<'EOF'
Usage: setup-firewall.sh

Interactive script that installs and configures a firewall.
Detects the active firewall, offers a choice among iptables, nftables,
firewalld and ufw, then performs the transition.

Before activation, automatically detects listening TCP/UDP ports
(non-loopback) and offers to allow them, to avoid breaking exposed
services (SSH, web, etc.).
EOF
    exit 0 ;;
esac

# --- Functions ---
log() { echo "$*"; }
err() { echo "ERROR: $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "missing command: $1"; exit 1; }
}

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

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  err "this script must be run as root."
  exit 1
fi

# --- Dependency check ---
need_cmd systemctl

# --- Package manager detection ---
PKG_MANAGER=""
if [ -r /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  os_ids="${ID:-} ${ID_LIKE:-}"
  case "$os_ids" in
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*) PKG_MANAGER="dnf" ;;
    *debian*|*ubuntu*) PKG_MANAGER="apt" ;;
  esac
fi
if [ -z "$PKG_MANAGER" ]; then
  if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
  fi
fi
if [ -z "$PKG_MANAGER" ]; then
  err "unsupported package manager (apt or dnf required)."
  exit 1
fi

# --- Active firewall detection ---
iptables_input_rules_present() {
  command -v iptables >/dev/null 2>&1 || return 1
  iptables -S INPUT 2>/dev/null | awk '$1 == "-A" { found=1 } END { exit(found ? 0 : 1) }'
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

explain_docker_chains_block() {
  err "Docker iptables chains are present (DOCKER-USER and/or nat/DOCKER)."
  err "Changing firewall or iptables backend while they exist can break Docker published ports."
  err "They may be active Docker chains or stale Docker chains left after Docker stopped."
}

docker_daemon_active() {
  systemctl is-active --quiet docker 2>/dev/null || systemctl is-active --quiet docker.service 2>/dev/null
}

docker_socket_active() {
  systemctl is-active --quiet docker.socket 2>/dev/null
}

docker_active() {
  docker_daemon_active || docker_socket_active
}

docker_running_container_count() {
  if command -v docker >/dev/null 2>&1 && docker_daemon_active; then
    docker ps -q 2>/dev/null | wc -l | awk '{print $1}'
  elif docker_daemon_active; then
    echo "unknown"
  else
    echo 0
  fi
}

cleanup_docker_iptables_bin() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || return 0

  local table chain rule delete_rule
  local chains=(
    DOCKER
    DOCKER-USER
    DOCKER-FORWARD
    DOCKER-BRIDGE
    DOCKER-CT
    DOCKER-INGRESS
    DOCKER-ISOLATION-STAGE-1
    DOCKER-ISOLATION-STAGE-2
  )

  for table in filter nat mangle raw; do
    "$bin" -t "$table" -S >/dev/null 2>&1 || continue

    # Delete jumps/gotos to Docker-owned chains before deleting the chains.
    while read -r rule; do
      [ -n "$rule" ] || continue
      delete_rule="${rule/#-A/-D}"
      # shellcheck disable=SC2086
      "$bin" -t "$table" $delete_rule >/dev/null 2>&1 || true
    done < <("$bin" -t "$table" -S 2>/dev/null | grep -E '^-A .*[[:space:]]-[jg][[:space:]]DOCKER(-[A-Z0-9]+)?([[:space:]]|$)' || true)

    for chain in "${chains[@]}"; do
      "$bin" -t "$table" -F "$chain" >/dev/null 2>&1 || true
      "$bin" -t "$table" -X "$chain" >/dev/null 2>&1 || true
    done
  done
}

cleanup_docker_iptables_chains() {
  local bin
  for bin in iptables iptables-nft iptables-legacy ip6tables ip6tables-nft ip6tables-legacy; do
    cleanup_docker_iptables_bin "$bin"
  done
}

DOCKER_STOPPED_BY_IPSHIELD=0
DOCKER_SERVICE_WAS_ACTIVE=0
DOCKER_SOCKET_WAS_ACTIVE=0
DOCKER_FIREWALL_PREPARED=0

stop_docker_for_firewall_transition() {
  log "Stopping Docker for firewall transition..."

  docker_daemon_active && DOCKER_SERVICE_WAS_ACTIVE=1
  docker_socket_active && DOCKER_SOCKET_WAS_ACTIVE=1

  systemctl stop docker.socket 2>/dev/null || true
  systemctl stop docker.service 2>/dev/null || systemctl stop docker 2>/dev/null || true

  if docker_active; then
    err "Docker is still active after stop request. Cannot safely clean Docker firewall chains."
    exit 1
  fi

  DOCKER_STOPPED_BY_IPSHIELD=1
}

restart_docker_after_firewall_transition() {
  [ "$DOCKER_STOPPED_BY_IPSHIELD" -eq 1 ] || return 0

  log "Restarting Docker..."
  if [ "$DOCKER_SOCKET_WAS_ACTIVE" -eq 1 ]; then
    systemctl start docker.socket 2>/dev/null || true
  fi
  if [ "$DOCKER_SERVICE_WAS_ACTIVE" -eq 1 ] && { systemctl start docker.service 2>/dev/null || systemctl start docker 2>/dev/null; }; then
    log "Docker restarted."
    DOCKER_STOPPED_BY_IPSHIELD=0
    return 0
  fi
  if [ "$DOCKER_SERVICE_WAS_ACTIVE" -eq 0 ] && [ "$DOCKER_SOCKET_WAS_ACTIVE" -eq 1 ]; then
    log "Docker socket restarted."
    DOCKER_STOPPED_BY_IPSHIELD=0
    return 0
  fi

  err "Cannot restart Docker automatically. Start it manually with: systemctl start docker docker.socket"
  return 1
}

prepare_docker_firewall_transition() {
  local reason="$1"
  local running_count default_answer live_restore

  [ "$DOCKER_FIREWALL_PREPARED" -eq 1 ] && return 0
  docker_iptables_chains_present || return 0

  echo ""
  explain_docker_chains_block
  err "Requested operation: $reason"

  if docker_active; then
    running_count="$(docker_running_container_count)"
    default_answer="no"
    [[ "$running_count" =~ ^[0-9]+$ ]] && [ "$running_count" -eq 0 ] && default_answer="yes"

    log "Docker is active. Running containers detected: $running_count"
    if [[ "$running_count" =~ ^[0-9]+$ ]] && [ "$running_count" -gt 0 ] && command -v docker >/dev/null 2>&1; then
      log "Running containers:"
      docker ps --format '  - {{.Names}} ({{.Status}})' 2>/dev/null | sed -n '1,20p' || true
      log ""
      log "Preferred production path: stop application containers cleanly first"
      log "(for example: docker compose down), then rerun setup-firewall.sh."
      log "Letting this setup stop Docker only stops the Docker daemon; it is not"
      log "equivalent to a clean application/Compose shutdown."
    elif [ "$running_count" = "unknown" ]; then
      err "Docker daemon is active, but the docker CLI is unavailable."
      err "Cannot determine whether containers are running; using the safe default: no."
    fi

    live_restore="false"
    if command -v docker >/dev/null 2>&1 && docker_daemon_active; then
      live_restore="$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null || echo false)"
    fi
    if [ "$live_restore" = "true" ] && [[ "$running_count" =~ ^[0-9]+$ ]] && [ "$running_count" -gt 0 ]; then
      err "Docker live-restore is enabled and containers are running."
      err "Stop the containers first, then rerun setup-firewall.sh."
      exit 1
    fi

    if ! ask_yes_no "Stop Docker daemon, clean Docker firewall chains, continue setup, then restart Docker? Prefer stopping containers cleanly first when any are running." "$default_answer"; then
      err "Docker firewall preparation declined. Aborting without firewall changes."
      exit 1
    fi

    stop_docker_for_firewall_transition
  else
    if ! ask_yes_no "Clean stale Docker firewall chains and continue setup?" yes; then
      err "Docker firewall cleanup declined. Aborting without firewall changes."
      exit 1
    fi
  fi

  log "Cleaning Docker firewall chains..."
  cleanup_docker_iptables_chains

  if docker_iptables_chains_present; then
    err "Docker firewall chains are still present after cleanup."
    err "Stop Docker containers manually or reboot during a maintenance window, then rerun setup-firewall.sh."
    restart_docker_after_firewall_transition || true
    exit 1
  fi

  DOCKER_FIREWALL_PREPARED=1
  log "Docker firewall chains cleaned."
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

ufw_status_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  ufw status 2>/dev/null | grep -qE "^Status: active$"
}

ufw_status_inactive() {
  command -v ufw >/dev/null 2>&1 || return 1
  ufw status 2>/dev/null | grep -qE "^Status: inactive$"
}

ufw_service_active_or_enabled() {
  systemctl is-active --quiet ufw 2>/dev/null || systemctl is-enabled --quiet ufw 2>/dev/null
}

offer_disable_inactive_ufw_service() {
  [ "$FIREWALL" != "ufw" ] || return 0
  ufw_status_inactive || return 0
  ufw_service_active_or_enabled || return 0

  echo ""
  log "UFW status is inactive, but the ufw systemd service is active/enabled."
  log "UFW is not filtering traffic, but leaving the service active can be confusing"
  log "when $FIREWALL is the selected firewall."
  if ask_yes_no "Disable the inactive UFW systemd service now?" yes; then
    if systemctl disable --now ufw >/dev/null 2>&1; then
      log "Inactive UFW service disabled."
    else
      err "Cannot disable ufw.service automatically. Continuing; check manually with: ufw status verbose"
    fi
  else
    log "Inactive UFW service kept as-is. Verify real UFW state with: ufw status verbose"
  fi
}

detect_firewall() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
    return
  fi

  # Anchor the match so "Status: inactive" is not treated as "active".
  if ufw_status_active; then
    echo "ufw"
    return
  fi

  if command -v iptables >/dev/null 2>&1 && iptables -V 2>/dev/null | grep -q "(legacy)"; then
    echo "iptables"
    return
  fi

  if systemctl is-active --quiet nftables 2>/dev/null; then
    echo "nftables"
    return
  fi
  if nft_input_hook_present; then
    echo "nftables"
    return
  fi

  if iptables_input_rules_present; then
    # Skip leftover ufw chains if ufw is installed but inactive
    if ! command -v ufw >/dev/null 2>&1 || ! iptables -L -n 2>/dev/null | grep -q "^Chain ufw-"; then
      echo "iptables"
      return
    fi
  fi

  echo "none"
}

DETECTED="$(detect_firewall)"

# --- Cron configuration (idempotent interactive prompt) ---
configure_cron() {
  echo ""
  if ! ask_yes_no "Configure the ipshield cron now?" yes; then
    log "Cron not configured. To do it later, re-run ./setup-firewall.sh."
    return 0
  fi

  # Check that crontab is available
  if ! command -v crontab >/dev/null 2>&1; then
    err "'crontab' command not available -- install cron manually."
    return 0
  fi

  # Initial crontab read (reused for default path + filter).
  # `|| true`: crontab -l returns 1 if no user crontab; do not let set -e exit.
  local current_cron
  current_cron="$(crontab -l 2>/dev/null || true)"

  # Default path: same directory as this script. Existing ipshield cron lines
  # are removed by basename below; the default is intentionally not parsed back
  # from crontab because quoted paths with spaces are ambiguous in cron syntax.
  local script_dir script_path log_path mailto reboot_delay
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  script_path="$script_dir/update-blocklist.sh"

  read -rp "Path to update-blocklist.sh [$script_path]: " ans
  [ -n "$ans" ] && script_path="$ans"
  if [ ! -x "$script_path" ]; then
    err "$script_path does not exist or is not executable. Cron not configured."
    return 0
  fi

  log_path="/var/log/update-blocklist.log"
  read -rp "Log file [$log_path]: " ans
  [ -n "$ans" ] && log_path="$ans"

  read -rp "Email for error notifications (empty = no MAILTO): " mailto
  if [ -n "$mailto" ] && ! [[ "$mailto" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    err "Invalid email address. Cron not configured."
    return 0
  fi

  reboot_delay=60
  read -rp "@reboot delay in seconds (lets Docker start) [$reboot_delay]: " ans
  if [ -n "$ans" ]; then
    if ! [[ "$ans" =~ ^[0-9]+$ ]] || [ "$ans" -gt 3600 ]; then
      err "Invalid delay. Expected an integer between 0 and 3600 seconds. Cron not configured."
      return 0
    fi
    reboot_delay="$ans"
  fi

  # Filter existing ipshield lines (by basename), plus future marker blocks.
  # Do not remove global MAILTO lines from the user's crontab: cron variables
  # are positional and may apply to unrelated jobs.
  local filtered_cron new_lines new_cron reboot_log_cmd script_cmd log_cmd
  local script_basename existing_mailto
  script_basename="$(basename "$script_path")"
  existing_mailto="$(printf '%s\n' "$current_cron" | awk '/^[[:space:]]*MAILTO=/{print; exit}')"

  filtered_cron="$(printf '%s\n' "$current_cron" | awk -v base="$script_basename" '
    /^[[:space:]]*# ipshield cron begin$/ { skip=1; next }
    /^[[:space:]]*# ipshield cron end$/ { skip=0; next }
    skip { next }
    index($0, base) { next }
    { print }
  ')"
  filtered_cron="${filtered_cron%$'\n'}"

  # New lines
  shell_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
  }
  script_cmd="$(shell_quote "$script_path")"
  log_cmd="$(shell_quote "$log_path")"
  reboot_log_cmd="echo \"--- Trigger: reboot on \$(date '+\\%Y-\\%m-\\%d \\%H:\\%M:\\%S \\%Z') ---\" >> $log_cmd"
  new_lines="# ipshield cron begin"$'\n'
  [ -n "$mailto" ] && new_lines+="MAILTO=$mailto"$'\n'
  new_lines+="0 */12 * * * $script_cmd >> $log_cmd 2>&1"$'\n'
  if [ "$reboot_delay" -gt 0 ]; then
    new_lines+="@reboot sleep $reboot_delay && $reboot_log_cmd && $script_cmd >> $log_cmd 2>&1"$'\n'
  else
    new_lines+="@reboot $reboot_log_cmd && $script_cmd >> $log_cmd 2>&1"$'\n'
  fi
  if [ -n "$mailto" ] && [ -n "$existing_mailto" ] && [ "$existing_mailto" != "MAILTO=$mailto" ]; then
    log "Existing crontab MAILTO will be preserved after the ipshield block: $existing_mailto"
    new_lines+="$existing_mailto"$'\n'
  fi
  new_lines+="# ipshield cron end"

  # Concatenation
  if [ -n "$filtered_cron" ]; then
    new_cron="${filtered_cron}"$'\n'"${new_lines}"
  else
    new_cron="$new_lines"
  fi

  echo ""
  echo "=== Current crontab (root) ==="
  if [ -z "$current_cron" ]; then echo "(empty)"; else echo "$current_cron"; fi
  echo ""
  echo "=== Crontab after change ==="
  echo "$new_cron"
  echo ""

  if [ "$current_cron" = "$new_cron" ]; then
    log "No change needed."
    return 0
  fi

  if ! ask_yes_no "Apply?" yes; then
    log "Cron not modified."
    return 0
  fi

  printf '%s\n' "$new_cron" | crontab -
  log "Crontab updated."
}

# --- Helper: install or update a config file ---
# Args: path, expected content, short description
# Returns: 0 if modified, 1 if no change
_install_config() {
  local path="$1"
  local content="$2"
  local desc="$3"

  if [ -f "$path" ]; then
    if [ "$(cat "$path")" = "$content" ]; then
      log "  $desc: already up-to-date ($path)"
      return 1
    fi
    log "  $desc: content differs ($path)"
    if ! ask_yes_no "  Overwrite?" no; then
      log "  Kept as-is."
      return 1
    fi
  fi
  printf '%s\n' "$content" > "$path"
  chmod 644 "$path"
  log "  $desc: installed ($path)"
  return 0
}

validate_root_config_file() {
  local path="$1"
  local conf_owner conf_perms conf_low

  [ -f "$path" ] || return 0
  conf_owner="$(stat -c '%u' "$path")"
  conf_perms="$(stat -c '%a' "$path")"
  if [ "$conf_owner" != "0" ]; then
    err "$path is not owned by root (uid=$conf_owner). Security risk."
    return 1
  fi
  conf_low="${conf_perms: -3}"
  if (( (8#$conf_low & 8#022) != 0 )); then
    err "$path is group/world-writable (perms=$conf_perms). Security risk."
    return 1
  fi
}

cleanup_ufw_ipshield_before_rules_for_transition() {
  local rules_path="/etc/ufw/before.rules"
  local snapshot="/etc/ufw/before.rules.ipshield-transition.bak"
  local conf_path="/etc/update-blocklist.conf"
  local set_name="blacklist"
  local whitelist_set_name="blacklist-allow"
  local ref_set before_count after_count
  local sets_to_remove=()

  [ -f "$rules_path" ] || return 0

  if [ -f "$conf_path" ]; then
    validate_root_config_file "$conf_path" || return 1
    # shellcheck source=/dev/null
    . "$conf_path"
    set_name="${SET_NAME:-$set_name}"
    whitelist_set_name="${WHITELIST_SET_NAME:-${set_name}-allow}"
  fi

  sets_to_remove+=("$set_name" "$whitelist_set_name")

  if command -v ipset >/dev/null 2>&1; then
    while read -r ref_set; do
      [[ "$ref_set" =~ ^[a-zA-Z0-9_-]+$ ]] || continue
      if ! ipset list -n 2>/dev/null | awk -v s="$ref_set" '$0==s{found=1} END{exit(found?0:1)}'; then
        sets_to_remove+=("$ref_set")
      fi
    done < <(grep -oE -- "--match-set [^ ]+ src" "$rules_path" 2>/dev/null | awk '{print $2}' | sort -u)
  fi

  cp "$rules_path" "$snapshot"
  before_count="$(wc -l < "$rules_path")"
  for ref_set in "${sets_to_remove[@]}"; do
    [ -n "$ref_set" ] || continue
    [[ "$ref_set" =~ ^[a-zA-Z0-9_-]+$ ]] || continue
    sed -i "\\|^-A ufw-before-input .*--match-set $ref_set src |d" "$rules_path"
  done
  after_count="$(wc -l < "$rules_path")"

  if [ "$before_count" != "$after_count" ]; then
    UFW_TRANSITION_BACKUP="$snapshot"
    log "Removed ipshield/orphan ipset rules from $rules_path (backup: $snapshot)."
  else
    rm -f "$snapshot"
  fi
}

# --- Configuration file installation ---
# /etc/update-blocklist.conf is required by update-blocklist.sh. Copied from
# update-blocklist.conf.example when missing. If present, kept as-is to
# preserve user modifications.
configure_conf() {
  local conf_path="/etc/update-blocklist.conf"
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local example="$script_dir/update-blocklist.conf.example"

  echo ""
  if [ -f "$conf_path" ]; then
    log "Configuration $conf_path: already present, kept as-is."
    log "  To reset from the example: sudo rm $conf_path && re-run setup-firewall.sh."
    return 0
  fi

  if [ ! -f "$example" ]; then
    err "$example not found. Cannot initialise $conf_path."
    err "  Copy the file manually from the repo, then re-run setup-firewall.sh."
    return 1
  fi

  log "Installing $conf_path from $example..."
  cp "$example" "$conf_path"
  chown root:root "$conf_path"
  chmod 600 "$conf_path"
  log "  Configuration installed. Edit if needed (whitelist, custom sources, etc.)."
}

# --- ipset persistence service ---
configure_ipset_restore() {
  local conf_path="/etc/update-blocklist.conf"
  local persist=1
  local save_file="/var/lib/ipshield/ipset.save"

  if [ -f "$conf_path" ]; then
    validate_root_config_file "$conf_path" || return 1
    # shellcheck source=/dev/null
    . "$conf_path"
    persist="${PERSIST_IPSET:-1}"
    save_file="${IPSET_SAVE_FILE:-/var/lib/ipshield/ipset.save}"
  fi

  if ! [[ "$persist" =~ ^[01]$ ]]; then
    err "invalid PERSIST_IPSET in $conf_path: $persist"
    return 1
  fi

  if [ "$persist" != "1" ]; then
    log "ipset persistence disabled by PERSIST_IPSET=0."
    return 0
  fi

  if [[ "$save_file" != /* ]] || [[ "$save_file" =~ [[:space:]] ]]; then
    err "invalid IPSET_SAVE_FILE in $conf_path: $save_file"
    return 1
  fi

  local default_answer="yes"
  [ "$FIREWALL" = "iptables" ] && default_answer="no"

  echo ""
  if ! ask_yes_no "Install/update the ipset restore systemd service?" "$default_answer"; then
    log "ipset restore service not configured."
    return 0
  fi

  if ! command -v ipset >/dev/null 2>&1; then
    err "ipset command not available. Cannot configure restore service."
    return 1
  fi

  local ipset_bin service_path unit_content save_dir
  ipset_bin="$(command -v ipset)"
  service_path="/etc/systemd/system/ipshield-restore.service"
  save_dir="$(dirname "$save_file")"
  mkdir -p "$save_dir"
  chmod 700 "$save_dir"

  unit_content="[Unit]
Description=Restore ipshield ipsets before firewall start
DefaultDependencies=no
After=local-fs.target
Before=netfilter-persistent.service nftables.service ufw.service firewalld.service
ConditionPathExists=$save_file
RequiresMountsFor=$save_dir

[Service]
Type=oneshot
ExecStart=$ipset_bin restore -! -f $save_file
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target"

  if [ -f "$service_path" ] && [ "$(cat "$service_path")" = "$unit_content" ]; then
    log "ipshield-restore.service already up-to-date."
  else
    printf '%s\n' "$unit_content" > "$service_path"
    chmod 644 "$service_path"
    log "Installed $service_path"
  fi

  systemctl daemon-reload
  systemctl enable ipshield-restore.service
  log "ipset restore service enabled. The save file will be written by update-blocklist.sh after a successful run."
}

# --- Logs configuration (rsyslog filter + logrotate) ---
configure_logs() {
  echo ""

  # Detect rsyslog BEFORE the prompt to adapt wording
  local has_rsyslog=0
  if systemctl is-active --quiet rsyslog 2>/dev/null; then
    has_rsyslog=1
  fi

  if [ "$has_rsyslog" -eq 1 ]; then
    # rsyslog active: single prompt
    if ! ask_yes_no "Configure the rsyslog filter + logrotate for ipshield logs?" yes; then
      log "Logs not configured. To do it later, re-run ./setup-firewall.sh."
      return 0
    fi
  else
    # rsyslog absent: inform then propose install
    log "rsyslog is not active on this system."
    log "  - With rsyslog : dedicated /var/log/blocked-ips.log file with rotation."
    log "  - Without rsyslog: logs in journald, via 'journalctl -k --grep BLOCKED:'"
    echo ""
    if ask_yes_no "Install rsyslog and configure the filter + logrotate?" yes; then
      log "Installing rsyslog..."
      if [ "$PKG_MANAGER" = "apt" ]; then
        apt install -y rsyslog
      else
        dnf install -y rsyslog
      fi
      systemctl enable rsyslog 2>/dev/null || true
      systemctl start rsyslog 2>/dev/null || true
      if systemctl is-active --quiet rsyslog 2>/dev/null; then
        has_rsyslog=1
        log "rsyslog installed and active."
      else
        err "rsyslog installed but not active after start. The filter will be ignored."
        log "To view logs: journalctl -k --grep 'BLOCKED:'"
      fi
    else
      # rsyslog declined: offer logrotate alone (useful for /var/log/update-blocklist.log)
      if ! ask_yes_no "Install logrotate alone anyway (without the rsyslog filter)?" yes; then
        log "Logs not configured. View blocked packets via:"
        log "  journalctl -k --grep 'BLOCKED:'"
        return 0
      fi
      log "Installing logrotate only (without the rsyslog filter)."
    fi
  fi

  # Expected contents (aligned with INSTALL.md)
  local rsyslog_content
  rsyslog_content='template(name="blockedFormat" type="string"
  string="%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute%:%timestamp:::date-second% %msg%\n")

:msg, contains, "BLOCKED: " /var/log/blocked-ips.log;blockedFormat
& stop'

  # 'su root root' is required by logrotate >= 3.18 when /var/log is owned
  # by root:syslog (Debian/Ubuntu default 775). Without it, rotation is
  # silently skipped on stricter setups. Standard pattern, also used by
  # /etc/logrotate.d/ubuntu-pro-client.
  local logrotate_app_content
  logrotate_app_content='/var/log/update-blocklist.log {
	su root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
}'

  local logrotate_blocked_content
  logrotate_blocked_content='/var/log/blocked-ips.log {
	su root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	postrotate
		if [ -x /usr/lib/rsyslog/rsyslog-rotate ]; then
			/usr/lib/rsyslog/rsyslog-rotate
		else
			/bin/systemctl reload rsyslog 2>/dev/null || true
		fi
	endscript
}'

  local need_rsyslog_restart=0

  if [ "$has_rsyslog" -eq 1 ]; then
    if _install_config /etc/rsyslog.d/30-blocked-ips.conf "$rsyslog_content" "rsyslog filter"; then
      need_rsyslog_restart=1
    fi
  fi
  _install_config /etc/logrotate.d/update-blocklist "$logrotate_app_content" "Logrotate update-blocklist" || true
  _install_config /etc/logrotate.d/blocked-ips "$logrotate_blocked_content" "Logrotate blocked-ips" || true

  if [ "$need_rsyslog_restart" -eq 1 ]; then
    if systemctl restart rsyslog 2>/dev/null; then
      log "rsyslog restarted."
    else
      err "Cannot restart rsyslog. Do it manually (systemctl restart rsyslog)."
    fi
  fi
}

extract_nft_admin_access_ports() {
  nft list chain inet admin_access input 2>/dev/null | awk '
    / accept/ && /(tcp|udp)[[:space:]]+dport/ {
      proto = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "tcp" || $i == "udp") {
          proto = $i
          break
        }
      }
      if (proto == "") next

      for (i = 1; i <= NF; i++) {
        if ($i != "dport") continue

        if ($(i + 1) ~ /^\{/) {
          for (j = i + 1; j <= NF; j++) {
            token = $j
            done = (token ~ /}/)
            gsub(/[{}]/, "", token)
            n = split(token, ports, ",")
            for (k = 1; k <= n; k++) {
              if (ports[k] ~ /^[0-9]+$/) print ports[k] "/" proto
            }
            if (done) break
          }
        } else {
          token = $(i + 1)
          gsub(/[{}]/, "", token)
          n = split(token, ports, ",")
          for (k = 1; k <= n; k++) {
            if (ports[k] ~ /^[0-9]+$/) print ports[k] "/" proto
          }
        }
      }
    }
  ' | sort -t/ -k1,1n -k2,2 -u | tr '\n' ' ' | sed 's/ *$//'
}

# --- Migration: legacy nftables admin_access chain priority bug ---
# Before this fix, the 'inet admin_access input' chain was created at priority -10
# (before the blocklist at priority 0). Result: on nftables, blacklisted IPs still
# passed on SSH/SAFE_PORTS because the admin_access accept evaluated before the
# blocklist drop. Priority must be positive so the blocklist drop applies first.
if command -v nft >/dev/null 2>&1; then
  # The pattern matches both forms: "priority -10" and "priority filter - 10"
  # (nftables canonicalises depending on the version: raw int on older,
  # named+offset on newer). The trailing ";" anchors the value so we don't
  # match -100, -101, etc.
  if nft list chain inet admin_access input 2>/dev/null | grep -qE "priority [^;]*-[[:space:]]*10[[:space:]]*;"; then
    log "Migration: 'inet admin_access input' chain detected at priority -10 (legacy bug)."
    existing_ports="$(extract_nft_admin_access_ports)"
    nft delete chain inet admin_access input
    nft add chain inet admin_access input '{ type filter hook input priority 10 ; policy accept ; }'
    if [ -n "${existing_ports:-}" ]; then
      for entry in $existing_ports; do
        p="${entry%/*}"
        proto="${entry#*/}"
        nft add rule inet admin_access input "$proto" dport "$p" accept
      done
      log "  Rules restored: ports $existing_ports"
    else
      err "Warning: no simple tcp/udp dport rule found to restore in admin_access."
    fi
    log "  Priority corrected to 10 -> the blocklist (priority 0) now evaluates BEFORE."
  fi
fi

# --- Detection result display ---
echo ""
if [ "$DETECTED" = "none" ]; then
  log "No active firewall detected on this system."
else
  log "Active firewall detected: $DETECTED"
fi

# --- Selection menu ---
echo ""
log "Choose the firewall to install and enable:"
echo ""
log "Security note:"
log "  ipshield installs blocklist rules; it is not a full default-deny firewall."
log "  On iptables/nftables, non-blacklisted traffic stays accepted unless you harden the host separately."
echo ""
log "Recommendation:"
log "  - Ubuntu/Debian production server: nftables"
log "  - Fedora/RHEL-family production server: firewalld"
log "  - Legacy/minimal systems: iptables"
log "  - UFW users: supported, but nftables is preferred for new production installs"
echo ""

options=("iptables" "nftables" "firewalld" "ufw")
descriptions=(
  "legacy fallback, broad compatibility for old/minimal systems"
  "recommended for Ubuntu/Debian production servers"
  "recommended for Fedora/RHEL-family production servers"
  "Ubuntu-friendly frontend; supported, nftables preferred for production"
)

for i in "${!options[@]}"; do
  num=$((i + 1))
  marker=""
  if [ "${options[$i]}" = "$DETECTED" ]; then
    marker=" (active)"
  fi
  echo "  $num) ${options[$i]} -- ${descriptions[$i]}${marker}"
done

echo ""
read -rp "Your choice [1-4]: " choice

case "$choice" in
  1) FIREWALL="iptables" ;;
  2) FIREWALL="nftables" ;;
  3) FIREWALL="firewalld" ;;
  4) FIREWALL="ufw" ;;
  *) err "invalid choice: $choice"; exit 1 ;;
esac

offer_disable_inactive_ufw_service

# --- Select iptables backend on systems using update-alternatives ---
select_iptables_backend() {
  local backend="$1"
  local iptables_bin=""
  local ip6tables_bin=""

  case "$backend" in
    legacy)
      iptables_bin="/usr/sbin/iptables-legacy"
      ip6tables_bin="/usr/sbin/ip6tables-legacy"
      ;;
    nft)
      iptables_bin="/usr/sbin/iptables-nft"
      ip6tables_bin="/usr/sbin/ip6tables-nft"
      ;;
    *)
      return 0
      ;;
  esac

  if ! command -v update-alternatives >/dev/null 2>&1; then
    err "cannot switch iptables backend to '$backend': update-alternatives is not available."
    return 1
  fi

  if [ ! -x "$iptables_bin" ]; then
    err "iptables backend '$backend' requested but $iptables_bin is missing."
    return 1
  fi
  if ! update-alternatives --set iptables "$iptables_bin" >/dev/null 2>&1; then
    err "cannot switch iptables backend to $iptables_bin."
    return 1
  fi
  if [ -x "$ip6tables_bin" ]; then
    if ! update-alternatives --set ip6tables "$ip6tables_bin" >/dev/null 2>&1; then
      err "Warning: cannot switch ip6tables backend to $ip6tables_bin."
    fi
  else
    err "Warning: ip6tables backend binary $ip6tables_bin is missing; IPv6 backend was not switched."
  fi
}

current_iptables_backend() {
  command -v iptables >/dev/null 2>&1 || { echo "none"; return; }
  case "$(iptables -V 2>/dev/null || true)" in
    *"(legacy)"*) echo "legacy" ;;
    *"(nf_tables)"*) echo "nft" ;;
    *) echo "unknown" ;;
  esac
}

ensure_iptables_backend() {
  local backend="$1"
  local current
  current="$(current_iptables_backend)"

  [ "$current" = "$backend" ] && return 0

  if docker_iptables_chains_present; then
    prepare_docker_firewall_transition "switch iptables backend from '$current' to '$backend'"
  fi

  if ! select_iptables_backend "$backend"; then
    restart_docker_after_firewall_transition || true
    err "Cannot switch iptables backend to '$backend'."
    exit 1
  fi

  current="$(current_iptables_backend)"
  if [ "$current" != "$backend" ]; then
    restart_docker_after_firewall_transition || true
    err "Requested iptables backend '$backend' but current backend is '$current'."
    exit 1
  fi
}

# --- Listening TCP/UDP ports detection (non-loopback) ---
# Pre-fills the list of ports to allow before activation or on an already
# active firewall, to avoid breaking exposed services.
detect_listening_ports() {
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  {
    ss -tlnp 2>/dev/null | awk -v proto="tcp" 'NR > 1 { print proto, $0 }'
    ss -ulnp 2>/dev/null | awk -v proto="udp" 'NR > 1 { print proto, $0 }'
  } | awk '
    {
      proto = $1
      addr_port = $5
      n = split(addr_port, parts, ":")
      port = parts[n]
      addr = substr(addr_port, 1, length(addr_port) - length(port) - 1)
      # Skip loopback (IPv4 127.0.0.0/8 and IPv6 [::1])
      if (addr == "[::1]" || addr ~ /^127\./) next
      if (port !~ /^[0-9]+$/) next
      proc = "?"
      for (i = 1; i <= NF; i++) {
        if (match($i, /\("[^"]+"/)) {
          # RLENGTH includes ("..."), drop 3 chars (first 2 and trailing ")
          proc = substr($i, RSTART+2, RLENGTH-3)
          break
        }
      }
      print port "/" proto, proc
    }
  ' | sort -t/ -k1,1n -k2,2 | awk '!seen[$1]++'
}

prompt_safe_ports() {
  local context="$1"
  local listening default_ports ans normalized_safe_ports entry p proto

  listening="$(detect_listening_ports)"

  echo ""
  if [ -n "$listening" ]; then
    log "TCP/UDP ports currently listening (non-loopback):"
    while IFS=' ' read -r entry proto; do
      printf "  %-12s %s\n" "$entry" "$proto"
    done <<< "$listening"
    echo ""
    default_ports="$(echo "$listening" | awk '{print $1}' | tr '\n' ' ' | sed 's/ *$//')"
    read -rp "Ports to open $context (port[/tcp|/udp], default: $default_ports, edit the list or 'no' to skip): " SAFE_PORTS
    [ -z "$SAFE_PORTS" ] && SAFE_PORTS="$default_ports"
  else
    read -rp "Ports to open $context (port[/tcp|/udp], bare port = tcp, empty to skip): " SAFE_PORTS
  fi

  if [ "$SAFE_PORTS" = "no" ] || [ "$SAFE_PORTS" = "n" ]; then
    SAFE_PORTS=""
  fi

  if [ -n "$SAFE_PORTS" ]; then
    normalized_safe_ports=""
    for entry in $SAFE_PORTS; do
      if ! [[ "$entry" =~ ^([0-9]+)(/(tcp|udp))?$ ]]; then
        err "invalid port/protocol: $entry"
        exit 1
      fi
      p="${BASH_REMATCH[1]}"
      proto="${BASH_REMATCH[3]:-tcp}"
      if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
        err "invalid port: $p"
        exit 1
      fi
      normalized_safe_ports+="$p/$proto"$'\n'
    done
    SAFE_PORTS="$(printf '%s' "$normalized_safe_ports" | sort -t/ -k1,1n -k2,2 -u | tr '\n' ' ' | sed 's/ *$//')"
  fi
}

ensure_iptables_accept_port() {
  local bin="$1"
  local proto="$2"
  local port="$3"

  "$bin" -C INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1 \
    || "$bin" -I INPUT -p "$proto" --dport "$port" -j ACCEPT
}

nft_admin_access_has_port() {
  local entry="$1"
  extract_nft_admin_access_ports | tr ' ' '\n' | grep -Fxq "$entry"
}

ensure_safe_ports_open() {
  local firewall="$1"
  local ports="$2"
  local entry p proto

  [ -n "$ports" ] || return 0

  case "$firewall" in
    iptables)
      for entry in $ports; do
        p="${entry%/*}"
        proto="${entry#*/}"
        ensure_iptables_accept_port iptables "$proto" "$p"
        if command -v ip6tables >/dev/null 2>&1; then
          ensure_iptables_accept_port ip6tables "$proto" "$p"
        fi
      done
      log "Ports opened (iptables IPv4 + IPv6): $ports"
      ;;
    nftables)
      nft add table inet admin_access 2>/dev/null || true
      # Priority 10 (POSITIVE, after the blocklist at priority 0): if an IP is
      # blacklisted, it is dropped by the blocklist BEFORE reaching this ACCEPT.
      nft add chain inet admin_access input '{ type filter hook input priority 10 ; policy accept ; }' 2>/dev/null || true
      for entry in $ports; do
        p="${entry%/*}"
        proto="${entry#*/}"
        if ! nft_admin_access_has_port "$entry"; then
          nft add rule inet admin_access input "$proto" dport "$p" accept
        fi
      done
      log "Ports opened (nftables): $ports"
      ;;
    firewalld)
      for entry in $ports; do
        firewall-cmd --permanent --add-port="$entry" >/dev/null
      done
      firewall-cmd --reload >/dev/null
      log "Ports opened (firewalld): $ports"
      ;;
    ufw)
      for entry in $ports; do
        ufw allow "$entry"
      done
      log "Ports opened (ufw): $ports"
      ;;
  esac
}

# --- Check if already active ---
if [ "$FIREWALL" = "$DETECTED" ]; then
  echo ""
  if [ "$FIREWALL" = "iptables" ]; then
    ensure_iptables_backend legacy
  elif [ "$FIREWALL" = "nftables" ]; then
    ensure_iptables_backend nft
  fi
  restart_docker_after_firewall_transition || exit 1
  log "$FIREWALL is already active on this system (no transition needed)."
  if ask_yes_no "Review/open listening ports on the active firewall now?" no; then
    prompt_safe_ports "on the active firewall"
    ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
  else
    log "Safe ports not modified."
  fi
  configure_conf
  configure_ipset_restore
  configure_cron
  configure_logs
  echo ""
  log "Now run update-blocklist.sh for the first update; the cron will take over afterwards."
  exit 0
fi

echo ""
log "Installing and enabling: $FIREWALL"

prompt_safe_ports "before activation"

# --- Automatic rollback on failure ---
# If the script fails between deactivating the old firewall and activating
# the new one, the server would be left unprotected. The trap reactivates
# the previous firewall on error or interruption.
rollback() {
  if [ "${ROLLBACK_ARMED:-0}" -eq 1 ]; then
    err "failure detected -- attempting to re-enable $DETECTED..."
    case "$DETECTED" in
      firewalld)
        if systemctl start firewalld 2>/dev/null; then log "firewalld re-enabled."
        else err "cannot re-enable firewalld."; fi ;;
      ufw)
        if [ -n "${UFW_TRANSITION_BACKUP:-}" ] && [ -f "$UFW_TRANSITION_BACKUP" ]; then
          cp "$UFW_TRANSITION_BACKUP" /etc/ufw/before.rules
          log "ufw before.rules restored from transition backup."
        fi
        if ufw --force enable 2>/dev/null; then log "ufw re-enabled."
        else err "cannot re-enable ufw."; fi ;;
      nftables)
        if systemctl start nftables 2>/dev/null; then log "nftables re-enabled."
        else err "cannot re-enable nftables."; fi ;;
      iptables)
        if [ -n "${IPTABLES_BACKUP:-}" ] && [ -f "$IPTABLES_BACKUP" ]; then
          if iptables-restore < "$IPTABLES_BACKUP" 2>/dev/null; then log "iptables rules restored."
          else err "cannot restore iptables rules."; fi
        else
          err "no iptables backup available."
        fi
        if [ -n "${IPTABLES_BACKUP6:-}" ] && [ -f "$IPTABLES_BACKUP6" ]; then
          if ip6tables-restore < "$IPTABLES_BACKUP6" 2>/dev/null; then log "ip6tables rules restored."
          else err "cannot restore ip6tables rules."; fi
        fi ;;
    esac
  fi
  restart_docker_after_firewall_transition || true
  rm -f "${IPTABLES_BACKUP:-}" "${IPTABLES_BACKUP6:-}" 2>/dev/null || true
}
trap rollback EXIT INT TERM

# Docker owns iptables/nft compatibility chains while it is running. Firewall
# transitions can delete or hide those chains (especially nat/DOCKER), breaking
# published ports. During an interactive setup, offer to stop Docker, clean
# Docker-owned chains, continue the transition, then restart Docker.
if [ "$FIREWALL" != "$DETECTED" ] && docker_iptables_chains_present; then
  prepare_docker_firewall_transition "firewall transition from '$DETECTED' to '$FIREWALL'"
fi

# --- Deactivate old firewall ---
if [ "$DETECTED" != "none" ]; then
  ROLLBACK_ARMED=1
  log "Disabling old firewall: $DETECTED"
  case "$DETECTED" in
    firewalld)
      systemctl stop firewalld
      systemctl disable firewalld
      ;;
    ufw)
      cleanup_ufw_ipshield_before_rules_for_transition
      ufw disable
      ;;
    nftables)
      systemctl stop nftables
      systemctl disable nftables
      ;;
    iptables)
      if docker_iptables_chains_present; then
        prepare_docker_firewall_transition "flush iptables tables while disabling old firewall"
      fi
      # Backup rules before flush (for rollback on failure)
      IPTABLES_BACKUP="$(mktemp)"
      iptables-save > "$IPTABLES_BACKUP"
      for table in filter nat mangle raw; do
        iptables -t "$table" -F 2>/dev/null || true
        iptables -t "$table" -X 2>/dev/null || true
      done
      if command -v ip6tables >/dev/null 2>&1; then
        IPTABLES_BACKUP6="$(mktemp)"
        ip6tables-save > "$IPTABLES_BACKUP6"
        for table in filter nat mangle raw; do
          ip6tables -t "$table" -F 2>/dev/null || true
          ip6tables -t "$table" -X 2>/dev/null || true
        done
      fi
      log "iptables/ip6tables tables flushed (flush + delete chains)."
      ;;
  esac
  log "$DETECTED disabled."
fi

# --- Install new firewall ---
log "Installing $FIREWALL package..."
if [ "$PKG_MANAGER" = "apt" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt update -qq
fi
# `ipset` and `curl` are installed alongside the firewall (dependencies of
# update-blocklist.sh, often missing on minimal Debian).
case "$FIREWALL" in
  iptables)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y iptables ipset curl
    else
      dnf install -y iptables ipset curl
    fi
    ;;
  nftables)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y nftables ipset curl
    else
      dnf install -y nftables ipset curl
    fi
    ;;
  firewalld)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y firewalld ipset curl
    else
      dnf install -y firewalld ipset curl
    fi
    ;;
  ufw)
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt install -y ufw ipset curl
    else
      dnf install -y ufw ipset curl
    fi
    ;;
esac

# --- Enable and start the new firewall ---
log "Enabling $FIREWALL..."
case "$FIREWALL" in
  iptables)
    ensure_iptables_backend legacy
    ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
    log "iptables is ready (no systemd service to enable)."
    ;;
  nftables)
    ensure_iptables_backend nft
    systemctl enable nftables
    systemctl start nftables
    ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
    ;;
  firewalld)
    systemctl enable firewalld
    systemctl start firewalld
    ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
    ;;
  ufw)
    ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
    ufw --force enable
    ;;
esac

# --- Post-activation verification: is the firewall responding? ---
# If the check fails, we exit with an error; the rollback trap will re-enable
# the old firewall (ROLLBACK_ARMED is still 1).
log "Checking firewall state..."
case "$FIREWALL" in
  iptables)
    if ! iptables -L -n >/dev/null 2>&1; then
      err "iptables not responding after installation."
      exit 1
    fi
    ;;
  nftables)
    if ! systemctl is-active --quiet nftables; then
      err "nftables not active after start (systemctl is-active failed)."
      exit 1
    fi
    ;;
  firewalld)
    state="$(firewall-cmd --state 2>/dev/null || echo "unknown")"
    if [ "$state" != "running" ]; then
      err "firewalld not in 'running' state (state: $state)."
      exit 1
    fi
    ;;
  ufw)
    if ! ufw status 2>/dev/null | grep -qE "^Status: active$"; then
      err "ufw not active after --force enable."
      exit 1
    fi
    ;;
esac
log "$FIREWALL is operational."

# Disarm the rollback once the new firewall is confirmed operational. A later
# Docker restart failure must not re-enable the old firewall on top of it.
ROLLBACK_ARMED=0
rm -f "${IPTABLES_BACKUP:-}" "${IPTABLES_BACKUP6:-}" 2>/dev/null || true

restart_docker_after_firewall_transition || exit 1

trap - EXIT INT TERM

echo ""
log "$FIREWALL installed and enabled successfully."

configure_conf
configure_ipset_restore
configure_cron
configure_logs

echo ""
log "Now run update-blocklist.sh for the first update; the cron will take over afterwards."
