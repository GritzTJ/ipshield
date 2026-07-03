#!/bin/bash
# ipshield v1.2.3
set -euo pipefail
umask 077

# Ensure /sbin and /usr/sbin are in PATH (firewall-cmd, ufw, iptables, nft,
# ipset, ip live there on Debian/Ubuntu). Same rationale as update-ipshield.sh.
export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}"

# --- Usage / help ---
case "${1:-}" in
  -h|--help)
    cat <<'EOF'
Usage: setup-ipshield.sh

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
      log "(for example: docker compose down), then rerun setup-ipshield.sh."
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
      err "Stop the containers first, then rerun setup-ipshield.sh."
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
    err "Stop Docker containers manually or reboot during a maintenance window, then rerun setup-ipshield.sh."
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

# Resolve the path to update-ipshield.sh used by the systemd units.
# Source of truth, in order:
#  1) An existing ipshield.service unit file.
#  2) An existing ipshield-apply.service unit file.
#  3) Same directory as setup-ipshield.sh (the typical fresh install layout).
# Returns the resolved path on stdout (empty string if none of the
# candidates points to an executable file).
detect_update_script_path() {
  local candidate script_dir unit
  for unit in /etc/systemd/system/ipshield.service /etc/systemd/system/ipshield-apply.service; do
    if [ -f "$unit" ]; then
      candidate="$(awk -F= '/^ExecStart=/{print $2; exit}' "$unit" \
        | awk '{print $1}')"
      if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        echo "$candidate"
        return 0
      fi
    fi
  done
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  candidate="$script_dir/update-ipshield.sh"
  if [ -x "$candidate" ]; then
    echo "$candidate"
    return 0
  fi
  return 1
}

# --- Systemd timer + service (8-hour blocklist refresh) ---
# Replaces the historical root crontab entry. The timer fires:
#   - 2 minutes after boot (catches a freshly booted machine; ipshield-apply
#     has already reattached the rules in parallel from the cached ipset),
#   - then at 00:00, 08:00, 16:00 every day with a 5-minute jitter,
#   - Persistent=true catches up a missed run if the machine was off at the
#     scheduled time.
# Stdout/stderr are captured by journald; check via:
#   journalctl -u ipshield.service
configure_timer() {
  local service_path="/etc/systemd/system/ipshield.service"
  local timer_path="/etc/systemd/system/ipshield.timer"
  local script_path

  echo ""
  log "Configuring ipshield.timer (8-hour blocklist refresh)..."

  script_path="$(detect_update_script_path)"
  if [ -z "$script_path" ] || [ ! -x "$script_path" ]; then
    err "Cannot locate an executable update-ipshield.sh. Timer not configured."
    return 0
  fi

  local service_content="[Unit]
Description=ipshield blocklist refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$script_path
StandardOutput=append:/var/log/update-ipshield.log
StandardError=append:/var/log/update-ipshield.log"

  local timer_content="[Unit]
Description=ipshield blocklist refresh schedule

[Timer]
OnBootSec=2min
OnCalendar=*-*-* 00,08,16:00:00
RandomizedDelaySec=5min
Persistent=true
Unit=ipshield.service

[Install]
WantedBy=timers.target"

  local changed=0
  if [ -f "$service_path" ] && [ "$(cat "$service_path")" = "$service_content" ]; then
    log "ipshield.service already up-to-date."
  else
    printf '%s\n' "$service_content" > "$service_path"
    chmod 644 "$service_path"
    log "Installed $service_path"
    changed=1
  fi

  if [ -f "$timer_path" ] && [ "$(cat "$timer_path")" = "$timer_content" ]; then
    log "ipshield.timer already up-to-date."
  else
    printf '%s\n' "$timer_content" > "$timer_path"
    chmod 644 "$timer_path"
    log "Installed $timer_path"
    changed=1
  fi

  if [ "$changed" -eq 1 ]; then
    systemctl daemon-reload
  fi
  systemctl enable --now ipshield.timer >/dev/null 2>&1 || true
  log "ipshield.timer enabled (next runs: 00:00, 08:00, 16:00 + boot)."
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
  local conf_owner conf_perms

  [ -f "$path" ] || return 0
  conf_owner="$(stat -c '%u' "$path")"
  conf_perms="$(stat -c '%a' "$path")"
  if [ "$conf_owner" != "0" ]; then
    err "$path is not owned by root (uid=$conf_owner). Security risk."
    return 1
  fi
  if (( (8#$conf_perms & 022) != 0 )); then
    err "$path is group/world-writable (perms=$conf_perms). Security risk."
    return 1
  fi
}

cleanup_ufw_ipshield_before_rules_for_transition() {
  local rules_path="/etc/ufw/before.rules"
  local snapshot="/etc/ufw/before.rules.ipshield-transition.bak"
  local conf_path="/etc/ipshield.conf"
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
# /etc/ipshield.conf is required by update-ipshield.sh. Copied from
# ipshield.conf.example when missing. If present, kept as-is to
# preserve user modifications.
configure_conf() {
  local conf_path="/etc/ipshield.conf"
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local example="$script_dir/ipshield.conf.example"

  echo ""
  if [ -f "$conf_path" ]; then
    log "Configuration $conf_path: already present, kept as-is."
    log "  To reset from the example: sudo rm $conf_path && re-run setup-ipshield.sh."
    return 0
  fi

  if [ ! -f "$example" ]; then
    err "$example not found. Cannot initialise $conf_path."
    err "  Copy the file manually from the repo, then re-run setup-ipshield.sh."
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
  local conf_path="/etc/ipshield.conf"
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
    # A previous install with PERSIST_IPSET=1 may have left the service
    # enabled; at boot it would load an ipset.save that update-ipshield.sh
    # no longer refreshes. Remove it here to stay consistent.
    local stale_service="/etc/systemd/system/ipshield-restore.service"
    if [ -f "$stale_service" ]; then
      log "Removing stale ipshield-restore.service (PERSIST_IPSET=0)..."
      systemctl disable --now ipshield-restore.service 2>/dev/null || true
      rm -f "$stale_service"
      systemctl daemon-reload 2>/dev/null || true
      log "ipshield-restore.service removed."
    fi
    return 0
  fi

  if [[ "$save_file" != /* ]] || [[ "$save_file" =~ [[:space:]] ]]; then
    err "invalid IPSET_SAVE_FILE in $conf_path: $save_file"
    return 1
  fi

  echo ""
  log "Configuring ipshield-restore.service (ipset persistence across reboot)..."

  if ! command -v ipset >/dev/null 2>&1; then
    err "ipset command not available. Cannot configure restore service."
    return 1
  fi

  local ipset_bin service_path unit_content save_dir source_cache_dir
  ipset_bin="$(command -v ipset)"
  service_path="/etc/systemd/system/ipshield-restore.service"
  save_dir="$(dirname "$save_file")"
  mkdir -p "$save_dir"
  chmod 700 "$save_dir"

  # Pre-create the per-source LKG cache dir under the same root so
  # update-ipshield.sh can write atomically on its first run.
  source_cache_dir="${SOURCE_CACHE_DIR:-/var/lib/ipshield/sources}"
  if [[ "$source_cache_dir" == /* ]] && [[ "$source_cache_dir" != *[[:space:]]* ]]; then
    mkdir -p "$source_cache_dir"
    chmod 700 "$source_cache_dir"
  fi

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
  log "ipset restore service enabled. The save file will be written by update-ipshield.sh after a successful run."
}

# --- ipshield-apply.service: attach firewall rules to the restored ipset ---
# Replaces the historical 'cron @reboot sleep 60 && update-ipshield.sh'
# trick which left a ~70s window where Docker was up but the blocklist was
# not yet applied. The unit runs After=docker.service so DOCKER-USER exists
# when update-ipshield.sh --apply-only inspects it; the apply-only fast
# path skips the download and just attaches LOG/DROP rules to the ipset
# already loaded by ipshield-restore.service. Falls back to a full update
# if the ipset is missing or empty (e.g. PERSIST_IPSET=0).
configure_apply_service() {
  local conf_path="/etc/ipshield.conf"
  local service_path="/etc/systemd/system/ipshield-apply.service"
  local script_path

  echo ""
  log "Configuring ipshield-apply.service (closes the boot exposure window)..."

  script_path="$(detect_update_script_path)"
  if [ -z "$script_path" ] || [ ! -x "$script_path" ]; then
    err "Cannot locate an executable update-ipshield.sh. ipshield-apply.service not configured."
    return 0
  fi

  local unit_content="[Unit]
Description=Attach ipshield firewall rules to the restored blacklist ipset
After=ipshield-restore.service nftables.service ufw.service firewalld.service docker.service
Wants=ipshield-restore.service
ConditionPathExists=$conf_path

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$script_path --apply-only
StandardOutput=append:/var/log/update-ipshield.log
StandardError=append:/var/log/update-ipshield.log

[Install]
WantedBy=multi-user.target"

  if [ -f "$service_path" ] && [ "$(cat "$service_path")" = "$unit_content" ]; then
    log "ipshield-apply.service already up-to-date."
  else
    printf '%s\n' "$unit_content" > "$service_path"
    chmod 644 "$service_path"
    log "Installed $service_path"
  fi

  systemctl daemon-reload
  systemctl enable ipshield-apply.service >/dev/null 2>&1 || true
  log "ipshield-apply.service enabled. Rules will be (re)attached at boot, after Docker."
}

# Resolve the "user group" rsyslog uses to create log files. rsyslog drops
# privileges to an unprivileged user (syslog on Debian/Ubuntu) that cannot
# create files in root-owned /var/log (mode 755, group syslog without write).
# /var/log/ipshield.log must therefore be pre-created -- and recreated by
# logrotate -- with this owner, otherwise the omfile action stays suspended
# ("open error: Permission denied") and no blocked packet is ever written.
# Mirror an existing rsyslog-managed file (ground truth on this host); fall
# back to the distro default when none exists yet (fresh rsyslog install).
# Arg 1: space-separated candidate reference files (override for tests).
# shellcheck disable=SC2120  # arg 1 is a test-only override; prod calls pass none
_rsyslog_file_owner() {
  local refs="${1:-/var/log/syslog /var/log/messages}" ref
  for ref in $refs; do
    if [ -e "$ref" ]; then
      stat -c '%U %G' "$ref" 2>/dev/null && return 0
    fi
  done
  if [ "${PKG_MANAGER:-}" = "apt" ]; then echo "syslog adm"; else echo "root root"; fi
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
    # rsyslog active: install filter + logrotate automatically.
    log "Configuring rsyslog filter + logrotate for ipshield logs..."
  else
    # rsyslog absent: inform then propose install
    log "rsyslog is not active on this system."
    log "  - With rsyslog : dedicated /var/log/ipshield.log file with rotation."
    log "  - Without rsyslog: logs in journald, via 'journalctl -k --grep BLOCKED:'"
    echo ""
    if ask_yes_no "Install rsyslog and configure the filter + logrotate?" yes; then
      log "Installing rsyslog..."
      # Tolerate install failure (no network, held dpkg lock, package absent on a
      # stripped image, disk full): err does not exit, so the is-active check
      # below still runs and falls back to journald instead of aborting setup.
      if [ "$PKG_MANAGER" = "apt" ]; then
        apt install -y rsyslog || err "rsyslog install failed; will fall back to journald."
      else
        dnf install -y rsyslog || err "rsyslog install failed; will fall back to journald."
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
      # rsyslog declined: offer logrotate alone (useful for /var/log/update-ipshield.log)
      if ! ask_yes_no "Install logrotate alone anyway (without the rsyslog filter)?" yes; then
        log "Logs not configured. View blocked packets via:"
        log "  journalctl -k --grep 'BLOCKED:'"
        return 0
      fi
      log "Installing logrotate only (without the rsyslog filter)."
    fi
  fi

  # Expected contents (aligned with README.md "Logs" section)
  # The "MAC=<14 bytes>" field added by iptables LOG is stripped: we block by
  # IP, never by MAC, and the bogon filter guarantees the SRC is never on the
  # same L2 -- the observed MAC is always the gateway's, identical everywhere.
  local rsyslog_content
  rsyslog_content='template(name="blockedFormat" type="string"
  string="%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute%:%timestamp:::date-second%%$.cleanmsg%\n")

if ($msg contains "BLOCKED: ") then {
  set $.pre  = re_extract($msg, "(.*) MAC=[0-9a-fA-F:]+(.*)", 0, 1, $msg);
  set $.post = re_extract($msg, "(.*) MAC=[0-9a-fA-F:]+(.*)", 0, 2, "");
  set $.cleanmsg = $.pre & $.post;
  action(type="omfile" file="/var/log/ipshield.log" template="blockedFormat")
  stop
}'

  # Owner rsyslog uses for the dedicated /var/log/ipshield.log file. logrotate
  # must recreate the file with this owner ('create' directive below) so that,
  # after rotation, the privilege-dropped rsyslog can reopen it -- the same
  # reason it cannot create the file in root-owned /var/log itself.
  local log_owner log_group owner_pair
  # shellcheck disable=SC2119  # intentional: use the default reference list
  owner_pair="$(_rsyslog_file_owner)"
  log_owner="${owner_pair%% *}"
  log_group="${owner_pair##* }"

  # 'su root root' is required by logrotate >= 3.18 when /var/log is owned
  # by root:syslog (Debian/Ubuntu default 755, group syslog without write).
  # Without it, rotation is silently skipped on stricter setups. Standard
  # pattern, also used by /etc/logrotate.d/ubuntu-pro-client.
  local logrotate_app_content
  logrotate_app_content='/var/log/update-ipshield.log {
	su root root
	create 0644 root root
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
}'

  local logrotate_blocked_content
  logrotate_blocked_content="/var/log/ipshield.log {
	su root root
	create 0640 $log_owner $log_group
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
}"

  local need_rsyslog_restart=0

  if [ "$has_rsyslog" -eq 1 ]; then
    # Pre-create the target file so the privilege-dropped rsyslog can open it
    # right away (it cannot create files in root-owned /var/log). Without this
    # the omfile action stays suspended and nothing is logged to the file.
    if [ ! -e /var/log/ipshield.log ]; then
      if install -o "$log_owner" -g "$log_group" -m 0640 /dev/null /var/log/ipshield.log; then
        log "Pre-created /var/log/ipshield.log ($log_owner:$log_group)."
      else
        err "Could not pre-create /var/log/ipshield.log; rsyslog may fail to write it."
      fi
    fi
    if _install_config /etc/rsyslog.d/30-ipshield.conf "$rsyslog_content" "rsyslog filter"; then
      need_rsyslog_restart=1
    fi
  fi
  _install_config /etc/logrotate.d/update-ipshield "$logrotate_app_content" "Logrotate update-ipshield" || true
  _install_config /etc/logrotate.d/ipshield "$logrotate_blocked_content" "Logrotate ipshield" || true

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

# --- Docker-safe firewall transition detection ---
# Returns 0 when the requested transition can be applied without stopping
# Docker. Safe iff:
#   - Target firewall is iptables or nftables (ufw/firewalld activation
#     rewrites tables aggressively and needs Docker stopped).
#   - No old firewall is being deactivated (DETECTED=none); otherwise the
#     deactivation path may flush iptables tables or perturb Docker chains.
#   - Current iptables backend already matches what the target firewall
#     requires (no update-alternatives switch, no orphaning of Docker rules).
firewall_transition_is_safe_for_docker() {
  local detected="$1"
  local target="$2"
  local current target_backend

  case "$target" in
    iptables|nftables) ;;
    *) return 1 ;;
  esac
  [ "$detected" = "none" ] || return 1

  current="$(current_iptables_backend)"
  case "$target" in
    iptables) target_backend="legacy" ;;
    nftables) target_backend="nft" ;;
  esac
  [ "$current" = "$target_backend" ] || return 1
}

# Make nftables.service restart-safe: protect the iptables-nft 'ip filter'
# table (which holds ipshield's blocklist LOG/DROP rules and any Docker
# rules) from being wiped on every 'systemctl restart nftables' -- which
# happens at boot, on nftables package upgrades, and on manual restarts.
#
# Two complementary patches:
#  1) Comment out 'flush ruleset' in /etc/nftables.conf so the ExecStart
#     reload of the conf no longer wipes existing tables.
#  2) Install a systemd drop-in at
#     /etc/systemd/system/nftables.service.d/ipshield.conf that clears
#     ExecStop= (the default unit ships ExecStop=/usr/sbin/nft flush
#     ruleset, which runs before ExecStart on every restart and is the
#     actual wipe trigger).
#
# Without (2), patching only the conf is ineffective for restarts: ExecStop
# fires the flush before ExecStart re-reads the conf. Idempotent. Original
# nftables.conf kept as .ipshield.bak on first patch.
ensure_nftables_persistent_safe() {
  local conf=/etc/nftables.conf
  if [ -f "$conf" ] && grep -qE '^[[:space:]]*flush ruleset' "$conf"; then
    cp "$conf" "${conf}.ipshield.bak"
    sed -i 's|^\([[:space:]]*\)flush ruleset|\1# flush ruleset  # disabled by ipshield: preserves iptables-nft blocklist rules across nftables restarts|' "$conf"
    log "Patched $conf to preserve iptables-nft rules on nftables.service restart (backup: ${conf}.ipshield.bak)."
  fi

  local dropin_dir=/etc/systemd/system/nftables.service.d
  local dropin_path="$dropin_dir/ipshield.conf"
  local dropin_content="# Installed by ipshield (setup-ipshield.sh).
# Clears the default ExecStop=/usr/sbin/nft flush ruleset which would
# otherwise wipe the iptables-nft 'ip filter' table (holding ipshield's
# blocklist LOG/DROP rules and any Docker rules) on every systemctl
# restart of nftables. Combined with the 'flush ruleset' comment-out in
# /etc/nftables.conf, this makes restarts non-destructive for ipshield.
[Service]
ExecStop="

  mkdir -p "$dropin_dir"
  if [ -f "$dropin_path" ] && [ "$(cat "$dropin_path")" = "$dropin_content" ]; then
    return 0
  fi
  printf '%s\n' "$dropin_content" > "$dropin_path"
  chmod 644 "$dropin_path"
  systemctl daemon-reload
  log "Installed $dropin_path (neutralises nftables.service ExecStop flush)."
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

# Returns 0 if the chosen firewall has a deny-by-default INPUT policy. When it
# is permissive (the common case on fresh Debian/Ubuntu with iptables/nftables),
# adding ACCEPT rules for listening ports is functionally a no-op and the prompt
# is skipped entirely.
firewall_input_is_default_deny() {
  local target="$1"
  case "$target" in
    ufw|firewalld)
      # Both ship with deny-by-default zones/policies; SAFE_PORTS always needed.
      return 0
      ;;
    iptables)
      iptables -L INPUT -n 2>/dev/null | head -1 | grep -qE 'policy (DROP|REJECT)'
      ;;
    nftables)
      # Prefer the runtime ruleset if available (it reflects what is actually
      # enforced); fall back to /etc/nftables.conf otherwise. The awk omits
      # `next` after `hook input` so a one-line chain such as
      # `chain input { type filter hook input ... ; policy drop ; }` is also
      # detected (the same line carries both the hook marker and the policy).
      if systemctl is-active --quiet nftables 2>/dev/null; then
        nft list ruleset 2>/dev/null | awk '
          /hook input/ { in_input=1 }
          in_input && /^[[:space:]]*}/ { in_input=0 }
          in_input && /policy (drop|reject)/ { found=1 }
          END { exit(found?0:1) }
        '
      elif [ -f /etc/nftables.conf ]; then
        awk '
          /hook input/ { in_input=1 }
          in_input && /^[[:space:]]*}/ { in_input=0 }
          in_input && /policy (drop|reject)/ { found=1 }
          END { exit(found?0:1) }
        ' /etc/nftables.conf
      else
        return 1
      fi
      ;;
    *)
      return 1
      ;;
  esac
}

# Skip-when-useless wrapper around prompt_safe_ports. Spares the operator the
# port-review prompt when the chosen firewall is permissive on INPUT (rules
# would be no-ops). Sets SAFE_PORTS="" in that case so ensure_safe_ports_open
# becomes a no-op.
configure_safe_ports() {
  local context="$1"
  if firewall_input_is_default_deny "$FIREWALL"; then
    prompt_safe_ports "$context"
  else
    SAFE_PORTS=""
    echo ""
    log "Default INPUT policy on $FIREWALL is ACCEPT; opening additional ports is not needed."
    log "Listening services remain reachable without explicit allow rules."
  fi
}

_generate_safe_ports_nft() {
  local path="$1" ports="$2" entry p proto
  {
    echo "# Generated by setup-ipshield.sh -- regenerated on each rerun."
    echo "table inet admin_access {"
    echo "    chain input {"
    echo "        type filter hook input priority 10; policy accept;"
    for entry in $ports; do
      p="${entry%/*}"
      proto="${entry#*/}"
      echo "        $proto dport $p accept"
    done
    echo "    }"
    echo "}"
  } > "$path"
  chmod 644 "$path"
}

_generate_safe_ports_v4() {
  local path="$1" ports="$2" entry p proto
  {
    echo "# Generated by setup-ipshield.sh -- regenerated on each rerun."
    echo "*filter"
    for entry in $ports; do
      p="${entry%/*}"
      proto="${entry#*/}"
      echo "-I INPUT -p $proto --dport $p -j ACCEPT"
    done
    echo "COMMIT"
  } > "$path"
  chmod 644 "$path"
}

# Persist SAFE_PORTS so they survive reboot on iptables/nftables (ufw and
# firewalld already persist via their own native mechanisms). A dedicated
# systemd unit reapplies the ACCEPT rules early in multi-user.target, before
# sshd.service and docker.service, so admin access is restored as soon as
# possible after boot under a deny-by-default policy.
persist_safe_ports() {
  local firewall="$1"
  local ports="$2"

  case "$firewall" in
    iptables|nftables) ;;
    *) return 0 ;;
  esac

  local service_path="/etc/systemd/system/ipshield-safe-ports.service"
  local conf_dir="/etc/ipshield"
  local nft_path="${conf_dir}/safe-ports.nft"
  local v4_path="${conf_dir}/safe-ports.v4"

  if [ -z "$ports" ]; then
    if [ -f "$service_path" ]; then
      systemctl disable --now ipshield-safe-ports.service >/dev/null 2>&1 || true
      rm -f "$service_path"
      systemctl daemon-reload
      log "ipshield-safe-ports.service removed (no safe ports to persist)."
    fi
    rm -f "$nft_path" "$v4_path"
    return 0
  fi

  mkdir -p "$conf_dir"
  chmod 755 "$conf_dir"

  local exec_start cond_path
  case "$firewall" in
    nftables)
      _generate_safe_ports_nft "$nft_path" "$ports"
      rm -f "$v4_path"
      exec_start="/usr/sbin/nft -f $nft_path"
      cond_path="$nft_path"
      ;;
    iptables)
      _generate_safe_ports_v4 "$v4_path" "$ports"
      rm -f "$nft_path"
      exec_start="/sbin/iptables-restore -n $v4_path"
      cond_path="$v4_path"
      ;;
  esac

  cat > "$service_path" <<EOF
[Unit]
Description=Restore ipshield safe ports for $firewall
After=local-fs.target nftables.service
Before=docker.service ssh.service sshd.service multi-user.target
ConditionPathExists=$cond_path

[Service]
Type=oneshot
ExecStart=$exec_start
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$service_path"
  systemctl daemon-reload
  systemctl enable ipshield-safe-ports.service >/dev/null 2>&1 || true
  log "Safe ports persistence enabled via ipshield-safe-ports.service ($cond_path)."
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
        firewall-cmd --permanent --add-port="$entry" >/dev/null \
          || err "Warning: firewall-cmd --permanent --add-port=$entry failed."
      done
      # Tolerate a reload failure: aborting here (set -e) after the new firewall
      # is already active would trigger the rollback trap and layer the old
      # firewall on top of the running one. Warn instead.
      firewall-cmd --reload >/dev/null \
        || err "Warning: firewall-cmd --reload failed; safe ports may not be active until the next reload."
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
    # Retro-apply the flush ruleset patch on existing installs that
    # predate this change (or that ran setup-ipshield.sh before Docker
    # was installed). Idempotent; no-op if already patched or absent.
    ensure_nftables_persistent_safe
  fi
  restart_docker_after_firewall_transition || exit 1
  log "$FIREWALL is already active on this system (no transition needed)."
  if firewall_input_is_default_deny "$FIREWALL"; then
    if ask_yes_no "Review/open listening ports on the active firewall now?" no; then
      prompt_safe_ports "on the active firewall"
      ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
      persist_safe_ports "$FIREWALL" "$SAFE_PORTS"
    else
      log "Safe ports not modified."
    fi
  else
    log "Default INPUT policy on $FIREWALL is ACCEPT; safe ports prompt skipped (no-op)."
  fi
  configure_conf
  configure_ipset_restore
  configure_timer
  configure_apply_service
  configure_logs
  echo ""
  log "ipshield.timer is now active. The first update may already be running (Persistent=true catches up missed daily slots)."
  log "Monitor with: journalctl -u ipshield.service -f"
  log "Scheduled runs: 00:00, 08:00, 16:00 server local time + boot."
  exit 0
fi

echo ""
log "Installing and enabling: $FIREWALL"

configure_safe_ports "before activation"

# --- Automatic rollback on failure ---
# If the script fails between deactivating the old firewall and activating
# the new one, the server would be left unprotected. The trap reactivates
# the previous firewall on error or interruption.
rollback() {
  if [ "${ROLLBACK_ARMED:-0}" -eq 1 ]; then
    err "failure detected -- attempting to re-enable $DETECTED..."
    case "$DETECTED" in
      firewalld)
        # enable --now: the old firewall was 'disable'd during the transition;
        # 'start' alone would not survive a reboot, leaving the host unprotected
        # at next boot.
        if systemctl enable --now firewalld 2>/dev/null; then log "firewalld re-enabled."
        else err "cannot re-enable firewalld."; fi ;;
      ufw)
        if [ -n "${UFW_TRANSITION_BACKUP:-}" ] && [ -f "$UFW_TRANSITION_BACKUP" ]; then
          cp "$UFW_TRANSITION_BACKUP" /etc/ufw/before.rules 2>/dev/null \
            || err "cannot restore ufw before.rules from transition backup."
          log "ufw before.rules restored from transition backup."
        fi
        if ufw --force enable 2>/dev/null; then log "ufw re-enabled."
        else err "cannot re-enable ufw."; fi ;;
      nftables)
        if systemctl enable --now nftables 2>/dev/null; then log "nftables re-enabled."
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
# When the transition is provably non-destructive (no flush, no backend
# switch, target = iptables/nftables on a Docker-compatible backend), skip the
# Docker stop entirely so running containers stay online.
if [ "$FIREWALL" != "$DETECTED" ] && docker_iptables_chains_present; then
  if firewall_transition_is_safe_for_docker "$DETECTED" "$FIREWALL"; then
    log "Docker chains detected; transition to '$FIREWALL' is safe (no iptables flush, no backend switch). Docker stays online."
  else
    prepare_docker_firewall_transition "firewall transition from '$DETECTED' to '$FIREWALL'"
  fi
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
      # Backup rules before flush (for rollback on failure). If the save fails
      # or yields an empty backup, abort BEFORE flushing: the original rules are
      # still in place, and we clear IPTABLES_BACKUP so the rollback trap does
      # not later restore an empty/partial ruleset over the good one.
      IPTABLES_BACKUP="$(mktemp)"
      if ! iptables-save > "$IPTABLES_BACKUP" || [ ! -s "$IPTABLES_BACKUP" ]; then
        err "iptables-save failed or produced an empty backup; aborting before flush (original rules left intact)."
        rm -f "$IPTABLES_BACKUP"; IPTABLES_BACKUP=""
        exit 1
      fi
      for table in filter nat mangle raw; do
        iptables -t "$table" -F 2>/dev/null || true
        iptables -t "$table" -X 2>/dev/null || true
      done
      if command -v ip6tables >/dev/null 2>&1; then
        IPTABLES_BACKUP6="$(mktemp)"
        # Same guard for IPv6: if the save fails, skip the IPv6 flush (and clear
        # the backup so rollback won't restore a partial v6 ruleset) rather than
        # flushing into an unrecoverable state.
        if ! ip6tables-save > "$IPTABLES_BACKUP6" || [ ! -s "$IPTABLES_BACKUP6" ]; then
          err "ip6tables-save failed or produced an empty backup; skipping IPv6 flush."
          rm -f "$IPTABLES_BACKUP6"; IPTABLES_BACKUP6=""
        else
          for table in filter nat mangle raw; do
            ip6tables -t "$table" -F 2>/dev/null || true
            ip6tables -t "$table" -X 2>/dev/null || true
          done
        fi
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
# update-ipshield.sh, often missing on minimal Debian).
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
    persist_safe_ports "$FIREWALL" "$SAFE_PORTS"
    log "iptables is ready (no systemd service to enable)."
    ;;
  nftables)
    ensure_iptables_backend nft
    # Always patch /etc/nftables.conf to drop 'flush ruleset': the wipe
    # destroys iptables-nft blocklist rules on every restart regardless
    # of Docker being present. The Docker case was the original trigger
    # but the issue is broader (boot, upgrade, manual restart).
    ensure_nftables_persistent_safe
    systemctl enable nftables
    systemctl start nftables
    ensure_safe_ports_open "$FIREWALL" "$SAFE_PORTS"
    persist_safe_ports "$FIREWALL" "$SAFE_PORTS"
    ;;
  firewalld)
    systemctl enable firewalld
    # Pre-seed the safe ports into the permanent config BEFORE starting the
    # daemon, so they are live the instant firewalld comes up. Otherwise a new
    # connection to a non-standard SSH port could be dropped by the default
    # deny-by-default zone during the window between 'start' and the reload in
    # ensure_safe_ports_open. firewall-offline-cmd ships with firewalld and
    # edits the permanent config while the daemon is stopped.
    if [ -n "$SAFE_PORTS" ] && command -v firewall-offline-cmd >/dev/null 2>&1; then
      for entry in $SAFE_PORTS; do
        firewall-offline-cmd --add-port="$entry" >/dev/null 2>&1 \
          || err "Warning: could not pre-seed port $entry offline; it will be added after start."
      done
    fi
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
configure_timer
configure_apply_service
configure_logs

echo ""
log "ipshield.timer is now active. The first update may already be running (Persistent=true catches up missed daily slots)."
log "Monitor with: journalctl -u ipshield.service -f"
log "Scheduled runs: 00:00, 08:00, 16:00 server local time + boot."
