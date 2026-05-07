#!/bin/bash
# Static regression checks for firewall/Docker safety.
#
# These checks do not touch the local firewall. They guard code paths that are
# hard to exercise on every development machine: Docker-owned chains,
# firewalld direct-rule migration, and iptables backend detection.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

PASS=0

ok() {
  echo "OK   $*"
  PASS=$((PASS + 1))
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

grep -Eq 'iptables -V .*grep -q "\(legacy\)"; then' update-blocklist.sh \
  || fail "update-blocklist.sh must detect iptables legacy even when INPUT has no rules"
ok "update-blocklist.sh detects empty iptables-legacy firewall"

grep -Eq 'iptables -V .*grep -q "\(legacy\)"; then' uninstall.sh \
  || fail "uninstall.sh must detect iptables legacy even when INPUT has no rules"
ok "uninstall.sh detects empty iptables-legacy firewall"

grep -Eq 'iptables -V .*grep -q "\(legacy\)"; then' setup-firewall.sh \
  || fail "setup-firewall.sh must detect iptables legacy even when INPUT has no rules"
ok "setup-firewall.sh detects empty iptables-legacy firewall"

if grep -Eq 'iptables -V .*grep -q "\(legacy\)".*&& iptables_input_rules_present' update-blocklist.sh uninstall.sh setup-firewall.sh; then
  fail "iptables legacy detection is still tied to INPUT rule presence"
fi
ok "iptables legacy detection is not tied to INPUT rules"

if grep -Eq 'firewall-cmd --permanent --direct --add-rule ipv4 filter DOCKER-USER' update-blocklist.sh; then
  fail "firewalld must not persist DOCKER-USER direct rules"
fi
ok "firewalld does not persist DOCKER-USER rules"

grep -q '_remove_firewalld_set_rules DOCKER-USER "$SET_NAME"' update-blocklist.sh \
  || fail "update-blocklist.sh must remove stale firewalld DOCKER-USER block rules"
grep -q '_remove_firewalld_set_rules DOCKER-USER "$WHITELIST_SET_NAME"' update-blocklist.sh \
  || fail "update-blocklist.sh must remove stale firewalld DOCKER-USER whitelist rules"
ok "stale firewalld DOCKER-USER rules are migrated away"

grep -q 'firewall-offline-cmd --direct --get-all-rules' update-blocklist.sh \
  || fail "update-blocklist.sh must be able to inspect broken firewalld permanent config offline"
grep -q 'firewall-offline-cmd --direct --get-all-rules' uninstall.sh \
  || fail "uninstall.sh must be able to inspect broken firewalld permanent config offline"
ok "firewalld offline cleanup path is present"

if grep -q 'read -r -a rule_args <<< "$line"' update-blocklist.sh uninstall.sh; then
  fail "firewalld direct-rule parser still splits quoted log-prefix incorrectly"
fi
ok "firewalld direct-rule parsing handles quoted log-prefix"

grep -q 'Refusing firewall transition' setup-firewall.sh \
  || fail "setup-firewall.sh must refuse firewall transitions while Docker chains exist"
grep -q 'Refusing to switch iptables backend' setup-firewall.sh \
  || fail "setup-firewall.sh must refuse backend switches while Docker chains exist"
ok "setup-firewall.sh keeps Docker firewall transitions guarded"

grep -q 'Docker chains detected outside the current iptables backend' uninstall.sh \
  || fail "uninstall.sh must warn when Docker chains are hidden by another iptables backend"
ok "uninstall.sh warns on hidden Docker chains"

grep -q '_warn_hidden_docker_chains' update-blocklist.sh \
  || fail "update-blocklist.sh must warn when Docker chains are hidden by another iptables backend"
ok "update-blocklist.sh warns on hidden Docker chains"

grep -q 'if remove_firewalld_rules DOCKER-USER; then need_reload=1; fi' uninstall.sh \
  || fail "uninstall.sh must remove stale firewalld DOCKER-USER rules even when Docker is stopped"
ok "uninstall.sh removes stale firewalld DOCKER-USER rules without Docker"

grep -q ': "${LOG_LIMIT=60/min}"' update-blocklist.sh \
  || fail "update-blocklist.sh must default LOG_LIMIT when omitted from config"
grep -q ': "${LOG_BURST=100}"' update-blocklist.sh \
  || fail "update-blocklist.sh must default LOG_BURST when omitted from config"
ok "LOG_LIMIT/LOG_BURST defaults are explicit"

grep -q 'grep -oE -- "--match-set \[\^ \]+ src"' update-blocklist.sh \
  || fail "ufw preflight must detect rules with conntrack before --match-set"
grep -Fq 'sed -i "\\|^-A ufw-before-input .*--match-set $ref_set src |d"' update-blocklist.sh \
  || fail "ufw preflight cleanup must remove generic ufw-before-input match-set rules"
ok "ufw preflight handles conntrack-prefixed rules"

grep -q '_firewalld_reload_or_restart' update-blocklist.sh \
  || fail "update-blocklist.sh must recover firewalld after offline direct-rule cleanup"
docker_cleanup_line="$(grep -n '_remove_firewalld_set_rules DOCKER-USER "$SET_NAME"' update-blocklist.sh | head -1 | cut -d: -f1)"
input_query_line="$(grep -n 'query-rule ipv4 filter INPUT 1' update-blocklist.sh | head -1 | cut -d: -f1)"
if [ -z "$docker_cleanup_line" ] || [ -z "$input_query_line" ] || [ "$docker_cleanup_line" -ge "$input_query_line" ]; then
  fail "firewalld stale DOCKER-USER cleanup must run before INPUT direct-rule queries"
fi
ok "firewalld stale DOCKER-USER cleanup runs before INPUT changes"

grep -q '_firewalld_remove_set_rules_with_reload_hint' update-blocklist.sh \
  || fail "firewalld partial direct-rule cleanup must still hint reload when a removal succeeded"
ok "firewalld partial set-rule cleanup keeps reload signal"

grep -q '_ufw_reload_or_rollback' update-blocklist.sh \
  || fail "ufw before.rules edits must rollback when ufw reload fails"
grep -q 'ufw-before-input .*--match-set $SET_NAME src' update-blocklist.sh \
  || fail "ufw whitelist insertion must match conntrack-prefixed blocklist rules"
ok "ufw rule edits have rollback and generic whitelist insertion"

grep -qF 'expected_pattern="^-A $chain .*--match-set $WHITELIST_SET_NAME src .*-j ACCEPT$"' update-blocklist.sh \
  || fail "iptables whitelist detection without iface must tolerate extra match modules"
ok "iptables whitelist detection is tolerant without iface"

grep -q 'validate_root_config_file "$conf_path" || return 1' setup-firewall.sh \
  || fail "setup-firewall.sh must validate /etc/update-blocklist.conf before sourcing"
ok "setup-firewall.sh validates config before sourcing"

grep -q 'requested but \$iptables_bin is missing' setup-firewall.sh \
  || fail "setup-firewall.sh must fail loudly when requested iptables backend binary is missing"
grep -q "Requested iptables backend" setup-firewall.sh \
  || fail "setup-firewall.sh must verify backend switch result"
! grep -q 'update-alternatives >/dev/null 2>&1 || return 0' setup-firewall.sh \
  || fail "setup-firewall.sh must not silently skip missing update-alternatives"
ok "setup-firewall.sh fails loudly on missing/unchanged iptables backend"

grep -q 'TCP ports to open before activation' setup-firewall.sh \
  || fail "setup-firewall.sh anti-lockout prompt must state that only TCP ports are auto-detected/opened"
ok "setup-firewall.sh labels anti-lockout ports as TCP"

grep -q 'cannot label $IPSET_SAVE_FILE as iptables_var_lib_t' update-blocklist.sh \
  || fail "update-blocklist.sh must warn when SELinux ipset save labeling fails"
ok "SELinux labeling failure is logged"

echo
echo "OK $PASS static regression checks"
