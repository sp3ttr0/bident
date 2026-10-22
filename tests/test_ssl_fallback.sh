#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/checks.sh
awk '
  /run_if_open.*NSE/ {last_nse = NR}
  /^[[:space:]]*run_ssl_checks$/ {tls = NR; count++}
  /^[[:space:]]*run_msf_auxiliary_checks$/ {msf = NR}
  END {if (count != 1 || tls <= last_nse || tls >= msf) exit 1}
' lib/workflow.sh || exit 1
test_dir="$(mktemp -d /tmp/bident-ssl-fallback.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR"
command_available() {
  case "$1" in
    testssl) [[ "$testssl_available" == true ]] ;;
    sslscan) [[ "$sslscan_available" == true ]] ;;
    *) return 1 ;;
  esac
}
open_target_ports() { printf '192.0.2.1 443\n'; }
open_targets_file_for_ports() { printf 'tls-targets.txt'; }
print_progress_bar() { :; }
run_tls_target() { shift; printf '%s\n' "$*" >> calls.txt; return 0; }
run_if_open() { shift 3; "$@"; }
nmap() { printf 'nmap %s\n' "$*" >> calls.txt; }
check_case() {
  testssl_available="$1"; sslscan_available="$2"; expected="$3"
  : > calls.txt
  run_ssl_checks > /dev/null
  actual="$(cat calls.txt)"
  [[ "$actual" == "$expected" ]] || { printf 'Unexpected TLS routing: %s\n' "$actual" >&2; exit 1; }
}
check_case true true $'testssl 192.0.2.1:443\nsslscan 192.0.2.1:443'
check_case true false 'testssl 192.0.2.1:443'
check_case false true 'sslscan 192.0.2.1:443'
testssl_available=false; sslscan_available=false
: > calls.txt
run_ssl_checks > /dev/null
grep -Fq -- '--script ssl-* and not dos' calls.txt || exit 1
grep -Fq -- '--script-timeout 30m' calls.txt || exit 1
[[ "$(wc -l < calls.txt | tr -d ' ')" == 1 ]] || exit 1
external_status=1
check_case true true $'testssl 192.0.2.1:443\nsslscan 192.0.2.1:443'
printf 'TLS fallback checks passed.\n'
