#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/checks.sh
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
run_logged() { shift; printf '%s\n' "$*" >> calls.txt; return "${external_status:-0}"; }
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
