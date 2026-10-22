#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ui.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
source lib/workflow.sh
[[ "$TLS_TIMEOUT" == 1800 ]] || { printf "Assertion failed at line %s\n" "$LINENO" >&2; exit 1; }
if (main -t 192.0.2.1 --tls-timeout 600) >/dev/null 2>&1; then exit 1; fi
test_dir="$(mktemp -d /tmp/bident-tls-timeout.XXXXXX)"
cd "$test_dir"
mkdir -p bin "$TOOL_DIR" "$LOG_DIR"
export TLS_TEST_CALLS="$test_dir/calls.txt"
cat > bin/timeout <<'EOF'
#!/bin/bash
printf 'timeout %s\n' "$*" >> "$TLS_TEST_CALLS"
shift 2
"$@"
tool_status=$?
if [[ "${TLS_TEST_TIMEOUT_STATUS:-0}" -ne 0 ]]; then exit "$TLS_TEST_TIMEOUT_STATUS"; fi
exit "$tool_status"
EOF
cat > bin/testssl <<'EOF'
#!/bin/bash
printf 'tool %s\n' "$*" >> "$TLS_TEST_CALLS"
printf 'TLS 1.2 offered\nTLS 1.3 not offered\n'
exit "${TLS_TEST_TOOL_STATUS:-0}"
EOF
cp bin/testssl bin/sslscan
chmod +x bin/timeout bin/testssl bin/sslscan
export PATH="$test_dir/bin:$PATH"
TLS_TIMEOUT=5
export TLS_TEST_TIMEOUT_STATUS=124
run_tls_target "$TOOL_DIR/testssl_results.txt" testssl 192.0.2.1:443 > notice.txt
grep -Fq 'per-target timeout (5s)' notice.txt || exit 1
grep -Fq 'timeout --kill-after=10s 5s testssl --wide --mapping iana 192.0.2.1:443' "$TLS_TEST_CALLS" || exit 1
grep -Fq 'Bident TLS result: Incomplete:' "$TOOL_DIR/testssl_results.txt" || exit 1
[[ -z "$(awk -v kind=testssl -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/testssl_results.txt")" ]] || { printf "Assertion failed at line %s\n" "$LINENO" >&2; exit 1; }
export TLS_TEST_TIMEOUT_STATUS=0
run_tls_target "$TOOL_DIR/testssl_results.txt" testssl 192.0.2.2:443
grep -Fq 'Finished; review output' "$LOG_DIR/tls_status.tsv" || exit 1
[[ "$(awk -v kind=testssl -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/testssl_results.txt" | awk -F '\034' '$1 == 5 {print $2}')" == '192.0.2.2:443' ]] || { printf "Assertion failed at line %s\n" "$LINENO" >&2; exit 1; }
export TLS_TEST_TIMEOUT_STATUS=137
run_tls_target "$TOOL_DIR/sslscan_results.txt" sslscan 192.0.2.3:443 > /dev/null
grep -Fq 'timeout or forced termination' "$LOG_DIR/tls_status.tsv" || exit 1
export TLS_TEST_TIMEOUT_STATUS=0
export TLS_TEST_TOOL_STATUS=1
run_tls_target "$TOOL_DIR/sslscan_results.txt" sslscan 192.0.2.6:443 > /dev/null
grep -Fq 'tool exited with status 1' "$LOG_DIR/tls_status.tsv" || exit 1
command_available() { return 1; }
run_tls_target "$TOOL_DIR/testssl_results.txt" testssl 192.0.2.4:443 > /dev/null
grep -Fq 'Incomplete: timeout command unavailable' "$LOG_DIR/tls_status.tsv" || exit 1
append_tls_status_artifacts status.html
grep -Fq 'TLS External Check Status' status.html || exit 1
grep -Fq '192.0.2.1:443' status.html || exit 1
grep -Fq 'execution log' status.html || exit 1
printf 'TLS per-target timeout checks passed.\n'
