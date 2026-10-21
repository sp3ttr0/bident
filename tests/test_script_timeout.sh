#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ui.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
source lib/workflow.sh
[[ "$SCRIPT_TIMEOUT" == 15m ]]

# Stop after argument validation; do not run any network commands.
require_root_scan_run() { printf 'validated:%s\n' "$SCRIPT_TIMEOUT"; exit 0; }
for value in 15m 1h 900 0 1.5s 500ms; do
  output="$(main -t 192.0.2.1 --script-timeout "$value")"
  [[ "$output" == "validated:$value" ]]
done
for value in invalid -1 1d '15m;echo unsafe' ''; do
  if (main -t 192.0.2.1 --script-timeout "$value") >/dev/null 2>&1; then
    printf 'Unexpectedly accepted timeout: %s\n' "$value" >&2
    exit 1
  fi
done
if (main -t 192.0.2.1 --script-timeout) >/dev/null 2>&1; then exit 1; fi

# All version/script commands must carry the timeout, after the timing template.
while IFS= read -r command; do
  [[ "$command" == *--script-timeout* ]]
done < <(grep -E 'nmap .*-(sV|sUV|sU .*sV)' lib/workflow.sh)

test_dir="$(mktemp -d /tmp/bident-script-timeout.XXXXXX)"
cd "$test_dir"
has_open_port() { return 0; }
timed_out() { printf 'NSE: ssh-brute M:123 timed out\n'; }
failed() { printf 'command failure\n'; return 2; }
finished() { printf 'username: discovered-user\n'; }
run_if_open 'SSH NSE' tcp 22 timed_out
run_if_open 'FTP NSE' tcp 21 failed
run_if_open 'MySQL NSE' tcp 3306 finished
grep -Fq 'Incomplete: script timeout' "$LOG_DIR/nse_status.tsv"
grep -Fq 'Incomplete: command failed (exit 2)' "$LOG_DIR/nse_status.tsv"
grep -Fq 'Finished; review output' "$LOG_DIR/nse_status.tsv"
grep -Fq 'username: discovered-user' "$LOG_DIR/nse_MySQL_NSE.log"
append_nse_status_section report.html
grep -Fq 'Incomplete: script timeout' report.html
grep -Fq 'logs/nse_SSH_NSE.log' report.html
printf 'Script timeout checks passed.\n'
