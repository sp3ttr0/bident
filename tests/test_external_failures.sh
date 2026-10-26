#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/ports.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-external-errors.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR" "$LOG_DIR" bin
cat > bin/mock-tool <<'MOCK'
#!/bin/bash
printf '%b\n' "$MOCK_OUTPUT"
exit "$MOCK_EXIT"
MOCK
cp bin/mock-tool bin/ssh-audit
chmod +x bin/*
export MOCK_OUTPUT MOCK_EXIT
export PATH="$fixture_dir/bin:$PATH"
run_with_timeout() { "$@"; }
MOCK_OUTPUT="Traceback (most recent call last):\nAttributeError: module 'lib' has no attribute 'GEN_EMAIL'"
MOCK_EXIT=1
run_logged_check 'Exposed RPC Services' "$TOOL_DIR/s_rpcdump_135.txt" mock-tool -p 135 192.0.2.1 > terminal.txt
! grep -q 'No Exposed RPC Services Found' terminal.txt || exit 1
grep -q 'Incomplete:' terminal.txt || exit 1
[[ ! -s "$TOOL_DIR/s_rpcdump_135.txt" ]] || exit 1
[[ "$(wc -l < "$LOG_DIR/external_status.tsv" | tr -d ' ')" == 1 ]] || exit 1
# A zero exit status with a traceback remains incomplete.
MOCK_EXIT=0
! run_external_capture 'NetExec' captured mock-tool >> terminal.txt || exit 1
# Timeouts remain distinct from a completed negative check.
MOCK_OUTPUT='partial output'; MOCK_EXIT=124
! run_external_capture 'IKE' captured mock-tool >> terminal.txt || exit 1
grep -q 'timeout or forced termination' terminal.txt || exit 1
# ssh-audit uses 2 and 3 for successful scans with algorithm warnings/failures.
MOCK_OUTPUT='(enc) aes128-cbc -- [fail] deprecated CBC'
for MOCK_EXIT in 2 3; do run_external_capture 'SSH' captured ssh-audit >> terminal.txt || exit 1; done
MOCK_OUTPUT='connection refused'; MOCK_EXIT=1
! run_external_capture 'SSH' captured ssh-audit >> terminal.txt || exit 1
# Ordinary completed negatives still use the existing negative message.
MOCK_OUTPUT='No endpoints returned'; MOCK_EXIT=0
run_logged_check 'Exposed RPC Services' "$TOOL_DIR/s_rpcdump_135.txt" mock-tool > negative.txt
grep -q 'No Exposed RPC Services Found' negative.txt || exit 1
# Successful findings are still retained with their command and evidence.
MOCK_OUTPUT='Protocol: test\nProvider: example'
run_logged_check 'Exposed RPC Services' "$TOOL_DIR/s_rpcdump_135.txt" mock-tool > positive.txt
grep -q 'Protocol: test' "$TOOL_DIR/s_rpcdump_135.txt" || exit 1
append_external_failed_artifacts artifacts.html
grep -q 'External Tool Failed / Incomplete Checks' artifacts.html || exit 1
grep -q GEN_EMAIL artifacts.html || exit 1
! grep -q 'deprecated CBC' artifacts.html || exit 1
# The report places execution errors under Core Artifacts.
generate_html_report
python3 - <<'PYTEST'
from pathlib import Path
s=Path('report.html').read_text()
assert s.index('External Tool Failed / Incomplete Checks') > s.index('<summary>Core Artifacts</summary>')
assert 'GEN_EMAIL' in s
PYTEST
# Exercise dedicated stage runners: none may overwrite a failure with "No ...".
for name in netexec dig ike-scan; do cp bin/mock-tool "bin/$name"; done
has_open_port() { return 0; }
open_target_ports() { printf '192.0.2.1 445\n'; }
MOCK_EXIT=1; MOCK_OUTPUT='Traceback (most recent call last):\nImportError: broken dependency'
printf 'old finding\n' > "$TOOL_DIR/nxc_smb_signing_false.txt"
run_smb_external_checks > smb-terminal.txt
! grep -q 'No .* Found' smb-terminal.txt || exit 1
[[ ! -s "$TOOL_DIR/nxc_smb_signing_false.txt" ]] || exit 1
open_target_ports() { printf '192.0.2.1 53\n'; }
run_dns_dig_checks > dns-terminal.txt
! grep -q 'No .* Found' dns-terminal.txt || exit 1
open_target_ports() { printf '192.0.2.1 500\n'; }
run_ike_weak_encryption_check > ike-terminal.txt
! grep -q 'No .* Found' ike-terminal.txt || exit 1
printf '192.0.2.1\n' > ssh-targets.txt
open_targets_file_for_ports() { printf 'ssh-targets.txt'; }
resolve_command() { printf '%s/bin/ssh-audit' "$fixture_dir"; }
print_progress_bar() { :; }
run_ssh_audit_check > ssh-terminal.txt
! grep -q 'No Weak SSH Ciphers Found' ssh-terminal.txt || exit 1
grep -q 'Incomplete' ssh-terminal.txt || exit 1
# Simulate sudo ownership handoff without requiring root in the test suite.
BIDENT_DROP_PRIVILEGES=true
BIDENT_RUN_USER=scan-owner
chown() { printf '%s\n' "$*" >> ownership.calls; }
MOCK_EXIT=1; MOCK_OUTPUT='Traceback (most recent call last):\nAttributeError: broken dependency'
! run_external_capture 'Ownership regression' captured mock-tool > ownership-terminal || exit 1
grep -q '^scan-owner logs/external_Ownership_regression' ownership.calls || exit 1
python3 - <<'PYTEST'
from pathlib import Path
import stat
files=list(Path('logs').glob('external_Ownership_regression.*'))
assert len(files)==1
assert stat.S_IMODE(files[0].stat().st_mode)==0o600
PYTEST
printf 'External failure handling checks passed.\n'
