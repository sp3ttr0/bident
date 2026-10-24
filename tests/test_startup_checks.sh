#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ui.sh
source lib/utils.sh
source lib/deps.sh
source lib/ports.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-startup-checks.XXXXXX")"
cd "$fixture_dir"
mkdir -p bin "$LOG_DIR" "$TOOL_DIR"
export STARTUP_CALLS="$fixture_dir/calls"
cat > bin/netexec <<'MOCK'
#!/bin/bash
printf 'netexec %s\n' "$*" >> "$STARTUP_CALLS"
[[ "$*" == 'smb -L' ]] || exit 99
if [[ "${STARTUP_BROKEN:-false}" == true ]]; then
  printf "Traceback (most recent call last):\nAttributeError: 'typing.Union' object has no attribute '__module__'\n"
  exit 1
fi
printf 'Available SMB modules\n'
MOCK
cat > bin/impacket-rpcdump <<'MOCK'
#!/bin/bash
printf 'rpcdump %s\n' "$*" >> "$STARTUP_CALLS"
[[ "$*" == '-h' ]] || exit 99
if [[ "${STARTUP_BROKEN:-false}" == true ]]; then
  printf "Traceback (most recent call last):\nAttributeError: module 'lib' has no attribute 'GEN_EMAIL'\n"
  exit 1
fi
printf 'usage: rpcdump\n'
MOCK
chmod +x bin/*
export PATH="$fixture_dir/bin:$PATH"
run_with_timeout() { [[ "$TOOL_TIMEOUT" == 20 ]] || return 98; "$@"; }
export STARTUP_BROKEN=false
check_external_tool_startup > ok-terminal
[[ "$NETEXEC_STARTUP_OK" == true && "$RPCDUMP_STARTUP_OK" == true ]] || exit 1
[[ ! -s "$LOG_DIR/external_status.tsv" ]] || exit 1
export STARTUP_BROKEN=true
check_external_tool_startup > failed-terminal
[[ "$NETEXEC_STARTUP_OK" == false && "$RPCDUMP_STARTUP_OK" == false ]] || exit 1
grep -q INCOMPLETE failed-terminal || exit 1
[[ "$(wc -l < "$LOG_DIR/external_status.tsv" | tr -d ' ')" == 2 ]] || exit 1
append_external_failed_artifacts failed.html
grep -q GEN_EMAIL failed.html || exit 1
grep -q typing.Union failed.html || exit 1
# Broken optional tools must not be invoked again during the service checks.
has_open_port() { return 0; }
open_target_ports() { printf '192.0.2.1 135\n'; }
command_available() { [[ "$1" != rpcclient ]]; }
run_smb_external_checks > skipped-terminal
run_rpc_135_checks >> skipped-terminal
[[ "$(wc -l < "$STARTUP_CALLS" | tr -d ' ')" == 4 ]] || exit 1
# Guard startup ordering: initialization preserves preflight logs, and no
# responder/discovery starts before dependency probing.
python3 - "$BIDENT_ROOT/lib/workflow.sh" <<'PYTEST'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
p=s.index('  check_external_tool_startup')
assert s.index(': > "${LOG_DIR}/external_status.tsv"') < p
assert p < s.index('  print_section \'Scope & Host Discovery\'')
assert p < s.index('    start_responder')
PYTEST
printf 'Startup dependency checks passed.\n'
