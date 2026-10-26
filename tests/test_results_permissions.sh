#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo_root="$PWD"
source lib/config.sh
source lib/utils.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-permissions.XXXXXX")"
RESULTS_DIR="$fixture_dir/results with spaces"
BIDENT_DROP_PRIVILEGES=true
BIDENT_RUN_USER="$(id -un)"
mkdir -p "$RESULTS_DIR"/{logs,base_scans,nmap_scripts,tool_results,metasploit/results}
for file in report.html summary.json logs/private.log base_scans/syn.nmap nmap_scripts/s_ftp.txt tool_results/ssh-audit_results.txt metasploit/results/rdp_scanner_tcp_3389.txt; do
 printf 'saved evidence\n' > "$RESULTS_DIR/$file"
 chmod 400 "$RESULTS_DIR/$file"
done
printf 'outside\n' > "$fixture_dir/outside.txt"
chmod 400 "$fixture_dir/outside.txt"
ln -s "$fixture_dir/outside.txt" "$RESULTS_DIR/logs/outside-link"
chmod 500 "$RESULTS_DIR/metasploit/results"
# Record ownership operations without needing root in the tests.
chown() { printf '%s\n' "$*" >> "$fixture_dir/chown.calls"; }
allow_unprivileged_output_writes
python3 - "$RESULTS_DIR" "$fixture_dir/outside.txt" <<'PYTEST'
from pathlib import Path
import stat,sys
root=Path(sys.argv[1])
for p in [root,*root.rglob('*')]:
    if p.is_symlink(): continue
    mode=stat.S_IMODE(p.stat().st_mode)
    assert mode & (0o700 if p.is_dir() else 0o600)==(0o700 if p.is_dir() else 0o600), str(p)
    if p.is_file(): assert not mode & 0o077, str(p)
assert stat.S_IMODE(Path(sys.argv[2]).stat().st_mode)==0o400
import shutil, tarfile
shutil.copytree(root, root.parent/'copied-results', symlinks=True)
with tarfile.open(root.parent/'results.tar.gz','w:gz') as archive:
    archive.add(root,arcname='results')
PYTEST
# Cleanup also runs on an unexpected exit and keeps the original exit status.
export RESULTS_DIR BIDENT_RUN_USER
bash -c 'source "$1/lib/config.sh"; source "$1/lib/utils.sh"; BIDENT_DROP_PRIVILEGES=true; BIDENT_RUN_USER="$(id -un)"; chown() { :; }; chmod 400 "$RESULTS_DIR/logs/private.log"; trap '\''finalize_results_on_exit "$?"'\'' EXIT; exit 7' test "$repo_root" && status=0 || status=$?
[[ "$status" == 7 && -w "$RESULTS_DIR/logs/private.log" ]] || exit 1
# Cancel/error cleanup stops only scanner sessions owned by this invocation.
BIDENT_OWNED_SCANS=(syn udp)
screen_session_exists() { return 0; }
screen() { printf '%s\n' "$*" >> "$fixture_dir/stopped.calls"; }
finalize_results_on_exit 130
grep -q 'syn -X quit' "$fixture_dir/stopped.calls" || exit 1
grep -q 'udp -X quit' "$fixture_dir/stopped.calls" || exit 1
! grep -q responder "$fixture_dir/stopped.calls" || exit 1
printf 'Whole-results permission checks passed.\n'
