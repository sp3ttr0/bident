#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ports.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-services.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$SCAN_DIR"
printf 'Host: 10.104.244.47 (host.example)\tPorts: 137/open/udp//netbios-ns//Microsoft Windows netbios-ns (workgroup: CORP)/\tIgnored State: open|filtered (999)\n' > "$SCAN_DIR/udp.gnmap"
printf 'Host: 10.104.244.48 ()\tPorts: 137/open|filtered/udp//netbios-ns///\tIgnored State: closed (999)\n' >> "$SCAN_DIR/udp.gnmap"
generate_services_report
python3 - <<'PYTEST'
from pathlib import Path
rows=Path('targets_with_open_ports/services.tsv').read_text().splitlines()
assert len(rows)==2
assert rows[1].split('\t')==['10.104.244.47','udp','137','netbios-ns','Microsoft Windows netbios-ns (workgroup: CORP)','10.104.244.47:137']
PYTEST
generate_html_report
grep -Fq '<td>10.104.244.47:137</td>' report.html || exit 1
! grep -Fq '<td>Ignored State:' report.html || exit 1
printf 'Service table field checks passed.\n'
