#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ports.sh
source lib/report.sh
python3 - "$BIDENT_ROOT/lib/workflow.sh" <<'PYWORKFLOW'
from pathlib import Path
import sys,re
s=Path(sys.argv[1]).read_text()
command=re.search(r'"[^"\n]*nmap -n -sU [^"\n]*',s).group()
assert '-sV' not in command and '-sUV' not in command
final=s.index("  print_section 'Report Generation'")
assert s.index('  generate_services_report',final)<s.index('  generate_html_report',final)
PYWORKFLOW
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-udp-services.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$SCAN_DIR" "$NSE_DIR"
for host in 1 2 3; do
 printf 'Host: 192.0.2.%s ()\tPorts: 53/open/udp//domain///, 123/open/udp//ntp///, 137/open/udp//netbios-ns///, 161/open/udp//snmp///, 623/open/udp//asf-rmcp///\n' "$host" >> "$SCAN_DIR/udp.gnmap"
done
printf 'Host: 192.0.2.1 ()\tPorts: 53/open/tcp//domain//TCP DNS version/\n' > "$SCAN_DIR/syn.gnmap"
cat > "$NSE_DIR/udp.txt" <<'DATA'
Nmap scan report for node.example (192.0.2.1)
53/udp open domain
| dns-nsid:
|   id.server: identifier-not-version
|_  bind.version: BIND 9.18.24
123/udp open ntp
| ntp-info:
|   version: ntpd 4.2.8p15
|_  system: Linux
137/udp open netbios-ns
161/udp open snmp
|  snmp-sysdescr: Linux appliance 5.15 <vendor>
|_   System uptime: 1 day
623/udp open asf-rmcp
| ipmi-version:
|_  Version: IPMI-2.0
Host script results:
|_nbstat: NetBIOS name: NODE01, NetBIOS user: <unknown>, NetBIOS MAC: 00:11:22:33:44:55
Nmap scan report for 192.0.2.2
53/tcp open domain
| dns-nsid:
|_ bind.version: MUST-NOT-LEAK-FROM-TCP
123/udp closed ntp
| ntp-info:
|_ version: MUST-NOT-LEAK-FROM-CLOSED-PORT
161/udp open snmp
| snmp-sysdescr: PARTIAL-MUST-NOT-APPEAR
|_ ERROR: Script execution failed
623/udp open|filtered asf-rmcp
| ipmi-version:
|_ Version: MUST-NOT-LEAK-FROM-AMBIGUOUS-PORT
Nmap scan report for 192.0.2.3
53/udp open domain
| dns-nsid:
|_ bind.version: unknown
Host script results:
|_nbstat: NetBIOS name: MUST-NOT-INFER-PORT, NetBIOS user: <unknown>
Nmap scan report for 192.0.2.99
53/udp open domain
| dns-nsid:
|_ bind.version: OUTSIDE-BASE-SCAN
DATA
generate_services_report
generate_html_report
python3 - <<'PYTEST'
from pathlib import Path
import csv
rows=list(csv.DictReader(Path('targets_with_open_ports/services.tsv').open(),delimiter='\t'))
lookup={(r['target'],r['protocol'],r['port']):r for r in rows}
assert lookup['192.0.2.1','tcp','53']['info']=='TCP DNS version'
for r in rows:
 if r['protocol']=='udp': assert r['info']=='',r
 assert r['target']!='192.0.2.99'
s=Path('report.html').read_text()
assert 'Evidence: nmap_scripts/udp.txt:' not in s
assert '<td>Not identified</td>' not in s
PYTEST
# Removing an NSE result must not retain stale enrichment.
: > "$NSE_DIR/udp.txt"
generate_services_report
[[ "$(awk -F '\t' 'NR>1 && $2=="udp" && $5!="" {n++} END {print n+0}' targets_with_open_ports/services.tsv)" == 0 ]] || exit 1
printf 'UDP service table isolation checks passed.\n'
