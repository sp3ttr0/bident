#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/metasploit.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-msf-capture.XXXXXX")"
mkdir -p "$fixture_dir/path with spaces"
cd "$fixture_dir/path with spaces"
mkdir -p bin targets_with_open_ports
cat > targets_with_open_ports/open_ports_all.tsv <<'DATA'
target	protocol	port
192.0.2.1	tcp	21
192.0.2.1	tcp	25
192.0.2.1	tcp	445
192.0.2.1	tcp	3389
192.0.2.1	tcp	5900
192.0.2.1	udp	137
192.0.2.1	udp	161
DATA
# Turn literal tabs into the TSV delimiter without shell interpretation.
python3 - <<'PYTEST'
from pathlib import Path
p=Path('targets_with_open_ports/open_ports_all.tsv'); p.write_text(p.read_text().replace('\\t','\t'))
PYTEST
cat > bin/msfconsole <<'MOCK'
#!/bin/bash
while [[ $# -gt 0 ]]; do
 if [[ "$1" == -r ]]; then rc_file="$2"; shift 2; else shift; fi
done
module=$(awk '/^use / {print $2}' "$rc_file")
[[ "$(awk '/^use / {n++} END {print n+0}' "$rc_file")" == 1 ]] || exit 98
if [[ "${MOCK_MSF_FAIL:-false}" == true && "$module" == */snmp_enumshares ]]; then
 printf '[-] Auxiliary failed: NameError broken dependency\n' >&2
 exit 1
fi
case "$module" in
 */ftp/anonymous) printf '[+] 192.0.2.1:21 - Anonymous READ access allowed\n' ;;
 */smtp/smtp_relay) printf '[+] 192.0.2.1:25 - Potential open SMTP relay detected\n' ;;
 */smb/smb_ms17_010) printf '[+] 192.0.2.1:445 - Host is likely VULNERABLE to MS17-010!\n' ;;
 */rdp/rdp_scanner) printf '[*] 192.0.2.1:3389 - Detected RDP on 192.0.2.1:3389 (name:LAB) (Requires NLA: No)\n' ;;
 */rdp/cve_2019_0708_bluekeep) printf '[+] 192.0.2.1:3389 - The target is vulnerable.\n' ;;
 */vnc/vnc_none_auth) printf '[+] 192.0.2.1:5900 - VNC server security types includes None, free access!\n' ;;
 */netbios/nbname) printf '[+] 192.0.2.1 [LAB] OS:Windows Names:(LAB) Mac:00:11:22:33:44:55\n' ;;
 */snmp/snmp_login) printf '[+] 192.0.2.1:161 - Login Successful: public\n' ;;
 */snmp/snmp_enum) printf 'Host IP : 192.0.2.1\n Hostname : LAB\n' ;;
 */snmp/snmp_enumusers) printf '[+] 192.0.2.1:161 Found 1 users: alice\n' ;;
 */snmp/snmp_enumshares) printf '[+] 192.0.2.1\n\tPUBLIC - C:\\Public (0)\n' ;;
 *) exit 97 ;;
esac
printf '[*] Auxiliary module execution completed\n'
MOCK
chmod +x bin/msfconsole
export PATH="$PWD/bin:$PATH"
MSF_TIMEOUT=0
print_progress_bar() { :; }
run_msf_auxiliary_checks > terminal.txt
[[ "$(find "$MSF_RESULT_DIR" -name '*.txt' | wc -l | tr -d ' ')" == 11 ]] || exit 1
for file in "$MSF_RESULT_DIR"/*.txt; do
 [[ -n "$(msf_finding_lines "$file" endpoints)" ]] || { printf 'Missing finding: %s\n' "$file" >&2; exit 1; }
 grep -Fq 'Bident Metasploit process exit: 0' "$file" || exit 1
done
append_findings_summary_section all-findings.html
[[ "$(grep -c '<li><details' all-findings.html)" == 11 ]] || exit 1
# Scope, port and repeated RDP endpoint must all agree.
printf '192.0.2.1\n' > "$MSF_DIR/targets_tcp_3389.txt"
printf '%s\n' '[*] 192.0.2.2:3389 - Detected RDP on 192.0.2.2:3389 (name:OTHER)' '[*] 192.0.2.1:3390 - Detected RDP on 192.0.2.1:3390 (name:WRONGPORT)' '[*] 192.0.2.1:3389 - Detected RDP on 192.0.2.2:3389 (name:MISMATCH)' > "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt" endpoints)" ]] || exit 1
export MOCK_MSF_FAIL=true
run_msf_auxiliary_checks >> terminal.txt
append_findings_summary_section partial-findings.html
[[ "$(grep -c '<li><details' partial-findings.html)" == 10 ]] || exit 1
append_msf_failed_artifacts errors.html
grep -q 'broken dependency' errors.html || exit 1
grep -q 'broken dependency' "$MSF_RESULT_DIR/snmp_enumshares_udp_161.txt" || exit 1
grep -q 'broken dependency' "$MSF_DIR/msfconsole.log" || exit 1
printf 'All-module Metasploit capture checks passed.\n'
