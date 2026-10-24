#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/metasploit.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-netbios.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$MSF_RESULT_DIR"
printf 'target\tprotocol\tport\n192.0.2.1\tudp\t137\n192.0.2.2\ttcp\t137\n192.0.2.3\tudp\t138\n' > open.tsv
msf_write_targets_file open.tsv udp 137 targets.txt
[[ "$(cat targets.txt)" == 192.0.2.1 ]] || exit 1
msf_add_port_modules netbios.rc udp 137 targets.txt
grep -Fq 'use auxiliary/scanner/netbios/nbname' netbios.rc || exit 1
grep -Fq 'set RPORT 137' netbios.rc || exit 1
msf_add_port_modules tcp.rc tcp 137 targets.txt
[[ ! -s tcp.rc ]] || exit 1
cat > "$MSF_RESULT_DIR/nbname_udp_137.txt" <<'DATA'
[*] Sending NetBIOS requests to 192.0.2.1->192.0.2.9 (9 hosts)
[+] 192.0.2.1 [SERVER01] OS:Windows Names:(SERVER01, CORP) Mac:00:11:22:33:44:55
[-] 192.0.2.2 Auxiliary failed: NameError
[*] Auxiliary module execution completed
DATA
[[ "$(msf_finding_lines "$MSF_RESULT_DIR/nbname_udp_137.txt" endpoints)" == 192.0.2.1:137 ]] || exit 1
append_findings_summary_section report.html
grep -Fq '<strong>NetBIOS Information Disclosure</strong>' report.html || exit 1
grep -Fq '<td>192.0.2.1:137</td>' report.html || exit 1
grep -Fq 'nbname_udp_137.txt:2' report.html || exit 1
[[ "$(default_result_label nbname_udp_137.txt)" == 'NetBIOS Information Disclosure' ]] || exit 1
printf 'NetBIOS Metasploit checks passed.\n'
