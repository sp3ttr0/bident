#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-ftp-sources.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$NSE_DIR" "$MSF_RESULT_DIR"
cat > "$NSE_DIR/s_ftp.txt" <<'DATA'
Nmap scan report for ftp.example (10.104.244.232)
21/tcp open ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_ -rw-r--r-- 1 ftp ftp 12 Jan 1 2026 welcome.txt
| ftp-brute: ERROR: Script execution failed
Nmap scan report for 192.0.2.2
2121/tcp open ftp
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
Nmap scan report for 192.0.2.3
21/tcp open ftp
| ftp-anon: Anonymous FTP login denied (FTP code 530)
Nmap scan report for 192.0.2.4
21/tcp closed ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
Nmap scan report for 192.0.2.5
21/tcp open ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_ ERROR: Script execution failed
Nmap scan report for 192.0.2.6
Host script results:
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
DATA
[[ "$(ftp_anonymous_nse_lines "$NSE_DIR/s_ftp.txt" endpoints)" == $'10.104.244.232:21\n192.0.2.2:2121' ]] || exit 1
append_findings_summary_section nse-only.html
grep -Fq '<strong>FTP Anonymous Enabled</strong>' nse-only.html || exit 1
grep -Fq '<td>10.104.244.232:21</td>' nse-only.html || exit 1
grep -Fq 'nmap_scripts/s_ftp.txt:3' nse-only.html || exit 1
cat > "$MSF_RESULT_DIR/ftp_anonymous_tcp_21.txt" <<'DATA'
[+] 10.104.244.232:21 - Anonymous READ access allowed
[+] 192.0.2.7:21 - Anonymous READ access allowed
DATA
append_findings_summary_section combined.html
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('combined.html').read_text()
assert s.count('<strong>FTP Anonymous Enabled</strong>')==1
assert '3 affected host(s)' in s
table=re.search(r'<div data-affected-targets>.*?</tbody></table>',s,re.S).group()
assert table.count('<td>10.104.244.232:21</td>')==1
for host in ['10.104.244.232:21','192.0.2.2:2121','192.0.2.7:21']:assert f'<td>{host}</td>' in table
for host in ['192.0.2.3:21','192.0.2.4:21','192.0.2.5:21','192.0.2.6:21']:assert host not in table
assert 'Anonymous FTP login allowed (FTP code 230)' in s
assert 'Anonymous READ access allowed' in s
PYTEST
printf 'FTP Nmap/Metasploit source checks passed.\n'
