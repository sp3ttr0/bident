#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-msf-findings.XXXXXX)"
cd "$test_dir"
mkdir -p "$MSF_RESULT_DIR"
module_file() {
  local slug="$1" proto=tcp port
  case "$slug" in
    ftp_anonymous) port=21 ;;
    smtp_relay) port=25 ;;
    smb_ms17_010) port=445 ;;
    rdp_scanner|cve_2019_0708_bluekeep) port=3389 ;;
    vnc_none_auth) port=5900 ;;
    snmp_*) proto=udp; port=161 ;;
  esac
  printf '%s/%s_%s_%s.txt' "$MSF_RESULT_DIR" "$slug" "$proto" "$port"
}

# A command/path, stack trace, or generic completion message cannot establish
# any of the ten findings, even when it contains each finding keyword.
for slug in ftp_anonymous smtp_relay smb_ms17_010 rdp_scanner cve_2019_0708_bluekeep vnc_none_auth snmp_login snmp_enum snmp_enumusers snmp_enumshares; do
  file="$(module_file "$slug")"
  cat > "$file" <<EOF
resource (metasploit/rdp.rc)> use auxiliary/scanner/rdp/${slug}
resource (metasploit/rdp.rc)> set username detected_rdp_protocol
RHOSTS => file:/client/open_relay_vulnerable_community_public_users.txt
[-] Auxiliary failed: NameError uninitialized constant Net::NTLM
[-] Call stack:
[-] /usr/share/metasploit-framework/lib/msf/core/exploit/remote/rdp.rb:206
[*] Auxiliary module execution completed
EOF
  [[ -z "$(msf_finding_lines "$file")" ]]
  [[ -n "$(msf_failure_lines "$file")" ]]
done
append_findings_summary_section rejected.html
! grep -Fq '<li>' rejected.html || exit 1
append_msf_failed_artifacts failed.html
grep -Fq 'Metasploit Failed / Incomplete Checks' failed.html || exit 1
grep -Fq 'uninitialized constant Net::NTLM' failed.html || exit 1
! grep -Fq $'\033' failed.html || exit 1

# Retain module-specific successes, including ordinary status-level RDP
# messages and multiline SNMP share enumeration.
while IFS='|' read -r slug evidence; do
  file="$(module_file "$slug")"
  : > "$file"
  if [[ "$slug" == snmp_enum ]]; then printf 'Host IP : 192.0.2.1\n' >> "$file"; fi
  printf '\033[32m%s\033[0m\n' "$evidence" >> "$file"
  [[ -n "$(msf_finding_lines "$file")" ]] || {
    printf 'Missed success: %s\n' "$slug" >&2; exit 1;
  }
done <<'EOF'
ftp_anonymous|[+] 192.0.2.1:21 - Anonymous READ access allowed
smtp_relay|[+] 192.0.2.1:25 - Potential open SMTP relay detected: MAIL FROM -> RCPT TO
smb_ms17_010|[+] 192.0.2.1:445 - Host is likely VULNERABLE to MS17-010!
rdp_scanner|[*] Detected RDP on 192.0.2.1:3389 (name:LAB)
cve_2019_0708_bluekeep|[+] 192.0.2.1:3389 - The target is vulnerable. The target attempted cleanup.
vnc_none_auth|[+] 192.0.2.1:5900 - VNC server security types includes None, free access!
snmp_login|[+] 192.0.2.1:161 - Login Successful: public
snmp_enum|  Hostname : laboratory
snmp_enumusers|[+] 192.0.2.1:161 Found 2 users: alice, bob
EOF
printf '[+] 192.0.2.1\n\tPUBLIC - C:\\Public (0)\n' > "$MSF_RESULT_DIR/snmp_enumshares_udp_161.txt"
[[ -n "$(msf_finding_lines "$MSF_RESULT_DIR/snmp_enumshares_udp_161.txt")" ]] || exit 1

# Errors on another target must not hide a real success in a shared spool.
printf '[-] Auxiliary failed: NameError uninitialized constant Net::NTLM\n' >> "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
append_findings_summary_section positive.html
[[ "$(grep -c '<li>' positive.html)" -eq 10 ]] || exit 1
# Complete logs intentionally retain failures; they must not be promoted evidence.
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('positive.html').read_text()
assert 'NameError' in s
promoted=re.sub(r'<details class="artifact"><summary>Full Evidence.*?</pre></details>', '', s, flags=re.S)
assert 'NameError' not in promoted
PYTEST
append_msf_failed_artifacts mixed-failed.html
grep -Fq 'NameError' mixed-failed.html || exit 1

# Negative and informational results are not findings or execution failures.
printf '[*] 192.0.2.1 does not appear vulnerable to MS17-010\n' > "$MSF_RESULT_DIR/smb_ms17_010_tcp_445.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/smb_ms17_010_tcp_445.txt")" ]] || exit 1
printf '[*] VNC server protocol version: 3.8\n' > "$MSF_RESULT_DIR/vnc_none_auth_tcp_5900.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/vnc_none_auth_tcp_5900.txt")" ]] || exit 1
printf '[-] 192.0.2.1:161 - LOGIN FAILED: public\n' > "$MSF_RESULT_DIR/snmp_login_udp_161.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/snmp_login_udp_161.txt")" ]] || exit 1
[[ -z "$(msf_failure_lines "$MSF_RESULT_DIR/snmp_login_udp_161.txt")" ]] || exit 1

printf 'tcp/3389\t143\n' > "$MSF_DIR/run_status.tsv"
append_msf_failed_artifacts process-failed.html
grep -Fq 'exit 143' process-failed.html || exit 1
generate_html_report
core_line="$(grep -n '<summary>Core Artifacts</summary>' report.html | cut -d: -f1)"
failed_line="$(grep -n '<summary>Metasploit Failed / Incomplete Checks</summary>' report.html | cut -d: -f1)"
[[ "$failed_line" -gt "$core_line" ]] || exit 1
# Core Artifacts embeds actual module output and console output, including
# modules that have no positive finding. Command scripts are separate.
printf '\033[31mConsole execution detail\033[0m\n' > "$MSF_DIR/msfconsole.log"
append_msf_output_artifacts actual-output.html
grep -Fq 'Full Metasploit Console Output' actual-output.html || exit 1
grep -Fq '<pre>Console execution detail' actual-output.html || exit 1
grep -Fq 'does not appear vulnerable to MS17-010' actual-output.html || exit 1
! grep -Fq $'\033' actual-output.html || exit 1
MSF_RESULT_DIR=missing-results append_msf_output_artifacts missing-output.html
grep -Fq 'No per-module result files were saved' missing-output.html || exit 1
grep -Fq 'Console execution detail' missing-output.html || exit 1
printf 'Metasploit finding checks passed.\n'
