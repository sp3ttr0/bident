#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-affected-endpoints.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR" "$MSF_RESULT_DIR"

append_command_header rpc.txt impacket-rpcdump -p 135 192.0.2.10
printf 'Protocol: test\nProvider: rpc\n' >> rpc.txt
append_command_header rpc.txt impacket-rpcdump -p 135 192.0.2.11
printf 'Protocol: partial\nConnection refused\n' >> rpc.txt
[[ "$(tool_finding_endpoints 'Exposed RPC Services' rpc.txt)" == '192.0.2.10:135' ]] || exit 1

append_command_header anon-rpc.txt rpcclient -U '' -N -c enumprivs 192.0.2.12
printf 'SeBackupPrivilege\n' >> anon-rpc.txt
[[ "$(tool_finding_endpoints 'Unauthenticated Remote Procedure Call' anon-rpc.txt)" == '192.0.2.12:445' ]] || exit 1
append_command_header auth-rpc.txt rpcclient -U admin -c enumprivs 192.0.2.13
printf 'SeBackupPrivilege\n' >> auth-rpc.txt
[[ -z "$(tool_finding_endpoints 'Unauthenticated Remote Procedure Call' auth-rpc.txt)" ]] || exit 1

append_command_header ldap.txt ldapsearch -x -s base -b '' '(objectClass=*)' '*' -H ldap://192.0.2.20:3268
printf 'dn:\nnamingContexts: dc=example,dc=test\n' >> ldap.txt
append_command_header ldap.txt ldapsearch -x -D admin -H ldap://192.0.2.21:389
printf 'dn: dc=example,dc=test\n' >> ldap.txt
[[ "$(tool_finding_endpoints 'LDAP Anonymous Bind' ldap.txt)" == '192.0.2.20:3268' ]] || exit 1

cat > smb.txt <<'EOF'
Command: netexec smb targets_live.txt
SMB 192.0.2.30 445 HOST [*] (signing:False) (SMBv1:True)
SMB 192.0.2.31 445 HOST [*] (signing:True) (SMBv1:False)
SMB 192.0.2.30 445 HOST [*] (signing:False)
EOF
[[ "$(tool_finding_endpoints 'Misconfigured Server Message Block Signing' smb.txt)" == '192.0.2.30:445' ]] || exit 1
[[ "$(tool_finding_endpoints 'SMBv1 Enabled' smb.txt)" == '192.0.2.30:445' ]] || exit 1

append_command_header dns.txt dig @192.0.2.40 google.com A
printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0\n' >> dns.txt
append_command_header dns.txt dig @192.0.2.41 google.com A
printf ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 2\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0\n' >> dns.txt
[[ "$(tool_finding_endpoints 'DNS Recursion Enabled' dns.txt)" == '192.0.2.40:53' ]] || exit 1
# An absent AD flag does not prove DNSSEC is unconfigured.
[[ -z "$(tool_finding_endpoints 'DNSSec Not Configured' dns.txt)" ]] || exit 1

append_command_header ike.txt ike-scan -M 192.0.2.50
printf '192.0.2.50 Main Mode Handshake returned\nSA=(Enc=3DES Hash=SHA1 Group=2:modp1024)\n' >> ike.txt
append_command_header ike.txt ike-scan -M 192.0.2.51
printf 'No handshake returned\nSuggested transform: Enc=3DES Hash=SHA1\n' >> ike.txt
[[ "$(tool_finding_endpoints 'IKE VPN Peer Weak Encryption' ike.txt)" == '192.0.2.50:500' ]] || exit 1

file="$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
cat > "$file" <<'EOF'
resource (rdp.rc)> set RHOSTS file:targets.txt
[*] Detected RDP on 192.0.2.60:3389 (name:LAB)
[-] 192.0.2.61:3389 Auxiliary failed: NameError Net::NTLM
[*] Auxiliary module execution completed
EOF
[[ "$(msf_finding_lines "$file" endpoints)" == '192.0.2.60:3389' ]] || exit 1
printf '[+] The target is vulnerable.\n' > "$MSF_RESULT_DIR/cve_2019_0708_bluekeep_tcp_3389.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/cve_2019_0708_bluekeep_tcp_3389.txt" endpoints)" ]] || exit 1
printf '[+] 192.0.2.62:161 Found 1 users: alice\n' > "$MSF_RESULT_DIR/snmp_enumusers_udp_161.txt"
[[ "$(msf_finding_lines "$MSF_RESULT_DIR/snmp_enumusers_udp_161.txt" endpoints)" == '192.0.2.62:161' ]] || exit 1

append_finding_item report.html Review 'Exposed RPC Services' rpc.txt
append_finding_glob_item report.html Review 'RDP Detection' "$file"
# Full raw output is retained; validate promoted findings separately.
python3 - <<'PYTEST'
from pathlib import Path
import re
p = Path("report.html")
s = p.read_text()
assert "Full Evidence" in s
p.write_text(re.sub(r'<details class="artifact"><summary>Full Evidence.*?</pre></details>', '', s, flags=re.S))
PYTEST
grep -Fq 'Affected' report.html || exit 1
grep -Fq 'Evidence' report.html || exit 1
grep -Fq '<td>192.0.2.10:135</td><td>Protocol: test</td>' report.html || exit 1
grep -Fq '<td>192.0.2.60:3389</td><td>[*] Detected RDP on 192.0.2.60:3389 (name:LAB)</td>' report.html || exit 1
! grep -Fq 'Connection refused' report.html || exit 1
grep -Fq '192.0.2.10:135' report.html || exit 1
grep -Fq '192.0.2.60:3389' report.html || exit 1
! grep -Fq '192.0.2.61:3389' report.html || exit 1
[[ "$(printf '%s\n' '[2001:db8::1]:443' '[2001::::1]:443' '999.2.3.4:22' '192.0.2.1:70000' | verified_ip_port_lines)" == '[2001:db8::1]:443' ]] || exit 1
printf 'Affected endpoint checks passed.\n'
