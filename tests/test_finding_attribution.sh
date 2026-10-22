#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-attribution.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR"
cat > ssh.txt <<'DATA'
Command: ssh-audit 192.0.2.1
(enc) aes128-cbc -- [fail] deprecated CBC
Connection reset by peer
Command: ssh-audit 192.0.2.2
(enc) 3des-cbc -- [fail] deprecated 3DES
DATA
[[ "$(ssh_weak_cipher_rows ssh.txt)" == $'192.0.2.2:22\t3des-cbc' ]] || exit 1
cat > "$TOOL_DIR/ssh-audit_results.txt" <<'DATA'
Command: ssh-audit 999.1.1.1
(enc) aes128-cbc -- [fail] deprecated CBC
Command: ssh-audit 192.0.2.3
(enc) 3des-cbc -- [fail] deprecated 3DES
DATA
append_ssh_weak_cipher_finding ssh.html
grep -Fq '<td>192.0.2.3:22</td>' ssh.html || exit 1
! grep -Fq '<td>999.1.1.1:22</td>' ssh.html || exit 1

cat > tls.txt <<'DATA'
Nmap scan report for 192.0.2.10
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.0:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
8443/tcp closed https-alt
| ssl-cert: Subject: commonName=*.wrong.example
| Not valid after: 2020-01-01T00:00:00
Nmap scan report for 192.0.2.11
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.0:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|_ ERROR: Script execution failed
DATA
awk -v kind=nse -v now_utc=20261022000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" tls.txt > tls.rows
[[ "$(awk -F '\034' '{print $1 ":" $2}' tls.rows)" == $'3:192.0.2.10:443\n6:192.0.2.10:443' ]] || exit 1
cat > smb.txt <<'DATA'
SMB 192.0.2.20 445 HOST [-] negotiation failed (signing:False) (SMBv1:True)
SMB 192.0.2.21 445 HOST [*] (signing:False) (SMBv1:True)
DATA
for title in 'Misconfigured Server Message Block Signing' 'SMBv1 Enabled'; do
 [[ "$(tool_finding_endpoints "$title" smb.txt)" == '192.0.2.21:445' ]] || exit 1
done
cat > ike.txt <<'DATA'
Command: ike-scan -M 192.0.2.30
192.0.2.30 Main Mode Handshake returned
192.0.2.31 SA=(Enc=3DES Hash=SHA1 Group=2:modp1024)
DATA
[[ -z "$(tool_finding_endpoints 'IKE VPN Peer Weak Encryption' ike.txt)" ]] || exit 1
cat > ftp_anonymous_tcp_21.txt <<'DATA'
[+] 192.0.2.40:21 Anonymous login failed
[+] 192.0.2.41:21 Anonymous READ access allowed
DATA
[[ "$(msf_finding_lines ftp_anonymous_tcp_21.txt endpoints)" == '192.0.2.41:21' ]] || exit 1
cat > snmp_enum_udp_161.txt <<'DATA'
Host IP : 192.0.2.50
  Hostname : unknown
  Contact : n/a
===== another command =====
  Description : must not use stale host
DATA
[[ -z "$(msf_finding_lines snmp_enum_udp_161.txt endpoints)" ]] || exit 1
printf 'Finding attribution checks passed.\n' 
