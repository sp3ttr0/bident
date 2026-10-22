#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-credential-endpoints.XXXXXX)"
cd "$test_dir"
mkdir -p "$NSE_DIR" "$MSF_RESULT_DIR"
cat > "$NSE_DIR/db_mysql.txt" <<'EOF'
# Nmap scan initiated as: nmap --script-args username=wrong,password=wrong
Nmap scan report for db.example (192.0.2.10)
3306/tcp open mysql
| mysql-users:
|   alice
|_  root
Nmap scan report for 192.0.2.11
| username: unattributed
2222/tcp open ssh
| username: bob
| password: spaces & <symbols>!
Host script results:
| username: host-only
Command: nmap -iL targets.txt --script-args user=wrong
| username: no-target
EOF
printf '[+] 192.0.2.12:161 - Login Successful: public (Access level: read-only)\n[-] 192.0.2.13:161 - LOGIN FAILED: private\n' > "$MSF_RESULT_DIR/snmp_login_udp_161.txt"
credential_candidate_lines "$NSE_DIR/db_mysql.txt" > rows.txt
expected=$'username: alice\t192.0.2.10:3306\nusername: root\t192.0.2.10:3306'
actual="$(awk -F '\034' '$3 ~ /^username:/ {print $3 "\t" $4}' rows.txt)"
[[ "$actual" == "$expected" ]] || exit 1
[[ "$(awk -F '\034' '$2 ~ /username: bob/ {print $4}' rows.txt)" == '192.0.2.11:2222' ]] || exit 1
[[ -z "$(awk -F '\034' '$2 ~ /unattributed|host-only|no-target/ {print $4}' rows.txt | tr -d '\n')" ]] || exit 1
append_credential_summary_section report.html
grep -Fq 'Copy entries with Host:Port' report.html || exit 1
grep -Fq 'Copy Host:Port only' report.html || exit 1
grep -Fq 'data-verified="true">192.0.2.10:3306' report.html || exit 1
grep -Fq 'data-verified="true">192.0.2.12:161' report.html || exit 1
grep -Fq 'data-verified="false">Not identified' report.html || exit 1
grep -Fq 'password: spaces &amp; &lt;symbols&gt;!' report.html || exit 1
! grep -Fq '192.0.2.13:161' report.html || exit 1
! grep -Fq 'user=wrong' report.html || exit 1
printf 'Credential endpoint checks passed.\n'
