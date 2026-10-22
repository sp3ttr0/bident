#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/report.sh

assert_count() {
  local expected="$1" actual
  actual="$(credential_candidate_lines /dev/stdin | awk 'END {print NR + 0}')"
  [[ "$actual" -eq "$expected" ]] || {
    printf 'Expected %s candidates, got %s\n' "$expected" "$actual" >&2
    exit 1
  }
}

assert_count 0 <<'EOF'
# Nmap scan initiated as: nmap --script-args username=sa,password=example
sudo /usr/bin/nmap --script-args username=sa
Command: curl https://example.test/?username=admin&password=test
https://example.test/?user=admin&token=example
| NTLM domain: WORKGROUP
| NTLM authentication supported for domain users
| username: <unknown>
| password: [redacted]
| password: ********
| password:
| token: null
| account: disabled
[-] Login failed: username=admin password=test
| Anonymous login denied
| Anonymous access disabled
| No valid credentials: found
| username: admin (incorrect password)
| Valid credentials not found
Usage: username=example
Example: password=example
| password policy: minimum length 8
EOF

assert_count 8 <<'EOF'
| mysql-users:
|   debian-sys-maint
|   guest
|_  rootx
| mysql-info:
|   Protocol: 10
|_  Version: 5.0.51a
| username: discovered-user
| password: discovered-password
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
[+] Login Successful: admin:example
| hash: abc123def456
EOF

# Explicit NSE credential pairs must work for every username, without a list
# of privileged/common names. Failed attempts and bare pairs stay excluded.
assert_count 11 <<'EOFPAIRS'
| root:root - Valid credentials
| netadmin:netadmin - Valid credentials
| guest:guest - Valid credentials
| user:user - Valid credentials
| web:web - Valid credentials
| sysadmin:sysadmin - Valid credentials
| administrator:administrator - Valid credentials
| webadmin:webadmin - Valid credentials
| admin:admin - Valid credentials
|_ test:test - Valid credentials
| custom-account:custom-password - Valid credentials
EOFPAIRS
assert_count 0 <<'EOFNEGATIVE'
| root:root
| root:root - Invalid credentials
| guest:guest - No valid credentials
| root:root - Valid credentials not found
Example: root:root - Valid credentials
Command: root:root - Valid credentials
| root:[redacted] - Valid credentials
EOFNEGATIVE
fixture="$(mktemp "${TMPDIR:-/tmp}/bident-valid-pairs.XXXXXX")"
printf 'Nmap scan report for 192.0.2.10\n21/tcp open ftp\n' > "$fixture"
for name in root netadmin guest user web sysadmin administrator webadmin admin test; do
  printf '| %s:%s - Valid credentials\n' "$name" "$name" >> "$fixture"
  [[ "$(credential_display_value "| $name:$name - Valid credentials")" == "$name:$name - Valid credentials" ]] || exit 1
done
credential_candidate_lines "$fixture" > "${fixture}.rows"
[[ "$(awk -F '\034' '$4 == "192.0.2.10:21" {n++} END {print n+0}' "${fixture}.rows")" == 10 ]] || exit 1
assert_count 0 <<'EOFBOUNDARY'
[-] username: admin
[-] 192.0.2.1:21 - root:root - Valid credentials
| username: admin - Not valid credentials
| root:******** - Valid credentials
| http-title: Login Successful
| banner: Authentication Successful
resource (test.rc)> set USERNAME login successful
Command: echo root:root - Valid credentials
EOFBOUNDARY
assert_count 2 <<'EOFSUCCESS'
[+] 192.0.2.10:21 - root:root - Valid credentials
[+] 192.0.2.11:161 - Login Successful: public
EOFSUCCESS
printf 'Credential extraction checks passed.\n'
