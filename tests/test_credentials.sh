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

printf 'Credential extraction checks passed.\n'
