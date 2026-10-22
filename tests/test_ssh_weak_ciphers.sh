#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-ssh-ciphers.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR"
fixture="$TOOL_DIR/ssh-audit_results.txt"
cat > "$fixture" <<'EOF'
===== timestamp =====
Command: /usr/bin/ssh-audit 192.0.2.1
(kex) diffie-hellman-group1-sha1 -- [fail] weak
(enc) aes256-ctr -- [info] supported
(mac) hmac-sha1 -- [fail] weak
===== timestamp =====
Command: /usr/bin/ssh-audit 192.0.2.2
(enc) aes128-cbc -- [warn] using weak cipher mode
(enc) 3des-cbc -- [fail] deprecated cipher
  `- [warn] small block size
(rec) -hmac-sha1 -- [warn] remove
===== timestamp =====
Command: /usr/bin/ssh-audit -p 2222 192.0.2.3
(enc) weak-test-cipher -- [info] supported
  `- [warn] insecure mode
===== timestamp =====
Command: /usr/bin/ssh-audit 192.0.2.4
Connection refused
EOF
printf '\n===== timestamp =====\nCommand: /usr/bin/ssh-audit 192.0.2.2\n\033[31m(enc) aes128-cbc -- [warn] weak\033[0m\n' >> "$fixture"
expected=$'192.0.2.2:22\taes128-cbc\n192.0.2.2:22\t3des-cbc\n192.0.2.3:2222\tweak-test-cipher'
[[ "$(ssh_weak_cipher_rows "$fixture")" == "$expected" ]]
printf '(key) ssh-rsa -- [fail] deprecated\n(enc) aes256-ctr -- [info] available\n' > clean.txt
if result_output_has_finding 'Weak SSH Ciphers' clean.txt; then exit 1; fi
printf '(enc) aes128-cbc -- [warn] weak\n' > weak.txt
result_output_has_finding 'Weak SSH Ciphers' weak.txt
append_ssh_weak_cipher_finding report.html
grep -Fq '2 affected host(s)' report.html
grep -Fq '<td>192.0.2.2:22</td><td>aes128-cbc, 3des-cbc</td>' report.html
grep -Fq '<td>192.0.2.3:2222</td>' report.html
! grep -Fq '<td>192.0.2.1:22</td>' report.html
! grep -Fq '<td>192.0.2.4:22</td>' report.html
printf 'SSH weak cipher checks passed.\n'
