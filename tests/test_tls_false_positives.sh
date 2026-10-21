#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-tls-false-positives.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
parse() { awk -v kind="$1" -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$2"; }
cat > "$TOOL_DIR/sslscan_results.txt" <<'EOF'
Command: sslscan 192.0.2.40:443
Testing SSL server 192.0.2.40 on port 443 using SNI name 192.0.2.40
TLSv1.2 enabled
TLSv1.3 disabled
TLSv1.3 handshake timed out
Command: sslscan 192.0.2.41:443
Testing SSL server 192.0.2.41 on port 443 using SNI name 192.0.2.41
TLSv1.2 enabled
TLSv1.3 disabled
Command: sslscan 192.0.2.42:443
Testing SSL server 192.0.2.42 on port 443 using SNI name 192.0.2.42
TLSv1.2 enabled
TLSv1.3 disabled
Accepted TLSv1.3 128 bits TLS_AES_128_GCM_SHA256
EOF
append_tls_findings_summary findings.html
grep -Fq 'TLSv1.3 Disabled</strong><span>1 affected target(s)' findings.html || exit 1
grep -Fq '192.0.2.41:443' findings.html || exit 1
! grep -Fq '192.0.2.40:443' findings.html || exit 1
! grep -Fq '192.0.2.42:443' findings.html || exit 1
cp "$TOOL_DIR/sslscan_results.txt" local-unsupported.txt
printf 'WARNING: Local OpenSSL build lacks TLSv1.3 support\n' >> local-unsupported.txt
[[ -z "$(parse sslscan local-unsupported.txt | awk -F '\034' '$1 == 5')" ]] || exit 1
# Positive TLS 1.3 handshakes still suppress conflicting negatives when a
# different, later operation fails in the same invocation.
printf 'Command: testssl 192.0.2.41:443\nTLS 1.3 offered\nFatal error: connection refused during another check\n' > "$TOOL_DIR/testssl_results.txt"
: > conflict.html
append_tls_findings_summary conflict.html
! grep -Fq 'TLSv1.3 Disabled' conflict.html || exit 1

cat > cert-text.txt <<'EOF'
Command: testssl 192.0.2.50:443
Certificate Validity (UTC) cannot determine whether certificate expired
Certificate Validity (UTC) not expired
Certificate Validity (UTC) expires in 3 days
Command: testssl 192.0.2.51:443
Certificate Validity (UTC) expired (2020-01-01)
Command: testssl 192.0.2.52:443
Certificate Validity (UTC) expired
Not valid after: Jan 1 00:00:00 2099 GMT
EOF
[[ "$(parse testssl cert-text.txt | awk -F '\034' '$1 == 10 {print $2}')" == '192.0.2.51:443' ]] || exit 1

for value in \
  'Feb 29 00:00:00 2023 GMT' \
  'Feb 30 00:00:00 2024 GMT' \
  'Apr 31 00:00:00 2020 GMT' \
  'Jan aa 00:00:00 2020 GMT' \
  'Jan 01 xx:00:00 2020 GMT' \
  'Jan 01 24:00:00 2020 GMT' \
  'Jan 01 00:60:00 2020 GMT' \
  'Jan 01 00:00:60 2020 GMT' \
  'Jan 01 00:00:00 2020 PST' \
  '2020-02-30T00:00:00Z' \
  '2020-01-01T00:00:00Ztrailing' \
  '2020-01-01T00:00:00+08:00' \
  '2099-01-01T00:00:00Z' \
  '2026-10-21T00:00:00Z'; do
  printf 'Command: sslscan 192.0.2.60:443\nSSL Certificate:\nNot valid after: %s\n' "$value" > date.txt
  [[ -z "$(parse sslscan date.txt | awk -F '\034' '$1 == 10')" ]] || { printf 'False expiry: %s\n' "$value" >&2; exit 1; }
done
for value in 'Feb 29 00:00:00 2024 GMT' '2024-02-29T00:00:00Z'; do
  printf 'Command: sslscan 192.0.2.61:443\nSSL Certificate:\nNot valid after: %s\n' "$value" > date.txt
  [[ "$(parse sslscan date.txt | awk -F '\034' '$1 == 10 {print $2}')" == '192.0.2.61:443' ]] || exit 1
done
cat > non-leaf.txt <<'EOF'
Command: sslscan 192.0.2.70:443
Not valid after: Jan 1 00:00:00 2020 GMT
Signature Algorithm: sha1WithRSAEncryption
SSL Certificate:
Subject: /O=*.organization.test/CN=ordinary.example.test
Not valid after: Jan 1 00:00:00 2099 GMT
Signature Algorithm: sha256WithRSAEncryption
SHA1 Fingerprint: abcdef
SSL Certificate chain:
Subject: /CN=*.issuer.test
Signature Algorithm: sha1WithRSAEncryption
Not valid after: Jan 1 00:00:00 2020 GMT
EOF
[[ -z "$(parse sslscan non-leaf.txt)" ]] || exit 1
cat > definitions.txt <<'EOF'
Command: testssl 192.0.2.80:443
TLS 1.2 offered
TLS 1.3 not offered (NOT ok)
Common Name (CN) *
Certificate Validity (UTC) expired (2026-10-20)
Command: testssl 192.0.2.81:443
Subject Alternative Name (SAN) unusual*name.example.test
Certificate Validity (UTC) expired (2026-10-21)
Command: testssl 192.0.2.82:443
Certificate Validity (UTC) expired
Command: sslscan 192.0.2.83:443
SSL Certificate:
Not valid after: Oct 21 00:00:00 2026 GMT
EOF
awk -v kind=testssl -v now_utc=20261021120000 -f "$BIDENT_ROOT/lib/tls_findings.awk" definitions.txt > definitions-rows.txt
[[ "$(awk -F '\034' '$1 == 5 {print $2}' definitions-rows.txt)" == '192.0.2.80:443' ]] || exit 1
[[ "$(awk -F '\034' '$1 == 8 {print $2}' definitions-rows.txt)" == $'192.0.2.80:443\n192.0.2.81:443' ]] || exit 1
[[ "$(awk -F '\034' '$1 == 10 {print $2}' definitions-rows.txt)" == '192.0.2.80:443' ]] || exit 1
printf 'TLS false-positive checks passed.\n'
