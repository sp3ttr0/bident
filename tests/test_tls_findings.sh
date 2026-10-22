#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-tls-findings.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
cat > "$TOOL_DIR/testssl_results.txt" <<'EOF'
===== 2026-10-21 10:00:00 =====
Command: testssl 192.0.2.10:443
 SSLv2 offered (NOT ok)
 SSLv3 offered (NOT ok)
 TLS 1 offered (deprecated)
 TLS 1.1 offered (deprecated)
 TLS 1.2 offered
 TLS 1.3 not offered
 NULL ciphers (no encryption) offered (NOT ok)
 BREACH (CVE-2013-3587) potentially NOT ok, "gzip deflate" HTTP compression detected
 BREACH (CVE-2013-3587) gzip:yes deflate:no
 Common Name (CN) *.example.test
 Signature Algorithm SHA1 with RSA
 Certificate Validity (UTC) expired (2020-01-01)
===== 2026-10-21 10:01:00 =====
Command: testssl 192.0.2.11:443
 SSLv2 not offered (OK)
 SSLv3 not offered (OK)
 TLS 1 not offered
 TLS 1.1 not offered
 TLS 1.3 offered
 NULL ciphers (no encryption) not offered (OK)
 BREACH (CVE-2013-3587) no gzip/deflate/compress/br HTTP compression (OK)
 Issuer CN=*.issuer.test
 Signature Algorithm SHA256 with RSA
 Certificate Validity (UTC) expires in 20 days
===== 2026-10-21 10:02:00 =====
Command: testssl 192.0.2.12:443
 SSLv2 offered
 Fatal error: connection refused
===== 2026-10-21 10:03:00 =====
Command: testssl 192.0.2.20:443
 TLS 1.3 offered
EOF
cat > "$TOOL_DIR/sslscan_results.txt" <<'EOF'
Command: sslscan 192.0.2.20:443
Testing SSL server 192.0.2.20 on port 443 using SNI name 192.0.2.20
SSLv2 enabled
SSLv3 enabled
TLSv1.0 enabled
TLSv1.1 enabled
TLSv1.2 enabled
TLSv1.3 disabled
Accepted TLSv1.2 112 bits DES-CBC3-SHA
SSL Certificate:
Signature Algorithm: sha1WithRSAEncryption
Subject: /CN=*.example.test
Not valid after: Jan  1 00:00:00 2020 GMT
Command: sslscan 192.0.2.21:443
Testing SSL server 192.0.2.21 on port 443 using SNI name 192.0.2.21
TLSv1.3 disabled
Rejected TLSv1.2 40 bits EXP-RC4-MD5
Command: sslscan 192.0.2.22:443
Testing SSL server 192.0.2.22 on port 443 using SNI name 192.0.2.22
TLSv1.2 enabled
TLSv1.3 disabled (client cannot test this protocol)
Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256
Signature Algorithm: sha256WithRSAEncryption
SHA1 Fingerprint: abcdef
Subject: /CN=ordinary.example.test
Not valid after: Jan  1 00:00:00 2099 GMT
SSL Certificate chain:
Signature Algorithm: sha1WithRSAEncryption
Subject: /CN=*.issuer.test
Not valid after: Jan  1 00:00:00 2020 GMT
EOF
cat > "$NSE_DIR/ssl_tls_results.txt" <<'EOF'
Nmap scan report for 192.0.2.30
8443/tcp open https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|   TLSv1.1:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
| ssl-cert: Subject: commonName=*.example.test
| Signature Algorithm: sha1WithRSAEncryption
| Not valid after: 2020-01-01T00:00:00
Nmap scan report for 192.0.2.31
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.0:
|_ ERROR: Script execution failed
Nmap scan report for 192.0.2.32
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.2:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
EOF
append_tls_findings_summary findings.html
[[ "$(grep -c '<li>' findings.html)" -eq 10 ]] || exit 1
for endpoint in 192.0.2.10:443 192.0.2.20:443 192.0.2.30:8443; do
  grep -Fq "$endpoint" findings.html || exit 1
done
for endpoint in 192.0.2.11:443 192.0.2.12:443 192.0.2.21:443 192.0.2.22:443 192.0.2.31:443 192.0.2.32:443; do
  ! grep -Fq "$endpoint" findings.html || exit 1
done
grep -Fq 'Copy hosts' findings.html || exit 1
grep -Fq 'Evidence by Host:Port' findings.html || exit 1
grep -Fq '<td>192.0.2.20:443</td><td>DES-CBC3-SHA</td>' findings.html || exit 1
grep -Fq '<td>192.0.2.30:8443</td><td>TLS_RSA_WITH_3DES_EDE_CBC_SHA</td>' findings.html || exit 1
grep -Fq '<td>192.0.2.10:443</td><td>Category only: NULL ciphers (no encryption)</td>' findings.html || exit 1
grep -Fq 'TLSv1.3 Disabled</strong><span>1 affected host(s)' findings.html || exit 1
grep -Fq 'nmap_scripts/ssl_tls_results.txt:15' findings.html || exit 1
! grep -Fq 'potential BREACH exposure' findings.html || exit 1
! grep -Fq 'Wildcard use alone does not establish a vulnerability' findings.html || exit 1
# Cross-tool TLS 1.3 success suppresses a conflicting disabled observation.
awk -F '\034' -v kind=sslscan -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/sslscan_results.txt" > rows.txt
# A client-side TLS 1.3 testing limitation anywhere in this tool output
# invalidates its negative protocol conclusions, including earlier endpoints.
[[ -z "$(awk -F '\034' '$1 == 5 {print $2}' rows.txt)" ]] || exit 1
# NSE missing protocol headings cannot produce a TLS 1.3-disabled finding.
awk -F '\034' -v kind=nse -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$NSE_DIR/ssl_tls_results.txt" > nse-rows.txt
[[ -z "$(awk -F '\034' '$1 == 5 {print}' nse-rows.txt)" ]] || exit 1
# Common testssl text output must work without debug-only compression markers.
printf 'Command: testssl 192.0.2.90:8443\nBREACH (CVE-2013-3587) potentially NOT ok, "gzip" HTTP compression detected.\n' > breach.txt
[[ "$(awk -v kind=testssl -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" breach.txt | awk -F '\034' '$1 == 7 {print $2}')" == '192.0.2.90:8443' ]] || exit 1
generate_html_report
grep -Fq '<strong>Weak SSL/TLS Ciphers</strong>' report.html || exit 1
grep -Fq '<strong>Expired SSL Certificate</strong>' report.html || exit 1
printf 'TLS finding checks passed.\n'
