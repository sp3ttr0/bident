#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-cipher-names.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
cat > "$TOOL_DIR/testssl_results.txt" <<'DATA'
Command: testssl --wide --mapping iana 192.0.2.10:443
 Obsoleted CBC ciphers (AES, ARIA etc.) offered
 Testing 370 ciphers via OpenSSL plus sockets against the server, ordered by encryption strength
 xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ECDH 256 AES 256 ECDHE-RSA-AES256-SHA384
 xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ECDH 256 AES 256 ECDHE-RSA-AES256-SHA384
 xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ECDH 256 AESGCM 128
 xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 rejected
 Running client simulations
 xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ECDH 256 AES 128
Command: testssl 192.0.2.11:8443
 Obsoleted CBC ciphers (AES, ARIA etc.) offered
DATA
cat > "$TOOL_DIR/sslscan_results.txt" <<'DATA'
Command: sslscan 192.0.2.10:443
Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-SHA384
Accepted TLSv1.2 128 bits AES128-SHA256
Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256
Rejected TLSv1.2 128 bits AES128-SHA
DATA
awk -v kind=testssl -v now_utc=20261022000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/testssl_results.txt" > parsed
[[ "$(awk -F '\034' '$1==6 && $5 !~ /^Category only:/ {print $5}' parsed)" == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ]] || exit 1
append_tls_findings_summary report.html
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('report.html').read_text()
table=re.search(r'<div data-affected-targets>.*?</tbody></table>',s,re.S).group()
assert '<li>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</li>' in table
assert '<li>ECDHE-RSA-AES256-SHA384</li>' in table
assert '<li>AES128-SHA256</li>' in table
assert 'Category only:' not in table
assert 'GCM' not in table
assert '<li>AES128-SHA</li>' not in table
assert 'rescan required' in table
assert 'Full Evidence' in s
PYTEST
printf 'TLS individual cipher checks passed.\n'
