#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/report.sh

test_dir="$(mktemp -d /tmp/bident-report-output.XXXXXX)"
fixture="${test_dir}/tool.txt"
{
  printf '\033[0;36m# general\033[0m\n'
  printf '[0;31m[fail] weak cipher[0m\n'
  printf '\033[32m[+] Login Successful: user:example\033[0m\n'
  printf '\033]8;;https://example.test\033\\link\033]8;;\033\\\n'
  printf '\033]0;tool title\007output\r\n'
  printf '\033[2K<banner> & [warn]\n'
  printf '%s\n' '\x1b[31mred\x1b[0m' '\033[32mgreen\033[0m' '\u001b[36mcyan\u001b[0m'
} > "$fixture"
expected='# general
[fail] weak cipher
[+] Login Successful: user:example
link
output
&lt;banner&gt; &amp; [warn]
red
green
cyan'
actual="$(html_escape_file "$fixture")"
[[ "$actual" == "$expected" ]]
[[ "$(html_escape_text "$(cat "$fixture")")" == "$expected" ]]
[[ "$(html_escape_file_preview "$fixture")" == "$expected" ]]
# Both head/tail preview paths must also use the clean renderer.
printf '\033[31mHEAD\033[0m\n%0200d\n\033[32mTAIL\033[0m\n' 0 > "${test_dir}/large.txt"
actual="$(REPORT_EVIDENCE_MAX_BYTES=100 html_escape_file_preview "${test_dir}/large.txt")"
[[ "$actual" == *HEAD* && "$actual" == *TAIL* && "$actual" == *truncated* ]]
[[ "$actual" != *$'\033'* && "$actual" != *'[31m'* && "$actual" != *'[32m'* ]]
# Report rendering must not modify source evidence.
grep -q $'\033' "$fixture"
printf 'Terminal output report checks passed.\n'
