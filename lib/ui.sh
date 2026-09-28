usage() {
  printf '%s\n' \
    'Usage: sudo ./bident.sh (-f <scope-file> | -t <target>) [-o <results-dir>] [-p-] [--no-udp] [--responder] [-T1|-T2|-T3|-T4|-T5]' \
    '' \
    'Bident is a network VAPT helper that expands scope, discovers live hosts,' \
    'runs TCP/UDP port scans, launches targeted follow-up checks, and generates' \
    'organized text outputs plus an HTML report.' \
    '' \
    'Target input:' \
    '  -f <scope-file>   Scope file to scan.' \
    '  -t <target>       Single IP/host to test.' \
    '' \
    'Options:' \
    '  -o <results-dir>  Write all results into this folder.' \
    '  -p-               Scan all TCP/UDP ports.' \
    '  --no-udp          Skip UDP scans and UDP follow-up checks.' \
    '  --responder       Start Responder on eth0 in a separate screen session.' \
    '  -T1..-T5          Set the Nmap timing template. Default: -T4.' \
    '  -T <1-5>          Alternate timing syntax.' \
    '  --speed <1-5>     Alternate timing syntax.' \
    '' \
    'Examples:' \
    '  sudo ./bident.sh -f scope.txt -p- -T4' \
    '  sudo ./bident.sh -t 192.0.2.10 --no-udp -T4'
}

print_banner() {
  banner_line() {
    printf '%s|%s %-74s %s|%s\n' "$CLR_BLUE" "$CLR_RESET" "$1" "$CLR_BLUE" "$CLR_RESET"
  }

  printf '\n'
  printf '%s+----------------------------------------------------------------------------+%s\n' "$CLR_BLUE" "$CLR_RESET"
  banner_line ""
  banner_line "                               /\\           /\\"
  banner_line "                              /  \\         /  \\"
  banner_line "                             / /\\ \\       / /\\ \\"
  banner_line "                            / /  \\ \\     / /  \\ \\"
  banner_line "                           / /    \\ \\   / /    \\ \\"
  banner_line "                          /_/      \\ \\_/ /      \\_\\"
  banner_line "                         /          \\   /          \\"
  banner_line "                        /   _________\\_/_________   \\"
  banner_line "                       /___/       _     _       \\___\\"
  banner_line "                                  / \\___/ \\"
  banner_line "                                 |  x   x  |"
  banner_line "                                 |    ^    |"
  banner_line "                                  \\  ---  /"
  banner_line "                                   \\_____/ "
  banner_line "                                     |||"
  banner_line "                                     |||"
  banner_line "                                     |||"
  banner_line "                                   __|||__"
  banner_line ""
  banner_line "                            Network VAPT Tool"
  banner_line "                                by sp3ttr0"
  banner_line ""
  printf '%s+----------------------------------------------------------------------------+%s\n' "$CLR_BLUE" "$CLR_RESET"
  printf '\n'
}
