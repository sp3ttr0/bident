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
  local CLR_DIM=""
  local CLR_WHITE=""
  local CLR_SKULL=""
  local CLR_HANDLE=""

  if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    CLR_DIM="$(printf '\033[2m')"
    CLR_WHITE="$(printf '\033[97m')"
    CLR_SKULL="$(printf '\033[97m')"
    CLR_HANDLE="$(printf '\033[90m')"
  fi

  banner_line() {
    printf '%s%s%s\n' "$1" "$2" "$CLR_RESET"
  }

  printf '\n'
  banner_line "$CLR_DIM"    "                    . . . . . . . . . . . . . . . . . ."
  banner_line "$CLR_RED"    "                               /\\           /\\"
  banner_line "$CLR_RED"    "                              /  \\         /  \\"
  banner_line "$CLR_RED"    "                             / /\\ \\       / /\\ \\"
  banner_line "$CLR_RED"    "                            / /  \\ \\     / /  \\ \\"
  banner_line "$CLR_RED"    "                           / /    \\ \\   / /    \\ \\"
  banner_line "$CLR_RED"    "                          /_/      \\ \\_/ /      \\_\\"
  banner_line "$CLR_RED"    "                         /          \\   /          \\"
  banner_line "$CLR_RED"    "                        /   _________\\_/_________   \\"
  banner_line "$CLR_RED"    "                       /___/       _     _       \\___\\"
  banner_line "$CLR_SKULL"  "                                  / \\___/ \\"
  banner_line "$CLR_SKULL"  "                                 |  x   x  |"
  banner_line "$CLR_SKULL"  "                                 |    ^    |"
  banner_line "$CLR_SKULL"  "                                  \\  ---  /"
  banner_line "$CLR_SKULL"  "                                   \\_____/ "
  banner_line "$CLR_HANDLE" "                                     |||"
  banner_line "$CLR_HANDLE" "                                     |||"
  banner_line "$CLR_HANDLE" "                                     |||"
  banner_line "$CLR_HANDLE" "                                   __|||__"
  banner_line "$CLR_DIM"    "                    . . . . . . . . . . . . . . . . . ."
  printf '\n'
  printf '                         %s%sNetwork VAPT Tool%s\n' "$CLR_BOLD" "$CLR_CYAN" "$CLR_RESET"
  printf '                               %sby sp3ttr0%s\n' "$CLR_YELLOW" "$CLR_RESET"
  printf '                    %srecon | proof | reporting%s\n' "$CLR_DIM" "$CLR_RESET"
  printf '\n'
}
