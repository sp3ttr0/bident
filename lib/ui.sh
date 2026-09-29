usage() {
  printf '%s\n' \
    'Usage: sudo ./bident.sh (-f <scope-file> | -t <target> | --resume <results-dir>) [-o <results-dir>] [-p-] [--no-udp] [--responder] [-T1|-T2|-T3|-T4|-T5]' \
    '       sudo ./bident.sh --check-deps' \
    '       sudo ./bident.sh --install-deps' \
    '' \
    'Bident is a network VAPT helper that expands scope, discovers live hosts,' \
    'runs TCP/UDP port scans, launches targeted follow-up checks, and generates' \
    'organized text outputs plus an HTML report.' \
    '' \
    'Target input:' \
    '  -f <scope-file>   Scope file to scan.' \
    '  -t <target>       Single IP/host to test.' \
    '  --resume <dir>    Resume from an existing Bident results folder.' \
    '' \
    'Options:' \
    '  -o <results-dir>  Write all results into this folder.' \
    '  -p-               Scan all TCP/UDP ports.' \
    '  --check-deps      Show installed and missing tools.' \
    '  --install-deps    Install supported dependencies from Kali/Parrot apt repos.' \
    '  --no-udp          Skip UDP scans and UDP follow-up checks.' \
    '  --responder       Start Responder on eth0 in a separate screen session.' \
    '  -T1..-T5          Set the Nmap timing template. Default: -T4.' \
    '  -T <1-5>          Alternate timing syntax.' \
    '  --speed <1-5>     Alternate timing syntax.' \
    '' \
    'Examples:' \
    '  sudo ./bident.sh -f scope.txt -p- -T4' \
    '  sudo ./bident.sh -t 192.0.2.10 --no-udp -T4' \
    '  sudo ./bident.sh --check-deps' \
    '  sudo ./bident.sh --install-deps' \
    '  sudo ./bident.sh --resume bident_results_20260928_120000'
}

print_banner() {
  local CLR_DIM=""
  local CLR_WHITE=""
  local CLR_SKULL=""
  local CLR_HANDLE=""
  local CLR_DARK_RED=""
  local CLR_BRIGHT_RED=""
  local CLR_SOFT_RED=""

  if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    CLR_DIM="$(printf '\033[2m')"
    CLR_WHITE="$(printf '\033[90m')"
    CLR_SKULL="$(printf '\033[31m')"
    CLR_HANDLE="$(printf '\033[90m')"
    CLR_DARK_RED="$(printf '\033[2;31m')"
    CLR_BRIGHT_RED="$(printf '\033[91m')"
    CLR_SOFT_RED="$(printf '\033[0;31m')"
  fi

  banner_line() {
    printf '%s%s%s\n' "$1" "$2" "$CLR_RESET"
  }

  printf '\n'
  banner_line "$CLR_DIM"    "                         . . . . . . . . . . ."
  banner_line "$CLR_DARK_RED" "                            :#*       *#:"
  banner_line "$CLR_DARK_RED" "                           :###       ###:"
  banner_line "$CLR_DARK_RED" "                           ####       ####"
  banner_line "$CLR_SOFT_RED" "                          :####       ####:"
  banner_line "$CLR_SOFT_RED" "                          #####       #####"
  banner_line "$CLR_SOFT_RED" "                          #####:     :#####"
  banner_line "$CLR_BRIGHT_RED" "                          #####*     *#####"
  banner_line "$CLR_BRIGHT_RED" "                          ######     ######"
  banner_line "$CLR_BRIGHT_RED" "                          ######*   *######"
  banner_line "$CLR_BRIGHT_RED" "                          #######. .#######"
  banner_line "$CLR_BRIGHT_RED" "                          *####### #######*"
  banner_line "$CLR_SOFT_RED" "                          .###############."
  banner_line "$CLR_SOFT_RED" "                           *#############*"
  banner_line "$CLR_SKULL"    "                            *###########*"
  banner_line "$CLR_SKULL"    "                             :#########:"
  banner_line "$CLR_SKULL"    "                              *#######*"
  banner_line "$CLR_WHITE"    "                              #########"
  banner_line "$CLR_WHITE"    "                              #########"
  banner_line "$CLR_HANDLE"   "                             :#########:"
  banner_line "$CLR_HANDLE"   "                             *#########*"
  banner_line "$CLR_DARK_RED" "                             ###########"
  banner_line "$CLR_DARK_RED" "                             :#########:"
  banner_line "$CLR_DIM"    "                                :::::"
  banner_line "$CLR_DIM"    "                         . . . . . . . . . . ."
  printf '\n'
  printf '                              %s%sBident%s\n' "$CLR_BOLD" "$CLR_BRIGHT_RED" "$CLR_RESET"
  printf '                         %s%sNetwork VAPT Tool%s\n' "$CLR_BOLD" "$CLR_SOFT_RED" "$CLR_RESET"
  printf '                               %sby sp3ttr0%s\n' "$CLR_HANDLE" "$CLR_RESET"
  printf '\n'
}
