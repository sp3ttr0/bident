usage() {
  cat <<'BIDENT_HELP'
Bident - Network VAPT Toolkit
Discover live hosts, scan TCP/UDP ports, run follow-up checks, and create
an HTML report with findings, affected hosts, and full evidence.

Usage:
  sudo ./bident.sh -f <scope-file> [options]
  sudo ./bident.sh -t <host> [options]
  sudo ./bident.sh --resume <results-dir> [options]
  ./bident.sh --check-deps
  sudo ./bident.sh --install-deps

Choose one input:
  -f <scope-file>
      Read hosts from a text file, one entry per line. Entries can be host
      addresses, hostnames, or CIDR networks (for example, 192.0.2.0/24).
  -t <host>
      Scan one host without creating a scope file yourself.
      Example: -t 192.0.2.10
  --resume <results-dir>
      Continue using an existing results folder and reuse saved scan work.
      Do not combine this with -f or -t. Use the original scan options.

Scan options:
  -o <results-dir>, --output-dir <results-dir>, --results-dir <results-dir>
      Save the report, scan output, evidence, and logs in this folder.
      Default: a new bident_results_<date>_<time> folder.
  -p-
      Scan all ports (1-65535) instead of Nmap's default common ports.
      Applies to TCP and, unless --no-udp is set, UDP. Takes longer.
  --no-udp
      Skip UDP port scans and UDP follow-up checks. TCP checks still run.
  --no-msf
      Skip Metasploit module checks. Nmap and external-tool checks still run.
  -T1, -T2, -T3, -T4, -T5
      Choose Nmap's timing preset. Lower numbers are slower; higher numbers
      are more aggressive. Default: -T4. This is not a total scan time limit.
  --responder
      Start Responder in a separate screen session on eth0 by default.
      This optional service can remain running after the scan finishes.

Timeouts and parallel checks:
  --script-timeout <duration>
      Limit each Nmap NSE script instance, not the entire service or scan.
      Default: 30m (30 minutes). Examples: 900 (seconds), 15m, 1h.
      Use 0 for no script time limit. Timed-out checks are incomplete.
      Does not set a host timeout or a UDP base-scan time limit.
  --tool-timeout <seconds>
      Limit each external-tool command that uses the shared timeout runner.
      Default: 0 (no additional limit). Example: 300 = 5 minutes.
      testssl and sslscan have a separate fixed 30-minute limit per tool
      per host; this option does not change that limit. Requires timeout.
  --msf-timeout <seconds>
      Limit each Metasploit module run for a port group, across its hosts.
      Default: 120 (2 minutes). Use 0 for no limit. Requires timeout.
      An interrupted module is incomplete; this is not a per-host limit.
  --msf-threads <number>
      Set concurrent host checks for Metasploit scanner modules.
      Default: 16. Use a positive whole number; higher values add load.
      Applies to modules that support the THREADS setting.

Setup and help:
  --check-deps
      List installed and missing dependencies, then exit without scanning.
      Does not install anything and can run without sudo.
  --install-deps
      Install supported dependencies through apt on Kali/Parrot-style
      Debian systems, then exit. Run with sudo; downloads packages.
  -h, --help
      Show this help and exit without scanning. Use as the first argument.

Examples:
  sudo ./bident.sh -t 192.0.2.10
      Scan one host with the default settings.
  sudo ./bident.sh -f scope.txt -o results/ --no-udp
      Scan hosts from a file, skip UDP, and save everything in results/.
  sudo ./bident.sh -f scope.txt -p- --script-timeout 30m --msf-timeout 300
      Scan all ports and allow each Metasploit module run up to 5 minutes.
  sudo ./bident.sh --resume results/
      Continue from saved results.
BIDENT_HELP
}

print_section() {
  printf '\n%s%s== %s ==%s\n' "$CLR_BOLD" "$CLR_BRIGHT_RED" "$1" "$CLR_RESET"
  printf '%s------------------------------------------------------------%s\n' "$CLR_GRAY" "$CLR_RESET"
}

print_summary_row() {
  local value_color="${3:-$CLR_WHITE}"
  printf '  %s%-29s%s %s%s%s\n' "$CLR_CYAN" "$1" "$CLR_RESET" "$value_color" "$2" "$CLR_RESET"
}

print_completion() {
  printf '\n%s%s[+] Scan Completed.%s\n\n' "$CLR_BOLD" "$CLR_GREEN" "$CLR_RESET"
}

print_banner() {
  local line=""
  local banner_width=42

  banner_art() {
    cat <<'BIDENT_ART'
           "                "
          ".                '"
         ` ;                ?''
          :!                [_
         .-]               '[]
         ^[{^              ^}]^
         ,{)?              i]-^
         ")((`            ^[]_'
         `)|)] `        ''??_I
          ?)1}l.`      ''_]_l^
           ![]-: `    '._]-l^
           .:!!I,.   "'?[-l`
             ''''. "".^"^'
                ,}rCLj}"
               _$$$$$$$$i
               z$$,"$j dc
               |$$$W$$$$1
               "]B$W8$@~,
               "')|tt|1`"
              ,"""}[+! """
                  """"
                 ,,
BIDENT_ART
  }

  banner_colored_line() {
    local text="$1"
    local i=0
    local ch=""

    while [[ "$i" -lt "${#text}" ]]; do
      ch="${text:i:1}"
      case "$ch" in
        '['|']'|'{'|'}'|'('|')'|'?'|'!'|'1'|'l'|'I'|'_'|'-')
          printf '%s%s%s' "$CLR_BRIGHT_RED" "$ch" "$CLR_RESET"
          ;;
        '$'|'W'|'8'|'B'|'@'|'|')
          printf '%s%s%s' "$CLR_WHITE" "$ch" "$CLR_RESET"
          ;;
        ' ')
          printf ' '
          ;;
        *)
          printf '%s%s%s' "$CLR_GRAY" "$ch" "$CLR_RESET"
          ;;
      esac
      i=$((i + 1))
    done
    printf '\n'
  }

  banner_label_line() {
    local color="$1"
    local text="$2"
    local text_length="${#text}"
    local padding=0

    if ((banner_width > text_length)); then
      padding=$(((banner_width - text_length) / 2))
      padding=$((padding > 3 ? padding - 3 : 0))
    fi
    padding=$((padding + 2))

    printf '%*s%s%s%s\n' "$padding" "" "$color" "$text" "$CLR_RESET"
  }

  printf '\n'
  while IFS= read -r line; do
    banner_colored_line "$line"
  done < <(banner_art)
  printf '\n'
  banner_label_line "${CLR_BOLD}${CLR_BRIGHT_RED}" "Bident"
  banner_label_line "${CLR_BOLD}${CLR_BRIGHT_RED}" "Network VAPT Toolkit"
  banner_label_line "$CLR_GRAY" "by sp3ttr0"
  printf '\n'
}
