die() {
  printf '%sError:%s %s\n' "$CLR_RED" "$CLR_RESET" "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

command_available() {
  command -v "$1" >/dev/null 2>&1
}

resolve_command() {
  local command_name="$1"
  local candidate

  if command -v "$command_name" >/dev/null 2>&1; then
    command -v "$command_name"
    return 0
  fi

  for candidate in \
    "/usr/local/bin/${command_name}" \
    "/opt/homebrew/bin/${command_name}" \
    "/usr/bin/${command_name}" \
    "/bin/${command_name}" \
    "/usr/sbin/${command_name}" \
    "/sbin/${command_name}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

run_with_timeout() {
  if [[ "${TOOL_TIMEOUT:-0}" =~ ^[0-9]+$ && "${TOOL_TIMEOUT:-0}" -gt 0 ]] && command_available timeout; then
    timeout --preserve-status "${TOOL_TIMEOUT}" "$@"
  else
    "$@"
  fi
}

print_progress_bar() {
  local label="$1"
  local current="$2"
  local total="$3"
  local width=28
  local percent=0
  local filled=0
  local bar=""
  local i

  if ((total > 0)); then
    percent=$((current * 100 / total))
    filled=$((percent * width / 100))
  fi

  for ((i = 0; i < width; i++)); do
    if ((i < filled)); then
      bar+="#"
    else
      bar+="."
    fi
  done

  if [[ -t 1 ]]; then
    printf '\r%s%s:%s [%s] %s/%s (%s%%)' "$CLR_CYAN" "$label" "$CLR_RESET" "$bar" "$current" "$total" "$percent"
    if ((current >= total)); then
      printf '\n'
    fi
  else
    printf '%s%s:%s [%s] %s/%s (%s%%)\n' "$CLR_CYAN" "$label" "$CLR_RESET" "$bar" "$current" "$total" "$percent"
  fi
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%sRun This Command With Sudo:%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    printf '  sudo ./bident.sh --install-deps\n' >&2
    exit 1
  fi
}

require_non_root_scan_run() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    printf '%sRun Bident Without Sudo:%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    printf '  ./bident.sh -f <scope-file>\n' >&2
    printf '%sBident Will Use Sudo Only For Privileged Scans.%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    exit 1
  fi
}

require_sudo_for_privileged_scans() {
  need_command "$SUDO_CMD"
  printf '%sPreparing Sudo For Privileged Scans Only%s\n' "$CLR_CYAN" "$CLR_RESET"
  "$SUDO_CMD" -v || die "Sudo authentication failed"
}

count_files_in_dir() {
  local dir="$1"

  if [[ -d "$dir" ]]; then
    find "$dir" -type f 2>/dev/null | wc -l | tr -d '[:space:]'
  else
    printf '0'
  fi
}

print_final_summary() {
  local scoped_hosts=0
  local live_hosts=0
  local open_rows=0
  local nse_files=0
  local tool_files=0
  local msf_files=0

  [[ -f "$TARGETS_FILE" ]] && scoped_hosts="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  [[ -f "$LIVE_TARGETS_FILE" ]] && live_hosts="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  if [[ -f targets_with_open_ports/open_ports_all.tsv ]]; then
    open_rows="$(awk 'NR > 1 {count++} END {print count + 0}' targets_with_open_ports/open_ports_all.tsv)"
  fi
  nse_files="$(count_files_in_dir "$NSE_DIR")"
  tool_files="$(count_files_in_dir "$TOOL_DIR")"
  if [[ "${NO_MSF:-false}" == true ]]; then
    msf_files=0
  else
    msf_files="$(count_files_in_dir "$MSF_RESULT_DIR")"
  fi

  printf '%sScan Summary%s\n' "$CLR_BOLD" "$CLR_RESET"
  printf '%sResults Folder:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$PWD"
  printf '%sScoped Hosts:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$scoped_hosts"
  printf '%sLive Hosts/IPs:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$live_hosts"
  printf '%sTotal Ports Open:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$open_rows"
  printf '%sNmap Script Result Files:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$nse_files"
  printf '%sExternal Tool Result Files:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$tool_files"
  printf '%sMetasploit Result Files:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$msf_files"
  [[ -f report.html ]] && printf '%sHTML Report:%s report.html\n' "$CLR_CYAN" "$CLR_RESET"
  [[ -f summary.json ]] && printf '%sJSON Summary:%s summary.json\n' "$CLR_CYAN" "$CLR_RESET"
}
