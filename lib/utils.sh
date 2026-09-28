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
    printf '%sRun This Script With Sudo:%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    printf '  sudo ./bident.sh -f <scope-file>\n' >&2
    exit 1
  fi
}
