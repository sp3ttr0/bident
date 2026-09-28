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

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%sRun This Script With Sudo:%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    printf '  sudo ./bident.sh -f <scope-file>\n' >&2
    exit 1
  fi
}
