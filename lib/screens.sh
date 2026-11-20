screen_session_exists() {
  local session_name="$1"
  screen -list | grep -Eq "[[:space:]][0-9]+\\.${session_name}[[:space:]]"
}

stop_screen_scans() {
  local session_name

  for session_name in syn con udp; do
    if screen_session_exists "$session_name"; then
      printf '%sStopping Screen Session:%s %s\n' "$CLR_YELLOW" "$CLR_RESET" "$session_name"
      screen -S "$session_name" -X quit || true
    fi
  done
}

confirm_cancel() {
  local answer=""

  printf '\n%sCancel the script? [y/N]:%s ' "$CLR_YELLOW" "$CLR_RESET" > /dev/tty
  if read -r answer < /dev/tty; then
    case "$answer" in
      y|Y|yes|YES|Yes)
        trap - INT
        stop_screen_scans
        printf '%sScan Cancelled.%s\n' "$CLR_YELLOW" "$CLR_RESET"
        exit 130
        ;;
      *)
        printf '%sContinuing Scan.%s\n' "$CLR_GREEN" "$CLR_RESET"
        return 0
        ;;
    esac
  fi

  return 0
}

start_screen_scan() {
  local session_name="$1"
  local command_text="$2"

  mkdir -p "$LOG_DIR"
  screen -L -Logfile "${LOG_DIR}/${session_name}.screen.log" -dmS "$session_name" bash -lc "$command_text"
  BIDENT_OWNED_SCANS+=("$session_name")
  printf '%sStarted Screen Session:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$session_name"
  printf '%sScreen Log File:%s %s/%s.screen.log\n' "$CLR_CYAN" "$CLR_RESET" "$LOG_DIR" "$session_name"
}

start_responder() {
  local output="${RESULTS_DIR:-$PWD}/responder" command_text owner_uid="" owner_gid=""
  if [[ -n "${BIDENT_RUN_USER:-}" ]]; then
    owner_uid="$(id -u "$BIDENT_RUN_USER")"
    owner_gid="$(id -g "$BIDENT_RUN_USER")"
  fi
  mkdir -p "$output/logs" "$output/captures"
  printf -v command_text '%s python3 %q %q %q %q %q' "${PRIVILEGED_CMD_PREFIX}" \
    "${BIDENT_ROOT}/lib/responder.py" "$output" "$RESPONDER_INTERFACE" "$owner_uid" "$owner_gid"
  screen -L -Logfile "$output/logs/console.log" -dmS responder bash -lc "exec $command_text"
  printf '%sStarted Screen Session:%s responder\n' "$CLR_GREEN" "$CLR_RESET"
  printf '%sResponder Interface:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$RESPONDER_INTERFACE"
  printf '%sResponder Output:%s %s (logs/ and captures/)\n' "$CLR_CYAN" "$CLR_RESET" "$output"
  printf '%sResponder Will Continue Running After Bident Finishes.%s\n' "$CLR_YELLOW" "$CLR_RESET"
}

ensure_screen_sessions_available() {
  local session_name

  for session_name in "$@"; do
    if screen_session_exists "$session_name"; then
      die "Screen session already exists: ${session_name}"
    fi
  done
}

wait_for_screen_scans() {
  local running=()
  local session_name
  local total="$#"
  local completed=0
  local percent=0
  local bar_width=28
  local filled=0
  local bar=""
  local active_text=""
  local status=""
  local previous_status=""
  local i

  printf '%sWaiting For Base Scan Sessions To Finish...%s\n' "$CLR_CYAN" "$CLR_RESET"
  while :; do
    running=()
    for session_name in "$@"; do
      if screen_session_exists "$session_name"; then
        running+=("$session_name")
      fi
    done

    completed=$((total - ${#running[@]}))
    percent=$((completed * 100 / total))
    filled=$((percent * bar_width / 100))
    bar=""
    for ((i = 0; i < bar_width; i++)); do
      if ((i < filled)); then
        bar+="#"
      else
        bar+="."
      fi
    done
    active_text="${running[*]:-None}"
    status=$(printf '%sBase Scan Progress:%s [%s] %s/%s (%s%%) Active: %s' "$CLR_CYAN" "$CLR_RESET" "$bar" "$completed" "$total" "$percent" "$active_text")

    if [[ "${#running[@]}" -eq 0 ]]; then
      if [[ -t 1 ]]; then
        printf '\r%s\n' "$status"
      elif [[ "$status" != "$previous_status" ]]; then
        printf '%s\n' "$status"
      fi
      break
    fi

  if [[ -t 1 ]]; then
    printf '\r%s' "$status"
  elif [[ "$status" != "$previous_status" ]]; then
    printf '%s\n' "$status"
  fi
  previous_status="$status"
  sleep "$SCAN_POLL_SECONDS" || true
  done
}
