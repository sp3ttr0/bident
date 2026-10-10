msf_module_slug() {
  local module_name="${1##*/}"

  printf '%s' "$module_name" | tr -c 'A-Za-z0-9_' '_'
}

msf_absolute_path() {
  local path="$1"

  case "$path" in
    /*) printf '%s' "$path" ;;
    *) printf '%s/%s' "$PWD" "$path" ;;
  esac
}

msf_append_module() {
  local rc_file="$1"
  local module="$2"
  local proto="$3"
  local port="$4"
  local ssl_mode="$5"
  local targets_file="$6"
  local slug
  local result_file

  slug="$(msf_module_slug "$module")"
  result_file="${MSF_RESULT_DIR}/${slug}_${proto}_${port}.txt"

  {
    printf 'spool %s\n' "$(msf_absolute_path "$result_file")"
    printf 'use %s\n' "$module"
    printf 'set RHOSTS file:%s\n' "$(msf_absolute_path "$targets_file")"
    printf 'set RPORT %s\n' "$port"
    printf 'set THREADS %s\n' "$MSF_THREADS"
    if [[ "$ssl_mode" == true ]]; then
      printf 'set SSL true\n'
    fi
    printf 'run\n'
    printf 'spool off\n'
    printf '\n'
  } >> "$rc_file"
}

msf_add_port_modules() {
  local rc_file="$1"
  local proto="$2"
  local port="$3"
  local targets_file="$4"
  local ssl_mode=false

  case "${proto}/${port}" in
    tcp/21)
      msf_append_module "$rc_file" auxiliary/scanner/ftp/ftp_version "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/ftp/ftp_anonymous "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/22)
      msf_append_module "$rc_file" auxiliary/scanner/ssh/ssh_version "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/23)
      msf_append_module "$rc_file" auxiliary/scanner/telnet/telnet_version "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/25|tcp/465|tcp/587)
      msf_append_module "$rc_file" auxiliary/scanner/smtp/smtp_version "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/smtp/smtp_relay "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/53|udp/53)
      msf_append_module "$rc_file" auxiliary/scanner/dns/dns_amp "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/139|tcp/445)
      msf_append_module "$rc_file" auxiliary/scanner/smb/smb_version "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/smb/smb_ms17_010 "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/smb/smb_enumshares "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/smb/smb_enumusers "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/1433)
      msf_append_module "$rc_file" auxiliary/scanner/mssql/mssql_ping "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/3306)
      msf_append_module "$rc_file" auxiliary/scanner/mysql/mysql_version "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/3389)
      msf_append_module "$rc_file" auxiliary/scanner/rdp/rdp_scanner "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/rdp/cve_2019_0708_bluekeep "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/5800|tcp/5801|tcp/5900|tcp/5901)
      msf_append_module "$rc_file" auxiliary/scanner/vnc/vnc_none_auth "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
  esac
}

msf_write_targets_file() {
  local open_tsv="$1"
  local proto="$2"
  local port="$3"
  local target_file="$4"

  awk -F '\t' -v wanted_proto="$proto" -v wanted_port="$port" '
    NR > 1 && $2 == wanted_proto && $3 == wanted_port {
      print $1
    }
  ' "$open_tsv" | awk '!seen[$0]++' > "$target_file"
}

msf_print_modules_for_rc() {
  local rc_file="$1"
  local label="$2"
  local module_name

  while IFS= read -r module_name; do
    [[ -n "${module_name:-}" ]] || continue
    printf '%sRunning Metasploit Module:%s %s (%s)\n' "$CLR_CYAN" "$CLR_RESET" "$module_name" "$label"
  done < <(awk '/^use / {print $2}' "$rc_file")
}

run_msf_auxiliary_checks() {
  local open_tsv="targets_with_open_ports/open_ports_all.tsv"
  local index_rc_file="${MSF_DIR}/metasploit_auxiliary.rc"
  local rc_file
  local proto
  local port
  local key
  local previous_key=""
  local target_file
  local module_count=0
  local port_module_count=0
  local completed_modules=0
  local rc_files=()
  local rc_labels=()
  local rc_module_counts=()
  local index=0
  local status=0

  if [[ ! -s "$open_tsv" ]]; then
    return
  fi

  if ! command_available msfconsole; then
    printf '%sSkipping Metasploit Auxiliary Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  mkdir -p "$MSF_DIR" "$MSF_RESULT_DIR"
  rm -f "${MSF_DIR}"/metasploit_auxiliary_*.rc "${MSF_RESULT_DIR}"/*.txt 2>/dev/null || true
  : > "$index_rc_file"
  : > "${MSF_DIR}/msfconsole.log"

  while IFS=$'\t' read -r proto port; do
    [[ -n "${proto:-}" && -n "${port:-}" ]] || continue
    key="${proto}/${port}"
    [[ "$key" == "$previous_key" ]] && continue
    previous_key="$key"

    case "$key" in
      tcp/21|tcp/22|tcp/23|tcp/25|tcp/465|tcp/587|tcp/53|udp/53|tcp/139|tcp/445|tcp/1433|tcp/3306|tcp/3389|tcp/5800|tcp/5801|tcp/5900|tcp/5901)
        target_file="${MSF_DIR}/targets_${proto}_${port}.txt"
        rc_file="${MSF_DIR}/metasploit_auxiliary_${proto}_${port}.rc"
        : > "$rc_file"
        msf_write_targets_file "$open_tsv" "$proto" "$port" "$target_file"
        if [[ -s "$target_file" ]]; then
          msf_add_port_modules "$rc_file" "$proto" "$port" "$target_file"
        fi
        port_module_count="$(grep -c '^run$' "$rc_file" 2>/dev/null || true)"
        if [[ "$port_module_count" -gt 0 ]]; then
          printf 'resource %s\n' "$(msf_absolute_path "$rc_file")" >> "$index_rc_file"
          rc_files+=("$rc_file")
          rc_labels+=("${proto}/${port}")
          rc_module_counts+=("$port_module_count")
          module_count=$((module_count + port_module_count))
        else
          rm -f "$rc_file"
        fi
        ;;
    esac
  done < <(awk -F '\t' 'NR > 1 {print $2 "\t" $3}' "$open_tsv" | sort -k1,1 -k2,2n)

  if [[ ! -s "$index_rc_file" ]]; then
    return
  fi

  printf '%sRunning Metasploit Auxiliary Checks%s\n' "$CLR_CYAN" "$CLR_RESET"
  printf '%sMetasploit Module Runs:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$module_count"
  printf '%sMetasploit Threads:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$MSF_THREADS"
  if [[ "$MSF_TIMEOUT" -gt 0 ]]; then
    if command_available timeout; then
      printf '%sMetasploit Timeout:%s %s seconds per port group\n' "$CLR_CYAN" "$CLR_RESET" "$MSF_TIMEOUT"
    else
      printf '%sMetasploit Timeout:%s Disabled because timeout command was not found\n' "$CLR_YELLOW" "$CLR_RESET"
    fi
  fi
  printf '%sMetasploit Resource File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$index_rc_file"
  print_progress_bar "Metasploit Progress" "$completed_modules" "$module_count"
  [[ -t 1 ]] && printf '\n'

  for index in "${!rc_files[@]}"; do
    rc_file="${rc_files[$index]}"
    port_module_count="${rc_module_counts[$index]}"
    printf '%sRunning Metasploit Auxiliary For:%s %s (%s module(s))\n' "$CLR_CYAN" "$CLR_RESET" "${rc_labels[$index]}" "$port_module_count"
    msf_print_modules_for_rc "$rc_file" "${rc_labels[$index]}"
    status=0
    {
      printf '\n===== %s :: %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${rc_labels[$index]}"
      if [[ "${MSF_TIMEOUT:-0}" =~ ^[0-9]+$ && "${MSF_TIMEOUT:-0}" -gt 0 ]] && command_available timeout; then
        timeout --preserve-status "$MSF_TIMEOUT" msfconsole -q -r "$rc_file"
      else
        msfconsole -q -r "$rc_file"
      fi
    } >> "${MSF_DIR}/msfconsole.log" 2>&1 || status=$?
    if [[ "$status" -ne 0 ]]; then
      printf '%sMetasploit Auxiliary For %s Finished With Status:%s %s\n' "$CLR_YELLOW" "${rc_labels[$index]}" "$CLR_RESET" "$status"
    fi
    completed_modules=$((completed_modules + port_module_count))
    print_progress_bar "Metasploit Progress" "$completed_modules" "$module_count"
  done

  find "$MSF_RESULT_DIR" -type f -size 0 -delete 2>/dev/null || true
  printf '%sMetasploit Auxiliary Checks Finished%s\n' "$CLR_GREEN" "$CLR_RESET"
}
