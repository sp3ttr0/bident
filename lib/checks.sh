run_if_open() {
  local label="$1"
  local proto="$2"
  local ports_csv="$3"
  shift 3
  local ports=()
  local check_label="$label"

  check_label="${check_label% NSE}"
  check_label="${check_label% scan}"

  IFS=',' read -r -a ports <<< "$ports_csv"
  printf '\n%sChecking %s (%s)%s\n' "$CLR_CYAN" "$check_label" "$ports_csv" "$CLR_RESET"
  if has_open_port "$proto" "${ports[@]}"; then
    printf '\n%sRunning %s:%s Detected Open %s Port(s): (%s)\n' "$CLR_CYAN" "$label" "$CLR_RESET" "$proto" "$ports_csv"
    "$@"
  else
    printf '%sNo %s (%s) Found%s\n' "$CLR_YELLOW" "$check_label" "$ports_csv" "$CLR_RESET"
  fi
}

append_command_header() {
  local outfile="$1"
  shift

  {
    printf '\n===== %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\n\n'
  } >> "$outfile"
}

run_logged() {
  local outfile="$1"
  shift

  append_command_header "$outfile" "$@"
  "$@" >> "$outfile" 2>&1
}

print_check_result() {
  local label="$1"
  local result_file="$2"

  if result_output_has_finding "$label" "$result_file"; then
    printf '%s%s Found%s\n' "$CLR_GREEN" "$label" "$CLR_RESET"
  else
    printf '%sNo %s Found%s\n' "$CLR_YELLOW" "$label" "$CLR_RESET"
  fi
}

print_smb_relay_note() {
  printf '%sNote:%s Possible for Server Message Block (SMB) Relay Attack when SMB signing is disabled.\n' "$CLR_YELLOW" "$CLR_RESET"
}

result_output_has_finding() {
  local label="$1"
  local result_file="$2"

  [[ -s "$result_file" ]] || return 1

  case "$label" in
    "Weak SSH Ciphers")
      grep -Eiq '\(fail\)|\[fail\]|\(warn\)|\[warn\]|(^|[^[:alnum:]])(weak|deprecated|insecure|cbc|arcfour|3des|blowfish|rijndael|diffie-hellman-group1|diffie-hellman-group14-sha1|ssh-rsa|dss|md5|sha-?1)([^[:alnum:]]|$)' "$result_file"
      ;;
    "Exposed RPC Services")
      grep -Eiq '(^Protocol:|^Provider:|^[[:space:]]*[0-9a-fA-F-]{36}|ncacn_|MS-RPCE|uuid)' "$result_file" &&
        ! grep -Eiq 'connection refused|NT_STATUS_|failed|error|timed out|No route to host' "$result_file"
      ;;
    "Unauthenticated Remote Procedure Call")
      grep -Eiq 'Se[A-Za-z]+Privilege|found[[:space:]]+[0-9]+[[:space:]]+privileges|privilege' "$result_file" &&
        ! grep -Eiq 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|Cannot connect|failed|error|timed out' "$result_file"
      ;;
    "LDAP Anonymous Bind")
      grep -Eiq '^(dn:|namingContexts:|defaultNamingContext:|rootDomainNamingContext:|supportedLDAPVersion:|supportedSASLMechanisms:)' "$result_file" &&
        ! grep -Eiq 'Invalid credentials|Can.t contact LDAP server|ldap_bind:|failed|error|timed out' "$result_file"
      ;;
    "Misconfigured Server Message Block Signing")
      grep -Eq 'signing:False' "$result_file"
      ;;
    "SMBv1 Enabled")
      grep -Eq 'SMBv1:True' "$result_file"
      ;;
    *)
      grep -Ev '^[[:space:]]*$|^===== |^Command:' "$result_file" >/dev/null
      ;;
  esac
}

run_logged_check() {
  local label="$1"
  local outfile="$2"
  local temp_output
  local status=0
  shift 2

  temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
  "$@" > "$temp_output" 2>&1 || status=$?
  if result_output_has_finding "$label" "$temp_output"; then
    append_command_header "$outfile" "$@"
    cat "$temp_output" >> "$outfile"
  elif [[ ! -s "$outfile" ]]; then
    rm -f "$outfile"
  fi
  print_check_result "$label" "$temp_output"
  rm -f "$temp_output"
  return "$status"
}

run_rpc_135_checks() {
  local found=false
  local target
  local port

  printf '\n%sChecking MSRPC (135)%s\n' "$CLR_CYAN" "$CLR_RESET"
  rm -f ${TOOL_DIR}/s_rpcdump_135.txt ${TOOL_DIR}/s_rpcclient_135.txt

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true

    if command_available impacket-rpcdump; then
      printf '\n%sChecking For Exposed RPC Services:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
      run_logged_check "Exposed RPC Services" ${TOOL_DIR}/s_rpcdump_135.txt impacket-rpcdump -p "$port" "$target" || true
    else
      printf '%sSkipping impacket-rpcdump For %s:%s:%s Command Not Found\n' "$CLR_YELLOW" "$target" "$port" "$CLR_RESET"
    fi

    if command_available rpcclient; then
      printf '%sChecking For Unauthenticated Remote Procedure Call:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$target"
      run_logged_check "Unauthenticated Remote Procedure Call" ${TOOL_DIR}/s_rpcclient_135.txt rpcclient -U "" -N -c enumprivs "$target" || true
    else
      printf '%sSkipping rpcclient For %s:%s Command Not Found\n' "$CLR_YELLOW" "$target" "$CLR_RESET"
    fi
  done < <(open_target_ports tcp 135)

  if [[ "$found" == false ]]; then
    printf '%sNo MSRPC (135) Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
  fi
}

run_ldapsearch_checks() {
  local found=false
  local target
  local port

  rm -f ${TOOL_DIR}/s_ldapsearch.txt

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true

    if command_available ldapsearch; then
      printf '\n%sChecking For LDAP Anonymous Bind:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
      run_logged_check "LDAP Anonymous Bind" ${TOOL_DIR}/s_ldapsearch.txt ldapsearch -x -s base -b "" "(objectClass=*)" "*" -H "ldap://${target}:${port}" || true
    else
      printf '%sSkipping ldapsearch For %s:%s:%s Command Not Found\n' "$CLR_YELLOW" "$target" "$port" "$CLR_RESET"
    fi
  done < <(open_target_ports tcp 389 3268)

  if [[ "$found" == false ]]; then
    printf '%sNo LDAP Anonymous Bind (389,3268) Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
  fi
}

write_open_targets_file() {
  local proto="$1"
  local port="$2"
  local outfile="$3"

  open_target_ports "$proto" "$port" | awk '{print $1}' > "$outfile"
}

run_smb_external_checks() {
  local temp_output

  if ! has_open_port tcp 445; then
    printf '%sNo SMB (445) Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  write_open_targets_file tcp 445 ${TOOL_DIR}/targets_smb.txt
  if [[ ! -s ${TOOL_DIR}/targets_smb.txt ]]; then
    printf '%sNo SMB (445) Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  if ! command_available netexec; then
    printf '%sSkipping NetExec SMB Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  printf '\n%sChecking For Misconfigured Server Message Block Signing%s\n' "$CLR_CYAN" "$CLR_RESET"
  temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
  netexec smb --gen-relay-list ${TOOL_DIR}/targets_smb.txt "$LIVE_TARGETS_FILE" 2>&1 \
    | grep 'signing:False' > "$temp_output" || true
  if [[ -s "$temp_output" ]]; then
    append_command_header ${TOOL_DIR}/nxc_smb_signing_false.txt netexec smb --gen-relay-list ${TOOL_DIR}/targets_smb.txt "$LIVE_TARGETS_FILE"
    cat "$temp_output" >> ${TOOL_DIR}/nxc_smb_signing_false.txt
  else
    rm -f ${TOOL_DIR}/nxc_smb_signing_false.txt
  fi
  print_check_result "Misconfigured Server Message Block Signing" "$temp_output"
  if result_output_has_finding "Misconfigured Server Message Block Signing" "$temp_output"; then
    print_smb_relay_note
  fi
  rm -f "$temp_output"

  printf '%sChecking For SMBv1 Enabled%s\n' "$CLR_CYAN" "$CLR_RESET"
  temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
  netexec smb "$LIVE_TARGETS_FILE" 2>&1 \
    | grep 'SMBv1:True' > "$temp_output" || true
  if [[ -s "$temp_output" ]]; then
    append_command_header ${TOOL_DIR}/nxc_smbv1_true.txt netexec smb "$LIVE_TARGETS_FILE"
    cat "$temp_output" >> ${TOOL_DIR}/nxc_smbv1_true.txt
  else
    rm -f ${TOOL_DIR}/nxc_smbv1_true.txt
  fi
  print_check_result "SMBv1 Enabled" "$temp_output"
  rm -f "$temp_output"
}

run_ssh_audit_check() {
  if ! has_open_port tcp 22; then
    printf '%sNo Weak SSH Ciphers (22) Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  if ! command_available ssh-audit; then
    printf '%sSkipping ssh-audit:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  printf '\n%sChecking For Weak SSH Ciphers%s\n' "$CLR_CYAN" "$CLR_RESET"
  rm -f ${TOOL_DIR}/ssh-audit_results.txt
  run_logged_check "Weak SSH Ciphers" ${TOOL_DIR}/ssh-audit_results.txt ssh-audit -T "$LIVE_TARGETS_FILE" || true
}

run_dns_dig_checks() {
  local target
  local port
  local temp_output
  local dnssec_file="${TOOL_DIR}/dnssec_not_configured.txt"
  local recursion_file="${TOOL_DIR}/dns_recursion_enabled.txt"

  if ! has_open_port any 53; then
    return
  fi

  if ! command_available dig; then
    printf '%sSkipping DNS dig Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  : > "$dnssec_file"
  : > "$recursion_file"

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue

    printf '\n%sChecking For DNSSec Not Configured:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
    temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
    if [[ "$NO_UDP" == true ]]; then
      dig +tcp +dnssec "@${target}" google.com A > "$temp_output" 2>&1 || true
    else
      dig +dnssec "@${target}" google.com A > "$temp_output" 2>&1 || true
    fi
    if grep -q 'flags:' "$temp_output" && ! grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]' "$temp_output"; then
      if [[ "$NO_UDP" == true ]]; then
        append_command_header "$dnssec_file" dig +tcp +dnssec "@${target}" google.com A
      else
        append_command_header "$dnssec_file" dig +dnssec "@${target}" google.com A
      fi
      cat "$temp_output" >> "$dnssec_file"
      printf '%sDNSSec Not Configured Found%s\n' "$CLR_GREEN" "$CLR_RESET"
    else
      printf '%sNo DNSSec Not Configured Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
    fi
    rm -f "$temp_output"

    printf '%sChecking For DNS Recursion Enabled:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
    temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
    if [[ "$NO_UDP" == true ]]; then
      dig +tcp "@${target}" google.com A > "$temp_output" 2>&1 || true
    else
      dig "@${target}" google.com A > "$temp_output" 2>&1 || true
    fi
    if grep -Eq 'flags:.*[[:space:]]ra[;[:space:]]' "$temp_output"; then
      if [[ "$NO_UDP" == true ]]; then
        append_command_header "$recursion_file" dig +tcp "@${target}" google.com A
      else
        append_command_header "$recursion_file" dig "@${target}" google.com A
      fi
      cat "$temp_output" >> "$recursion_file"
      printf '%sDNS Recursion Enabled Found%s\n' "$CLR_GREEN" "$CLR_RESET"
    else
      printf '%sNo DNS Recursion Enabled Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
    fi
    rm -f "$temp_output"
  done < <(open_target_ports any 53)

  [[ -s "$dnssec_file" ]] || rm -f "$dnssec_file"
  [[ -s "$recursion_file" ]] || rm -f "$recursion_file"
}

run_ssl_external_checks() {
  local found=false
  local has_testssl=false
  local has_sslscan=false
  local target
  local port
  local ssl_targets=()
  local entry

  if command_available testssl; then
    has_testssl=true
    : > ${TOOL_DIR}/testssl_results.txt
  else
    printf '%sSkipping testssl Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
  fi

  if command_available sslscan; then
    has_sslscan=true
    : > ${TOOL_DIR}/sslscan_results.txt
  else
    printf '%sSkipping sslscan Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
  fi

  if [[ "$has_testssl" == false && "$has_sslscan" == false ]]; then
    return
  fi

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true
    ssl_targets+=("${target}:${port}")
  done < <(open_target_ports tcp 443 465 587 636 993 995 3269 3389 8443)

  if [[ "$found" == false ]]; then
    printf '%sNo SSL/TLS Ports Found For testssl/sslscan%s\n' "$CLR_YELLOW" "$CLR_RESET"
    [[ ! -e ${TOOL_DIR}/testssl_results.txt || -s ${TOOL_DIR}/testssl_results.txt ]] || rm -f ${TOOL_DIR}/testssl_results.txt
    [[ ! -e ${TOOL_DIR}/sslscan_results.txt || -s ${TOOL_DIR}/sslscan_results.txt ]] || rm -f ${TOOL_DIR}/sslscan_results.txt
    return
  fi

  if [[ "$has_testssl" == true ]]; then
    printf '\n%sRunning testssl%s\n' "$CLR_CYAN" "$CLR_RESET"
    for entry in "${ssl_targets[@]}"; do
      run_logged ${TOOL_DIR}/testssl_results.txt testssl "$entry" || true
    done
  fi

  if [[ "$has_sslscan" == true ]]; then
    printf '%sRunning sslscan%s\n' "$CLR_CYAN" "$CLR_RESET"
    for entry in "${ssl_targets[@]}"; do
      run_logged ${TOOL_DIR}/sslscan_results.txt sslscan "$entry" || true
    done
  fi

  [[ ! -e ${TOOL_DIR}/testssl_results.txt || -s ${TOOL_DIR}/testssl_results.txt ]] || rm -f ${TOOL_DIR}/testssl_results.txt
  [[ ! -e ${TOOL_DIR}/sslscan_results.txt || -s ${TOOL_DIR}/sslscan_results.txt ]] || rm -f ${TOOL_DIR}/sslscan_results.txt
}

run_ike_weak_encryption_check() {
  local found=false
  local finding=false
  local target
  local port
  local temp_output
  local outfile="${TOOL_DIR}/ike_weak_encryption.txt"

  if ! has_open_port udp 500; then
    return
  fi

  if ! command_available ike-scan; then
    printf '%sSkipping ike-scan Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  rm -f "$outfile"

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true

    printf '\n%sChecking For IKE VPN Peer Weak Encryption:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
    temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
    ike-scan -M "$target" > "$temp_output" 2>&1 || true

    if grep -Eiq '(^|[^A-Za-z0-9])(3des|des|md5|sha-?1|group[[:space:]]*1|group[[:space:]]*2|modp768|modp1024)([^A-Za-z0-9]|$)' "$temp_output"; then
      append_command_header "$outfile" ike-scan -M "$target"
      cat "$temp_output" >> "$outfile"
      printf '%sIKE VPN Peer Weak Encryption Found%s\n' "$CLR_GREEN" "$CLR_RESET"
      finding=true
    else
      printf '%sNo IKE VPN Peer Weak Encryption Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
    fi

    rm -f "$temp_output"
  done < <(open_target_ports udp 500)

  if [[ "$found" == false ]]; then
    printf '%sNo IKE (500) Found%s\n' "$CLR_YELLOW" "$CLR_RESET"
  fi

  [[ "$finding" == true ]] || rm -f "$outfile"
}

run_if_any_open() {
  local label="$1"
  shift

  if has_any_open_port; then
    printf '\n%sRunning %s:%s At Least One Confirmed Open Port Was Detected\n' "$CLR_CYAN" "$label" "$CLR_RESET"
    "$@"
  else
    printf '%sNo %s Found%s\n' "$CLR_YELLOW" "$label" "$CLR_RESET"
  fi
}
