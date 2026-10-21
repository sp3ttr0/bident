html_escape_file() {
  awk '
    {
      gsub(/&/, "\\&amp;")
      gsub(/</, "\\&lt;")
      gsub(/>/, "\\&gt;")
      print
    }
  ' "$1"
}

file_size_bytes() {
  wc -c < "$1" | tr -d '[:space:]'
}

html_escape_file_preview() {
  local file="$1"
  local max_bytes="${REPORT_EVIDENCE_MAX_BYTES:-200000}"
  local size
  local head_bytes
  local tail_bytes

  size="$(file_size_bytes "$file")"
  if [[ ! "$max_bytes" =~ ^[0-9]+$ || "$max_bytes" -eq 0 || "$size" -le "$max_bytes" ]]; then
    html_escape_file "$file"
    return
  fi

  head_bytes=$((max_bytes * 3 / 4))
  tail_bytes=$((max_bytes - head_bytes))

  head -c "$head_bytes" "$file" | awk '
    {
      gsub(/&/, "\\&amp;")
      gsub(/</, "\\&lt;")
      gsub(/>/, "\\&gt;")
      print
    }
  '
  printf '\n\n[ Bident truncated this evidence preview: %s bytes total, showing first %s bytes and last %s bytes. Open the source file above for the full output. ]\n\n' \
    "$size" "$head_bytes" "$tail_bytes"
  tail -c "$tail_bytes" "$file" | awk '
    {
      gsub(/&/, "\\&amp;")
      gsub(/</, "\\&lt;")
      gsub(/>/, "\\&gt;")
      print
    }
  '
}

html_escape_text() {
  printf '%s' "$1" | awk '
    {
      gsub(/&/, "\\&amp;")
      gsub(/</, "\\&lt;")
      gsub(/>/, "\\&gt;")
      print
    }
  '
}

title_case_acronyms() {
  awk '{
    for (i = 1; i <= NF; i++) {
      lower = tolower($i)
      if (lower == "ssh" || lower == "ftp" || lower == "smtp" || lower == "dns" ||
          lower == "smb" || lower == "mssql" || lower == "mysql" || lower == "rdp" ||
          lower == "vnc" || lower == "snmp" || lower == "ntp") {
        $i = toupper($i)
      } else {
        $i = toupper(substr($i, 1, 1)) substr($i, 2)
      }
    }
    print
  }'
}

default_result_label() {
  local result_name="${1##*/}"
  local msf_name

  if [[ "$result_name" =~ ^[A-Za-z0-9_]+_(tcp|udp)_[0-9]+\.txt$ ]]; then
    msf_name="${result_name%.txt}"
    msf_name="$(printf '%s' "$msf_name" | sed -E 's/_(tcp|udp)_[0-9]+$//; s/_/ /g')"
    printf '%s Metasploit Results' "$(printf '%s' "$msf_name" | title_case_acronyms)"
    return
  fi

  case "$result_name" in
    s_ftp.txt) printf 'FTP NMAP Results' ;;
    s_ssh.txt) printf 'SSH NMAP Results' ;;
    s_telnet.txt) printf 'Telnet NMAP Results' ;;
    s_smtp.txt) printf 'SMTP NMAP Results' ;;
    s_dns.txt) printf 'DNS NMAP Results' ;;
    s_http.txt) printf 'HTTP NMAP Results' ;;
    s_ajp.txt) printf 'AJP NMAP Results' ;;
    s_kerberos.txt) printf 'Kerberos NMAP Results' ;;
    s_pop3.txt) printf 'POP3 NMAP Results' ;;
    s_rpcbind.txt) printf 'RPCBind NMAP Results' ;;
    s_ntp.txt) printf 'NTP NMAP Results' ;;
    s_netbios.txt) printf 'NetBIOS NMAP Results' ;;
    s_smb.txt) printf 'SMB NMAP Results' ;;
    s_snmp.txt) printf 'SNMP NMAP Results' ;;
    s_ldap.txt) printf 'LDAP NMAP Results' ;;
    s_ike.txt) printf 'IKE NMAP Results' ;;
    s_ipmi.txt) printf 'IPMI NMAP Results' ;;
    ike_weak_encryption.txt) printf 'IKE VPN Peer Weak Encryption' ;;
    s_oracle.txt) printf 'Oracle NMAP Results' ;;
    s_nfs.txt) printf 'NFS NMAP Results' ;;
    s_rdp.txt) printf 'RDP NMAP Results' ;;
    s_sip.txt) printf 'SIP NMAP Results' ;;
    s_vnc.txt) printf 'VNC NMAP Results' ;;
    ssl_tls_results.txt) printf 'SSL/TLS NMAP Results' ;;
    testssl_results.txt) printf 'testssl Results' ;;
    sslscan_results.txt) printf 'sslscan Results' ;;
    dnssec_not_configured.txt) printf 'DNSSec Not Configured' ;;
    dns_recursion_enabled.txt) printf 'DNS Recursion Enabled' ;;
    db_mssql.txt) printf 'MSSQL NMAP Results' ;;
    db_mysql.txt) printf 'MySQL NMAP Results' ;;
    *) printf '%s' "$result_name" ;;
  esac
}

resolve_result_file() {
  local result_file="$1"

  if [[ -s "$result_file" ]]; then
    printf '%s' "$result_file"
    return 0
  fi

  for result_file in "${NSE_DIR}/${result_file}" "${TOOL_DIR}/${result_file}" "${SCAN_DIR}/${result_file}" "${LOG_DIR}/${result_file}"; do
    if [[ -s "$result_file" ]]; then
      printf '%s' "$result_file"
      return 0
    fi
  done

  return 1
}

append_result_file_section() {
  local outfile="$1"
  local result_file="$2"
  local result_label="${3:-}"
  local resolved_file
  local result_name

  if [[ -z "$result_label" ]]; then
    result_label="$(default_result_label "$result_file")"
  fi

  resolved_file="$(resolve_result_file "$result_file")" || return 1
  result_name="${resolved_file##*/}"

  {
    printf '<details class="artifact result-panel">\n'
    if [[ "$result_label" == "$result_name" ]]; then
      printf '<summary>%s</summary>\n' "$(html_escape_text "$resolved_file")"
    else
      printf '<summary>%s <span class="artifact-file">%s</span></summary>\n' "$(html_escape_text "$result_label")" "$(html_escape_text "$resolved_file")"
    fi
    printf '<pre>'
    html_escape_file_preview "$resolved_file"
    printf '</pre>\n'
    printf '</details>\n'
  } >> "$outfile"
  return 0
}

append_ssl_external_result_files() {
  local outfile="$1"
  local appended=1

  append_result_file_section "$outfile" testssl_results.txt && appended=0
  append_result_file_section "$outfile" sslscan_results.txt && appended=0
  return "$appended"
}

append_artifact_link() {
  local outfile="$1"
  local artifact="$2"

  if [[ -s "$artifact" ]]; then
    printf '<a href="%s">%s</a>\n' "$(html_escape_text "$artifact")" "$(html_escape_text "$artifact")" >> "$outfile"
  fi
}

append_core_artifact_group() {
  local outfile="$1"
  local label="$2"
  shift 2
  local artifact
  local temp_file
  local item_count=0

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_artifacts.XXXXXX")"
  for artifact in "$@"; do
    if [[ -s "$artifact" ]]; then
      printf '<a href="%s">%s</a>\n' "$(html_escape_text "$artifact")" "$(html_escape_text "$artifact")" >> "$temp_file"
      item_count=$((item_count + 1))
    fi
  done

  if [[ -s "$temp_file" ]]; then
    {
      printf '    <details class="artifact artifact-group">\n'
      printf '      <summary>%s <span class="artifact-file">%s item(s)</span></summary>\n' "$(html_escape_text "$label")" "$item_count"
      printf '      <div class="file-list">'
      cat "$temp_file"
      printf '      </div>\n'
      printf '    </details>\n'
    } >> "$outfile"
  fi

  rm -f "$temp_file"
}

append_msf_result_files() {
  local outfile="$1"
  local proto="$2"
  local port="$3"
  local result_file
  local appended=1

  [[ "${NO_MSF:-false}" == true ]] && return 1

  for result_file in "${MSF_RESULT_DIR}/"*"_${proto}_${port}.txt"; do
    [[ -s "$result_file" ]] || continue
    append_result_file_section "$outfile" "$result_file" && appended=0
  done
  return "$appended"
}

append_base_scan_port_evidence() {
  local outfile="$1"
  local proto="$2"
  local port="$3"
  local temp_file
  local source_file
  local sources=()

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_base_evidence.XXXXXX")"

  case "$proto" in
    tcp)
      sources=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap")
      ;;
    udp)
      sources=("${SCAN_DIR}/udp.gnmap")
      ;;
    *)
      sources=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap")
      ;;
  esac

  for source_file in "${sources[@]}"; do
    [[ -s "$source_file" ]] || continue
    awk -v wanted_port="$port" -v wanted_proto="$proto" -v source_file="$source_file" '
      $0 ~ "Ports:" {
        split($0, parts, "Ports: ")
        split(parts[2], ports, ", ")
        for (i in ports) {
          split(ports[i], fields, "/")
          if (fields[1] == wanted_port && fields[2] == "open" && fields[3] == wanted_proto) {
            print "===== " source_file " ====="
            print $0
            print ""
            break
          }
        }
      }
    ' "$source_file" >> "$temp_file"
  done

  if [[ -s "$temp_file" ]]; then
    {
      printf '<details class="artifact result-panel">\n'
      printf '<summary>Base Scan Evidence <span class="artifact-file">%s/%s</span></summary>\n' "$(html_escape_text "$proto")" "$(html_escape_text "$port")"
      printf '<pre>'
      html_escape_file_preview "$temp_file"
      printf '</pre>\n'
      printf '</details>\n'
    } >> "$outfile"
    rm -f "$temp_file"
    return 0
  fi

  rm -f "$temp_file"
  return 1
}

append_nse_status_section() {
  local outfile="$1" label status log_file
  {
    printf '  <h2>NSE Check Status</h2>\n'
    printf '  <p class="muted">Script timeout: %s per instance (0 = unlimited). Timed-out checks are incomplete, not evidence that credentials or vulnerabilities are absent.</p>\n' "$(html_escape_text "$SCRIPT_TIMEOUT")"
    if [[ -s "${LOG_DIR}/nse_status.tsv" ]]; then
      printf '  <ul>\n'
      while IFS=$'\t' read -r label status log_file; do
        printf '    <li><strong>%s</strong>: %s — <a href="%s">execution log</a></li>\n' \
          "$(html_escape_text "$label")" "$(html_escape_text "$status")" "$(html_escape_text "$log_file")"
      done < "${LOG_DIR}/nse_status.tsv"
      printf '  </ul>\n'
    else
      printf '  <p class="muted">No follow-up NSE checks recorded for this run.</p>\n'
    fi
  } >> "$outfile"
}

append_scan_configuration_section() {
  local outfile="$1"
  local scope_display="${SCOPE_FILE:-resume}"
  local udp_mode="Enabled"
  local msf_mode="Enabled"
  local ports_mode="Default Nmap ports"
  local discovery_timeout="${DISCOVERY_HOST_TIMEOUT:-5m}"

  [[ "$NO_UDP" == true ]] && udp_mode="Disabled"
  [[ "$NO_MSF" == true ]] && msf_mode="Disabled"
  [[ "$PORT_FLAG" == "-p-" ]] && ports_mode="All ports (-p-)"

  {
    printf '  <h2>Scan Configuration</h2>\n'
    printf '  <section class="summary-grid">\n'
    printf '    <div class="summary-card"><span>Target input</span><strong>%s</strong></div>\n' "$(html_escape_text "$scope_display")"
    printf '    <div class="summary-card"><span>Ports</span><strong>%s</strong></div>\n' "$(html_escape_text "$ports_mode")"
    printf '    <div class="summary-card"><span>Timing</span><strong>-%s</strong></div>\n' "$(html_escape_text "$TIMING")"
    printf '    <div class="summary-card"><span>Base min-rate</span><strong>%s</strong></div>\n' "$(html_escape_text "$MIN_RATE")"
    printf '    <div class="summary-card"><span>NSE min-rate</span><strong>%s</strong></div>\n' "$(html_escape_text "$NSE_MIN_RATE")"
    printf '    <div class="summary-card"><span>Host discovery timeout</span><strong>%s</strong></div>\n' "$(html_escape_text "$discovery_timeout")"
    printf '    <div class="summary-card"><span>UDP scans</span><strong>%s</strong></div>\n' "$(html_escape_text "$udp_mode")"
    printf '    <div class="summary-card"><span>Metasploit</span><strong>%s</strong></div>\n' "$(html_escape_text "$msf_mode")"
    printf '    <div class="summary-card"><span>Tool timeout</span><strong>%s</strong></div>\n' "$([[ "$TOOL_TIMEOUT" -gt 0 ]] && html_escape_text "${TOOL_TIMEOUT}s" || printf 'Disabled')"
    printf '    <div class="summary-card"><span>Metasploit timeout</span><strong>%s</strong></div>\n' "$([[ "$MSF_TIMEOUT" -gt 0 ]] && html_escape_text "${MSF_TIMEOUT}s" || printf 'Disabled')"
    printf '    <div class="summary-card"><span>Metasploit threads</span><strong>%s</strong></div>\n' "$(html_escape_text "$MSF_THREADS")"
    printf '    <div class="summary-card"><span>Metasploit connect timeout</span><strong>%ss</strong></div>\n' "$(html_escape_text "$MSF_CONNECT_TIMEOUT")"
    printf '    <div class="summary-card"><span>Metasploit TCP timeout</span><strong>%ss</strong></div>\n' "$(html_escape_text "$MSF_TCP_TIMEOUT")"
    printf '  </section>\n'
  } >> "$outfile"
}

finding_count_for_file() {
  local file="$1"

  [[ -s "$file" ]] || {
    printf '0'
    return
  }

  awk 'END {print NR + 0}' "$file"
}

finding_file_has_verified_evidence() {
  local title="$1"
  local source_file="$2"

  [[ -s "$source_file" ]] || return 1

  case "$title" in
    "Weak SSH Ciphers")
      grep -Eiq '\(fail\)|\[fail\]|\(warn\)|\[warn\]|(^|[^[:alnum:]])(weak|deprecated|insecure|cbc|arcfour|3des|blowfish|rijndael|diffie-hellman-group1|diffie-hellman-group14-sha1|ssh-rsa|dss|md5|sha-?1)([^[:alnum:]]|$)' "$source_file"
      ;;
    "Exposed RPC Services")
      grep -Eiq '(^Protocol:|^Provider:|^[[:space:]]*[0-9a-fA-F-]{36}|ncacn_|MS-RPCE|uuid)' "$source_file" &&
        ! grep -Eiq 'connection refused|NT_STATUS_|failed|error|timed out|No route to host' "$source_file"
      ;;
    "Unauthenticated Remote Procedure Call")
      grep -Eiq 'Se[A-Za-z]+Privilege|found[[:space:]]+[0-9]+[[:space:]]+privileges|privilege' "$source_file" &&
        ! grep -Eiq 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|Cannot connect|failed|error|timed out' "$source_file"
      ;;
    "Misconfigured Server Message Block Signing")
      grep -Eq 'signing:False' "$source_file"
      ;;
    "SMBv1 Enabled")
      grep -Eq 'SMBv1:True' "$source_file"
      ;;
    "LDAP Anonymous Bind")
      grep -Eiq '^(dn:|namingContexts:|defaultNamingContext:|rootDomainNamingContext:|supportedLDAPVersion:|supportedSASLMechanisms:)' "$source_file" &&
        ! grep -Eiq 'Invalid credentials|Can.t contact LDAP server|ldap_bind:|failed|error|timed out' "$source_file"
      ;;
    "DNSSec Not Configured")
      grep -q 'flags:' "$source_file" && ! grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]' "$source_file"
      ;;
    "DNS Recursion Enabled")
      grep -Eq 'flags:.*[[:space:]]ra[;[:space:]]' "$source_file"
      ;;
    "IKE VPN Peer Weak Encryption")
      grep -Eiq '(^|[^A-Za-z0-9])(3des|des|md5|sha-?1|group[[:space:]]*1|group[[:space:]]*2|modp768|modp1024)([^A-Za-z0-9]|$)' "$source_file"
      ;;
    *)
      return 1
      ;;
  esac
}

append_finding_item() {
  local outfile="$1"
  local severity="$2"
  local title="$3"
  local source_file="$4"
  local detail="${5:-}"
  local count=0

  [[ -s "$source_file" ]] || return 0
  finding_file_has_verified_evidence "$title" "$source_file" || return 0
  count="$(finding_count_for_file "$source_file")"

  {
    printf '    <li><details class="finding-panel">\n'
    printf '      <summary><span class="finding-severity">%s</span><div><strong>%s</strong>\n' "$(html_escape_text "$severity")" "$(html_escape_text "$title")"
    printf '        <span>%s%s</span>\n' "$(html_escape_text "$source_file")" "$([[ "$count" -gt 0 ]] && printf ' · %s line(s)' "$count")"
    if [[ -n "$detail" ]]; then
      printf '        <p>%s</p>\n' "$(html_escape_text "$detail")"
    fi
    printf '      </div></summary>\n'
    printf '      <pre class="finding-evidence">'
    html_escape_file_preview "$source_file"
    printf '</pre>\n'
    printf '    </details></li>\n'
  } >> "$outfile"
}

append_finding_glob_item() {
  local outfile="$1"
  local severity="$2"
  local title="$3"
  local source_pattern="$4"
  local detail="${5:-}"
  local success_regex="${6:-}"
  local reject_regex="${7:-}"
  local source_file
  local files=()
  local count=0

  for source_file in $source_pattern; do
    [[ -s "$source_file" ]] || continue
    if [[ -n "$success_regex" ]] && ! grep -Eiq "$success_regex" "$source_file"; then
      continue
    fi
    if [[ -n "$reject_regex" ]] && grep -Eiq "$reject_regex" "$source_file"; then
      continue
    fi
    files+=("$source_file")
    count=$((count + $(finding_count_for_file "$source_file")))
  done

  [[ "${#files[@]}" -gt 0 ]] || return 0

  {
    printf '    <li><details class="finding-panel">\n'
    printf '      <summary><span class="finding-severity">%s</span><div><strong>%s</strong>\n' "$(html_escape_text "$severity")" "$(html_escape_text "$title")"
    printf '        <span>%s file(s) · %s line(s)</span>\n' "${#files[@]}" "$count"
    if [[ -n "$detail" ]]; then
      printf '        <p>%s</p>\n' "$(html_escape_text "$detail")"
    fi
    printf '      </div></summary>\n'
    printf '      <pre class="finding-evidence">'
    for source_file in "${files[@]}"; do
      printf '===== %s =====\n' "$(html_escape_text "$source_file")"
      html_escape_file_preview "$source_file"
      printf '\n'
    done
    printf '</pre>\n'
    printf '    </details></li>\n'
  } >> "$outfile"
}

credential_candidate_lines() {
  local file="$1"

  awk '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    function is_credential_line(value, lowered, field, token) {
      lowered = tolower(value)
      sub(/^\|[_ ]*[[:space:]]*/, "", lowered)
      sub(/^\[[+*!-]\][[:space:]]*/, "", lowered)
      # Rejected attempts and diagnostic/help text are not discoveries.
      if (lowered ~ /^(error|warning|usage|example|command|debug|failed|invalid|testing|trying|attempting)([[:space:]:]|$)/ ||
          lowered ~ /(login|authentication|access)[[:space:]]+(failed|failure|denied|disabled|not allowed)/ ||
          lowered ~ /(invalid|incorrect|rejected)[[:space:]]+(credentials|password)|credentials[[:space:]]+(invalid|rejected|not found)/ ||
          lowered ~ /no[[:space:]]+(valid[[:space:]]+)?credentials/ ||
          lowered ~ /status_logon_failure|nt_status_logon_failure/) return 0

      # Require an actual field, rather than a URL parameter, script name,
      # NTLM domain metadata, or a mention of credential terminology.
      if (lowered ~ /^(user(name)?|login|account|acct|password|passwd|pwd|credential|credentials|hash|secret|token)[[:space:]]*[:=]/) {
        field = lowered
        sub(/[:=].*$/, "", field)
        token = lowered
        sub(/^[^:=]*[:=][[:space:]]*/, "", token)
        sub(/[[:space:],;].*$/, "", token)
        if (token == "" || token ~ /^(none|null|nil|n\/a|unknown|redacted|disabled|required|not|false|true|\*+|x{4,}|<[^>]*>|\[[^]]*\])$/) return 0
        return 1
      }
      if (lowered ~ /(anonymous[[:space:]_-]*(login|access|ftp).*(allowed|enabled|successful)|valid[[:space:]_-]+credentials[[:space:]]*[:=]|login successful|authentication successful|empty[[:space:]_-]+password.*(allowed|enabled|found)|default[[:space:]_-]+credentials.*(found|valid|accepted))/) return 1
      return 0
    }
    {
      line = trim($0)
      # Nmap headers and echoed invocations describe requested checks,
      # not discovered credentials (for example --script-args user=...).
      if (line ~ /^#/ || tolower(line) ~ /(^|[[:space:]])([^[:space:]]*\/)?nmap([[:space:]]|$)/) {
        in_mysql_users = 0
        next
      }
      if (line ~ /^\|[ _]*mysql-users:[[:space:]]*$/) {
        in_mysql_users = 1
        next
      }
      if (in_mysql_users) {
        # Only indented, single-name entries belong to this NSE list.
        # Stop at another script, host, port, or non-list output line.
        if (line ~ /^\|[_ ]?[[:space:]]+[^[:space:]:]+[[:space:]]*$/) {
          username = line
          sub(/^\|[_ ]?[[:space:]]+/, "", username)
          username = trim(username)
          print NR "\034" username "\034username: " username
          if (line ~ /^\|_/) in_mysql_users = 0
          next
        }
        in_mysql_users = 0
      }
      if (line != "" && is_credential_line(line)) {
        print NR "\034" line
      }
    }
  ' "$file"
}

credential_candidate_count() {
  local file
  local total_count=0

  for file in "${NSE_DIR}"/*.txt "${TOOL_DIR}"/*.txt "${MSF_RESULT_DIR}"/*.txt; do
    [[ -s "$file" ]] || continue
    total_count=$((total_count + $(credential_candidate_lines "$file" | awk 'END {print NR + 0}')))
  done

  printf '%s' "$total_count"
}

append_findings_summary_section() {
  local outfile="$1"
  local temp_file

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_findings.XXXXXX")"
  append_finding_item "$temp_file" "Review" "Weak SSH Ciphers" "${TOOL_DIR}/ssh-audit_results.txt"
  append_finding_item "$temp_file" "Review" "Exposed RPC Services" "${TOOL_DIR}/s_rpcdump_135.txt"
  append_finding_item "$temp_file" "Review" "Unauthenticated Remote Procedure Call" "${TOOL_DIR}/s_rpcclient_135.txt"
  append_finding_item "$temp_file" "Review" "Misconfigured Server Message Block Signing" "${TOOL_DIR}/nxc_smb_signing_false.txt" "Possible Server Message Block (SMB) relay attack exposure."
  append_finding_item "$temp_file" "Review" "SMBv1 Enabled" "${TOOL_DIR}/nxc_smbv1_true.txt"
  append_finding_item "$temp_file" "Review" "LDAP Anonymous Bind" "${TOOL_DIR}/s_ldapsearch.txt"
  append_finding_item "$temp_file" "Review" "DNSSec Not Configured" "${TOOL_DIR}/dnssec_not_configured.txt"
  append_finding_item "$temp_file" "Review" "DNS Recursion Enabled" "${TOOL_DIR}/dns_recursion_enabled.txt"
  append_finding_item "$temp_file" "Review" "IKE VPN Peer Weak Encryption" "${TOOL_DIR}/ike_weak_encryption.txt"
  append_finding_glob_item "$temp_file" "Review" "FTP Anonymous Enabled" "${MSF_RESULT_DIR}/ftp_anonymous_tcp_*.txt" "" "anonymous.*(allowed|enabled|login|read|write)|logged in successfully|success.*anonymous" "failed to load module|unknown command|timed out|no anonymous|anonymous.*(denied|disabled|not allowed)|not vulnerable|not exploitable"
  append_finding_glob_item "$temp_file" "Review" "SMTP Open Relay" "${MSF_RESULT_DIR}/smtp_relay_tcp_*.txt" "" "open relay|relay.*(accepted|allowed|successful)|success.*relay" "failed to load module|unknown command|timed out|not an open relay|relay.*(denied|not allowed|failed)|not vulnerable|not exploitable"
  append_finding_glob_item "$temp_file" "Review" "Server Message Block (SMB) MS17-010 (EternalBlue) Vulnerability" "${MSF_RESULT_DIR}/smb_ms17_010_tcp_*.txt" "" "vulnerable|ms17-010.*detected|likely.*vulnerable" "failed to load module|unknown command|timed out|not vulnerable|not likely vulnerable|does not appear|not exploitable"
  append_finding_glob_item "$temp_file" "Review" "Remote Desktop Protocol Detection" "${MSF_RESULT_DIR}/rdp_scanner_tcp_*.txt" "" "detected|rdp|remote desktop|protocol" "failed to load module|unknown command|timed out|not found|no response|connection refused|denied"
  append_finding_glob_item "$temp_file" "Review" "Remote Desktop Protocol (RDP) BlueKeep Vulnerability" "${MSF_RESULT_DIR}/cve_2019_0708_bluekeep_tcp_*.txt" "" "vulnerable|bluekeep.*detected|likely.*vulnerable" "failed to load module|unknown command|timed out|not vulnerable|not likely vulnerable|does not appear|not exploitable"
  append_finding_glob_item "$temp_file" "Review" "Virtual Network Computing (VNC) None Authentication" "${MSF_RESULT_DIR}/vnc_none_auth_tcp_*.txt" "" "no authentication|required.*false|authentication.*disabled|does not require authentication" "failed to load module|unknown command|timed out|no authentication types available|too many authentication failures|auth negotiation failed|requires authentication|authentication failed|not vulnerable|not exploitable"
  append_finding_glob_item "$temp_file" "Review" "SNMP Default/Weak Community String" "${MSF_RESULT_DIR}/snmp_login_udp_*.txt" "" "login successful|success.*community|community.*(public|private)|\\[\\+\\].*(public|private)" "failed to load module|unknown command|timed out|login failed|no valid|not found|denied"
  append_finding_glob_item "$temp_file" "Review" "SNMP Information Disclosure" "${MSF_RESULT_DIR}/snmp_enum_udp_*.txt" "" "system information|sysdescr|hostname|uptime|contact|location|interfaces|processes|storage" "failed to load module|unknown command|timed out|no access|not found|denied"
  append_finding_glob_item "$temp_file" "Review" "SNMP Users Enumeration" "${MSF_RESULT_DIR}/snmp_enumusers_udp_*.txt" "" "\\[\\+\\].*(user|account|uid)|(^|[[:space:]])(User|Username|Account|UID)[[:space:]]*[:=]" "failed to load module|unknown command|timed out|no access|not found|denied"
  append_finding_glob_item "$temp_file" "Review" "SNMP Shares Enumeration" "${MSF_RESULT_DIR}/snmp_enumshares_udp_*.txt" "" "\\[\\+\\].*(share|path)|(^|[[:space:]])(Share|Share Name|Path)[[:space:]]*[:=]" "failed to load module|unknown command|timed out|no access|not found|denied"

  {
    printf '  <h2>Findings Summary</h2>\n'
    if [[ -s "$temp_file" ]]; then
      printf '  <ul class="finding-list">\n'
      cat "$temp_file"
      printf '  </ul>\n'
    else
      printf '  <div class="empty">No targeted findings were written by follow-up checks.</div>\n'
    fi
  } >> "$outfile"

  rm -f "$temp_file"
}

credential_display_value() {
  local line="$1"
  local value=""
  local label=""
  local secret=""

  value="$(printf '%s' "$line" | sed -nE 's/.*([Uu]sername|[Uu]ser|[Ll]ogin|[Aa]ccount|[Aa]cct|[Pp]assword|[Pp]asswd|[Pp]wd|[Cc]redential|[Hh]ash|[Ss]ecret|[Tt]oken)[=:][[:space:]]*([^[:space:]&;,"'"'"'<>]+).*/\1:::BIDENT:::\2/p' | head -n 1)"
  if [[ -n "$value" ]]; then
    label="${value%%:::BIDENT:::*}"
    secret="${value#*:::BIDENT:::}"
    label="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]')"
    case "$label" in
      acct) label="account" ;;
      passwd|pwd) label="password" ;;
    esac
    printf '%s: %s' "$label" "$secret"
    return
  fi

  value="$(printf '%s' "$line" | sed -nE 's/.*[?&]([Uu]sername|[Uu]ser|[Ll]ogin|[Aa]ccount|[Aa]cct|[Pp]assword|[Pp]asswd|[Pp]wd|[Tt]oken)=([^&[:space:]<>"'"'"']+).*/\1:::BIDENT:::\2/p' | head -n 1)"
  if [[ -n "$value" ]]; then
    label="${value%%:::BIDENT:::*}"
    secret="${value#*:::BIDENT:::}"
    label="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]')"
    case "$label" in
      acct) label="account" ;;
      passwd|pwd) label="password" ;;
    esac
    printf '%s: %s' "$label" "$secret"
    return
  fi

  if printf '%s' "$line" | grep -Eiq 'anonymous'; then
    printf 'anonymous access'
  elif printf '%s' "$line" | grep -Eiq 'ntlm'; then
    printf 'NTLM-related evidence'
  else
    printf 'credential-related keyword'
  fi
}

append_credential_summary_section() {
  local outfile="$1"
  local temp_file
  local file
  local file_label
  local line_number
  local line_text
  local display_value
  local total_count=0
  local max_items=80

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_credentials.XXXXXX")"
  for file in "${NSE_DIR}"/*.txt "${TOOL_DIR}"/*.txt "${MSF_RESULT_DIR}"/*.txt; do
    [[ -s "$file" ]] || continue
    file_label="$(default_result_label "$file")"
    while IFS=$'\034' read -r line_number line_text display_value; do
      [[ -n "${line_text:-}" ]] || continue
      total_count=$((total_count + 1))
      [[ "$total_count" -le "$max_items" ]] || continue
      if [[ -z "$display_value" ]]; then
        display_value="$(credential_display_value "$line_text")"
      fi
      {
        printf '    <li><details class="finding-panel">\n'
        printf '      <summary><span class="finding-severity">Review</span><div><strong>%s</strong><span>%s</span><p>%s:%s</p></div></summary>\n' \
          "$(html_escape_text "$display_value")" \
          "$(html_escape_text "$file_label")" \
          "$(html_escape_text "$file")" \
          "$(html_escape_text "$line_number")"
        printf '      <pre class="finding-evidence">%s</pre>\n' "$(html_escape_text "$line_text")"
        printf '    </details></li>\n'
      } >> "$temp_file"
    done < <(credential_candidate_lines "$file")
  done

  {
    printf '  <h2>Possible Usernames / Credentials</h2>\n'
    if [[ -s "$temp_file" ]]; then
      printf '  <p class="muted">These entries were extracted from tool output using credential-related keywords and username enumeration lists. Usernames alone do not confirm valid credentials; entries should be manually verified.</p>\n'
      printf '  <ul class="finding-list credential-list">\n'
      cat "$temp_file"
      printf '  </ul>\n'
      if [[ "$total_count" -gt "$max_items" ]]; then
        printf '  <p class="muted">Showing first %s of %s possible credential-related line(s).</p>\n' "$max_items" "$total_count"
      fi
    else
      printf '  <div class="empty">No username or credential-related lines were detected in saved result files.</div>\n'
    fi
  } >> "$outfile"

  rm -f "$temp_file"
}

append_per_host_summary_section() {
  local outfile="$1"
  local open_tsv="$2"

  printf '  <h2>Per-Host Summary</h2>\n' >> "$outfile"
  if [[ ! -s "$open_tsv" ]]; then
    printf '  <div class="empty">No per-host open-port summary is available.</div>\n' >> "$outfile"
    return
  fi

  {
    printf '  <div class="host-summary-grid">\n'
    awk -F '\t' '
      NR > 1 {
        host = $1
        entry = $3 "/" toupper($2)
        if (!seen[host, entry]++) {
          ports[host] = ports[host] ? ports[host] ", " entry : entry
        }
      }
      END {
        for (host in ports) {
          print host "\034" ports[host]
        }
      }
    ' "$open_tsv" | sort | while IFS=$'\034' read -r host ports; do
      [[ -n "${host:-}" ]] || continue
      printf '    <details class="artifact host-summary"><summary>%s</summary><pre>%s</pre></details>\n' "$(html_escape_text "$host")" "$(html_escape_text "$ports")"
    done
    printf '  </div>\n'
  } >> "$outfile"
}

normalize_service_name() {
  local proto="$1"
  local port="$2"
  local name="${3:-}"
  local lowered

  lowered="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"

  case "${proto}/${port}" in
    tcp/443|tcp/8443)
      printf 'HTTPS'
      return
      ;;
    tcp/80|tcp/81|tcp/8000|tcp/8080)
      printf 'HTTP'
      return
      ;;
  esac

  case "$lowered" in
    ""|unknown)
      case "${proto}/${port}" in
        tcp/21) printf 'FTP' ;;
        tcp/22) printf 'SSH' ;;
        tcp/23) printf 'Telnet' ;;
        tcp/25|tcp/465|tcp/587) printf 'SMTP' ;;
        tcp/53|udp/53) printf 'DNS' ;;
        tcp/88) printf 'Kerberos' ;;
        tcp/110|tcp/995) printf 'POP3' ;;
        tcp/111|udp/111) printf 'RPCBind' ;;
        tcp/135) printf 'MSRPC' ;;
        udp/123) printf 'NTP' ;;
        udp/137) printf 'NetBIOS' ;;
        tcp/139|tcp/445) printf 'SMB' ;;
        udp/161|udp/162) printf 'SNMP' ;;
        tcp/389|tcp/636|tcp/3268|tcp/3269) printf 'LDAP' ;;
        udp/500) printf 'IKE' ;;
        udp/623) printf 'IPMI' ;;
        tcp/1433) printf 'MSSQL' ;;
        tcp/1521) printf 'Oracle' ;;
        tcp/2049) printf 'NFS' ;;
        tcp/3306) printf 'MySQL' ;;
        tcp/3389) printf 'RDP' ;;
        udp/5060) printf 'SIP' ;;
        tcp/5800|tcp/5801|tcp/5900|tcp/5901) printf 'VNC' ;;
        tcp/8009) printf 'AJP13' ;;
        *) printf 'Unknown' ;;
      esac
      ;;
    ssl\|http|ssl/http|https)
      printf 'HTTPS'
      ;;
    http|http*)
      printf 'HTTP'
      ;;
    ssh)
      printf 'SSH'
      ;;
    ftp)
      printf 'FTP'
      ;;
    smtp)
      printf 'SMTP'
      ;;
    dns|domain)
      printf 'DNS'
      ;;
    ntp)
      printf 'NTP'
      ;;
    snmp|snmptrap)
      printf 'SNMP'
      ;;
    rpcbind)
      printf 'RPCBind'
      ;;
    nfs)
      printf 'NFS'
      ;;
    vnc)
      printf 'VNC'
      ;;
    irc)
      printf 'IRC'
      ;;
    ajp13|ajp)
      printf 'AJP13'
      ;;
    java-rmi)
      printf 'Java-RMI'
      ;;
    ms-sql*|mssql*)
      printf 'MSSQL'
      ;;
    mysql*)
      printf 'MySQL'
      ;;
    netbios*|netbios-ssn)
      printf 'NetBIOS'
      ;;
    microsoft-ds)
      printf 'SMB'
      ;;
    *)
      printf '%s' "$name" | awk '{print toupper(substr($0, 1, 1)) substr($0, 2)}'
      ;;
  esac
}

port_card_label() {
  local proto="$1"
  local port="$2"
  local services_tsv="$3"
  local name=""
  local proto_upper

  proto_upper="$(printf '%s' "$proto" | tr '[:lower:]' '[:upper:]')"
  if [[ -s "$services_tsv" ]]; then
    name="$(awk -F '\t' -v wanted_proto="$proto" -v wanted_port="$port" '
      NR > 1 && $2 == wanted_proto && $3 == wanted_port && $4 != "" {
        print $4
        exit
      }
    ' "$services_tsv")"
  fi

  printf '%s/%s (%s)' "$port" "$proto_upper" "$(normalize_service_name "$proto" "$port" "$name")"
}

append_port_result_files() {
  local outfile="$1"
  local proto="$2"
  local port="$3"
  local appended=1

  case "${proto}/${port}" in
    tcp/21) append_result_file_section "$outfile" s_ftp.txt && appended=0 ;;
    tcp/22)
      append_result_file_section "$outfile" s_ssh.txt && appended=0
      append_result_file_section "$outfile" ssh-audit_results.txt "Weak SSH Ciphers" && appended=0
      ;;
    tcp/23) append_result_file_section "$outfile" s_telnet.txt && appended=0 ;;
    tcp/25) append_result_file_section "$outfile" s_smtp.txt && appended=0 ;;
    tcp/465|tcp/587)
      append_result_file_section "$outfile" s_smtp.txt && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/53|udp/53)
      append_result_file_section "$outfile" s_dns.txt && appended=0
      append_result_file_section "$outfile" dnssec_not_configured.txt && appended=0
      append_result_file_section "$outfile" dns_recursion_enabled.txt && appended=0
      ;;
    tcp/80|tcp/81|tcp/8000|tcp/8080)
      append_result_file_section "$outfile" s_http.txt && appended=0
      ;;
    tcp/443|tcp/8443)
      append_result_file_section "$outfile" s_http.txt "HTTPS NMAP Results" && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/8009) append_result_file_section "$outfile" s_ajp.txt && appended=0 ;;
    tcp/88) append_result_file_section "$outfile" s_kerberos.txt && appended=0 ;;
    tcp/110)
      append_result_file_section "$outfile" s_pop3.txt && appended=0
      ;;
    tcp/995)
      append_result_file_section "$outfile" s_pop3.txt && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/993)
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/111|udp/111) append_result_file_section "$outfile" s_rpcbind.txt && appended=0 ;;
    tcp/135)
      append_result_file_section "$outfile" s_rpcdump_135.txt "Exposed RPC Services" && appended=0
      append_result_file_section "$outfile" s_rpcclient_135.txt "Unauthenticated Remote Procedure Call" && appended=0
      ;;
    udp/123) append_result_file_section "$outfile" s_ntp.txt && appended=0 ;;
    udp/137) append_result_file_section "$outfile" s_netbios.txt && appended=0 ;;
    tcp/139|tcp/445)
      append_result_file_section "$outfile" s_smb.txt && appended=0
      append_result_file_section "$outfile" nxc_smb_signing_false.txt "Misconfigured Server Message Block Signing" && appended=0
      append_result_file_section "$outfile" nxc_smbv1_true.txt "SMBv1 Enabled" && appended=0
      ;;
    udp/161|udp/162) append_result_file_section "$outfile" s_snmp.txt && appended=0 ;;
    tcp/389|tcp/3268)
      append_result_file_section "$outfile" s_ldap.txt && appended=0
      append_result_file_section "$outfile" s_ldapsearch.txt "LDAP Anonymous Bind" && appended=0
      ;;
    tcp/636|tcp/3269)
      append_result_file_section "$outfile" s_ldap.txt && appended=0
      append_result_file_section "$outfile" s_ldapsearch.txt "LDAP Anonymous Bind" && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    udp/500)
      append_result_file_section "$outfile" s_ike.txt && appended=0
      append_result_file_section "$outfile" ike_weak_encryption.txt && appended=0
      ;;
    udp/623) append_result_file_section "$outfile" s_ipmi.txt && appended=0 ;;
    tcp/1433) append_result_file_section "$outfile" db_mssql.txt && appended=0 ;;
    tcp/1521) append_result_file_section "$outfile" s_oracle.txt && appended=0 ;;
    tcp/2049) append_result_file_section "$outfile" s_nfs.txt && appended=0 ;;
    tcp/3306) append_result_file_section "$outfile" db_mysql.txt && appended=0 ;;
    tcp/3389)
      append_result_file_section "$outfile" s_rdp.txt && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    udp/5060) append_result_file_section "$outfile" s_sip.txt && appended=0 ;;
    tcp/5800|tcp/5801|tcp/5900|tcp/5901) append_result_file_section "$outfile" s_vnc.txt && appended=0 ;;
  esac

  append_msf_result_files "$outfile" "$proto" "$port" && appended=0
  [[ "$appended" -eq 0 ]] || append_base_scan_port_evidence "$outfile" "$proto" "$port"
}

generate_html_report() {
  local report_file="report.html"
  local open_tsv="targets_with_open_ports/open_ports_all.tsv"
  local services_tsv="targets_with_open_ports/services.tsv"
  local scope_count=0
  local live_count=0
  local open_rows=0
  local service_rows=0
  local generated_at
  local key
  local proto
  local port
  local previous_key=""
  local previous_proto=""
  local previous_port=""
  local first_group=true
  local display_label=""

  [[ -f "$TARGETS_FILE" ]] && scope_count="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  [[ -f "$LIVE_TARGETS_FILE" ]] && live_count="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  if [[ -f "$open_tsv" ]]; then
    open_rows="$(awk 'NR > 1 {count++} END {print count + 0}' "$open_tsv")"
  fi
  if [[ -f "$services_tsv" ]]; then
    service_rows="$(awk 'NR > 1 {count++} END {print count + 0}' "$services_tsv")"
  fi
  generated_at="$(date '+%Y-%m-%d %H:%M:%S %Z')"

  {
    cat <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bident Scan Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef4ff;
      --bg-accent: #f7fbff;
      --panel: #ffffff;
      --text: #18202a;
      --muted: #657080;
      --line: #cfd9ea;
      --accent: #2457c5;
      --accent-2: #0f9f8f;
      --accent-3: #d97706;
      --chip: #e8f0ff;
      --chip-text: #153f9f;
      --code-bg: #101827;
      --code-text: #e5eefc;
      --shadow: 0 12px 30px rgba(31, 65, 120, 0.10);
    }
    [data-theme="dark"] {
      color-scheme: dark;
      --bg: #0c1220;
      --bg-accent: #111a2d;
      --panel: #151f33;
      --text: #edf4ff;
      --muted: #9fb0c9;
      --line: #2a3954;
      --accent: #6ea8ff;
      --accent-2: #39d5c4;
      --accent-3: #f7b955;
      --chip: #1d345d;
      --chip-text: #bfdbff;
      --code-bg: #070b12;
      --code-text: #e7edf7;
      --shadow: 0 12px 30px rgba(0, 0, 0, 0.28);
    }
    body {
      margin: 0;
      background:
        radial-gradient(circle at top left, color-mix(in srgb, var(--accent) 18%, transparent), transparent 34rem),
        linear-gradient(135deg, var(--bg), var(--bg-accent));
      color: var(--text);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      min-height: 100vh;
    }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    h1, h2, h3 {
      line-height: 1.2;
      margin: 0;
    }
    h1 {
      font-size: 30px;
      margin-bottom: 6px;
    }
    h2 {
      font-size: 20px;
      margin-top: 30px;
      margin-bottom: 12px;
    }
    h3 {
      font-size: 16px;
      margin-bottom: 10px;
    }
    .muted {
      color: var(--muted);
    }
    .report-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 20px;
    }
    .brand {
      align-items: center;
      display: flex;
      gap: 14px;
    }
    .report-mark {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      flex: 0 0 auto;
      height: 72px;
      padding: 8px;
      width: 62px;
    }
    .theme-toggle {
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      color: var(--text);
      cursor: pointer;
      display: inline-flex;
      font-size: 18px;
      height: 42px;
      justify-content: center;
      line-height: 1;
      padding: 0;
      box-shadow: var(--shadow);
      white-space: nowrap;
      width: 42px;
    }
    .theme-toggle:hover {
      border-color: var(--accent);
    }
    .notice {
      background: color-mix(in srgb, var(--accent-3) 12%, var(--panel));
      border: 1px solid color-mix(in srgb, var(--accent-3) 45%, var(--line));
      border-left: 5px solid var(--accent-3);
      border-radius: 8px;
      box-shadow: var(--shadow);
      margin: 24px 0 0;
      padding: 14px 16px;
    }
    .notice strong {
      display: block;
      margin-bottom: 4px;
    }
    .notice p {
      margin: 0;
      color: var(--muted);
    }
    .report-footer {
      border-top: 1px solid var(--line);
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 8px 16px;
      justify-content: space-between;
      margin-top: 28px;
      padding-top: 14px;
      font-size: 12px;
    }
    .report-footer strong {
      color: var(--text);
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 24px 0;
    }
    .metric, .port-card, .artifact, .empty {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .metric {
      padding: 14px 16px;
      border-top: 4px solid var(--accent);
    }
    .metric:nth-child(2) {
      border-top-color: var(--accent-2);
    }
    .metric:nth-child(3) {
      border-top-color: var(--accent-3);
    }
    .metric strong {
      display: block;
      font-size: 26px;
      line-height: 1;
      margin-bottom: 6px;
    }
    .summary-grid {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      margin-bottom: 18px;
    }
    .summary-card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 12px 14px;
    }
    .summary-card span {
      color: var(--muted);
      display: block;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      margin-bottom: 5px;
      text-transform: uppercase;
    }
    .summary-card strong {
      display: block;
      font-size: 14px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .finding-list {
      display: grid;
      gap: 8px;
      list-style: none;
      margin: 0 0 18px;
      padding: 0;
    }
    .finding-list li {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .finding-panel summary {
      align-items: flex-start;
      cursor: pointer;
      display: flex;
      gap: 10px;
      list-style: none;
      padding: 11px 12px;
    }
    .finding-panel summary::-webkit-details-marker {
      display: none;
    }
    .finding-list strong,
    .finding-list span,
    .finding-list p {
      display: block;
    }
    .finding-list span {
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .finding-list p {
      color: var(--muted);
      margin: 5px 0 0;
    }
    .finding-severity {
      background: var(--chip);
      border-radius: 999px;
      color: var(--chip-text) !important;
      flex: 0 0 auto;
      font-size: 11px !important;
      font-weight: 800;
      padding: 2px 8px;
      text-transform: uppercase;
    }
    .finding-evidence {
      border-top: 1px solid var(--line);
      margin: 0;
      max-height: 360px;
      overflow: auto;
      padding: 12px;
      background: var(--code-bg);
      color: var(--code-text);
      font: 12px/1.45 "SFMono-Regular", Consolas, monospace;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .credential-list {
      max-height: 360px;
      overflow: auto;
    }
    .host-summary-grid {
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      margin-bottom: 18px;
    }
    .host-summary {
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .host-summary summary {
      color: var(--accent);
      cursor: pointer;
      font-weight: 800;
      padding: 10px 12px;
    }
    .host-summary pre {
      background: transparent;
      color: var(--text);
      font: 13px/1.5 "SFMono-Regular", Consolas, monospace;
      margin: 0;
      padding: 0 12px 12px;
      white-space: pre-wrap;
    }
    .port-card {
      margin-bottom: 8px;
      overflow: hidden;
    }
    .open-ports-wrap {
      max-height: min(620px, 64vh);
      overflow: auto;
      padding-right: 4px;
    }
    .open-ports-wrap .port-card:last-child {
      margin-bottom: 0;
    }
    .port-summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      cursor: pointer;
      list-style: none;
      padding: 10px 16px;
      min-height: 44px;
      border-left: 4px solid var(--accent);
      transition: background 160ms ease, border-color 160ms ease;
    }
    .port-summary::-webkit-details-marker {
      display: none;
    }
    .port-title {
      display: inline-flex;
      align-items: center;
      gap: 9px;
    }
    .port-chevron {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 20px;
      height: 20px;
      border-radius: 999px;
      background: var(--chip);
      color: var(--chip-text);
      font-size: 15px;
      font-weight: 900;
      line-height: 1;
      transition: transform 160ms ease, background 160ms ease;
    }
    .port-summary strong {
      display: block;
      font-size: 15px;
      line-height: 1.2;
    }
    .port-card[open] .port-summary {
      background: color-mix(in srgb, var(--accent) 10%, transparent);
    }
    .port-card[open] .port-chevron {
      transform: rotate(90deg);
      background: var(--accent);
      color: #06111f;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 8px;
      background: var(--chip);
      color: var(--chip-text);
      font-weight: 700;
      font-size: 11px;
      text-transform: uppercase;
    }
    .targets {
      background: transparent;
      color: var(--text);
      font: 14px/1.65 "SFMono-Regular", Consolas, monospace;
      margin: 0;
      padding: 0 14px 14px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .table-tools {
      display: flex;
      justify-content: flex-end;
      margin: 0 0 10px;
    }
    .service-search {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--text);
      font: inherit;
      max-width: 340px;
      padding: 10px 12px;
      width: 100%;
    }
    .service-search:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
      outline: none;
    }
    .service-table-wrap {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      max-height: min(560px, 58vh);
      overflow: auto;
    }
    .service-table {
      border-collapse: collapse;
      min-width: 860px;
      width: 100%;
    }
    .service-table th,
    .service-table td {
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }
    .service-table tbody tr:last-child td {
      border-bottom: 0;
    }
    .service-table tbody tr:hover {
      background: color-mix(in srgb, var(--accent) 8%, transparent);
    }
    .service-table th {
      background: color-mix(in srgb, var(--panel) 88%, var(--accent));
      box-shadow: 0 1px 0 var(--line);
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .sort-button {
      align-items: center;
      background: transparent;
      border: 0;
      color: var(--text);
      cursor: pointer;
      display: inline-flex;
      font: inherit;
      font-weight: 800;
      gap: 6px;
      padding: 0;
    }
    .sort-button::after {
      color: var(--muted);
      content: "↕";
      font-size: 12px;
    }
    .sort-button[data-direction="asc"]::after {
      color: var(--accent);
      content: "↑";
    }
    .sort-button[data-direction="desc"]::after {
      color: var(--accent);
      content: "↓";
    }
    .service-table td:nth-child(4) {
      color: var(--muted);
      min-width: 240px;
    }
    .service-table td:nth-child(5) {
      font-family: "SFMono-Regular", Consolas, monospace;
      white-space: nowrap;
    }
    .table-tools {
      align-items: end;
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      margin-bottom: 12px;
    }
    .service-search {
      grid-column: 1 / -1;
    }
    .service-filter {
      display: grid;
      gap: 5px;
    }
    .service-filter label {
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .service-filter select,
    .service-search {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--text);
      font: inherit;
      min-width: 0;
      padding: 10px 12px;
    }
    li {
      break-inside: avoid;
    }
    details.artifact {
      overflow: hidden;
      transition: border-color 160ms ease, background 160ms ease;
    }
    details.artifact[open] {
      border-color: color-mix(in srgb, var(--accent) 45%, var(--line));
    }
    details.artifact summary {
      cursor: pointer;
      padding: 12px 14px;
      font-weight: 700;
      color: var(--accent);
      background: color-mix(in srgb, var(--panel) 92%, var(--accent));
    }
    details.artifact[open] summary {
      border-bottom: 1px solid var(--line);
    }
    .artifact-file {
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      margin-left: 8px;
    }
    .target-panel, .result-panel {
      margin: 10px 16px;
    }
    .result-panel + .result-panel {
      margin-top: 12px;
    }
    .target-panel .targets {
      padding-top: 0;
    }
    pre {
      margin: 0;
      padding: 12px;
      max-height: 520px;
      overflow: auto;
      background: var(--code-bg);
      color: var(--code-text);
      font: 12px/1.45 "SFMono-Regular", Consolas, monospace;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .file-list {
      display: block;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      margin: 0;
      padding: 12px;
      font: 14px/1.7 "SFMono-Regular", Consolas, monospace;
      white-space: pre-wrap;
    }
    .file-list a {
      display: block;
    }
    .core-artifacts {
      margin-top: 10px;
    }
    .artifact-group {
      box-shadow: none;
      margin: 10px 14px;
    }
    .artifact-group .file-list {
      border: 0;
      border-radius: 0;
      box-shadow: none;
      margin: 0;
    }
    .empty {
      padding: 14px 16px;
    }
    a {
      color: var(--accent);
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    @media (max-width: 640px) {
      .report-header {
        align-items: stretch;
        flex-direction: column;
      }
      .brand {
        align-items: flex-start;
      }
      .theme-toggle {
        width: 100%;
      }
    }
  </style>
</head>
<body>
<main>
HTML
    printf '  <header class="report-header">\n'
    printf '    <div class="brand">\n'
    printf '      <svg class="report-mark" viewBox="0 0 256 320" role="img" aria-label="Bident logo"><defs><linearGradient id="reportRedSteel" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stop-color="#2a0202"/><stop offset="0.42" stop-color="#7b0d0d"/><stop offset="1" stop-color="#190101"/></linearGradient><linearGradient id="reportHandleSteel" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stop-color="#111318"/><stop offset="0.5" stop-color="#3a3d43"/><stop offset="1" stop-color="#050608"/></linearGradient></defs><path d="M83 292h90l-14-92c28-21 51-58 48-113-2-36-13-66-31-87 2 48-6 91-23 128-9 20-18 34-25 43-7-9-16-23-25-43C86 91 78 48 80 0 62 21 51 51 49 87c-3 55 20 92 48 113L83 292z" fill="#07080b" stroke="#030303" stroke-width="7" stroke-linejoin="round"/><path d="M87 184c-18-16-31-46-27-91 2-21 8-40 18-56-4 36 2 72 16 105 7 17 16 32 26 45-12 1-23 0-33-3z" fill="url(#reportRedSteel)" stroke="#120101" stroke-width="5" stroke-linejoin="round"/><path d="M169 184c18-16 31-46 27-91-2-21-8-40-18-56 4 36-2 72-16 105-7 17-16 32-26 45 12 1 23 0 33-3z" fill="url(#reportRedSteel)" stroke="#120101" stroke-width="5" stroke-linejoin="round"/><path d="M111 300h34l-5-82h-24l-5 82z" fill="url(#reportHandleSteel)" stroke="#030303" stroke-width="6" stroke-linejoin="round"/><path d="M100 204c9 11 19 17 28 17s19-6 28-17c-7 33-16 51-28 51s-21-18-28-51z" fill="#300202" stroke="#090101" stroke-width="5" stroke-linejoin="round"/><g transform="translate(98 194)"><path d="M30 2c18 0 30 14 30 31 0 11-5 18-13 23v17H13V56C5 51 0 44 0 33 0 16 12 2 30 2z" fill="#efefef" stroke="#080808" stroke-width="6" stroke-linejoin="round"/><path d="M14 34c0-6 4-11 10-11 5 0 9 4 9 10 0 7-5 11-11 11-5 0-8-4-8-10z" fill="#050505"/><path d="M36 33c0-6 4-10 9-10 6 0 10 5 10 11 0 6-3 10-8 10-6 0-11-4-11-11z" fill="#050505"/><path d="M30 42l-7 11h14l-7-11z" fill="#050505"/><path d="M18 63h24" fill="none" stroke="#050505" stroke-width="5" stroke-linecap="round"/><path d="M22 57v16M30 56v17M38 57v16" fill="none" stroke="#050505" stroke-width="4" stroke-linecap="round"/></g><path d="M93 292h70" fill="none" stroke="#050505" stroke-width="12" stroke-linecap="round"/></svg>\n'
    printf '      <div>\n'
    printf '        <h1>Bident Scan Report</h1>\n'
    printf '        <p class="muted">Generated %s</p>\n' "$(html_escape_text "$generated_at")"
    printf '      </div>\n'
    printf '    </div>\n'
    printf '    <button class="theme-toggle" type="button" id="themeToggle" aria-label="Toggle dark mode" title="Toggle theme">☾</button>\n'
    printf '  </header>\n'
    printf '  <section class="notice" aria-label="Scan timing">\n'
    printf '    <strong>Scan Timing</strong>\n'
    printf '    <p>Start Time: %s</p>\n' "$(html_escape_text "${SCAN_STARTED_AT:-Unavailable}")"
    printf '    <p>Finish Time: %s</p>\n' "$(html_escape_text "${SCAN_FINISHED_AT:-Unavailable}")"
    printf '    <p>Run Time (HH:MM:SS): %s</p>\n' "$(html_escape_text "${SCAN_RUNTIME:-Unavailable}")"
    printf '  </section>\n'
    printf '  <section class="metrics">\n'
    printf '    <div class="metric"><strong>%s</strong><span>Scoped Hosts/IPs</span></div>\n' "$scope_count"
    printf '    <div class="metric"><strong>%s</strong><span>Live Hosts/IPs</span></div>\n' "$live_count"
    printf '    <div class="metric"><strong>%s</strong><span>Total Ports Open</span></div>\n' "$open_rows"
    printf '  </section>\n'
  } > "$report_file"

  printf '  <h2>Services</h2>\n' >> "$report_file"
  if [[ ! -s "$services_tsv" || "$service_rows" -eq 0 ]]; then
    printf '  <div class="empty">No services were confirmed.</div>\n' >> "$report_file"
  else
    {
      printf '  <div class="table-tools">\n'
      printf '    <input class="service-search" id="serviceSearch" type="search" placeholder="Search services..." aria-label="Search services">\n'
      printf '    <div class="service-filter"><label for="filterHost">Hosts/IPs</label><select id="filterHost" data-column="0"><option value="">All Hosts/IPs</option></select></div>\n'
      printf '    <div class="service-filter"><label for="filterPortProtocol">Port/Protocol</label><select id="filterPortProtocol" data-column="1"><option value="">All Port/Protocol</option></select></div>\n'
      printf '    <div class="service-filter"><label for="filterName">Name</label><select id="filterName" data-column="2"><option value="">All Names</option></select></div>\n'
      printf '    <div class="service-filter"><label for="filterInfo">Info</label><select id="filterInfo" data-column="3"><option value="">All Info</option></select></div>\n'
      printf '  </div>\n'
      printf '  <div class="service-table-wrap">\n'
      printf '    <table class="service-table" id="servicesTable">\n'
      printf '      <thead><tr>\n'
      printf '        <th><button class="sort-button" type="button" data-column="0">Hosts/IPs</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="1">Port/Protocol</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="2">Name</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="3">Info</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="4">Hosts/IPs:Port</button></th>\n'
      printf '      </tr></thead>\n'
      printf '      <tbody>\n'
    } >> "$report_file"
    while IFS=$'\034' read -r target proto port name info target_port; do
      [[ -n "${target:-}" ]] || continue
      printf '        <tr><td>%s</td><td>%s/%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape_text "$target")" \
        "$(html_escape_text "$port")" \
        "$(html_escape_text "$proto")" \
        "$(html_escape_text "$(normalize_service_name "$proto" "$port" "$name")")" \
        "$(html_escape_text "$info")" \
        "$(html_escape_text "$target_port")" >> "$report_file"
    done < <(awk -F '\t' 'NR > 1 {print $1 "\034" $2 "\034" $3 "\034" $4 "\034" $5 "\034" $6}' "$services_tsv")
    {
      printf '      </tbody>\n'
      printf '    </table>\n'
      printf '  </div>\n'
    } >> "$report_file"
  fi

  printf '  <h2>Open Ports Found</h2>\n' >> "$report_file"

  if [[ ! -s "$open_tsv" || "$open_rows" -eq 0 ]]; then
    printf '  <div class="empty">No open ports were confirmed.</div>\n' >> "$report_file"
  else
    printf '  <div class="open-ports-wrap">\n' >> "$report_file"
    while IFS=$'\t' read -r proto port target; do
      key="${proto}/${port}"
      if [[ "$key" != "$previous_key" ]]; then
        if [[ "$first_group" == false ]]; then
          printf '      </pre>\n' >> "$report_file"
          printf '      </details>\n' >> "$report_file"
          append_port_result_files "$report_file" "$previous_proto" "$previous_port"
          printf '    </details>\n' >> "$report_file"
        fi
        first_group=false
        previous_key="$key"
        previous_proto="$proto"
        previous_port="$port"
        display_label="$(port_card_label "$proto" "$port" "$services_tsv")"
        printf '    <details class="port-card" name="open-port">\n' >> "$report_file"
        printf '      <summary class="port-summary"><span class="port-title"><span class="port-chevron" aria-hidden="true">›</span><strong>%s</strong></span><span class="badge">%s</span></summary>\n' \
          "$(html_escape_text "$display_label")" "$(html_escape_text "$proto")" >> "$report_file"
        printf '      <details class="artifact target-panel">\n' >> "$report_file"
        printf '      <summary>Hosts/IPs</summary>\n' >> "$report_file"
        printf '      <pre class="targets">' >> "$report_file"
      fi
      printf '%s:%s\n' "$(html_escape_text "$target")" "$(html_escape_text "$port")" >> "$report_file"
    done < <(awk -F '\t' 'NR > 1 {print $2 "\t" $3 "\t" $1}' "$open_tsv" | sort -k2,2n -k1,1 -k3,3)

    if [[ "$first_group" == false ]]; then
      printf '      </pre>\n' >> "$report_file"
      printf '      </details>\n' >> "$report_file"
      append_port_result_files "$report_file" "$previous_proto" "$previous_port"
      printf '    </details>\n' >> "$report_file"
    fi
    printf '  </div>\n' >> "$report_file"
  fi

  append_nse_status_section "$report_file"
  append_findings_summary_section "$report_file"
  append_credential_summary_section "$report_file"

  {
    printf '  <h2>Core Artifacts</h2>\n'
    printf '  <details class="artifact core-artifacts">\n'
    printf '    <summary>Core Artifacts</summary>\n'
  } >> "$report_file"
  append_core_artifact_group "$report_file" "Targets" \
    "$TARGETS_FILE" "$LIVE_TARGETS_FILE"
  append_core_artifact_group "$report_file" "Base Scan Outputs" \
    "${SCAN_DIR}/syn.nmap" "${SCAN_DIR}/con.nmap" "${SCAN_DIR}/udp.nmap" \
    "${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap" \
    "${SCAN_DIR}/syn.xml" "${SCAN_DIR}/con.xml" "${SCAN_DIR}/udp.xml"
  append_core_artifact_group "$report_file" "Open Port Tables" \
    targets_with_open_ports/services.tsv \
    targets_with_open_ports/open_ports_all.tsv \
    targets_with_open_ports/open_ports_mentioned.tsv \
    targets_with_open_ports/open_ports_by_target.txt
  append_core_artifact_group "$report_file" "Nmap Script Results" \
    "${NSE_DIR}"/*.txt
  append_core_artifact_group "$report_file" "External Tool Results" \
    "${TOOL_DIR}"/*.txt
  if [[ "${NO_MSF:-false}" != true ]]; then
    append_core_artifact_group "$report_file" "Metasploit Results" \
      "${MSF_DIR}/metasploit_auxiliary.rc" \
      "${MSF_DIR}"/metasploit_auxiliary_*.rc \
      "${MSF_DIR}/msfconsole.log"
  fi
  {
    printf '  </details>\n'
    printf '  <section class="notice">\n'
    printf '    <strong>Disclaimer</strong>\n'
    printf '    <p>Some findings may be false positives and should be manually validated before action is taken. Use this tool only for authorized and legal security testing. The owner of this script is not liable for illegal, unauthorized, or harmful use.</p>\n'
    printf '  </section>\n'
    printf '  <footer class="report-footer">\n'
    printf '    <span><strong>Bident</strong> Network VAPT Toolkit</span>\n'
    printf '    <span>Generated %s</span>\n' "$(html_escape_text "$generated_at")"
    printf '  </footer>\n'
    cat <<'HTML'
</main>
<script>
  const root = document.documentElement;
  const toggle = document.getElementById('themeToggle');
  const savedTheme = localStorage.getItem('bident-theme') || 'light';

  function setTheme(theme) {
    root.dataset.theme = theme;
    toggle.textContent = theme === 'dark' ? '☀' : '☾';
    toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    localStorage.setItem('bident-theme', theme);
  }

  setTheme(savedTheme);

  toggle.addEventListener('click', () => {
    setTheme(root.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  const serviceSearch = document.getElementById('serviceSearch');
  const servicesTable = document.getElementById('servicesTable');

  if (serviceSearch && servicesTable) {
    const tableBody = servicesTable.tBodies[0];
    const rows = Array.from(tableBody.rows);
    const serviceFilters = Array.from(document.querySelectorAll('.service-filter select'));

    function sortServices(column, direction) {
      const sortedRows = rows.slice().sort((a, b) => {
        const first = a.cells[column].textContent.trim();
        const second = b.cells[column].textContent.trim();
        let result;

        if (column === 1) {
          result = Number.parseInt(first, 10) - Number.parseInt(second, 10);
          if (result === 0) {
            result = first.localeCompare(second, undefined, { numeric: true, sensitivity: 'base' });
          }
        } else {
          result = first.localeCompare(second, undefined, { numeric: true, sensitivity: 'base' });
        }

        return direction === 'asc' ? result : -result;
      });

      sortedRows.forEach((row) => tableBody.appendChild(row));
    }

    function filterServices() {
      const query = serviceSearch.value.trim().toLowerCase();
      rows.forEach((row) => {
        const matchesSearch = row.textContent.toLowerCase().includes(query);
        const matchesFilters = serviceFilters.every((filter) => {
          if (!filter.value) {
            return true;
          }
          const column = Number(filter.dataset.column);
          return row.cells[column].textContent.trim() === filter.value;
        });
        row.style.display = matchesSearch && matchesFilters ? '' : 'none';
      });
    }

    function populateServiceFilters() {
      serviceFilters.forEach((filter) => {
        const column = Number(filter.dataset.column);
        const values = Array.from(new Set(rows.map((row) => row.cells[column].textContent.trim()).filter(Boolean)))
          .sort((first, second) => first.localeCompare(second, undefined, { numeric: true, sensitivity: 'base' }));
        values.forEach((value) => {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = value;
          filter.appendChild(option);
        });
        filter.addEventListener('change', filterServices);
      });
    }

    serviceSearch.addEventListener('input', filterServices);
    populateServiceFilters();

    servicesTable.querySelectorAll('.sort-button').forEach((button) => {
      button.addEventListener('click', () => {
        const column = Number(button.dataset.column);
        const nextDirection = button.dataset.direction === 'asc' ? 'desc' : 'asc';

        servicesTable.querySelectorAll('.sort-button').forEach((other) => {
          if (other !== button) {
            other.removeAttribute('data-direction');
          }
        });
        button.dataset.direction = nextDirection;

        sortServices(column, nextDirection);
      });
    });

    const portProtocolSort = servicesTable.querySelector('.sort-button[data-column="1"]');
    if (portProtocolSort) {
      portProtocolSort.dataset.direction = 'asc';
      sortServices(1, 'asc');
    }
  }

  document.querySelectorAll('details.port-card').forEach((details) => {
    details.addEventListener('toggle', () => {
      if (!details.open) {
        return;
      }
      document.querySelectorAll('details.port-card[open]').forEach((other) => {
        if (other !== details) {
          other.open = false;
        }
      });
    });
  });
</script>
</body>
</html>
HTML
  } >> "$report_file"

  printf '%sWrote HTML Report:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$report_file"
}
