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
          lower == "vnc") {
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

  resolved_file="$(resolve_result_file "$result_file")" || return 0
  result_name="${resolved_file##*/}"

  {
    printf '<details class="artifact result-panel">\n'
    if [[ "$result_label" == "$result_name" ]]; then
      printf '<summary>%s</summary>\n' "$(html_escape_text "$resolved_file")"
    else
      printf '<summary>%s <span class="artifact-file">%s</span></summary>\n' "$(html_escape_text "$result_label")" "$(html_escape_text "$resolved_file")"
    fi
    printf '<pre>'
    html_escape_file "$resolved_file"
    printf '</pre>\n'
    printf '</details>\n'
  } >> "$outfile"
}

append_ssl_external_result_files() {
  local outfile="$1"

  append_result_file_section "$outfile" testssl_results.txt
  append_result_file_section "$outfile" sslscan_results.txt
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

  [[ "${NO_MSF:-false}" == true ]] && return

  for result_file in "${MSF_RESULT_DIR}/"*"_${proto}_${port}.txt"; do
    [[ -s "$result_file" ]] || continue
    append_result_file_section "$outfile" "$result_file"
  done
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
        tcp/8009) printf 'AJP' ;;
        *) printf 'Unknown' ;;
      esac
      ;;
    ssl\|http|ssl/http|https)
      printf 'HTTPS'
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

  case "${proto}/${port}" in
    tcp/21) append_result_file_section "$outfile" s_ftp.txt ;;
    tcp/22)
      append_result_file_section "$outfile" s_ssh.txt
      append_result_file_section "$outfile" ssh-audit_results.txt "Weak SSH Ciphers"
      ;;
    tcp/23) append_result_file_section "$outfile" s_telnet.txt ;;
    tcp/25) append_result_file_section "$outfile" s_smtp.txt ;;
    tcp/465|tcp/587)
      append_result_file_section "$outfile" s_smtp.txt
      append_result_file_section "$outfile" ssl_tls_results.txt
      append_ssl_external_result_files "$outfile"
      ;;
    tcp/53|udp/53)
      append_result_file_section "$outfile" s_dns.txt
      append_result_file_section "$outfile" dnssec_not_configured.txt
      append_result_file_section "$outfile" dns_recursion_enabled.txt
      ;;
    tcp/80|tcp/81|tcp/8000|tcp/8080)
      append_result_file_section "$outfile" s_http.txt
      ;;
    tcp/443|tcp/8443)
      append_result_file_section "$outfile" s_http.txt "HTTPS NMAP Results"
      append_result_file_section "$outfile" ssl_tls_results.txt
      append_ssl_external_result_files "$outfile"
      ;;
    tcp/8009) append_result_file_section "$outfile" s_ajp.txt ;;
    tcp/88) append_result_file_section "$outfile" s_kerberos.txt ;;
    tcp/110)
      append_result_file_section "$outfile" s_pop3.txt
      ;;
    tcp/995)
      append_result_file_section "$outfile" s_pop3.txt
      append_result_file_section "$outfile" ssl_tls_results.txt
      append_ssl_external_result_files "$outfile"
      ;;
    tcp/993)
      append_result_file_section "$outfile" ssl_tls_results.txt
      append_ssl_external_result_files "$outfile"
      ;;
    tcp/111|udp/111) append_result_file_section "$outfile" s_rpcbind.txt ;;
    tcp/135)
      append_result_file_section "$outfile" s_rpcdump_135.txt "Exposed RPC Services"
      append_result_file_section "$outfile" s_rpcclient_135.txt "Unauthenticated Remote Procedure Call"
      ;;
    udp/123) append_result_file_section "$outfile" s_ntp.txt ;;
    udp/137) append_result_file_section "$outfile" s_netbios.txt ;;
    tcp/139|tcp/445)
      append_result_file_section "$outfile" s_smb.txt
      append_result_file_section "$outfile" nxc_smb_signing_false.txt "Misconfigured Server Message Block Signing"
      append_result_file_section "$outfile" nxc_smbv1_true.txt "SMBv1 Enabled"
      ;;
    udp/161|udp/162) append_result_file_section "$outfile" s_snmp.txt ;;
    tcp/389|tcp/3268)
      append_result_file_section "$outfile" s_ldap.txt
      append_result_file_section "$outfile" s_ldapsearch.txt "LDAP Anonymous Bind"
      ;;
    tcp/636|tcp/3269)
      append_result_file_section "$outfile" s_ldap.txt
      append_result_file_section "$outfile" s_ldapsearch.txt "LDAP Anonymous Bind"
      append_result_file_section "$outfile" ssl_tls_results.txt
      append_ssl_external_result_files "$outfile"
      ;;
    udp/500)
      append_result_file_section "$outfile" s_ike.txt
      append_result_file_section "$outfile" ike_weak_encryption.txt
      ;;
    udp/623) append_result_file_section "$outfile" s_ipmi.txt ;;
    tcp/1433) append_result_file_section "$outfile" db_mssql.txt ;;
    tcp/1521) append_result_file_section "$outfile" s_oracle.txt ;;
    tcp/2049) append_result_file_section "$outfile" s_nfs.txt ;;
    tcp/3306) append_result_file_section "$outfile" db_mysql.txt ;;
    tcp/3389)
      append_result_file_section "$outfile" s_rdp.txt
      append_result_file_section "$outfile" ssl_tls_results.txt
      append_ssl_external_result_files "$outfile"
      ;;
    udp/5060) append_result_file_section "$outfile" s_sip.txt ;;
    tcp/5800|tcp/5801|tcp/5900|tcp/5901) append_result_file_section "$outfile" s_vnc.txt ;;
  esac

  append_msf_result_files "$outfile" "$proto" "$port"
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
    .port-card {
      margin-bottom: 14px;
      overflow: hidden;
    }
    .port-summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      cursor: pointer;
      list-style: none;
      padding: 18px 20px;
      min-height: 64px;
      border-left: 5px solid var(--accent);
      transition: background 160ms ease, border-color 160ms ease;
    }
    .port-summary::-webkit-details-marker {
      display: none;
    }
    .port-title {
      display: inline-flex;
      align-items: center;
      gap: 10px;
    }
    .port-chevron {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 24px;
      height: 24px;
      border-radius: 999px;
      background: var(--chip);
      color: var(--chip-text);
      font-size: 18px;
      font-weight: 900;
      line-height: 1;
      transition: transform 160ms ease, background 160ms ease;
    }
    .port-summary strong {
      display: block;
      font-size: 16px;
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
      padding: 3px 9px;
      background: var(--chip);
      color: var(--chip-text);
      font-weight: 700;
      font-size: 12px;
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
      position: sticky;
      top: 0;
      z-index: 1;
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
    printf '  <section class="metrics">\n'
    printf '    <div class="metric"><strong>%s</strong><span>Scoped hosts</span></div>\n' "$scope_count"
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
        "$(html_escape_text "$name")" \
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
  fi

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
