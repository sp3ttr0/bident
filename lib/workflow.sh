main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f)
        [[ -n "${2:-}" ]] || die "-f requires a scope file"
        SCOPE_FILE="$2"
        shift 2
        ;;
      -t)
        [[ -n "${2:-}" ]] || die "-t requires a target"
        SINGLE_TARGET="$2"
        shift 2
        ;;
      -p-)
        PORT_FLAG="-p-"
        shift
        ;;
      --no-udp)
        NO_UDP=true
        shift
        ;;
      --responder)
        RUN_RESPONDER=true
        shift
        ;;
      -o|--output-dir|--results-dir)
        [[ -n "${2:-}" ]] || die "$1 requires a results directory"
        RESULTS_DIR="$2"
        shift 2
        ;;
      -T[1-5])
        TIMING="${1#-}"
        shift
        ;;
      -T)
        [[ -n "${2:-}" ]] || die "-T requires a value from 1 to 5"
        case "$2" in
          [1-5])
            TIMING="T$2"
            ;;
          T[1-5])
            TIMING="$2"
            ;;
          -T[1-5])
            TIMING="${2#-}"
            ;;
          *)
            die "Invalid timing value: $2. Use -T1 through -T5"
            ;;
        esac
        shift 2
        ;;
      --speed|--timing)
        [[ -n "${2:-}" ]] || die "$1 requires a value from 1 to 5"
        case "$2" in
          [1-5])
            TIMING="T$2"
            ;;
          T[1-5])
            TIMING="$2"
            ;;
          -T[1-5])
            TIMING="${2#-}"
            ;;
          *)
            die "Invalid timing value: $2. Use 1 through 5"
            ;;
        esac
        shift 2
        ;;
      -*)
        die "Unknown option: $1"
        ;;
      *)
        die "Unexpected positional argument: $1"
        ;;
    esac
  done
  
  if [[ -z "$SCOPE_FILE" && -z "$SINGLE_TARGET" ]]; then
    die "Missing target input: use -f <scope-file> or -t <target>"
  fi
  
  if [[ -n "$SCOPE_FILE" && -n "$SINGLE_TARGET" ]]; then
    die "Use either -f <scope-file> or -t <target>, not both"
  fi
  
  case "$TIMING" in
    T[1-5])
      ;;
    [1-5])
      TIMING="T$TIMING"
      ;;
    -T[1-5])
      TIMING="${TIMING#-}"
      ;;
    *)
      die "Invalid timing value: $TIMING. Use -T1 through -T5"
      ;;
  esac
  
  print_banner
  printf '%sTiming Template:%s -%s\n' "$CLR_CYAN" "$CLR_RESET" "$TIMING"
  
  need_command awk
  need_command cat
  need_command cp
  need_command date
  need_command grep
  need_command mktemp
  need_command mkdir
  need_command nmap
  need_command rm
  need_command screen
  need_command sort
  if [[ "$RUN_RESPONDER" == true ]]; then
    need_command responder
  fi
  
  require_root
  trap confirm_cancel INT
  
  if [[ -n "$SCOPE_FILE" ]]; then
    [[ -f "$SCOPE_FILE" ]] || die "Scope file not found: $SCOPE_FILE"
    [[ -s "$SCOPE_FILE" ]] || die "Scope file is empty: $SCOPE_FILE"
  fi
  
  if [[ -z "$RESULTS_DIR" ]]; then
    RESULTS_DIR="bident_results_$(date '+%Y%m%d_%H%M%S')"
  fi
  
  mkdir -p "$RESULTS_DIR"
  printf '%sResults Folder:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$RESULTS_DIR"
  
  if [[ -n "$SCOPE_FILE" ]]; then
    ORIGINAL_SCOPE_FILE="$SCOPE_FILE"
    SCOPE_BASENAME="${SCOPE_FILE##*/}"
    cp "$ORIGINAL_SCOPE_FILE" "${RESULTS_DIR}/${SCOPE_BASENAME}"
    printf '%sCopied Scope File:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "${RESULTS_DIR}/${SCOPE_BASENAME}"
  else
    SCOPE_BASENAME="single_target_scope.txt"
    printf '%s\n' "$SINGLE_TARGET" > "${RESULTS_DIR}/${SCOPE_BASENAME}"
    printf '%sWrote Single Target Scope File:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "${RESULTS_DIR}/${SCOPE_BASENAME}"
  fi
  
  cd "$RESULTS_DIR"
  SCOPE_FILE="$SCOPE_BASENAME"
  mkdir -p "$SCAN_DIR" "$NSE_DIR" "$TOOL_DIR" "$LOG_DIR"
  
  if [[ "$RUN_RESPONDER" == true ]]; then
    ensure_screen_sessions_available responder
    start_responder
  fi
  
  printf '%sExpanding Scope From:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$SCOPE_FILE"
  nmap -sL -n "-${TIMING}" -iL "$SCOPE_FILE" \
    | awk '/Nmap scan report for/ {print $NF}' \
    | sort -u \
    > "$TARGETS_FILE"
  
  if [[ ! -s "$TARGETS_FILE" ]]; then
    die "No scoped targets found; ${TARGETS_FILE} was not created with any hosts"
  fi
  
  target_count="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  printf '\n%sTotal Hosts/IPs To Scan:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$target_count"
  printf '%sScoped Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$TARGETS_FILE"
  
  printf '%sDiscovering Live Hosts From:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$TARGETS_FILE"
  : > "$LIVE_TARGETS_FILE"
  nmap -sn -n --reason "-${TIMING}" -iL "$TARGETS_FILE" 2>&1 \
    | awk '
        /Nmap scan report for/ {
          ip = $NF
        }
        /Host is up/ {
          print ip >> live_targets_file
          fflush(live_targets_file)
        }
      ' live_targets_file="$LIVE_TARGETS_FILE"
  
  if [[ ! -s "$LIVE_TARGETS_FILE" ]]; then
    printf '\n%sNo Live Hosts/IPs Was Found.%s\n' "$CLR_YELLOW" "$CLR_RESET"
    printf '%sLive Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$LIVE_TARGETS_FILE"
    printf '%sNothing More To Scan. Exiting.%s\n' "$CLR_YELLOW" "$CLR_RESET"
    printf '%sScan Completed.%s\n' "$CLR_GREEN" "$CLR_RESET"
    exit 0
  fi
  
  live_target_count="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  printf '\n%sTotal Live Hosts/IPs:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$live_target_count"
  printf '%sLive Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$LIVE_TARGETS_FILE"
  printf '%sLive Hosts/IPs:%s\n' "$CLR_CYAN" "$CLR_RESET"
  awk '{print "  " $0}' "$LIVE_TARGETS_FILE"
  if [[ -n "$PORT_FLAG" ]]; then
    printf '%sPort Mode:%s All Ports (-p- Enabled)\n' "$CLR_CYAN" "$CLR_RESET"
  else
    printf '%sPort Mode:%s Default Nmap Ports (-p- Disabled)\n' "$CLR_CYAN" "$CLR_RESET"
  fi
  if [[ "$NO_UDP" == true ]]; then
    printf '%sUDP Mode:%s Disabled (--no-udp Enabled)\n' "$CLR_CYAN" "$CLR_RESET"
  else
    printf '%sUDP Mode:%s Enabled\n' "$CLR_CYAN" "$CLR_RESET"
  fi
  
  BASE_SCAN_SESSIONS=(syn con)
  BASE_SCAN_OUTPUTS=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap")
  if [[ "$NO_UDP" != true ]]; then
    BASE_SCAN_SESSIONS+=(udp)
    BASE_SCAN_OUTPUTS+=("${SCAN_DIR}/udp.gnmap")
  fi
  
  ensure_screen_sessions_available "${BASE_SCAN_SESSIONS[@]}"
  
  start_screen_scan "syn" \
    "nmap -sV -sS -v --reason ${PORT_FLAG} --min-rate ${MIN_RATE} -${TIMING} -oA ${SCAN_DIR}/syn -iL ${LIVE_TARGETS_FILE} --open"
  
  start_screen_scan "con" \
    "nmap -sV -sT -v --reason ${PORT_FLAG} --min-rate ${MIN_RATE} -${TIMING} -oA ${SCAN_DIR}/con -iL ${LIVE_TARGETS_FILE} --open"
  
  if [[ "$NO_UDP" != true ]]; then
    start_screen_scan "udp" \
      "nmap -n -sUV --version-intensity 1 -v --reason --max-rtt-timeout=100ms --max-retries=0 --min-rate ${MIN_RATE} -${TIMING} ${PORT_FLAG} -oA ${SCAN_DIR}/udp -iL ${LIVE_TARGETS_FILE} --open"
  fi
  
  printf '\n%sBase Scan Sessions Were Launched.%s\n' "$CLR_GREEN" "$CLR_RESET"
  printf '\n%sUseful Monitor Commands:%s\n' "$CLR_CYAN" "$CLR_RESET"
  printf '  sudo screen -ls\n'
  printf '  sudo screen -r syn\n'
  printf '  sudo screen -r con\n'
  if [[ "$NO_UDP" != true ]]; then
    printf '  sudo screen -r udp\n'
    printf '\n%sScreen Logs:%s %s/syn.screen.log, %s/con.screen.log, %s/udp.screen.log\n' "$CLR_CYAN" "$CLR_RESET" "$LOG_DIR" "$LOG_DIR" "$LOG_DIR"
  else
    printf '\n%sScreen Logs:%s %s/syn.screen.log, %s/con.screen.log\n' "$CLR_CYAN" "$CLR_RESET" "$LOG_DIR" "$LOG_DIR"
  fi
  if [[ "$RUN_RESPONDER" == true ]]; then
    printf '  sudo screen -r responder\n'
  fi
  printf '\n%sDetach From A Screen Session With:%s Ctrl-a Then d\n' "$CLR_CYAN" "$CLR_RESET"
  
  wait_for_screen_scans "${BASE_SCAN_SESSIONS[@]}"
  
  for base_output in "${BASE_SCAN_OUTPUTS[@]}"; do
    [[ -f "$base_output" ]] || die "Expected base scan output not found: $base_output"
  done
  
  generate_open_port_reports
  
  printf '\n%sBase Scans Finished:%s Starting Conditional NSE Stage...\n' "$CLR_GREEN" "$CLR_RESET"
  
  run_if_open "FTP NSE" tcp "21" \
    nmap -n -sV "-${TIMING}" --script 'ftp-*' -p 21 -oN ${NSE_DIR}/s_ftp.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "SSH NSE" tcp "22" \
    nmap -n -sV "-${TIMING}" --script 'ssh*' -p 22 -oN ${NSE_DIR}/s_ssh.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_ssh_audit_check
  
  run_if_open "Telnet NSE" tcp "23" \
    nmap -n -sV "-${TIMING}" --script '*telnet*' -p 23 -oN ${NSE_DIR}/s_telnet.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "SMTP NSE" tcp "25,465,587" \
    nmap -n -sV "-${TIMING}" --script 'smtp-*' -p 25,465,587 -oN ${NSE_DIR}/s_smtp.txt -iL "$LIVE_TARGETS_FILE" --open
  
  if [[ "$NO_UDP" == true ]]; then
    run_if_open "DNS NSE" tcp "53" \
      nmap -n -sS -sV "-${TIMING}" --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' -p 53 -oN ${NSE_DIR}/s_dns.txt -iL "$LIVE_TARGETS_FILE" --open
  else
    run_if_open "DNS NSE" any "53" \
      nmap -n -sS -sU -sV "-${TIMING}" --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' -p 53 -oN ${NSE_DIR}/s_dns.txt -iL "$LIVE_TARGETS_FILE" --open
  fi
  
  run_dns_dig_checks
  
  run_if_open "HTTP/HTTPS NSE" tcp "80,81,443,8000,8080,8443" \
    nmap -n -sV "-${TIMING}" --script '(http* or ssl*) and not (dos or http-slowloris*)' -p 80,81,443,8000,8080,8443 -oN ${NSE_DIR}/s_http.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "AJP NSE" tcp "8009" \
    nmap -n -sV "-${TIMING}" --script 'ajp-*' -p 8009 -oN ${NSE_DIR}/s_ajp.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "SSL/TLS NSE" tcp "443,465,587,636,993,995,3269,3389,8443" \
    nmap -n -sV "-${TIMING}" --script 'ssl-*' -oN ${NSE_DIR}/ssl_tls_results.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_ssl_external_checks
  
  run_if_open "Kerberos NSE" tcp "88" \
    nmap -n -sV "-${TIMING}" --script krb5-enum-users -p 88 -oN ${NSE_DIR}/s_kerberos.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "POP3 NSE" tcp "110,995" \
    nmap -n -sV "-${TIMING}" --script 'pop3-capabilities or pop3-ntlm-info' -p 110,995 -oN ${NSE_DIR}/s_pop3.txt -iL "$LIVE_TARGETS_FILE" --open
  
  if [[ "$NO_UDP" == true ]]; then
    run_if_open "RPCBind NSE" tcp "111" \
      nmap -n -sV -sS "-${TIMING}" -p 111 -oN ${NSE_DIR}/s_rpcbind.txt -iL "$LIVE_TARGETS_FILE" --open
  else
    run_if_open "RPCBind NSE" any "111" \
      nmap -n -sV -sSUC "-${TIMING}" -p 111 -oN ${NSE_DIR}/s_rpcbind.txt -iL "$LIVE_TARGETS_FILE" --open
  fi
  
  run_rpc_135_checks
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "NTP NSE" udp "123" \
      nmap -n -sU -sV "-${TIMING}" --script 'ntp* and (discovery or vuln) and not (dos or brute)' -p 123 -oN ${NSE_DIR}/s_ntp.txt -iL "$LIVE_TARGETS_FILE" --open
  
    run_if_open "NetBIOS NSE" udp "137" \
      nmap -n -sU -sV "-${TIMING}" --script nbstat -p 137 -oN ${NSE_DIR}/s_netbios.txt -iL "$LIVE_TARGETS_FILE" --open
  fi
  
  run_if_open "SMB NSE" tcp "139,445" \
    nmap -n -sV "-${TIMING}" --script 'smb-vuln*,smb-enum*,smb-protocols,smb-security-mode,smb2-security-mode' -p 139,445 -oN ${NSE_DIR}/s_smb.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_smb_external_checks
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "SNMP NSE" udp "161,162" \
      nmap -n -sUV "-${TIMING}" --script 'snmp-*' -p 161,162 -oN ${NSE_DIR}/s_snmp.txt -iL "$LIVE_TARGETS_FILE" --open
  fi
  
  run_if_open "LDAP NSE" tcp "389,636,3268,3269" \
    nmap -n -sV "-${TIMING}" --script 'ldap* and not brute' -p 389,636,3268,3269 -oN ${NSE_DIR}/s_ldap.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_ldapsearch_checks
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "IKE scan" udp "500" \
      nmap -n -sUV "-${TIMING}" -p 500 -oN ${NSE_DIR}/s_ike.txt -iL "$LIVE_TARGETS_FILE" --open
  
    run_ike_weak_encryption_check
  
    run_if_open "IPMI NSE" udp "623" \
      nmap -n -sV "-${TIMING}" --script 'ipmi-*' -p 623 -oN ${NSE_DIR}/s_ipmi.txt -iL "$LIVE_TARGETS_FILE" --open
  fi
  
  run_if_open "MSSQL NSE" tcp "1433" \
    nmap -n -sV "-${TIMING}" --script ms-sql-info,ms-sql-empty-password,ms-sql-brute,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -p 1433 -oN ${NSE_DIR}/db_mssql.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "Oracle NSE" tcp "1521" \
    nmap -n -sV "-${TIMING}" --script oracle-tns-version,oracle-sid-brute -p 1521 -oN ${NSE_DIR}/s_oracle.txt -iL "$LIVE_TARGETS_FILE"
  
  run_if_open "NFS NSE" tcp "2049" \
    nmap -n -sV "-${TIMING}" --script nfs-ls,nfs-showmount,nfs-statfs -p 2049 -oN ${NSE_DIR}/s_nfs.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "MySQL NSE" tcp "3306" \
    nmap -n -sV "-${TIMING}" --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p 3306 -oN ${NSE_DIR}/db_mysql.txt -iL "$LIVE_TARGETS_FILE" --open
  
  run_if_open "RDP NSE" tcp "3389" \
    nmap -n -sV "-${TIMING}" --script 'rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info' -p 3389 -oN ${NSE_DIR}/s_rdp.txt -iL "$LIVE_TARGETS_FILE" --open
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "SIP NSE" udp "5060" \
      nmap -n -sU -sV "-${TIMING}" --script 'sip-*' -p 5060 -oN ${NSE_DIR}/s_sip.txt -iL "$LIVE_TARGETS_FILE" --open
  fi
  
  run_if_open "VNC NSE" tcp "5800,5801,5900,5901" \
    nmap -n -sV "-${TIMING}" --script 'vnc-*' -p 5800,5801,5900,5901 -oN ${NSE_DIR}/s_vnc.txt -iL "$LIVE_TARGETS_FILE" --open
  
  generate_html_report
  
  printf '\n%sConditional NSE Stage Finished.%s\n' "$CLR_GREEN" "$CLR_RESET"
  printf '%sScan Completed.%s\n' "$CLR_GREEN" "$CLR_RESET"
  exit 0
  
}
