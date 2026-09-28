has_open_port() {
  local proto="$1"
  shift
  local files=()
  local file
  local port

  case "$proto" in
    tcp)
      files=(syn.gnmap con.gnmap)
      ;;
    udp)
      files=(udp.gnmap)
      ;;
    any)
      files=(syn.gnmap con.gnmap udp.gnmap)
      ;;
    *)
      die "Unknown protocol for port check: $proto"
      ;;
  esac

  for port in "$@"; do
    for file in "${files[@]}"; do
      [[ -s "$file" ]] || continue
      if awk -v wanted_port="$port" -v wanted_proto="$proto" '
        /Ports: / {
          ports = $0
          sub(/^.*Ports: /, "", ports)
          count = split(ports, entries, ", ")
          for (i = 1; i <= count; i++) {
            split(entries[i], fields, "/")
            if (fields[1] == wanted_port && fields[2] == "open" &&
                (wanted_proto == "any" || fields[3] == wanted_proto)) {
              found = 1
            }
          }
        }
        END {
          if (found) {
            exit 0
          }
          exit 1
        }
      ' "$file"; then
        return 0
      fi
    done
  done

  return 1
}

has_any_open_port() {
  local file

  for file in syn.gnmap con.gnmap udp.gnmap; do
    [[ -s "$file" ]] || continue
    if awk '
      /Ports: / {
        ports = $0
        sub(/^.*Ports: /, "", ports)
        count = split(ports, entries, ", ")
        for (i = 1; i <= count; i++) {
          split(entries[i], fields, "/")
          if (fields[2] == "open") {
            found = 1
          }
        }
      }
      END {
        if (found) {
          exit 0
        }
        exit 1
      }
    ' "$file"; then
      return 0
    fi
  done

  return 1
}

open_target_ports() {
  local proto="$1"
  shift
  local files=()
  local file
  local port_args

  case "$proto" in
    tcp)
      files=(syn.gnmap con.gnmap)
      ;;
    udp)
      files=(udp.gnmap)
      ;;
    any)
      files=(syn.gnmap con.gnmap udp.gnmap)
      ;;
    *)
      die "Unknown protocol for target-port extraction: $proto"
      ;;
  esac

  port_args="$*"
  for file in "${files[@]}"; do
    [[ -s "$file" ]] || continue
    awk -v wanted_proto="$proto" -v wanted_ports="$port_args" '
      BEGIN {
        split(wanted_ports, raw_ports, " ")
        for (i in raw_ports) {
          wanted[raw_ports[i]] = 1
        }
      }
      /Ports: / {
        target = $2
        ports = $0
        sub(/^.*Ports: /, "", ports)
        count = split(ports, entries, ", ")
        for (i = 1; i <= count; i++) {
          split(entries[i], fields, "/")
          if (wanted[fields[1]] && fields[2] == "open" &&
              (wanted_proto == "any" || fields[3] == wanted_proto)) {
            print target, fields[1]
          }
        }
      }
    ' "$file"
  done | awk '!seen[$1 ":" $2]++'
}

all_open_target_ports() {
  local file

  for file in syn.gnmap con.gnmap udp.gnmap; do
    [[ -s "$file" ]] || continue
    awk '
      /Ports: / {
        target = $2
        ports = $0
        sub(/^.*Ports: /, "", ports)
        count = split(ports, entries, ", ")
        for (i = 1; i <= count; i++) {
          split(entries[i], fields, "/")
          if (fields[2] == "open") {
            print target, fields[3], fields[1]
          }
        }
      }
    ' "$file"
  done | awk '!seen[$1 ":" $2 ":" $3]++'
}

generate_services_report() {
  local report_dir="targets_with_open_ports"
  local services_tsv="${report_dir}/services.tsv"
  local file

  mkdir -p "$report_dir"

  {
    printf 'target\tprotocol\tport\tname\tinfo\ttarget_port\n'
    for file in syn.gnmap con.gnmap udp.gnmap; do
      [[ -s "$file" ]] || continue
      awk '
        function trim(value) {
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
          return value
        }
        /Ports: / {
          target = $2
          ports = $0
          sub(/^.*Ports: /, "", ports)
          count = split(ports, entries, ", ")
          for (i = 1; i <= count; i++) {
            field_count = split(entries[i], fields, "/")
            if (fields[2] != "open") {
              continue
            }
            port = fields[1]
            proto = fields[3]
            name = trim(fields[5])
            info = ""
            for (j = 7; j <= field_count; j++) {
              if (fields[j] == "") {
                continue
              }
              info = info ? info "/" fields[j] : fields[j]
            }
            info = trim(info)
            if (name == "") {
              name = "unknown"
            }
            print target "\t" proto "\t" port "\t" name "\t" info "\t" target ":" port
          }
        }
      ' "$file"
    done | awk -F '\t' '
      {
        key = $1 FS $2 FS $3
        if (!(key in seen)) {
          order[++order_count] = key
          seen[key] = 1
          row[key] = $0
          info[key] = $5
        } else if (info[key] == "" && $5 != "") {
          row[key] = $0
          info[key] = $5
        }
      }
      END {
        for (i = 1; i <= order_count; i++) {
          print row[order[i]]
        }
      }
    ' | sort -t "$(printf '\t')" -k3,3n -k2,2 -k1,1
  } > "$services_tsv"
}

generate_open_port_reports() {
  local report_dir="targets_with_open_ports"
  local report_tsv="${report_dir}/open_ports_all.tsv"
  local legacy_report_tsv="${report_dir}/open_ports_mentioned.tsv"
  local report_txt="${report_dir}/open_ports_by_target.txt"
  local proto
  local port
  local port_file

  mkdir -p "$report_dir"

  {
    printf 'target\tprotocol\tport\n'
    all_open_target_ports | awk '{print $1 "\t" $2 "\t" $3}'
  } | awk 'NR == 1 || !seen[$0]++' | sort -t "$(printf '\t')" -k3,3n -k2,2 -k1,1 > "$report_tsv"

  cp "$report_tsv" "$legacy_report_tsv"

  awk -F '\t' 'NR > 1 {print $2 "\t" $3}' "$report_tsv" | sort -u -k2,2n -k1,1 |
    while IFS=$'\t' read -r proto port; do
      [[ -n "${proto:-}" && -n "${port:-}" ]] || continue
      port_file="${report_dir}/${proto}_${port}.txt"
      awk -F '\t' -v wanted_proto="$proto" -v wanted_port="$port" \
        'NR > 1 && $2 == wanted_proto && $3 == wanted_port {print $1}' "$report_tsv" > "$port_file"
      [[ -s "$port_file" ]] || rm -f "$port_file"
    done

  awk '
    NR == 1 {
      next
    }
    {
      key = $1
      entry = $2 "/" $3
      if (!seen[key, entry]++) {
        ports[key] = ports[key] ? ports[key] ", " entry : entry
      }
    }
    END {
      for (target in ports) {
        print target ": " ports[target]
      }
    }
  ' "$report_tsv" | sort > "$report_txt"

  generate_services_report

  printf '\n%sWrote Open-Port Reports Under:%s %s/\n' "$CLR_GREEN" "$CLR_RESET" "$report_dir"
  printf '%sWrote Target/Port Table:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$report_tsv"
  printf '%sWrote Grouped Target Summary:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$report_txt"
  printf '%sWrote Per-Port Target Lists Under:%s %s/\n' "$CLR_GREEN" "$CLR_RESET" "$report_dir"
}
