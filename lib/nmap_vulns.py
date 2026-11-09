"""Extract explicit, port-attributed NSE vulnerability results for the report."""
import html
import ipaddress
import re
import sys
from pathlib import Path

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SCRIPT = re.compile(r"^\|[_ ]([a-zA-Z0-9_-]+):(?:\s*(.*))?$")
MARKER = re.compile(r"^(?:NOT |LIKELY |POSSIBLY )?VULNERABLE:\s*$", re.I)
POSITIVE = re.compile(r"^(?:State:\s*)?VULNERABLE(?:\s*\(Exploitable\))?\s*[:.]?\s*$", re.I)
NEGATIVE = re.compile(r"\b(?:NOT|LIKELY|POSSIBLY|POTENTIALLY)\s+VULNERABLE\b|State:\s*(?:UNKNOWN|ERROR)|ERROR:|Script execution failed|timed out|could not (?:test|verify)|unable to (?:test|verify)", re.I)


def host_address(value):
    try:
        return str(ipaddress.ip_address(value.strip('()[]')))
    except ValueError:
        return None


def clean(line):
    return re.sub(r'^\|[_ ]?', '', line).strip()


def parse_file(path, scope, include_negative=False):
    lines = path.read_text(errors='replace').splitlines()
    host = port = proto = None
    script = None
    script_header = ""
    block = []
    header = []
    records = []

    def flush():
        if not (host in scope and port and script and block and any(clean(raw) for _, raw in block)):
            return
        # Split separate vulnerability states within the same script so a CVE
        # in a negative or inconclusive result cannot inherit a positive state.
        chunks, chunk = [], []
        structural_level = min(len(re.sub(r'^\|[_ ]?', '', raw)) - len(re.sub(r'^\|[_ ]?', '', raw).lstrip()) for _, raw in block if clean(raw))
        for nr, raw in block:
            body = re.sub(r'^\|[_ ]?', '', raw)
            indent = len(body) - len(body.lstrip())
            if MARKER.fullmatch(clean(raw)) and indent == structural_level and chunk:
                chunks.append(chunk)
                chunk = []
            chunk.append((nr, raw))
        if chunk:
            chunks.append(chunk)
        for chunk in chunks:
            text = '\n'.join(clean(raw) for _, raw in chunk)
            # A VULNERABLE heading must not override an explicit nonpositive
            # state. Restrict state/ID fields to the record's structural level,
            # excluding indented descriptions and reference text.
            fields = []
            for nr, raw in chunk:
                body = re.sub(r'^\|[_ ]?', '', raw)
                if raw == script_header:
                    body = body.split(':', 1)[1]
                fields.append((nr, raw, len(body) - len(body.lstrip()), body.strip()))
            base_level = min(f[2] for f in fields if f[3])
            state_fields = [f for f in fields if re.match(r'^State:', f[3], re.I)]
            states = []
            if state_fields:
                level = min(f[2] for f in state_fields)
                states = [f[3] for f in state_fields if f[2] == level]
            positive = bool(states) and level <= base_level + 2 and all(POSITIVE.fullmatch(state) for state in states)
            if not states:
                # Also accept the standard standalone NSE VULNERABLE marker.
                positive = any(f[2] == base_level and POSITIVE.fullmatch(f[3]) for f in fields)
            if NEGATIVE.search(text) or any(re.search(r'^(?:ERROR:|.*Script execution failed|.*timed out)', clean(raw), re.I) for _, raw in block):
                positive = False
            negative = any(re.fullmatch(r'(?:State:\s*)?NOT VULNERABLE[:.]?', f[3], re.I) for f in fields)
            if not positive and not (include_negative and negative):
                continue
            # CVEs belong to the IDs field, not arbitrary descriptions/links.
            # Never attach a CVE merely mentioned as a comparison or reference.
            ids = [f for f in fields if re.match(r'^IDs?:', f[3], re.I)]
            ids_level = min((f[2] for f in ids), default=-1)
            cves = sorted({cve.upper() for f in ids if f[2] == ids_level and f[2] <= base_level + 2 and (not states or f[2] == level) for cve in CVE.findall(f[3])})
            title = script
            for _, raw in chunk:
                candidate = clean(raw)
                if candidate and not MARKER.fullmatch(candidate) and not re.match(r'^(State|IDs|Risk factor|Description|References|Disclosure date|Exploit results):', candidate, re.I) and not candidate.startswith(script + ':') and not POSITIVE.fullmatch(candidate):
                    title = candidate
                    break
            # Retain every original line in this script block, unmodified,
            # together with its host and open-port context.
            evidence = '\n'.join(header + [script_header] + [raw for _, raw in block])
            records.append(dict(host=host, port=port, proto=proto, script=script,
                                title=title, cves=cves, file=str(path), line=chunk[0][0],
                                evidence=evidence, positive=positive))

    for nr, raw in enumerate(lines, 1):
        if raw.startswith('Nmap scan report for '):
            flush(); script = None; block = []; port = proto = None
            value = raw.removeprefix('Nmap scan report for ')
            host = host_address(value.split()[-1]) if value.split() else None
            header = [raw]
            continue
        match = re.match(r'^(\d+)/(tcp|udp)\s+(\S+)\s+', raw)
        if match:
            flush(); script = None; block = []; port = proto = None
            if match[3] == 'open' and 1 <= int(match[1]) <= 65535:
                port, proto = int(match[1]), match[2]
                header = header[:1] + [raw]
            continue
        if raw.startswith(('Host script results:', 'Nmap done:', '# Nmap', '===== ', 'Command:')) or (raw and not raw.startswith('|')):
            flush(); script = None; block = []; port = proto = None
            continue
        match = SCRIPT.match(raw)
        if match:
            flush(); script = match[1]; script_header = raw; block = []
            if match[2]:
                block.append((nr, raw))
        elif script and raw.startswith('|'):
            block.append((nr, raw))
    flush()
    return records


def render(records):
    esc = html.escape
    groups = {}
    for row in records:
        if not row.get('positive', True):
            continue
        # Conflicting explicit negative results for the same service/script
        # suppress promotion. Unknown CVE identities are handled conservatively.
        if any(not other.get('positive', True)
               and all(row[k] == other[k] for k in ('host', 'port', 'proto', 'script'))
               and (not row['cves'] or not other['cves'] or set(row['cves']) & set(other['cves']))
               for other in records):
            continue
        key = (row['script'], tuple(row['cves']), row['title'])
        groups.setdefault(key, []).append(row)
    for (script, cves, title), rows in sorted(groups.items()):
        endpoints = sorted({f"[{r['host']}]:{r['port']}" if ':' in r['host'] else f"{r['host']}:{r['port']}" for r in rows})
        heading = title + (' — ' + ', '.join(cves) if cves else '')
        print('<li><details class="finding-panel"><summary><div><strong>' + esc(heading) + '</strong><span>' + str(len(endpoints)) + ' affected host(s)</span></div></summary>')
        print('<div data-affected-targets><div class="copy-targets-toolbar"><button type="button" class="copy-targets">Copy hosts <svg class="copy-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg></button><span class="copy-targets-status muted" role="status" aria-live="polite"></span></div>')
        print('<div class="service-table-wrap"><table class="service-table"><thead><tr><th>Host:Port</th></tr></thead><tbody>')
        for endpoint in endpoints:
            print('<tr><td>' + esc(endpoint) + '</td></tr>')
        print('</tbody></table></div></div>')
        seen = set()
        for row in rows:
            key = (row['host'], row['port'], row['proto'], row['evidence'])
            if key in seen:
                continue
            seen.add(key)
            endpoint = f"[{row['host']}]:{row['port']}" if ':' in row['host'] else f"{row['host']}:{row['port']}"
            print('<details class="artifact"><summary>Full Evidence — ' + esc(endpoint + ' (' + row['proto'] + ') — ' + row['file']) + '</summary><p class="muted evidence-source">Matched source: ' + esc(row['file']) + ':' + str(row['line']) + '</p><pre class="finding-evidence">' + esc(row['evidence']) + '</pre></details>')
        print('</details></li>')


def main():
    scope = {host_address(line) for line in Path(sys.argv[1]).read_text().splitlines()} - {None}
    records = []
    for folder, pattern in [(sys.argv[2], '*.txt'), (sys.argv[3], '*.nmap')]:
        for path in sorted(Path(folder).glob(pattern)):
            if path.is_file() and not path.is_symlink():
                records.extend(parse_file(path, scope, include_negative=True))
    render(records)


if __name__ == '__main__':
    main()
