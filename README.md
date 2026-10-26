<p align="center">
  <img src="assets/bident-logo.svg" alt="Bident logo" width="160">
</p>

# Bident

Bident is a network VAPT helper for authorized internal reconnaissance. It expands a scope file or single target, discovers live hosts, runs TCP and optional UDP port scans, launches targeted follow-up checks only when matching ports are confirmed open, and generates organized text outputs plus a searchable HTML report.

Completed scans show the start time, finish time (including timezone), and runtime
(HH:MM:SS) in the terminal and HTML report, including scans with no live hosts.
Timing covers discovery and scan checks, ending before report generation. When
using `--resume`, timing covers the current invocation only.

Terminal output uses red stage headings, cyan labels, colored summary values,
and a highlighted runtime. Colors are disabled for redirected output, dumb
terminals, or when `NO_COLOR` is set.

```text
Network VAPT Toolkit
by sp3ttr0
```

## Requirements

Core tools:

```bash
nmap screen awk sort grep tee sudo
```

Optional tools used when matching ports are found:

```bash
netexec ssh-audit impacket-rpcdump rpcclient ldapsearch dig testssl sslscan ike-scan responder msfconsole
```

## Installation

Clone the repository and make the script executable:

```bash
git clone <repository-url>
cd <repository-folder>
chmod +x bident.sh
```

Check what is already installed:

```bash
./bident.sh --check-deps
```

Install supported dependencies automatically:

```bash
sudo ./bident.sh --install-deps
```

Bident currently focuses automatic installation on VAPT-focused Debian-based systems such as Kali and Parrot. `--install-deps` uses `apt` and installs packages available from the configured repositories. Any unavailable package is skipped with a clear message.

Packages attempted by `--install-deps`:

```bash
nmap screen dnsutils ldap-utils smbclient samba-common-bin sslscan ike-scan ssh-audit python3-impacket responder metasploit-framework testssl.sh netexec
```

## Usage

```bash
sudo ./bident.sh (-f <scope-file> | -t <target> | --resume <results-dir>) [-o <results-dir>] [options] ...
```

Run Bident with sudo/root for scans. Privileged scans run as root, and when launched with sudo, external tools such as `ssh-audit` run as the original sudo user when possible.

### Target Input

```bash
-f <scope-file>   Scope file to scan.
-t <target>       Single IP or host to test.
--resume <dir>    Resume from an existing Bident results folder.
```

### Options

```bash
-o <results-dir>  Write all results into this folder.
-p-               Scan all TCP/UDP ports.
--check-deps      Show installed and missing tools.
--install-deps    Install supported dependencies from Kali/Parrot apt repos.
                  Package installation may require sudo.
--no-msf          Skip Metasploit auxiliary checks.
--msf-timeout N   Timeout for each Metasploit port group, in seconds. Default: 120.
--msf-threads N   THREADS value for Metasploit scanner modules. Default: 16.
--no-udp          Skip UDP scans and UDP follow-up checks.
--responder       Start Responder on eth0 in a separate screen session.
--tool-timeout N  Timeout for external tools, in seconds. Default: disabled.
--script-timeout T Timeout per NSE script instance. Default: 30m; 0 = unlimited.
                   Accepts seconds or ms/s/m/h suffixes (e.g. 900, 15m, 1h).
-T1..-T5          Set the Nmap timing template. Default: -T4.
```

### Wordlists

Bident includes a small default SNMP community list at:

```bash
wordlists/snmp_communities.txt
```

The SNMP Metasploit login check uses this file with `PASS_FILE`. Keep this list short unless you have explicit authorization to run broader community-string checks.

### Examples

Scan a scope file using default ports:

```bash
sudo ./bident.sh -f scope.txt
```

Scan all ports with Nmap timing `-T4`:

```bash
sudo ./bident.sh -f scope.txt -p- -T4
```

Run without Metasploit and cap external tool runtime at 300 seconds:

```bash
sudo ./bident.sh -f scope.txt --no-msf --tool-timeout 300
```

Tune Metasploit scanner speed and per-port runtime:

```bash
sudo ./bident.sh -f scope.txt --msf-threads 24 --msf-timeout 120
```

Scan a single target and skip UDP:

```bash
sudo ./bident.sh -t 192.0.2.10 --no-udp -T4
```

Write results to a custom folder:

```bash
sudo ./bident.sh -f scope.txt -o client_scan_results -p-
```

Resume from an existing results folder:

```bash
sudo ./bident.sh --resume bident_results_20260928_120000
```

## Output Layout

TLS checks run testssl first as the primary assessment and sslscan next as a
cross-check when installed. If only one is installed, Bident uses that tool.
The SSL/TLS NSE group runs only when neither external tool is available; an
external tool error does not trigger an automatic NSE retry. The target ports
are 443 and 8443.

The SSL/TLS stage runs after the other NSE checks, before Metasploit. Each
external TLS tool has a fixed 30-minute limit per IP:port, independent of
`--tool-timeout`. A timeout sends TERM, with KILL after a further 10 seconds
if necessary, then continues to the next check. GNU `timeout` or `gtimeout`
is required; if missing, checks are marked incomplete rather than run without
a limit. Status and execution logs
appear under **Core Artifacts → TLS External Check Status**. Raw output remains
available, but incomplete runs are excluded from verified TLS findings.

All Nmap scan commands that can execute NSE scripts receive `--script-timeout`,
including version-detection scripts. Brute-force checks remain enabled as before.
For a longer run, use `sudo ./bident.sh -f scope.txt --script-timeout 1h`.
The limit applies to each script instance, not the whole scan. Follow-up check
statuses and execution logs are shown in the report; detected script timeouts
and failed commands are marked incomplete and remaining checks continue.
Nmap may discard the timed-out script instance’s output; results already written
by other checks and captured execution logs remain available. No credential
result from an incomplete check must be interpreted as a confirmed absence.

Metasploit findings require module-specific positive result messages. Command
echoes, stack traces, and generic completion messages do not establish findings.
Failures and nonzero process exits are listed under **Core Artifacts → Metasploit
Failed / Incomplete Checks**, with execution-log links. A genuine result for one
target is retained even if another target fails in the same module output.

The Weak SSH Ciphers finding groups affected IP:port endpoints with their cipher
names. Only encryption (`enc`) warnings/failures qualify; key-exchange, host-key,
or MAC warnings alone do not. Affected endpoints appear in the report rather
than the terminal and are saved to `tool_results/ssh_weak_cipher_targets.txt`.

Other Findings Summary cards also show deduplicated affected IP:port lists.
Endpoints must be tied to a positive result line or a successful single-target
command block; target-list inputs and command echoes are never counted as
affected endpoints. Unattributable, failed, or ambiguous output remains available
in Core Artifacts but is omitted from verified finding lists. In particular,
the existing DNSSEC check records a missing AD flag, which is insufficient to
promote a target to a verified “DNSSEC not configured” finding.

Possible Usernames / Credentials entries show the source IP:port when the saved
output identifies it. Use **Copy entries with IP:Port** for tab-separated endpoint
and entry rows, or **Copy IP:Port only** for unique known endpoints. Entries without
an attributable endpoint display **Not identified** and are excluded from the
endpoint-only copy. Copy buttons include the entries displayed in the report
(up to 80), rather than hidden or truncated results.

TLS Findings Summary cards cover SSLv2/SSLv3/TLS 1.0/TLS 1.1 support, explicit
TLS 1.3 unavailability, accepted weak ciphers, HTTP compression, wildcard served
certificates, weak certificate signature hashes, and expired served certificates.
Each card includes affected IP:port endpoints, a copy button, and source evidence
with line numbers from testssl, sslscan, or the NSE fallback. Missing tests and
connection failures are excluded. TLS 1.3 unavailability also requires evidence
of a working TLS service, and is suppressed when another saved result explicitly
shows TLS 1.3 support on the same endpoint. Certificate expiry dates must be
before today in UTC; certificates expiring today are excluded. HTTP compression indicates potential BREACH
exposure, and wildcard use alone is an informational review item; neither is
presented as independently verified exploitability.

TLS 1.3 negative results are also suppressed for scanner capability warnings and
inconclusive or timed-out tests. Accepted TLS 1.3 cipher handshakes count as
contradictory support evidence. Expiry dates must be complete and valid UTC dates
(including month lengths and leap years), with an expiry date before today (UTC);
soon-to-expire certificates, chain-only certificates, unknown dates, and
conflicting unexpired dates for the same served certificate are excluded.
An `expired` label without a usable expiry date is insufficient. Wildcard
certificate entries require a literal `*` in the common name or alternative
names; an asterisk in an organization name or issuer alone does not qualify.

TLS cards show **Evidence by Host:Port** tables. Weak TLS cipher entries include
the specific accepted suite names where enumerated; category-only observations
are explicitly marked and never expanded into assumed cipher names. Other
supported findings, including Metasploit findings, also associate each evidence
row with its affected endpoint and source line. Failed or unrelated target
blocks are excluded from those tables; full raw output remains in Core Artifacts.

```text
base_scans/              SYN, connect, and UDP Nmap base scan outputs.
nmap_scripts/            Targeted Nmap NSE result files.
tool_results/            External tool outputs.
metasploit/              Metasploit auxiliary resource file and results.
logs/                    Detached screen session logs.
targets_with_open_ports/ Open-port target lists and service tables.
report.html              Searchable HTML report.
summary.json             Machine-readable JSON summary.
```

## Disclaimer

### Keeping local results out of Git

The `.gitignore` excludes standard scan artifacts, common result folders,
local scope/target lists, and common credential/key exports. Use `-o results/`
for a custom output location inside the repository. If you choose a different
folder name, add it to `.gitignore` before staging files. Arbitrary output names
and credentials embedded in source files cannot be protected by filename rules.
Files already tracked by Git are unaffected by ignore rules. Check
`git status --short` and `git diff --cached` before committing. Keep `tests/`
and the bundled SNMP community wordlist; tests must contain synthetic data only.

Bident is intended only for authorized security testing, validation, and assessment work. Some findings may be false positives and should be manually verified before action is taken. Do not run this tool against systems, networks, or assets you do not own or do not have explicit permission to test.

The owner and contributors of this script are not responsible or liable for illegal, unauthorized, or harmful use.

## License

Add your preferred license before publishing the repository.

Weak SSL/TLS cipher tables list observed individual cipher names on separate
lines per Host:Port, including deprecated CBC suites. testssl runs use
`--wide --mapping iana` to retain IANA suite names in remote enumeration output.
Only successful remote cipher rows are parsed; local catalogues, client
simulations, rejected suites, and incomplete runs do not establish affected
cipher names. Category-only historical logs show that individual names are
unavailable and require a rescan; no names are inferred from category labels.

External check failures (RPC, LDAP, NetExec, ssh-audit, DNS dig, and ike-scan)
print **Incomplete** rather than a negative finding. Nonzero execution errors,
timeouts, Python dependency tracebacks, and connection errors are saved with
the command and full output under `logs/external_*`; the HTML report embeds
them under **Core Artifacts → External Tool Failed / Incomplete Checks**.
ssh-audit exit codes 2 and 3 indicate algorithm warnings/failures and remain
eligible for findings. TLS and Metasploit keep their dedicated incomplete-check
sections. Failed executions are excluded from credential/finding input files.

Before host discovery (including resumed runs), Bident probes NetExec using
`netexec smb -L` with no targets, and rpcdump using `impacket-rpcdump -h`.
The NetExec probe loads the SMB implementation rather than exiting early at
argument help. The probes run through the same user/privilege wrapper as the
scan commands, with a 20-second timeout when GNU `timeout` is available.
Broken or missing tools are marked incomplete, logged under Core Artifacts,
and skipped for the rest of that run; the remaining scan continues. No package
installation or dependency repair is performed automatically.

Metasploit runs each configured module in a separate console process. Bident
captures its complete stdout/stderr directly into `metasploit/results/`, even
when it fails; capture no longer depends on Metasploit's spool command. The
combined `metasploit/msfconsole.log` and per-module process exit status are also
retained. Separate processes add console startup time but prevent output from
one module being attributed to another. Result Host:Port must match the job's
port and, when its target file is available, a host in that file. RDP's repeated
endpoint must agree with its result prefix. Successful scanner observations
qualify for the Findings Summary; failures and completion messages alone do not.

When launched with sudo from a normal user account, Bident returns ownership
of the whole results tree to that user and grants owner read/write access to
files and owner read/write/traversal access to directories. Cleanup also runs
on cancellation, termination, early completion, and ordinary errors. Private
logs keep their restrictive group/other permissions. Symlinks are not followed
outside the results tree. A forced SIGKILL or machine shutdown cannot run exit
cleanup; existing interrupted folders may still require manual ownership repair.
