<p align="center">
  <img src="assets/bident-logo.svg" alt="Bident logo" width="160">
</p>

# Bident

Bident is a network VAPT helper for authorized internal reconnaissance. It expands a scope file or single target, discovers live hosts, runs TCP and optional UDP port scans, launches targeted follow-up checks only when matching ports are confirmed open, and generates organized text outputs plus a searchable HTML report.

```text
Network VAPT Tool
by sp3ttr0
```

## Features

- Scope expansion from CIDR ranges, hostnames, or IP lists.
- Live host discovery before port scanning.
- Parallel TCP SYN, TCP connect, and optional UDP scans through `screen`.
- Optional all-port scanning with `-p-`.
- Timing control with `-T1` through `-T5`.
- Targeted follow-up checks based on confirmed open ports.
- Per-port target lists under `targets_with_open_ports/`.
- HTML report with light/dark mode, searchable sortable Services table, open ports grouped by port number, and expandable result panels.
- Graceful no-live-host handling and Ctrl+C cancellation prompt.

## Requirements

Core tools:

```bash
nmap screen awk sort grep tee sudo
```

Optional tools used when matching ports are found:

```bash
netexec ssh-audit impacket-rpcdump rpcclient ldapsearch dig testssl sslscan ike-scan responder
```

Bident should be run with `sudo` so scans running in detached `screen` sessions do not stop for password prompts.

## Installation

Clone the repository and make the script executable:

```bash
git clone <repository-url>
cd <repository-folder>
chmod +x bident.sh
```

Install core dependencies with your package manager. Example for Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y nmap screen dnsutils ldap-utils smbclient
```

Install optional tools as needed for deeper checks.

## Project Structure

```text
bident.sh              Main launcher.
lib/config.sh          Defaults, colors, and port lists.
lib/ui.sh              Help text and terminal banner.
lib/utils.sh           Shared utility helpers.
lib/screens.sh         Screen session handling, cancellation, and progress.
lib/ports.sh           Open-port parsing and target/port exports.
lib/checks.sh          Conditional follow-up checks.
lib/report.sh          HTML report generation.
lib/workflow.sh        Main scan workflow.
assets/bident-logo.svg Logo asset used by the README.
```

## Usage

```bash
sudo ./bident.sh (-f <scope-file> | -t <target>) [-o <results-dir>] [-p-] [--no-udp] [--responder] [-T1|-T2|-T3|-T4|-T5]
```

### Target Input

```bash
-f <scope-file>   Scope file to scan.
-t <target>       Single IP or host to test.
```

### Options

```bash
-o <results-dir>  Write all results into this folder.
-p-               Scan all TCP/UDP ports.
--no-udp          Skip UDP scans and UDP follow-up checks.
--responder       Start Responder on eth0 in a separate screen session.
-T1..-T5          Set the Nmap timing template. Default: -T4.
-T <1-5>          Alternate timing syntax.
--speed <1-5>     Alternate timing syntax.
```

### Examples

Scan a scope file using default ports:

```bash
sudo ./bident.sh -f scope.txt
```

Scan all ports with Nmap timing `-T4`:

```bash
sudo ./bident.sh -f scope.txt -p- -T4
```

Scan a single target and skip UDP:

```bash
sudo ./bident.sh -t 192.0.2.10 --no-udp -T4
```

Write results to a custom folder:

```bash
sudo ./bident.sh -f scope.txt -o client_scan_results -p-
```

Start Responder separately while scanning:

```bash
sudo ./bident.sh -f scope.txt --responder
```

Responder is intentionally not stopped by Bident when the scan finishes or is cancelled.

## Output

Bident creates a parent results folder and copies the scope file into it. Common outputs include:

```text
targets.txt
targets_live.txt
syn.nmap / syn.gnmap / syn.xml
con.nmap / con.gnmap / con.xml
udp.nmap / udp.gnmap / udp.xml
report.html
targets_with_open_ports/
```

The `targets_with_open_ports/` folder includes:

```text
services.tsv
open_ports_all.tsv
open_ports_mentioned.tsv
open_ports_by_target.txt
tcp_<port>.txt
udp_<port>.txt
```

Per-port files are generated only when matching open ports are found.

## HTML Report

`report.html` includes:

- scan summary metrics
- Services table
- sortable columns
- search textbox
- open ports grouped by port number
- expandable Hosts/IPs and result panels
- Core Artifacts list
- light/dark mode toggle
- legal and validation disclaimer

The Services table uses these columns:

```text
Hosts/IPs
Port/Protocol
Name
Info
Hosts/IPs:Port
```

By default, Services are sorted by `Port/Protocol` from lowest to highest.

## Conditional Checks

Bident runs follow-up checks only when the related port is confirmed open in the base scan results. Examples include:

- FTP, SSH, Telnet, SMTP, DNS, HTTP/HTTPS, SSL/TLS, Kerberos, POP3
- RPCBind, MSRPC, NTP, NetBIOS, SMB, SNMP, LDAP, IKE, IPMI
- MSSQL, Oracle, NFS, MySQL, RDP, SIP, VNC, AJP
- Weak SSH cipher checks with `ssh-audit`
- SMB signing and SMBv1 checks with `netexec`
- LDAP anonymous bind checks with `ldapsearch`
- DNSSEC and DNS recursion checks with `dig`
- SSL/TLS checks with `testssl` and `sslscan`
- IKE weak encryption checks with `ike-scan`

## Cancellation

Pressing `Ctrl+C` prompts:

```text
Cancel the script? [y/N]:
```

Answering `y` stops the active scan screens for SYN, connect, and UDP scans. Responder is not stopped automatically.

## Disclaimer

Bident is intended only for authorized security testing, validation, and assessment work. Some findings may be false positives and should be manually verified before action is taken. Do not run this tool against systems, networks, or assets you do not own or do not have explicit permission to test.

The owner and contributors of this script are not responsible or liable for illegal, unauthorized, or harmful use.

## License

Add your preferred license before publishing the repository.
