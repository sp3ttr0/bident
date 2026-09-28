# Bident

Bident is a network VAPT helper for authorized internal reconnaissance. It expands a scope file or single target, discovers live hosts, runs TCP and optional UDP port scans, launches targeted follow-up checks only when matching ports are confirmed open, and generates organized text outputs plus a searchable HTML report.

```text
Network VAPT Tool
by sp3ttr0
```

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



Answering `y` stops the active scan screens for SYN, connect, and UDP scans. Responder is not stopped automatically.

## Disclaimer

Bident is intended only for authorized security testing, validation, and assessment work. Some findings may be false positives and should be manually verified before action is taken. Do not run this tool against systems, networks, or assets you do not own or do not have explicit permission to test.

The owner and contributors of this script are not responsible or liable for illegal, unauthorized, or harmful use.

## License

Add your preferred license before publishing the repository.
