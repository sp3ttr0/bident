<p align="center">
  <img src="assets/bident-logo.svg" alt="Bident logo" width="160">
</p>

# Bident

Bident is a network VAPT helper for authorized internal reconnaissance. It expands a scope file or single target, discovers live hosts, runs TCP and optional UDP port scans, launches targeted follow-up checks only when matching ports are confirmed open, and generates organized text outputs plus a searchable HTML report.

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
--host-timeout N  Add Nmap --host-timeout to scans and override live discovery timeout.
--msf-timeout N   Timeout for each Metasploit port group, in seconds. Default: 300.
--msf-threads N   THREADS value for Metasploit scanner modules. Default: 16.
--no-udp          Skip UDP scans and UDP follow-up checks.
--responder       Start Responder on eth0 in a separate screen session.
--tool-timeout N  Timeout for external tools, in seconds. Default: disabled.
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

Run without Metasploit and cap external tool runtime at 300 seconds:

```bash
sudo ./bident.sh -f scope.txt --no-msf --tool-timeout 300
```

Tune Metasploit scanner speed and per-port runtime:

```bash
sudo ./bident.sh -f scope.txt --msf-threads 24 --msf-timeout 180
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

Bident is intended only for authorized security testing, validation, and assessment work. Some findings may be false positives and should be manually verified before action is taken. Do not run this tool against systems, networks, or assets you do not own or do not have explicit permission to test.

The owner and contributors of this script are not responsible or liable for illegal, unauthorized, or harmful use.

## License

Add your preferred license before publishing the repository.
