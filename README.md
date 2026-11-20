# Bident

Network VAPT Toolkit by **sp3ttr0**. Scans hosts and ports, runs security checks, and generates an HTML report with findings, known vulnerabilities, and evidence.

## Setup

Designed for Kali Linux and Parrot OS.

```bash
chmod +x bident.sh
./bident.sh --check-deps
sudo ./bident.sh --install-deps
```

## Usage

```bash
sudo ./bident.sh -f scope.txt -o results/
```

Put the hosts to assess in `scope.txt`. Run `./bident.sh --help` for all options. Open `results/report.html` when finished.

## Flags

| Flag | Description |
| --- | --- |
| `-f <scope-file>` | Read host addresses, hostnames, or CIDR networks from a file, one per line. |
| `-t <host>` | Scan a single host. |
| `--resume <results-dir>` | Continue from saved results using the original scan options. Do not combine with `-f` or `-t`. |
| `-o <dir>`, `--output-dir <dir>`, `--results-dir <dir>` | Save results in this folder. Default: a new dated `bident_results_…` folder. |
| `-p-` | Scan all ports (1–65535) for TCP and, unless skipped, UDP. |
| `--no-udp` | Skip UDP scans and follow-up checks. |
| `--no-msf` | Skip Metasploit checks. |
| `-T1` … `-T5` | Set Nmap timing; lower is slower, higher is more aggressive. Default: `-T4`. |
| `--responder` | Start Responder in a separate screen session, using `eth0` by default. It may remain running after the scan. |
| `--script-timeout <duration>` | Limit each NSE script instance. Default: `30m`; `0` means unlimited. This is not a host or whole-scan timeout. |
| `--tool-timeout <seconds>` | Limit external commands using the shared timeout runner. Default: `0` (unlimited). testssl and sslscan retain their separate 30-minute limit per tool per host. Requires `timeout`. |
| `--msf-timeout <seconds>` | Limit each Metasploit module run across its port-group hosts. Default: `120`; `0` means unlimited. Requires `timeout`. |
| `--msf-threads <number>` | Set concurrent host checks for modules supporting `THREADS`. Default: `16`. |
| `--check-deps` | List installed and missing dependencies without scanning. |
| `--install-deps` | Install supported dependencies through apt; requires sudo. |
| `-h`, `--help` | Show help without scanning. Use as the first argument. |

## Disclaimer

Use only on systems you own or have explicit permission to assess. Automated results may be incomplete or inaccurate; validate findings before taking action. Keep scan results, scope files, credentials, and logs private. The owner and contributors are not liable for unauthorized or harmful use.
