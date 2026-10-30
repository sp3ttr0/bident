<p align="center">
  <img src="assets/bident-logo.svg" alt="Bident logo" width="160">
</p>

# Bident

Network VAPT Toolkit by **sp3ttr0**. Discovers hosts, scans TCP/UDP ports, runs NSE and external-tool checks, and generates an HTML report with findings, affected Host:Port lists, copy buttons, and full evidence.

## Setup

Designed for Kali/Parrot-style Debian systems.

```bash
chmod +x bident.sh
./bident.sh --check-deps
sudo ./bident.sh --install-deps
```

## Usage

Run with sudo from your normal account:

```bash
# Scan hosts from a scope file.
sudo ./bident.sh -f scope.txt -o results/

# Scan one host without UDP.
sudo ./bident.sh -t 192.0.2.10 --no-udp

# Resume a scan.
sudo ./bident.sh --resume results/
```

Use `./bident.sh --help` for all options, including `-p-` for all ports and `--no-msf` to skip Metasploit.

## Key Defaults

- NSE script timeout: **30 minutes per instance** (`--script-timeout`).
- SSL/TLS: **443 and 8443**, using testssl and sslscan, with NSE as fallback. Timeout: **30 minutes per tool per host**.
- Metasploit timeout: **120 seconds per module process** (`--msf-timeout`).
- UDP base scans omit version detection.
- Verified findings show **Found and verified**; failed checks show **Incomplete**. Completed external-tool and Metasploit checks with no finding stay silent.

## Results

Open **`report.html`** in the results folder. It contains findings, credentials, affected hosts, full evidence, and scan details. Failed checks are under **Core Artifacts**.

Raw outputs are saved in `base_scans/`, `nmap_scripts/`, `tool_results/`, `metasploit/`, and `logs/`. Verified Ghostcat files are saved in `metasploit/loot/` (requires Python 3).

Keep real scan results, scope files, credentials, and logs out of Git. Standard output folders are ignored; check custom paths before committing. Keep `tests/` in the repository.

## Tests

```bash
bash tests/run.sh
```

Requires Bash, Python 3, and Node.js. Tests use synthetic data and mocked tools, with no live scans.

## Disclaimer

Use only on systems you own or are authorized to assess. Review findings carefully; automated results can contain false positives. Enumerated usernames alone do not confirm valid credentials. The owner and contributors are not liable for unauthorized or harmful use.
