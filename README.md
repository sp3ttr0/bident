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

## Disclaimer

Use only on systems you own or have explicit permission to assess. Automated results may be incomplete or inaccurate; validate findings before taking action. Keep scan results, scope files, credentials, and logs private. The owner and contributors are not liable for unauthorized or harmful use.
