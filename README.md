# Bident

Network VAPT Toolkit by **sp3ttr0**. Scans hosts and ports, runs security checks, and generates an HTML report with findings and evidence.

## Setup

Designed for Kali/Parrot-style Debian systems.

```bash
chmod +x bident.sh
./bident.sh --check-deps
sudo ./bident.sh --install-deps
```

## Usage

```bash
sudo ./bident.sh -f scope.txt -o results/
sudo ./bident.sh -t 192.0.2.10 --no-udp
sudo ./bident.sh --resume results/
```

Run `./bident.sh --help` for all options. Open `report.html` in the results folder when finished.

NSE and SSL/TLS checks default to 30-minute timeouts; Metasploit defaults to 120 seconds per module process. SSL/TLS checks cover ports 443 and 8443.

Keep scan results, scope files, credentials, and logs out of Git.

## Disclaimer

Use only on systems you own or have explicit permission to assess. Automated results may be incomplete or inaccurate; review findings and evidence before taking action. Discovered usernames alone do not confirm valid credentials. The owner and contributors are not liable for unauthorized or harmful use.
