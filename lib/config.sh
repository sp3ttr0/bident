TARGETS_FILE="${TARGETS_FILE:-targets.txt}"
LIVE_TARGETS_FILE="${LIVE_TARGETS_FILE:-targets_live.txt}"
RESULTS_DIR="${RESULTS_DIR:-}"
RESUME_DIR="${RESUME_DIR:-}"
SCAN_DIR="${SCAN_DIR:-base_scans}"
NSE_DIR="${NSE_DIR:-nmap_scripts}"
TOOL_DIR="${TOOL_DIR:-tool_results}"
LOG_DIR="${LOG_DIR:-logs}"
MSF_DIR="${MSF_DIR:-metasploit}"
MSF_RESULT_DIR="${MSF_RESULT_DIR:-metasploit/results}"
MSF_TIMEOUT="${MSF_TIMEOUT:-300}"
MSF_THREADS="${MSF_THREADS:-16}"
MIN_RATE="${MIN_RATE:-2000}"
HOST_TIMEOUT="${HOST_TIMEOUT:-5m}"
NSE_MIN_RATE="${NSE_MIN_RATE:-2000}"
NSE_HOST_TIMEOUT="${NSE_HOST_TIMEOUT:-5m}"
TIMING="${TIMING:-T4}"
SCAN_POLL_SECONDS="${SCAN_POLL_SECONDS:-60}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-0}"
PORT_FLAG=""
NO_UDP=false
NO_MSF=false
RUN_RESPONDER=false
CHECK_DEPS=false
INSTALL_DEPS=false
RESPONDER_INTERFACE="${RESPONDER_INTERFACE:-eth0}"
SUDO_CMD="${SUDO_CMD:-sudo}"
SCOPE_FILE=""
SINGLE_TARGET=""
CLR_RESET=""
CLR_BOLD=""
CLR_RED=""
CLR_GREEN=""
CLR_YELLOW=""
CLR_CYAN=""
CLR_BLUE=""
MENTIONED_TCP_PORTS=(
  21 22 23 25 53 80 81 88 110 111 135 139 389 443 445 465 587 636
  993 995 1433 1521 2049 3268 3269 3306 3389 5800 5801 5900 5901
  8000 8009 8080 8443
)
MENTIONED_UDP_PORTS=(
  53 111 123 137 161 162 500 623 5060
)

CORE_TOOLS=(
  nmap screen awk sort grep tee sudo
)

OPTIONAL_TOOLS=(
  netexec ssh-audit impacket-rpcdump rpcclient ldapsearch dig testssl sslscan
  ike-scan responder msfconsole
)

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  CLR_RESET="$(printf '\033[0m')"
  CLR_BOLD="$(printf '\033[1m')"
  CLR_RED="$(printf '\033[31m')"
  CLR_GREEN="$(printf '\033[32m')"
  CLR_YELLOW="$(printf '\033[33m')"
  CLR_CYAN="$(printf '\033[36m')"
  CLR_BLUE="$(printf '\033[34m')"
fi
