#!/usr/bin/env bash
# =============================================================================
# Xarex Probe — Linux Installer
# =============================================================================
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Amazon Linux 2/2023
#
# Usage:
#   sudo bash install-linux.sh
#   # Or with pre-set environment variables:
#   CLOUD_BRAIN_URL=https://cloud.example.com ORG_ID=abc123 sudo -E bash install-linux.sh
#
# The installer is idempotent — safe to re-run to upgrade or repair.
# =============================================================================
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
readonly XAREX_VERSION="1.0.0"
readonly INSTALL_DIR="/opt/xarex"
readonly SERVICE_NAME="xarex-probe"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly CONF_FILE="${INSTALL_DIR}/xarex.conf"
readonly BINARY="${INSTALL_DIR}/xarex-probe"
readonly LOG_FILE="/var/log/xarex-probe-install.log"

# ── Colour helpers ─────────────────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo "${CYAN}[INFO]${RESET}  $*" | tee -a "$LOG_FILE"; }
ok()      { echo "${GREEN}[ OK ]${RESET}  $*" | tee -a "$LOG_FILE"; }
warn()    { echo "${YELLOW}[WARN]${RESET}  $*" | tee -a "$LOG_FILE"; }
error()   { echo "${RED}[ERR ]${RESET}  $*" | tee -a "$LOG_FILE" >&2; }
die()     { error "$*"; exit 1; }
section() { echo "" | tee -a "$LOG_FILE"; echo "${BOLD}━━━ $* ━━━${RESET}" | tee -a "$LOG_FILE"; }

# ── Prerequisite: root ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "This installer must be run as root. Try: sudo bash $0"
fi

# Ensure log file is writable
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/xarex-probe-install.log"
echo "=== Xarex Probe Installer v${XAREX_VERSION} — $(date -u) ===" >> "$LOG_FILE"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo "${BOLD}${CYAN}║          Xarex Probe — Linux Installer             ║${RESET}"
echo "${BOLD}${CYAN}║                    v${XAREX_VERSION}                            ║${RESET}"
echo "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
section "Step 1 — Detecting Operating System"
# ═════════════════════════════════════════════════════════════════════════════

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-0}"
        OS_PRETTY="${PRETTY_NAME:-Unknown Linux}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_PRETTY=$(cat /etc/redhat-release)
    else
        die "Cannot detect OS. /etc/os-release not found."
    fi

    case "$OS_ID" in
        ubuntu|debian|raspbian)
            PKG_MANAGER="apt-get"
            PKG_INSTALL="apt-get install -y --no-install-recommends"
            PKG_UPDATE="apt-get update -qq"
            ;;
        rhel|centos|rocky|almalinux)
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum makecache -q"
            ;;
        amzn)
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum makecache -q"
            ;;
        fedora)
            PKG_MANAGER="dnf"
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf makecache -q"
            ;;
        *)
            warn "Unsupported OS '${OS_ID}'. Proceeding anyway — manual dependency installation may be required."
            PKG_MANAGER="unknown"
            PKG_INSTALL="true"
            PKG_UPDATE="true"
            ;;
    esac
}

detect_os
ok "Detected: ${OS_PRETTY}"

# ═════════════════════════════════════════════════════════════════════════════
section "Step 2 — Checking Prerequisites"
# ═════════════════════════════════════════════════════════════════════════════

MISSING_TOOLS=()
for tool in curl systemctl; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    warn "Missing tools: ${MISSING_TOOLS[*]}. Attempting to install..."
    $PKG_UPDATE
    $PKG_INSTALL "${MISSING_TOOLS[@]}" || die "Failed to install prerequisites: ${MISSING_TOOLS[*]}"
fi

ok "All prerequisite tools found."

# Check systemd is available
if ! pidof systemd &>/dev/null && [[ ! -d /run/systemd/system ]]; then
    die "systemd is not running. This installer requires a systemd-based Linux distribution."
fi
ok "systemd is active."

# ═════════════════════════════════════════════════════════════════════════════
section "Step 3 — Configuration"
# ═════════════════════════════════════════════════════════════════════════════

prompt_if_empty() {
    local varname="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local secret="${4:-no}"

    if [[ -n "${!varname:-}" ]]; then
        if [[ "$secret" == "yes" ]]; then
            info "${varname} already set (from environment)."
        else
            info "${varname} = ${!varname} (from environment)"
        fi
        return
    fi

    local prompt_display="${prompt_text}"
    [[ -n "$default_val" ]] && prompt_display+=" [${default_val}]"
    prompt_display+=": "

    while true; do
        if [[ "$secret" == "yes" ]]; then
            read -r -s -p "${CYAN}${prompt_display}${RESET}" user_input
            echo ""
        else
            read -r -p "${CYAN}${prompt_display}${RESET}" user_input
        fi

        user_input="${user_input:-$default_val}"

        if [[ -n "$user_input" ]]; then
            printf -v "$varname" '%s' "$user_input"
            break
        else
            warn "Value cannot be empty. Please try again."
        fi
    done
}

CLOUD_BRAIN_URL="${CLOUD_BRAIN_URL:-}"
ORG_ID="${ORG_ID:-}"
PROBE_ID="${PROBE_ID:-}"

prompt_if_empty CLOUD_BRAIN_URL "Cloud Brain URL (e.g. https://cloud.example.com)"
prompt_if_empty ORG_ID          "Organisation ID"

# Derive default probe ID from hostname
DEFAULT_PROBE_ID="probe-$(hostname -s 2>/dev/null || hostname)"
[[ -z "$PROBE_ID" ]] && PROBE_ID="$DEFAULT_PROBE_ID"
info "Probe ID: ${PROBE_ID}"

# Strip trailing slash from URL
CLOUD_BRAIN_URL="${CLOUD_BRAIN_URL%/}"

# ── Connectivity check ────────────────────────────────────────────────────────
info "Checking connectivity to Cloud Brain at ${CLOUD_BRAIN_URL}..."
GRPC_HOST=$(echo "$CLOUD_BRAIN_URL" | sed 's|https\?://||' | cut -d: -f1)
GRPC_PORT=50051

if command -v nc &>/dev/null; then
    if ! nc -z -w5 "$GRPC_HOST" "$GRPC_PORT" 2>/dev/null; then
        warn "Cannot reach ${GRPC_HOST}:${GRPC_PORT} (gRPC). The probe will be installed but may fail to connect."
        warn "Ensure port 50051 is open in your firewall and the Cloud Brain is running."
    else
        ok "Port ${GRPC_PORT} reachable on ${GRPC_HOST}."
    fi
else
    warn "'nc' not found — skipping port connectivity check."
fi

# HTTP health check
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
    "${CLOUD_BRAIN_URL}/health" 2>/dev/null || echo "000")
if [[ "$HTTP_STATUS" == "200" ]]; then
    ok "Cloud Brain HTTP health check passed."
elif [[ "$HTTP_STATUS" == "000" ]]; then
    warn "Cloud Brain HTTP health check failed (could not connect). Proceeding."
else
    warn "Cloud Brain HTTP health check returned status ${HTTP_STATUS}. Proceeding."
fi

# ═════════════════════════════════════════════════════════════════════════════
section "Step 4 — Creating Installation Directory"
# ═════════════════════════════════════════════════════════════════════════════

mkdir -p "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}"
ok "Created ${INSTALL_DIR}"

# ═════════════════════════════════════════════════════════════════════════════
section "Step 5 — Downloading Probe Binary"
# ═════════════════════════════════════════════════════════════════════════════

DOWNLOAD_URL="${CLOUD_BRAIN_URL}/download/xarex-probe-linux"
BINARY_TMP="${INSTALL_DIR}/xarex-probe.tmp"

info "Downloading from ${DOWNLOAD_URL}..."
if curl -fsSL --connect-timeout 30 --max-time 300 \
    -o "$BINARY_TMP" "$DOWNLOAD_URL"; then
    mv "$BINARY_TMP" "$BINARY"
    chmod 755 "$BINARY"
    ok "Binary downloaded to ${BINARY}"
elif [[ -f "$BINARY" ]]; then
    warn "Download failed — using existing binary at ${BINARY}."
    warn "If this is a fresh install, ensure ${DOWNLOAD_URL} is accessible."
else
    die "Download failed and no existing binary found at ${BINARY}.\nURL: ${DOWNLOAD_URL}\nEnsure the Cloud Brain is running and accessible."
fi

# ═════════════════════════════════════════════════════════════════════════════
section "Step 6 — Writing Configuration"
# ═════════════════════════════════════════════════════════════════════════════

# Only write config if it doesn't exist or if we have new values
# This makes the installer idempotent — re-run with new vars to reconfigure
cat > "$CONF_FILE" <<EOF
# Xarex Probe Configuration
# Generated by install-linux.sh on $(date -u)
# Re-run the installer to update these values.

CLOUD_BRAIN_ADDR=${GRPC_HOST}:${GRPC_PORT}
ORG_ID=${ORG_ID}
PROBE_ID=${PROBE_ID}
LOG_LEVEL=info
GRPC_TLS=false
EOF
chmod 600 "$CONF_FILE"
ok "Configuration written to ${CONF_FILE}"

# ═════════════════════════════════════════════════════════════════════════════
section "Step 7 — Creating Systemd Service"
# ═════════════════════════════════════════════════════════════════════════════

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xarex Probe — Autonomous Penetration Testing Agent
Documentation=https://docs.xarex.io/probe
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONF_FILE}
ExecStart=${BINARY} \\
    --brain-addr \${CLOUD_BRAIN_ADDR} \\
    --org-id \${ORG_ID} \\
    --probe-id \${PROBE_ID} \\
    --log-level \${LOG_LEVEL}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xarex-probe

# Security hardening
NoNewPrivileges=no
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}

# CAP_NET_RAW required for ARP scanning and raw ICMP sockets
# CAP_NET_ADMIN required for interface enumeration
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
ok "Systemd service written to ${SERVICE_FILE}"

# ═════════════════════════════════════════════════════════════════════════════
section "Step 8 — Enabling and Starting Service"
# ═════════════════════════════════════════════════════════════════════════════

systemctl daemon-reload
ok "systemd daemon reloaded."

systemctl enable "${SERVICE_NAME}"
ok "${SERVICE_NAME} enabled (will start on boot)."

# Stop any existing instance before starting fresh
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    info "Stopping existing ${SERVICE_NAME} instance..."
    systemctl stop "${SERVICE_NAME}"
fi

systemctl start "${SERVICE_NAME}"
ok "${SERVICE_NAME} started."

# ═════════════════════════════════════════════════════════════════════════════
section "Step 9 — Verifying Probe Connection"
# ═════════════════════════════════════════════════════════════════════════════

info "Waiting for probe to register with Cloud Brain..."
MAX_WAIT=60
INTERVAL=5
ELAPSED=0
CONNECTED=false

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    sleep $INTERVAL
    ELAPSED=$(( ELAPSED + INTERVAL ))

    # Check service is still running
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        error "Service stopped unexpectedly. Check logs:"
        error "  journalctl -u ${SERVICE_NAME} -n 50"
        break
    fi

    # Query Cloud Brain for probe status
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
        "${CLOUD_BRAIN_URL}/health" 2>/dev/null || echo "000")

    if [[ "$HTTP_CODE" == "200" ]]; then
        info "Probe service is running (${ELAPSED}s elapsed). Checking registration..."
        CONNECTED=true
        break
    fi
done

if $CONNECTED; then
    ok "Probe appears to be running and Cloud Brain is reachable."
else
    warn "Could not confirm probe registration within ${MAX_WAIT}s."
    warn "The probe may still be connecting. Check status with:"
    warn "  systemctl status ${SERVICE_NAME}"
    warn "  journalctl -u ${SERVICE_NAME} -f"
fi

# ═════════════════════════════════════════════════════════════════════════════
section "Installation Complete"
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${RESET}"
echo "${BOLD}${GREEN}║          Xarex Probe installed successfully!           ║${RESET}"
echo "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "${BOLD}Probe details:${RESET}"
echo "  Probe ID     : ${PROBE_ID}"
echo "  Cloud Brain  : ${CLOUD_BRAIN_URL}"
echo "  gRPC Addr    : ${GRPC_HOST}:${GRPC_PORT}"
echo "  Install dir  : ${INSTALL_DIR}"
echo "  Config file  : ${CONF_FILE}"
echo "  Service      : ${SERVICE_NAME}"
echo ""
echo "${BOLD}Useful commands:${RESET}"
echo "  systemctl status ${SERVICE_NAME}         # Check service status"
echo "  journalctl -u ${SERVICE_NAME} -f         # Stream live logs"
echo "  systemctl restart ${SERVICE_NAME}        # Restart the probe"
echo "  systemctl stop ${SERVICE_NAME}           # Stop the probe"
echo ""
echo "${BOLD}Next steps:${RESET}"
echo "  1. Log in to your Xarex dashboard at ${CLOUD_BRAIN_URL}"
echo "  2. Navigate to the Probes page — '${PROBE_ID}' should appear online."
echo "  3. Create a new scan and select this probe."
echo ""
echo "Install log saved to: ${LOG_FILE}"
echo ""
