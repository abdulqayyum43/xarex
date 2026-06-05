#!/usr/bin/env bash
# =============================================================================
# Xarex Probe — Docker One-Liner Generator
# =============================================================================
# Prompts for configuration and prints (then optionally runs) the correct
# docker run command for deploying the Xarex Probe as a container.
#
# Usage:
#   bash docker-run.sh                  # Interactive
#   bash docker-run.sh --run            # Interactive + run immediately
#   CLOUD_BRAIN_ADDR=host:50051 ORG_ID=abc bash docker-run.sh --run
# =============================================================================
set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()  { echo "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo "${GREEN}[ OK ]${RESET}  $*"; }
warn()  { echo "${YELLOW}[WARN]${RESET}  $*"; }
die()   { echo "${RED}[ERR ]${RESET}  $*" >&2; exit 1; }

# ── Parse flags ───────────────────────────────────────────────────────────────
RUN_NOW=false
for arg in "$@"; do
    case "$arg" in
        --run) RUN_NOW=true ;;
        --help|-h)
            echo "Usage: bash docker-run.sh [--run]"
            echo "  --run    Run the generated docker command immediately"
            exit 0 ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo "${BOLD}${CYAN}║        Xarex Probe — Docker Deployment             ║${RESET}"
echo "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Check Docker ──────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    die "Docker is not installed or not in PATH. Install Docker first: https://docs.docker.com/get-docker/"
fi

DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
ok "Docker found (version ${DOCKER_VERSION})"

# ── Prompt helpers ─────────────────────────────────────────────────────────────
prompt_if_empty() {
    local varname="$1"
    local prompt_text="$2"
    local default_val="${3:-}"

    if [[ -n "${!varname:-}" ]]; then
        info "${varname} = ${!varname} (from environment)"
        return
    fi

    local display="${prompt_text}"
    [[ -n "$default_val" ]] && display+=" [${default_val}]"
    display+=": "

    while true; do
        read -r -p "${CYAN}${display}${RESET}" user_input
        user_input="${user_input:-$default_val}"
        if [[ -n "$user_input" ]]; then
            printf -v "$varname" '%s' "$user_input"
            break
        fi
        warn "Value cannot be empty."
    done
}

# ── Gather configuration ─────────────────────────────────────────────────────
CLOUD_BRAIN_ADDR="${CLOUD_BRAIN_ADDR:-}"
ORG_ID="${ORG_ID:-}"
PROBE_ID="${PROBE_ID:-}"
IMAGE_TAG="${IMAGE_TAG:-xarex-probe:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-xarex-probe}"
LOG_LEVEL="${LOG_LEVEL:-info}"
GRPC_TLS="${GRPC_TLS:-false}"

prompt_if_empty CLOUD_BRAIN_ADDR \
    "Cloud Brain gRPC address (e.g. cloud.example.com:50051 or 192.168.1.10:50051)"

prompt_if_empty ORG_ID \
    "Organisation ID"

DEFAULT_PROBE_ID="probe-$(hostname -s 2>/dev/null || hostname)"
[[ -z "$PROBE_ID" ]] && read -r -p "${CYAN}Probe ID [${DEFAULT_PROBE_ID}]: ${RESET}" PROBE_ID
PROBE_ID="${PROBE_ID:-$DEFAULT_PROBE_ID}"

echo ""
info "Image       : ${IMAGE_TAG}"
info "Container   : ${CONTAINER_NAME}"
info "Brain addr  : ${CLOUD_BRAIN_ADDR}"
info "Org ID      : ${ORG_ID}"
info "Probe ID    : ${PROBE_ID}"
info "Log level   : ${LOG_LEVEL}"
info "gRPC TLS    : ${GRPC_TLS}"
echo ""

# ── Build the docker run command ──────────────────────────────────────────────
# Notes:
#   --network host     — Required so the probe can reach all hosts on the LAN
#                        without NAT. On macOS/Windows use host-gateway instead.
#   --cap-add NET_RAW  — Required for ARP scanning (raw sockets)
#   --cap-add NET_ADMIN — Required for interface enumeration
#   --restart unless-stopped — Keep running across reboots/crashes

DOCKER_CMD="docker run -d \\
  --name ${CONTAINER_NAME} \\
  --network host \\
  --cap-add NET_RAW \\
  --cap-add NET_ADMIN \\
  --restart unless-stopped \\
  -e CLOUD_BRAIN_ADDR=${CLOUD_BRAIN_ADDR} \\
  -e ORG_ID=${ORG_ID} \\
  -e PROBE_ID=${PROBE_ID} \\
  -e LOG_LEVEL=${LOG_LEVEL} \\
  -e GRPC_TLS=${GRPC_TLS} \\
  ${IMAGE_TAG}"

echo "${BOLD}Generated docker command:${RESET}"
echo "────────────────────────────────────────────────────"
echo "$DOCKER_CMD"
echo "────────────────────────────────────────────────────"
echo ""

# ── Copy to clipboard if available ────────────────────────────────────────────
ONELINER="docker run -d --name ${CONTAINER_NAME} --network host --cap-add NET_RAW --cap-add NET_ADMIN --restart unless-stopped -e CLOUD_BRAIN_ADDR=${CLOUD_BRAIN_ADDR} -e ORG_ID=${ORG_ID} -e PROBE_ID=${PROBE_ID} -e LOG_LEVEL=${LOG_LEVEL} -e GRPC_TLS=${GRPC_TLS} ${IMAGE_TAG}"

if command -v xclip &>/dev/null; then
    echo "$ONELINER" | xclip -selection clipboard
    ok "One-liner copied to clipboard."
elif command -v pbcopy &>/dev/null; then
    echo "$ONELINER" | pbcopy
    ok "One-liner copied to clipboard."
else
    info "Install xclip or pbcopy to auto-copy the command."
fi

# ── Optionally run immediately ────────────────────────────────────────────────
if $RUN_NOW; then
    echo ""

    # Pull image if it doesn't exist locally
    if ! docker image inspect "${IMAGE_TAG}" &>/dev/null; then
        info "Image '${IMAGE_TAG}' not found locally. Attempting to pull..."
        docker pull "${IMAGE_TAG}" || die "Failed to pull image '${IMAGE_TAG}'. Build it first: docker build -t ${IMAGE_TAG} ./probe"
    fi

    # Remove existing container of the same name
    if docker inspect "${CONTAINER_NAME}" &>/dev/null; then
        warn "Container '${CONTAINER_NAME}' already exists. Removing it..."
        docker rm -f "${CONTAINER_NAME}"
    fi

    info "Starting container..."
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --network host \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        --restart unless-stopped \
        -e "CLOUD_BRAIN_ADDR=${CLOUD_BRAIN_ADDR}" \
        -e "ORG_ID=${ORG_ID}" \
        -e "PROBE_ID=${PROBE_ID}" \
        -e "LOG_LEVEL=${LOG_LEVEL}" \
        -e "GRPC_TLS=${GRPC_TLS}" \
        "${IMAGE_TAG}"

    echo ""
    ok "Container '${CONTAINER_NAME}' started."
    echo ""
    echo "${BOLD}Useful commands:${RESET}"
    echo "  docker logs -f ${CONTAINER_NAME}          # Stream live logs"
    echo "  docker inspect ${CONTAINER_NAME}          # Container details"
    echo "  docker stop ${CONTAINER_NAME}             # Stop the probe"
    echo "  docker rm -f ${CONTAINER_NAME}            # Remove the probe"
    echo ""
    echo "${BOLD}Note:${RESET} The probe will appear in your Xarex dashboard under Probes"
    echo "      once it successfully connects to ${CLOUD_BRAIN_ADDR}."
else
    echo "${BOLD}To run it now:${RESET} bash $0 --run"
    echo "  Or copy the command above and run it manually."
fi

echo ""
