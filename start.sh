#!/usr/bin/env bash
# =============================================================================
# Xarex — Local Development Startup Script
# =============================================================================
# Run from the xarex/ root directory.
#
# Usage:
#   bash start.sh              # Start in development mode (hot reload)
#   bash start.sh --prod       # Start in production mode (no reload, 2 workers)
#   bash start.sh --help       # Show this help
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
error() { echo "${RED}[ERR ]${RESET}  $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Paths ─────────────────────────────────────────────────────────────────────
XAREX_DIR="$(cd "$(dirname "$0")" && pwd)"
BRAIN_DIR="$XAREX_DIR/cloud-brain"
PROTO_SRC="$XAREX_DIR/shared/proto/xarex.proto"
PROTO_OUT="$BRAIN_DIR/proto"

# ── Flags ─────────────────────────────────────────────────────────────────────
PROD_MODE=false

for arg in "$@"; do
    case "$arg" in
        --prod)
            PROD_MODE=true
            ;;
        --help|-h)
            echo ""
            echo "${BOLD}Xarex — Local Development Startup${RESET}"
            echo ""
            echo "Usage: bash start.sh [options]"
            echo ""
            echo "Options:"
            echo "  (none)      Start in development mode — hot reload enabled, log level info"
            echo "  --prod      Start in production mode — no reload, 2 workers, log level warning"
            echo "  --help      Show this help message"
            echo ""
            echo "Environment:"
            echo "  The script reads cloud-brain/.env if it exists."
            echo "  Required: DATABASE_URL, ADMIN_SECRET"
            echo "  Optional: ANTHROPIC_API_KEY, SLACK_WEBHOOK_URL, NVD_API_KEY"
            echo ""
            echo "Ports:"
            echo "  HTTP API + Dashboard : http://localhost:8005"
            echo "  API docs (Swagger)   : http://localhost:8005/docs"
            echo "  gRPC (probe channel) : localhost:50051"
            echo ""
            exit 0
            ;;
        *)
            die "Unknown flag: $arg. Run 'bash start.sh --help' for usage."
            ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
echo "${BOLD}${CYAN}║        Xarex Cloud Brain — Local Dev           ║${RESET}"
if $PROD_MODE; then
echo "${BOLD}${CYAN}║                  PRODUCTION MODE                ║${RESET}"
fi
echo "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Step 1 — PostgreSQL
# ═════════════════════════════════════════════════════════════════════════════
echo "[1/4] ${BOLD}Checking PostgreSQL...${RESET}"

start_postgres() {
    if sudo service postgresql start 2>/dev/null; then
        return 0
    elif sudo systemctl start postgresql 2>/dev/null; then
        return 0
    fi
    return 1
}

if pg_isready -U xarex -h localhost -p 5432 -q 2>/dev/null; then
    ok "PostgreSQL is already running."
else
    info "PostgreSQL not ready. Attempting to start..."
    if ! start_postgres; then
        warn "Could not start PostgreSQL automatically."
        warn "Start it manually: sudo systemctl start postgresql"
        warn "Then re-run this script."
        die "PostgreSQL is required but could not be started."
    fi

    # Give PostgreSQL a moment to initialise
    sleep 2

    if ! pg_isready -U xarex -h localhost -p 5432 -q 2>/dev/null; then
        info "PostgreSQL started but 'xarex' user/database not found. Creating them..."
        sudo -u postgres psql -c "CREATE USER xarex WITH PASSWORD 'xarex';" 2>/dev/null \
            || info "  (user may already exist)"
        sudo -u postgres psql -c "CREATE DATABASE xarex OWNER xarex;" 2>/dev/null \
            || info "  (database may already exist)"
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE xarex TO xarex;" 2>/dev/null \
            || true

        sleep 1
        if ! pg_isready -U xarex -h localhost -p 5432 -q 2>/dev/null; then
            die "PostgreSQL started but 'xarex' database is still not ready. Check PostgreSQL logs."
        fi
    fi
    ok "PostgreSQL is ready."
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 2 — Proto Stubs
# ═════════════════════════════════════════════════════════════════════════════
echo "[2/4] ${BOLD}Checking proto stubs...${RESET}"

if [[ ! -f "$PROTO_OUT/xarex_pb2.py" ]]; then
    info "Proto stubs not found. Generating..."

    if ! python3 -m grpc_tools.protoc --version &>/dev/null 2>&1; then
        warn "grpc_tools not installed. Installing..."
        pip install grpcio-tools --break-system-packages -q \
            || pip install grpcio-tools -q \
            || die "Failed to install grpcio-tools. Run: pip install grpcio-tools"
    fi

    mkdir -p "$PROTO_OUT"
    if ! python3 -m grpc_tools.protoc \
        -I "$XAREX_DIR/shared/proto" \
        --python_out="$PROTO_OUT" \
        --grpc_python_out="$PROTO_OUT" \
        "$PROTO_SRC"; then
        die "Proto generation failed. Ensure '$PROTO_SRC' exists and is valid."
    fi
    ok "Proto stubs generated."
else
    ok "Proto stubs are up to date."
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 3 — Python Dependencies
# ═════════════════════════════════════════════════════════════════════════════
echo "[3/4] ${BOLD}Checking Python dependencies...${RESET}"

cd "$BRAIN_DIR"

REQUIRED_PACKAGES="fastapi sqlalchemy asyncpg grpc networkx structlog anthropic apscheduler croniter"
MISSING_PACKAGES=()

for pkg in $REQUIRED_PACKAGES; do
    # Map package name to import name for packages that differ
    import_name="$pkg"
    case "$pkg" in
        grpc) import_name="grpc" ;;
        asyncpg) import_name="asyncpg" ;;
    esac
    if ! python3 -c "import $import_name" 2>/dev/null; then
        MISSING_PACKAGES+=("$pkg")
    fi
done

if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
    warn "Missing packages: ${MISSING_PACKAGES[*]}"
    info "Installing from requirements.txt..."
    pip install -r requirements.txt --break-system-packages -q 2>/dev/null \
        || pip install -r requirements.txt -q \
        || die "Failed to install dependencies. Run manually: pip install -r cloud-brain/requirements.txt"
    ok "Dependencies installed."
else
    ok "All Python dependencies are present."
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 4 — Start Cloud Brain
# ═════════════════════════════════════════════════════════════════════════════
echo "[4/4] ${BOLD}Starting Cloud Brain...${RESET}"

# Determine local IP (WSL2 / Linux)
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
if $PROD_MODE; then
    echo "  ${BOLD}Mode        :${RESET} Production (2 workers, no reload)"
else
    echo "  ${BOLD}Mode        :${RESET} Development (hot reload enabled)"
fi
echo "  ${BOLD}HTTP API    :${RESET} http://localhost:8005"
echo "  ${BOLD}Dashboard   :${RESET} http://localhost:8005"
echo "  ${BOLD}Swagger     :${RESET} http://localhost:8005/docs"
echo "  ${BOLD}gRPC        :${RESET} localhost:50051"
echo "  ${BOLD}Local IP    :${RESET} ${LOCAL_IP} (use for probe CLOUD_BRAIN_ADDR: ${LOCAL_IP}:50051)"
echo ""
echo "  ${BOLD}First-time setup — create your organisation:${RESET}"
echo "  ${CYAN}curl -X POST http://localhost:8005/api/v1/admin/orgs \\${RESET}"
echo "  ${CYAN}  -H \"X-Admin-Secret: \$(grep ADMIN_SECRET .env | cut -d= -f2)\" \\${RESET}"
echo "  ${CYAN}  -H \"Content-Type: application/json\" \\${RESET}"
echo "  ${CYAN}  -d '{\"name\": \"My Organisation\"}'${RESET}"
echo ""
echo "  Press ${BOLD}Ctrl+C${RESET} to stop."
echo "  ────────────────────────────────────────────────────"
echo ""

# Build uvicorn command based on mode
UVICORN_ARGS=(
    "main:app"
    "--host" "0.0.0.0"
    "--port" "8005"
    "--log-level" "info"
)

if $PROD_MODE; then
    UVICORN_ARGS+=("--workers" "2")
    # Swap log level to warning in prod
    for i in "${!UVICORN_ARGS[@]}"; do
        [[ "${UVICORN_ARGS[$i]}" == "info" ]] && UVICORN_ARGS[$i]="warning"
    done
else
    UVICORN_ARGS+=("--reload")
fi

cd "$BRAIN_DIR"
exec python3 -m uvicorn "${UVICORN_ARGS[@]}"
