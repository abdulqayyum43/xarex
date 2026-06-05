FROM python:3.12-slim

# --- system dependencies ---
# git is needed by services/secrets_scanner.py (shallow-clones public
# repos into /tmp, scans for leaked credentials, then deletes the dir).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python dependencies (layer-cached) ---
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# --- Application code ---
COPY . .

# Expose HTTP + gRPC ports
EXPOSE 8005 50051

# Default runtime command.
# SECURITY: --workers MUST stay at 1 until services/billing.py::_REVEAL_TOKENS
# moves to Redis. The reveal-token store is process-local — multi-worker would
# randomly 404 /session-status polls and break the post-checkout credential
# reveal flow. See SECURITY note in services/billing.py near _REVEAL_TOKENS.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005", "--workers", "1", "--log-level", "info"]
