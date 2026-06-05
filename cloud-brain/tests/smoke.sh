#!/usr/bin/env bash
# Live smoke tests for POST /api/v1/leads. Run with the stack already up:
#   docker compose up -d
#   bash cloud-brain/tests/smoke.sh
set -u

URL="${1:-http://localhost:8005/api/v1/leads}"

hr()  { printf '\n── %s ──\n' "$*"; }
hit() {
  # $1 = label, $2 = JSON body
  hr "$1"
  curl -sS -w '\nHTTP=%{http_code}\n' -X POST "$URL" \
    -H 'Content-Type: application/json' \
    --data-raw "$2"
  echo
}

hit "1. Valid submission" \
    '{"email":"alice@example.com","name":"Alice","company":"Acme","size":"11-50"}'

hit "2. Honeypot triggered (should look like 201, no row)" \
    '{"email":"bot@example.com","website":"http://spam.example"}'

hit "3. Malformed email (expect 422)" \
    '{"email":"not-an-email"}'

# Build an oversized name (201 chars > 200 cap)
LONGNAME=$(head -c 201 /dev/zero | tr '\0' 'x')
hit "4. Oversized name (expect 422)" \
    "{\"email\":\"big@example.com\",\"name\":\"$LONGNAME\"}"

hit "5. Extra field rejected (expect 422)" \
    '{"email":"x@example.com","secret_admin":true}'

hr "6. Rate limit: rapid-fire 7 POSTs (expect 429 on the 6th+)"
for i in 1 2 3 4 5 6 7; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$URL" \
    -H 'Content-Type: application/json' \
    --data-raw "{\"email\":\"rapid${i}@example.com\"}")
  echo "  hit #${i} → HTTP ${code}"
done
