#!/bin/bash
K='xrx_Nngxj0XFwzRkPEi9hvUnfoGAq4BpYTnq4MSG1fKG5io'

echo '═══ ROUTING + STATIC ═══'
for p in / /signup /demo /app/ /app/css/style.css /app/js/app.js /health; do
  c=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:8005${p}")
  printf '  %-30s  HTTP %s\n' "$p" "$c"
done

echo
echo '═══ CORE DASHBOARD API ═══'
for p in /api/v1/me /api/v1/probes /api/v1/scans /api/v1/findings /api/v1/findings/stats /api/v1/scan-templates /api/v1/notifications /api/v1/threat-intel/iocs /api/v1/security-score /api/v1/breach-monitor /api/v1/domain-guardian /api/v1/footprint/scans /api/v1/guardian/scans /api/v1/integrations /api/v1/phishing /api/v1/reports /api/v1/schedules /api/v1/findings/host-risk; do
  c=$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $K" "http://localhost:8005${p}")
  printf '  %-40s  HTTP %s\n' "$p" "$c"
done

echo
echo '═══ NEW FEATURES (recon + secrets) ═══'

echo '── Subdomain enum: hackerone.com'
curl -s -X POST -H "X-API-Key: $K" -H 'Content-Type: application/json' \
  http://localhost:8005/api/v1/recon/subdomains \
  -d '{"domain":"hackerone.com","resolve":false,"max_results":10}' > /tmp/sub.json
python3 -c '
import json
d = json.load(open("/tmp/sub.json"))
print(f"   {d[\"discovered\"]} subdomains from {d[\"sources_succeeded\"]} (failed: {d[\"sources_failed\"]})")
for s in d["subdomains"][:5]:
    print(f"     {s[\"host\"]:50}")
'

echo
echo '── OSINT email harvest: protonmail.com'
curl -s -X POST -H "X-API-Key: $K" -H 'Content-Type: application/json' \
  http://localhost:8005/api/v1/recon/emails \
  -d '{"domain":"protonmail.com","check_breaches":false,"max_results":5}' > /tmp/em.json
python3 -c '
import json
d = json.load(open("/tmp/em.json"))
print(f"   {d[\"discovered\"]} emails from {d[\"sources_succeeded\"]} (failed: {d[\"sources_failed\"]})")
for e in d["emails"][:5]:
    print(f"     {e[\"email\"]:50}")
'

echo
echo '── Secrets scan: Plazmaz/leaky-repo'
curl -s -X POST -H "X-API-Key: $K" -H 'Content-Type: application/json' \
  http://localhost:8005/api/v1/secrets/scan \
  -d '{"git_url":"https://github.com/Plazmaz/leaky-repo"}' > /tmp/sec.json
python3 -c '
import json
d = json.load(open("/tmp/sec.json"))
print(f"   {d[\"total\"]} secrets · severity {d[\"by_severity\"]}")
for f in d["findings"][:5]:
    sev = {4:"CRIT",3:"HIGH",2:"MED",1:"LOW"}.get(f["severity"], "?")
    print(f"     [{sev}] {f[\"rule_name\"][:35]:35} {f[\"file\"]}:{f[\"line\"]}")
'
