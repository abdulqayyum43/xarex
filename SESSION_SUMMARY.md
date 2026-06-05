# Xarex — Session Handoff Summary

This document captures the state of the Xarex project after the long session that built out marketing, billing, lead capture, infra hardening, and verified the test-mode payment flow. **Paste this into a fresh Claude conversation as the first message to bring the new assistant up to speed.**

---

## TL;DR — what's done

1. **Marketing site rebuild** — `website/index.html` heavily reworked. Monthly/annual pricing toggle, three tiers (Starter $49 / Pro $199 / Enterprise contact), 20% annual savings, lead-capture gate for sample report, dialog-based checkout flow, mobile nav, copy refactored from "14-day trial" to "2 free scans".
2. **Sample report** — `website/sample-report.html` (14-page polished illustrative report, served by the lead gate).
3. **Lead capture API** — `POST /api/v1/leads`. Honeypot, rate-limit (slowapi), regex whitelist on inputs, PII-minimized logging, retention scheduler (PII@90d, hard-delete@2y).
4. **Stripe billing** — `POST /api/billing/checkout/stripe` accepting `{email, tier, cadence}` with 4 price IDs (Starter/Pro × monthly/annual). Reveal-token-gated `/session-status` endpoint (closes the post-checkout credential disclosure vuln). Stripe webhook with signature verification + idempotency via unique constraint. Customer Portal endpoint NOT built yet.
5. **Two rounds of security review** — first BLOCK with 5 P0s + 5 Highs, then SHIP-WITH-CHANGES after fixes, then a final polish pass for the timing-oracle / `/subscription` credential exposure / `--workers 1` pin.
6. **48/48 unit tests passing** in `cloud-brain/tests/`.
7. **Test-mode happy path verified live** — paid via Stripe Checkout with `4242 4242 4242 4242`, webhook fired, License row provisioned, success page revealed credentials in browser.
8. **Frontend dashboard mount** — fixed (`./frontend:/frontend:ro` in `docker-compose.yml`). Dashboard accessible at `http://localhost:8005` after sign-in modal.
9. **Testlab** — 7 of 8 intentionally-vulnerable services running for scan testing.
10. **WSL2 stability** — root-caused: idle-shutdown was killing containers every 60s. Fixed via `C:\Users\abdul\.wslconfig` with `vmIdleTimeout=-1`. **User must keep one WSL terminal window open** for the duration of the dev session.

---

## Session 2026-05-22 additions

11. **Protobuf cascade rebuild** — fixed `VersionError gencode 6.31.1 runtime 5.27.0` by pinning `protobuf>=6.31.1,<7.0` in `cloud-brain/requirements.txt` and rebuilding. gRPC :50051 healthy.
12. **Probe deployed** — `xarex-probe` container built and running via `probe/deploy/docker-compose.yml` (network_mode: host, `--cap-add NET_RAW`). 15 modules registered, status: online. Scan against testlab returns real critical findings (Redis no-auth, Elasticsearch no-auth, SMTP open relay, Memcached exposed).
13. **Scanner orchestration bugs fixed** —
    - `autonomous_engine.py`: dedup key now includes port (`(scan_id, task_type, host:port)`) so `DEFAULT_CRED_TEST` fires per open port instead of once per host. Added SMTP ports 25 + 587 to `PORT_TASK_MAP`.
    - `task_manager.py`: pending-task counter now tracks autonomously-queued tasks so the scan waits for full task drain instead of completing 1 second after `HOST_DISCOVERY`.
14. **`provision_license` Org-creation bug fixed** — `services/billing.py` now creates the matching `Org` row alongside `License` so a paying customer's `api_key` actually authenticates against `/api/v1/scans`. Backfills any pre-existing License missing its Org. Unique `Org.name` via `f"{customer.name} [{org_id[:8]}]"`. 48/48 tests pass. Live e2e verified.
15. **Dashboard tour** — all 24 dashboard data endpoints + 5 per-scan endpoints + dashboard HTML/JS return 200/201. Functional.
16. **Deploy Probe page rewritten** — beginner-friendly, plain-English steps, `xarex.com` URLs everywhere (no more localhost in customer-facing docs), real `org_id` from new `GET /api/v1/me` endpoint, ~520 lines of new CSS, three install methods (Linux/Docker/Windows) verified in real browser.
17. **4 new features shipped** — recon + secrets layer:
    - **Subdomain enumeration** (`POST /api/v1/recon/subdomains`) — crt.sh + HackerTarget + AlienVault OTX + Cloudflare DoH resolution. New dashboard tab under Recon.
    - **OSINT email harvest** (`POST /api/v1/recon/emails`) — crt.sh cert SANs + PGP keyservers, enriched with HIBP if `HIBP_API_KEY` set. New dashboard tab under Recon.
    - **Secrets / git scanner** (`POST /api/v1/secrets/scan`) — clones any public HTTPS git URL into temp dir (100 MB cap, 60 s wall clock, HTTPS-only SSRF defence), regex-scans 20+ secret patterns (AWS, Stripe, Anthropic, OpenAI, GitHub PATs, Slack tokens, PEM private keys, env passwords, etc.). New dashboard tab under Protect. Requires `git` in the cloud-brain Docker image (added to Dockerfile).
    - **Nuclei templated scans** (probe-side `NUCLEI_SCAN` task type) — wraps upstream nuclei binary (Apache 2.0, pinned 3.3.7 via `NUCLEI_VERSION` ARG in `probe/Dockerfile`) with community templates cloned at build time. Auto-fires on web ports (80/443/8080/8443) via `PORT_TASK_MAP`. Findings flow into existing Findings page via gRPC ScanResult — no new UI. **Verified end-to-end**: testlab scan produced 24 persisted findings including 6 HIGH-severity Redis default-login matches.

### Gotchas worth knowing
- **Nuclei `-t` flag is mandatory**: the `NUCLEI_TEMPLATES_DIR` env var is unreliable across Docker setups. `probe/scanner/nuclei.go` always passes `-t /opt/nuclei-templates` explicitly. If you change the templates path, update the `defaultNucleiTemplates` constant.
- **NUL-byte poisoning**: Nuclei (and any scanner that captures binary-protocol responses like Redis / memcached) sometimes returns raw `\x00` bytes in the evidence field. Postgres rejects NUL bytes in text columns with `CharacterNotInRepertoireError` and the whole batch insert fails atomically. Both `probe/scanner/nuclei.go` and `cloud-brain/orchestrator/task_manager.py` now scrub NUL bytes defensively.
- **Templates pulled via `git clone` not `nuclei -update-templates`**: the upstream updater is flaky in Docker (no TTY). The probe Dockerfile installs `git`, clones `projectdiscovery/nuclei-templates --depth 1` to `/opt/nuclei-templates`, then removes git to keep the runtime image small.
- **Browser caches `/js/app.js` aggressively**: after dashboard JS changes, hit Ctrl-Shift-R or the new code won't load. Functions register as `undefined` if you skip this.
- **The cloud-brain `Dockerfile` now installs `git`** (for the secrets scanner's `git clone`). Rebuilt and verified persistent (`/usr/bin/git` is in the image now).

### Polish round (same session, after the 4 features shipped)

18. **Duplicate findings eliminated** — pruned `PER_HOST_CHECKS` in `cloud-brain/orchestrator/task_manager.py` down to the truly port-agnostic checks (`PORT_SCAN`, `LLMNR_POISON_CHECK`, `SNMP_COMMUNITY_STRING`, `DNS_ZONE_TRANSFER`). The autonomous engine handles every per-port check via `PORT_TASK_MAP`, so listing them in `PER_HOST_CHECKS` too was making every web-port finding appear twice. Verified: a fresh testlab scan now shows exactly 1 of each "Missing security header" finding instead of 2.
19. **Pipeline counter race fixed** — `_run_autonomous_engine` now ALWAYS increments `_pending_tasks[scan_id]`, initialising it to 0 if missing. Previously, autonomous tasks queued from HOST_DISCOVERY findings (SNMP, DNS zone transfer) were never counted, so they decremented the counter without ever incrementing it — premature scan completion before PORT_SCAN finished.
20. **Browser-cache-bust headers** — `cloud-brain/main.py` now wraps the frontend `StaticFiles` mount in `_RevalidatingStatic` which adds `Cache-Control: no-cache, must-revalidate` to every HTML/JS/CSS response. Browsers still get cheap 304s via ETag, but they never serve stale JS after a deploy. Eliminates the "function not defined after deploy" footgun.
21. **Tests still green** — 48/48 cloud-brain unit tests pass after the polish round.

### Marketing-site overhaul + demo page (this session, after polish)

22. **Routing reorganised** — `cloud-brain/main.py` now mounts the **marketing site at `/`** and the **dashboard at `/app/`**. Previously `localhost:8005` dropped you straight into the dashboard (because the only mount was `frontend/` at root, and cached localStorage credentials auto-signed-in). Marketing site lives in `website/`, mounted via the same `_RevalidatingStatic` wrapper. `/signup` and `/demo` are FastAPI route handlers that 302-redirect to `/app/` and `/demo.html` respectively. `docker-compose.yml` gained `./website:/website:ro` mount. `frontend/index.html` switched from absolute (`/css/style.css`) to relative (`css/style.css`) asset paths so the dashboard works from any base path.
23. **4 new feature cards added to marketing** — `website/index.html` features-grid now includes Subdomain Enumeration, OSINT Email Harvest, Secrets/Git Scanner, and 9,000+ Templated CVE Checks. Each tagged "New". Subtitle updated from "16 purpose-built features" → "20+ purpose-built features…". Demo link added to both desktop + mobile nav.
24. **Typography polish** — section + feature titles use `text-wrap: balance` (no orphan words), body copy uses `text-wrap: pretty` + `hyphens: auto` for clean line breaks. Section subtitle max-width bumped 560 → 640px for better reading rhythm.
25. **NEW: `website/demo.html`** — 7-section feature showcase with sticky TOC, sample-data mockups of each feature output, "Why this matters" panels with real-world customer scenarios, and modern panel designs (glass cards, gradient accents, JetBrains Mono labels). Justified body text on long paragraphs in the AI-report section. Bottom CTA + footer. 1 single-file standalone HTML (~700 lines), no JS framework, deploys identically with the rest of `website/`.

### Known intermittent issues (not blocking)

- **Cloud-brain container restart cycle** — Docker Desktop / WSL2 backgrounds the container roughly every 60–180 s. Docker events show clean shutdown (exit 0, OOMKilled=false, memory 110 MiB / 31 GiB limit, healthcheck disabled). Cycle persists with healthcheck off, restart policy unchanged, and across both probe-up and probe-down states. Bug is in the host environment (WSL2 → Docker Desktop scheduling, possibly), not the app code. Service recovers in ~30 s. Production hosting on Fly.io won't have this issue.
- **Probe-disconnect bug (task 28)** — ScanStream ending triggers cloud-brain shutdown. Deferred for diagnosis. Workaround: restart probe after cloud-brain.

---

## Operational notes for next session

- **Cloud-brain + probe restart order matters.** When you restart cloud-brain, the probe's ScanStream gets stuck (probe doesn't auto-recover the in-flight gRPC stream properly — known long-standing bug). Workaround: always `docker restart xarex-probe` right after `docker restart xarex-cloud-brain`. Symptom if you forget: scans submit, HOST_DISCOVERY runs on the probe, no further tasks dispatch.
- **Default org credentials still valid**: Test Org `61d48eb4-…`, api_key `xrx_Nngxj0XFwzRkPEi9hvUnfoGAq4BpYTnq4MSG1fKG5io` (dev only — rotate before shipping).
- **Probe templates location**: `/opt/nuclei-templates` baked into the probe image. Update via probe Docker rebuild.

---

## Remaining launch-prep items (need user action — can't be automated)

**A full step-by-step ship guide lives in [LAUNCH_RUNBOOK.md](LAUNCH_RUNBOOK.md).** TL;DR:

1. **Domain** — Cloudflare Registrar, ~$10/yr. (~15 min)
2. **Marketing site** — Cloudflare Pages from `website/` git repo. Free. (~30 min)
3. **Cloud-brain** — Fly.io: shared-cpu-1x app + managed Postgres. ~$22/mo total. (~2-3 hrs)
4. **Live Stripe** — rotate `sk_live_…`, recreate 4 prices in live mode, register webhook at `https://api.xarex.com/api/billing/webhook/stripe`. (~1 hr)
5. **Resend + DNS** — add DKIM/SPF/DMARC records in Cloudflare, generate API key. (~1 hr)
6. **End-to-end smoke** — fresh-incognito-from-phone test of the full signup → probe → scan flow. (~30 min)

Total: ≈ 8 hours of focused work for a complete launch. The runbook is opinionated — each decision picks one path with rationale, so no comparison shopping needed.

---

## Current credentials (test mode, dev-only)

```
Org name:        Test Org
Org ID:          61d48eb4-53b9-4e49-8e2e-63e943f9dac5
API key:         xrx_Nngxj0XFwzRkPEi9hvUnfoGAq4BpYTnq4MSG1fKG5io
Stripe customer: cus_UWpY88bekxVyra (from smoke test)
Smoke-test plan: xarex_starter (Annual, $470/yr) → active in Postgres
```

**Critical: the live `sk_live_…` Stripe key that was sitting in `.env` should be rotated in the Stripe Dashboard.** I told the user to do this but I don't know if it's been done.

---

## What's running right now (assuming WSL terminal stays open)

```
http://localhost:8005          Dashboard + API
http://localhost:8005/docs     OpenAPI Swagger UI
http://localhost:5432          Postgres (xarex / xarex)
http://localhost:50051         gRPC (probe channel) — BROKEN, see below
file:///.../website/index.html Marketing site
file:///.../website/sample-report.html Sample report

Testlab vulnerable services (intentionally exposed):
  redis-noauth     :6379
  mongo-noauth     :27017
  elasticsearch    :9200
  ftp-anonymous    :21
  memcached        :11211
  smtp-openrelay   :25
  nginx-baseline   :8080
  nginx-oldtls     — WON'T START (WSL2 single-file mount quirk)
```

---

## Known issues + their state

### 1. gRPC protobuf version mismatch (blocks probe registration) — STILL BROKEN

- Error: `google.protobuf.runtime_version.VersionError: gencode 6.31.1 runtime 5.27.0`
- **First fix attempt failed.** I initially pinned `protobuf>=5.31.1,<6.0`. That doesn't resolve — protobuf python jumped from 5.29.6 straight to 6.30.0 (skipping 5.30/5.31 entirely). The build erred with `No matching distribution found for protobuf<6.0,>=5.31.1`. Container kept running on the old cached image.
- **Corrected pin is now in `cloud-brain/requirements.txt`**: `protobuf>=6.31.1,<7.0` (matches the gencode version directly).
- **A third rebuild WAS kicked off in the background** with the corrected pin right before this session ended (background task `b2bk0hmys`, output at `C:\Users\abdul\AppData\Local\Temp\claude\C--Users-abdul-OneDrive-Desktop-projs-phantom\f5f065bc-3c17-44fb-8a53-2e3e1ed3088c\tasks\b2bk0hmys.output`). It may have completed by the time the next session starts. **First step in the new session is to verify whether that build succeeded**:
  ```bash
  tail -5 "C:\Users\abdul\AppData\Local\Temp\claude\C--Users-abdul-OneDrive-Desktop-projs-phantom\f5f065bc-3c17-44fb-8a53-2e3e1ed3088c\tasks\b2bk0hmys.output"
  ```
  Look for `Container xarex-cloud-brain Started` or an `ERROR` line. If the build succeeded, jump straight to the `VersionError` check below. If it errored OR is missing, re-run:
  ```bash
  wsl.exe -- bash -c "cd /mnt/c/Users/abdul/OneDrive/Desktop/projs/phantom && docker compose build --no-cache cloud-brain && docker compose up -d cloud-brain --force-recreate"
  ```
  Then verify:
  ```bash
  wsl.exe -- bash -c "docker logs xarex-cloud-brain 2>&1 | grep VersionError | tail -3"
  ```
  Empty = fixed. Any output = pin still wrong (try `protobuf>=6.32` or regenerate proto stubs).
- **Watch for cascading breakage**: bumping protobuf to 6.x is a major version bump. If FastAPI / Pydantic / any other dep is incompatible, the rebuild will fail elsewhere. If that happens, the fallback is to regenerate the proto stubs with an OLDER protoc instead of bumping protobuf: run `python -m grpc_tools.protoc -I=. --python_out=. --grpc_python_out=. xarex.proto` from `cloud-brain/proto/` using the installed `grpcio-tools==1.64.0`.

### 2. `provision_license` does NOT create an Org row (real bug, not yet fixed)

- Stripe checkout completes successfully, License row is provisioned with an `org_id`, but the corresponding Org row is never created. Result: the `api_key` issued to a paying customer cannot authenticate against `/api/v1/scans` etc.
- Workaround for this session: provisioned a Test Org via admin endpoint (`POST /api/v1/admin/orgs` with `X-Admin-Secret: xarex-admin-secret`).
- **Must be fixed before real customers can use the product.** Dispatch `revenue-ops` agent: "Fix `services/billing.py::provision_license` to create an Org row (with the License's `api_key` and the customer's name) when transitioning a Customer from no-license to having a paid license."

### 3. Resend welcome email — `403 Forbidden`

- `EMAIL_FROM` is set to `onboarding@resend.dev` (the Resend sandbox sender — works without domain verification). The 403 means `RESEND_API_KEY` is either missing or invalid in `.env`.
- The user does NOT own a real domain yet — `xarexsec.io` was placeholder copy. They plan to register one before launch.
- Until then: keep `EMAIL_FROM=onboarding@resend.dev` and just make sure `RESEND_API_KEY` is set. Then welcome emails will arrive from "Xarex Security <onboarding@resend.dev>".

### 4. `nginx-oldtls` testlab service won't start (low priority)

- WSL2 can't bind-mount a single file from a Windows-side path. Fails with `not a directory: Are you trying to mount a directory onto a file?`
- Workaround: copy the conf into a directory mount, OR skip this service. The other 7 testlab services are sufficient for scan testing.

### 5. Container healthcheck reports "unhealthy" (cosmetic)

- The healthcheck uses `curl -f http://localhost:8005/health` but the Python slim image doesn't include `curl`. The API works fine; the healthcheck always fails. Either install curl in the Dockerfile or rewrite the healthcheck to use `python -c "import urllib.request; urllib.request.urlopen('http://localhost:8005/')"`.

### 6. WSL2 idle shutdown was killing everything every 60 seconds

- FIXED via `C:\Users\abdul\.wslconfig`:
  ```ini
  [wsl2]
  vmIdleTimeout=-1
  memory=8GB
  ```
- User must run `wsl --shutdown` once to apply, then keep one WSL terminal open.

---

## Where the user is in the journey

**Done in this session:**
- Built the full marketing → checkout → provision → reveal-credentials flow
- Two security audits + remediation passes
- 48 unit tests passing
- Test-mode E2E happy path verified with a real Stripe Checkout payment
- Dashboard is now accessible at `http://localhost:8005` (after fixing the frontend mount, the protobuf bug, and WSL2 idle shutdown)

**Immediate next steps (in order):**

1. **Confirm protobuf rebuild succeeded** — query the gRPC error pattern as shown above.
2. **Deploy a probe + run a scan** — give the user the probe deploy steps below. This validates the end-to-end scan flow.
3. **Tour the dashboard** — every page (Scans, Findings, Attack Paths, Reports, Probes, Schedules, Breach Monitor, Domain Guardian, Security Score, Threat Intelligence, Compliance, Tools, Deploy Probe).
4. **Fix the `provision_license` Org-creation bug** — blocking before any real customer signups.
5. **Buy a domain + pick hosting** — user hasn't done this yet. Stack to host: marketing site (static HTML → Cloudflare Pages/Netlify), cloud-brain (FastAPI + Postgres → Fly.io or Railway), domain via Cloudflare Registrar.
6. **Production Stripe cutover** — flip Stripe Dashboard to live mode, recreate products/prices, register live webhook, rotate the `sk_live_…` key that was sitting in `.env`, set `ENVIRONMENT=production` so the live-key-in-dev warning stays quiet.

---

## Probe deploy steps (give to user after protobuf fix is confirmed)

The probe is a Go binary in `probe/` that connects to cloud-brain via gRPC, registers under an org, receives scan tasks, and streams findings back. To deploy locally for testing:

```bash
# In the WSL terminal the user is keeping open, from the project root:
cd /mnt/c/Users/abdul/OneDrive/Desktop/projs/phantom/probe

# Option A: run the prebuilt binary natively (fast)
sudo ./run-probe.sh
# It reads probe/xarex.conf for cloud-brain URL + api_key.
# Edit xarex.conf if needed:
#   cloud_brain_grpc = "localhost:50051"
#   api_key          = "xrx_Nngxj0XFwzRkPEi9hvUnfoGAq4BpYTnq4MSG1fKG5io"
#   probe_id         = "probe-dev-01"

# Option B: run via Docker (cleaner isolation, joins the same Docker network)
docker compose -f deploy/docker-compose.yml up -d
```

After the probe is running, it should register with cloud-brain. Verify:

```bash
curl -s -H 'X-API-Key: xrx_Nngxj0XFwzRkPEi9hvUnfoGAq4BpYTnq4MSG1fKG5io' \
  http://localhost:8005/api/v1/probes | python3 -m json.tool
```

You should see one probe entry with `status: "online"`.

Then start a scan from the dashboard:
- Navigate to **Scans** → **New Scan**
- Target: `127.0.0.1` (will scan the testlab services running on host ports)
- Or target the testlab Docker network if probe is in Docker
- Click **Start scan**
- Watch findings stream in real-time on the dashboard

Expected findings from the testlab:
- **CRITICAL** Redis no-auth on :6379
- **CRITICAL** MongoDB no-auth on :27017
- **CRITICAL** Elasticsearch no-auth on :9200
- **HIGH** FTP anonymous login on :21
- **HIGH** Memcached exposed on :11211
- **HIGH** SMTP open relay on :25
- **INFO** Nginx baseline fingerprint on :8080

---

## Files touched this session (high-level inventory)

```
NEW    cloud-brain/api/leads.py
NEW    cloud-brain/services/turnstile.py
NEW    cloud-brain/services/retention.py
NEW    cloud-brain/services/pii.py
NEW    cloud-brain/limiter.py
NEW    cloud-brain/tests/{__init__.py,conftest.py,test_leads.py,test_billing.py,smoke.sh}
NEW    cloud-brain/pytest.ini
NEW    cloud-brain/requirements-dev.txt
NEW    cloud-brain/.env.example  (updated to current shape)
NEW    website/sample-report.html
NEW    SESSION_SUMMARY.md  (this file)
EDIT   cloud-brain/main.py                 — CORS tightening, slowapi wiring, frontend mount path
EDIT   cloud-brain/config.py               — CORS_ORIGINS, LEAD_*, TURNSTILE_*, 4-tier STRIPE_PRICE_*, sk_live warning
EDIT   cloud-brain/requirements.txt        — slowapi, protobuf>=5.31, grpcio>=1.68
EDIT   cloud-brain/api/billing.py          — Pydantic tier/cadence Literals, session-status reveal-token gate, success-page polling HTML, /subscription credential strip
EDIT   cloud-brain/services/billing.py     — create_stripe_checkout(tier,cadence), webhook tier-from-price-id, reveal-token store, payload minimization, _to_plain_dict for Stripe object recursion
EDIT   cloud-brain/models/tables.py        — Lead table + composite index, BillingEvent unique constraint on provider_event_id
EDIT   cloud-brain/services/scheduler.py   — daily retention job at 03:30 UTC
EDIT   docker-compose.yml                  — ./frontend mount, removed --reload (OneDrive sync caused thrash), workers=1 SECURITY pin comment
EDIT   website/index.html                  — pricing toggle, tier CTAs, copy rewrite, checkout dialog, file:// XAREX_API_BASE auto-default
EDIT   frontend/index.html + js/app.js     — tier+cadence in checkout modal, monthly/annual toggle
EDIT   cloud-brain/.env                    — (locally edited by user; contains real Stripe + Resend keys; not committed)
```

---

## How to resume work after starting a fresh Claude conversation

After pasting this file into a new conversation, the new assistant should:

1. **Re-verify the env is up** (assuming the user kept their WSL terminal alive):
   ```bash
   wsl.exe -- bash -c "docker ps --format 'table {{.Names}}\t{{.Status}}'"
   wsl.exe -- bash -c "curl -s -o /dev/null -w 'HTTP=%{http_code}\n' http://localhost:8005/"
   ```
   If WSL terminal was closed → user runs `wsl` again, then `cd /mnt/c/.../phantom && sudo service docker start && docker compose up -d`.

2. **Check whether the protobuf fix landed**:
   ```bash
   wsl.exe -- bash -c "docker logs xarex-cloud-brain 2>&1 | grep VersionError | tail -3"
   ```
   Empty output → fix worked. Output → re-run the rebuild.

3. **Proceed to probe deploy** (steps in this file).

4. **After probe → fix `provision_license` Org bug** — dispatch revenue-ops agent.

5. **Then the launch sequence**: domain registration → marketing-site hosting → cloud-brain hosting → DNS for Resend domain → live Stripe cutover.

---

## Tone / interaction preferences observed

- User prefers concrete, decisive answers over hedging.
- User got frustrated with repeated technical detours (Docker install, WSL networking, Chrome cache, protobuf mismatch) — keep diagnostics fast and offer concrete fixes, not "try this and tell me what happens" loops when avoidable.
- User is a builder, not a security/infra specialist — explain WHY a fix is needed, not just HOW.
- They want to ship and start getting customers in the next ~week or two.
- They paid for at least one test-mode Stripe transaction during the session (refundable in dashboard).

Good luck. The architecture is solid; the remaining work is mostly the Org-creation bug, the protobuf rebuild confirmation, the probe deploy, and the launch logistics.
