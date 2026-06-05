# Xarex — Autonomous Penetration Testing Platform

> **Xarex** is a production-grade autonomous penetration testing platform built on a hybrid architecture. A lightweight Go **Probe** deploys inside the target network and performs all active scanning. The Python **Cloud Brain** orchestrates tasks, stores results, computes attack paths, runs AI analysis, and serves the web dashboard — no manual step-by-step operator involvement required after a scan is launched.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start — 5 Minutes](#quick-start--5-minutes)
3. [Cloud Brain Deployment](#cloud-brain-deployment)
   - [Local Development](#local-development)
   - [Production — Docker Compose](#production--docker-compose)
   - [Environment Variables Reference](#environment-variables-reference)
4. [Probe Deployment](#probe-deployment)
   - [Linux (systemd)](#linux-systemd)
   - [Docker](#docker)
   - [Windows](#windows)
   - [Kubernetes (Helm)](#kubernetes-helm)
5. [Running Your First Scan](#running-your-first-scan)
   - [Creating a Scan via API](#creating-a-scan-via-api)
   - [Creating a Scan via Dashboard](#creating-a-scan-via-dashboard)
   - [Understanding the Scan Pipeline](#understanding-the-scan-pipeline)
6. [Scan Modules Reference](#scan-modules-reference)
7. [Report Generation](#report-generation)
8. [API Reference](#api-reference)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Overview

### Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    CLOUD BRAIN (Python/FastAPI)            │
│                                                            │
│  HTTP :8005 (REST + WebSocket)    gRPC :50051              │
│  PostgreSQL backend               NetworkX graph engine    │
│                                                            │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Task Manager │  │  Graph Engine│  │ Autonomous     │  │
│  │  (pipeline)   │  │  (NetworkX)  │  │ Engine (rules) │  │
│  └───────────────┘  └──────────────┘  └────────────────┘  │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  AI Analyst   │  │  CVE Enricher│  │  Notifier      │  │
│  │  (Claude)     │  │  (NVD/EPSS)  │  │  (Slack/webhook│  │
│  └───────────────┘  └──────────────┘  └────────────────┘  │
│  ┌───────────────┐  ┌──────────────┐                       │
│  │  APScheduler  │  │  Report Gen  │                       │
│  │  (cron scans) │  │  (HTML)      │                       │
│  └───────────────┘  └──────────────┘                       │
└──────────────────────────┬─────────────────────────────────┘
                           │ gRPC bidirectional stream
                           │ (TLS optional)
┌──────────────────────────▼─────────────────────────────────┐
│                   GO PROBE (per network)                   │
│                                                            │
│  Deployed inside the target network segment                │
│  Requires CAP_NET_RAW for ARP/ICMP scanning               │
│                                                            │
│  ARP Scanner · Port Scanner · Service Fingerprinter        │
│  Credential Checker · SMB Relay · LLMNR Detector          │
│  Active Directory Enumerator · Kerberoast/AS-REP           │
└────────────────────────────────────────────────────────────┘
```

### Key Design Principles

| Principle | Detail |
|-----------|--------|
| Probe-only scanning | The Cloud Brain never touches the target network directly — all active scanning is done by the Probe |
| Non-destructive | Xarex reads and tests — it never exploits, modifies, or writes to target systems |
| Full autonomy | One scan launch triggers the entire chain: discovery → enumeration → specialised checks → AI analysis → report |
| Multi-tenancy | All resources are scoped to an Organisation; multiple teams/clients can share one Cloud Brain |
| Zero-retention probe | The Probe holds no persistent state; all findings are streamed to the Cloud Brain immediately |

---

## Quick Start — 5 Minutes

**Prerequisites:** Docker and Docker Compose installed.

```bash
# 1. Clone and enter the project
git clone https://github.com/your-org/xarex.git
cd xarex

# 2. Create environment file
cp .env.example .env
# Edit .env — set ADMIN_SECRET and (optionally) ANTHROPIC_API_KEY

# 3. Start the Cloud Brain + PostgreSQL
docker compose up -d

# 4. Create your first organisation
curl -X POST http://localhost:8005/api/v1/admin/orgs \
  -H "X-Admin-Secret: $(grep ADMIN_SECRET .env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Organisation"}'
# Returns: { "id": "...", "name": "My Organisation", "api_key": "xrx_..." }

# 5. Open the dashboard
# → http://localhost:8005
# Paste your api_key into the top bar and click Connect

# 6. Deploy the Probe inside your target network (see Probe Deployment below)
```

---

## Cloud Brain Deployment

### Local Development

The `start.sh` helper script handles PostgreSQL, proto stub generation, dependency checks, and server startup in one command.

```bash
cd xarex/
bash start.sh          # Start in development mode (hot reload)
bash start.sh --prod   # Start in production mode (no reload, 2 workers)
bash start.sh --help   # Show all options
```

Manual startup without the helper:

```bash
cd cloud-brain/
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8005 --reload
```

The server starts on **http://localhost:8005**.  
gRPC listens on **:50051**.

### Production — Docker Compose

#### Development Compose (with hot reload)

```bash
# Start
docker compose up -d

# View logs
docker compose logs -f cloud-brain

# Stop
docker compose down
```

#### Production Compose (immutable image, Nginx, SSL)

```bash
# 1. Configure environment
cp .env.example .env      # Fill in all values — see table below

# 2. Place SSL certificates
mkdir -p nginx/ssl
cp /path/to/fullchain.pem nginx/ssl/fullchain.pem
cp /path/to/privkey.pem   nginx/ssl/privkey.pem

# 3. Start
docker compose -f docker-compose.prod.yml up -d

# 4. Monitor
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f
```

The production stack starts:
- **Nginx** on ports 80 (redirects to HTTPS) and 443
- **Cloud Brain** on internal port 8005 (proxied via Nginx)
- **gRPC** on port 50051 (exposed directly — bypasses Nginx)
- **PostgreSQL** on internal network only (not exposed to host)

#### Environment File Example

```bash
# Required
POSTGRES_USER=xarex
POSTGRES_PASSWORD=<strong-random-password>
POSTGRES_DB=xarex
ADMIN_SECRET=<strong-random-secret>
SECRET_KEY=<strong-random-key-for-JWT>

# Optional — AI Analysis
ANTHROPIC_API_KEY=sk-ant-...

# Optional — CVE Intelligence
NVD_API_KEY=<nvd-api-key>     # Raises rate limit from 5/30s to 50/30s

# Optional — Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Optional — Automation
AUTO_ENRICH_CVE=true
AUTO_GENERATE_REPORT=true
AUTO_AI_ANALYSIS=false
NOTIFY_ON_SCAN_COMPLETE=true
LOG_LEVEL=info
```

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string: `postgresql+asyncpg://user:pass@host/db` |
| `ADMIN_SECRET` | Yes | — | Secret header value for admin endpoints. Keep private. |
| `SECRET_KEY` | Yes | — | Random key for internal signing. Minimum 32 characters. |
| `ANTHROPIC_API_KEY` | No | — | Enables AI Security Analyst (Claude). Leave blank to disable. |
| `NVD_API_KEY` | No | — | NVD API key. Without it, enrichment is rate-limited to 5 req/30s. |
| `SLACK_WEBHOOK_URL` | No | — | Slack incoming webhook for scan completion notifications. |
| `AUTO_ENRICH_CVE` | No | `true` | Automatically enrich findings that contain CVE IDs. |
| `AUTO_GENERATE_REPORT` | No | `true` | Automatically generate HTML report on scan completion. |
| `AUTO_AI_ANALYSIS` | No | `false` | Automatically run Claude analysis on scan completion. |
| `NOTIFY_ON_SCAN_COMPLETE` | No | `false` | Send Slack/webhook notification when a scan finishes. |
| `LOG_LEVEL` | No | `info` | Logging verbosity: `debug`, `info`, `warning`, `error`. |
| `ENVIRONMENT` | No | `development` | Set to `production` to disable debug endpoints. |

---

## Probe Deployment

The Go Probe must be deployed **inside the network segment you want to assess**. It connects outbound to the Cloud Brain's gRPC port (50051) — no inbound ports are opened on the target network.

**Network requirements for the Probe host:**
- Outbound TCP to the Cloud Brain on port 50051
- Layer-2 adjacency to the target hosts (same VLAN/subnet) for ARP scanning
- Root privileges or `CAP_NET_RAW` / `CAP_NET_ADMIN` for raw socket operations

### Linux (systemd)

The installer script automates binary download, configuration, and service registration:

```bash
# Download and run the installer (requires root)
curl -fsSL https://your-cloud-brain.com/download/install-linux.sh | sudo bash

# Or with pre-set variables (for automated/scripted deployment)
CLOUD_BRAIN_URL=https://your-cloud-brain.com \
ORG_ID=your-org-id \
PROBE_ID=probe-datacenter-1 \
sudo -E bash install-linux.sh
```

The installer:
1. Detects your Linux distribution (Ubuntu/Debian/RHEL/CentOS/Amazon Linux)
2. Checks prerequisites and connectivity to the Cloud Brain
3. Downloads the `xarex-probe` binary to `/opt/xarex/`
4. Writes `/opt/xarex/xarex.conf` with your configuration
5. Creates `/etc/systemd/system/xarex-probe.service`
6. Enables and starts the service
7. Verifies the probe appears online

**Service management:**

```bash
systemctl status xarex-probe          # Check status
journalctl -u xarex-probe -f          # Stream live logs
systemctl restart xarex-probe         # Restart
systemctl stop xarex-probe            # Stop
```

**Configuration file** (`/opt/xarex/xarex.conf`):

```ini
CLOUD_BRAIN_ADDR=cloud.example.com:50051
ORG_ID=your-org-id
PROBE_ID=probe-datacenter-1
LOG_LEVEL=info
GRPC_TLS=false
```

Re-run the installer at any time to update configuration or upgrade the binary.

### Docker

Use Docker when you want the Probe containerised or when running from a jump host that has Docker available.

**Using the helper script (interactive):**

```bash
bash probe/deploy/docker-run.sh         # Prompts for config, prints command
bash probe/deploy/docker-run.sh --run   # Prompts for config and runs immediately
```

**Manual docker run:**

```bash
docker run -d \
  --name xarex-probe \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --restart unless-stopped \
  -e CLOUD_BRAIN_ADDR=cloud.example.com:50051 \
  -e ORG_ID=your-org-id \
  -e PROBE_ID=probe-1 \
  xarex-probe:latest
```

**Build the image locally:**

```bash
cd probe/
docker build -t xarex-probe:latest .
```

**Key flags explained:**

| Flag | Reason |
|------|--------|
| `--network host` | Required so the probe can reach all Layer-2 hosts on the LAN without NAT |
| `--cap-add NET_RAW` | Required for ARP scanning and raw ICMP sockets |
| `--cap-add NET_ADMIN` | Required for network interface enumeration |

> **macOS / Windows Docker Desktop:** `--network host` is not supported. Use `--add-host=host-gateway:host-gateway` and ensure the target hosts are reachable from the Docker network. ARP scanning will not function without Layer-2 access; ICMP mode will be used instead.

### Windows

The PowerShell installer registers the Probe as a native Windows service:

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\probe\deploy\install-windows.ps1

# Or with pre-set parameters
.\probe\deploy\install-windows.ps1 `
  -CloudBrainUrl https://cloud.example.com `
  -OrgId your-org-id `
  -ProbeId probe-windows-1
```

The installer:
1. Verifies Administrator privileges
2. Checks connectivity to the Cloud Brain
3. Downloads `xarex-probe.exe` to `C:\Program Files\Xarex\`
4. Writes the configuration file
5. Registers a Windows service (using NSSM if available, otherwise `sc.exe`)
6. Starts the service and verifies connectivity

**Service management (PowerShell):**

```powershell
Get-Service XarexProbe                       # Check status
Restart-Service XarexProbe                   # Restart
Stop-Service XarexProbe                      # Stop
Get-EventLog -LogName Application -Source XarexProbe -Newest 50  # Logs
```

### Kubernetes (Helm)

> Helm chart is planned for a future release. In the interim, deploy the Probe as a DaemonSet or Deployment using the Docker image with the required environment variables and `securityContext.capabilities.add: [NET_RAW, NET_ADMIN]`.

```yaml
# Example pod spec excerpt
spec:
  containers:
    - name: xarex-probe
      image: xarex-probe:latest
      env:
        - name: CLOUD_BRAIN_ADDR
          value: "cloud.example.com:50051"
        - name: ORG_ID
          valueFrom:
            secretKeyRef:
              name: xarex-secrets
              key: org-id
      securityContext:
        capabilities:
          add: [NET_RAW, NET_ADMIN]
      hostNetwork: true   # Required for Layer-2 access
```

---

## Running Your First Scan

### Creating a Scan via API

```bash
# 1. Get your probe ID (after the probe has registered)
curl -s http://localhost:8005/api/v1/probes \
  -H "X-API-Key: xrx_your_api_key" | jq '.[0].id'

# 2. Launch a scan
curl -X POST http://localhost:8005/api/v1/scans \
  -H "X-API-Key: xrx_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal Network Assessment — Q2 2026",
    "probe_id": "your-probe-uuid",
    "config": {
      "subnets": ["192.168.1.0/24", "10.0.0.0/16"],
      "checks": [
        "HOST_DISCOVERY",
        "PORT_SCAN",
        "SERVICE_FINGERPRINT",
        "DEFAULT_CRED_TEST",
        "SMB_RELAY_CHECK",
        "LLMNR_CHECK",
        "ACTIVE_DIRECTORY_ENUM"
      ]
    }
  }'

# 3. Monitor scan status
curl -s http://localhost:8005/api/v1/scans/{scan_id} \
  -H "X-API-Key: xrx_your_api_key" | jq '{status, progress}'
```

Leave `checks` empty to run all available modules. Leave `subnets` empty to auto-detect from the probe's network interfaces.

### Creating a Scan via Dashboard

1. Open the dashboard at `http://your-cloud-brain-host:8005`
2. Paste your API key into the top bar and click **Connect**
3. Click **+ New Scan** in the top-right corner
4. Complete the form:
   - **Scan Name** — a descriptive label (e.g. "Production Network Q2 2026")
   - **Subnets** — comma-separated CIDR ranges. Leave blank for auto-detect.
   - **Probe** — select the probe that is deployed in the target network
   - **Checks** — select the scan modules to run
5. Click **Launch Scan**

The browser subscribes to the live WebSocket feed immediately. Findings appear in real time as the probe reports them.

### Understanding the Scan Pipeline

When a scan is launched, the Cloud Brain executes this pipeline automatically:

```
1. HOST_DISCOVERY
        │
        ▼ (for each discovered host)
2. PORT_SCAN
        │
        ▼ (for each open port)
3. SERVICE_FINGERPRINT
        │
        ▼ (Autonomous Engine triggers per-port specialised checks)
4. DEFAULT_CRED_TEST (FTP, Redis, MongoDB, SSH, etc.)
   SMB_RELAY_CHECK   (port 445/139)
   LLMNR_CHECK       (UDP 5355/137)
   ACTIVE_DIRECTORY_ENUM (port 389/636)
   KERBEROAST_ENUM   (port 88)
   ASREP_ROAST_ENUM  (port 88)
   VULN_CHECK        (SNMP, Docker API, Kubernetes, ICS ports)
        │
        ▼ (on all tasks complete)
5. REPORT_GENERATION  (if AUTO_GENERATE_REPORT=true)
6. AI_ANALYSIS        (if AUTO_AI_ANALYSIS=true)
7. NOTIFICATION       (if NOTIFY_ON_SCAN_COMPLETE=true)
```

The Autonomous Engine eliminates manual task queuing. Opening port 389 on a discovered host automatically triggers `ACTIVE_DIRECTORY_ENUM` — no configuration required.

**Scan status values:**

| Status | Meaning |
|--------|---------|
| `PENDING` | Queued, awaiting an available probe |
| `RUNNING` | Actively scanning |
| `COMPLETED` | All tasks finished successfully |
| `FAILED` | One or more critical tasks failed — check logs |

---

## Scan Modules Reference

| Module | Task Type | Triggered By | Description |
|--------|-----------|-------------|-------------|
| Host Discovery | `HOST_DISCOVERY` | Manual / scan launch | ARP broadcast scan to find live hosts on the subnet. Falls back to ICMP on routed subnets. Returns IP, MAC, hostname. |
| Port Scanning | `PORT_SCAN` | After host discovery | Concurrent TCP connect scan across top-1000 ports. Configurable port list and concurrency. |
| Service Fingerprinting | `SERVICE_FINGERPRINT` | After port scan | Protocol-specific banner grabbing to identify exact service names and versions. |
| Default Credential Test | `DEFAULT_CRED_TEST` | Port 21/22/23/3306/5432/3389/6379/27017/9200/11211/5900/1433 | Tests for anonymous access and default credentials on databases, FTP, SSH, RDP, VNC, Redis, MongoDB, Elasticsearch, and more. |
| SMB Relay Check | `SMB_RELAY_CHECK` | Port 445/139 | Sends SMBv2 NEGOTIATE to check whether SMB signing is required. Disabled signing means the host is vulnerable to NTLM relay attacks. |
| LLMNR Poisoning Check | `LLMNR_CHECK` | Scan launch | Listens on UDP 5355 and sends a crafted query to detect LLMNR responders. Active LLMNR enables credential poisoning attacks. |
| Active Directory Enum | `ACTIVE_DIRECTORY_ENUM` | Port 389/636/3268 | Read-only LDAP queries against Domain Controllers. Enumerates: domain info, password policy, all users/groups, privileged group memberships, SPN accounts. |
| Kerberoasting Enum | `KERBEROAST_ENUM` | Port 88 (via AD enum) | Identifies service accounts with SPNs set — these are targetable for Kerberoasting offline password cracking. |
| AS-REP Roasting Enum | `ASREP_ROAST_ENUM` | Port 88 (via AD enum) | Finds accounts with Kerberos pre-authentication disabled — these are targetable without credentials. |
| Vulnerability Check | `VULN_CHECK` | Port 161/2375/6443/502/102 | Protocol-specific probes for unauthenticated SNMP, exposed Docker API, exposed Kubernetes API, and ICS/SCADA protocols (Modbus, S7comm). |
| CVE Enrichment | `CVE_ENRICH` | Automatic (background) | Looks up CVSS scores, EPSS probability, and references from NVD for any finding with a CVE ID. |
| Attack Path Analysis | `GRAPH_ANALYSIS` | On scan completion | NetworkX graph computation to identify multi-hop attack chains from entry points to high-value targets. |
| AI Analysis | `AI_ANALYSIS` | Manual or auto | Claude-powered analysis of all findings, attack paths, and context. Produces executive summary, risk score, attack narrative, and remediation plan. |
| Report Generation | `REPORT_GEN` | Manual or auto | Generates a self-contained HTML report with all findings, attack paths, and AI summary. |
| Scheduled Scan | `SCHEDULED_SCAN` | Cron trigger | Launches a scan automatically according to a user-defined cron schedule. |
| Lateral Movement | Internal (Autonomous Engine) | Critical finding discovered | When a Critical finding is stored, auto-queues `SMB_RELAY_CHECK` against all /24 neighbours of the affected host. |

---

## Report Generation

Reports are standalone HTML files that capture the complete state of a scan assessment, suitable for archiving as audit evidence or sharing with stakeholders.

### Report Contents

- Scan metadata (name, date, duration, probe)
- Statistics grid: finding counts by severity
- Full findings table with CVE IDs, CVSS scores, MITRE ATT&CK techniques, and remediation steps
- Attack paths table with risk scores and step chains
- AI-generated executive summary (if analysis has been run)

### Generating a Report

**Automatically:** A report is generated as soon as each scan completes when `AUTO_GENERATE_REPORT=true` (the default).

**Via dashboard:** On the **Reports** page, click the scan's report card, then **↓ HTML** to download.

**Via API:**

```bash
# Trigger report generation
curl -X POST http://localhost:8005/api/v1/reports/scans/{scan_id} \
  -H "X-API-Key: xrx_..."

# Download the report
curl http://localhost:8005/api/v1/reports/{report_id} \
  -H "X-API-Key: xrx_..." -o report.html

# Trigger AI analysis on an existing report
curl -X POST http://localhost:8005/api/v1/reports/{report_id}/analyse \
  -H "X-API-Key: xrx_..."
```

---

## API Reference

All API routes require `X-API-Key: xrx_your_key` unless noted.  
Admin routes additionally require `X-Admin-Secret: your-admin-secret`.

### Organisations (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/admin/orgs` | Create a new organisation |
| `GET` | `/api/v1/admin/orgs` | List all organisations |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scans` | Launch a new scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan status and details |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan and all its findings |

### Findings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/findings` | List findings (filter: `scan_id`, `severity`) |
| `GET` | `/api/v1/findings/{id}` | Get a single finding with full detail |
| `PATCH` | `/api/v1/findings/{id}/suppress` | Mark finding as false positive |
| `DELETE` | `/api/v1/findings/{id}/suppress` | Un-suppress a finding |
| `POST` | `/api/v1/findings/{id}/enrich` | Trigger NVD CVE enrichment |
| `GET` | `/api/v1/findings/export.csv` | Export findings as CSV |
| `GET` | `/api/v1/findings/export.json` | Export findings as JSON |

### Probes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/probes` | List all registered probes |
| `GET` | `/api/v1/probes/{id}` | Get probe status and details |
| `DELETE` | `/api/v1/probes/{id}` | Remove a probe record |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/reports` | List all reports |
| `GET` | `/api/v1/reports/{id}` | Download HTML report |
| `GET` | `/api/v1/reports/{id}/summary` | Get AI summary as JSON |
| `POST` | `/api/v1/reports/scans/{scan_id}` | Generate report for a scan |
| `POST` | `/api/v1/reports/{id}/analyse` | Run AI analysis on a report |

### Schedules

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/schedules` | Create a scheduled scan |
| `GET` | `/api/v1/schedules` | List all schedules |
| `DELETE` | `/api/v1/schedules/{id}` | Delete a schedule |
| `POST` | `/api/v1/schedules/{id}/run` | Trigger schedule immediately |

### Attack Paths

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/attack-paths` | Get attack paths (filter: `scan_id`) |
| `POST` | `/api/v1/attack-paths/compute/{scan_id}` | Recompute attack paths for a scan |

### Utility

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — returns `{"status": "ok"}` |
| `GET` | `/docs` | Swagger/OpenAPI interactive documentation |

---

## Security Considerations

### Probe Network Requirements

The Probe establishes **outbound-only** connections to the Cloud Brain — no inbound ports are opened on the network where the Probe is deployed. The minimum firewall rule required is:

```
Allow: <probe-host> → <cloud-brain-host>:50051 (TCP, outbound)
```

If gRPC TLS is enabled (`GRPC_TLS=true`), the Probe verifies the Cloud Brain's TLS certificate. Use a valid certificate from a trusted CA (or configure a custom CA) to prevent man-in-the-middle attacks on the control channel.

### Scanning Scope and Authorisation

Xarex is designed for **authorised penetration testing only**. Deploying the Probe and running scans against networks or systems without explicit written authorisation from the asset owner is illegal in most jurisdictions. Always ensure you have a signed scope-of-work or authorisation document before deploying the Probe.

### Data Handling

All findings, banners, and credentials discovered during a scan are stored in the Cloud Brain's PostgreSQL database. This data may include sensitive information such as software versions, open ports, and service banners from internal systems. Treat the PostgreSQL database and all reports as confidential assets:

- Encrypt the PostgreSQL volume at rest in production
- Store `.env` files with restricted filesystem permissions (`chmod 600`)
- Rotate the `ADMIN_SECRET` and organisation API keys periodically
- Do not expose port 8005 or 5432 directly to the internet — use the Nginx reverse proxy with TLS termination

### API Key Rotation

To rotate an organisation's API key:

```bash
curl -X POST http://localhost:8005/api/v1/admin/orgs/{org_id}/rotate-key \
  -H "X-Admin-Secret: your-admin-secret"
# Returns: { "api_key": "xrx_new_key..." }
```

Update all Probe `xarex.conf` files and any CI/CD integrations with the new key.

### Probe Binary Integrity

Verify the SHA-256 checksum of the downloaded `xarex-probe` binary against the checksum published on your Cloud Brain's download page before deploying in sensitive environments.

---

## Troubleshooting

### Probe Won't Connect

**Symptom:** Probe does not appear on the Probes page after startup.

**Checks:**
1. Verify outbound TCP connectivity from the probe host to the Cloud Brain on port 50051:
   ```bash
   nc -zv cloud.example.com 50051
   ```
2. Confirm the `CLOUD_BRAIN_ADDR` in `xarex.conf` uses `host:port` format (not `https://...`):
   ```ini
   CLOUD_BRAIN_ADDR=cloud.example.com:50051   # Correct
   CLOUD_BRAIN_ADDR=https://cloud.example.com  # Wrong
   ```
3. Check probe logs for gRPC error details:
   ```bash
   journalctl -u xarex-probe -n 100 --no-pager
   ```
4. Common gRPC errors:
   - `connection refused` — Cloud Brain is not running or port 50051 is firewalled
   - `deadline exceeded` — Network latency or routing issue; check MTU and firewall state tables
   - `UNAVAILABLE` — Cloud Brain gRPC server started but is not ready (wait for it to be healthy)

### Scan Stuck in RUNNING

**Symptom:** Scan status shows `RUNNING` for an extended period with no new findings.

**Checks:**
1. Verify the probe is still online (Probes page shows green status)
2. Check Cloud Brain logs for task dispatch errors:
   ```bash
   docker compose logs cloud-brain | grep ERROR
   ```
3. Check probe logs for task execution errors:
   ```bash
   journalctl -u xarex-probe -n 200 --no-pager | grep -i error
   ```
4. If the probe process crashed mid-scan, restart it — in-progress tasks will be re-queued on reconnect
5. Force-complete a stuck scan via API:
   ```bash
   curl -X PATCH http://localhost:8005/api/v1/scans/{scan_id}/status \
     -H "X-API-Key: xrx_..." \
     -H "Content-Type: application/json" \
     -d '{"status": "FAILED"}'
   ```

### gRPC Errors

| Error | Likely Cause | Resolution |
|-------|-------------|------------|
| `transport: Error while dialing: dial tcp: connection refused` | Cloud Brain gRPC port not listening | Start the Cloud Brain; check port 50051 is not blocked |
| `rpc error: code = Unauthenticated` | Invalid or missing ORG_ID | Verify ORG_ID in xarex.conf matches an organisation in the Cloud Brain |
| `rpc error: code = Unavailable` | Cloud Brain restarting | Wait 30 seconds; the probe will reconnect automatically |
| `context deadline exceeded` | Network timeout | Check routing between probe and Cloud Brain; increase firewall session timeouts |
| `x509: certificate signed by unknown authority` | TLS mismatch | Set `GRPC_TLS=false`, or install the correct CA certificate on the probe host |

### AI Analysis Not Running

**Checks:**
1. Verify `ANTHROPIC_API_KEY` is set in the Cloud Brain environment
2. Test the key directly: `curl https://api.anthropic.com/v1/messages -H "x-api-key: $ANTHROPIC_API_KEY" ...`
3. Check Cloud Brain logs for Claude API errors: `docker compose logs cloud-brain | grep anthropic`
4. The AI analyst requires a completed scan with at least one finding — it cannot run on empty or still-running scans

### Database Connection Errors

```bash
# Verify PostgreSQL is running
docker compose ps postgres

# Check postgres logs
docker compose logs postgres

# Test connection manually
docker compose exec postgres psql -U xarex -d xarex -c "\l"

# If tables are missing (fresh install)
docker compose exec cloud-brain python3 -c \
  "from models.database import init_db; import asyncio; asyncio.run(init_db())"
```

---

## FAQ

**Q: Does Xarex require internet access?**  
A: The Cloud Brain needs internet access only for: NVD CVE lookups (CVE enrichment), EPSS score fetching, Anthropic API calls (AI analysis), and Slack/webhook notifications. All of these are optional — Xarex is fully functional without internet access; you simply won't have CVE data or AI-powered reports.

**Q: Can I run multiple probes for the same organisation?**  
A: Yes. Deploy as many probes as needed — one per network segment, VLAN, or geographic site. Each probe registers with a unique `PROBE_ID`. When creating a scan, select which probe to use. All probes report findings to the same Cloud Brain and the same database.

**Q: Is ARP scanning safe to run on production networks?**  
A: ARP scans are passive broadcasts — they generate no more traffic than a standard network device joining a VLAN. They do not disrupt services. Port scanning is connection-oriented (TCP SYN) and can generate log entries on firewalls and IDS systems; this is expected and normal for an authorised penetration test.

**Q: How do I scope a scan to specific hosts rather than a full subnet?**  
A: Pass individual host IPs in the `subnets` field:
```json
"subnets": ["192.168.1.50/32", "192.168.1.100/32", "10.0.0.0/24"]
```

**Q: Can the Probe scan across VLANs or routed segments?**  
A: Yes. ARP scanning is Layer-2 only, so it only discovers hosts on the same VLAN as the probe. For hosts on different VLANs, Xarex automatically falls back to ICMP ping for host discovery. Port scanning and all other modules work across routed segments with no restriction.

**Q: How do I update the Probe binary?**  
A: Re-run the installer script on each probe host. It will download the latest binary and restart the service. For Docker deployments, pull the new image and recreate the container.

**Q: What data is sent from the Probe to the Cloud Brain?**  
A: The Probe sends only scan results over gRPC: IP addresses, open port numbers, service banners, and test outcomes. It never sends full packet captures, keystrokes, file contents, or any data beyond what is needed to construct a finding. The Cloud Brain stores this data in PostgreSQL.

**Q: Can I host the Cloud Brain on a cloud provider?**  
A: Yes. Deploy using `docker-compose.prod.yml` on any Linux VM (AWS EC2, Azure VM, GCP Compute Engine, etc.). Ensure port 50051 is reachable by probe hosts (add an inbound security group rule), and place the Cloud Brain's API behind the Nginx proxy with a valid TLS certificate. Probes in on-premise networks connect out to the cloud-hosted Cloud Brain over the internet.

**Q: How are findings deduplicated?**  
A: The Autonomous Engine tracks `(probe_id, task_type, host)` tuples per scan. If the same check has already been queued for a host (e.g. `ACTIVE_DIRECTORY_ENUM` triggered by both port 389 and port 636), it is queued only once.
