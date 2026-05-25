# Xarex

**Autonomous penetration testing platform — deploy a Go probe, the cloud brain does the rest**

Xarex is a production-grade autonomous pentest platform built on a hybrid architecture. A lightweight Go probe deploys inside any network and handles all active scanning. A Python cloud brain orchestrates tasks, computes attack paths with a graph engine, enriches findings with live CVE data, runs AI analysis via Claude, and generates a complete pentest report — all without manual steps after launch. One deploy, walk away, come back to a full report.

> ⚠️ **Authorized use only.** Designed for security teams and penetration testers with explicit written authorization to test target systems. Unauthorized use is illegal.

## Why Xarex?

Traditional pentests require a consultant on-site and a week of manual work. Xarex automates the entire pipeline: discover hosts, enumerate services, check credentials, detect AD misconfigurations, map attack paths, and produce an executive-ready report — all chained automatically. The probe never holds state and the brain never touches the target network directly.

## What It Does

```
Probe (inside target network)          Cloud Brain (your server)
                                                │
ARP Discovery → Port Scan                       │
Service Fingerprint → Cred Check    ──gRPC──>   │
SMB/LLMNR Detection                             │
AD Enumeration                                  │
Kerberoast / AS-REP Detection                   │
                                       ┌────────▼────────────┐
                                       │  Task Orchestrator   │
                                       │  CVE Enricher (NVD)  │
                                       │  Attack Path Engine  │
                                       │  AI Analyst (Claude) │
                                       │  Report Generator    │
                                       └─────────────────────┘
                                                │
                                    HTML Report + Dashboard
```

## Quick Start

```bash
git clone https://github.com/abdulqayyum43/xarex.git
cd xarex
cp .env.example .env          # set ADMIN_SECRET and ANTHROPIC_API_KEY
docker compose up -d
curl http://localhost:8005/health
```

Create your first org and get an API key:

```bash
curl -X POST http://localhost:8005/api/v1/admin/orgs \
  -H "X-Admin-Secret: your-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Organisation"}'
```

Deploy the probe into the target network:

```bash
sudo ./probe-linux-amd64 \
  --brain-url=http://YOUR_CLOUD_BRAIN_IP:8005 \
  --org-id=YOUR_ORG_ID \
  --api-key=YOUR_API_KEY
```

Interactive docs at **http://localhost:8005/docs**

## What You Get

| Feature | Description |
|---|---|
| 🔍 **ARP Discovery** | Map every live host in the target subnet |
| 🔌 **Port Scanner** | TCP/UDP scan with service fingerprinting and banner grabbing |
| 🔑 **Credential Checker** | Test default and common credentials against every discovered service |
| 🪟 **SMB Relay Detector** | Identify SMB relay attack opportunities in the network |
| 📡 **LLMNR Detector** | Detect LLMNR/NBT-NS poisoning exposure |
| 🏢 **AD Enumerator** | Active Directory users, groups, GPOs, and trust relationships |
| 🎟️ **Kerberoast / AS-REP** | Identify Kerberoastable and AS-REP roastable accounts |
| 📋 **CVE Enrichment** | Auto-enrich every service with NVD CVEs, CVSS scores, and EPSS exploit probability |
| 🗺️ **Attack Path Engine** | NetworkX graph computes realistic multi-hop attack paths an attacker could chain |
| 🤖 **AI Analyst** | Claude generates executive summary and technical findings from raw scan data |
| 📄 **Report Generator** | Full HTML pentest report — exec summary, findings, attack paths, remediation |

## Scan Modules

| Module | Description |
|---|---|
| **ARP Discovery** | Subnet sweep to identify live hosts |
| **Port Scanner** | TCP/UDP with service version detection |
| **Service Fingerprinter** | Banner grabbing and version identification |
| **Credential Checker** | Default/common credential testing across services |
| **SMB Relay Detector** | SMB signing and relay attack surface analysis |
| **LLMNR Detector** | LLMNR/NBT-NS poisoning exposure detection |
| **AD Enumerator** | Full Active Directory enumeration |
| **Kerberoast / AS-REP** | Kerberos attack surface identification |
| **CVE Enricher** | NVD + EPSS enrichment for discovered services |
| **Attack Path Engine** | Multi-hop lateral movement path computation |
| **AI Analyst** | Executive and technical report generation |

## Running a Scan

```bash
curl -X POST http://localhost:8005/api/v1/scans \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal Network Audit",
    "target": "192.168.1.0/24",
    "modules": ["discovery", "port_scan", "service_fingerprint", "credential_check", "ad_enum"],
    "ai_analysis": true
  }'
```

Scan pipeline:

```
Launch → ARP Discovery → Port Scan → Service Fingerprint
       → Credential Check → SMB/AD/Kerberos checks
       → CVE Enrichment → Attack Path Computation
       → AI Analysis → HTML Report
```

## Report Contents

Every Xarex report includes:

| Section | Contents |
|---|---|
| **Executive Summary** | Business-language risk summary, AI-generated |
| **Technical Findings** | Host-by-host breakdown with CVEs and CVSS scores |
| **Attack Paths** | Visualized multi-hop lateral movement chains |
| **Remediation Guidance** | Prioritized fix list per finding with effort estimates |
| **Compliance Mapping** | Findings mapped to CIS Controls, NIST, ISO 27001 |

```bash
curl http://localhost:8005/api/v1/scans/{scan_id}/report \
  -H "X-API-Key: your-api-key" \
  --output pentest-report.html
```

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/scans` | Launch a scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Scan status and results |
| `GET` | `/api/v1/scans/{id}/report` | Download HTML report |
| `GET` | `/api/v1/scans/{id}/attack-paths` | Computed attack paths |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/v1/probes` | List connected probes |
| `POST` | `/api/v1/admin/orgs` | Create an organisation |

## Configuration

| Variable | Description |
|---|---|
| `ADMIN_SECRET` | Required — admin endpoint secret |
| `ANTHROPIC_API_KEY` | Claude AI analysis (optional but recommended) |
| `DATABASE_URL` | PostgreSQL connection string |
| `GRPC_PORT` | Probe-to-brain gRPC port (default: `50051`) |

## Project Structure

```
xarex/
├── cloud-brain/
│   ├── main.py               # FastAPI app
│   ├── task_manager.py       # Scan pipeline orchestration
│   ├── graph_engine.py       # NetworkX attack path computation
│   ├── ai_analyst.py         # Claude AI analysis
│   ├── cve_enricher.py       # NVD / EPSS CVE lookup
│   ├── report_gen.py         # HTML report generator
│   └── notifier.py           # Slack / webhook alerts
├── probe/                    # Go probe (active scanner)
│   ├── arp_scanner.go
│   ├── port_scanner.go
│   ├── fingerprinter.go
│   ├── credential_checker.go
│   ├── smb_relay.go
│   ├── llmnr_detector.go
│   └── ad_enumerator.go
├── shared/                   # Protobuf definitions
├── frontend/                 # Web dashboard
├── nginx/                    # Reverse proxy config
├── mcp_server.py             # MCP server integration
├── docker-compose.yml
├── docker-compose.prod.yml
└── smoke-all.sh              # Smoke test suite
```

## Running with Docker

```bash
docker compose up -d
```

---

Built by **Abdul Quyyam** · MIT License
