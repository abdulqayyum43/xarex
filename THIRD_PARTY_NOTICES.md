# Third-Party Notices

Xarex ships and depends on several third-party components. This document
records the components we embed (binary or source-vendored) and the
upstream projects whose concepts inspired our own implementations.

---

## Embedded binaries

### libpcap

- **Used by:** Go probe (`probe/`), via `gopacket` for ARP / ICMP packet capture.
- **License:** BSD 3-Clause.
- **How embedded:** `libpcap-dev` is installed in the Alpine builder stage of
  `probe/Dockerfile` and statically linked into the `phantom-probe` binary
  via `CGO_ENABLED=1 -extldflags=-static`.

### Nuclei

- **Used by:** Go probe (`probe/`), via `probe/scanner/nuclei.go` shelling out to `/usr/local/bin/nuclei`.
- **Upstream:** https://github.com/projectdiscovery/nuclei
- **License:** Apache License 2.0.
- **Version:** pinned by `NUCLEI_VERSION` ARG in `probe/Dockerfile`
  (currently `3.3.7`).
- **How embedded:** the upstream release tarball for the pinned version is
  downloaded at probe-image build time and installed to `/usr/local/bin/nuclei`.
- **Templates:** community templates from
  https://github.com/projectdiscovery/nuclei-templates (MIT License) are
  fetched into `/opt/nuclei-templates` at build time via
  `nuclei -update-templates -ud /opt/nuclei-templates`. Templates are
  pinned to whatever is current at build time — we do not auto-update
  at runtime in production.

---

## Clean-room re-implementations (concept-inspired, no source consulted)

The following Xarex modules were implemented from scratch based only on
the **concept descriptions** in the upstream projects' READMEs. No
upstream source code was consulted during implementation. This is a
deliberate posture to avoid licensing entanglements (in particular,
AGPL-3.0 source would force Xarex to publish its own source to every
customer under the AGPL Section 13 network-use clause, which is
incompatible with our commercial model).

| Xarex module | Inspired by (concept only) | Upstream license we avoided |
|---|---|---|
| `cloud-brain/services/subdomain_enum.py` | Subfinder, Amass, hackingtool-plugin's recon category | (Apache-2.0 / MIT — but reimplemented for consistency with our async/httpx stack) |
| `cloud-brain/services/osint_email.py` | TheHarvester (concept only) | GPL-2.0 — reimplemented to keep Xarex free of GPL obligations |
| `cloud-brain/services/secrets_scanner.py` | gitleaks, trufflehog (concept only) | MIT / AGPL-3.0 — reimplemented to avoid AGPL exposure |
| `probe/scanner/cred_checker.go` (FTP/Redis/Mongo/Elasticsearch/Memcached/SMTP-relay checks) | Various; concept similar to many tools | Reimplemented from protocol RFCs |

For the secrets scanner specifically: every regex pattern in
`services/secrets_scanner.py::_PATTERNS` was written from scratch against
each provider's officially-documented key format (AWS docs, Stripe docs,
GitHub docs, etc.) — not adapted from gitleaks' rule library or
trufflehog's detectors.

---

## Python dependencies (cloud-brain)

The Cloud Brain is a FastAPI application with the dependencies declared
in `cloud-brain/requirements.txt`. Notable transitive licenses:

- FastAPI, Uvicorn, Pydantic, SQLAlchemy — MIT
- asyncpg, psycopg2 — PostgreSQL-style permissive
- httpx, h11, httpcore — BSD 3-Clause
- structlog — Apache 2.0 / MIT dual
- stripe-python — MIT
- anthropic — MIT
- slowapi — MIT
- protobuf, grpcio — BSD-3
- python-jose, passlib, bcrypt — BSD / Apache 2.0 / MIT

A full SBOM is generated from `pip freeze` in the cloud-brain container
when needed for enterprise procurement.

---

## Go dependencies (probe)

The probe is a Go binary with dependencies declared in `probe/go.mod`.
Notable direct dependencies:

- google.golang.org/grpc, google.golang.org/protobuf — BSD-3
- google/gopacket — BSD-3
- google/uuid — BSD-3

---

## Inspirations explicitly NOT used

This section documents projects we evaluated and chose **not** to vendor
or recreate, for posterity:

- **Pantheon-Security/medusa** (AGPL-3.0) — evaluated 2026-05-22. The
  network-use clause of AGPL-3.0 is incompatible with Xarex's commercial
  hosted-SaaS model. None of Medusa's source was consulted during the
  implementation of Xarex's recon or secrets-scanning modules.
- **AKCodez/hackingtool-plugin** (no license file) — evaluated 2026-05-22.
  The plugin is a launcher for 183 third-party CLI tools that assumes
  local install; this is the wrong architecture for a hosted SaaS, and
  bundling 183 tools would multiply our supply-chain attack surface.
  We picked a handful of high-leverage categories (subdomain enum, email
  OSINT, secrets, Nuclei) and built each ourselves.
