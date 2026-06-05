import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    api_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    probes: Mapped[list["Probe"]] = relationship("Probe", back_populates="org", lazy="noload")
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="org", lazy="noload")


class Probe(Base):
    __tablename__ = "probes"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    network_context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="offline")

    org: Mapped["Org"] = relationship("Org", back_populates="probes")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    org: Mapped["Org"] = relationship("Org", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", lazy="noload"
    )
    graph_nodes: Mapped[list["GraphNode"]] = relationship(
        "GraphNode", back_populates="scan", lazy="noload"
    )
    graph_edges: Mapped[list["GraphEdge"]] = relationship(
        "GraphEdge", back_populates="scan", lazy="noload"
    )
    attack_paths: Mapped[list["AttackPath"]] = relationship(
        "AttackPath", back_populates="scan", lazy="noload"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    service: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Remediation tracking
    remediation_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="new"
    )  # new | in_progress | fixed | false_positive | accepted_risk
    remediation_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="graph_nodes")
    source_edges: Mapped[list["GraphEdge"]] = relationship(
        "GraphEdge", foreign_keys="GraphEdge.source_node_id", back_populates="source_node"
    )
    target_edges: Mapped[list["GraphEdge"]] = relationship(
        "GraphEdge", foreign_keys="GraphEdge.target_node_id", back_populates="target_node"
    )


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_node_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    target_node_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="graph_edges")
    source_node: Mapped["GraphNode"] = relationship(
        "GraphNode", foreign_keys=[source_node_id], back_populates="source_edges"
    )
    target_node: Mapped["GraphNode"] = relationship(
        "GraphNode", foreign_keys=[target_node_id], back_populates="target_edges"
    )


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    nodes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    impact: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    entry_point: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="attack_paths")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True, unique=True
    )
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    html_content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ScanTemplate(Base):
    """Saved scan configuration profiles that can be reused."""
    __tablename__ = "scan_templates"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    # Suggested scan name (can be overridden at launch time)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # Stored scan config (target, subnets, options…)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)
    probe_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# ─────────────────────────────────────────────────────────────────────────────
# Billing tables
# ─────────────────────────────────────────────────────────────────────────────

class Customer(Base):
    """A paying (or trialling) customer — independent of Org to allow upgrades."""
    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Payment gateway customer IDs
    stripe_customer_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    toyyibpay_order_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    subscriptions: Mapped[list["Subscription"]] = relationship(
        "Subscription", back_populates="customer", lazy="selectin"
    )
    licenses: Mapped[list["License"]] = relationship(
        "License", back_populates="customer", lazy="selectin"
    )


class Subscription(Base):
    """Active or cancelled billing subscription."""
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("customers.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    # "stripe" | "toyyibpay"
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    # Stripe subscription ID or ToyyibPay billcode
    provider_sub_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    # "trialing" | "active" | "past_due" | "cancelled" | "pending"
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    plan: Mapped[str] = mapped_column(String(64), nullable=False, default="xarex_pro")
    # Amount in smallest currency unit (cents / sen)
    amount: Mapped[int] = mapped_column(Integer, nullable=False, default=4900)
    currency: Mapped[str] = mapped_column(String(8), nullable=False, default="usd")
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    customer: Mapped["Customer"] = relationship("Customer", back_populates="subscriptions")


class License(Base):
    """Provisioned license key tied to a customer subscription."""
    __tablename__ = "licenses"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("customers.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    # The Org + API key pair the customer uses to run the Cloud Brain
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False, index=True)
    api_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    # "active" | "suspended" | "cancelled"
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    # "free" | "xarex_pro"
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="xarex_pro")
    scan_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scan_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = unlimited
    download_token: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    welcome_email_sent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    customer: Mapped["Customer"] = relationship("Customer", back_populates="licenses")


class BillingEvent(Base):
    """Append-only log of every payment event received from Stripe / ToyyibPay."""
    __tablename__ = "billing_events"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    # Unique so the DB enforces idempotency on duplicate webhook deliveries
    # (see services/billing.py::handle_stripe_event — write-then-catch-
    # IntegrityError pattern). Migration in main.py's lifespan adds the
    # constraint on existing deployments.
    provider_event_id: Mapped[str | None] = mapped_column(
        String(256), nullable=True, unique=True, index=True
    )
    customer_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )



class Integration(Base):
    """SIEM / webhook integration endpoint configured per org."""
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)   # splunk|sentinel|webhook|qradar|elastic
    url: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PhishingCampaign(Base):
    """Phishing simulation campaign."""
    __tablename__ = "phishing_campaigns"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    template: Mapped[str] = mapped_column(String(64), nullable=False, default="generic")
    landing_page: Mapped[str] = mapped_column(String(64), nullable=False, default="credential_harvest")
    redirect_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    targets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    target_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    opened_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    clicked_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    submitted_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IOCWatch(Base):
    """IOC (Indicator of Compromise) watchlist entry per org."""
    __tablename__ = "ioc_watch"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # "ip" | "domain" | "url" | "hash"
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ThreatIntelCache(Base):
    """Cached threat intel lookup result to avoid repeated external API calls."""
    __tablename__ = "threat_intel_cache"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    lookup_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# ── Feature: Breach Monitor ───────────────────────────────────────────────────

class BreachMonitor(Base):
    """An email address being continuously monitored for data breaches."""
    __tablename__ = "breach_monitors"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    breach_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BreachHit(Base):
    """A specific breach that was found for a monitored email."""
    __tablename__ = "breach_hits"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    monitor_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("breach_monitors.id", ondelete="CASCADE"), nullable=False, index=True)
    breach_name: Mapped[str] = mapped_column(String(256), nullable=False)
    breach_domain: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    breach_date: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    pwn_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    data_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    logo_path: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ── Feature: Link / Email Analyzer ───────────────────────────────────────────

class AnalysisResult(Base):
    """Cached result of a URL or email-header analysis."""
    __tablename__ = "analysis_results"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)          # "url" | "email"
    input_value: Mapped[str] = mapped_column(Text, nullable=False)         # the URL or email text
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")  # safe|suspicious|malicious
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)          # 0-100
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ── Feature: Personal Security Score ─────────────────────────────────────────

class SecurityScore(Base):
    """Point-in-time personal security score for an org."""
    __tablename__ = "security_scores"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    grade: Mapped[str] = mapped_column(String(4), nullable=False, default="A")
    breakdown: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


# ── Feature: Digital Footprint ────────────────────────────────────────────────

class FootprintScan(Base):
    """A footprint scan request for a person."""
    __tablename__ = "footprint_scans"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(256), nullable=False)
    location: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")  # pending|running|done|failed
    exposure_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sources_checked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exposures_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    results: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ── Feature: Domain Guardian ──────────────────────────────────────────────────

class DomainMonitor(Base):
    """A domain being monitored by Domain Guardian."""
    __tablename__ = "domain_monitors"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")  # pending|ok|warning|critical|failed
    health_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # SSL
    ssl_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ssl_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ssl_days_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ssl_issuer: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # DNS
    spf_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dmarc_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dkim_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dmarc_policy: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mx_records: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    ns_records: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # WHOIS
    whois_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    whois_days_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Lookalikes
    lookalike_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lookalikes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Issues + raw result
    issues: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    last_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Timestamps
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


# ── Feature: Notification Center ─────────────────────────────────────────────

class Notification(Base):
    """In-app notification for security events across all Guardian features."""
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    # classification
    kind: Mapped[str] = mapped_column(String(64), nullable=False)        # domain_ssl | domain_lookalike | domain_dns | breach_new | breach_refresh | security_score | system
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")  # critical | high | medium | low | info
    # content
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    action_url: Mapped[str | None] = mapped_column(String(512), nullable=True)   # e.g. "domain-guardian"
    action_label: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g. "View domain"
    metadata_: Mapped[dict] = mapped_column("meta", JSON, nullable=False, default=dict)
    # state
    read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


# ── Feature: Marketing Lead Capture ──────────────────────────────────────────

class Lead(Base):
    """A lead-capture submission from the public marketing site.

    Receives anonymous form submissions (e.g. sample-report gate, "Contact sales").
    No org / customer / auth relationship — these are pre-signup prospects.
    """
    __tablename__ = "leads"
    __table_args__ = (
        # Sales-analytics shape: "how many leads from <source> in the last <window>".
        Index("ix_leads_source_created", "source", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)  # NOT unique — repeat submissions OK
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    company: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Org size bracket (free-form to allow new buckets without migration); e.g. "11–50", "1,000+"
    size: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Which form/page produced the lead, e.g. "sample-report-gate", "contact-sales"
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="sample-report-gate", index=True)
    # Optional free-text message for "Contact sales"-style forms.
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NOTE: ip_address is PII in some jurisdictions (e.g. GDPR). Used only for
    # spam/abuse detection; do NOT return it in any API response. IPv6-friendly length.
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
