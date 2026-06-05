from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Org
# ---------------------------------------------------------------------------

class OrgCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class OrgRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    api_key: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class ProbeRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    org_id: str
    probe_id: str
    version: str
    capabilities: dict[str, Any]
    network_context: dict[str, Any]
    last_seen: datetime | None
    status: str


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    probe_id: str | None = Field(default=None, max_length=128)  # auto-selects if omitted
    name: str = Field(default="Quick Scan", min_length=1, max_length=255)
    target: str | None = Field(default=None)  # convenience: merged into config["target"]
    config: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        # Allow callers to pass target at the top level; merge into config so
        # TaskManager always reads config["target"] regardless of call style.
        if self.target and "target" not in self.config:
            self.config["target"] = self.target


class ScanRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    org_id: str
    probe_id: str
    name: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    config: dict[str, Any]
    finding_count: int = 0
    critical_count: int = 0


class ScanDetail(ScanRead):
    findings: list[FindingRead] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class FindingRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    scan_id: str
    host: str
    port: int | None
    protocol: str | None
    service: str | None
    severity: int
    cve_id: str | None
    title: str
    description: str
    evidence: str
    remediation: str
    metadata_: dict[str, Any] = Field(alias="metadata_")
    timestamp: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

class GraphNodeRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    scan_id: str
    node_type: str
    identifier: str
    properties: dict[str, Any]


class GraphEdgeRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    scan_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    weight: float
    metadata_: dict[str, Any] = Field(alias="metadata_")

    model_config = {"from_attributes": True, "populate_by_name": True}


class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Attack Path
# ---------------------------------------------------------------------------

class AttackPathRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    scan_id: str
    nodes: list[Any]
    risk_score: float
    impact: str
    entry_point: str
    target: str


# ---------------------------------------------------------------------------
# Scan Task (internal / gRPC boundary)
# ---------------------------------------------------------------------------

class ScanTask(BaseModel):
    task_id: str
    scan_id: str
    task_type: str  # HOST_DISCOVERY | PORT_SCAN | SERVICE_FINGERPRINT | VULN_CHECK
    target: str
    options: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Admin stats
# ---------------------------------------------------------------------------

class AdminStats(BaseModel):
    total_orgs: int
    total_probes: int
    total_scans: int
    total_findings: int


# ---------------------------------------------------------------------------
# Generic responses
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    message: str


# Forward references resolved
ScanDetail.model_rebuild()
