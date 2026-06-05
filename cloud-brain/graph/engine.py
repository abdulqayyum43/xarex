"""Attack-path graph engine backed by NetworkX."""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from typing import Any

import networkx as nx
import structlog

logger = structlog.get_logger(__name__)

# Severity thresholds used for classifying nodes (0-4 scale: 0=Info, 1=Low, 2=Med, 3=High, 4=Critical)
SEVERITY_CRITICAL = 4
SEVERITY_HIGH = 3
SEVERITY_MEDIUM = 2

# Node types
NT_HOST = "host"
NT_SERVICE = "service"
NT_VULN = "vulnerability"

# Edge types
ET_RUNS = "RUNS"          # host → service
ET_HAS_VULN = "HAS_VULN"  # service → vuln
ET_EXPLOITS = "EXPLOITS"  # vuln → target host (lateral movement)


@dataclass
class FindingInput:
    """Lightweight representation of a finding fed into the graph engine."""
    id: str
    scan_id: str
    host: str
    port: int | None
    protocol: str | None
    service: str | None
    severity: int
    cve_id: str | None
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    id: str
    scan_id: str
    nodes: list[str]
    risk_score: float
    impact: str
    entry_point: str
    target: str


class GraphEngine:
    """Build an attack-path graph from scan findings and compute risk scores."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._graph: nx.DiGraph = nx.DiGraph()
        self._finding_nodes: list[str] = []   # node IDs that are vuln nodes
        self._host_nodes: set[str] = set()

        logger.info("GraphEngine initialised", scan_id=scan_id)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_finding(self, finding: FindingInput) -> None:
        """Add a finding to the graph, creating host/service/vuln nodes."""
        host_node = self._ensure_host_node(finding.host)

        # Service node (optional – only when port/service are known)
        if finding.port is not None or finding.service:
            service_key = f"{finding.host}:{finding.port or 0}/{finding.protocol or 'tcp'}"
            service_node = f"service:{service_key}"
            if not self._graph.has_node(service_node):
                self._graph.add_node(
                    service_node,
                    node_type=NT_SERVICE,
                    identifier=service_key,
                    properties={
                        "host": finding.host,
                        "port": finding.port,
                        "protocol": finding.protocol,
                        "service": finding.service,
                    },
                )
            if not self._graph.has_edge(host_node, service_node):
                self._graph.add_edge(host_node, service_node, edge_type=ET_RUNS, weight=1.0)
            parent_node = service_node
        else:
            parent_node = host_node

        # Vulnerability node
        vuln_node = f"vuln:{finding.id}"
        self._graph.add_node(
            vuln_node,
            node_type=NT_VULN,
            identifier=finding.cve_id or finding.title,
            properties={
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "cve_id": finding.cve_id,
                "description": finding.description,
                "remediation": finding.remediation,
            },
        )
        # Weight inversely proportional to severity (higher severity = lower weight = preferred path)
        edge_weight = max(0.1, 10.0 - finding.severity)
        self._graph.add_edge(parent_node, vuln_node, edge_type=ET_HAS_VULN, weight=edge_weight)
        self._finding_nodes.append(vuln_node)

        # Model lateral movement: a critical vuln on host A can pivot to other hosts
        if finding.severity >= SEVERITY_HIGH:
            self._add_lateral_edges(finding, vuln_node)

        logger.debug(
            "Finding added to graph",
            scan_id=self.scan_id,
            host=finding.host,
            severity=finding.severity,
            vuln_node=vuln_node,
        )

    def build_attack_paths(self) -> list[AttackPath]:
        """
        Discover attack paths from low-severity entry-point hosts to
        high-value / critical-severity targets using NetworkX shortest-path
        algorithms.
        """
        paths: list[AttackPath] = []

        entry_points = self._find_entry_points()
        targets = self._find_high_value_targets()

        if not entry_points:
            logger.info("No entry points found; skipping attack-path computation", scan_id=self.scan_id)
            return paths

        if not targets:
            logger.info("No high-value targets found; skipping attack-path computation", scan_id=self.scan_id)
            return paths

        for entry in entry_points:
            for target in targets:
                if entry == target:
                    continue
                try:
                    # Use Dijkstra weighted shortest path
                    raw_path = nx.dijkstra_path(self._graph, entry, target, weight="weight")
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

                risk = self.compute_risk_score(raw_path)
                ap = AttackPath(
                    id=str(uuid.uuid4()),
                    scan_id=self.scan_id,
                    nodes=raw_path,
                    risk_score=risk,
                    impact=self._describe_impact(target),
                    entry_point=entry,
                    target=target,
                )
                paths.append(ap)
                logger.debug(
                    "Attack path found",
                    scan_id=self.scan_id,
                    entry=entry,
                    target=target,
                    risk=risk,
                )

        # Deduplicate and sort by risk descending
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def compute_risk_score(self, path: list[str]) -> float:
        """
        Compute a weighted risk score for a path.

        The score is the sum of severity values of all vuln nodes in the path,
        amplified by path length (longer chains = higher risk) and normalised
        to [0, 10].
        """
        severity_sum = 0.0
        vuln_count = 0
        for node_id in path:
            node_data = self._graph.nodes.get(node_id, {})
            if node_data.get("node_type") == NT_VULN:
                sev = node_data.get("properties", {}).get("severity", 0)
                severity_sum += sev
                vuln_count += 1

        if vuln_count == 0:
            return 0.0

        avg_severity = severity_sum / vuln_count
        # Logarithmic amplification based on path length
        length_factor = 1.0 + math.log(max(1, len(path))) * 0.3
        raw = avg_severity * length_factor
        return round(min(10.0, raw), 2)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialise the graph for frontend visualisation.

        Returns:
            {
                "nodes": [{"id": ..., "node_type": ..., "identifier": ..., "properties": {...}}, ...],
                "edges": [{"source": ..., "target": ..., "edge_type": ..., "weight": ...}, ...],
            }
        """
        nodes = []
        for node_id, attrs in self._graph.nodes(data=True):
            nodes.append(
                {
                    "id": node_id,
                    "node_type": attrs.get("node_type", "unknown"),
                    "identifier": attrs.get("identifier", node_id),
                    "properties": attrs.get("properties", {}),
                }
            )

        edges = []
        for src, dst, attrs in self._graph.edges(data=True):
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "edge_type": attrs.get("edge_type", "UNKNOWN"),
                    "weight": attrs.get("weight", 1.0),
                }
            )

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_host_node(self, host: str) -> str:
        node_id = f"host:{host}"
        if not self._graph.has_node(node_id):
            self._graph.add_node(
                node_id,
                node_type=NT_HOST,
                identifier=host,
                properties={"host": host},
            )
            self._host_nodes.add(node_id)
        return node_id

    def _add_lateral_edges(self, finding: FindingInput, vuln_node: str) -> None:
        """For high-severity vulns, add edges representing lateral movement potential."""
        for host_node in list(self._host_nodes):
            target_host = self._graph.nodes[host_node]["properties"]["host"]
            if target_host == finding.host:
                continue
            edge_weight = max(0.1, 10.0 - finding.severity)
            if not self._graph.has_edge(vuln_node, host_node):
                self._graph.add_edge(
                    vuln_node,
                    host_node,
                    edge_type=ET_EXPLOITS,
                    weight=edge_weight,
                )

    def _find_entry_points(self) -> list[str]:
        """
        Entry points are host nodes that have any reachable vuln node with
        severity <= SEVERITY_MEDIUM (info/low/medium — publicly reachable).
        Traverses both direct host→vuln and host→service→vuln edges.
        """
        entries = []
        for host_node in self._host_nodes:
            found = False
            for _, neighbour in self._graph.out_edges(host_node):
                if found:
                    break
                ntype = self._graph.nodes.get(neighbour, {}).get("node_type")
                if ntype == NT_VULN:
                    sev = self._graph.nodes[neighbour].get("properties", {}).get("severity", 0)
                    if sev <= SEVERITY_MEDIUM:
                        found = True
                elif ntype == NT_SERVICE:
                    for _, vuln_node in self._graph.out_edges(neighbour):
                        if self._graph.nodes.get(vuln_node, {}).get("node_type") == NT_VULN:
                            sev = self._graph.nodes[vuln_node].get("properties", {}).get("severity", 0)
                            if sev <= SEVERITY_MEDIUM:
                                found = True
                                break
            if found:
                entries.append(host_node)
        # If no medium-or-below entry points, use ALL host nodes as entries
        return list(set(entries)) or list(self._host_nodes)

    def _find_high_value_targets(self) -> list[str]:
        """
        High-value targets are host nodes that have any reachable vuln with
        severity >= SEVERITY_HIGH (high or critical).
        Traverses both direct host→vuln and host→service→vuln edges.
        Also directly targets critical vuln nodes.
        """
        targets = []
        for host_node in self._host_nodes:
            found = False
            for _, neighbour in self._graph.out_edges(host_node):
                if found:
                    break
                ntype = self._graph.nodes.get(neighbour, {}).get("node_type")
                if ntype == NT_VULN:
                    sev = self._graph.nodes[neighbour].get("properties", {}).get("severity", 0)
                    if sev >= SEVERITY_HIGH:
                        found = True
                elif ntype == NT_SERVICE:
                    for _, vuln_node in self._graph.out_edges(neighbour):
                        if self._graph.nodes.get(vuln_node, {}).get("node_type") == NT_VULN:
                            sev = self._graph.nodes[vuln_node].get("properties", {}).get("severity", 0)
                            if sev >= SEVERITY_HIGH:
                                found = True
                                break
            if found:
                targets.append(host_node)
        # Also directly target critical/high vuln nodes
        for vuln_node in self._finding_nodes:
            props = self._graph.nodes.get(vuln_node, {}).get("properties", {})
            if props.get("severity", 0) >= SEVERITY_HIGH:
                targets.append(vuln_node)
        return list(set(targets))

    def _describe_impact(self, target_node: str) -> str:
        node_data = self._graph.nodes.get(target_node, {})
        ntype = node_data.get("node_type", "unknown")
        identifier = node_data.get("identifier", target_node)
        if ntype == NT_VULN:
            props = node_data.get("properties", {})
            return f"Remote exploitation of {props.get('cve_id') or props.get('title', identifier)}"
        if ntype == NT_HOST:
            return f"Full compromise of host {identifier}"
        return f"Exploitation of {identifier}"
