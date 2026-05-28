"""
Attack path engine using NetworkX — computes all lateral movement paths
from internet-exposed hosts to high-value internal targets.
"""
import json
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


def build_host_graph(hosts: list) -> "nx.DiGraph":
    G = nx.DiGraph()
    for host in hosts:
        ip = host.get("ip", "unknown")
        G.add_node(ip, **{k: v for k, v in host.items() if k != "ip"})

    for host in hosts:
        src = host.get("ip")
        vulns = host.get("vulnerabilities", [])
        # Hosts with critical/high CVEs can pivot to adjacent network hosts
        has_rce = any(
            v.get("priority") in ("critical", "high") for v in vulns
        )
        if has_rce:
            for other in hosts:
                dst = other.get("ip")
                if dst != src:
                    G.add_edge(src, dst, via="exploit")
    return G


def compute_attack_paths_handler(hosts: list, targets: list = None) -> str:
    if not HAS_NETWORKX:
        return json.dumps({"error": "networkx not installed", "paths": []})

    G = build_host_graph(hosts)
    all_ips = [h.get("ip") for h in hosts]

    internet_exposed = [
        h.get("ip") for h in hosts if h.get("exposed_to_internet", False)
    ]
    if not internet_exposed:
        internet_exposed = all_ips[:1]

    high_value = targets or [
        h.get("ip") for h in hosts if h.get("role") in ("dc", "database", "admin")
    ]

    paths = []
    for src in internet_exposed:
        for dst in high_value:
            if src == dst:
                continue
            try:
                for path in nx.all_simple_paths(G, src, dst, cutoff=5):
                    paths.append({"from": src, "to": dst, "hops": path, "length": len(path) - 1})
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass

    paths.sort(key=lambda p: p["length"])
    return json.dumps({"paths": paths[:20]})
