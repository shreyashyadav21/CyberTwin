import networkx as nx
from typing import List, Dict, Tuple, Optional, Any
from backend.app.schemas.network import DeviceSchema, ConnectionSchema, SecurityRuleSchema

def build_network_graph(devices: List[DeviceSchema], connections: List[ConnectionSchema]) -> nx.Graph:
    G = nx.Graph()
    for dev in devices:
        G.add_node(dev.id, **dev.model_dump())
    for conn in connections:
        G.add_edge(conn.source, conn.target, id=conn.id)
    return G

def matches_rule_endpoint(rule_endpoint: str, device: DeviceSchema) -> bool:
    if rule_endpoint == "*":
        return True
    if rule_endpoint.lower() == device.id.lower():
        return True
    if device.zone and rule_endpoint.lower() == device.zone.lower():
        return True
    return False

def matches_service(rule_service: str, service_name: str, port: Optional[int] = None) -> bool:
    if rule_service == "*" or rule_service.lower() == "any":
        return True
    if service_name and rule_service.lower() == service_name.lower():
        return True
    if port is not None and str(port) == rule_service.strip():
        return True
    return False

def evaluate_hop_traffic(
    src_device: DeviceSchema,
    dst_device: DeviceSchema,
    final_destination: Optional[DeviceSchema] = None,
    rules: Optional[List[SecurityRuleSchema]] = None,
    service: str = "*",
    port: Optional[int] = None,
    origin_device: Optional[DeviceSchema] = None
) -> Tuple[bool, Optional[SecurityRuleSchema], str]:
    """
    Evaluates hop reachability using a real stateful firewall policy engine:
    1. Virtual Containment Check: Devices with status 'isolated' or 'quarantined' are immediately blocked.
    2. Explicit Rule Matching ordered by priority:
       - 'reject': Connection rejected (TCP RST / Port Unreachable).
       - 'deny': Packet dropped silently.
       - 'allow': Stateful connection established.
    3. Boundary / Zone / Firewall Check: Enforces default deny between dissimilar zones or crossing firewalls.
    4. Intra-zone unrestricted fallback.
    """
    dest = final_destination or dst_device
    origin = origin_device or src_device
    active_rules = rules or []

    # 1. Virtual Isolation / Containment Check
    for dev, role in [(src_device, "Source"), (dst_device, "Destination"), (origin, "Originator"), (dest, "Final Target")]:
        if getattr(dev, "security_status", "normal") in ("isolated", "quarantined"):
            return (
                False,
                None,
                f"Blocked: {role} device '{dev.name}' ({dev.id}) is under active incident isolation containment. Network interface disabled."
            )

    # Sort rules by priority (ascending: 10 before 100)
    sorted_rules = sorted(active_rules, key=lambda r: getattr(r, "priority", 100))

    # 2. Explicit DENY and REJECT take precedence
    for rule in sorted_rules:
        if rule.action in ("deny", "reject"):
            src_matches = matches_rule_endpoint(rule.source, src_device) or matches_rule_endpoint(rule.source, origin)
            dst_matches = matches_rule_endpoint(rule.destination, dst_device) or matches_rule_endpoint(rule.destination, dest)
            svc_matches = matches_service(rule.service, service, port)
            if src_matches and dst_matches and svc_matches:
                prio = getattr(rule, "priority", 100)
                if rule.action == "reject":
                    return False, rule, f"Rejected: Connection actively refused by rule '{rule.id}' (TCP RST / ICMP Unreachable, Priority {prio})"
                return False, rule, f"Denied: Packet dropped silently by explicit security rule '{rule.id}' (Priority {prio})"

    # 3. Explicit ALLOW rules
    matched_allow_rule = None
    for rule in sorted_rules:
        if rule.action == "allow":
            src_matches = matches_rule_endpoint(rule.source, src_device) or matches_rule_endpoint(rule.source, origin)
            dst_matches = matches_rule_endpoint(rule.destination, dst_device) or matches_rule_endpoint(rule.destination, dest)
            svc_matches = matches_service(rule.service, service, port)
            if src_matches and dst_matches and svc_matches:
                matched_allow_rule = rule
                break

    if matched_allow_rule:
        prio = getattr(matched_allow_rule, "priority", 100)
        return (
            True,
            matched_allow_rule,
            f"Permitted: Stateful connection ESTABLISHED by rule '{matched_allow_rule.id}' ({matched_allow_rule.source} -> {matched_allow_rule.destination}:{matched_allow_rule.service}, Priority {prio})"
        )

    # 4. Default Deny at Firewalls or Zone Boundaries
    is_firewall = (src_device.type == "firewall" or dst_device.type == "firewall")
    different_zones = (src_device.zone != dst_device.zone)

    if is_firewall or different_zones:
        return (
            False,
            None,
            f"Blocked: Default Deny policy enforced at firewall boundary for traffic from '{origin.name}' to '{dst_device.name}' on service '{service}'"
        )

    return True, None, "Permitted: Unfiltered intra-zone traffic"

def find_all_candidate_paths(
    graph: nx.Graph,
    source_id: str,
    target_id: str,
    max_hops: int = 5
) -> List[List[str]]:
    if source_id not in graph or target_id not in graph:
        return []
    try:
        paths = list(nx.all_simple_paths(graph, source=source_id, target=target_id, cutoff=max_hops))
        paths.sort(key=len)
        return paths
    except Exception:
        return []

def evaluate_complete_path(
    path: List[str],
    devices_dict: Dict[str, DeviceSchema],
    rules: List[SecurityRuleSchema],
    service: str = "*",
    port: Optional[int] = None
) -> Tuple[bool, List[Dict[str, Any]]]:
    if len(path) < 2:
        return False, []

    final_dest = devices_dict.get(path[-1])
    origin_dev = devices_dict.get(path[0])
    if not final_dest or not origin_dev:
        return False, []

    hop_results = []
    overall_allowed = True

    for i in range(len(path) - 1):
        u_id = path[i]
        v_id = path[i + 1]
        src_dev = devices_dict.get(u_id)
        dst_dev = devices_dict.get(v_id)
        if not src_dev or not dst_dev:
            overall_allowed = False
            break

        allowed, rule, reason = evaluate_hop_traffic(
            src_device=src_dev,
            dst_device=dst_dev,
            final_destination=final_dest,
            rules=rules,
            service=service,
            port=port,
            origin_device=origin_dev
        )

        connection_state = "ESTABLISHED" if allowed else ("REJECTED" if rule and rule.action == "reject" else "DROPPED")

        hop_results.append({
            "from_node": u_id,
            "to_node": v_id,
            "from_name": src_dev.name,
            "to_name": dst_dev.name,
            "service": service,
            "port": port,
            "allowed": allowed,
            "rule_id": rule.id if rule else None,
            "rule_action": rule.action if rule else ("allow" if allowed else "deny"),
            "connection_state": connection_state,
            "reason": reason
        })

        if not allowed:
            overall_allowed = False
            break

    return overall_allowed, hop_results
