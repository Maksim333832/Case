from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from pydantic import ValidationError

from app.core.models import WorkflowEdgeModel, WorkflowGraphModel, WorkflowNodeModel
from app.nodes.base import BaseNode, Port
from app.nodes.registry import get_node_class


class WorkflowValidationError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class ResolvedEdge:
    edge: WorkflowEdgeModel
    source_port: str
    target_port: str


def _resolve_output_port(node_id: str, node_cls: type[BaseNode], handle: str | None) -> Port:
    if not node_cls.outputs:
        raise ValueError(f"Node '{node_id}' ({node_cls.type}) has no output ports")
    if handle:
        for port in node_cls.outputs:
            if port.name == handle:
                return port
        available = ", ".join(p.name for p in node_cls.outputs)
        raise ValueError(f"Node '{node_id}' has no output port '{handle}' (available: {available})")
    if len(node_cls.outputs) == 1:
        return node_cls.outputs[0]
    available = ", ".join(p.name for p in node_cls.outputs)
    raise ValueError(f"Edge from '{node_id}' must specify sourceHandle ({available})")


def _resolve_input_port(node_id: str, node_cls: type[BaseNode], handle: str | None) -> Port:
    if not node_cls.inputs:
        raise ValueError(f"Node '{node_id}' ({node_cls.type}) has no input ports")
    if handle:
        for port in node_cls.inputs:
            if port.name == handle:
                return port
        available = ", ".join(p.name for p in node_cls.inputs)
        raise ValueError(f"Node '{node_id}' has no input port '{handle}' (available: {available})")
    if len(node_cls.inputs) == 1:
        return node_cls.inputs[0]
    available = ", ".join(p.name for p in node_cls.inputs)
    raise ValueError(f"Edge to '{node_id}' must specify targetHandle ({available})")


def _ports_compatible(src: Port, dst: Port) -> bool:
    if src.kind == "Any" or dst.kind == "Any":
        return True
    return src.kind == dst.kind


def validate_and_sort_graph(graph: WorkflowGraphModel) -> tuple[list[str], list[ResolvedEdge]]:
    errors: list[str] = []
    if not graph.nodes:
        raise WorkflowValidationError(["Workflow graph must contain at least one node"])

    nodes_by_id: dict[str, WorkflowNodeModel] = {}
    node_classes: dict[str, type[BaseNode]] = {}

    for node in graph.nodes:
        if node.id in nodes_by_id:
            errors.append(f"Duplicate node id '{node.id}'")
            continue
        nodes_by_id[node.id] = node
        try:
            node_cls = get_node_class(node.type)
            node_classes[node.id] = node_cls
            node_cls.Params.model_validate(node.params)
        except KeyError:
            errors.append(f"Node '{node.id}' uses unknown type '{node.type}'")
        except ValidationError as exc:
            errors.append(f"Node '{node.id}' ({node.type}) invalid params: {exc.errors()[0]['msg']}")

    if errors:
        raise WorkflowValidationError(errors)

    resolved_edges: list[ResolvedEdge] = []
    incoming_by_port: dict[tuple[str, str], list[ResolvedEdge]] = defaultdict(list)
    outgoing: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = {nid: 0 for nid in nodes_by_id}
    undirected: dict[str, set[str]] = {nid: set() for nid in nodes_by_id}

    for edge in graph.edges:
        if edge.source not in nodes_by_id:
            errors.append(f"Edge '{edge.id}' references unknown source node '{edge.source}'")
            continue
        if edge.target not in nodes_by_id:
            errors.append(f"Edge '{edge.id}' references unknown target node '{edge.target}'")
            continue
        if edge.source == edge.target:
            errors.append(f"Edge '{edge.id}' creates a self-loop on '{edge.source}'")
            continue

        src_cls = node_classes[edge.source]
        dst_cls = node_classes[edge.target]

        try:
            src_port = _resolve_output_port(edge.source, src_cls, edge.sourceHandle)
            dst_port = _resolve_input_port(edge.target, dst_cls, edge.targetHandle)
        except ValueError as exc:
            errors.append(f"Edge '{edge.id}': {exc}")
            continue

        if not _ports_compatible(src_port, dst_port):
            errors.append(
                f"Edge '{edge.id}' incompatible port types: {edge.source}.{src_port.name} ({src_port.kind}) -> "
                f"{edge.target}.{dst_port.name} ({dst_port.kind})"
            )
            continue

        re_edge = ResolvedEdge(edge=edge, source_port=src_port.name, target_port=dst_port.name)
        resolved_edges.append(re_edge)
        incoming_by_port[(edge.target, dst_port.name)].append(re_edge)
        outgoing[edge.source].append(edge.target)
        in_degree[edge.target] += 1
        undirected[edge.source].add(edge.target)
        undirected[edge.target].add(edge.source)

    # Check required inputs for non-trigger nodes
    for nid, node_cls in node_classes.items():
        for port in node_cls.inputs:
            if port.required and not incoming_by_port.get((nid, port.name)):
                errors.append(f"Node '{nid}' ({node_cls.type}) missing required input on port '{port.name}'")

    # Check connected components: each component must have exactly one trigger
    visited: set[str] = set()
    for nid in nodes_by_id:
        if nid in visited:
            continue
        comp: list[str] = []
        queue = deque([nid])
        visited.add(nid)
        while queue:
            cur = queue.popleft()
            comp.append(cur)
            for nb in undirected[cur]:
                if nb not in visited:
                    visited.add(nb)
                    queue.append(nb)

        triggers = [c for c in comp if node_classes[c].group == "trigger"]
        if len(triggers) == 0:
            errors.append(f"Connected component {sorted(comp)} must contain exactly one trigger node (found 0)")
        elif len(triggers) > 1:
            errors.append(f"Connected component {sorted(comp)} has multiple trigger nodes: {triggers}")

    # Topological sort / cycle detection
    topo_queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
    topo_order: list[str] = []
    deg_copy = dict(in_degree)
    while topo_queue:
        cur = topo_queue.popleft()
        topo_order.append(cur)
        for nxt in outgoing[cur]:
            deg_copy[nxt] -= 1
            if deg_copy[nxt] == 0:
                topo_queue.append(nxt)

    if len(topo_order) != len(nodes_by_id):
        errors.append("Workflow graph contains a cycle")

    if errors:
        raise WorkflowValidationError(errors)

    return topo_order, resolved_edges
