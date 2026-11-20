from __future__ import annotations

import importlib
import pkgutil
from typing import Type

from app.core.models import NodeTypeOut
from app.nodes.base import BaseNode

_REGISTRY: dict[str, Type[BaseNode]] = {}
_DISCOVERED: bool = False


def register_node(cls: Type[BaseNode]) -> Type[BaseNode]:
    """Class decorator to register a BaseNode subclass in the global node registry."""
    if not issubclass(cls, BaseNode):
        raise TypeError(f"{cls!r} must inherit from BaseNode")
    node_type = getattr(cls, "type", None)
    if not node_type or not isinstance(node_type, str):
        raise ValueError(f"{cls.__name__} must define a non-empty string 'type'")
    _REGISTRY[node_type] = cls
    return cls


def discover_nodes(force: bool = False) -> dict[str, Type[BaseNode]]:
    """Auto-discover all node modules under app.nodes.* without manual imports."""
    global _DISCOVERED
    if _DISCOVERED and not force:
        return dict(_REGISTRY)

    import app.nodes as nodes_pkg

    for module_info in pkgutil.walk_packages(nodes_pkg.__path__, prefix=f"{nodes_pkg.__name__}."):
        leaf = module_info.name.rsplit(".", 1)[-1]
        if leaf.startswith("_"):
            continue
        importlib.import_module(module_info.name)

    _DISCOVERED = True
    return dict(_REGISTRY)


def get_node_class(node_type: str) -> Type[BaseNode]:
    if not _DISCOVERED:
        discover_nodes()
    if node_type not in _REGISTRY:
        raise KeyError(f"Unknown node type: {node_type}")
    return _REGISTRY[node_type]


def create_node(node_type: str) -> BaseNode:
    return get_node_class(node_type)()


def list_node_types() -> list[NodeTypeOut]:
    if not _DISCOVERED:
        discover_nodes()
    return [
        _REGISTRY[key].to_node_type_out()
        for key in sorted(_REGISTRY.keys())
    ]


def unregister_node(node_type: str) -> None:
    _REGISTRY.pop(node_type, None)


def clear_registry() -> None:
    global _DISCOVERED
    _REGISTRY.clear()
    _DISCOVERED = False
