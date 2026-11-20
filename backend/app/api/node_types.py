from __future__ import annotations

from fastapi import APIRouter

from app.core.models import NodeTypeOut
from app.nodes.registry import list_node_types

router = APIRouter(prefix="/api", tags=["node-types"])


@router.get("/node-types", response_model=list[NodeTypeOut])
def get_node_types() -> list[NodeTypeOut]:
    return list_node_types()
