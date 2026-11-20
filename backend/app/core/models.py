from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator


class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # Required for export
    category: Literal["SECRET", "SAST", "SCA"]
    path: str

    # SECRET / SAST
    class_: str | None = Field(default=None, alias="class")
    line: StrictInt | None = None
    endLine: StrictInt | None = None

    # SCA
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    advisoryId: str | None = None

    # Common optional
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    description: str | None = None
    remediation: str | None = None

    # Internal only — NEVER exported via to_submission()
    id: str = ""
    rule_id: str = ""
    evidence: str | None = None
    confidence: float = 1.0
    aliases: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("path must be a non-empty string")
        cleaned = value.strip().replace("\\", "/")
        if cleaned.startswith("/"):
            raise ValueError("path must be relative, not absolute")
        if ":" in cleaned:
            raise ValueError("path must not contain ':' or drive letters")
        parts = [p for p in cleaned.split("/") if p]
        if any(p == ".." for p in parts) or cleaned == "..":
            raise ValueError("path must not contain '..'")
        normalized = "/".join(parts)
        if not normalized:
            raise ValueError("path must not be empty after normalization")
        return normalized

    @field_validator("class_", "group", "artifact", "version", "advisoryId", "description", "remediation")
    @classmethod
    def _strip_optional_nonempty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped if stripped else None

    @model_validator(mode="after")
    def _validate_category_requirements(self) -> "Finding":
        if self.line is not None and self.line < 1:
            raise ValueError("line must be >= 1")
        if self.endLine is not None:
            if self.line is None:
                raise ValueError("endLine requires line to be set")
            if self.endLine < self.line or self.endLine > self.line + 14:
                raise ValueError("endLine must satisfy line <= endLine <= line + 14")

        if self.category in ("SECRET", "SAST"):
            if not self.class_:
                raise ValueError(f"{self.category} finding requires non-empty 'class'")
            if self.line is None:
                raise ValueError(f"{self.category} finding requires integer 'line' >= 1")
        elif self.category == "SCA":
            missing = [
                field_name
                for field_name in ("group", "artifact", "version", "advisoryId")
                if not getattr(self, field_name)
            ]
            if missing:
                raise ValueError(f"SCA finding requires non-empty fields: {', '.join(missing)}")
        return self

    def to_submission(self) -> dict[str, Any]:
        """Serialize strictly to organizer submission format (omitting internal and null fields)."""
        out: dict[str, Any] = {
            "category": self.category,
            "path": self.path,
        }
        if self.category in ("SECRET", "SAST"):
            out["class"] = self.class_
            out["line"] = self.line
            if self.endLine is not None:
                out["endLine"] = self.endLine
        elif self.category == "SCA":
            out["group"] = self.group
            out["artifact"] = self.artifact
            out["version"] = self.version
            out["advisoryId"] = self.advisoryId

        if self.severity is not None:
            out["severity"] = self.severity
        if self.description is not None:
            out["description"] = self.description
        if self.remediation is not None:
            out["remediation"] = self.remediation
        return out


class WorkflowNodeModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    position: dict[str, float] = Field(default_factory=lambda: {"x": 0.0, "y": 0.0})

    @model_validator(mode="before")
    @classmethod
    def _accept_react_flow_data(cls, raw: Any) -> Any:
        if isinstance(raw, dict):
            data = dict(raw)
            if "params" not in data and isinstance(data.get("data"), dict):
                node_data = data["data"]
                data["params"] = node_data.get("params", {})
            return data
        return raw


class WorkflowEdgeModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    sourceHandle: str | None = None
    target: str = Field(min_length=1)
    targetHandle: str | None = None


class WorkflowGraphModel(BaseModel):
    nodes: list[WorkflowNodeModel]
    edges: list[WorkflowEdgeModel] = Field(default_factory=list)


class WorkflowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    graph: WorkflowGraphModel
    is_template: bool = False


class WorkflowUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    graph: WorkflowGraphModel | None = None
    is_template: bool | None = None


class WorkflowOut(BaseModel):
    id: str
    name: str
    description: str
    graph: WorkflowGraphModel
    is_template: bool
    created_at: datetime
    updated_at: datetime


class RunRequest(BaseModel):
    trigger: str = "manual"
    params: dict[str, Any] = Field(default_factory=dict)


class NodeRunOut(BaseModel):
    node_id: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    output_preview: dict[str, Any] | None = None
    error: str | None = None


class RunOut(BaseModel):
    id: str
    workflow_id: str
    status: str
    trigger: str
    started_at: datetime
    finished_at: datetime | None = None
    summary: dict[str, Any] | None = None
    ai_report: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    node_runs: list[NodeRunOut] = Field(default_factory=list)


class PortSchema(BaseModel):
    name: str
    kind: Literal["Workspace", "Findings", "Report", "Any"]
    required: bool = True
    multiple: bool = False
    description: str = ""


class NodeTypeOut(BaseModel):
    type: str
    label: str
    group: str
    description: str = ""
    inputs: list[PortSchema]
    outputs: list[PortSchema]
    params_schema: dict[str, Any]


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(min_length=1, max_length=60)
    value: str = Field(min_length=1)


class CredentialOut(BaseModel):
    id: str
    name: str
    kind: str
    masked_value: str
    created_at: datetime


class UploadOut(BaseModel):
    upload_id: str
    filename: str
    size_bytes: int
    created_at: datetime


class WorkflowEvent(BaseModel):
    event: Literal[
        "run_started",
        "node_started",
        "node_finished",
        "node_failed",
        "node_skipped",
        "run_finished",
    ]
    run_id: str
    node_id: str | None = None
    status: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int | None = None
    output_preview: dict[str, Any] | None = None
    error: str | None = None
    summary: dict[str, Any] | None = None
