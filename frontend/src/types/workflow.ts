export type PortKind = "Workspace" | "Findings" | "Report" | "Any";

export interface PortSchema {
  name: string;
  kind: PortKind;
  required: boolean;
  multiple: boolean;
  description: string;
}

export interface JsonSchemaProperty {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  enum?: string[];
  items?: { type?: string };
}

export interface NodeParamsSchema {
  type?: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
}

export interface NodeTypeOut {
  type: string;
  label: string;
  group: string;
  description: string;
  inputs: PortSchema[];
  outputs: PortSchema[];
  params_schema: NodeParamsSchema;
}

export interface WorkflowNodeModel {
  id: string;
  type: string;
  params: Record<string, unknown>;
  position: { x: number; y: number };
}

export interface WorkflowEdgeModel {
  id: string;
  source: string;
  sourceHandle?: string | null;
  target: string;
  targetHandle?: string | null;
}

export interface WorkflowGraphModel {
  nodes: WorkflowNodeModel[];
  edges: WorkflowEdgeModel[];
}

export interface WorkflowOut {
  id: string;
  name: string;
  description: string;
  graph: WorkflowGraphModel;
  is_template: boolean;
  created_at: string;
  updated_at: string;
}

export type NodeExecStatus = "pending" | "running" | "success" | "failed" | "skipped";

export interface NodeRunOut {
  node_id: string;
  status: NodeExecStatus | string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  output_preview: Record<string, unknown> | null;
  error: string | null;
}

export interface FindingSubmission {
  category: "SECRET" | "SAST" | "SCA";
  path: string;
  class?: string;
  line?: number;
  endLine?: number;
  group?: string;
  artifact?: string;
  version?: string;
  advisoryId?: string;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description?: string;
  remediation?: string;
}

export interface AiExplanationItem {
  finding_ref: string;
  explanation: string;
  risk: string;
  fix_steps: string[];
}

export interface AiValidationStats {
  passed: boolean;
  retried: boolean;
  dropped_items: number;
  dropped_cve: number;
  used_fallback: boolean;
  reasons?: string[];
}

export interface AiReport {
  summary?: string;
  findings?: AiExplanationItem[];
  items?: AiExplanationItem[];
  validation?: AiValidationStats;
  model?: string;
}

export interface RunSummary {
  status?: string;
  nodes?: {
    total: number;
    success: number;
    failed: number;
    skipped: number;
  };
  findings?: {
    count: number;
    max_severity: string | null;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
  };
  reports?: {
    json?: string;
    md?: string;
  };
}

export interface RunOut {
  id: string;
  workflow_id: string;
  status: string;
  trigger: string;
  started_at: string;
  finished_at: string | null;
  summary: RunSummary | null;
  ai_report: AiReport | null;
  findings: FindingSubmission[];
  node_runs: NodeRunOut[];
}

export interface CredentialOut {
  id: string;
  name: string;
  kind: string;
  masked_value: string;
  created_at: string;
}

export interface UploadOut {
  upload_id: string;
  filename: string;
  size_bytes: number;
  created_at: string;
}

export interface LlmSettingsOut {
  base_url: string;
  model: string;
  has_api_key: boolean;
  masked_api_key: string;
  source: string;
}

export interface HealthOut {
  status: string;
  app: string;
  use_stub_scanners: boolean;
}

export interface WorkflowEvent {
  event:
    | "run_started"
    | "node_started"
    | "node_finished"
    | "node_failed"
    | "node_skipped"
    | "run_finished"
    | "ping";
  run_id: string;
  node_id?: string | null;
  status?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  output_preview?: Record<string, unknown> | null;
  error?: string | null;
  summary?: Record<string, unknown> | null;
}
