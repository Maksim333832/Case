import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { LiveNodeState } from "../hooks/useRunWebSocket";
import type { NodeTypeOut } from "../types/workflow";
import { StatusBadge } from "../components/StatusBadge";

export interface WorkflowNodeData extends Record<string, unknown> {
  label: string;
  nodeType: string;
  group: string;
  params: Record<string, unknown>;
  typeDef?: NodeTypeOut;
  liveState?: LiveNodeState;
}

const GROUP_COLORS: Record<string, string> = {
  trigger: "#8b5cf6",
  source: "#06b6d4",
  scanner: "#f59e0b",
  logic: "#ec4899",
  findings: "#10b981",
  ai: "#3b82f6",
  notify: "#6366f1",
};

export function WorkflowNode({ data, selected }: NodeProps) {
  const nodeData = data as WorkflowNodeData;
  const inputs = nodeData.typeDef?.inputs ?? [];
  const outputs = nodeData.typeDef?.outputs ?? [];
  const status = nodeData.liveState?.status;
  const color = GROUP_COLORS[nodeData.group] ?? "#64748b";

  return (
    <div
      className={`wf-node ${selected ? "selected" : ""} ${status ? `status-${status}` : ""}`}
    >
      <div
        className="wf-node-header"
        style={{ borderTop: `3px solid ${color}` }}
      >
        <div>
          <div style={{ fontWeight: 700, fontSize: 12.5 }}>{nodeData.label}</div>
          <div className="mono" style={{ fontSize: 10, color: "#93a4c8" }}>
            {nodeData.nodeType}
          </div>
        </div>
        <span
          className="badge badge-muted"
          style={{ textTransform: "uppercase", fontSize: 9.5 }}
        >
          {nodeData.group}
        </span>
      </div>

      <div className="wf-node-ports">
        <div className="wf-port-col">
          {inputs.map((inp) => (
            <div key={inp.name} className="wf-port-row" title={`${inp.kind}: ${inp.description}`}>
              <Handle
                type="target"
                position={Position.Left}
                id={inp.name}
                style={{ left: -15 }}
              />
              <span>{inp.name}</span>
            </div>
          ))}
        </div>

        <div className="wf-port-col" style={{ alignItems: "flex-end" }}>
          {outputs.map((out) => (
            <div key={out.name} className="wf-port-row out" title={`${out.kind}: ${out.description}`}>
              <span>{out.name}</span>
              <Handle
                type="source"
                position={Position.Right}
                id={out.name}
                style={{ right: -15 }}
              />
            </div>
          ))}
        </div>
      </div>

      {(status || nodeData.liveState?.error) && (
        <div className="wf-node-footer">
          <StatusBadge status={status} />
          {typeof nodeData.liveState?.duration_ms === "number" && (
            <span className="mono" style={{ color: "#93a4c8" }}>
              {nodeData.liveState.duration_ms}ms
            </span>
          )}
        </div>
      )}
      {nodeData.liveState?.error && (
        <div
          style={{
            padding: "5px 10px 7px",
            fontSize: 11,
            color: "#fca5a5",
            borderTop: "1px solid rgba(239,68,68,0.25)",
            wordBreak: "break-word",
          }}
        >
          {nodeData.liveState.error}
        </div>
      )}
    </div>
  );
}
