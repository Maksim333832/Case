import { useState } from "react";
import { Trash2, Upload } from "lucide-react";
import { api } from "../api/client";
import type { LiveNodeState } from "../hooks/useRunWebSocket";
import type { CredentialOut, NodeTypeOut, UploadOut } from "../types/workflow";
import { StatusBadge } from "./StatusBadge";

interface Props {
  selectedNodeId: string | null;
  nodeTypeDef?: NodeTypeOut;
  params: Record<string, unknown>;
  liveState?: LiveNodeState;
  credentials: CredentialOut[];
  uploads: UploadOut[];
  onUploadCreated: (up: UploadOut) => void;
  onChangeParam: (key: string, value: unknown) => void;
  onDeleteNode: (nodeId: string) => void;
}

export function NodeInspector({
  selectedNodeId,
  nodeTypeDef,
  params,
  liveState,
  credentials,
  uploads,
  onUploadCreated,
  onChangeParam,
  onDeleteNode,
}: Props) {
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  if (!selectedNodeId || !nodeTypeDef) {
    return (
      <div style={{ color: "#93a4c8", fontSize: 13 }}>
        Select a node on the canvas to configure its parameters or inspect execution output.
      </div>
    );
  }

  const properties = nodeTypeDef.params_schema?.properties ?? {};

  const handleZipFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    try {
      const uploaded = await api.uploadZip(file);
      onUploadCreated(uploaded);
      onChangeParam("upload_id", uploaded.upload_id);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{nodeTypeDef.label}</div>
          <div className="mono" style={{ fontSize: 11, color: "#93a4c8" }}>
            {selectedNodeId} · {nodeTypeDef.type}
          </div>
        </div>
        <button
          type="button"
          className="btn btn-danger btn-sm"
          onClick={() => onDeleteNode(selectedNodeId)}
          title="Delete node"
        >
          <Trash2 size={13} />
        </button>
      </div>

      {nodeTypeDef.description && (
        <div style={{ fontSize: 12, color: "#93a4c8", lineHeight: 1.45 }}>
          {nodeTypeDef.description}
        </div>
      )}

      {liveState && (
        <div className="card" style={{ padding: 12, background: "var(--bg)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>Live Execution</span>
            <StatusBadge status={liveState.status} />
          </div>
          {typeof liveState.duration_ms === "number" && (
            <div style={{ fontSize: 11.5, color: "#93a4c8" }}>
              Duration: <span className="mono">{liveState.duration_ms}ms</span>
            </div>
          )}
          {liveState.error && (
            <div style={{ marginTop: 6, fontSize: 12, color: "#fca5a5" }}>{liveState.error}</div>
          )}
          {liveState.output_preview && (
            <pre
              className="mono"
              style={{
                marginTop: 8,
                marginBottom: 0,
                fontSize: 11,
                background: "#090d1a",
                padding: 8,
                borderRadius: 6,
                overflowX: "auto",
              }}
            >
              {JSON.stringify(liveState.output_preview, null, 2)}
            </pre>
          )}
        </div>
      )}

      <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
        <div style={{ fontWeight: 700, fontSize: 12.5, marginBottom: 10 }}>Parameters</div>
        {Object.keys(properties).length === 0 ? (
          <div style={{ fontSize: 12, color: "#93a4c8" }}>This node has no configurable parameters.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {Object.entries(properties).map(([key, prop]) => {
              const rawVal = params[key] ?? prop.default ?? "";

              if (key === "upload_id") {
                return (
                  <div key={key}>
                    <label className="field-label">{key}</label>
                    <select
                      className="select"
                      value={String(rawVal ?? "")}
                      onChange={(e) => onChangeParam(key, e.target.value)}
                    >
                      <option value="">-- Select uploaded ZIP --</option>
                      {uploads.map((u) => (
                        <option key={u.upload_id} value={u.upload_id}>
                          {u.filename} ({u.upload_id})
                        </option>
                      ))}
                      {Boolean(rawVal) && !uploads.some((u) => u.upload_id === String(rawVal)) && (
                        <option value={String(rawVal)}>{String(rawVal)}</option>
                      )}
                    </select>
                    <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 8 }}>
                      <label className="btn btn-sm" style={{ cursor: "pointer" }}>
                        <Upload size={12} /> {uploading ? "Uploading..." : "Upload .zip"}
                        <input
                          type="file"
                          accept=".zip"
                          style={{ display: "none" }}
                          onChange={handleZipFile}
                          disabled={uploading}
                        />
                      </label>
                      <input
                        className="input mono"
                        style={{ flex: 1, fontSize: 11.5 }}
                        placeholder="up_..."
                        value={String(rawVal ?? "")}
                        onChange={(e) => onChangeParam(key, e.target.value)}
                      />
                    </div>
                    {uploadError && (
                      <div style={{ fontSize: 11.5, color: "#fca5a5", marginTop: 4 }}>{uploadError}</div>
                    )}
                  </div>
                );
              }

              if (key === "credential_id") {
                return (
                  <div key={key}>
                    <label className="field-label">{key}</label>
                    <select
                      className="select"
                      value={String(rawVal ?? "")}
                      onChange={(e) => onChangeParam(key, e.target.value)}
                    >
                      <option value="">-- None / Use default config --</option>
                      {credentials.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} [{c.kind}] ({c.masked_value})
                        </option>
                      ))}
                    </select>
                    {prop.description && (
                      <div style={{ fontSize: 11, color: "#93a4c8", marginTop: 4 }}>{prop.description}</div>
                    )}
                  </div>
                );
              }

              if (prop.type === "boolean") {
                return (
                  <label
                    key={key}
                    style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}
                  >
                    <input
                      type="checkbox"
                      checked={Boolean(rawVal)}
                      onChange={(e) => onChangeParam(key, e.target.checked)}
                    />
                    <span>{key}</span>
                  </label>
                );
              }

              if (Array.isArray(prop.enum) && prop.enum.length > 0) {
                return (
                  <div key={key}>
                    <label className="field-label">{key}</label>
                    <select
                      className="select"
                      value={String(rawVal)}
                      onChange={(e) => onChangeParam(key, e.target.value)}
                    >
                      {prop.enum.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  </div>
                );
              }

              if (prop.type === "integer" || prop.type === "number") {
                return (
                  <div key={key}>
                    <label className="field-label">{key}</label>
                    <input
                      type="number"
                      className="input"
                      value={rawVal === "" || rawVal === null || rawVal === undefined ? "" : Number(rawVal)}
                      onChange={(e) =>
                        onChangeParam(
                          key,
                          e.target.value === ""
                            ? 0
                            : prop.type === "integer"
                              ? parseInt(e.target.value, 10)
                              : parseFloat(e.target.value),
                        )
                      }
                    />
                    {prop.description && (
                      <div style={{ fontSize: 11, color: "#93a4c8", marginTop: 3 }}>{prop.description}</div>
                    )}
                  </div>
                );
              }

              if (prop.type === "array") {
                const strVal = Array.isArray(rawVal) ? rawVal.join(", ") : String(rawVal ?? "");
                return (
                  <div key={key}>
                    <label className="field-label">{key} (comma-separated)</label>
                    <input
                      className="input mono"
                      value={strVal}
                      onChange={(e) =>
                        onChangeParam(
                          key,
                          e.target.value
                            .split(",")
                            .map((s) => s.trim())
                            .filter(Boolean),
                        )
                      }
                    />
                    {prop.description && (
                      <div style={{ fontSize: 11, color: "#93a4c8", marginTop: 3 }}>{prop.description}</div>
                    )}
                  </div>
                );
              }

              return (
                <div key={key}>
                  <label className="field-label">{key}</label>
                  <input
                    className="input"
                    value={String(rawVal ?? "")}
                    onChange={(e) => onChangeParam(key, e.target.value)}
                  />
                  {prop.description && (
                    <div style={{ fontSize: 11, color: "#93a4c8", marginTop: 3 }}>{prop.description}</div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
