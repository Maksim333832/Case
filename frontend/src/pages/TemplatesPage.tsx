import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, Layers } from "lucide-react";
import { api } from "../api/client";
import type { WorkflowOut } from "../types/workflow";

export function TemplatesPage() {
  const navigate = useNavigate();
  const [templates, setTemplates] = useState<WorkflowOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    api
      .listTemplates()
      .then(setTemplates)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load templates"))
      .finally(() => setLoading(false));
  }, []);

  const handleUseTemplate = async (tpl: WorkflowOut) => {
    setBusyId(tpl.id);
    setError(null);
    try {
      const copied = await api.copyTemplate(tpl.id, {
        name: `${tpl.name} (Workspace)`,
      });
      navigate(`/editor/${copied.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to copy template");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Workflow Templates</h1>
          <p className="page-subtitle">
            Pre-built security audit blueprints ready to customize and execute
          </p>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {loading && <div style={{ color: "#93a4c8" }}>Loading templates...</div>}

      <div className="grid-2">
        {templates.map((tpl) => (
          <div key={tpl.id} className="card" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Layers size={16} color="#60a5fa" />
                  <span style={{ fontWeight: 700, fontSize: 16 }}>{tpl.name}</span>
                </div>
                <div className="mono" style={{ fontSize: 11, color: "#93a4c8", marginTop: 2 }}>
                  {tpl.id}
                </div>
              </div>
              <span className="badge badge-muted">{tpl.graph.nodes.length} nodes</span>
            </div>

            <div style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.5 }}>
              {tpl.description || "Security workflow blueprint."}
            </div>

            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {tpl.graph.nodes.map((n) => (
                <span key={n.id} className="badge badge-muted mono" style={{ fontSize: 10.5 }}>
                  {n.type}
                </span>
              ))}
            </div>

            <div style={{ marginTop: "auto", paddingTop: 8 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => handleUseTemplate(tpl)}
                disabled={busyId === tpl.id}
              >
                <Copy size={14} /> {busyId === tpl.id ? "Creating..." : "Use Template in Editor"}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
