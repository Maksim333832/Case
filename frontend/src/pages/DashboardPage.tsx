import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowRight,
  GitBranch,
  Layers,
  Play,
  Trash2,
} from "lucide-react";
import { api } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import type { HealthOut, NodeTypeOut, RunOut, WorkflowOut } from "../types/workflow";

export function DashboardPage() {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthOut | null>(null);
  const [nodeTypes, setNodeTypes] = useState<NodeTypeOut[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowOut[]>([]);
  const [templates, setTemplates] = useState<WorkflowOut[]>([]);
  const [runs, setRuns] = useState<RunOut[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadAll = async () => {
    try {
      const [h, nt, wf, tpl, r] = await Promise.all([
        api.getHealth(),
        api.getNodeTypes(),
        api.listWorkflows(false),
        api.listTemplates(),
        api.listRuns(undefined, 15),
      ]);
      setHealth(h);
      setNodeTypes(nt);
      setWorkflows(wf);
      setTemplates(tpl);
      setRuns(r);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard data");
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleQuickUseTemplate = async (tplId: string) => {
    setBusyId(tplId);
    try {
      const created = await api.copyTemplate(tplId);
      navigate(`/editor/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to clone template");
    } finally {
      setBusyId(null);
    }
  };

  const handleQuickRun = async (wfId: string) => {
    setBusyId(wfId);
    try {
      const res = await api.runWorkflow(wfId, false);
      navigate(`/runs/${res.run_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run workflow");
    } finally {
      setBusyId(null);
    }
  };

  const handleDeleteWorkflow = async (wfId: string) => {
    try {
      await api.deleteWorkflow(wfId);
      setWorkflows((prev) => prev.filter((w) => w.id !== wfId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete workflow");
    }
  };

  const latestCompleted = runs.find((r) => r.summary?.findings?.count !== undefined);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Workflow Dashboard</h1>
          <p className="page-subtitle">
            Automated Secrets, SCA &amp; SAST scanning pipelines with validated AI reporting
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Link to="/templates" className="btn">
            <Layers size={15} /> Browse Templates
          </Link>
          <Link to="/editor" className="btn btn-primary">
            <GitBranch size={15} /> Open Editor
          </Link>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="grid-4">
        <div className="card">
          <div className="stat-label">Registered Nodes</div>
          <div className="stat-value">{nodeTypes.length}</div>
          <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
            Auto-discovered · {health?.use_stub_scanners ? "Stubs ON" : "Real Scanners"}
          </div>
        </div>
        <div className="card">
          <div className="stat-label">Saved Workflows</div>
          <div className="stat-value">{workflows.length}</div>
          <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
            {templates.length} ready templates available
          </div>
        </div>
        <div className="card">
          <div className="stat-label">Total Runs</div>
          <div className="stat-value">{runs.length}</div>
          <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
            {runs.filter((r) => r.status === "success").length} successful
          </div>
        </div>
        <div className="card">
          <div className="stat-label">Latest Audit Findings</div>
          <div className="stat-value">
            {latestCompleted?.summary?.findings?.count ?? "—"}
          </div>
          <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
            Max severity:{" "}
            {latestCompleted?.summary?.findings?.max_severity ? (
              <SeverityBadge severity={latestCompleted.summary.findings.max_severity} />
            ) : (
              "—"
            )}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">
            <span>Workflows</span>
            <Link to="/editor" className="btn btn-sm">
              + New Workflow
            </Link>
          </div>
          {workflows.length === 0 ? (
            <div style={{ color: "#93a4c8", fontSize: 13 }}>
              No custom workflows yet. Clone a template below or build one in the Editor.
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Nodes</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {workflows.map((wf) => (
                    <tr key={wf.id}>
                      <td>
                        <Link to={`/editor/${wf.id}`} style={{ fontWeight: 600, color: "#7bb4ff" }}>
                          {wf.name}
                        </Link>
                        <div className="mono" style={{ fontSize: 11, color: "#93a4c8" }}>
                          {wf.id}
                        </div>
                      </td>
                      <td>{wf.graph.nodes.length}</td>
                      <td>
                        <div style={{ display: "flex", gap: 6 }}>
                          <button
                            type="button"
                            className="btn btn-sm btn-success"
                            onClick={() => handleQuickRun(wf.id)}
                            disabled={busyId === wf.id}
                          >
                            <Play size={12} /> Run
                          </button>
                          <Link to={`/editor/${wf.id}`} className="btn btn-sm">
                            Edit
                          </Link>
                          <button
                            type="button"
                            className="btn btn-sm btn-danger"
                            onClick={() => handleDeleteWorkflow(wf.id)}
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {templates.length > 0 && (
            <div style={{ marginTop: 18, paddingTop: 14, borderTop: "1px solid var(--border)" }}>
              <div style={{ fontSize: 12.5, fontWeight: 700, marginBottom: 8, color: "#93a4c8" }}>
                Quick-start from Template
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {templates.map((tpl) => (
                  <button
                    key={tpl.id}
                    type="button"
                    className="btn btn-sm"
                    onClick={() => handleQuickUseTemplate(tpl.id)}
                    disabled={busyId === tpl.id}
                  >
                    {tpl.name} <ArrowRight size={12} />
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-title">
            <span>Recent Runs</span>
            <Link to="/runs" className="btn btn-sm">
              All Runs
            </Link>
          </div>
          {runs.length === 0 ? (
            <div style={{ color: "#93a4c8", fontSize: 13 }}>No workflow runs recorded yet.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Run</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Max Sev</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(0, 8).map((r) => (
                    <tr key={r.id}>
                      <td>
                        <Link to={`/runs/${r.id}`} style={{ fontWeight: 600, color: "#7bb4ff" }} className="mono">
                          {r.id}
                        </Link>
                        <div style={{ fontSize: 11, color: "#93a4c8" }}>
                          {new Date(r.started_at).toLocaleString()}
                        </div>
                      </td>
                      <td>
                        <StatusBadge status={r.status} />
                      </td>
                      <td>{r.summary?.findings?.count ?? "—"}</td>
                      <td>
                        {r.summary?.findings?.max_severity ? (
                          <SeverityBadge severity={r.summary.findings.max_severity} />
                        ) : (
                          <span style={{ color: "#93a4c8" }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
