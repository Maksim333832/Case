import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Download, ExternalLink, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import type { RunOut } from "../types/workflow";

export function RunHistoryPage() {
  const [runs, setRuns] = useState<RunOut[]>([]);
  const [workflows, setWorkflows] = useState<Record<string, string>>({});
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadRuns = async () => {
    setLoading(true);
    try {
      const [runList, wfList] = await Promise.all([api.listRuns(undefined, 100), api.listWorkflows(true)]);
      const wfMap: Record<string, string> = {};
      for (const wf of wfList) wfMap[wf.id] = wf.name;
      setWorkflows(wfMap);
      setRuns(runList);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load run history");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRuns();
  }, []);

  const visible =
    statusFilter === "all" ? runs : runs.filter((r) => r.status.toLowerCase() === statusFilter);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Run History</h1>
          <p className="page-subtitle">All executed workflow runs, statuses, and exported reports</p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <select
            className="select"
            style={{ width: 150 }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="success">success</option>
            <option value="partial">partial</option>
            <option value="failed">failed</option>
            <option value="running">running</option>
          </select>
          <button type="button" className="btn" onClick={loadRuns} disabled={loading}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Workflow</th>
                <th>Trigger</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Max Severity</th>
                <th>Started</th>
                <th>Reports</th>
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ color: "#93a4c8", textAlign: "center", padding: 24 }}>
                    {loading ? "Loading..." : "No runs found."}
                  </td>
                </tr>
              ) : (
                visible.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <Link to={`/runs/${r.id}`} className="mono" style={{ color: "#7bb4ff", fontWeight: 600 }}>
                        {r.id}
                      </Link>
                    </td>
                    <td>
                      <Link to={`/editor/${r.workflow_id}`}>
                        {workflows[r.workflow_id] ?? r.workflow_id}
                      </Link>
                    </td>
                    <td>
                      <span className="badge badge-muted">{r.trigger}</span>
                    </td>
                    <td>
                      <StatusBadge status={r.status} />
                    </td>
                    <td>{r.summary?.findings?.count ?? "—"}</td>
                    <td>
                      {r.summary?.findings?.max_severity ? (
                        <SeverityBadge severity={r.summary.findings.max_severity} />
                      ) : (
                        "—"
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: "#93a4c8" }}>
                      {new Date(r.started_at).toLocaleString()}
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <Link to={`/runs/${r.id}`} className="btn btn-sm">
                          <ExternalLink size={12} /> Details
                        </Link>
                        {r.summary?.reports?.json && (
                          <a
                            href={`/api/runs/${r.id}/report.json`}
                            download={`report-${r.id}.json`}
                            className="btn btn-sm"
                          >
                            <Download size={12} /> JSON
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
