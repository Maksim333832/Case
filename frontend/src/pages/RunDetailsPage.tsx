import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Bot,
  Download,
  FileText,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { api } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { useRunWebSocket } from "../hooks/useRunWebSocket";
import type { FindingSubmission, RunOut } from "../types/workflow";

export function RunDetailsPage() {
  const { runId } = useParams<{ runId: string }>();
  const [run, setRun] = useState<RunOut | null>(null);
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [showMarkdown, setShowMarkdown] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);

  const loadRun = async (id: string) => {
    try {
      const data = await api.getRun(id);
      setRun(data);
      setError(null);
      if (data.summary?.reports?.md) {
        api.getReportMarkdown(id).then(setMarkdown).catch(() => {});
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load run details");
    }
  };

  useEffect(() => {
    if (runId) loadRun(runId);
  }, [runId]);

  const activeWsRunId = run && !run.finished_at ? run.id : null;
  const { nodeStates } = useRunWebSocket(activeWsRunId, (finishedId) => {
    loadRun(finishedId);
  });

  const findings = run?.findings ?? [];

  const filteredFindings = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f: FindingSubmission) => {
      if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
      if (severityFilter !== "all" && (f.severity || "").toUpperCase() !== severityFilter) {
        return false;
      }
      if (!q) return true;
      const hay = [
        f.category,
        f.path,
        f.class,
        f.group,
        f.artifact,
        f.version,
        f.advisoryId,
        f.description,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [findings, categoryFilter, severityFilter, query]);

  const aiItems = run?.ai_report?.findings ?? run?.ai_report?.items ?? [];
  const validation = run?.ai_report?.validation;
  const sevCounts = run?.summary?.findings?.by_severity ?? {};

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h1 className="page-title mono">{runId}</h1>
            {run && <StatusBadge status={run.status} />}
          </div>
          <p className="page-subtitle">
            {run
              ? `Workflow: ${run.workflow_id} · Trigger: ${run.trigger} · Started ${new Date(run.started_at).toLocaleString()}`
              : "Loading run report..."}
          </p>
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {run && (
            <Link to={`/editor/${run.workflow_id}`} className="btn">
              Open Workflow
            </Link>
          )}
          <button
            type="button"
            className="btn"
            onClick={() => runId && loadRun(runId)}
          >
            <RefreshCw size={14} /> Refresh
          </button>
          {run?.summary?.reports?.json && (
            <a
              href={`/api/runs/${run.id}/report.json`}
              download={`report-${run.id}.json`}
              className="btn btn-primary"
            >
              <Download size={14} /> Download JSON
            </a>
          )}
          {run?.summary?.reports?.md && (
            <>
              <a
                href={`/api/runs/${run.id}/report.md`}
                download={`report-${run.id}.md`}
                className="btn btn-success"
              >
                <Download size={14} /> Download Markdown
              </a>
              <button
                type="button"
                className="btn"
                onClick={() => setShowMarkdown((s) => !s)}
              >
                <FileText size={14} /> {showMarkdown ? "Hide MD" : "Preview MD"}
              </button>
            </>
          )}
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {run && (
        <>
          <div className="grid-4">
            <div className="card">
              <div className="stat-label">Total Findings</div>
              <div className="stat-value">{findings.length}</div>
              <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
                Max severity:{" "}
                {run.summary?.findings?.max_severity ? (
                  <SeverityBadge severity={run.summary.findings.max_severity} />
                ) : (
                  "None"
                )}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">Critical / High</div>
              <div className="stat-value">
                {(sevCounts.CRITICAL ?? 0) + (sevCounts.HIGH ?? 0)}
              </div>
              <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
                CRITICAL: {sevCounts.CRITICAL ?? 0} · HIGH: {sevCounts.HIGH ?? 0}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">Medium / Low</div>
              <div className="stat-value">
                {(sevCounts.MEDIUM ?? 0) + (sevCounts.LOW ?? 0)}
              </div>
              <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 4 }}>
                MEDIUM: {sevCounts.MEDIUM ?? 0} · LOW: {sevCounts.LOW ?? 0}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">AI Validation</div>
              <div className="stat-value" style={{ fontSize: 20, marginTop: 10 }}>
                {validation
                  ? validation.used_fallback
                    ? "Fallback"
                    : validation.passed
                      ? "Validated"
                      : "Partial"
                  : "Not run"}
              </div>
              <div style={{ fontSize: 12, color: "#93a4c8", marginTop: 6 }}>
                {validation
                  ? `Model: ${run.ai_report?.model ?? "default"} · Dropped: ${validation.dropped_items} items / ${validation.dropped_cve} CVE`
                  : "Add ai.explain node to workflow"}
              </div>
            </div>
          </div>

          {showMarkdown && markdown !== null && (
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-title">Markdown Report Preview</div>
              <pre
                className="mono"
                style={{
                  whiteSpace: "pre-wrap",
                  background: "var(--bg)",
                  padding: 14,
                  borderRadius: 8,
                  fontSize: 12,
                  maxHeight: 380,
                  overflow: "auto",
                }}
              >
                {markdown}
              </pre>
            </div>
          )}

          {/* Findings List */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">
              <span>Detected Findings ({filteredFindings.length})</span>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <input
                  className="input"
                  style={{ width: 210 }}
                  placeholder="Search path, class, CVE..."
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
                <select
                  className="select"
                  style={{ width: 130 }}
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                >
                  <option value="all">All Categories</option>
                  <option value="SECRET">SECRET</option>
                  <option value="SCA">SCA</option>
                  <option value="SAST">SAST</option>
                </select>
                <select
                  className="select"
                  style={{ width: 130 }}
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="all">All Severities</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Class / Advisory</th>
                    <th>Location / Dependency</th>
                    <th>Description &amp; Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={5} style={{ textAlign: "center", color: "#93a4c8", padding: 24 }}>
                        No findings match current filter.
                      </td>
                    </tr>
                  ) : (
                    filteredFindings.map((f, idx) => (
                      <tr key={`${f.category}-${f.path}-${f.line ?? f.advisoryId ?? idx}`}>
                        <td>
                          <span className="badge badge-muted">{f.category}</span>
                        </td>
                        <td>
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="mono" style={{ fontSize: 12 }}>
                          {f.category === "SCA" ? f.advisoryId : f.class}
                        </td>
                        <td className="mono" style={{ fontSize: 12 }}>
                          <div>{f.path}</div>
                          {f.line !== undefined && (
                            <div style={{ color: "#93a4c8" }}>
                              line {f.line}
                              {f.endLine && f.endLine !== f.line ? `–${f.endLine}` : ""}
                            </div>
                          )}
                          {f.category === "SCA" && (
                            <div style={{ color: "#93a4c8" }}>
                              {f.group}:{f.artifact}:{f.version}
                            </div>
                          )}
                        </td>
                        <td style={{ maxWidth: 480 }}>
                          <div style={{ lineHeight: 1.45 }}>{f.description || "—"}</div>
                          {f.remediation && (
                            <div style={{ fontSize: 12, color: "#6ee7b7", marginTop: 4 }}>
                              Fix: {f.remediation}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* AI Recommendations */}
          {run.ai_report && (
            <div className="card" style={{ marginBottom: 20 }}>
              <div className="card-title">
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Bot size={16} color="#60a5fa" /> AI Security Analysis &amp; Recommendations
                </span>
                {validation && (
                  <span className={`badge ${validation.passed ? "badge-success" : "badge-warning"}`}>
                    <ShieldCheck size={12} />{" "}
                    {validation.used_fallback ? "Deterministic Fallback" : "Hallucination Guard Passed"}
                  </span>
                )}
              </div>

              {run.ai_report.summary && (
                <div
                  style={{
                    background: "var(--bg)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    padding: 12,
                    marginBottom: 14,
                    lineHeight: 1.5,
                    fontSize: 13.5,
                  }}
                >
                  {run.ai_report.summary}
                </div>
              )}

              <div className="grid-2">
                {aiItems.map((item, idx) => (
                  <div
                    key={`${item.finding_ref}-${idx}`}
                    style={{
                      background: "var(--bg)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      padding: 12,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span className="badge badge-running mono">{item.finding_ref}</span>
                    </div>
                    <div style={{ fontSize: 13, lineHeight: 1.45, marginBottom: 6 }}>
                      {item.explanation}
                    </div>
                    <div style={{ fontSize: 12, color: "#fcd34d", marginBottom: 6 }}>
                      <strong>Risk:</strong> {item.risk}
                    </div>
                    {item.fix_steps && item.fix_steps.length > 0 && (
                      <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: "#a7f3d0" }}>
                        {item.fix_steps.map((step, sIdx) => (
                          <li key={sIdx}>{step}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Node Execution Timeline */}
          <div className="card">
            <div className="card-title">Node Execution Timeline ({run.node_runs.length})</div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Node ID</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Output / Error</th>
                  </tr>
                </thead>
                <tbody>
                  {run.node_runs.map((nr) => {
                    const live = nodeStates[nr.node_id];
                    const st = live?.status ?? nr.status;
                    const dur = live?.duration_ms ?? nr.duration_ms;
                    const err = live?.error ?? nr.error;
                    const preview = live?.output_preview ?? nr.output_preview;
                    return (
                      <tr key={nr.node_id}>
                        <td className="mono" style={{ fontWeight: 600 }}>
                          {nr.node_id}
                        </td>
                        <td>
                          <StatusBadge status={st} />
                        </td>
                        <td className="mono">{typeof dur === "number" ? `${dur}ms` : "—"}</td>
                        <td>
                          {err ? (
                            <span style={{ color: "#fca5a5" }}>{err}</span>
                          ) : preview ? (
                            <span className="mono" style={{ fontSize: 11.5, color: "#93a4c8" }}>
                              {JSON.stringify(preview)}
                            </span>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
