export function SeverityBadge({ severity }: { severity?: string | null }) {
  const s = (severity || "INFO").toUpperCase();
  const cls =
    s === "CRITICAL"
      ? "badge-critical"
      : s === "HIGH"
        ? "badge-danger"
        : s === "MEDIUM"
          ? "badge-warning"
          : s === "LOW"
            ? "badge-running"
            : "badge-muted";
  return <span className={`badge ${cls}`}>{s}</span>;
}
