import { CheckCircle2, CircleDashed, Loader2, SkipForward, XCircle } from "lucide-react";

export function StatusBadge({ status }: { status?: string | null }) {
  const s = (status || "pending").toLowerCase();
  if (s === "success") {
    return (
      <span className="badge badge-success">
        <CheckCircle2 size={12} /> success
      </span>
    );
  }
  if (s === "running") {
    return (
      <span className="badge badge-running">
        <Loader2 size={12} /> running
      </span>
    );
  }
  if (s === "partial") {
    return (
      <span className="badge badge-warning">
        <XCircle size={12} /> partial
      </span>
    );
  }
  if (s === "failed") {
    return (
      <span className="badge badge-danger">
        <XCircle size={12} /> failed
      </span>
    );
  }
  if (s === "skipped") {
    return (
      <span className="badge badge-muted">
        <SkipForward size={12} /> skipped
      </span>
    );
  }
  return (
    <span className="badge badge-muted">
      <CircleDashed size={12} /> {s}
    </span>
  );
}
