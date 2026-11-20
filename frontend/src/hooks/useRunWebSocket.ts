import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { NodeExecStatus, WorkflowEvent } from "../types/workflow";

export interface LiveNodeState {
  status: NodeExecStatus;
  duration_ms?: number | null;
  output_preview?: Record<string, unknown> | null;
  error?: string | null;
}

export function useRunWebSocket(
  runId: string | null,
  onRunFinished?: (runId: string, status: string) => void,
) {
  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [nodeStates, setNodeStates] = useState<Record<string, LiveNodeState>>({});
  const [runStatus, setRunStatus] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) {
      setEvents([]);
      setNodeStates({});
      setRunStatus(null);
      return;
    }

    let closed = false;
    let pollTimer: number | undefined;

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/runs/${encodeURIComponent(runId)}`;
    const ws = new WebSocket(wsUrl);

    setEvents([]);
    setNodeStates({});
    setRunStatus("running");

    const applyEvent = (ev: WorkflowEvent) => {
      if (ev.event === "ping") return;
      setEvents((prev) => [...prev, ev]);

      if (ev.event === "run_started") {
        setRunStatus("running");
      } else if (ev.node_id) {
        const statusMap: Record<string, NodeExecStatus> = {
          node_started: "running",
          node_finished: "success",
          node_failed: "failed",
          node_skipped: "skipped",
        };
        const mapped = statusMap[ev.event];
        if (mapped) {
          setNodeStates((prev) => ({
            ...prev,
            [ev.node_id!]: {
              status: mapped,
              duration_ms: ev.duration_ms ?? prev[ev.node_id!]?.duration_ms,
              output_preview: ev.output_preview ?? prev[ev.node_id!]?.output_preview,
              error: ev.error ?? null,
            },
          }));
        }
      } else if (ev.event === "run_finished") {
        const finalSt = ev.status ?? "success";
        setRunStatus(finalSt);
        onRunFinished?.(runId, finalSt);
      }
    };

    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as WorkflowEvent;
        applyEvent(parsed);
      } catch {
        // ignore malformed frames
      }
    };

    // Safety fallback poll in case WS disconnects before run_finished
    ws.onerror = () => {
      if (closed) return;
      pollTimer = window.setInterval(async () => {
        try {
          const run = await api.getRun(runId);
          const nextMap: Record<string, LiveNodeState> = {};
          for (const nr of run.node_runs) {
            nextMap[nr.node_id] = {
              status: (nr.status as NodeExecStatus) || "pending",
              duration_ms: nr.duration_ms,
              output_preview: nr.output_preview,
              error: nr.error,
            };
          }
          setNodeStates(nextMap);
          setRunStatus(run.status);
          if (run.finished_at) {
            window.clearInterval(pollTimer);
            onRunFinished?.(runId, run.status);
          }
        } catch {
          // ignore transient fetch errors
        }
      }, 1500);
    };

    return () => {
      closed = true;
      if (pollTimer) window.clearInterval(pollTimer);
      try {
        ws.close();
      } catch {
        // ignore
      }
    };
  }, [runId]);

  return { events, nodeStates, runStatus };
}
