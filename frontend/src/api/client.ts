import type {
  CredentialOut,
  HealthOut,
  LlmSettingsOut,
  NodeTypeOut,
  RunOut,
  UploadOut,
  WorkflowGraphModel,
  WorkflowOut,
} from "../types/workflow";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(init?.headers ?? {}),
    },
  });
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try {
      const data = await resp.json();
      if (typeof data?.detail === "string") {
        message = data.detail;
      } else if (data?.detail?.errors && Array.isArray(data.detail.errors)) {
        message = data.detail.errors.join("; ");
      } else if (data?.detail) {
        message = JSON.stringify(data.detail);
      }
    } catch {
      const txt = await resp.text().catch(() => "");
      if (txt) message = txt;
    }
    throw new Error(message);
  }
  if (resp.status === 204) {
    return undefined as T;
  }
  return (await resp.json()) as T;
}

async function requestText(url: string): Promise<string> {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  return await resp.text();
}

export const api = {
  getHealth: () => requestJson<HealthOut>("/health"),

  getNodeTypes: () => requestJson<NodeTypeOut[]>("/api/node-types"),

  listWorkflows: (includeTemplates = false) =>
    requestJson<WorkflowOut[]>(`/api/workflows?include_templates=${includeTemplates}`),

  getWorkflow: (id: string) => requestJson<WorkflowOut>(`/api/workflows/${encodeURIComponent(id)}`),

  createWorkflow: (payload: {
    name: string;
    description?: string;
    graph: WorkflowGraphModel;
    is_template?: boolean;
  }) =>
    requestJson<WorkflowOut>("/api/workflows", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateWorkflow: (
    id: string,
    payload: {
      name?: string;
      description?: string;
      graph?: WorkflowGraphModel;
      is_template?: boolean;
    },
  ) =>
    requestJson<WorkflowOut>(`/api/workflows/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteWorkflow: (id: string) =>
    requestJson<void>(`/api/workflows/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),

  runWorkflow: (id: string, wait = false) =>
    requestJson<{ run_id: string; status: string }>(
      `/api/workflows/${encodeURIComponent(id)}/run?wait=${wait}`,
      {
        method: "POST",
        body: JSON.stringify({ trigger: "manual", params: {} }),
      },
    ),

  publishWorkflowAsTemplate: (id: string, name?: string, description?: string) =>
    requestJson<WorkflowOut>(`/api/workflows/${encodeURIComponent(id)}/publish`, {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),

  getCiConfig: (workflowId: string, provider: "github" | "gitlab") =>
    requestText(`/api/ci/workflows/${encodeURIComponent(workflowId)}/config?provider=${provider}`),

  listTemplates: () => requestJson<WorkflowOut[]>("/api/templates"),

  copyTemplate: (
    templateId: string,
    payload?: {
      name?: string;
      description?: string;
      param_overrides?: Record<string, Record<string, unknown>>;
    },
  ) =>
    requestJson<WorkflowOut>(`/api/templates/${encodeURIComponent(templateId)}/copy`, {
      method: "POST",
      body: JSON.stringify(payload ?? {}),
    }),

  listRuns: (workflowId?: string, limit = 50) => {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (workflowId) qs.set("workflow_id", workflowId);
    return requestJson<RunOut[]>(`/api/runs?${qs.toString()}`);
  },

  getRun: (id: string) => requestJson<RunOut>(`/api/runs/${encodeURIComponent(id)}`),

  getReportMarkdown: (id: string) => requestText(`/api/runs/${encodeURIComponent(id)}/report.md`),

  listUploads: () => requestJson<UploadOut[]>("/api/uploads"),

  uploadZip: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return requestJson<UploadOut>("/api/uploads", {
      method: "POST",
      body: fd,
    });
  },

  listCredentials: () => requestJson<CredentialOut[]>("/api/credentials"),

  createCredential: (payload: { name: string; kind: string; value: string }) =>
    requestJson<CredentialOut>("/api/credentials", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteCredential: (id: string) =>
    requestJson<void>(`/api/credentials/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),

  getLlmSettings: () => requestJson<LlmSettingsOut>("/api/settings/llm"),

  updateLlmSettings: (payload: {
    base_url: string;
    model: string;
    api_key?: string;
    clear_api_key?: boolean;
  }) =>
    requestJson<LlmSettingsOut>("/api/settings/llm", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
};
