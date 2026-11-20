import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  addEdge,
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  BookmarkPlus,
  Code2,
  ExternalLink,
  FilePlus2,
  Play,
  Save,
} from "lucide-react";
import { api } from "../api/client";
import { NodeInspector } from "../components/NodeInspector";
import { NodePalette } from "../components/NodePalette";
import { StatusBadge } from "../components/StatusBadge";
import { useRunWebSocket } from "../hooks/useRunWebSocket";
import { WorkflowNode, type WorkflowNodeData } from "../nodes/WorkflowNode";
import type {
  CredentialOut,
  NodeTypeOut,
  UploadOut,
  WorkflowGraphModel,
  WorkflowOut,
} from "../types/workflow";

const nodeTypesMap = {
  workflowNode: WorkflowNode,
};

function defaultParamsForType(def?: NodeTypeOut): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const props = def?.params_schema?.properties ?? {};
  for (const [k, prop] of Object.entries(props)) {
    if (prop.default !== undefined) out[k] = prop.default;
  }
  return out;
}

function EditorInner() {
  const { workflowId } = useParams<{ workflowId?: string }>();
  const navigate = useNavigate();
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const { screenToFlowPosition } = useReactFlow();

  const [nodeTypes, setNodeTypes] = useState<NodeTypeOut[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowOut[]>([]);
  const [credentials, setCredentials] = useState<CredentialOut[]>([]);
  const [uploads, setUploads] = useState<UploadOut[]>([]);

  const [currentWorkflowId, setCurrentWorkflowId] = useState<string | null>(workflowId ?? null);
  const [wfName, setWfName] = useState("New Security Workflow");
  const [wfDesc, setWfDesc] = useState("");

  const [nodes, setNodes, onNodesChange] = useNodesState<Node<WorkflowNodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [ciModal, setCiModal] = useState<{ provider: "github" | "gitlab"; content: string } | null>(null);

  const nodeTypeByName = useMemo(() => {
    const map = new Map<string, NodeTypeOut>();
    for (const nt of nodeTypes) map.set(nt.type, nt);
    return map;
  }, [nodeTypes]);

  const { events, nodeStates, runStatus } = useRunWebSocket(activeRunId, () => {
    setRunning(false);
  });

  // Load metadata
  useEffect(() => {
    Promise.all([
      api.getNodeTypes(),
      api.listWorkflows(false),
      api.listCredentials(),
      api.listUploads(),
    ])
      .then(([nts, wfs, creds, ups]) => {
        setNodeTypes(nts);
        setWorkflows(wfs);
        setCredentials(creds);
        setUploads(ups);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to initialize editor"));
  }, []);

  // Load workflow graph when route param or nodeTypes ready
  useEffect(() => {
    setCurrentWorkflowId(workflowId ?? null);
    if (!workflowId) {
      setWfName("New Security Workflow");
      setWfDesc("");
      setNodes([]);
      setEdges([]);
      setSelectedNodeId(null);
      setActiveRunId(null);
      return;
    }

    api
      .getWorkflow(workflowId)
      .then((wf) => {
        setWfName(wf.name);
        setWfDesc(wf.description);
        const rfNodes: Node<WorkflowNodeData>[] = wf.graph.nodes.map((n, idx) => {
          const def = nodeTypeByName.get(n.type);
          return {
            id: n.id,
            type: "workflowNode",
            position: n.position ?? { x: 80 + idx * 240, y: 120 },
            data: {
              label: def?.label ?? n.type,
              nodeType: n.type,
              group: def?.group ?? n.type.split(".")[0],
              params: n.params ?? {},
              typeDef: def,
            },
          };
        });
        const rfEdges: Edge[] = wf.graph.edges.map((e) => ({
          id: e.id,
          source: e.source,
          sourceHandle: e.sourceHandle ?? undefined,
          target: e.target,
          targetHandle: e.targetHandle ?? undefined,
          animated: false,
          style: { stroke: "#4f72b8", strokeWidth: 2 },
        }));
        setNodes(rfNodes);
        setEdges(rfEdges);
        setSelectedNodeId(rfNodes[0]?.id ?? null);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load workflow"));
  }, [workflowId, nodeTypeByName, setNodes, setEdges]);

  // Propagate live WebSocket nodeStates into React Flow node data
  useEffect(() => {
    setNodes((nds) =>
      nds.map((node) => ({
        ...node,
        data: {
          ...node.data,
          typeDef: nodeTypeByName.get(node.data.nodeType) ?? node.data.typeDef,
          liveState: nodeStates[node.id],
        },
      })),
    );
  }, [nodeStates, nodeTypeByName, setNodes]);

  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((eds) =>
        addEdge(
          {
            ...connection,
            id: `e_${Date.now()}_${Math.random().toString(16).slice(2, 6)}`,
            style: { stroke: "#4f72b8", strokeWidth: 2 },
          },
          eds,
        ),
      );
    },
    [setEdges],
  );

  const createFlowNode = useCallback(
    (nt: NodeTypeOut, position: { x: number; y: number }) => {
      const id = `n_${Date.now().toString(36).slice(-4)}_${Math.random().toString(36).slice(2, 5)}`;
      const newNode: Node<WorkflowNodeData> = {
        id,
        type: "workflowNode",
        position,
        data: {
          label: nt.label,
          nodeType: nt.type,
          group: nt.group,
          params: defaultParamsForType(nt),
          typeDef: nt,
        },
      };
      setNodes((nds) => [...nds, newNode]);
      setSelectedNodeId(id);
    },
    [setNodes],
  );

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      const typeName = event.dataTransfer.getData("application/reactflow-nodetype");
      const nt = nodeTypeByName.get(typeName);
      if (!nt) return;
      const pos = screenToFlowPosition({ x: event.clientX, y: event.clientY });
      createFlowNode(nt, pos);
    },
    [nodeTypeByName, screenToFlowPosition, createFlowNode],
  );

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
  }, []);

  const serializeGraph = useCallback((): WorkflowGraphModel => {
    return {
      nodes: nodes.map((n) => ({
        id: n.id,
        type: n.data.nodeType,
        params: n.data.params ?? {},
        position: { x: Math.round(n.position.x), y: Math.round(n.position.y) },
      })),
      edges: edges.map((e) => ({
        id: e.id,
        source: e.source,
        sourceHandle: e.sourceHandle ?? null,
        target: e.target,
        targetHandle: e.targetHandle ?? null,
      })),
    };
  }, [nodes, edges]);

  const saveWorkflow = async (): Promise<WorkflowOut | null> => {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const graph = serializeGraph();
      let saved: WorkflowOut;
      if (currentWorkflowId) {
        saved = await api.updateWorkflow(currentWorkflowId, {
          name: wfName.trim() || "Untitled Workflow",
          description: wfDesc,
          graph,
        });
      } else {
        saved = await api.createWorkflow({
          name: wfName.trim() || "Untitled Workflow",
          description: wfDesc,
          graph,
        });
        setCurrentWorkflowId(saved.id);
        setWorkflows((prev) => [saved, ...prev]);
        navigate(`/editor/${saved.id}`, { replace: true });
      }
      setNotice("Workflow saved.");
      return saved;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save workflow");
      return null;
    } finally {
      setSaving(false);
    }
  };

  const handleRun = async () => {
    const saved = await saveWorkflow();
    if (!saved) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.runWorkflow(saved.id, false);
      setActiveRunId(res.run_id);
      setNotice(`Run ${res.run_id} started via WebSocket stream.`);
    } catch (err) {
      setRunning(false);
      setError(err instanceof Error ? err.message : "Failed to start workflow run");
    }
  };

  const handlePublishTemplate = async () => {
    const saved = await saveWorkflow();
    if (!saved) return;
    try {
      const tpl = await api.publishWorkflowAsTemplate(saved.id, `${saved.name} Template`);
      setNotice(`Published as template '${tpl.name}' (${tpl.id}).`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish template");
    }
  };

  const handleShowCi = async (provider: "github" | "gitlab") => {
    if (!currentWorkflowId) {
      setError("Save workflow first to generate CI config.");
      return;
    }
    try {
      const yaml = await api.getCiConfig(currentWorkflowId, provider);
      setCiModal({ provider, content: yaml });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch CI config");
    }
  };

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId],
  );

  const handleParamChange = (key: string, value: unknown) => {
    if (!selectedNodeId) return;
    setNodes((nds) =>
      nds.map((n) =>
        n.id === selectedNodeId
          ? {
              ...n,
              data: {
                ...n.data,
                params: { ...n.data.params, [key]: value },
              },
            }
          : n,
      ),
    );
  };

  const handleDeleteNode = (nodeId: string) => {
    setNodes((nds) => nds.filter((n) => n.id !== nodeId));
    setEdges((eds) => eds.filter((e) => e.source !== nodeId && e.target !== nodeId));
    if (selectedNodeId === nodeId) setSelectedNodeId(null);
  };

  return (
    <div className="editor-shell">
      <div className="editor-topbar">
        <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, flex: 1 }}>
          <select
            className="select"
            style={{ width: 210 }}
            value={currentWorkflowId ?? ""}
            onChange={(e) => {
              const val = e.target.value;
              navigate(val ? `/editor/${val}` : "/editor");
            }}
          >
            <option value="">-- New Empty Canvas --</option>
            {workflows.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name}
              </option>
            ))}
          </select>

          <input
            className="input"
            style={{ maxWidth: 260, fontWeight: 600 }}
            value={wfName}
            onChange={(e) => setWfName(e.target.value)}
            placeholder="Workflow name"
          />

          <button
            type="button"
            className="btn btn-sm"
            onClick={() => navigate("/editor")}
            title="Start blank workflow"
          >
            <FilePlus2 size={14} /> New
          </button>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {activeRunId && (
            <Link to={`/runs/${activeRunId}`} className="btn btn-sm">
              <StatusBadge status={runStatus} />
              <span className="mono">{activeRunId}</span>
              <ExternalLink size={12} />
            </Link>
          )}
          <button type="button" className="btn btn-sm" onClick={() => handleShowCi("github")}>
            <Code2 size={14} /> CI YAML
          </button>
          <button type="button" className="btn btn-sm" onClick={handlePublishTemplate}>
            <BookmarkPlus size={14} /> Save as Template
          </button>
          <button type="button" className="btn" onClick={saveWorkflow} disabled={saving}>
            <Save size={14} /> {saving ? "Saving..." : "Save"}
          </button>
          <button type="button" className="btn btn-success" onClick={handleRun} disabled={running}>
            <Play size={14} /> {running ? "Running..." : "Run Workflow"}
          </button>
        </div>
      </div>

      {(error || notice) && (
        <div style={{ padding: "8px 16px", background: "var(--bg-elevated)", borderBottom: "1px solid var(--border)" }}>
          {error && <div className="alert alert-error" style={{ margin: 0 }}>{error}</div>}
          {!error && notice && <div className="alert alert-success" style={{ margin: 0 }}>{notice}</div>}
        </div>
      )}

      <div className="editor-body">
        <NodePalette
          nodeTypes={nodeTypes}
          onAddNode={(nt) => createFlowNode(nt, { x: 140 + nodes.length * 40, y: 120 + (nodes.length % 4) * 70 })}
        />

        <div className="editor-canvas" ref={wrapperRef}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypesMap}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            onPaneClick={() => setSelectedNodeId(null)}
            fitView
            deleteKeyCode={["Backspace", "Delete"]}
          >
            <Background color="#1d2847" gap={20} />
            <Controls />
            <MiniMap
              style={{ background: "#11182b" }}
              nodeColor="#3b82f6"
              maskColor="rgba(8, 12, 25, 0.7)"
            />
          </ReactFlow>
        </div>

        <div className="editor-inspector">
          <NodeInspector
            selectedNodeId={selectedNode?.id ?? null}
            nodeTypeDef={selectedNode ? nodeTypeByName.get(selectedNode.data.nodeType) : undefined}
            params={selectedNode?.data.params ?? {}}
            liveState={selectedNode?.data.liveState}
            credentials={credentials}
            uploads={uploads}
            onUploadCreated={(u) => setUploads((prev) => [u, ...prev])}
            onChangeParam={handleParamChange}
            onDeleteNode={handleDeleteNode}
          />

          {events.length > 0 && (
            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
              <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 8 }}>
                Live WebSocket Stream ({events.length})
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 220, overflowY: "auto" }}>
                {events.map((ev, idx) => (
                  <div
                    key={idx}
                    className="mono"
                    style={{
                      fontSize: 11,
                      padding: "6px 8px",
                      background: "var(--bg)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                    }}
                  >
                    <span style={{ color: "#7bb4ff" }}>{ev.event}</span>
                    {ev.node_id ? ` · ${ev.node_id}` : ""}
                    {ev.error ? <div style={{ color: "#fca5a5" }}>{ev.error}</div> : null}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {ciModal && (
        <div className="modal-backdrop" onClick={() => setCiModal(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="card-title">
              <span>CI/CD Gate Snippet ({ciModal.provider})</span>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => handleShowCi("github")}
                >
                  GitHub Actions
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => handleShowCi("gitlab")}
                >
                  GitLab CI
                </button>
                <button type="button" className="btn btn-sm" onClick={() => setCiModal(null)}>
                  Close
                </button>
              </div>
            </div>
            <pre
              className="mono"
              style={{
                background: "var(--bg)",
                padding: 12,
                borderRadius: 8,
                fontSize: 12,
                overflowX: "auto",
              }}
            >
              {ciModal.content}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

export function WorkflowEditorPage() {
  return (
    <ReactFlowProvider>
      <EditorInner />
    </ReactFlowProvider>
  );
}
