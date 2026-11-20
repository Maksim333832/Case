import { useMemo, useState } from "react";
import { Plus, Search } from "lucide-react";
import type { NodeTypeOut } from "../types/workflow";

interface Props {
  nodeTypes: NodeTypeOut[];
  onAddNode: (nodeType: NodeTypeOut) => void;
}

const GROUP_ORDER = ["trigger", "source", "scanner", "logic", "findings", "ai", "notify"];

export function NodePalette({ nodeTypes, onAddNode }: Props) {
  const [query, setQuery] = useState("");

  const grouped = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? nodeTypes.filter(
          (nt) =>
            nt.label.toLowerCase().includes(q) ||
            nt.type.toLowerCase().includes(q) ||
            nt.group.toLowerCase().includes(q),
        )
      : nodeTypes;

    const map = new Map<string, NodeTypeOut[]>();
    for (const nt of filtered) {
      const list = map.get(nt.group) ?? [];
      list.push(nt);
      map.set(nt.group, list);
    }

    return Array.from(map.entries()).sort((a, b) => {
      const ia = GROUP_ORDER.indexOf(a[0]);
      const ib = GROUP_ORDER.indexOf(b[0]);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });
  }, [nodeTypes, query]);

  const onDragStart = (event: React.DragEvent, nodeType: string) => {
    event.dataTransfer.setData("application/reactflow-nodetype", nodeType);
    event.dataTransfer.effectAllowed = "move";
  };

  return (
    <div className="editor-palette">
      <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 8 }}>
        Node Registry ({nodeTypes.length})
      </div>
      <div style={{ position: "relative", marginBottom: 12 }}>
        <Search
          size={13}
          style={{ position: "absolute", left: 9, top: 10, color: "#93a4c8" }}
        />
        <input
          className="input"
          style={{ paddingLeft: 28 }}
          placeholder="Filter nodes..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {grouped.map(([group, items]) => (
        <div key={group} style={{ marginBottom: 14 }}>
          <div
            style={{
              fontSize: 11,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "#93a4c8",
              marginBottom: 6,
            }}
          >
            {group}
          </div>
          {items.map((nt) => (
            <div
              key={nt.type}
              className="palette-item"
              draggable
              onDragStart={(e) => onDragStart(e, nt.type)}
              title={nt.description}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {nt.label}
                </div>
                <div className="mono" style={{ fontSize: 10.5, color: "#93a4c8" }}>
                  {nt.type}
                </div>
              </div>
              <button
                type="button"
                className="btn btn-sm"
                title="Add node to canvas"
                onClick={() => onAddNode(nt)}
                style={{ padding: "4px 6px" }}
              >
                <Plus size={13} />
              </button>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
