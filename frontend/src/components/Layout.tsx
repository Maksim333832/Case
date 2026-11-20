import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  GitBranch,
  History,
  LayoutDashboard,
  Layers,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { api } from "../api/client";
import type { HealthOut } from "../types/workflow";

export function Layout() {
  const [health, setHealth] = useState<HealthOut | null>(null);

  useEffect(() => {
    api.getHealth().then(setHealth).catch(() => setHealth(null));
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={19} />
          </div>
          <div>
            <div className="brand-title">AI Security</div>
            <div className="brand-sub">Workflow Platform</div>
          </div>
        </div>

        <NavLink to="/" end className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
          <LayoutDashboard size={16} /> Dashboard
        </NavLink>
        <NavLink to="/editor" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
          <GitBranch size={16} /> Workflow Editor
        </NavLink>
        <NavLink to="/templates" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
          <Layers size={16} /> Templates
        </NavLink>
        <NavLink to="/runs" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
          <History size={16} /> Run History
        </NavLink>
        <NavLink to="/settings" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
          <Settings size={16} /> Settings
        </NavLink>

        <div className="sidebar-footer">
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <Activity size={13} color={health?.status === "ok" ? "#10b981" : "#ef4444"} />
            <span>API: {health ? health.status.toUpperCase() : "OFFLINE"}</span>
          </div>
          <div style={{ fontSize: 11 }}>
            Scanners: {health ? (health.use_stub_scanners ? "Stub Mode" : "Real Engines") : "—"}
          </div>
        </div>
      </aside>

      <main className="main-area">
        <Outlet />
      </main>
    </div>
  );
}
