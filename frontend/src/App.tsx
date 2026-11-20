import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { RunDetailsPage } from "./pages/RunDetailsPage";
import { RunHistoryPage } from "./pages/RunHistoryPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TemplatesPage } from "./pages/TemplatesPage";
import { WorkflowEditorPage } from "./pages/WorkflowEditorPage";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/editor" element={<WorkflowEditorPage />} />
          <Route path="/editor/:workflowId" element={<WorkflowEditorPage />} />
          <Route path="/templates" element={<TemplatesPage />} />
          <Route path="/runs" element={<RunHistoryPage />} />
          <Route path="/runs/:runId" element={<RunDetailsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
