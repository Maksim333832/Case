import { useEffect, useState } from "react";
import { Bot, KeyRound, Plus, Save, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { CredentialOut, LlmSettingsOut } from "../types/workflow";

export function SettingsPage() {
  const [llm, setLlm] = useState<LlmSettingsOut | null>(null);
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [savingLlm, setSavingLlm] = useState(false);

  const [credentials, setCredentials] = useState<CredentialOut[]>([]);
  const [credName, setCredName] = useState("");
  const [credKind, setCredKind] = useState("telegram");
  const [credValue, setCredValue] = useState("");
  const [savingCred, setSavingCred] = useState(false);

  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadSettings = async () => {
    try {
      const [llmCfg, creds] = await Promise.all([api.getLlmSettings(), api.listCredentials()]);
      setLlm(llmCfg);
      setBaseUrl(llmCfg.base_url);
      setModel(llmCfg.model);
      setCredentials(creds);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveLlm = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingLlm(true);
    setNotice(null);
    setError(null);
    try {
      const updated = await api.updateLlmSettings({
        base_url: baseUrl.trim(),
        model: model.trim(),
        api_key: apiKeyInput.trim() || undefined,
      });
      setLlm(updated);
      setApiKeyInput("");
      setNotice("LLM provider settings saved securely.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update LLM settings");
    } finally {
      setSavingLlm(false);
    }
  };

  const handleClearLlmKey = async () => {
    setSavingLlm(true);
    try {
      const updated = await api.updateLlmSettings({
        base_url: baseUrl.trim(),
        model: model.trim(),
        clear_api_key: true,
      });
      setLlm(updated);
      setNotice("Custom LLM API key cleared.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to clear key");
    } finally {
      setSavingLlm(false);
    }
  };

  const handleCreateCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!credName.trim() || !credValue.trim()) return;
    setSavingCred(true);
    setNotice(null);
    setError(null);
    try {
      const created = await api.createCredential({
        name: credName.trim(),
        kind: credKind,
        value: credValue.trim(),
      });
      setCredentials((prev) => [created, ...prev]);
      setCredName("");
      setCredValue("");
      setNotice(`Encrypted credential '${created.name}' saved.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create credential");
    } finally {
      setSavingCred(false);
    }
  };

  const handleDeleteCredential = async (id: string) => {
    try {
      await api.deleteCredential(id);
      setCredentials((prev) => prev.filter((c) => c.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete credential");
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings &amp; Credentials</h1>
          <p className="page-subtitle">
            Switch OpenAI-compatible LLM providers and manage Fernet-encrypted integration secrets
          </p>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {notice && <div className="alert alert-success">{notice}</div>}

      <div className="grid-2">
        {/* LLM Provider Settings */}
        <div className="card">
          <div className="card-title">
            <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Bot size={16} color="#60a5fa" /> LLM Provider Configuration
            </span>
            {llm && <span className="badge badge-muted">source: {llm.source}</span>}
          </div>

          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setBaseUrl("https://generativelanguage.googleapis.com/v1beta/openai");
                setModel("gemini-3.5-flash-lite");
              }}
            >
              Preset: Gemini Flash-Lite
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setBaseUrl("http://localhost:11434/v1");
                setModel("qwen2.5-coder:7b");
              }}
            >
              Preset: Local Ollama
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setBaseUrl("http://localhost:8001/v1");
                setModel("Qwen/Qwen2.5-Coder-7B-Instruct");
              }}
            >
              Preset: Local vLLM
            </button>
          </div>

          <form onSubmit={handleSaveLlm} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <label className="field-label">OpenAI-Compatible Base URL</label>
              <input
                className="input mono"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="field-label">Model Name</label>
              <input
                className="input mono"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="field-label">
                API Key{" "}
                {llm?.has_api_key ? (
                  <span className="mono" style={{ color: "#6ee7b7" }}>
                    (configured: {llm.masked_api_key})
                  </span>
                ) : (
                  <span style={{ color: "#93a4c8" }}>(not set — local endpoint or fallback)</span>
                )}
              </label>
              <input
                type="password"
                className="input mono"
                placeholder="Enter new API key (leave empty to keep current)"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
              />
            </div>

            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <button type="submit" className="btn btn-primary" disabled={savingLlm}>
                <Save size={14} /> {savingLlm ? "Saving..." : "Save Provider Settings"}
              </button>
              {llm?.has_api_key && (
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={handleClearLlmKey}
                  disabled={savingLlm}
                >
                  Clear Key
                </button>
              )}
            </div>
          </form>
        </div>

        {/* Encrypted Credentials */}
        <div className="card">
          <div className="card-title">
            <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <KeyRound size={16} color="#10b981" /> Encrypted Credentials Vault
            </span>
            <span className="badge badge-success">Fernet AES</span>
          </div>

          <form onSubmit={handleCreateCredential} style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 18 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 130px", gap: 8 }}>
              <div>
                <label className="field-label">Name</label>
                <input
                  className="input"
                  placeholder="e.g. security-telegram-bot"
                  value={credName}
                  onChange={(e) => setCredName(e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="field-label">Kind</label>
                <select
                  className="select"
                  value={credKind}
                  onChange={(e) => setCredKind(e.target.value)}
                >
                  <option value="telegram">telegram</option>
                  <option value="webhook">webhook</option>
                  <option value="llm">llm</option>
                  <option value="smtp">smtp</option>
                  <option value="git">git</option>
                </select>
              </div>
            </div>

            <div>
              <label className="field-label">Secret Value (never returned in plaintext)</label>
              <input
                type="password"
                className="input mono"
                placeholder="Bot token, bearer token, or API secret"
                value={credValue}
                onChange={(e) => setCredValue(e.target.value)}
                required
              />
            </div>

            <div>
              <button type="submit" className="btn btn-success" disabled={savingCred}>
                <Plus size={14} /> {savingCred ? "Encrypting..." : "Store Encrypted Credential"}
              </button>
            </div>
          </form>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name / ID</th>
                  <th>Kind</th>
                  <th>Masked</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {credentials.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ color: "#93a4c8", textAlign: "center" }}>
                      No stored credentials yet.
                    </td>
                  </tr>
                ) : (
                  credentials.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{c.name}</div>
                        <div className="mono" style={{ fontSize: 11, color: "#93a4c8" }}>
                          {c.id}
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-muted">{c.kind}</span>
                      </td>
                      <td className="mono">{c.masked_value}</td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-sm btn-danger"
                          onClick={() => handleDeleteCredential(c.id)}
                          title="Delete credential"
                        >
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
