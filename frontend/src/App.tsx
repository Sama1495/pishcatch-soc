import { useEffect, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { FishBot } from "./components/FishBot";
import { Inbox } from "./components/Inbox";
import { ToastProvider } from "./components/Toasts";
import { UploadProvider, useUpload } from "./components/UploadContext";
import { IncidentPage } from "./pages/IncidentPage";
import { QueuePage } from "./pages/QueuePage";
import { AnalystContext, analystId, useAnalyst } from "./lib/analyst";
import { getHealth } from "./services/api";

export function App() {
  return (
    <ToastProvider>
      <UploadProvider>
        <Shell />
      </UploadProvider>
    </ToastProvider>
  );
}

function Shell() {
  const upload = useUpload();
  const [analyst, setAnalyst] = useAnalyst();
  const [health, setHealth] = useState("checking");

  useEffect(() => {
    getHealth()
      .then((body) => setHealth(body.explainer_provider === "gemini" ? "api · gemini" : "api up"))
      .catch(() => setHealth("api down"));
  }, []);

  return (
    <AnalystContext.Provider value={analystId(analyst)}>
      <div className="app">
        <header className="topbar">
          <Link to="/" className="brand">
            <FishBot mood={upload.busy ? "analyzing" : "idle"} size={36} />
            <span>
              <strong>PhishCatch</strong>
              <em>FishBot</em>
            </span>
          </Link>
          <p className="keys">j/k move · Enter open · y yes · n no · c correct · w wrong</p>
          <label className="analyst">
            Analyst
            <input
              aria-label="Analyst id"
              value={analyst}
              onChange={(event) => setAnalyst(event.target.value)}
              maxLength={120}
            />
          </label>
          <button type="button" className="btn primary" onClick={upload.openPicker}>
            Upload mail
          </button>
          <span className={health.startsWith("api") && health !== "api down" ? "health ok" : "health"}>{health}</span>
        </header>
        <div className="workspace">
          <Inbox />
          <div className="stage">
            <Routes>
              <Route path="/" element={<QueuePage />} />
              <Route path="/incidents/:incidentId" element={<IncidentPage />} />
            </Routes>
          </div>
        </div>
      </div>
    </AnalystContext.Provider>
  );
}
