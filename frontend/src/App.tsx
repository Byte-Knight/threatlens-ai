import { useState } from "react";
import "./App.css";

type IncidentReport = {
  title: string;
  summary: string;
  severity: string;
  evidence: string[];
  recommended_actions: string[];
};

type Analysis = {
  threat_level: string;
  attack_type: string;
  failed_logins: number;
  successful_logins: number;
  suspicious_ips: string[];
  recommendations: string[];
  incident_report: IncidentReport;
};

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(false);

  const handleUpload = async () => {
    if (!selectedFile) {
      alert("Please select a log file.");
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);
    setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/upload-log", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);

      const data = await response.json();
      setAnalysis(data.analysis);
    } catch (error) {
      console.error("Upload error:", error);
      alert("Upload failed. Check browser console.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <h1>🛡️ ThreatLens AI</h1>
        <p>AI-powered cybersecurity threat analysis platform.</p>
      </section>

      <section className="card upload-card">
        <h2>Upload Security Log</h2>
        <input type="file" onChange={(e) => setSelectedFile(e.target.files?.[0] || null)} />
        <button onClick={handleUpload} disabled={loading}>
          {loading ? "Analyzing..." : "Analyze Log"}
        </button>
      </section>

      {!analysis && (
        <section className="card empty-state">
          <h2>Threat Analysis Results</h2>
          <p>No analysis yet. Upload a log file to begin.</p>
        </section>
      )}

      {analysis && (
        <>
          <section className="grid">
            <div className="card">
              <h3>Threat Level</h3>
              <span className={`badge ${analysis.threat_level.toLowerCase()}`}>
                {analysis.threat_level}
              </span>
            </div>

            <div className="card">
              <h3>Failed Logins</h3>
              <p className="metric">{analysis.failed_logins}</p>
            </div>

            <div className="card">
              <h3>Successful Logins</h3>
              <p className="metric">{analysis.successful_logins}</p>
            </div>
          </section>

          <section className="card">
            <h2>Detected Attacks</h2>
            <p>{analysis.attack_type}</p>
          </section>

          <section className="grid two">
            <div className="card">
              <h3>Suspicious IPs</h3>
              <ul>
                {analysis.suspicious_ips.map((ip, index) => (
                  <li key={index}>{ip}</li>
                ))}
              </ul>
            </div>

            <div className="card">
              <h3>Recommendations</h3>
              <ul>
                {analysis.recommendations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          </section>

          <section className="card report">
            <h2>Incident Report</h2>
            <h3>{analysis.incident_report.title}</h3>
            <p>{analysis.incident_report.summary}</p>

            <h4>Evidence</h4>
            <ul>
              {analysis.incident_report.evidence.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </section>
        </>
      )}
    </main>
  );
}

export default App;