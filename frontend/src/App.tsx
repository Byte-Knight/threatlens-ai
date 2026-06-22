import { useState } from "react";

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
      const response = await fetch(
        "http://127.0.0.1:8000/upload-log",
        {
          method: "POST",
          body: formData,
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
      }

      const data = await response.json();

      console.log("Backend response:", data);

      setAnalysis(data.analysis);
    } catch (error) {
      console.error("Upload error:", error);
      alert("Upload failed. Check browser console.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        maxWidth: "1000px",
        margin: "0 auto",
        padding: "40px",
        fontFamily: "Arial",
      }}
    >
      <h1>🛡️ ThreatLens AI</h1>

      <p>AI-powered cybersecurity threat analysis platform.</p>

      <hr />

      <h2>Upload Security Log</h2>

      <input
        type="file"
        onChange={(e) =>
          setSelectedFile(e.target.files?.[0] || null)
        }
      />

      <br />
      <br />

      <button onClick={handleUpload} disabled={loading}>
        {loading ? "Analyzing..." : "Analyze Log"}
      </button>

      <hr />

      <h2>Threat Analysis Results</h2>

      {!analysis && <p>No analysis yet.</p>}

      {analysis && (
        <div>
          <h3>Threat Level</h3>
          <p>{analysis.threat_level}</p>

          <h3>Attack Type</h3>
          <p>{analysis.attack_type}</p>

          <h3>Failed Logins</h3>
          <p>{analysis.failed_logins}</p>

          <h3>Successful Logins</h3>
          <p>{analysis.successful_logins}</p>

          <h3>Suspicious IPs</h3>
          <ul>
            {analysis.suspicious_ips?.map(
              (ip: string, index: number) => (
                <li key={index}>{ip}</li>
              )
            )}
          </ul>

          <h3>Recommendations</h3>
          <ul>
            {analysis.recommendations?.map(
              (item: string, index: number) => (
                <li key={index}>{item}</li>
              )
            )}
          </ul>

          {analysis.incident_report && (
            <>
              <hr />

              <h2>Incident Report</h2>

              <h3>{analysis.incident_report.title}</h3>

              <p>
                <strong>Severity:</strong>{" "}
                {analysis.incident_report.severity}
              </p>

              <p>{analysis.incident_report.summary}</p>

              <h4>Evidence</h4>
              <ul>
                {analysis.incident_report.evidence?.map(
                  (item: string, index: number) => (
                    <li key={index}>{item}</li>
                  )
                )}
              </ul>

              <h4>Recommended Actions</h4>
              <ul>
                {analysis.incident_report.recommended_actions?.map(
                  (item: string, index: number) => (
                    <li key={index}>{item}</li>
                  )
                )}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;