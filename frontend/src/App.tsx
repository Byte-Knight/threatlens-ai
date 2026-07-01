import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
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

type SavedReport = {
  id: number;
  filename: string;
  threat_level: string;
  attack_type: string;
  summary: string;
  created_at: string;
};

const CHART_COLORS = ["#ef4444", "#22c55e", "#f59e0b", "#3b82f6"];

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [reports, setReports] = useState<SavedReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<SavedReport | null>(
    null
  );
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterLevel, setFilterLevel] = useState("ALL");

  const fetchReports = useCallback(async () => {
    try {
      const response = await fetch("http://127.0.0.1:8000/reports");

      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
      }

      const data = await response.json();
      setReports(data);
    } catch (error) {
      console.error("Failed to fetch reports:", error);
    }
  }, []);

  useEffect(() => {
    void fetchReports();
  }, [fetchReports]);

  const downloadPdf = (id: number) => {
    window.open(`http://127.0.0.1:8000/reports/${id}/pdf`, "_blank");
  };

  const totalReports = reports.length;

  const highSeverityReports = reports.filter(
    (report) => report.threat_level === "HIGH"
  ).length;

  const lowSeverityReports = reports.filter(
    (report) => report.threat_level === "LOW"
  ).length;

  const uniqueAttackTypes = new Set(
    reports.map((report) => report.attack_type)
  ).size;

  const threatLevelData = [
    { name: "High", value: highSeverityReports },
    { name: "Low", value: lowSeverityReports },
  ].filter((item) => item.value > 0);

  const attackFrequencyMap = reports.reduce<Record<string, number>>(
    (accumulator, report) => {
      const attacks = report.attack_type.split(", ");

      attacks.forEach((attack) => {
        accumulator[attack] = (accumulator[attack] || 0) + 1;
      });

      return accumulator;
    },
    {}
  );

  const attackChartData = Object.entries(attackFrequencyMap).map(
    ([attack, count]) => ({
      attack,
      count,
    })
  );

  const filteredReports = reports.filter((report) => {
    const search = searchTerm.toLowerCase();

    const matchesSearch =
      report.filename.toLowerCase().includes(search) ||
      report.attack_type.toLowerCase().includes(search) ||
      report.summary.toLowerCase().includes(search);

    const matchesLevel =
      filterLevel === "ALL" || report.threat_level === filterLevel;

    return matchesSearch && matchesLevel;
  });

  const deleteReport = async (id: number) => {
    try {
      const response = await fetch(`http://127.0.0.1:8000/reports/${id}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error("Failed to delete report");
      }

      setReports((currentReports) =>
        currentReports.filter((report) => report.id !== id)
      );

      if (selectedReport?.id === id) {
        setSelectedReport(null);
      }
    } catch (error) {
      console.error("Delete error:", error);
      alert("Could not delete report.");
    }
  };

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

      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
      }

      const data = await response.json();

      setAnalysis(data.analysis);
      void fetchReports();
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
        <h1>🛡️ ThreatLens AI 🛡️</h1>
        <p>AI-powered cybersecurity threat analysis platform.</p>
      </section>

      <section className="card upload-card">
        <h2>Upload Security Log</h2>

        <input
          type="file"
          onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
        />

        <button onClick={handleUpload} disabled={loading}>
          {loading ? "Analyzing..." : "Analyze Log"}
        </button>
      </section>

      <section className="grid dashboard-grid">
        <div className="card stat-card">
          <h3>Total Reports</h3>
          <p className="metric">{totalReports}</p>
        </div>

        <div className="card stat-card">
          <h3>High Severity</h3>
          <p className="metric">{highSeverityReports}</p>
        </div>

        <div className="card stat-card">
          <h3>Low Severity</h3>
          <p className="metric">{lowSeverityReports}</p>
        </div>

        <div className="card stat-card">
          <h3>Attack Categories</h3>
          <p className="metric">{uniqueAttackTypes}</p>
        </div>
      </section>

      <section className="grid two">
        <div className="card chart-card">
          <h2>Threat Level Distribution</h2>

          {threatLevelData.length === 0 ? (
            <p>No chart data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={threatLevelData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={90}
                  label
                >
                  {threatLevelData.map((entry, index) => (
                    <Cell
                      key={entry.name}
                      fill={CHART_COLORS[index % CHART_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card chart-card">
          <h2>Attack Type Frequency</h2>

          {attackChartData.length === 0 ? (
            <p>No chart data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={attackChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="attack"
                  angle={-35}
                  textAnchor="end"
                  interval={0}
                  height={100}
                />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
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

      <section className="card">
        <h2>Recent Reports</h2>

        <div className="filter-row">
          <input
            type="text"
            placeholder="Search reports..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          <select
            value={filterLevel}
            onChange={(e) => setFilterLevel(e.target.value)}
          >
            <option value="ALL">All severities</option>
            <option value="HIGH">High</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {reports.length === 0 && <p>No saved reports loaded yet.</p>}

        {reports.length > 0 && filteredReports.length === 0 && (
          <p>No reports match your search/filter.</p>
        )}

        {filteredReports.length > 0 && (
          <div>
            {filteredReports.map((report) => (
              <div key={report.id} className="report-row">
                <button onClick={() => setSelectedReport(report)}>
                  #{report.id}
                </button>

                <span>{report.filename}</span>

                <span className={`badge ${report.threat_level.toLowerCase()}`}>
                  {report.threat_level}
                </span>

                <span>{report.attack_type}</span>

                <button
                  className="delete-btn"
                  onClick={() => void deleteReport(report.id)}
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {selectedReport && (
        <section className="card report">
          <h2>Selected Report</h2>

          <p>
            <strong>ID:</strong> #{selectedReport.id}
          </p>

          <p>
            <strong>Filename:</strong> {selectedReport.filename}
          </p>

          <p>
            <strong>Threat Level:</strong> {selectedReport.threat_level}
          </p>

          <p>
            <strong>Attack Type:</strong> {selectedReport.attack_type}
          </p>

          <p>
            <strong>Created At:</strong> {selectedReport.created_at}
          </p>

          <p>
            <strong>Summary:</strong> {selectedReport.summary}
          </p>

          <button onClick={() => downloadPdf(selectedReport.id)}>
            Download PDF
          </button>
        </section>
      )}
    </main>
  );
}

export default App;