
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle,
  Clock,
  LayoutDashboard,
  RefreshCw,
  Search,
  Shield,
  Zap,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8000/api";

interface Alert {
  alert_id: string;
  service: string;
  alert_type: string;
  message: string;
  severity: string;
  timestamp: string;
}

interface Analytics {
  total_alerts: number;
  total_incidents: number;
  severity_distribution: Record<string, number>;
}

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [analytics, setAnalytics] = useState<Analytics>({
    total_alerts: 0,
    total_incidents: 0,
    severity_distribution: {},
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState("");

  const loadDashboard = async () => {
    try {
      setError("");

      const [alertsResponse, analyticsResponse] = await Promise.all([
        fetch(`${API}/alerts`),
        fetch(`${API}/analytics`),
      ]);

      if (!alertsResponse.ok || !analyticsResponse.ok) {
        throw new Error("Unable to load dashboard data.");
      }

      const alertData = await alertsResponse.json();
      const analyticsData = await analyticsResponse.json();

      setAlerts(alertData);
      setAnalytics(analyticsData);
    } catch {
      setError("Backend connection failed. Please start your FastAPI server.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const analyzeAlerts = async () => {
    try {
      setAnalyzing(true);
      setAnalysisMessage("");

      const response = await fetch(`${API}/incidents/analyze`, {
        method: "POST",
      });

      const data = await response.json();

      setAnalysisMessage(data.message || "Analysis request completed.");
      await loadDashboard();
    } catch {
      setAnalysisMessage("Could not connect to the backend.");
    } finally {
      setAnalyzing(false);
    }
  };

  const filteredAlerts = alerts.filter((alert) =>
    `${alert.alert_id} ${alert.service} ${alert.message} ${alert.severity}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  const severityCount = (severity: string) =>
    alerts.filter(
      (alert) => alert.severity?.toLowerCase() === severity
    ).length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><Shield size={25} /></div>
          <div>
            <h2>AlertSense</h2>
            <span>INTELLIGENT MONITORING</span>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <div className="nav-item active">
          <LayoutDashboard size={19} /> Overview
        </div>
        <div className="nav-item">
          <Bell size={19} /> Live Alerts
        </div>
        <div className="nav-item">
          <Activity size={19} /> Incidents
        </div>
        <div className="nav-item">
          <Zap size={19} /> Root Cause Analysis
        </div>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <span>AlertSense Platform</span>
          <small>v1.0.0</small>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="breadcrumb">WORKSPACE / OVERVIEW</p>
            <h1>System Overview</h1>
          </div>
          <div className="top-actions">
            <button className="refresh-button" onClick={loadDashboard}>
              <RefreshCw size={16} /> Refresh
            </button>
            <div className="user-avatar">AS</div>
          </div>
        </header>

        {error && <div className="error-banner">{error}</div>}

        <section className="welcome-section">
          <div>
            <h2>Monitoring Dashboard</h2>
            <p>Monitor alerts and track system health in one place.</p>
          </div>
          <button
            className="analyze-button"
            onClick={analyzeAlerts}
            disabled={analyzing}
          >
            <Zap size={17} />
            {analyzing ? "Processing..." : "Analyze Alerts"}
          </button>
        </section>

        {analysisMessage && (
          <div className="info-banner">{analysisMessage}</div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span>Total Alerts</span>
              <Activity />
            </div>
            <h2>{loading ? "..." : analytics.total_alerts}</h2>
            <p>Alerts received by platform</p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Total Incidents</span>
              <AlertTriangle />
            </div>
            <h2>{loading ? "..." : analytics.total_incidents}</h2>
            <p>Recorded incidents</p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Critical Alerts</span>
              <Zap />
            </div>
            <h2>{loading ? "..." : severityCount("critical")}</h2>
            <p>Require immediate attention</p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Platform Status</span>
              <CheckCircle />
            </div>
            <h2 className="status-text">{error ? "Offline" : "Connected"}</h2>
            <p>Backend connection status</p>
          </div>
        </section>

        <section className="content-card">
          <div className="section-heading">
            <div>
              <h2>Recent Alerts</h2>
              <p>Latest alerts received by AlertSense</p>
            </div>
            <div className="search-box">
              <Search size={17} />
              <input
                placeholder="Search alerts..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ALERT ID</th>
                  <th>SERVICE</th>
                  <th>ALERT TYPE</th>
                  <th>MESSAGE</th>
                  <th>SEVERITY</th>
                  <th>TIMESTAMP</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} className="empty-state">Loading alerts...</td></tr>
                ) : filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-state">
                      No alerts found. Submit alerts through the API to get started.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert) => (
                    <tr key={alert.alert_id}>
                      <td className="alert-id">{alert.alert_id}</td>
                      <td>{alert.service}</td>
                      <td>{alert.alert_type}</td>
                      <td className="message-cell">{alert.message}</td>
                      <td>
                        <span className={`severity ${alert.severity?.toLowerCase()}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td>{alert.timestamp}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="bottom-grid">
          <div className="content-card">
            <h2>Severity Distribution</h2>
            <p className="muted">Alert breakdown by severity</p>
            {Object.entries(analytics.severity_distribution).length === 0 ? (
              <p className="empty-state">No severity data available.</p>
            ) : (
              Object.entries(analytics.severity_distribution).map(([key, value]) => (
                <div className="severity-row" key={key}>
                  <span>{key}</span>
                  <strong>{value}</strong>
                </div>
              ))
            )}
          </div>

          <div className="content-card platform-card">
            <Clock size={24} />
            <h2>AI Investigation</h2>
            <p>
              Alert ingestion is available. LangGraph agent investigation
              integration is pending.
            </p>
            <span className="pending-label">AGENT INTEGRATION PENDING</span>
          </div>
        </section>

        <footer>AlertSense © 2026 · Intelligent Alert Monitoring Platform</footer>
      </main>
    </div>
  );
}

export default App;
