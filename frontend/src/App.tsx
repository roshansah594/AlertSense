import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bell,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  Clock,
  Database,
  FileText,
  Layers,
  LayoutDashboard,
  RefreshCw,
  Search,
  Server,
  Shield,
  Trash2,
  Zap,
} from "lucide-react";
import "./App.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api";
const AUTH_TOKEN = import.meta.env.VITE_API_KEY || "alertsense-admin-dev-key";

const getHeaders = (extraHeaders?: Record<string, string>) => {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...extraHeaders,
  };
  if (AUTH_TOKEN) {
    headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  }
  return headers;
};

type TabType = "overview" | "alerts" | "incidents" | "rca";

interface Alert {
  alert_id: string;
  service: string;
  alert_type: string;
  message: string;
  severity: string;
  timestamp: string;
}

interface IncidentAction {
  action: string;
  category: string;
  is_safe_readonly: boolean;
}

interface Incident {
  incident_id: string;
  title: string;
  summary: string;
  severity_level: string; // P1, P2, P3, P4
  severity_score: number;
  severity_reasoning: string;
  root_cause_service: string;
  root_cause_hypothesis: string;
  confidence_score: number;
  affected_services: string[];
  alert_ids: string[];
  duplicate_alert_ids: string[];
  alerts?: Alert[];
  recommended_actions: IncidentAction[];
  created_at?: string;
}

interface Analytics {
  total_alerts: number;
  total_incidents: number;
  noise_reduction_ratio: number;
  severity_distribution: Record<string, number>;
  incident_severity_distribution: Record<string, number>;
}

function App() {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [analytics, setAnalytics] = useState<Analytics>({
    total_alerts: 0,
    total_incidents: 0,
    noise_reduction_ratio: 0.0,
    severity_distribution: {},
    incident_severity_distribution: {},
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [loadingSamples, setLoadingSamples] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState("");

  // Filters
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [serviceFilter, setServiceFilter] = useState("all");

  // Incident timeline toggle map
  const [expandedTimelines, setExpandedTimelines] = useState<Record<string, boolean>>({});

  const toggleTimeline = (id: string) => {
    setExpandedTimelines((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const loadDashboard = async () => {
    try {
      setError("");

      const [alertsRes, incidentsRes, analyticsRes] = await Promise.all([
        fetch(`${API}/alerts`, { headers: getHeaders() }),
        fetch(`${API}/incidents`, { headers: getHeaders() }),
        fetch(`${API}/analytics`, { headers: getHeaders() }),
      ]);

      if (alertsRes.status === 401 || alertsRes.status === 403) {
        throw new Error("Authentication failed: invalid or missing API credentials.");
      }

      if (!alertsRes.ok || !incidentsRes.ok || !analyticsRes.ok) {
        throw new Error("Unable to load platform data from backend.");
      }

      const alertData = await alertsRes.json();
      const incidentData = await incidentsRes.json();
      const analyticsData = await analyticsRes.json();

      setAlerts(Array.isArray(alertData) ? alertData : []);
      setIncidents(Array.isArray(incidentData) ? incidentData : []);
      setAnalytics({
        total_alerts: analyticsData?.total_alerts || 0,
        total_incidents: analyticsData?.total_incidents || 0,
        noise_reduction_ratio: analyticsData?.noise_reduction_ratio || 0.0,
        severity_distribution: analyticsData?.severity_distribution || {},
        incident_severity_distribution: analyticsData?.incident_severity_distribution || {},
      });
    } catch (err: any) {
      setError(err?.message || "Backend connection failed. Please ensure FastAPI server is running on http://127.0.0.1:8000.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadSampleAlerts = async () => {
    try {
      setLoadingSamples(true);
      setError("");
      setAnalysisMessage("");

      const response = await fetch(`${API}/alerts/load-sample`, {
        method: "POST",
        headers: getHeaders(),
      });
      if (response.status === 401 || response.status === 403) {
        throw new Error("Authentication failed: invalid or missing API credentials.");
      }
      if (!response.ok) throw new Error("Failed to load sample alerts.");

      const data = await response.json();
      setAnalysisMessage(data.message || "Benchmark sample alerts loaded successfully.");
      await loadDashboard();
    } catch (e: any) {
      setError(e.message || "Failed to load benchmark dataset.");
    } finally {
      setLoadingSamples(false);
    }
  };

  const analyzeAlerts = async () => {
    try {
      setAnalyzing(true);
      setError("");
      setAnalysisMessage("");

      const response = await fetch(`${API}/incidents/analyze`, {
        method: "POST",
        headers: getHeaders(),
      });
      if (response.status === 401 || response.status === 403) {
        throw new Error("Authentication failed: invalid or missing API credentials.");
      }
      if (!response.ok) throw new Error("Analysis failed on backend.");

      const data = await response.json();
      setAnalysisMessage(
        data.message ||
          `Investigation completed: consolidated into ${data.incidents_count || 0} incidents.`
      );
      await loadDashboard();
      if (data.incidents && data.incidents.length > 0) {
        setActiveTab("incidents");
      }
    } catch (e: any) {
      setError(e.message || "Failed to trigger AI multi-agent investigation.");
    } finally {
      setAnalyzing(false);
    }
  };

  const resetPlatform = async () => {
    if (resetting) return;
    if (!window.confirm("Are you sure you want to clear all alerts and incidents?")) return;
    try {
      setResetting(true);
      setError("");
      const response = await fetch(`${API}/reset`, {
        method: "POST",
        headers: getHeaders(),
      });
      if (response.status === 403) {
        throw new Error("Reset denied: Administrator privileges required.");
      }
      if (response.status === 401) {
        throw new Error("Authentication failed: invalid or missing API credentials.");
      }
      if (!response.ok) {
        throw new Error("Failed to reset platform.");
      }
      setAnalysisMessage("Platform reset: all alerts and incidents cleared.");
      await loadDashboard();
    } catch (err: any) {
      setError(err?.message || "Failed to reset platform.");
    } finally {
      setResetting(false);
    }
  };

  // Unique service names for filtering
  const uniqueServices = Array.from(new Set(alerts.map((a) => a.service))).sort();

  // Filtered alerts
  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch = `${alert.alert_id} ${alert.service} ${alert.message} ${alert.severity}`
      .toLowerCase()
      .includes(search.toLowerCase());
    const matchesSeverity =
      severityFilter === "all" || alert.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesService = serviceFilter === "all" || alert.service === serviceFilter;
    return matchesSearch && matchesSeverity && matchesService;
  });

  const severityCount = (severity: string) =>
    alerts.filter((alert) => alert.severity?.toLowerCase() === severity.toLowerCase()).length;

  const renderSeverityBadge = (level: string) => {
    const norm = (level || "").toUpperCase();
    if (norm.startsWith("P1") || norm.includes("CRITICAL")) return <span className="severity-pill-p1">P1 - CRITICAL</span>;
    if (norm.startsWith("P2") || norm.includes("HIGH")) return <span className="severity-pill-p2">P2 - HIGH</span>;
    if (norm.startsWith("P3") || norm.includes("MEDIUM")) return <span className="severity-pill-p3">P3 - MEDIUM</span>;
    return <span className="severity-pill-p4">P4 - LOW</span>;
  };

  const renderConfidenceBadge = (score: number) => {
    const pct = Math.round((score || 0) * 100);
    if (score >= 0.85) return <span className="confidence-badge confidence-high">{pct}% Confidence</span>;
    if (score >= 0.6) return <span className="confidence-badge confidence-medium">{pct}% Confidence</span>;
    return <span className="confidence-badge confidence-low">{pct}% Confidence</span>;
  };

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={24} />
          </div>
          <div>
            <h2>AlertSense</h2>
            <span>AI INCIDENT PLATFORM</span>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <div
          className={`nav-item ${activeTab === "overview" ? "active" : ""}`}
          onClick={() => setActiveTab("overview")}
        >
          <LayoutDashboard size={18} /> Overview
        </div>
        <div
          className={`nav-item ${activeTab === "alerts" ? "active" : ""}`}
          onClick={() => setActiveTab("alerts")}
        >
          <Bell size={18} /> Live Alerts
          <span className="tab-badge">{alerts.length}</span>
        </div>
        <div
          className={`nav-item ${activeTab === "incidents" ? "active" : ""}`}
          onClick={() => setActiveTab("incidents")}
        >
          <Activity size={18} /> Incidents
          <span className="tab-badge">{incidents.length}</span>
        </div>
        <div
          className={`nav-item ${activeTab === "rca" ? "active" : ""}`}
          onClick={() => setActiveTab("rca")}
        >
          <Zap size={18} /> Root Cause Analysis
        </div>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <span>{error ? "Backend Offline" : "Multi-Agent System Online"}</span>
          <small>v1.0.0</small>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <div>
            <p className="breadcrumb">WORKSPACE / {activeTab.toUpperCase()}</p>
            <h1>
              {activeTab === "overview" && "System Overview"}
              {activeTab === "alerts" && "Live Alert Storm Stream"}
              {activeTab === "incidents" && "Candidate Incident Clusters"}
              {activeTab === "rca" && "Root Cause Investigation & Mitigations"}
            </h1>
          </div>
          <div className="top-actions">
            <button
              className="sample-button"
              onClick={loadSampleAlerts}
              disabled={loadingSamples}
              title="Load 16 synthetic benchmark alerts across 6 scenarios"
            >
              <Database size={15} />
              {loadingSamples ? "Loading..." : "Load Sample Data"}
            </button>
            <button
              className="refresh-button"
              onClick={loadDashboard}
              title="Refresh alerts, incidents, and analytics"
            >
              <RefreshCw size={15} /> Refresh
            </button>
            <button
              className="reset-button"
              onClick={resetPlatform}
              disabled={resetting}
              title="Clear all alerts and incidents"
            >
              <Trash2 size={15} /> {resetting ? "Resetting..." : "Reset"}
            </button>
            <div className="user-avatar" title="AlertSense Engineer">AS</div>
          </div>
        </header>

        {error && <div className="error-banner">{error}</div>}
        {analysisMessage && <div className="info-banner">{analysisMessage}</div>}

        {/* Global Action Banner */}
        <section className="welcome-section">
          <div>
            <h2>Alert Storm Correlation & Root Cause Intelligence</h2>
            <p>
              AI-driven multi-agent correlation reducing alert fatigue, isolating blast radius, and identifying root causes.
            </p>
          </div>
          <button
            className="analyze-button"
            onClick={analyzeAlerts}
            disabled={analyzing}
          >
            <Zap size={17} />
            {analyzing ? "Running LangGraph Multi-Agent Workflow..." : "Run AI Investigation"}
          </button>
        </section>

        {/* =========================================================================
            TAB 1: OVERVIEW
           ========================================================================= */}
        {activeTab === "overview" && (
          <>
            <section className="stats-grid">
              <div className="stat-card">
                <div className="stat-top">
                  <span>Total Ingested Alerts</span>
                  <Activity />
                </div>
                <h2>{loading ? "..." : analytics.total_alerts}</h2>
                <p>Raw incoming telemetry alerts</p>
              </div>

              <div className="stat-card">
                <div className="stat-top">
                  <span>Candidate Incidents</span>
                  <AlertTriangle />
                </div>
                <h2>{loading ? "..." : analytics.total_incidents}</h2>
                <p>Correlated incident clusters</p>
              </div>

              <div className="stat-card">
                <div className="stat-top">
                  <span>Noise Reduction Ratio</span>
                  <Layers />
                </div>
                <h2>
                  {loading
                    ? "..."
                    : `${Math.round(analytics.noise_reduction_ratio * 100)}%`}
                </h2>
                <p>Alert suppression & deduplication</p>
              </div>

              <div className="stat-card">
                <div className="stat-top">
                  <span>Critical (P1 / Critical)</span>
                  <Zap />
                </div>
                <h2>{loading ? "..." : severityCount("critical")}</h2>
                <p>Requires immediate triage</p>
              </div>
            </section>

            {/* LangGraph Pipeline Status Card */}
            <section className="content-card">
              <div className="section-heading">
                <div>
                  <h2>LangGraph Multi-Agent Pipeline Architecture</h2>
                  <p>Autonomous state graph coordinating deterministic clustering with Google Gemini LLM reasoning</p>
                </div>
                <div className="active-agent-badge">
                  <CheckCircle size={14} /> Pipeline Operational
                </div>
              </div>

              <div className="pipeline-diagram">
                <div className="pipeline-step active">
                  <Server size={14} /> 1. Alert Ingestion & Cleaning
                </div>
                <span className="pipeline-arrow"><ArrowRight size={14} /></span>
                <div className="pipeline-step active">
                  <Layers size={14} /> 2. Multi-Signal Correlation Agent
                </div>
                <span className="pipeline-arrow"><ArrowRight size={14} /></span>
                <div className="pipeline-step active">
                  <Zap size={14} /> 3. Root Cause Analysis Agent
                </div>
                <span className="pipeline-arrow"><ArrowRight size={14} /></span>
                <div className="pipeline-step active">
                  <AlertTriangle size={14} /> 4. Deterministic Severity Agent
                </div>
                <span className="pipeline-arrow"><ArrowRight size={14} /></span>
                <div className="pipeline-step active">
                  <FileText size={14} /> 5. Executive Reporting Agent
                </div>
              </div>
            </section>

            {/* Recent Alerts Preview */}
            <section className="content-card">
              <div className="section-heading">
                <div>
                  <h2>Recent Ingested Alerts</h2>
                  <p>Showing latest alerts streaming into AlertSense</p>
                </div>
                <button
                  className="timeline-toggle-btn"
                  onClick={() => setActiveTab("alerts")}
                >
                  View All Alerts <ArrowRight size={13} />
                </button>
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
                      <tr>
                        <td colSpan={6} className="empty-state">Loading alerts...</td>
                      </tr>
                    ) : alerts.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="empty-state">
                          No alerts available. Click "Load Sample Data" to load benchmark telemetry.
                        </td>
                      </tr>
                    ) : (
                      alerts.slice(0, 6).map((alert) => (
                        <tr key={alert.alert_id}>
                          <td className="alert-id">{alert.alert_id}</td>
                          <td>
                            <span className="service-pill">{alert.service}</span>
                          </td>
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

            {/* Bottom Grid: Distributions */}
            <section className="bottom-grid">
              <div className="content-card">
                <h2>Alert Severity Distribution</h2>
                <p className="muted">Breakdown across all received alerts</p>
                {Object.entries(analytics.severity_distribution).length === 0 ? (
                  <p className="empty-state">No severity data available.</p>
                ) : (
                  Object.entries(analytics.severity_distribution).map(([key, value]) => (
                    <div className="severity-row" key={key}>
                      <span className={`severity ${key.toLowerCase()}`}>{key}</span>
                      <strong>{value} alerts</strong>
                    </div>
                  ))
                )}
              </div>

              <div className="content-card">
                <h2>Incident Priority Breakdown</h2>
                <p className="muted">Consolidated incidents by evaluated impact tier</p>
                {Object.entries(analytics.incident_severity_distribution).length === 0 ? (
                  <p className="empty-state">
                    No incidents yet. Click "Run AI Investigation" to evaluate clusters.
                  </p>
                ) : (
                  Object.entries(analytics.incident_severity_distribution).map(([key, value]) => (
                    <div className="severity-row" key={key}>
                      <span>{renderSeverityBadge(key)}</span>
                      <strong>{value} incident(s)</strong>
                    </div>
                  ))
                )}
              </div>
            </section>
          </>
        )}

        {/* =========================================================================
            TAB 2: LIVE ALERTS
           ========================================================================= */}
        {activeTab === "alerts" && (
          <section className="content-card">
            <div className="section-heading">
              <div>
                <h2>Live Alert Storm Telemetry</h2>
                <p>
                  Showing {filteredAlerts.length} of {alerts.length} total alerts
                </p>
              </div>

              <div className="filter-row">
                {/* Search */}
                <div className="search-box">
                  <Search size={16} />
                  <input
                    placeholder="Search alert, message, service..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>

                {/* Severity Filter */}
                <select
                  className="filter-select"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>

                {/* Service Filter */}
                <select
                  className="filter-select"
                  value={serviceFilter}
                  onChange={(e) => setServiceFilter(e.target.value)}
                >
                  <option value="all">All Services</option>
                  {uniqueServices.map((svc) => (
                    <option key={svc} value={svc}>
                      {svc}
                    </option>
                  ))}
                </select>
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
                    <tr>
                      <td colSpan={6} className="empty-state">Loading alerts...</td>
                    </tr>
                  ) : filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="empty-state">
                        No alerts match the selected criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredAlerts.map((alert) => (
                      <tr key={alert.alert_id}>
                        <td className="alert-id">{alert.alert_id}</td>
                        <td>
                          <span className="service-pill">{alert.service}</span>
                        </td>
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
        )}

        {/* =========================================================================
            TAB 3: INCIDENTS
           ========================================================================= */}
        {activeTab === "incidents" && (
          <div>
            {incidents.length === 0 ? (
              <div className="content-card empty-state">
                <AlertTriangle size={32} style={{ color: "#f59f00", marginBottom: 12 }} />
                <h3>No Incidents Analyzed Yet</h3>
                <p style={{ margin: "8px 0 16px" }}>
                  Load the synthetic sample alerts and run the AI multi-agent investigation to generate candidate incidents.
                </p>
                <button className="analyze-button" onClick={analyzeAlerts} disabled={analyzing}>
                  <Zap size={16} /> Run AI Investigation
                </button>
              </div>
            ) : (
              incidents.map((inc) => (
                <div className="incident-card" key={inc.incident_id}>
                  <div className="incident-header">
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span className="incident-id-badge">{inc.incident_id}</span>
                      {renderSeverityBadge(inc.severity_level)}
                    </div>
                    {renderConfidenceBadge(inc.confidence_score)}
                  </div>

                  <h3 className="incident-title">{inc.title}</h3>
                  <p className="incident-summary">{inc.summary}</p>

                  <div className="incident-meta-row">
                    <div className="meta-item">
                      <strong>Root Cause Service:</strong>
                      <span className="service-pill">{inc.root_cause_service}</span>
                    </div>

                    <div className="meta-item">
                      <strong>Severity Score:</strong>
                      <span>{inc.severity_score} / 100.0</span>
                    </div>

                    <div className="meta-item">
                      <strong>Correlated Alerts:</strong>
                      <span>{inc.alert_ids?.length || 0} alerts</span>
                      {inc.duplicate_alert_ids?.length > 0 && (
                        <small style={{ color: "#8994a8" }}>
                          ({inc.duplicate_alert_ids.length} deduplicated)
                        </small>
                      )}
                    </div>

                    <div className="meta-item">
                      <strong>Blast Radius:</strong>
                      <div className="tag-list">
                        {inc.affected_services?.map((svc) => (
                          <span className="service-pill" key={svc}>
                            {svc}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Collapsible Alert Cascade Timeline */}
                  <div style={{ marginTop: 12 }}>
                    <button
                      className="timeline-toggle-btn"
                      onClick={() => toggleTimeline(inc.incident_id)}
                    >
                      <Clock size={14} />
                      {expandedTimelines[inc.incident_id] ? "Hide" : "View"} Alert Cascade Timeline ({inc.alerts?.length || inc.alert_ids?.length || 0})
                      {expandedTimelines[inc.incident_id] ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>

                    {expandedTimelines[inc.incident_id] && (
                      <div className="timeline-container">
                        {(!inc.alerts || inc.alerts.length === 0) ? (
                          <p style={{ fontSize: 12, color: "#64748b" }}>
                            Associated alert IDs: {inc.alert_ids?.join(", ")}
                          </p>
                        ) : (
                          inc.alerts.map((alt) => (
                            <div className="timeline-item" key={alt.alert_id}>
                              <div className="timeline-time">{alt.timestamp}</div>
                              <div className="timeline-content">
                                <div className="timeline-title">
                                  [{alt.alert_id}] {alt.service} — {alt.alert_type}
                                  <span
                                    className={`severity ${alt.severity?.toLowerCase()}`}
                                    style={{ marginLeft: 8 }}
                                  >
                                    {alt.severity}
                                  </span>
                                </div>
                                <div className="timeline-msg">{alt.message}</div>
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 4: ROOT CAUSE ANALYSIS (RCA)
           ========================================================================= */}
        {activeTab === "rca" && (
          <div>
            {incidents.length === 0 ? (
              <div className="content-card empty-state">
                <Zap size={32} style={{ color: "#2865e9", marginBottom: 12 }} />
                <h3>No RCA Reports Available</h3>
                <p style={{ margin: "8px 0 16px" }}>
                  Execute the AI investigation to perform root cause hypothesis generation and mitigation planning.
                </p>
                <button className="analyze-button" onClick={analyzeAlerts} disabled={analyzing}>
                  <Zap size={16} /> Run AI Investigation
                </button>
              </div>
            ) : (
              incidents.map((inc) => (
                <div className="rca-card" key={inc.incident_id}>
                  <div className="rca-title-row">
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                        <span className="incident-id-badge">{inc.incident_id}</span>
                        {renderSeverityBadge(inc.severity_level)}
                        <span style={{ fontSize: 13, color: "#64748b" }}>
                          Suspected Service: <strong>{inc.root_cause_service}</strong>
                        </span>
                      </div>
                      <h3 style={{ margin: 0, fontSize: 18, color: "#0f172a" }}>{inc.title}</h3>
                    </div>
                    {renderConfidenceBadge(inc.confidence_score)}
                  </div>

                  {/* Primary Root Cause Hypothesis */}
                  <div className="rca-narrative">
                    <strong>Primary Root Cause Hypothesis:</strong>
                    <p style={{ marginTop: 6, lineHeight: 1.6 }}>{inc.root_cause_hypothesis}</p>
                  </div>

                  {/* Evidence Alerts */}
                  <div className="evidence-box">
                    <h4>Correlated Evidence Alerts ({inc.alert_ids?.length || 0})</h4>
                    <div>
                      {inc.alert_ids?.map((aid) => (
                        <span className="evidence-badge" key={aid}>
                          {aid}
                        </span>
                      ))}
                    </div>
                    <p style={{ fontSize: 11, color: "#64748b", marginTop: 8 }}>
                      * All hypotheses are strictly grounded in observed telemetry and topology. Correlation does not automatically prove causality.
                    </p>
                  </div>

                  {/* Severity Decision Reasoning */}
                  <div style={{ background: "#f8fafc", padding: "12px 16px", borderRadius: 8, marginBottom: 16 }}>
                    <h4 style={{ margin: "0 0 6px", fontSize: 13, color: "#1e293b" }}>Severity Evaluation Reasoning</h4>
                    <p style={{ fontSize: 12, color: "#475569", margin: 0 }}>{inc.severity_reasoning}</p>
                  </div>

                  {/* Recommended Action Plan */}
                  <div className="recommendations-box">
                    <h4>Categorized Mitigation Plan</h4>
                    {inc.recommended_actions?.length === 0 ? (
                      <p style={{ fontSize: 12, color: "#8994a8" }}>No specific actions generated.</p>
                    ) : (
                      inc.recommended_actions?.map((act, idx) => (
                        <div className="action-card" key={idx}>
                          <span className="action-category">
                            {act.category?.replace(/_/g, " ").toUpperCase()}
                          </span>
                          <span style={{ flex: 1, color: "#334155" }}>{act.action}</span>
                          {act.is_safe_readonly && (
                            <span
                              style={{
                                background: "#e6fcf5",
                                color: "#0ca678",
                                fontSize: 10,
                                fontWeight: 700,
                                padding: "3px 8px",
                                borderRadius: 4,
                              }}
                            >
                              SAFE READONLY
                            </span>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        <footer>AlertSense © 2026 · Intelligent Alert Storm Monitoring & Multi-Agent RCA Platform</footer>
      </main>
    </div>
  );
}

export default App;
