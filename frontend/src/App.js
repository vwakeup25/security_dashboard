import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { Line, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  LineElement,
  ArcElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Tooltip,
  Legend,
} from "chart.js";
import { motion, AnimatePresence } from "framer-motion";

ChartJS.register(LineElement, ArcElement, CategoryScale, LinearScale, PointElement, Tooltip, Legend);

// ===================== CONFIG =====================
const API_BASE = "http://127.0.0.1:8000"; // backend
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const chip = (text, color) => (
  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${color}`}>{text}</span>
);

// 🔑 Ensure token exists (Steps 5 & 6)
// Logs in once, stores JWT, and attaches it to axios for all future requests.
async function ensureToken() {
  try {
    let token = localStorage.getItem("token");
    if (!token) {
      const form = new FormData();
      // These must match your backend ENV (ADMIN_USER / ADMIN_PASS)
      form.append("username", "admin");
      form.append("password", "admin123");

      const res = await fetch(`${API_BASE}/login`, { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok || !data?.access_token) {
        console.error("Login failed:", data);
        return;
      }
      token = data.access_token;
      localStorage.setItem("token", token);
    }
    axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  } catch (e) {
    console.error("ensureToken error:", e);
  }
}

// ===================== APP =====================
function App() {
  // ---- data state
  const [mode, setMode] = useState("simulate");
  const [connected, setConnected] = useState(false);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [limit, setLimit] = useState(25);
  const [filterType, setFilterType] = useState("All");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [packetRate, setPacketRate] = useState(0);
  const [rateHistory, setRateHistory] = useState([]);

  // ---- UI state
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [downloading, setDownloading] = useState(false);

  // Acquire token once on app mount and attach to axios
  useEffect(() => {
    ensureToken();
  }, []);

  // Reset when mode changes
  useEffect(() => {
    setPackets([]);
    setAlerts([]);
    setLogs([]);
    setPage(1);
  }, [mode]);

  // Polling backend
  useEffect(() => {
    let stop = false;
    const tick = async () => {
      while (!stop) {
        try {
          const [c, l, pr] = await Promise.all([
            axios.get(`${API_BASE}/capture?mode=${mode}`), // public
            axios.get(`${API_BASE}/logs`, {
              // protected by JWT
              params: { page, limit, type: filterType, severity: filterSeverity },
            }),
            axios.get(`${API_BASE}/packet_rate`), // public
          ]);
          setConnected(true);

          if (c.data?.packet) {
            setPackets((prev) => [...prev.slice(-30), c.data.packet]);
            if (c.data.packet.anomaly) {
              setAlerts((prev) => [
                {
                  t: new Date().toLocaleTimeString(),
                  src: c.data.packet.src_ip,
                  size: c.data.packet.size,
                  sev: c.data.packet.severity,
                  atk: c.data.packet.attack_type,
                  by: c.data.packet.detected_by,
                  conf: c.data.packet.ml_confidence,
                },
                ...prev.slice(0, 20),
              ]);
            }
          }

          const ld = l.data || {};
          setLogs(ld.items || []);
          setPages(ld.pages || 1);

          setPacketRate(pr.data?.rate ?? 0);
          setRateHistory(pr.data?.history ?? []);
        } catch (e) {
          setConnected(false);
        }
        await sleep(2500);
      }
    };
    tick();
    return () => {
      stop = true;
    };
  }, [mode, page, limit, filterType, filterSeverity]);

  // ---- computed
  const totalPackets = useMemo(() => logs.length, [logs]);
  const totalAnomalies = useMemo(
    () => logs.filter((r) => r.severity !== "Normal").length,
    [logs]
  );
  const severityCounts = useMemo(() => {
    let n = 0,
      lo = 0,
      md = 0,
      hi = 0;
    logs.forEach((r) => {
      if (r.severity === "Normal") n++;
      else if (r.severity === "Low") lo++;
      else if (r.severity === "Medium") md++;
      else if (r.severity === "High") hi++;
    });
    return { n, lo, md, hi };
  }, [logs]);

  // ---- charts
  const trafficData = {
    labels: packets.map((p) => p.src_ip),
    datasets: [
      {
        label: "Packet Size (bytes)",
        data: packets.map((p) => p.size),
        borderColor: "#22c55e",
        backgroundColor: "rgba(34,197,94,0.2)",
        tension: 0.35,
        pointRadius: 2,
      },
    ],
  };
  const donutData = {
    labels: ["High", "Medium", "Low", "Normal"],
    datasets: [
      {
        data: [severityCounts.hi, severityCounts.md, severityCounts.lo, severityCounts.n],
        backgroundColor: ["#ef4444", "#f59e0b", "#84cc16", "#64748b"],
        borderColor: "#0b0f14",
        borderWidth: 2,
      },
    ],
  };
  const chartCommon = {
    plugins: {
      legend: { labels: { color: "#0b0f14" } },
      tooltip: {
        titleColor: "#0b0f14",
        bodyColor: "#0b0f14",
        backgroundColor: "#e5e7eb",
      },
    },
    scales: {
      x: { ticks: { color: "#333" }, grid: { color: "rgba(148,163,184,0.18)" } },
      y: { ticks: { color: "#333" }, grid: { color: "rgba(148,163,184,0.18)" } },
    },
  };

  // ---- actions
  const downloadPDF = async () => {
    setDownloading(true);
    try {
      const res = await axios.get(`${API_BASE}/export`, {
        params: { format: "pdf" }, // protected by JWT
        responseType: "blob",
      });
      const blob = new Blob([res.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "logs.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {}
    setDownloading(false);
  };

  const handleReset = async () => {
    try {
      await axios.post(`${API_BASE}/reset`); // protected by JWT
      setPackets([]);
      setAlerts([]);
      setLogs([]);
      setPage(1);
    } catch {}
  };

  // ---- chips
  const sevChip = (s) => {
    if (s === "High") return chip("High", "bg-red-600 text-white");
    if (s === "Medium") return chip("Medium", "bg-yellow-500 text-black");
    if (s === "Low") return chip("Low", "bg-lime-500 text-black");
    return chip("Normal", "bg-slate-600 text-white");
  };
  const byChip = (b) =>
    b === "ML"
      ? chip("ML", "bg-purple-600 text-white")
      : b === "Rule"
      ? chip("Rule", "bg-sky-600 text-white")
      : chip("None", "bg-slate-600 text-white");

  // ===================== UI =====================
  return (
    <div className="min-h-screen bg-white text-black">
      {/* Top bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-white shadow">
        <div className="flex items-center gap-3">
          {/* Hamburger */}
          <button
            onClick={() => setSidebarOpen((s) => !s)}
            className="w-10 h-10 grid place-items-center rounded hover:bg-slate-800/10 active:scale-95 transition"
            aria-label="Toggle menu"
            title="Menu"
          >
            <div className="w-5 border-t-2 border-black" />
            <div className="w-5 border-t-2 border-black mt-1" />
            <div className="w-5 border-t-2 border-black mt-1" />
          </button>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-wide text-black">
            Smart Security Dashboard
          </h1>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`px-3 py-1 rounded-full text-sm ${
              connected ? "bg-emerald-500 text-black" : "bg-red-600 text-white"
            }`}
          >
            {connected ? "Connected" : "Disconnected"}
          </span>
          <span className="px-2 py-1 rounded bg-slate-800 text-sm text-white">Environment: Local</span>
        </div>
      </div>

      {/* Push layout: sidebar pushes content (not overlay) */}
      <div className="relative flex">
        {/* Sidebar */}
        <AnimatePresence initial={false}>
          <motion.aside
            key={String(sidebarOpen)}
            className="h-[calc(100vh-56px)] sticky top-[56px] bg-[#ececec] border-r border-slate-800 z-20"
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: sidebarOpen ? 288 : 0, opacity: sidebarOpen ? 1 : 0 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ type: "spring", stiffness: 250, damping: 28 }}
            style={{ overflow: "hidden" }}
          >
            <div className="h-full w-72 px-4 py-4">
              <div className="text-lg font-bold mb-3 text-emerald-600">⚡ Menu</div>

              {/* Mode */}
              <div className="bg-gray-200 rounded-lg p-3 border border-slate-800">
                <div className="text-sm mb-2 opacity-90 text-black">Capture Mode</div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setMode("simulate")}
                    className={`px-3 py-1 rounded transition ${
                      mode === "simulate"
                        ? "bg-emerald-500 text-black shadow-lg shadow-emerald-500/30"
                        : "bg-gray-300 hover:bg-gray-400 text-black"
                    }`}
                  >
                    Simulation
                  </button>
                  <button
                    onClick={() => setMode("real")}
                    className={`px-3 py-1 rounded transition ${
                      mode === "real"
                        ? "bg-red-500 text-white shadow-lg shadow-red-500/30"
                        : "bg-gray-300 hover:bg-gray-400 text-black"
                    }`}
                  >
                    Real
                  </button>
                </div>
              </div>

              {/* Export PDF */}
              <button
                onClick={downloadPDF}
                className="w-full mt-3 text-left px-3 py-2 rounded bg-gray-200 hover:bg-violet-200 border border-slate-800 hover:border-violet-500 transition text-black"
              >
                ⬇️ Export PDF
              </button>

              {/* Reset */}
              <button
                onClick={handleReset}
                className="w-full mt-2 text-left px-3 py-2 rounded bg-gray-200 hover:bg-amber-200 border border-slate-800 hover:border-amber-400 transition text-black"
              >
                ♻️ Reset Logs
              </button>

              {/* Filters */}
              <div className="bg-gray-200 rounded-lg p-3 border border-slate-800 mt-3">
                <div className="text-sm opacity-90 mb-2 text-black">Filters</div>
                <div className="grid grid-cols-2 gap-2">
                  <select
                    value={filterType}
                    onChange={(e) => {
                      setPage(1);
                      setFilterType(e.target.value);
                    }}
                    className="bg-gray-300 rounded px-2 py-1 text-black"
                  >
                    {[
                      "All",
                      "Possible DDoS",
                      "Suspicious Host",
                      "Unknown Attack (AI Flagged)",
                      "Normal",
                      "Large Packet",
                    ].map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                  <select
                    value={filterSeverity}
                    onChange={(e) => {
                      setPage(1);
                      setFilterSeverity(e.target.value);
                    }}
                    className="bg-gray-300 rounded px-2 py-1 text-black"
                  >
                    {["All", "High", "Medium", "Low", "Normal"].map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="text-sm opacity-80 mt-3 text-black">
                User: <span className="font-semibold">demo@local</span>
              </div>
              <button className="w-full mt-2 text-left px-3 py-2 rounded bg-gray-200 hover:bg-red-200 border border-slate-800 hover:border-red-500 transition text-black">
                🚪 Logout
              </button>

              {downloading && <div className="mt-4 text-xs opacity-80 text-black">Preparing PDF…</div>}
            </div>
          </motion.aside>
        </AnimatePresence>

        {/* Main content (shifts when sidebar opens) */}
        <motion.main
          className="flex-1 p-4 md:p-6 bg-white text-black"
          animate={{ marginLeft: sidebarOpen ? 16 : 0 }}
          transition={{ type: "spring", stiffness: 250, damping: 28 }}
        >
          {/* KPI row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <div className="bg-gray-100 rounded-xl p-4 border border-slate-800 hover:border-emerald-500/40 transition">
              <div className="text-sm text-gray-600">Total Packets</div>
              <div className="text-2xl font-bold text-black">{totalPackets}</div>
            </div>
            <div className="bg-gray-100 rounded-xl p-4 border border-slate-800 hover:border-rose-500/40 transition">
              <div className="text-sm text-gray-600">Anomalies</div>
              <div className="text-2xl font-bold text-rose-600">{totalAnomalies}</div>
            </div>
            <div className="bg-gray-100 rounded-xl p-4 border border-slate-800 hover:border-sky-500/40 transition">
              <div className="text-sm text-gray-600">Packet Rate (per sec)</div>
              <div className="text-2xl font-bold text-black">{packetRate.toFixed(2)}</div>
            </div>
            <div className="bg-gray-100 rounded-xl p-4 border border-slate-800 hover:border-violet-500/40 transition">
              <div className="text-sm text-gray-600">Environment</div>
              <div className="text-2xl font-bold text-black">Local</div>
            </div>
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            <div className="lg:col-span-2 bg-gray-100 rounded-xl p-4 border border-slate-800">
              <div className="font-semibold text-black mb-2">Network Traffic</div>
              <Line data={trafficData} options={chartCommon} />
            </div>
            <div className="bg-gray-100 rounded-xl p-4 border border-slate-800">
              <div className="font-semibold text-black mb-2">Anomalies Detected</div>
              <Doughnut
                data={donutData}
                options={{
                  plugins: { legend: { labels: { color: "#0b0f14" } } },
                }}
              />
            </div>
          </div>

          {/* Alerts + Logs */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Alerts (compact) */}
            <div className="bg-gray-100 rounded-xl p-4 border border-slate-800">
              <div className="font-semibold text-black mb-2">Real-time Alerts</div>
              <div className="space-y-2 max-h-[280px] overflow-auto pr-1">
                {alerts.length === 0 && (
                  <div className="text-sm text-gray-600">No anomalies detected</div>
                )}
                {alerts.map((a, i) => (
                  <div key={i} className="p-2 rounded bg-gray-200 border border-slate-700">
                    <div className="text-xs text-gray-600">{a.t}</div>
                    <div className="text-sm text-black">
                      Suspicious packet from <span className="font-semibold">{a.src}</span> → {a.size} B
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2">
                      {sevChip(a.sev)}
                      {chip(a.atk, "bg-amber-600 text-black")}
                      {byChip(a.by)}
                      {a.by === "ML" && chip(`${Math.round(a.conf * 100)}%`, "bg-purple-700 text-white")}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Logs (BIG) */}
            <div className="lg:col-span-2 bg-gray-100 rounded-xl p-3 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <div className="font-semibold text-black">Secure Logs</div>
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-gray-600">Rows:</span>
                  <select
                    value={limit}
                    onChange={(e) => {
                      setPage(1);
                      setLimit(+e.target.value);
                    }}
                    className="bg-gray-300 text-black rounded px-2 py-1"
                  >
                    {[10, 25, 50, 100].map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="overflow-auto">
                <table className="min-w-full text-sm">
                  <thead className="sticky top-0 bg-gray-200/80 backdrop-blur z-10">
                    <tr className="text-left text-black">
                      {[
                        "Index",
                        "Timestamp",
                        "Src IP",
                        "Dst IP",
                        "Size",
                        "Severity",
                        "Attack Type",
                        "Detected By",
                        "Conf",
                        "Hostname",
                        "Country",
                        "City",
                        "ISP",
                        "Hash",
                      ].map((h) => (
                        <th key={h} className="px-2 py-2 border-b border-slate-700 whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((r) => (
                      <tr key={r.index} className="border-b border-slate-800 hover:bg-gray-200/60 text-black">
                        <td className="px-2 py-2">{r.index}</td>
                        <td className="px-2 py-2 whitespace-nowrap">{r.timestamp}</td>
                        <td className="px-2 py-2">{r.src_ip}</td>
                        <td className="px-2 py-2">{r.dst_ip}</td>
                        <td className="px-2 py-2">{r.size}</td>
                        <td className="px-2 py-2">{sevChip(r.severity)}</td>
                        <td className="px-2 py-2">
                          <span className="truncate inline-block max-w-[160px]" title={r.attack_type}>
                            {r.attack_type}
                          </span>
                        </td>
                        <td className="px-2 py-2">{byChip(r.detected_by)}</td>
                        <td className="px-2 py-2">
                          {r.detected_by === "ML" ? `${Math.round(r.ml_confidence * 100)}%` : "-"}
                        </td>
                        <td className="px-2 py-2 truncate max-w-[160px]" title={r.hostname}>
                          {r.hostname}
                        </td>
                        <td className="px-2 py-2">{r.country}</td>
                        <td className="px-2 py-2">{r.city}</td>
                        <td className="px-2 py-2 truncate max-w-[160px]" title={r.isp}>
                          {r.isp}
                        </td>
                        <td className="px-2 py-2 truncate max-w-[200px]" title={r.hash}>
                          {r.hash}
                        </td>
                      </tr>
                    ))}
                    {logs.length === 0 && (
                      <tr>
                        <td className="px-2 py-8 text-center text-gray-600" colSpan={14}>
                          No data
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-end gap-2 mt-3">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className={`px-3 py-1 rounded ${
                    page <= 1 ? "bg-gray-300 opacity-50 text-gray-600" : "bg-gray-300 hover:bg-gray-400 text-black"
                  }`}
                >
                  Prev
                </button>
                <span className="text-sm text-gray-600">
                  Page {page} / {pages}
                </span>
                <button
                  disabled={page >= pages}
                  onClick={() => setPage((p) => Math.min(pages, p + 1))}
                  className={`px-3 py-1 rounded ${
                    page >= pages ? "bg-gray-300 opacity-50 text-gray-600" : "bg-gray-300 hover:bg-gray-400 text-black"
                  }`}
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </motion.main>
      </div>
    </div>
  );
}

export default App;




