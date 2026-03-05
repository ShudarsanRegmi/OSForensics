import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Search, Upload, Trash2, Settings, Microscope,
  X, FolderOpen, AlertTriangle, CheckCircle, HardDrive, Activity,
  Clock, Shield, Eye, ChevronDown, ChevronUp, Hash, Terminal,
  Lock, Server, Key,
} from "lucide-react";

// ─── API ──────────────────────────────────────────────────────────────────────
const API = "http://127.0.0.1:8000";

async function apiAnalyze(path) {
  const res = await fetch(`${API}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ image_path: path }),
  });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
}

async function apiUpload(file) {
  const fd = new FormData();
  fd.append("file", file, file.name);
  const res = await fetch(`${API}/upload`, { method: "POST", body: fd });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
}

// ─── Severity helpers ─────────────────────────────────────────────────────────
const SEV_COLOR = {
  high:   "#dc2626",
  medium: "#d97706",
  low:    "#16a34a",
  info:   "#2563eb",
};
const SEV_BG = {
  high:   "#fff1f0",
  medium: "#fffbeb",
  low:    "#f0fdf4",
  info:   "#eff6ff",
};
function SevBadge({ sev }) {
  const s = (sev || "info").toLowerCase();
  return (
    <span className="sev-badge" style={{ background: SEV_COLOR[s] || "#6b7280" }}>
      {s}
    </span>
  );
}

// ─── MODAL ────────────────────────────────────────────────────────────────────
function Modal({ title, onClose, children, width = 540 }) {
  const ref = useRef(null);
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const drag = useRef({ dragging: false, ox: 0, oy: 0 });
  const [pos, setPos] = useState(null);
  const onMouseDown = (e) => {
    const r = ref.current.getBoundingClientRect();
    drag.current = { dragging: true, ox: e.clientX - r.left, oy: e.clientY - r.top };
  };
  const onMouseMove = useCallback((e) => {
    if (!drag.current.dragging) return;
    setPos({ x: e.clientX - drag.current.ox, y: e.clientY - drag.current.oy });
  }, []);
  const onMouseUp = useCallback(() => { drag.current.dragging = false; }, []);
  useEffect(() => {
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => { window.removeEventListener("mousemove", onMouseMove); window.removeEventListener("mouseup", onMouseUp); };
  }, [onMouseMove, onMouseUp]);

  const style = pos ? { position: "fixed", left: pos.x, top: pos.y, transform: "none", width } : { width };
  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal-window" ref={ref} style={style}>
        <div className="modal-titlebar" onMouseDown={onMouseDown}>
          <span className="modal-title">{title}</span>
          <button className="modal-close" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

// ─── ANALYZE DIALOG ───────────────────────────────────────────────────────────
function AnalyzeDialog({ onClose, onResult }) {
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  async function run() {
    if (!path) return;
    setLoading(true); setErr(null);
    try { const r = await apiAnalyze(path); onResult(r); onClose(); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }
  return (
    <Modal title="Analyze — Open Image or Mountpoint" onClose={onClose} width={600}>
      <div className="dlg-field">
        <label>Path to image / mountpoint</label>
        <input autoFocus value={path} onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="/mnt/snapshot  or  /path/to/disk.img" />
        <div className="dlg-hint">Use a mounted directory path for non-pytsk3 environments.</div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !path}>
          <Search size={14} />{loading ? "Analyzing…" : "Analyze"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── UPLOAD DIALOG ────────────────────────────────────────────────────────────
function UploadDialog({ onClose, onResult }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  async function run() {
    if (!file) return;
    setLoading(true); setErr(null);
    try { const r = await apiUpload(file); onResult(r); onClose(); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }
  return (
    <Modal title="Upload Image for Analysis" onClose={onClose} width={520}>
      <div className="dlg-field">
        <label>Select disk image file</label>
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <div className="dlg-hint">File is uploaded to the server, analyzed, then deleted automatically.</div>
      </div>
      {file && <div className="dlg-fileinfo">Selected: <strong>{file.name}</strong> ({(file.size/1024/1024).toFixed(1)} MB)</div>}
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !file}>
          <Upload size={14} />{loading ? "Uploading…" : "Upload & Analyze"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── ABOUT DIALOG ─────────────────────────────────────────────────────────────
function AboutDialog({ onClose }) {
  return (
    <Modal title="About OS Forensics" onClose={onClose} width={420}>
      <div className="about-body">
        <div className="about-icon"><Microscope size={52} strokeWidth={1.4} /></div>
        <h2>OS Forensics</h2>
        <p className="about-ver">build 0.2.0</p>
        <p>Advanced forensic detection and analysis tool for Linux-based environments. Supports live mounts and raw disk images via pytsk3 (SleuthKit).</p>
        <p className="about-stack">Backend: Python · FastAPI · pytsk3<br />Frontend: React · Vite</p>
        <p className="about-stack">Engines: Timeline Reconstruction · Deleted File Detection · Persistence Scanner</p>
      </div>
      <div className="dlg-actions"><button className="btn-primary" onClick={onClose}>OK</button></div>
    </Modal>
  );
}

// ─── SETTINGS DIALOG ──────────────────────────────────────────────────────────
function SettingsDialog({ onClose }) {
  return (
    <Modal title="Preferences" onClose={onClose} width={460}>
      <div className="dlg-field">
        <label>API Server URL</label>
        <input defaultValue="http://127.0.0.1:8000" disabled />
        <div className="dlg-hint">Configurable in a future release.</div>
      </div>
      <div className="dlg-field">
        <label>Theme</label>
        <select defaultValue="light"><option value="light">Light</option><option value="dark">Dark (coming soon)</option></select>
      </div>
      <div className="dlg-actions">
        <button className="btn-primary" onClick={onClose}>Save</button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── SHORTCUTS DIALOG ─────────────────────────────────────────────────────────
function ShortcutsDialog({ onClose }) {
  const shortcuts = [
    ["Ctrl + O", "Open Analyze dialog"],
    ["Ctrl + U", "Open Upload dialog"],
    ["Ctrl + ,", "Preferences"],
    ["F1",       "Help / About"],
    ["Escape",   "Close current dialog"],
  ];
  return (
    <Modal title="Keyboard Shortcuts" onClose={onClose} width={400}>
      <table className="rp-table">
        <thead><tr><th>Key</th><th>Action</th></tr></thead>
        <tbody>{shortcuts.map(([k, v]) => <tr key={k}><td><kbd>{k}</kbd></td><td>{v}</td></tr>)}</tbody>
      </table>
      <div className="dlg-actions"><button className="btn-primary" onClick={onClose}>OK</button></div>
    </Modal>
  );
}

// ─── MENU BAR ─────────────────────────────────────────────────────────────────
function MenuBar({ onAction }) {
  const [open, setOpen] = useState(null);
  const barRef = useRef(null);
  useEffect(() => {
    const close = (e) => { if (!barRef.current?.contains(e.target)) setOpen(null); };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, []);
  const menus = {
    File: [
      { label: "Analyze Image / Mountpoint…", key: "analyze",  shortcut: "Ctrl+O" },
      { label: "Upload Image for Analysis…",   key: "upload",   shortcut: "Ctrl+U" },
      { type: "sep" },
      { label: "Export Report JSON…",          key: "export" },
      { type: "sep" },
      { label: "Clear Analysis",               key: "clear" },
      { type: "sep" },
      { label: "Exit",                         key: "exit" },
    ],
    Edit: [
      { label: "Clear Analysis",  key: "clear" },
      { type: "sep" },
      { label: "Preferences…",    key: "settings", shortcut: "Ctrl+," },
    ],
    View: [
      { label: "Toggle Toolbar",    key: "toolbar" },
      { label: "Toggle Status Bar", key: "statusbar" },
    ],
    Tools: [
      { label: "Analyze Image / Mountpoint…", key: "analyze" },
      { label: "Upload Image for Analysis…",  key: "upload" },
      { type: "sep" },
      { label: "Keyboard Shortcuts…",         key: "shortcuts" },
    ],
    Help: [
      { label: "Keyboard Shortcuts…", key: "shortcuts", shortcut: "F1" },
      { type: "sep" },
      { label: "About OS Forensics…", key: "about" },
    ],
  };
  function pick(key) { setOpen(null); onAction(key); }
  return (
    <nav className="menubar" ref={barRef} role="menubar">
      {Object.entries(menus).map(([name, items]) => (
        <div key={name} className={`mb-item ${open === name ? "open" : ""}`}>
          <button className="mb-label" role="menuitem" aria-haspopup="true" aria-expanded={open === name}
            onClick={() => setOpen(open === name ? null : name)}
            onMouseEnter={() => open && setOpen(name)}>
            {name}
          </button>
          {open === name && (
            <ul className="mb-dropdown" role="menu">
              {items.map((item, i) =>
                item.type === "sep" ? <li key={i} className="mb-sep" role="separator" /> : (
                  <li key={i} className="mb-option" role="menuitem" onClick={() => pick(item.key)}>
                    <span>{item.label}</span>
                    {item.shortcut && <span className="mb-shortcut">{item.shortcut}</span>}
                  </li>
                )
              )}
            </ul>
          )}
        </div>
      ))}
    </nav>
  );
}

// ─── TOOLBAR ──────────────────────────────────────────────────────────────────
const TOOLBAR_BUTTONS = [
  { Icon: Search,   label: "Analyze",  key: "analyze",  title: "Analyze (Ctrl+O)" },
  { Icon: Upload,   label: "Upload",   key: "upload",   title: "Upload (Ctrl+U)" },
  { type: "sep" },
  { Icon: Trash2,   label: "Clear",    key: "clear",    title: "Clear analysis" },
  { type: "sep" },
  { Icon: Settings, label: "Prefs",    key: "settings", title: "Preferences (Ctrl+,)" },
];
function Toolbar({ visible, onAction }) {
  if (!visible) return null;
  return (
    <div className="toolbar" role="toolbar">
      {TOOLBAR_BUTTONS.map((b, i) =>
        b.type === "sep" ? <div key={i} className="tb-sep" /> : (
          <button key={i} className="tb-btn" title={b.title} onClick={() => onAction(b.key)}>
            <span className="tb-icon"><b.Icon size={18} strokeWidth={1.6} /></span>
            <span className="tb-label">{b.label}</span>
          </button>
        )
      )}
    </div>
  );
}

// ─── STATUS BAR ───────────────────────────────────────────────────────────────
function StatusBar({ visible, status, report }) {
  if (!visible) return null;
  const totalHigh = report?.summary?.total_high ?? 0;
  return (
    <div className="statusbar">
      <Activity size={11} className="sb-icon" />
      <span className="sb-status">{status}</span>
      {report && (
        <>
          <span className="sb-sep" />
          <HardDrive size={11} className="sb-icon" />
          <span>OS: <strong>{report.os_info?.name || "Unknown"}</strong></span>
          <span className="sb-sep" />
          <span>Tools: <strong>{report.summary?.total_tools ?? 0}</strong></span>
          <span className="sb-sep" />
          <span>Timeline: <strong>{report.summary?.timeline_events ?? 0}</strong></span>
          <span className="sb-sep" />
          <span className={totalHigh > 0 ? "sb-high" : "sb-ok"}>
            {totalHigh > 0 ? <AlertTriangle size={11} className="sb-icon" /> : <CheckCircle size={11} className="sb-icon" />}
            High: {totalHigh}
          </span>
        </>
      )}
    </div>
  );
}

// ─── WORKSPACE HOME ───────────────────────────────────────────────────────────
function WorkspaceHome({ onAction }) {
  return (
    <div className="ws-home">
      <div className="ws-logo"><Microscope size={64} strokeWidth={1.2} className="ws-logo-icon" /></div>
      <h1 className="ws-title">OS Forensics</h1>
      <p className="ws-sub">Advanced forensic detection for Linux-based environments</p>
      <div className="ws-feature-badges">
        <span className="feat-badge"><Clock size={12} /> Timeline Engine</span>
        <span className="feat-badge"><Eye size={12} /> Deleted File Detection</span>
        <span className="feat-badge"><Shield size={12} /> Persistence Scanner</span>
      </div>
      <div className="ws-quickactions">
        <button className="qa-btn" onClick={() => onAction("analyze")}>
          <span className="qa-icon"><Search size={28} strokeWidth={1.5} /></span>
          <span className="qa-label">Analyze Image</span>
          <span className="qa-hint">Ctrl+O</span>
        </button>
        <button className="qa-btn" onClick={() => onAction("upload")}>
          <span className="qa-icon"><Upload size={28} strokeWidth={1.5} /></span>
          <span className="qa-label">Upload Image</span>
          <span className="qa-hint">Ctrl+U</span>
        </button>
      </div>
      <p className="ws-tip">Use the <kbd>File</kbd> menu or toolbar to begin. Press <kbd>F1</kbd> for help.</p>
    </div>
  );
}

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
const TABS = [
  { id: "summary",     label: "Summary",       Icon: HardDrive },
  { id: "timeline",    label: "Timeline",       Icon: Clock     },
  { id: "deleted",     label: "Deleted Files",  Icon: Eye       },
  { id: "persistence", label: "Persistence",    Icon: Shield    },
  { id: "tools",       label: "Tools",          Icon: Search    },
];

function EmptyState({ icon: Icon, message }) {
  return (
    <div className="empty-state">
      <Icon size={36} strokeWidth={1.2} className="empty-icon" />
      <p>{message}</p>
    </div>
  );
}

// ── Summary Tab ───────────────────────────────────────────────────────────────
function SummaryTab({ report }) {
  const { os_info, summary } = report;
  const totalHigh = summary?.total_high ?? 0;
  const threatLevel =
    totalHigh >= 10 ? { label: "CRITICAL", cls: "tl-critical" }
    : totalHigh >= 5  ? { label: "HIGH",     cls: "tl-high"     }
    : totalHigh >= 1  ? { label: "MEDIUM",   cls: "tl-medium"   }
    :                   { label: "CLEAN",    cls: "tl-low"      };
  const stats = [
    { label: "Tool Findings",        value: summary?.total_tools ?? 0,           danger: false },
    { label: "High-Risk Tools",      value: summary?.high_risk_tools ?? 0,       danger: true  },
    { label: "Timeline Events",      value: summary?.timeline_events ?? 0,       danger: false },
    { label: "High Timeline",        value: summary?.high_timeline ?? 0,         danger: true  },
    { label: "Deleted / Missing",    value: summary?.deleted_findings ?? 0,      danger: false },
    { label: "High Deleted",         value: summary?.high_deleted ?? 0,          danger: true  },
    { label: "Persistence Hits",     value: summary?.persistence_findings ?? 0,  danger: false },
    { label: "High Persistence",     value: summary?.high_persistence ?? 0,      danger: true  },
  ];
  return (
    <div className="tab-content">
      <div className="sum-top">
        <div className="sum-os-card">
          <div className="sum-os-label">Operating System</div>
          <div className="sum-os-name">{os_info?.name || "Unknown"}</div>
          <div className="sum-os-meta">
            {os_info?.id && <span className="tag">{os_info.id}</span>}
            {os_info?.variant_tags?.map((t) => <span key={t} className="tag tag-warn">{t}</span>)}
          </div>
          {os_info?.notes?.length > 0 && (
            <ul className="sum-os-notes">{os_info.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          )}
        </div>
        <div className={`sum-threat-card ${threatLevel.cls}`}>
          <div className="sum-threat-label">Threat Level</div>
          <div className="sum-threat-value">{threatLevel.label}</div>
          <div className="sum-threat-sub">{totalHigh} high-severity indicator{totalHigh !== 1 ? "s" : ""}</div>
        </div>
      </div>
      <div className="sum-stats-grid">
        {stats.map(({ label, value, danger }) => (
          <div key={label} className={`stat-card ${danger && value > 0 ? "stat-card-danger" : ""}`}>
            <div className="stat-value" style={{ color: danger && value > 0 ? SEV_COLOR.high : undefined }}>{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Timeline Tab ──────────────────────────────────────────────────────────────
const SRC_ICON = { "bash_history": Terminal, "auth.log": Lock, "secure": Lock, "syslog": Server, "messages": Server, "inode": Hash };

function TimelineTab({ events = [] }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  if (events.length === 0) return <EmptyState icon={Clock} message="No timeline events found." />;

  const counts = events.reduce((acc, e) => { acc[e.severity] = (acc[e.severity] || 0) + 1; return acc; }, {});
  const filtered = events.filter((e) => {
    if (filter !== "all" && e.severity !== filter) return false;
    if (search && !e.detail.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="tab-content">
      <div className="tl-toolbar">
        <div className="tl-filters">
          {["all", "high", "medium", "info"].map((f) => (
            <button key={f} className={`tl-filter-btn ${filter === f ? "active" : ""}`} onClick={() => setFilter(f)}>
              {f === "all" ? `All (${events.length})` : `${f} (${counts[f] || 0})`}
            </button>
          ))}
        </div>
        <input className="tl-search" placeholder="Search events…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <div className="tl-list">
        {filtered.length === 0 ? (
          <div className="tl-empty">No events match the current filter.</div>
        ) : filtered.map((ev, i) => {
          const Icon = SRC_ICON[ev.source] || Activity;
          return (
            <div key={i} className="tl-row" style={{ borderLeft: `3px solid ${SEV_COLOR[ev.severity] || "#6b7280"}`, background: SEV_BG[ev.severity] || "#fff" }}>
              <div className="tl-ts">{ev.timestamp}</div>
              <span className="tl-icon-wrap"><Icon size={13} style={{ color: SEV_COLOR[ev.severity] || "#6b7280" }} /></span>
              <div className="tl-body">
                <span className="tl-source">[{ev.source}]</span>
                <span className="tl-detail">{ev.detail}</span>
              </div>
              <SevBadge sev={ev.severity} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Deleted Files Tab ─────────────────────────────────────────────────────────
const DEL_TYPE_LABELS = { deleted_inode: "Deleted Inodes (TSK)", missing_expected: "Missing Expected Files", scan_error: "Scan Errors" };

function DeletedTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Eye} message="No deleted or missing files detected." />;
  const byType = findings.reduce((acc, f) => { const k = f.type || "other"; if (!acc[k]) acc[k] = []; acc[k].push(f); return acc; }, {});
  return (
    <div className="tab-content">
      {Object.entries(byType).map(([type, items]) => (
        <div key={type} className="del-group">
          <div className="del-group-header">
            <Eye size={13} />
            <span>{DEL_TYPE_LABELS[type] || type}</span>
            <span className="del-count">{items.length}</span>
          </div>
          <div className="del-list">
            {items.map((f, i) => (
              <div key={i} className="del-row" style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#6b7280"}` }}>
                <code className="del-path">{f.path}</code>
                <div className="del-detail">{f.detail}</div>
                <SevBadge sev={f.severity} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Persistence Tab ───────────────────────────────────────────────────────────
const PERSIST_ICONS  = { crontab: Clock, systemd_service: Server, shell_startup: Terminal, ssh_authorized_keys: Key };
const PERSIST_LABELS = { crontab: "Suspicious Crontab Entries", systemd_service: "Unknown Systemd Services", shell_startup: "Shell Startup Modifications", ssh_authorized_keys: "SSH Authorized Keys" };

function SnippetBlock({ snippet }) {
  const [open, setOpen] = useState(false);
  if (!snippet) return null;
  return (
    <div className="snippet-wrap">
      <button className="snippet-toggle" onClick={() => setOpen((v) => !v)}>
        {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />} {open ? "Hide" : "Show"} snippet
      </button>
      {open && <pre className="snippet-code">{snippet}</pre>}
    </div>
  );
}

function PersistenceTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Shield} message="No persistence mechanisms detected." />;
  const byCategory = findings.reduce((acc, f) => { const k = f.category || "other"; if (!acc[k]) acc[k] = []; acc[k].push(f); return acc; }, {});
  return (
    <div className="tab-content">
      {Object.entries(byCategory).map(([cat, items]) => {
        const Icon = PERSIST_ICONS[cat] || Shield;
        return (
          <div key={cat} className="persist-group">
            <div className="persist-group-header">
              <Icon size={13} />
              <span>{PERSIST_LABELS[cat] || cat}</span>
              <span className="del-count">{items.length}</span>
            </div>
            <div className="persist-list">
              {items.map((f, i) => (
                <div key={i} className="persist-row" style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#6b7280"}` }}>
                  <div className="persist-top">
                    <code className="del-path">{f.source}</code>
                    <SevBadge sev={f.severity} />
                  </div>
                  <div className="del-detail">{f.detail}</div>
                  <SnippetBlock snippet={f.snippet} />
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Tools Tab ─────────────────────────────────────────────────────────────────
const RISK_COLOR = { high: "#dc2626", medium: "#d97706", low: "#16a34a", "privacy-infrastructure": "#7c3aed", "dual-use": "#2563eb", infrastructure: "#0891b2" };
function ToolsTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Search} message="No notable tools detected." />;
  return (
    <div className="tab-content">
      <table className="rp-table findings">
        <thead><tr><th>Tool</th><th>Risk</th><th>Evidence</th></tr></thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i}>
              <td><strong>{f.tool}</strong></td>
              <td><span className="sev-badge" style={{ background: RISK_COLOR[f.risk] || "#6b7280" }}>{f.risk}</span></td>
              <td>
                <ul className="evidence-list">
                  {f.evidence?.map((ev, j) => <li key={j}><code>{ev}</code></li>)}
                </ul>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function WorkspaceDashboard({ report, onClear, onExport }) {
  const [tab, setTab] = useState("summary");
  const { summary } = report;
  const tabBadge = {
    timeline:    summary?.high_timeline    > 0 ? summary.high_timeline    : null,
    deleted:     summary?.high_deleted     > 0 ? summary.high_deleted     : null,
    persistence: summary?.high_persistence > 0 ? summary.high_persistence : null,
    tools:       summary?.high_risk_tools  > 0 ? summary.high_risk_tools  : null,
  };
  return (
    <div className="dashboard">
      <div className="dash-header">
        <div className="dash-header-left">
          <Microscope size={18} strokeWidth={1.6} className="dash-logo" />
          <span className="dash-title">Analysis Report</span>
          <span className="dash-os">{report.os_info?.name || "Unknown OS"}</span>
          {(summary?.total_high ?? 0) > 0 && (
            <span className="dash-alert">
              <AlertTriangle size={12} />{summary.total_high} high-severity indicator{summary.total_high !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        <div className="dash-header-right">
          <button className="btn-secondary btn-sm" onClick={onExport}><FolderOpen size={13} /> Export JSON</button>
          <button className="btn-secondary btn-sm" onClick={onClear}><Trash2 size={13} /> Clear</button>
        </div>
      </div>
      <div className="dash-tabbar">
        {TABS.map(({ id, label, Icon }) => (
          <button key={id} className={`dash-tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <Icon size={13} />{label}
            {tabBadge[id] != null && <span className="tab-badge">{tabBadge[id]}</span>}
          </button>
        ))}
      </div>
      <div className="dash-body">
        {tab === "summary"     && <SummaryTab     report={report} />}
        {tab === "timeline"    && <TimelineTab    events={report.timeline} />}
        {tab === "deleted"     && <DeletedTab     findings={report.deleted} />}
        {tab === "persistence" && <PersistenceTab findings={report.persistence} />}
        {tab === "tools"       && <ToolsTab       findings={report.findings} />}
      </div>
    </div>
  );
}

// ─── ROOT APP ─────────────────────────────────────────────────────────────────
export default function App() {
  const [dialog,    setDialog]    = useState(null);
  const [report,    setReport]    = useState(null);
  const [status,    setStatus]    = useState("Ready");
  const [toolbar,   setToolbar]   = useState(true);
  const [statbar,   setStatbar]   = useState(true);

  function closeDialog() { setDialog(null); }

  function handleResult(r) {
    setReport(r);
    const hi = r.summary?.total_high ?? 0;
    setStatus(
      `Analysis complete — ${r.findings?.length ?? 0} tool(s), ` +
      `${r.summary?.timeline_events ?? 0} timeline event(s), ` +
      `${hi} high-severity indicator${hi !== 1 ? "s" : ""}`
    );
  }

  function downloadJSON(r) {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "forensic_report.json"; a.click();
    URL.revokeObjectURL(url);
  }

  function handleAction(key) {
    switch (key) {
      case "analyze":   return setDialog("analyze");
      case "upload":    return setDialog("upload");
      case "export":    return report ? downloadJSON(report) : setStatus("No report to export");
      case "clear":     setReport(null); return setStatus("Analysis cleared");
      case "settings":  return setDialog("settings");
      case "shortcuts": return setDialog("shortcuts");
      case "about":     return setDialog("about");
      case "statusbar": return setStatbar((v) => !v);
      case "toolbar":   return setToolbar((v) => !v);
      case "exit":      return setStatus("Close the browser tab to exit.");
      default:          return;
    }
  }

  useEffect(() => {
    function onKey(e) {
      if (e.ctrlKey && e.key === "o") { e.preventDefault(); handleAction("analyze"); }
      if (e.ctrlKey && e.key === "u") { e.preventDefault(); handleAction("upload"); }
      if (e.ctrlKey && e.key === ",") { e.preventDefault(); handleAction("settings"); }
      if (e.key === "F1")             { e.preventDefault(); handleAction("about"); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <div className="app-shell">
      <div className="titlebar">
        <Microscope size={16} strokeWidth={1.8} className="title-icon" />
        <span className="title-name">OS Forensics</span>
        <span className="title-build">Advanced Forensic Analysis</span>
      </div>
      <MenuBar onAction={handleAction} />
      <Toolbar visible={toolbar} onAction={handleAction} />
      <div className="workspace">
        {report
          ? <WorkspaceDashboard report={report} onClear={() => handleAction("clear")} onExport={() => downloadJSON(report)} />
          : <WorkspaceHome onAction={handleAction} />}
      </div>
      <StatusBar visible={statbar} status={status} report={report} />
      {dialog === "analyze"   && <AnalyzeDialog   onClose={closeDialog} onResult={handleResult} />}
      {dialog === "upload"    && <UploadDialog    onClose={closeDialog} onResult={handleResult} />}
      {dialog === "settings"  && <SettingsDialog  onClose={closeDialog} />}
      {dialog === "shortcuts" && <ShortcutsDialog onClose={closeDialog} />}
      {dialog === "about"     && <AboutDialog     onClose={closeDialog} />}
    </div>
  );
}
