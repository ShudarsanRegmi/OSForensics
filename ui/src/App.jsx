import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Search, Upload, Trash2, Settings, Microscope,
  X, FolderOpen, AlertTriangle, CheckCircle, HardDrive, Activity,
  Clock, Shield, Eye, ChevronDown, ChevronRight, Hash, Terminal,
  Lock, Server, Key, Folder, FolderOpen as FolderOpenIcon, FileText,
  Wifi, Package, List, Database, Cpu, Box, Globe, Users, ChevronUp,
  File, Code, RefreshCw, Info, LayoutPanelLeft, BarChart2, Home,
} from "lucide-react";

// ─── API ──────────────────────────────────────────────────────────────────────
const API = "http://127.0.0.1:8000";

const post = async (url, body) => {
  const res = await fetch(`${API}${url}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
};

const get = async (url) => {
  const res = await fetch(`${API}${url}`);
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
};

const apiAnalyze  = (path)       => post("/analyze",        { image_path: path });
const apiUpload   = (file) => {
  const fd = new FormData();
  fd.append("file", file, file.name);
  return fetch(`${API}/upload`, { method: "POST", body: fd })
    .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(new Error(t))));
};
const apiBrowse   = (img, path)  => post("/explore/browse", { image_path: img, path });
const apiStat     = (img, path)  => post("/explore/stat",   { image_path: img, path });
const apiRead     = (img, path)  => post("/explore/read",   { image_path: img, path });
const apiTree     = ()           => get("/explore/tree");

// ─── Severity / icon helpers ──────────────────────────────────────────────────
const SEV_COLOR = { high: "#dc2626", medium: "#d97706", low: "#16a34a", info: "#2563eb" };
const SEV_BG    = { high: "#fff1f0", medium: "#fffbeb", low: "#f0fdf4", info: "#eff6ff" };

function SevBadge({ sev }) {
  const s = (sev || "info").toLowerCase();
  return <span className="sev-badge" style={{ background: SEV_COLOR[s] || "#6b7280" }}>{s}</span>;
}

const ICON_MAP = {
  HardDrive, Terminal, Lock, Server, Key, Folder, FileText, Wifi, Package, List,
  Database, Cpu, Box, Globe, Users, Clock, Shield, Activity, AlertTriangle, File,
  Hash, Eye, Search, FolderOpen: FolderOpenIcon,
};
function NodeIcon({ name, size = 14, style }) {
  const C = ICON_MAP[name] || File;
  return <C size={size} style={style} />;
}

// ─── MODAL ────────────────────────────────────────────────────────────────────
function Modal({ title, onClose, children, width = 540 }) {
  const ref = useRef(null);
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const drag = useRef({ d: false, ox: 0, oy: 0 });
  const [pos, setPos] = useState(null);
  const onMD = (e) => { const r = ref.current.getBoundingClientRect(); drag.current = { d: true, ox: e.clientX - r.left, oy: e.clientY - r.top }; };
  const onMM = useCallback((e) => { if (!drag.current.d) return; setPos({ x: e.clientX - drag.current.ox, y: e.clientY - drag.current.oy }); }, []);
  const onMU = useCallback(() => { drag.current.d = false; }, []);
  useEffect(() => {
    window.addEventListener("mousemove", onMM);
    window.addEventListener("mouseup", onMU);
    return () => { window.removeEventListener("mousemove", onMM); window.removeEventListener("mouseup", onMU); };
  }, [onMM, onMU]);

  const style = pos ? { position: "fixed", left: pos.x, top: pos.y, transform: "none", width } : { width };
  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal-window" ref={ref} style={style}>
        <div className="modal-titlebar" onMouseDown={onMD}>
          <span className="modal-title">{title}</span>
          <button className="modal-close" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

// ─── Dialogs ──────────────────────────────────────────────────────────────────
function AnalyzeDialog({ onClose, onResult }) {
  const [path, setPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  async function run() {
    if (!path.trim()) return;
    setLoading(true); setErr(null);
    try { onResult(await apiAnalyze(path.trim()), path.trim()); onClose(); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }
  return (
    <Modal title="Analyze — Open Image or Mountpoint" onClose={onClose} width={600}>
      <div className="dlg-field">
        <label>Path to image / mountpoint</label>
        <input autoFocus value={path} onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="/mnt/snapshot  or  /path/to/disk.img  or  /" />
        <div className="dlg-hint">Use a mounted directory path for non-pytsk3 environments.</div>
      </div>
      {err && <div className="dlg-error">{err}</div>}
      <div className="dlg-actions">
        <button className="btn-primary" onClick={run} disabled={loading || !path.trim()}>
          <Search size={14} />{loading ? "Analyzing…" : "Analyze"}
        </button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

function UploadDialog({ onClose, onResult }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  async function run() {
    if (!file) return;
    setLoading(true); setErr(null);
    try { onResult(await apiUpload(file), file.name); onClose(); }
    catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  }
  return (
    <Modal title="Upload Image for Analysis" onClose={onClose} width={520}>
      <div className="dlg-field">
        <label>Select disk image file</label>
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <div className="dlg-hint">File is uploaded, analyzed, then deleted automatically.</div>
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

function AboutDialog({ onClose }) {
  return (
    <Modal title="About OS Forensics" onClose={onClose} width={420}>
      <div className="about-body">
        <div className="about-icon"><Microscope size={52} strokeWidth={1.4} /></div>
        <h2>OS Forensics</h2>
        <p className="about-ver">build 0.3.0 — Explorative Edition</p>
        <p>Advanced forensic detection and artifact exploration for Linux-based environments. Autopsy-style navigation with full inode metadata, file viewer, and analysis reports.</p>
        <p className="about-stack">Backend: Python · FastAPI · pytsk3<br />Frontend: React · Vite</p>
      </div>
      <div className="dlg-actions"><button className="btn-primary" onClick={onClose}>OK</button></div>
    </Modal>
  );
}

function SettingsDialog({ onClose }) {
  return (
    <Modal title="Preferences" onClose={onClose} width={460}>
      <div className="dlg-field">
        <label>API Server URL</label>
        <input defaultValue="http://127.0.0.1:8000" disabled />
        <div className="dlg-hint">Configurable in a future release.</div>
      </div>
      <div className="dlg-actions">
        <button className="btn-primary" onClick={onClose}>OK</button>
        <button className="btn-secondary" onClick={onClose}>Cancel</button>
      </div>
    </Modal>
  );
}

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
      { label: "Analyze Image / Mountpoint…", key: "analyze", shortcut: "Ctrl+O" },
      { label: "Upload Image for Analysis…",  key: "upload",  shortcut: "Ctrl+U" },
      { type: "sep" },
      { label: "Export Report JSON…",         key: "export" },
      { type: "sep" },
      { label: "Clear Analysis",              key: "clear" },
    ],
    View: [
      { label: "Show Explorer",   key: "view_explorer" },
      { label: "Show Report",     key: "view_report" },
      { type: "sep" },
      { label: "Toggle Toolbar",  key: "toolbar" },
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
          <button className="mb-label" onClick={() => setOpen(open === name ? null : name)}
            onMouseEnter={() => open && setOpen(name)}>
            {name}
          </button>
          {open === name && (
            <ul className="mb-dropdown">
              {items.map((item, i) =>
                item.type === "sep" ? <li key={i} className="mb-sep" /> : (
                  <li key={i} className="mb-option" onClick={() => pick(item.key)}>
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
function Toolbar({ visible, onAction }) {
  if (!visible) return null;
  const btns = [
    { Icon: Search,         label: "Analyze",  key: "analyze",        title: "Analyze (Ctrl+O)" },
    { Icon: Upload,         label: "Upload",   key: "upload",         title: "Upload (Ctrl+U)" },
    { type: "sep" },
    { Icon: LayoutPanelLeft,label: "Explorer", key: "view_explorer",  title: "Explorer view" },
    { Icon: BarChart2,      label: "Report",   key: "view_report",    title: "Report view" },
    { type: "sep" },
    { Icon: Trash2,         label: "Clear",    key: "clear",          title: "Clear analysis" },
    { type: "sep" },
    { Icon: Settings,       label: "Prefs",    key: "settings",       title: "Preferences" },
  ];
  return (
    <div className="toolbar">
      {btns.map((b, i) =>
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

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLORER SECTION
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Artifact Tree Node (left sidebar) ────────────────────────────────────────
function TreeNode({ node, depth = 0, onSelect, selectedId, expandedIds, onToggle }) {
  const hasChildren = node.children?.length > 0;
  const isExpanded = expandedIds.has(node.id);
  const isSelected = selectedId === node.id;
  const indent = depth * 14;

  return (
    <div>
      <div
        className={`tree-node ${isSelected ? "selected" : ""}`}
        style={{ paddingLeft: 8 + indent }}
        onClick={() => { onSelect(node); if (hasChildren) onToggle(node.id); }}
      >
        <span className="tree-expand-icon">
          {hasChildren
            ? (isExpanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />)
            : <span style={{ display: "inline-block", width: 11 }} />}
        </span>
        <span className="tree-node-icon">
          <NodeIcon
            name={isExpanded && hasChildren ? "FolderOpen" : node.icon}
            size={13}
            style={{ color: isSelected ? "#fff" : undefined }}
          />
        </span>
        <span className="tree-node-label">{node.label}</span>
      </div>
      {hasChildren && isExpanded && node.children.map((child) => (
        <TreeNode key={child.id} node={child} depth={depth + 1}
          onSelect={onSelect} selectedId={selectedId}
          expandedIds={expandedIds} onToggle={onToggle} />
      ))}
    </div>
  );
}

// ─── File List (middle pane) ──────────────────────────────────────────────────
function FileTypeIcon({ type, name }) {
  if (type === "directory") return <Folder size={13} style={{ color: "#f59e0b" }} />;
  const ext = name?.split(".").pop()?.toLowerCase();
  if (["log", "txt", "conf", "cfg", "ini", "md"].includes(ext)) return <FileText size={13} style={{ color: "#6366f1" }} />;
  if (["sh", "bash", "py", "rb", "pl"].includes(ext))            return <Code     size={13} style={{ color: "#10b981" }} />;
  if (["service", "socket", "timer"].includes(ext))              return <Server   size={13} style={{ color: "#8b5cf6" }} />;
  return <File size={13} style={{ color: "#9ca3af" }} />;
}

function FileList({ entries, onOpen, selectedPath, loading, path }) {
  if (loading) return <div className="pane-loading"><RefreshCw size={16} className="spin" />Loading…</div>;
  if (!entries) return <div className="pane-empty"><Folder size={32} /><p>Select an item in the tree to browse.</p></div>;
  if (entries.length === 0) return <div className="pane-empty"><Folder size={32} /><p>Directory is empty.</p></div>;

  return (
    <div className="file-list-wrap">
      <div className="file-list-header">
        <span className="fl-col-name">Name</span>
        <span className="fl-col-size">Size</span>
        <span className="fl-col-mtime">Modified</span>
        <span className="fl-col-mode">Permissions</span>
        <span className="fl-col-uid">UID</span>
      </div>
      <div className="file-list-body">
        {entries.map((e) => (
          <div
            key={e.path}
            className={`fl-row ${selectedPath === e.path ? "selected" : ""} ${e.type === "directory" ? "fl-dir" : ""}`}
            onClick={() => onOpen(e)}
            onDoubleClick={() => e.type === "directory" && onOpen(e, true)}
          >
            <span className="fl-col-name">
              <FileTypeIcon type={e.type} name={e.name} />
              <span className="fl-name-text">{e.name}</span>
              {e.symlink_target && <span className="fl-symlink"> → {e.symlink_target}</span>}
            </span>
            <span className="fl-col-size">{e.type === "directory" ? "—" : (e.size_human || "?")}</span>
            <span className="fl-col-mtime">{e.mtime || "—"}</span>
            <span className="fl-col-mode"><code className="mono-small">{e.mode || "—"}</code></span>
            <span className="fl-col-uid">{e.uid ?? "—"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Metadata / Content Viewer (right pane) ──────────────────────────────────
function MetaRow({ label, value, mono }) {
  if (value === undefined || value === null) return null;
  return (
    <tr>
      <td className="meta-key">{label}</td>
      <td className="meta-val">{mono ? <code className="mono-small">{String(value)}</code> : String(value)}</td>
    </tr>
  );
}

function ContentPane({ item, imgPath }) {
  const [tab, setTab] = useState("meta");
  const [content, setContent] = useState(null);
  const [loadingContent, setLoadingContent] = useState(false);
  const [contentErr, setContentErr] = useState(null);

  // Reset when item changes
  useEffect(() => {
    setTab("meta");
    setContent(null);
    setContentErr(null);
  }, [item?.path]);

  async function loadContent() {
    if (!item || !imgPath) return;
    setLoadingContent(true); setContentErr(null);
    try { setContent(await apiRead(imgPath, item.path)); }
    catch (e) { setContentErr(String(e)); }
    finally { setLoadingContent(false); }
  }

  useEffect(() => {
    if (tab === "content" && !content && item && !item.is_dir && imgPath) {
      loadContent();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, item?.path]);

  if (!item) {
    return (
      <div className="content-pane-empty">
        <Info size={32} style={{ opacity: .3 }} />
        <p>Select a file to view metadata and content.</p>
      </div>
    );
  }

  const suid_flags = [];
  if (item.is_suid)   suid_flags.push("SUID");
  if (item.is_sgid)   suid_flags.push("SGID");
  if (item.is_sticky) suid_flags.push("Sticky");

  return (
    <div className="content-pane">
      <div className="content-pane-header">
        <FileTypeIcon type={item.type} name={item.name} />
        <span className="content-pane-name" title={item.path}>{item.name || item.path}</span>
        <span className="content-pane-path" title={item.path}>{item.path}</span>
        {suid_flags.length > 0 && suid_flags.map(f => (
          <span key={f} className="sev-badge" style={{ background: "#dc2626", fontSize: 9 }}>{f}</span>
        ))}
      </div>
      <div className="content-pane-tabs">
        <button className={`cp-tab ${tab === "meta" ? "active" : ""}`} onClick={() => setTab("meta")}>
          <Info size={11} /> Metadata
        </button>
        {!item.is_dir && (
          <button className={`cp-tab ${tab === "content" ? "active" : ""}`} onClick={() => setTab("content")}>
            <FileText size={11} /> Content
          </button>
        )}
      </div>
      <div className="content-pane-body">
        {tab === "meta" && (
          <table className="meta-table">
            <tbody>
              <MetaRow label="Path"        value={item.path} mono />
              <MetaRow label="Type"        value={item.type} />
              <MetaRow label="Size"        value={item.size_human ? `${item.size_human} (${item.size?.toLocaleString()} bytes)` : item.size} />
              <MetaRow label="Permissions" value={item.mode} mono />
              <MetaRow label="Mode (octal)"value={item.mode_octal} mono />
              <MetaRow label="Owner (UID)" value={item.uid} />
              <MetaRow label="Group (GID)" value={item.gid} />
              <MetaRow label="Inode"       value={item.inode} />
              <MetaRow label="Hard Links"  value={item.nlinks} />
              <MetaRow label="Modified"    value={item.mtime} />
              <MetaRow label="Accessed"    value={item.atime} />
              <MetaRow label="Changed"     value={item.ctime} />
              {item.symlink_target && <MetaRow label="Symlink →" value={item.symlink_target} mono />}
              {suid_flags.length > 0 && <MetaRow label="Special Bits" value={suid_flags.join(", ")} />}
            </tbody>
          </table>
        )}
        {tab === "content" && (
          <div className="file-content-wrap">
            {loadingContent && <div className="pane-loading"><RefreshCw size={14} className="spin" />Reading file…</div>}
            {contentErr && <div className="dlg-error">{contentErr}</div>}
            {content && !loadingContent && (
              <>
                {content.truncated && (
                  <div className="content-truncated-warn">
                    <AlertTriangle size={12} /> Showing first {content.size_human || ""} — file truncated at 200 KB
                  </div>
                )}
                {content.error && <div className="dlg-error">{content.error}</div>}
                {content.content != null && (
                  <pre className={`file-content-pre ${content.encoding === "hex" ? "hex-view" : ""}`}>
                    {content.content}
                  </pre>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Full Explorer (3-pane) ───────────────────────────────────────────────────
function Explorer({ imgPath }) {
  const [tree, setTree]             = useState(null);
  const [treeErr, setTreeErr]       = useState(null);
  const [expandedIds, setExpanded]  = useState(new Set(["os", "logs", "shell_history"]));
  const [selectedNode, setSelNode]  = useState(null);
  const [browseEntries, setBrowse]  = useState(null);
  const [browseLoading, setBrowseL] = useState(false);
  const [browsePath, setBrowsePath] = useState(null);
  const [selectedFile, setSelFile]  = useState(null);
  const [navStack, setNavStack]     = useState([]);

  // Load tree once
  useEffect(() => {
    apiTree()
      .then(d => setTree(d.tree))
      .catch(e => setTreeErr(String(e)));
  }, []);

  function toggleExpand(id) {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function selectNode(node) {
    setSelNode(node);
    setSelFile(null);

    if (!node.path) return; // grouping node, no path

    setBrowseL(true); setBrowse(null); setBrowsePath(node.path);
    setNavStack([node.path]);

    // Determine if it's a dir or file
    try {
      const meta = await apiStat(imgPath, node.path);
      if (meta.is_dir) {
        const dir = await apiBrowse(imgPath, node.path);
        setBrowse(dir.children);
        setSelFile(meta);
      } else {
        // Leaf file: show only the file itself in file list so user can click
        setBrowse([{ name: node.path.split("/").pop(), path: node.path, type: meta.type, ...meta }]);
        setSelFile(meta);
      }
    } catch (e) {
      setBrowse([]);
    } finally {
      setBrowseL(false);
    }
  }

  async function openEntry(entry, navigate = false) {
    setSelFile(null);

    // Fetch stat
    let meta;
    try {
      meta = await apiStat(imgPath, entry.path);
    } catch (e) {
      meta = entry;
    }

    setSelFile({ ...entry, ...meta });

    if (meta.is_dir && navigate) {
      // Navigate into directory
      setBrowseL(true);
      setBrowsePath(entry.path);
      setNavStack(prev => [...prev, entry.path]);
      try {
        const dir = await apiBrowse(imgPath, entry.path);
        setBrowse(dir.children);
      } catch (e) {
        setBrowse([]);
      } finally {
        setBrowseL(false);
      }
    }
  }

  async function navUp() {
    if (navStack.length <= 1) return;
    const newStack = navStack.slice(0, -1);
    const parentPath = newStack[newStack.length - 1];
    setNavStack(newStack);
    setBrowsePath(parentPath);
    setBrowseL(true);
    try {
      const dir = await apiBrowse(imgPath, parentPath);
      setBrowse(dir.children);
    } catch (e) { setBrowse([]); }
    finally { setBrowseL(false); }
  }

  return (
    <div className="explorer-shell">
      {/* Left: tree */}
      <div className="explorer-tree-pane">
        <div className="explorer-pane-header">
          <FolderOpenIcon size={12} /> Artifact Tree
        </div>
        <div className="explorer-tree-scroll">
          {treeErr && <div className="dlg-error" style={{ margin: 8, fontSize: 11 }}>{treeErr}</div>}
          {!tree && !treeErr && <div className="pane-loading"><RefreshCw size={12} className="spin" />Loading…</div>}
          {tree?.map(node => (
            <TreeNode key={node.id} node={node}
              onSelect={selectNode} selectedId={selectedNode?.id}
              expandedIds={expandedIds} onToggle={toggleExpand} />
          ))}
        </div>
      </div>

      {/* Middle: file list */}
      <div className="explorer-files-pane">
        <div className="explorer-pane-header">
          <Folder size={12} />
          <span className="explorer-path-label" title={browsePath}>{browsePath || "—"}</span>
          {navStack.length > 1 && (
            <button className="nav-up-btn" onClick={navUp} title="Up one level">
              <ChevronUp size={11} /> Up
            </button>
          )}
        </div>
        <FileList
          entries={browseEntries}
          loading={browseLoading}
          path={browsePath}
          selectedPath={selectedFile?.path}
          onOpen={openEntry}
        />
      </div>

      {/* Right: metadata + content */}
      <div className="explorer-meta-pane">
        <div className="explorer-pane-header">
          <Info size={12} /> Properties
        </div>
        <ContentPane item={selectedFile} imgPath={imgPath} />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT / ANALYSIS TABS
// ═══════════════════════════════════════════════════════════════════════════════

const SRC_ICON = { bash_history: Terminal, "auth.log": Lock, secure: Lock, syslog: Server, messages: Server, inode: Hash };
const PERSIST_ICONS  = { crontab: Clock, systemd_service: Server, shell_startup: Terminal, ssh_authorized_keys: Key };
const PERSIST_LABELS = { crontab: "Suspicious Crontab Entries", systemd_service: "Unknown Systemd Services", shell_startup: "Shell Startup Modifications", ssh_authorized_keys: "SSH Authorized Keys" };
const DEL_TYPE_LABELS = { deleted_inode: "Deleted Inodes (TSK)", missing_expected: "Missing Expected Files", scan_error: "Scan Errors" };

function EmptyState({ icon: Icon, message }) {
  return <div className="empty-state"><Icon size={36} strokeWidth={1.2} className="empty-icon" /><p>{message}</p></div>;
}

function SnippetBlock({ snippet }) {
  const [open, setOpen] = useState(false);
  if (!snippet) return null;
  return (
    <div className="snippet-wrap">
      <button className="snippet-toggle" onClick={() => setOpen(v => !v)}>
        {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />} {open ? "Hide" : "Show"} snippet
      </button>
      {open && <pre className="snippet-code">{snippet}</pre>}
    </div>
  );
}

function SummaryTab({ report }) {
  const { os_info, summary } = report;
  const totalHigh = summary?.total_high ?? 0;
  const threatLevel =
    totalHigh >= 10 ? { label: "CRITICAL", cls: "tl-critical" }
    : totalHigh >= 5  ? { label: "HIGH",     cls: "tl-high"     }
    : totalHigh >= 1  ? { label: "MEDIUM",   cls: "tl-medium"   }
    :                   { label: "CLEAN",    cls: "tl-low"      };
  const stats = [
    { label: "Tool Findings",       value: summary?.total_tools ?? 0,          danger: false },
    { label: "High-Risk Tools",     value: summary?.high_risk_tools ?? 0,      danger: true  },
    { label: "Timeline Events",     value: summary?.timeline_events ?? 0,      danger: false },
    { label: "High Timeline",       value: summary?.high_timeline ?? 0,        danger: true  },
    { label: "Deleted / Missing",   value: summary?.deleted_findings ?? 0,     danger: false },
    { label: "High Deleted",        value: summary?.high_deleted ?? 0,         danger: true  },
    { label: "Persistence Hits",    value: summary?.persistence_findings ?? 0, danger: false },
    { label: "High Persistence",    value: summary?.high_persistence ?? 0,     danger: true  },
  ];
  return (
    <div className="tab-content">
      <div className="sum-top">
        <div className="sum-os-card">
          <div className="sum-os-label">Operating System</div>
          <div className="sum-os-name">{os_info?.name || "Unknown"}</div>
          <div className="sum-os-meta">
            {os_info?.id && <span className="tag">{os_info.id}</span>}
            {os_info?.variant_tags?.map(t => <span key={t} className="tag tag-warn">{t}</span>)}
          </div>
          {os_info?.notes?.length > 0 && <ul className="sum-os-notes">{os_info.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
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

function TimelineTab({ events = [] }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  if (events.length === 0) return <EmptyState icon={Clock} message="No timeline events found." />;
  const counts = events.reduce((acc, e) => { acc[e.severity] = (acc[e.severity] || 0) + 1; return acc; }, {});
  const filtered = events.filter(e => {
    if (filter !== "all" && e.severity !== filter) return false;
    if (search && !e.detail.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });
  return (
    <div className="tab-content">
      <div className="tl-toolbar">
        <div className="tl-filters">
          {["all", "high", "medium", "info"].map(f => (
            <button key={f} className={`tl-filter-btn ${filter === f ? "active" : ""}`} onClick={() => setFilter(f)}>
              {f === "all" ? `All (${events.length})` : `${f} (${counts[f] || 0})`}
            </button>
          ))}
        </div>
        <input className="tl-search" placeholder="Search events…" value={search} onChange={e => setSearch(e.target.value)} />
      </div>
      <div className="tl-list">
        {filtered.length === 0
          ? <div className="tl-empty">No events match the current filter.</div>
          : filtered.map((ev, i) => {
              const Icon = SRC_ICON[ev.source] || Activity;
              return (
                <div key={i} className="tl-row" style={{ borderLeft: `3px solid ${SEV_COLOR[ev.severity] || "#6b7280"}`, background: SEV_BG[ev.severity] || "#fff" }}>
                  <div className="tl-ts">{ev.timestamp}</div>
                  <span className="tl-icon-wrap"><Icon size={13} style={{ color: SEV_COLOR[ev.severity] || "#6b7280" }} /></span>
                  <div className="tl-body"><span className="tl-source">[{ev.source}]</span><span className="tl-detail">{ev.detail}</span></div>
                  <SevBadge sev={ev.severity} />
                </div>
              );
            })}
      </div>
    </div>
  );
}

function DeletedTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Eye} message="No deleted or missing files detected." />;
  const byType = findings.reduce((acc, f) => { const k = f.type || "other"; if (!acc[k]) acc[k] = []; acc[k].push(f); return acc; }, {});
  return (
    <div className="tab-content">
      {Object.entries(byType).map(([type, items]) => (
        <div key={type} className="del-group">
          <div className="del-group-header"><Eye size={13} /><span>{DEL_TYPE_LABELS[type] || type}</span><span className="del-count">{items.length}</span></div>
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

function PersistenceTab({ findings = [] }) {
  if (findings.length === 0) return <EmptyState icon={Shield} message="No persistence mechanisms detected." />;
  const byCategory = findings.reduce((acc, f) => { const k = f.category || "other"; if (!acc[k]) acc[k] = []; acc[k].push(f); return acc; }, {});
  return (
    <div className="tab-content">
      {Object.entries(byCategory).map(([cat, items]) => {
        const Icon = PERSIST_ICONS[cat] || Shield;
        return (
          <div key={cat} className="persist-group">
            <div className="persist-group-header"><Icon size={13} /><span>{PERSIST_LABELS[cat] || cat}</span><span className="del-count">{items.length}</span></div>
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
              <td><ul className="evidence-list">{f.evidence?.map((ev, j) => <li key={j}><code>{ev}</code></li>)}</ul></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Dashboard (Report panel) ─────────────────────────────────────────────────
const REPORT_TABS = [
  { id: "summary",     label: "Summary",      Icon: HardDrive },
  { id: "timeline",    label: "Timeline",     Icon: Clock     },
  { id: "deleted",     label: "Deleted",      Icon: Eye       },
  { id: "persistence", label: "Persistence",  Icon: Shield    },
  { id: "tools",       label: "Tools",        Icon: Search    },
];

function ReportPanel({ report, onClear, onExport }) {
  const [tab, setTab] = useState("summary");
  const { summary } = report;
  const badge = {
    timeline:    summary?.high_timeline    > 0 ? summary.high_timeline    : null,
    deleted:     summary?.high_deleted     > 0 ? summary.high_deleted     : null,
    persistence: summary?.high_persistence > 0 ? summary.high_persistence : null,
    tools:       summary?.high_risk_tools  > 0 ? summary.high_risk_tools  : null,
  };
  return (
    <div className="report-panel">
      <div className="report-panel-header">
        <div className="report-panel-header-left">
          <Microscope size={15} strokeWidth={1.6} style={{ color: "#2563eb" }} />
          <span className="report-panel-title">Analysis Report</span>
          <span className="dash-os">{report.os_info?.name || "Unknown OS"}</span>
          {(summary?.total_high ?? 0) > 0 && (
            <span className="dash-alert"><AlertTriangle size={11} />{summary.total_high} high</span>
          )}
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn-secondary btn-sm" onClick={onExport}><FolderOpen size={12} /> Export</button>
          <button className="btn-secondary btn-sm" onClick={onClear}><Trash2 size={12} /> Clear</button>
        </div>
      </div>
      <div className="report-tabbar">
        {REPORT_TABS.map(({ id, label, Icon }) => (
          <button key={id} className={`dash-tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <Icon size={12} />{label}
            {badge[id] != null && <span className="tab-badge">{badge[id]}</span>}
          </button>
        ))}
      </div>
      <div className="report-panel-body">
        {tab === "summary"     && <SummaryTab     report={report} />}
        {tab === "timeline"    && <TimelineTab    events={report.timeline} />}
        {tab === "deleted"     && <DeletedTab     findings={report.deleted} />}
        {tab === "persistence" && <PersistenceTab findings={report.persistence} />}
        {tab === "tools"       && <ToolsTab       findings={report.findings} />}
      </div>
    </div>
  );
}

// ─── WORKSPACE HOME ───────────────────────────────────────────────────────────
function WorkspaceHome({ onAction }) {
  return (
    <div className="ws-home">
      <div className="ws-logo"><Microscope size={64} strokeWidth={1.2} className="ws-logo-icon" /></div>
      <h1 className="ws-title">OS Forensics</h1>
      <p className="ws-sub">Advanced forensic detection &amp; artifact exploration for Linux-based environments</p>
      <div className="ws-feature-badges">
        <span className="feat-badge"><Clock size={12} /> Timeline Engine</span>
        <span className="feat-badge"><Eye size={12} /> Deleted Detection</span>
        <span className="feat-badge"><Shield size={12} /> Persistence Scanner</span>
        <span className="feat-badge"><FolderOpenIcon size={12} /> Artifact Explorer</span>
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

// ═══════════════════════════════════════════════════════════════════════════════
// ROOT APP
// ═══════════════════════════════════════════════════════════════════════════════
// ─── ACTIVITY BAR ─────────────────────────────────────────────────────────────
function ActivityBar({ view, onView, hasExplorer, hasReport }) {
  const items = [
    { id: "home",     Icon: Home,           label: "Home",    always: true },
    { id: "explorer", Icon: LayoutPanelLeft, label: "Explorer",disabled: !hasExplorer },
    { id: "report",   Icon: BarChart2,       label: "Report",  disabled: !hasReport },
  ];
  return (
    <div className="activity-bar">
      {items.map(({ id, Icon, label, always, disabled }) => (
        <button
          key={id}
          className={`act-btn ${view === id ? "active" : ""}`}
          title={label}
          disabled={!always && disabled}
          onClick={() => !disabled && onView(id)}
        >
          <Icon size={20} strokeWidth={1.6} />
          <span className="act-label">{label}</span>
        </button>
      ))}
    </div>
  );
}

export default function App() {
  const [dialog,  setDialog]  = useState(null);
  const [report,  setReport]  = useState(null);
  const [imgPath, setImgPath] = useState(null);
  const [status,  setStatus]  = useState("Ready");
  const [toolbar, setToolbar] = useState(true);
  const [statbar, setStatbar] = useState(true);
  // "home" | "explorer" | "report"
  const [view,    setView]    = useState("home");

  function closeDialog() { setDialog(null); }

  function handleResult(r, path) {
    setReport(r);
    setImgPath(path || imgPath);
    setView("report");
    const hi = r.summary?.total_high ?? 0;
    setStatus(
      `Analysis complete — ${r.findings?.length ?? 0} tool(s), ` +
      `${r.summary?.timeline_events ?? 0} timeline event(s), ` +
      `${hi} high-severity indicator${hi !== 1 ? "s" : ""}`
    );
  }

  function downloadJSON(r) {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "forensic_report.json"; a.click();
  }

  function handleAction(key) {
    switch (key) {
      case "analyze":      return setDialog("analyze");
      case "upload":       return setDialog("upload");
      case "export":       return report ? downloadJSON(report) : setStatus("No report to export");
      case "clear":        setReport(null); setImgPath(null); setView("home"); return setStatus("Analysis cleared");
      case "settings":     return setDialog("settings");
      case "shortcuts":    return setDialog("shortcuts");
      case "about":        return setDialog("about");
      case "statusbar":    return setStatbar(v => !v);
      case "toolbar":      return setToolbar(v => !v);
      case "view_explorer": return imgPath  ? setView("explorer") : setStatus("Open an image first");
      case "view_report":   return report   ? setView("report")   : setStatus("Run analysis first");
      // legacy keys still wired in menus
      case "explorer":     return imgPath  ? setView("explorer") : setStatus("Open an image first");
      case "report_panel": return report   ? setView("report")   : setStatus("Run analysis first");
      default:             return;
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
        {imgPath && <span className="title-path">{imgPath}</span>}
      </div>
      <MenuBar onAction={handleAction} />
      <Toolbar visible={toolbar} onAction={handleAction} />

      <div className="workspace">
        {/* Activity bar — always visible once anything is loaded */}
        {(report || imgPath) && (
          <ActivityBar
            view={view}
            onView={setView}
            hasExplorer={!!imgPath}
            hasReport={!!report}
          />
        )}

        {/* Main content — single full-width panel at a time */}
        <div className="main-content">
          {view === "home"     && <WorkspaceHome onAction={handleAction} />}
          {view === "explorer" && imgPath && <Explorer imgPath={imgPath} />}
          {view === "report"   && report  && (
            <ReportPanel
              report={report}
              onClear={() => handleAction("clear")}
              onExport={() => downloadJSON(report)}
            />
          )}
          {/* fallback: nothing loaded yet */}
          {!report && !imgPath && <WorkspaceHome onAction={handleAction} />}
        </div>
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
