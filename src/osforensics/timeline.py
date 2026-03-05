"""Timeline Reconstruction Engine.

Parses timestamps from:
  - inode metadata (atime, mtime, ctime) for sensitive files — local mode only
  - /var/log/auth.log  (and /var/log/secure on RHEL-based systems)
  - /var/log/syslog    (and /var/log/messages)
  - per-user .bash_history  (including embedded HISTTIMEFORMAT timestamps)

Produces a list of TimelineEvent dicts sorted by timestamp, with unknown
timestamps pushed to the end.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .extractor import FilesystemAccessor

# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _from_epoch(epoch: float) -> str:
    return _fmt(datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None))


def _make_event(
    timestamp: Optional[str],
    source: str,
    event_type: str,
    detail: str,
    severity: str = "info",
) -> Dict:
    return {
        "timestamp": timestamp or "unknown",
        "source": source,
        "event_type": event_type,
        "detail": detail,
        "severity": severity,
    }


# ── Suspicious bash command patterns ─────────────────────────────────────────

SUSPICIOUS_CMDS: List[tuple] = [
    (re.compile(r"\bnmap\b"),                              "nmap executed",                    "medium"),
    (re.compile(r"\b(msfconsole|msfvenom|metasploit)\b"),  "Metasploit tool executed",          "high"),
    (re.compile(r"\bsqlmap\b"),                            "sqlmap executed",                   "high"),
    (re.compile(r"\bhydra\b"),                             "Hydra brute-force executed",        "high"),
    (re.compile(r"\baircrack|airmon|airodump\b"),          "Wireless attack tool executed",     "high"),
    (re.compile(r"\btor\b"),                               "tor invoked",                       "medium"),
    (re.compile(r"\bssh\b.+-[DRL]\b"),                     "SSH tunnel created",                "medium"),
    (re.compile(r"\b(wget|curl)\b.+http"),                 "Remote file download",              "medium"),
    (re.compile(r"\bchmod\b.+[+][xs]"),                    "SUID/SGID bit set",                 "high"),
    (re.compile(r"\bdd\b.+if="),                           "dd disk operation",                 "medium"),
    (re.compile(r"\b(wireshark|tcpdump|tshark)\b"),        "Packet capture tool",               "medium"),
    (re.compile(r"\b(nc|netcat)\b"),                       "netcat executed",                   "medium"),
    (re.compile(r"\bsudo\b"),                              "sudo used",                         "info"),
    (re.compile(r"\brm\s+-[rf]{1,2}\b"),                   "Forced file removal",               "medium"),
    (re.compile(r"\bhistory\s+-[ca]\b|unset\s+HISTFILE"),  "History clear attempted",           "high"),
    (re.compile(r">\s*/var/log/\S+"),                      "Log file overwritten via shell",    "high"),
    (re.compile(r"\bproxychains\b"),                       "proxychains executed",              "medium"),
    (re.compile(r"\bjohn\b|\bhashcat\b"),                  "Password cracker executed",         "high"),
    (re.compile(r"\bburpsuite\b|\bburp\b"),                "Burp Suite executed",               "medium"),
    (re.compile(r"\bnikto\b|\bdirb\b|\bgobuster\b"),       "Web scanner executed",              "high"),
    (re.compile(r"\bsocat\b"),                             "socat executed",                    "medium"),
]

# ── Log parsing patterns ──────────────────────────────────────────────────────

AUTH_PATTERNS: List[tuple] = [
    (re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
     "SSH login success: user={1} from={2}", "medium"),
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
     "SSH login failure: user={1} from={2}", "high"),
    (re.compile(r"sudo:\s+(\S+) .* COMMAND=(.+)"),
     "sudo: user={1} cmd={2}", "medium"),
    (re.compile(r"new user: name=(\S+)"),
     "User account created: {1}", "high"),
    (re.compile(r"useradd.* '(\S+)'"),
     "useradd: {1}", "high"),
    (re.compile(r"session opened for user (\S+) by"),
     "Session opened: {1}", "info"),
    (re.compile(r"session closed for user (\S+)"),
     "Session closed: {1}", "info"),
]

SYSLOG_PATTERNS: List[tuple] = [
    (re.compile(r"(tor|openvpn|wireguard|wg-quick)\["),
     "Network anonymizer service active: {1}", "medium"),
    (re.compile(r"Started\s+(.+?)\s*\.service"),
     "Service started: {1}", "info"),
    (re.compile(r"kernel:.*segfault at"),
     "Kernel segfault (possible exploit)", "high"),
    (re.compile(r"OUT=\S+ SRC=(\S+) DST=(\S+).*DPT=(\S+)"),
     "Firewall event: {1} → {2}:{3}", "info"),
    (re.compile(r"(msfconsole|metasploit|msfvenom)"),
     "Metasploit reference in syslog", "high"),
]


def _parse_log_timestamp(line: str) -> Optional[datetime]:
    """Try multiple common log timestamp formats."""
    # ISO-8601: 2026-02-12T10:21:00 or 2026-02-12 10:21:00
    m = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
    if m:
        raw = m.group(1).replace("T", " ")
        try:
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    # classic syslog: Feb 12 10:21:00
    m = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            year = datetime.now().year
            return datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return None


def _apply_log_patterns(
    line: str, patterns: List[tuple], source: str
) -> Optional[Dict]:
    ts = _parse_log_timestamp(line)
    ts_str = _fmt(ts) if ts else None
    for pattern, label_tmpl, severity in patterns:
        m = pattern.search(line)
        if m:
            label = label_tmpl
            for i, g in enumerate(m.groups(), 1):
                label = label.replace(f"{{{i}}}", (g or "").strip()[:60])
            return _make_event(ts_str, source, "log_event", label, severity)
    return None


# ── Scanner functions ─────────────────────────────────────────────────────────

def scan_inode_metadata(fs: FilesystemAccessor) -> List[Dict]:
    """Collect mtime/atime for security-sensitive files (local mode only)."""
    if fs.mode != "local":
        return []

    candidates = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/crontab", "/etc/ssh/sshd_config",
        "/root/.bash_history", "/root/.bashrc",
        "/etc/hosts", "/etc/resolv.conf",
    ]

    events: List[Dict] = []

    for p in candidates:
        full = fs._local_full(p)
        try:
            s = os.stat(full)
            events.append(_make_event(
                _from_epoch(s.st_mtime), "inode", "file_modified",
                f"Modified: {p}", "info",
            ))
        except OSError:
            pass

    # per-user home dirs
    home_base = fs._local_full("/home")
    try:
        for user in os.listdir(home_base):
            hist = os.path.join(home_base, user, ".bash_history")
            try:
                s = os.stat(hist)
                events.append(_make_event(
                    _from_epoch(s.st_mtime), "inode", "file_modified",
                    f"Modified: /home/{user}/.bash_history", "info",
                ))
            except OSError:
                pass
    except OSError:
        pass

    return events


def scan_bash_history(fs: FilesystemAccessor) -> List[Dict]:
    """Extract suspicious commands from all bash history files."""
    history_files: List[tuple] = []

    if fs.exists("/root/.bash_history"):
        history_files.append(("/root/.bash_history", "root"))

    for user in fs.list_dir("/home"):
        p = f"/home/{user}/.bash_history"
        if fs.exists(p):
            history_files.append((p, user))

    events: List[Dict] = []

    for hist_path, user in history_files:
        content = fs.read_file(hist_path, max_bytes=2_000_000)
        if not content:
            continue

        # Wiped / zeroed history — anti-forensics indicator
        if len(content.strip()) < 5:
            events.append(_make_event(
                None, "bash_history", "anti_forensics",
                f"Bash history appears wiped for user '{user}'", "high",
            ))
            continue

        lines = content.decode("utf-8", errors="ignore").splitlines()
        current_ts: Optional[str] = None

        for line in lines:
            line = line.strip()
            # HISTTIMEFORMAT timestamp comment: #1234567890
            if line.startswith("#") and line[1:].isdigit():
                try:
                    current_ts = _from_epoch(float(line[1:]))
                except Exception:
                    pass
                continue

            for pattern, label, severity in SUSPICIOUS_CMDS:
                if pattern.search(line):
                    events.append(_make_event(
                        current_ts, "bash_history", "suspicious_command",
                        f"[{user}] {label}: `{line[:120]}`", severity,
                    ))
                    break  # one match per line is enough

    return events


def scan_logs(fs: FilesystemAccessor) -> List[Dict]:
    """Parse system logs for authentication, service, and anomaly events."""
    log_targets = [
        ("/var/log/auth.log",  AUTH_PATTERNS,   "auth.log"),
        ("/var/log/secure",    AUTH_PATTERNS,   "secure"),
        ("/var/log/syslog",    SYSLOG_PATTERNS, "syslog"),
        ("/var/log/messages",  SYSLOG_PATTERNS, "messages"),
    ]

    events: List[Dict] = []

    for log_path, patterns, source in log_targets:
        content = fs.read_file(log_path, max_bytes=5_000_000)
        if not content:
            continue

        raw_len = len(content.strip())
        if raw_len < 64:
            events.append(_make_event(
                None, source, "anti_forensics",
                f"Log appears truncated or wiped: {log_path} ({raw_len} bytes)", "high",
            ))
            continue

        lines = content.decode("utf-8", errors="ignore").splitlines()
        # Analyse the most recent 10 000 lines to keep performance reasonable
        for line in lines[-10_000:]:
            ev = _apply_log_patterns(line, patterns, source)
            if ev:
                events.append(ev)

    return events


# ── Public entry point ────────────────────────────────────────────────────────

def build_timeline(fs: FilesystemAccessor) -> List[Dict]:
    """Build and return the sorted timeline for the given filesystem."""
    events: List[Dict] = []
    events.extend(scan_inode_metadata(fs))
    events.extend(scan_bash_history(fs))
    events.extend(scan_logs(fs))

    def sort_key(e: Dict) -> str:
        ts = e["timestamp"]
        return "9999-99-99 99:99:99" if ts == "unknown" else ts

    events.sort(key=sort_key)
    return events
