"""Deleted File Detection.

Two complementary strategies:

1. **pytsk3 / TSK scan** (disk-image mode)
   Walks the entire filesystem inode table, flagging entries whose meta-flags
   contain TSK_FS_META_FLAG_UNALLOC (0x02).  Deleted file *names* can still be
   recovered this way because the directory entry often persists after the inode
   is freed.

2. **Missing-expected-file analysis** (both modes)
   Checks for the absence of files that should always be present on a healthy
   Linux system (auth.log, syslog, /etc/passwd, per-user .bash_history, etc.).
   A missing file is a forensically significant indicator of log-wiping or
   anti-forensics activity.
"""
from __future__ import annotations

from typing import Dict, List

from .extractor import FilesystemAccessor

try:
    import pytsk3 as _tsk
    _HAS_PYTSK3 = True
    _UNALLOC_FLAG = 0x02          # TSK_FS_META_FLAG_UNALLOC
    _META_TYPE_DIR = _tsk.TSK_FS_META_TYPE_DIR
except Exception:
    _tsk = None                   # type: ignore
    _HAS_PYTSK3 = False
    _UNALLOC_FLAG = 0x02
    _META_TYPE_DIR = 2            # numeric fallback

# ── Baseline artefacts that should exist on a healthy system ─────────────────

EXPECTED_SYSTEM_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/kern.log",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hostname",
]

EXPECTED_USER_FILES = [".bash_history", ".bashrc"]

# Files/names that are especially high-value if found deleted
HIGH_SEVERITY_NAMES = frozenset(
    ["bash_history", "auth.log", "syslog", "secure", "messages", "passwd", "shadow"]
)

_MAX_FINDINGS = 500   # hard cap to prevent scan runaway on huge images
_MAX_DEPTH    = 6     # maximum recursion depth for TSK inode walk


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    path: str,
    finding_type: str,
    detail: str,
    severity: str = "medium",
) -> Dict:
    return {
        "path": path,
        "type": finding_type,
        "detail": detail,
        "severity": severity,
    }


def _name_severity(name: str) -> str:
    lower = name.lower()
    return "high" if any(h in lower for h in HIGH_SEVERITY_NAMES) else "medium"


# ── pytsk3 recursive inode scan ───────────────────────────────────────────────

def _recurse_deleted(
    dir_obj,
    current_path: str,
    findings: List[Dict],
    depth: int,
) -> None:
    if depth > _MAX_DEPTH or len(findings) >= _MAX_FINDINGS:
        return

    for entry in dir_obj:
        if len(findings) >= _MAX_FINDINGS:
            break
        if not hasattr(entry, "info") or entry.info is None:
            continue
        if entry.info.name is None:
            continue

        try:
            name = entry.info.name.name.decode("utf-8", errors="ignore")
        except Exception:
            continue

        if name in (".", ".."):
            continue

        meta = entry.info.meta
        if meta is None:
            continue

        path = f"{current_path.rstrip('/')}/{name}"
        is_deleted = bool(meta.flags & _UNALLOC_FLAG)

        if is_deleted:
            findings.append(_make_finding(
                path, "deleted_inode",
                f"Deleted inode recovered: {path}",
                _name_severity(name),
            ))

        # Recurse into live subdirectories only (avoid walking deleted subtrees)
        if not is_deleted and depth < _MAX_DEPTH:
            try:
                meta_type = int(meta.type)
            except Exception:
                continue
            if meta_type == _META_TYPE_DIR:
                try:
                    sub_dir = entry.as_directory()
                    _recurse_deleted(sub_dir, path, findings, depth + 1)
                except Exception:
                    pass


def scan_deleted_tsk(fs: FilesystemAccessor) -> List[Dict]:
    """Use pytsk3 to recover deleted inodes from a disk image."""
    if not (_HAS_PYTSK3 and fs.mode == "tsk"):
        return []

    findings: List[Dict] = []
    try:
        root_dir = fs.fs.open_dir("/")
        _recurse_deleted(root_dir, "/", findings, depth=0)
    except Exception as exc:
        findings.append(_make_finding(
            "/", "scan_error",
            f"pytsk3 scan encountered an error: {exc}", "info",
        ))

    return findings


# ── Missing-file baseline check (works in both modes) ─────────────────────────

def scan_missing_expected(fs: FilesystemAccessor) -> List[Dict]:
    """Flag expected system and user files that are absent."""
    findings: List[Dict] = []

    for p in EXPECTED_SYSTEM_FILES:
        if not fs.exists(p):
            findings.append(_make_finding(
                p, "missing_expected",
                f"Expected system file absent (possibly deleted): {p}",
                "high" if any(x in p for x in ("log", "auth", "shadow")) else "medium",
            ))

    for user in fs.list_dir("/home"):
        for fname in EXPECTED_USER_FILES:
            p = f"/home/{user}/{fname}"
            if not fs.exists(p):
                findings.append(_make_finding(
                    p, "missing_expected",
                    f"Expected user file absent for '{user}': {p}",
                    "medium",
                ))

    return findings


# ── Public entry point ────────────────────────────────────────────────────────

def detect_deleted(fs: FilesystemAccessor) -> List[Dict]:
    """Return combined deleted-file findings from TSK scan + baseline check."""
    findings: List[Dict] = []
    findings.extend(scan_deleted_tsk(fs))
    findings.extend(scan_missing_expected(fs))
    return findings
