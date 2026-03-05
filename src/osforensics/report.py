"""Reporting models and helpers to build structured forensic output.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


# ── Tool detection models ─────────────────────────────────────────────────────

class ToolFinding(BaseModel):
    tool: str
    risk: str
    evidence: List[str]


class OSInfo(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None
    variant_tags: List[str] = []
    notes: List[str] = []


# ── Timeline models ───────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: str
    source: str
    event_type: str
    detail: str
    severity: str = "info"


# ── Deleted file models ───────────────────────────────────────────────────────

class DeletedFinding(BaseModel):
    path: str
    type: str
    detail: str
    severity: str = "medium"


# ── Persistence models ────────────────────────────────────────────────────────

class PersistenceFinding(BaseModel):
    source: str
    category: str
    detail: str
    severity: str = "medium"
    snippet: str = ""


# ── Top-level report ──────────────────────────────────────────────────────────

class ForensicReport(BaseModel):
    os_info: OSInfo
    findings: List[ToolFinding]
    summary: Dict[str, Any] = {}
    timeline: List[TimelineEvent] = []
    deleted: List[DeletedFinding] = []
    persistence: List[PersistenceFinding] = []


def build_report(
    os_info: Dict[str, object],
    classified_findings: List[Dict[str, object]],
    timeline: Optional[List[Dict]] = None,
    deleted: Optional[List[Dict]] = None,
    persistence: Optional[List[Dict]] = None,
) -> ForensicReport:
    os_model = OSInfo(
        name=os_info.get("name"),
        id=os_info.get("id"),
        variant_tags=os_info.get("variant_tags", []),
        notes=os_info.get("notes", []),
    )

    tool_findings = [
        ToolFinding(tool=f["tool"], risk=f.get("risk", "unknown"), evidence=f.get("evidence", []))
        for f in classified_findings
    ]

    timeline_events = [
        TimelineEvent(**e) for e in (timeline or [])
    ]

    deleted_findings = [
        DeletedFinding(**d) for d in (deleted or [])
    ]

    persistence_findings = [
        PersistenceFinding(**p) for p in (persistence or [])
    ]

    high_timeline  = sum(1 for e in timeline_events  if e.severity == "high")
    high_deleted   = sum(1 for d in deleted_findings  if d.severity == "high")
    high_persist   = sum(1 for p in persistence_findings if p.severity == "high")

    summary = {
        "total_tools":         len(tool_findings),
        "high_risk_tools":     sum(1 for f in tool_findings if f.risk == "high"),
        # keep legacy key so the existing status bar still works
        "high_risk":           sum(1 for f in tool_findings if f.risk == "high"),
        "timeline_events":     len(timeline_events),
        "high_timeline":       high_timeline,
        "deleted_findings":    len(deleted_findings),
        "high_deleted":        high_deleted,
        "persistence_findings": len(persistence_findings),
        "high_persistence":    high_persist,
        "total_high":          sum(1 for f in tool_findings if f.risk == "high") + high_timeline + high_deleted + high_persist,
    }

    return ForensicReport(
        os_info=os_model,
        findings=tool_findings,
        summary=summary,
        timeline=timeline_events,
        deleted=deleted_findings,
        persistence=persistence_findings,
    )
