"""FastAPI application exposing analysis endpoints.

The endpoint /analyze accepts JSON with an `image_path` pointing to either
an on-disk mounted directory (for development) or a disk image file (dd, etc.).

Extended endpoints:
  POST /analyze           – full analysis (tools + timeline + deleted + persistence)
  POST /upload            – upload a disk image, analyse, then delete temporary file
  POST /timeline          – timeline-only scan for a given path
  POST /deleted           – deleted-file scan for a given path
  POST /persistence       – persistence-mechanism scan for a given path
"""
from __future__ import annotations

import os
import shutil
import tempfile
import traceback

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .classifier import classify_findings
from .deleted import detect_deleted
from .detector import detect_os, detect_tools
from .extractor import FilesystemAccessor
from .persistence import detect_persistence
from .report import build_report
from .timeline import build_timeline


class AnalyzeRequest(BaseModel):
    image_path: str


app = FastAPI(title="OS Forensics API")

# Allow the UI dev server to call this API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Shared helper ─────────────────────────────────────────────────────────────

def _full_analysis(fs: FilesystemAccessor) -> dict:
    os_info    = detect_os(fs)
    findings   = detect_tools(fs)
    classified = classify_findings(findings)
    timeline   = build_timeline(fs)
    deleted    = detect_deleted(fs)
    persistence = detect_persistence(fs)
    report = build_report(os_info, classified, timeline=timeline, deleted=deleted, persistence=persistence)
    return report.dict()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Full forensic analysis: OS, tools, timeline, deleted files, persistence."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return _full_analysis(fs)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/upload")
def upload_image(file: UploadFile = File(...)):
    """Accept an uploaded image, analyse it, then remove the temporary file."""
    tmp_dir = tempfile.mkdtemp(prefix="osforensics_upload_")
    try:
        tmp_path = os.path.join(tmp_dir, file.filename)
        with open(tmp_path, "wb") as out_f:
            shutil.copyfileobj(file.file, out_f)
        fs = FilesystemAccessor(tmp_path)
        return _full_analysis(fs)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})
    finally:
        try:
            file.file.close()
        except Exception:
            pass
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass


@app.post("/timeline")
def timeline_scan(req: AnalyzeRequest):
    """Return only the timeline events for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"timeline": build_timeline(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/deleted")
def deleted_scan(req: AnalyzeRequest):
    """Return only the deleted-file findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"deleted": detect_deleted(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/persistence")
def persistence_scan(req: AnalyzeRequest):
    """Return only the persistence-mechanism findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"persistence": detect_persistence(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})
