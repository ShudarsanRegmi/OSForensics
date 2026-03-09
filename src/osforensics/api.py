"""FastAPI application exposing analysis endpoints.

The endpoint /analyze accepts JSON with an `image_path` pointing to either
an on-disk mounted directory (for development) or a disk image file (dd, etc.).

Extended endpoints:
  POST /analyze           – full analysis (tools + timeline + deleted + persistence + config + services + browsers)
  POST /upload            – upload a disk image, analyse, then delete temporary file
  POST /timeline          – timeline-only scan for a given path
  POST /deleted           – deleted-file scan for a given path
  POST /persistence       – persistence-mechanism scan for a given path
  POST /config            – configuration-file audit for a given path
  POST /services          – service detection and enumeration for a given path
  POST /browsers          – browser forensics (history, bookmarks, cookies, extensions …)

Explorer endpoints (Autopsy-style navigation):
  POST /explore/tree      – static artifact category tree
  POST /explore/browse    – list directory children with metadata
  POST /explore/stat      – full inode metadata for a single path
  POST /explore/read      – read file content (text or hex preview)
"""
from __future__ import annotations

import os
import shutil
import tempfile
import traceback
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .browser import detect_browsers
from .cases import (
    list_cases, create_case, get_case, update_case, delete_case,
    add_data_source, remove_data_source,
)
from .classifier import classify_findings
from .config import analyze_configs
from .deleted import detect_deleted
from .detector import detect_os, detect_tools
from .explorer import ARTIFACT_TREE, browse, stat_file, read_text
from .extractor import FilesystemAccessor
from .persistence import detect_persistence
from .report import build_report
from .services import detect_services
from .timeline import build_timeline


class AnalyzeRequest(BaseModel):
    image_path: str


class ExploreRequest(BaseModel):
    image_path: str
    path: str
    limit: Optional[int] = 200_000


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
    config     = analyze_configs(fs)
    services   = detect_services(fs)
    browsers   = detect_browsers(fs)
    report = build_report(os_info, classified, timeline=timeline, deleted=deleted,
                          persistence=persistence, config=config, services=services,
                          browsers=browsers)
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


@app.post("/config")
def config_scan(req: AnalyzeRequest):
    """Return configuration-file audit findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"config": analyze_configs(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/services")
def services_scan(req: AnalyzeRequest):
    """Return service detection findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"services": detect_services(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/browsers")
def browser_scan(req: AnalyzeRequest):
    """Return browser forensics findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"browsers": detect_browsers(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


# ── Explorer endpoints (Autopsy-style navigation) ─────────────────────────────

@app.get("/explore/tree")
def artifact_tree():
    """Return the static artifact category tree (no image_path needed)."""
    return {"tree": ARTIFACT_TREE}


@app.post("/explore/browse")
def explore_browse(req: ExploreRequest):
    """List a directory with per-entry inode metadata."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return browse(fs, req.path)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/explore/stat")
def explore_stat(req: ExploreRequest):
    """Return full inode metadata for a single path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return stat_file(fs, req.path)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/explore/read")
def explore_read(req: ExploreRequest):
    """Read file content (UTF-8 text or hex preview for binary files)."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return read_text(fs, req.path, limit=req.limit or 200_000)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


# ── Host filesystem browser (for the file-picker dialog) ─────────────────────

class FsBrowseRequest(BaseModel):
    path: str = "/"


@app.post("/fs/browse")
def fs_browse(req: FsBrowseRequest):
    """List the host filesystem directory for the GUI file-picker.

    Returns the normalized path and a list of children:
      { name, path, is_dir, size, mtime }
    Silently skips entries that cannot be stat'd.
    """
    import stat as _stat
    path = os.path.normpath(req.path or "/")
    if not os.path.isdir(path):
        raise HTTPException(status_code=400, detail=f"Not a directory: {path}")
    try:
        raw = os.listdir(path)
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Permission denied: {path}")

    children = []
    for name in sorted(raw, key=lambda n: (not os.path.isdir(os.path.join(path, n)), n.lower())):
        full = os.path.join(path, name)
        try:
            st = os.lstat(full)
            is_dir = _stat.S_ISDIR(st.st_mode)
            children.append({
                "name":   name,
                "path":   full,
                "is_dir": is_dir,
                "size":   st.st_size if not is_dir else None,
                "mtime":  st.st_mtime,
            })
        except OSError:
            pass

    # Build breadcrumb from the current path
    parts = [p for p in path.split("/") if p]
    crumbs = [{"label": "/", "path": "/"}]
    for i, part in enumerate(parts):
        crumbs.append({"label": part, "path": "/" + "/".join(parts[:i + 1])})

    return {"path": path, "children": children, "breadcrumbs": crumbs}


# ── Case management models ────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    name: str
    number: str = ""
    examiner: str = ""
    description: str = ""


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    number: Optional[str] = None
    examiner: Optional[str] = None
    description: Optional[str] = None


class CaseAnalyzeRequest(BaseModel):
    image_path: str


# ── Case management endpoints ─────────────────────────────────────────────────

@app.get("/cases")
def cases_list():
    """Return a lightweight summary list of all cases."""
    return {"cases": list_cases()}


@app.post("/cases")
def cases_create(req: CaseCreate):
    """Create a new case and return its full data."""
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Case name is required")
    return create_case(req.name, req.number, req.examiner, req.description)


@app.get("/cases/{case_id}")
def cases_get(case_id: str):
    """Return the full case data including all data sources and reports."""
    try:
        return get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/cases/{case_id}")
def cases_update(case_id: str, req: CaseUpdate):
    """Update case metadata (name, number, examiner, description)."""
    try:
        return update_case(case_id, req.name, req.number, req.examiner, req.description)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/cases/{case_id}")
def cases_delete(case_id: str):
    """Permanently delete a case and all its stored data."""
    try:
        delete_case(case_id)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/cases/{case_id}/analyze")
def cases_analyze(case_id: str, req: CaseAnalyzeRequest):
    """Run a full forensic analysis and save the result as a data source in the case."""
    try:
        get_case(case_id)   # verify exists before expensive analysis
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _full_analysis(fs)
        label  = os.path.basename(req.image_path.rstrip("/")) or req.image_path
        source = add_data_source(case_id, req.image_path, label, report)
        return {"source": source, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.delete("/cases/{case_id}/sources/{source_id}")
def cases_remove_source(case_id: str, source_id: str):
    """Remove a data source from a case."""
    try:
        remove_data_source(case_id, source_id)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

