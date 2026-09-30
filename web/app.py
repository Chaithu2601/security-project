#!/usr/bin/env python3
"""
Web UI for the DAST Harness.

A thin FastAPI layer that WRAPS the existing dast_scan.py engine unchanged:
the browser form builds a config, this backend writes it to a temp YAML,
runs `python dast_scan.py --config <tmp>` as a subprocess, streams its live
output to the page (Server-Sent Events), then serves the REPORT.html /
report.json the engine generates.

Run:
    pip install -r requirements.txt
    python web/app.py           # -> http://127.0.0.1:8700

Only scan systems you own or are explicitly authorised to test.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ------------------------------------------------------------------ #
#  Paths — everything is relative to the Security project root
# ------------------------------------------------------------------ #
ROOT = Path(__file__).resolve().parent.parent      # .../Security project
ENGINE = ROOT / "dast_scan.py"

# Import the presets from the engine rather than restating them here — one
# source of truth, so a preset can never mean two different things depending
# on whether the scan was launched from the CLI or the UI.
sys.path.insert(0, str(ROOT))
from dast_scan import PRESETS, apply_preset   # noqa: E402
BASE_CONFIG = ROOT / "config.yaml"
WEB_DIR = Path(__file__).resolve().parent
STATIC = WEB_DIR / "static"
RUNS_DIR = WEB_DIR / "runs"                          # temp configs + job metadata
RUNS_DIR.mkdir(exist_ok=True)

# ------------------------------------------------------------------ #
#  UI selection -> engine config mapping
# ------------------------------------------------------------------ #
# Scan types the UI exposes -> the phase key in config.yaml `phases:`
SCAN_PHASES = {
    "fuzz_dast":       "Nuclei DAST fuzzing (injection)",
    "template_scan":   "Nuclei templates (CVE / exposure / misconfig)",
    "zap":             "OWASP ZAP active scan",
    "nikto":           "Nikto web-server scan",
    "testssl":         "testssl.sh TLS/cipher scan",
    "secret_scan":     "Secret/key leak scan (frontend JS)",
    "token_analysis":  "JWT / token lifetime analysis (passive)",
    "token_probe":     "Active token / broken-auth probe (replay + tamper)",
    "idor_probe":      "IDOR / access-control probe (auto-discovers objects)",
    "depscan":         "Vulnerable frontend JS libraries (black-box SCA / A06)",
    "cors":            "CORS misconfiguration probe (A05)",
    "csrf":            "CSRF / cookie-security check (SameSite, Secure, HttpOnly)",
    "api_spec":        "API spec ingestion (OpenAPI / GraphQL)",
    "sqlmap_confirm":  "sqlmap confirmation of SQLi",
}

# Injection test type (UI) -> Nuclei -dast template tag.
# These are the REAL tags used by current nuclei-templates dast/ templates
# (the old "fuzzing-req-*" tags match nothing and silently return zero).
INJECTION_TAGS = {
    "sqli":     "sqli",
    "xss":      "xss",
    "ssti":     "ssti",
    "lfi":      "lfi",
    "ssrf":     "ssrf",
    "rce":      "rce",
    "redirect": "redirect",
    "crlf":     "crlf",
    "xxe":      "xxe",
}
# The -dast flag already scopes to fuzzing templates, so no separate location
# tags are needed (the old fuzzing-req-query/body tags no longer exist).
LOCATION_TAGS = []

# Phases that need a crawl to have produced endpoints first.
NEEDS_CRAWL = {"fuzz_dast", "template_scan", "secret_scan", "token_analysis",
               "depscan", "idor_probe", "cors", "token_probe", "csrf"}


# ------------------------------------------------------------------ #
#  Job registry (in-memory)
# ------------------------------------------------------------------ #
class Job:
    def __init__(self, job_id: str, config: dict):
        self.id = job_id
        self.config = config
        self.lines: list[str] = []
        self.status = "starting"          # starting | running | done | error | aborted
        self.run_dir: Path | None = None  # projects/<name>/<date>/ once known
        self.proc: subprocess.Popen | None = None
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self.returncode: int | None = None

    def log(self, line: str):
        self.lines.append(line.rstrip("\n"))

    def to_meta(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "started": self.started,
            "returncode": self.returncode,
            "project": self.config.get("project", {}).get("name"),
            "target": self.config.get("target", {}).get("scope_domain"),
            "run_dir": str(self.run_dir) if self.run_dir else None,
            "has_report": bool(self.run_dir and (self.run_dir / "REPORT.html").exists()),
        }


JOBS: dict[str, Job] = {}


# ------------------------------------------------------------------ #
#  Build an engine config dict from the UI request
# ------------------------------------------------------------------ #
class ScanRequest(BaseModel):
    url: str
    project_name: str | None = None
    scope_domain: str | None = None
    auth_cookie: str | None = None
    auth_bearer: str | None = None
    auth_raw_headers: list[str] = []
    scans: list[str] = []
    injection_tests: list[str] = []
    zap_mode: str = "full"
    api_spec_source: str | None = None      # OpenAPI/GraphQL spec URL or file path
    api_spec_format: str | None = None       # openapi | swagger | graphql | ""
    rate_limit: int = 10
    concurrency: int = 5
    crawl_depth: int = 5
    preset: str | None = None        # quick | standard | deep; None = custom
    parallel: bool = True            # run independent phases concurrently
    budget_secs: int | None = None   # wall-clock cap; None = preset default


def _slug(s: str) -> str:
    keep = "".join(c if c.isalnum() or c in "-_." else "-" for c in s)
    return keep.strip("-") or "scan"


def build_config(req: ScanRequest) -> dict:
    """Start from the tuned base config.yaml, then override with UI choices.
    Reusing the base keeps the operator's tool paths / keywords / resilience."""
    cfg = yaml.safe_load(BASE_CONFIG.read_text()) if BASE_CONFIG.exists() else {}

    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.netloc or url
    # scope_domain is matched against a URL's HOSTNAME, so it must not carry a
    # port — "127.0.0.1:8799" matches nothing and silently empties the scan.
    scope = (req.scope_domain or parsed.hostname or host).strip()
    name = req.project_name or _slug(host)

    cfg.setdefault("project", {})
    cfg["project"]["name"] = name
    # Keep runs inside web/runs so the UI owns them and can list them.
    cfg["project"]["workdir"] = str(RUNS_DIR / "projects")

    cfg.setdefault("target", {})
    cfg["target"]["scope_domain"] = scope
    cfg["target"]["seeds"] = [url]
    cfg["target"]["seeds_file"] = ""

    # Preflight/monitor otherwise assume https://<domain>; honour the scheme and
    # port the user actually gave (fixes http-only apps and non-standard ports).
    cfg.setdefault("resilience", {})
    cfg["resilience"]["health_url"] = url

    # --- auth ---
    headers: list[str] = []
    if req.auth_cookie:
        c = req.auth_cookie.strip()
        headers.append(c if c.lower().startswith("cookie:") else f"Cookie: {c}")
    if req.auth_bearer:
        b = req.auth_bearer.strip()
        b = b[7:].strip() if b.lower().startswith("bearer ") else b
        headers.append(f"Authorization: Bearer {b}")
    for h in req.auth_raw_headers:
        if h.strip():
            headers.append(h.strip())
    cfg.setdefault("auth", {})
    cfg["auth"]["enabled"] = bool(headers)
    cfg["auth"]["headers"] = headers or ["Cookie: none=none"]

    # A supplied spec must be in cfg BEFORE apply_preset, so the preset can
    # auto-enable api_spec ingestion (it checks api_spec.source).
    if req.api_spec_source and req.api_spec_source.strip():
        cfg["api_spec"] = {"source": req.api_spec_source.strip(),
                           "format": (req.api_spec_format or "").strip()}

    # --- phases: a preset decides them, otherwise the UI's own selection ---
    if req.preset:
        # config.yaml ships budget_secs:0; left in place it would shadow the
        # preset's own time budget. Drop the file default here unless the UI
        # sent an explicit budget (handled just below).
        if req.budget_secs is None:
            (cfg.get("limits") or {}).pop("budget_secs", None)
        apply_preset(cfg, req.preset)
    else:
        # The base config may itself name a preset; an explicit Custom
        # selection must not be silently overridden by it when the engine
        # re-reads the config.
        cfg.pop("preset", None)
        phases = {k: False for k in cfg.get("phases", {})}
        for k in SCAN_PHASES:
            phases[k] = k in req.scans
        # crawl is implicit: enable it when a phase depends on discovered endpoints
        phases["crawl"] = bool(NEEDS_CRAWL & set(req.scans))
        cfg["phases"] = phases

    cfg.setdefault("limits", {})
    cfg["limits"]["parallel"] = bool(req.parallel)
    if req.budget_secs is not None:
        cfg["limits"]["budget_secs"] = int(req.budget_secs)

    # --- injection classes -> dast tags ---
    if "fuzz_dast" in req.scans:
        chosen = [INJECTION_TAGS[t] for t in req.injection_tests if t in INJECTION_TAGS]
        if not chosen:  # nothing ticked -> fuzz everything
            chosen = list(INJECTION_TAGS.values())
        cfg.setdefault("scan", {})
        cfg["scan"]["dast_tags"] = LOCATION_TAGS + chosen

    cfg.setdefault("scan", {})
    cfg["scan"]["rate_limit"] = int(req.rate_limit)
    cfg["scan"]["concurrency"] = int(req.concurrency)
    cfg["scan"]["crawl_depth"] = int(req.crawl_depth)

    # --- zap mode ---
    if "zap" in req.scans:
        cfg.setdefault("zap", {})
        cfg["zap"]["mode"] = req.zap_mode

    # --- IDOR: clean defaults so the base config's placeholder 2nd account
    # never leaks in. UI has one account -> authed-vs-anon + auto-discovery. ---
    if "idor_probe" in req.scans:
        cfg["idor"] = {
            "enabled": True,
            "auto_discover": True,
            "user_a_headers": [],      # falls back to the main auth headers
            "user_b_headers": [],      # none -> authed-vs-anonymous mode
            "victim_urls": [],
            "similarity_tolerance": 0.15,
        }

    # --- API spec ingestion: enable whenever a source was given (any preset) ---
    if (cfg.get("api_spec") or {}).get("source"):
        cfg["phases"]["api_spec"] = True
    else:
        cfg["phases"]["api_spec"] = False   # nothing to ingest without a source

    return cfg


# ------------------------------------------------------------------ #
#  Run the engine as a subprocess, stream stdout into the job
# ------------------------------------------------------------------ #
def run_engine(job: Job, config_path: Path):
    cmd = [sys.executable, "-u", str(ENGINE), "--config", str(config_path)]
    job.log("$ " + " ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as e:
        job.status = "error"
        job.log(f"[ERR] failed to launch engine: {e}")
        return
    job.proc = proc
    job.status = "running"

    for line in proc.stdout:                       # blocking read, one line at a time
        job.log(line)
        # The engine prints "Run dir: <path>" near the top — capture it so we
        # know where REPORT.html will land.
        s = line.strip()
        if s.startswith("Run dir:") and job.run_dir is None:
            job.run_dir = Path(s.split("Run dir:", 1)[1].strip())

    proc.wait()
    job.returncode = proc.returncode
    if job.status != "aborted":
        job.status = "done" if proc.returncode == 0 else "error"
    job.log(f"\n[engine exited with code {proc.returncode}]")


# ------------------------------------------------------------------ #
#  FastAPI app
# ------------------------------------------------------------------ #
app = FastAPI(title="DAST Harness UI")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/manual", response_class=HTMLResponse)
def manual():
    """Operator manual: engines used, scan types, and how each works."""
    return (STATIC / "manual.html").read_text(encoding="utf-8")


@app.get("/api/options")
def options():
    """Everything the UI needs to render its checkboxes/labels."""
    return {
        "scans": [{"key": k, "label": v} for k, v in SCAN_PHASES.items()],
        "injection_tests": [
            {"key": "sqli", "label": "SQL Injection (SQLi)"},
            {"key": "xss", "label": "Cross-Site Scripting (XSS)"},
            {"key": "ssti", "label": "Server-Side Template Injection"},
            {"key": "lfi", "label": "Local File Inclusion (LFI)"},
            {"key": "ssrf", "label": "Server-Side Request Forgery"},
            {"key": "rce", "label": "Remote Code Execution (RCE)"},
            {"key": "redirect", "label": "Open Redirect"},
            {"key": "crlf", "label": "CRLF Injection"},
            {"key": "xxe", "label": "XML External Entity (XXE)"},
        ],
        "zap_modes": ["full", "baseline", "api"],
        "presets": [{"key": k, "label": v["label"], "desc": v["desc"],
                     "phases": v["phases"], "budget_secs": v["budget_secs"]}
                    for k, v in PRESETS.items()],
    }


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    if not req.url.strip():
        raise HTTPException(400, "A target URL is required.")
    if not req.scans and not req.preset:
        raise HTTPException(400, "Select at least one scan type.")

    cfg = build_config(req)
    job_id = uuid.uuid4().hex[:12]
    job = Job(job_id, cfg)
    JOBS[job_id] = job

    # write the temp config this job runs from
    cfg_path = RUNS_DIR / f"{job_id}.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))

    threading.Thread(target=run_engine, args=(job, cfg_path), daemon=True).start()
    return {"job_id": job_id, "config": cfg}


@app.get("/api/scan/{job_id}/status")
def scan_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return job.to_meta()


@app.get("/api/scan/{job_id}/stream")
def scan_stream(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")

    def gen():
        idx = 0
        # replay everything already buffered, then follow live
        while True:
            while idx < len(job.lines):
                yield f"data: {json.dumps(job.lines[idx])}\n\n"
                idx += 1
            if job.status in ("done", "error", "aborted") and idx >= len(job.lines):
                yield f"event: end\ndata: {json.dumps(job.to_meta())}\n\n"
                return
            time.sleep(0.3)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/api/scan/{job_id}/abort")
def scan_abort(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    if job.proc and job.proc.poll() is None:
        job.status = "aborted"
        job.proc.terminate()
        job.log("\n[aborted by user]")
    return job.to_meta()


# ------------------------------------------------------------------ #
#  Shared report serving — works for a live job OR a past run on disk
# ------------------------------------------------------------------ #
REPORT_FILES = {"html": "REPORT.html", "md": "REPORT.md",
                "json": "report.json", "sarif": "report.sarif"}


def _job_run_dir(job_id: str) -> Path:
    job = JOBS.get(job_id)
    if not job or not job.run_dir:
        raise HTTPException(404, "No report yet")
    return job.run_dir


def _run_dir_from_path(rel: str) -> Path:
    """Resolve a <project>/<datedir> path under runs/projects, refusing any
    path that escapes that root (directory-traversal protection)."""
    proj_root = (RUNS_DIR / "projects").resolve()
    target = (proj_root / rel).resolve()
    if proj_root not in target.parents and target != proj_root:
        raise HTTPException(400, "Invalid run path")
    if not target.is_dir():
        raise HTTPException(404, "Run not found")
    return target


def _serve_report_html(run_dir: Path) -> HTMLResponse:
    f = run_dir / "REPORT.html"
    if not f.exists():
        raise HTTPException(404, "REPORT.html not generated")
    return HTMLResponse(f.read_text(encoding="utf-8"))


def _serve_report_json(run_dir: Path) -> JSONResponse:
    f = run_dir / "report.json"
    if not f.exists():
        raise HTTPException(404, "report.json not generated")
    return JSONResponse(json.loads(f.read_text()))


def _serve_download(run_dir: Path, kind: str) -> FileResponse:
    fname = REPORT_FILES.get(kind)
    if not fname:
        raise HTTPException(400, "Unknown report kind")
    f = run_dir / fname
    if not f.exists():
        raise HTTPException(404, f"{fname} not generated")
    # name the download after the project folder (…/projects/<name>/<date>/)
    return FileResponse(f, filename=f"{run_dir.parent.name}-{fname}")


# --- live-job report endpoints ---
@app.get("/api/scan/{job_id}/report", response_class=HTMLResponse)
def scan_report(job_id: str):
    return _serve_report_html(_job_run_dir(job_id))


@app.get("/api/scan/{job_id}/report.json")
def scan_report_json(job_id: str):
    return _serve_report_json(_job_run_dir(job_id))


@app.get("/api/scan/{job_id}/download/{kind}")
def scan_download(job_id: str, kind: str):
    return _serve_download(_job_run_dir(job_id), kind)


# --- past-run report endpoints (keyed by on-disk path) ---
@app.get("/api/run/report", response_class=HTMLResponse)
def run_report(path: str):
    return _serve_report_html(_run_dir_from_path(path))


@app.get("/api/run/report.json")
def run_report_json(path: str):
    return _serve_report_json(_run_dir_from_path(path))


@app.get("/api/run/download/{kind}")
def run_download(kind: str, path: str):
    return _serve_download(_run_dir_from_path(path), kind)


@app.get("/api/runs")
def list_runs():
    """Past runs on disk (projects/<name>/<date>/) plus in-memory jobs."""
    out = []
    proj_root = RUNS_DIR / "projects"
    if proj_root.exists():
        for report in sorted(proj_root.glob("*/*/report.json"),
                             key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                meta = json.loads(report.read_text()).get("meta", {})
            except Exception:
                continue
            run_dir = report.parent
            out.append({
                "project": meta.get("project"),
                "target": meta.get("target"),
                "date": meta.get("date"),
                "total": meta.get("total"),
                "counts": meta.get("counts", {}),
                "run_dir": str(run_dir),
                # <project>/<datedir> — the key the /api/run/* endpoints take
                "rel": f"{run_dir.parent.name}/{run_dir.name}",
            })
    return {"runs": out}


# serve any static assets if we add them later
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


if __name__ == "__main__":
    import uvicorn
    print("DAST Harness UI  ->  http://127.0.0.1:8700")
    uvicorn.run(app, host="127.0.0.1", port=8700, log_level="info")
