# DAST Harness — Web UI

A browser front-end that **wraps the existing `dast_scan.py` engine unchanged**.
You pick a URL, which scans to run, and which injection tests to fuzz for; the
backend builds an engine config, runs the scanner, streams its live output to the
page, then displays the generated report.

```
web/
  app.py             FastAPI backend (jobs, live SSE streaming, report serving)
  static/index.html  the whole UI (self-contained, no build step)
  start.sh           one-command launcher (creates .venv on first run)
  runs/              per-job temp configs + projects/<name>/<date>/ report output
```

## Run

```bash
./web/start.sh
# open http://127.0.0.1:8700
```

First run creates a `.venv` and installs `requirements.txt` (FastAPI + uvicorn +
pydantic + pyyaml). Bound to `127.0.0.1` only — it never listens on the network.

## How the UI maps onto the engine

| UI control            | Engine config it sets                                  |
|-----------------------|--------------------------------------------------------|
| Target URL            | `target.seeds`, `target.scope_domain`, `resilience.health_url` (keeps your scheme/port) |
| Scans to run          | `phases.*` toggles (crawl is auto-enabled when needed) |
| Injection tests       | `scan.dast_tags` (SQLi/XSS/SSTI/LFI/SSRF/RCE/redirect/CRLF/XXE) |
| Auth cookie / bearer / raw headers | `auth.headers`, `auth.enabled`            |
| ZAP mode              | `zap.mode` (full / baseline / api)                     |
| Tuning                | `scan.rate_limit`, `scan.concurrency`, `scan.crawl_depth` |

Everything else (tool paths, resilience defaults, interesting-keyword list) is
inherited from the base `config.yaml`, so your tuned defaults still apply.

## What the engine needs

The web layer runs whatever tools are installed; missing ones are skipped
gracefully (the run log says so). For full coverage install: `katana`, `nuclei`,
Docker (for ZAP), `nikto`, `testssl.sh`, `sqlmap` — see the top-level `README.md`.

**Optional — `retire.js`** upgrades the *Vulnerable frontend JS libraries*
(`depscan`) scan from the built-in curated signatures to retire.js's full CVE
database. Install with `npm install -g retire` (needs Node.js); the phase picks
it up automatically, no config change. Without it, the curated set still runs.

## Reports

Each scan writes to `web/runs/projects/<name>/<date>/`:
`REPORT.html`, `REPORT.md`, `report.json`, `report.sarif`. The page shows the
HTML report inline with severity chips and download links; **Previous runs**
lists past scans. Only scan systems you own or are authorised to test.
