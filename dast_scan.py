#!/usr/bin/env python3
"""
DAST Harness — one command to run a full dynamic security assessment
against a web application you own, and produce a consolidated report.

Pipeline:  Katana crawl -> endpoint triage -> Nuclei DAST fuzzing
           -> Nuclei template scan -> secret/token leak scan
           -> JWT/token expiration analysis -> (optional) sqlmap confirm
           -> HTML + Markdown + JSON report

Usage:
    python dast_scan.py                    # uses ./config.yaml
    python dast_scan.py --config my.yaml
    python dast_scan.py --config my.yaml --phase fuzz_dast   # run one phase

Only run this against systems you own or are explicitly authorised to test.
"""
from __future__ import annotations
import argparse, base64, datetime, io, json, os, re, shutil, subprocess, sys, threading
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

import owasp  # local module: OWASP Top 10 mapping + WSTG coverage

# ------------------------------------------------------------------ #
#  Console helpers
# ------------------------------------------------------------------ #
C = {"red": "\033[0;31m", "grn": "\033[0;32m", "yel": "\033[1;33m",
     "blu": "\033[0;34m", "bold": "\033[1m", "off": "\033[0m"}
def _c(t, col): return f"{C[col]}{t}{C['off']}" if sys.stdout.isatty() else t

# When phases run concurrently their log lines would interleave into noise.
# Each parallel worker installs its own buffer here; output is replayed in one
# block when that phase finishes, so the console still reads phase by phase.
_out_sink = threading.local()

def _emit(line: str):
    buf = getattr(_out_sink, "buf", None)
    if buf is None:
        print(line, flush=True)
    else:
        buf.write(line + "\n")

def banner(t): _emit("\n" + _c(f"=== {t} ===", "blu"))
def ok(t):     _emit(_c("[OK]  ", "grn") + t)
def warn(t):   _emit(_c("[WARN]", "yel") + " " + t)
def err(t):    _emit(_c("[ERR] ", "red") + t)
def info(t):   _emit("      " + t)


def run_parallel(jobs: list) -> dict:
    """Run independent phases concurrently. jobs = [(name, callable), ...].

    Phases in one group must not share state or write the same output file.
    Each worker's console output is buffered and replayed whole, so grouping
    costs nothing in readability. A phase that raises is recorded and reported
    rather than taking the whole scan down with it.
    """
    if not jobs:
        return {}
    if len(jobs) == 1:
        name, fn = jobs[0]
        return {name: fn()}
    results = {}

    def work(name, fn):
        _out_sink.buf = io.StringIO()
        try:
            value, error = fn(), None
        except Exception as e:                    # keep sibling phases alive
            value, error = None, e
        finally:
            text = _out_sink.buf.getvalue()
            _out_sink.buf = None
        return name, value, error, text

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(work, n, f) for n, f in jobs]
        for fut in concurrent.futures.as_completed(futures):
            name, value, error, text = fut.result()
            sys.stdout.write(text)
            sys.stdout.flush()
            if error is not None:
                err(f"Phase '{name}' failed: {error}")
            results[name] = value
    return results

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

# ------------------------------------------------------------------ #
#  Scan presets
# ------------------------------------------------------------------ #
# Picking 18 individual phases requires knowing what each one costs. A preset
# answers the only question most users actually have: "how long am I willing
# to wait, and what do I have installed?"
#
# ACTIVE phases that write to the target or forge credentials (token_probe,
# upload, sqlmap_confirm) are never enabled by a preset — they stay explicit
# opt-ins, because "authorised targets only" is a decision, not a default.
PRESETS = {
    "quick": {
        "label": "Quick — no external tools needed (~1-3 min)",
        "desc":  "Built-in crawler plus every pure-Python check: leaked secrets, "
                 "JWT lifetimes, vulnerable JS libraries, CORS, cookie/CSRF flags, "
                 "IDOR. Runs anywhere Python runs.",
        "phases": ["crawl", "secret_scan", "token_analysis", "depscan",
                   "cors", "csrf", "idor_probe"],
        "scan": {"crawler": "builtin", "builtin_max_pages": 120,
                 "builtin_budget_secs": 90},
        "budget_secs": 420,
    },
    "standard": {
        "label": "Standard — adds installed scanners (~10-20 min)",
        "desc":  "Everything in Quick, plus katana deep crawl, the Nuclei template "
                 "pass (CVE / exposure / misconfig) and testssl.sh TLS analysis. "
                 "Each tool is skipped cleanly if it isn't installed.",
        "phases": ["crawl", "secret_scan", "token_analysis", "depscan",
                   "cors", "csrf", "idor_probe", "template_scan", "testssl"],
        "scan": {"crawler": "auto", "builtin_max_pages": 250,
                 "builtin_budget_secs": 180},
        "budget_secs": 1800,
    },
    "authenticated": {
        "label": "Authenticated — logged-in app + broken-auth probe (~15-25 min)",
        "desc":  "Everything in Standard, plus the active broken-authentication "
                 "probe (replays/forges/tampers your token against protected "
                 "endpoints). Needs a session cookie or bearer token — supplying "
                 "one is your authorisation to actively test the logged-in app.",
        "phases": ["crawl", "secret_scan", "token_analysis", "depscan",
                   "cors", "csrf", "idor_probe", "template_scan", "testssl",
                   "token_probe"],
        "scan": {"crawler": "auto", "builtin_max_pages": 250,
                 "builtin_budget_secs": 180},
        "budget_secs": 1800,
    },
    "deep": {
        "label": "Deep — full active assessment (hours)",
        "desc":  "Everything in Standard, plus Nuclei DAST fuzzing, OWASP ZAP "
                 "active scan and Nikto. This sends attack traffic and can take "
                 "several hours. Authorised targets only.",
        "phases": ["crawl", "secret_scan", "token_analysis", "depscan",
                   "cors", "csrf", "idor_probe", "template_scan", "testssl",
                   "fuzz_dast", "zap", "nikto"],
        "scan": {"crawler": "auto", "builtin_max_pages": 400,
                 "builtin_budget_secs": 300},
        "budget_secs": 0,          # 0 = no wall-clock cap
    },
}


def apply_preset(cfg: dict, name: str) -> dict:
    """Overlay a preset onto a config. The preset decides which phases run and
    the crawl/time budget; everything else in the config (target, auth, rate
    limits, tool paths) is left exactly as the user set it."""
    name = (name or "").strip().lower()
    if name not in PRESETS:
        raise SystemExit(f"Unknown preset '{name}'. Choose one of: "
                         + ", ".join(PRESETS))
    p = PRESETS[name]
    known = list(cfg.get("phases", {})) or p["phases"]
    phases = {k: False for k in set(known) | set(p["phases"])}
    for k in p["phases"]:
        phases[k] = True
    cfg["phases"] = phases
    cfg.setdefault("scan", {}).update(p["scan"])
    cfg["preset"] = name

    # A preset turns idor_probe on, so arm the probe itself — phase_idor exits
    # early unless idor.enabled is set, which would make the preset advertise a
    # check it never ran. Victim URLs and second-account headers are cleared
    # because the base config carries whichever target it was last used for,
    # and a preset must never aim a probe at a previous engagement's host.
    # Auto-discovery finds object URLs on the target actually being scanned.
    if "idor_probe" in p["phases"]:
        idc = cfg.setdefault("idor", {})
        idc.update({"enabled": True, "auto_discover": True, "victim_urls": [],
                    "user_a_headers": [], "user_b_headers": []})
        idc.setdefault("similarity_tolerance", 0.15)

    # If a spec was supplied it costs nothing to ingest and only widens coverage,
    # so let it ride along with any preset instead of requiring Custom mode.
    if (cfg.get("api_spec") or {}).get("source"):
        cfg["phases"]["api_spec"] = True
    cfg.setdefault("limits", {})
    # An explicit budget in the config always wins over the preset's default.
    cfg["limits"].setdefault("budget_secs", p["budget_secs"])
    return cfg


# ------------------------------------------------------------------ #
#  Token / JWT analysis  (covers the "non-expiring API key" concern)
# ------------------------------------------------------------------ #
def analyse_token(token: str) -> dict:
    """Decode a JWT (no signature check) and flag lifetime problems.
    Returns a finding dict. Non-JWT opaque tokens are reported as
    'opaque' so you still know a long-lived credential is in play."""
    result = {"token_preview": token[:12] + "...", "type": "opaque",
              "issues": [], "severity": "info", "claims": {}}
    parts = token.split(".")
    if len(parts) != 3:
        # Not a JWT. An opaque static token in frontend code is still a risk.
        result["issues"].append(
            "Opaque static token exposed in client-side code. Cannot verify "
            "expiration; treat as a long-lived public credential.")
        result["severity"] = "high"
        return result
    try:
        pad = lambda s: s + "=" * (-len(s) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    except Exception:
        result["issues"].append("Looks like a JWT but payload could not be decoded.")
        result["severity"] = "low"
        return result

    result["type"] = "jwt"
    result["claims"] = payload
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()

    if "exp" not in payload:
        result["issues"].append(
            "JWT has NO 'exp' claim — this token never expires. A non-expiring "
            "token embedded in frontend code is permanently valid to anyone who "
            "reads the JS. Rotate to short-lived tokens with refresh.")
        result["severity"] = "critical"
    else:
        remaining = payload["exp"] - now
        days = remaining / 86400
        if remaining <= 0:
            result["issues"].append("Token is already expired.")
            result["severity"] = "info"
        elif days > 365:
            result["issues"].append(
                f"Token valid for ~{days:.0f} days (>1 year). Effectively a "
                f"static credential; shorten its lifetime.")
            result["severity"] = "high"
        elif days > 30:
            result["issues"].append(
                f"Token valid for ~{days:.0f} days. Long-lived for a frontend "
                f"token; consider shortening.")
            result["severity"] = "medium"
        else:
            result["issues"].append(f"Token expires in ~{days:.1f} days (reasonable).")
            result["severity"] = "info"

    # Extra hygiene checks
    hdr = {}
    try:
        hdr = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
    except Exception:
        pass
    if hdr.get("alg", "").lower() == "none":
        result["issues"].append("JWT alg is 'none' — signature not enforced. Critical.")
        result["severity"] = "critical"
    if payload.get("role") in ("admin", "superadmin") or payload.get("admin") is True:
        result["issues"].append("Token carries elevated role/privilege in its claims.")
    return result

# secret/token patterns for the frontend leak scan
SECRET_PATTERNS = {
    "AWS Access Key":  r"AKIA[0-9A-Z]{16}",
    "AWS Secret":      r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub PAT":      r"ghp_[0-9A-Za-z]{36}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Google API Key":  r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token":     r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "JWT":             r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}",
    "Generic API key": r"(?i)(api[_\-]?key|apikey|secret|access[_\-]?token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]",
    "Private Key":     r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
}

def scan_text_for_secrets(text: str, source: str) -> list[dict]:
    findings = []
    for name, pat in SECRET_PATTERNS.items():
        for m in re.finditer(pat, text):
            val = m.group(0)
            findings.append({
                "type": name, "source": source,
                "match_preview": (val[:40] + "...") if len(val) > 40 else val,
                "raw": val,
            })
    return findings

# ------------------------------------------------------------------ #
#  Subprocess wrapper
# ------------------------------------------------------------------ #
# Wall-clock deadline for the whole scan (monotonic), or None for no cap.
# Every external tool is clamped to it, otherwise a 150s budget still waits out
# nuclei's 3-hour timeout: gating between phases can't shorten a phase already
# running, but capping the subprocess can.
_SCAN_DEADLINE = None

def _budget_left():
    """Seconds left in the scan budget, or None when uncapped. Floors at 1 so a
    subprocess is never handed a zero/negative timeout."""
    if _SCAN_DEADLINE is None:
        return None
    return max(1, int(_SCAN_DEADLINE - time.monotonic()))


def _budget_spent() -> bool:
    """True once the scan budget is gone. Distinct from _budget_left() == 1,
    which is also true with a second still to go."""
    return _SCAN_DEADLINE is not None and time.monotonic() >= _SCAN_DEADLINE


def run(cmd: list[str], outfile: Path | None = None, timeout=3600) -> tuple[int, str]:
    """Run a command. If outfile given, stdout is streamed to it."""
    left = _budget_left()
    if left is not None and left < timeout:
        info(f"(capping {cmd[0]} at {left}s — scan time budget)")
        timeout = left
    info("$ " + " ".join(str(c) for c in cmd))
    try:
        if outfile:
            with open(outfile, "w", encoding="utf-8", errors="replace") as f:
                p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE,
                                   text=True, timeout=timeout)
        else:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
        if p.stderr and p.returncode != 0:
            info(p.stderr.strip()[:300])
        return p.returncode, (p.stdout if not outfile else "")
    except FileNotFoundError:
        err(f"Tool not found: {cmd[0]}")
        return 127, ""
    except subprocess.TimeoutExpired:
        warn(f"Timed out after {timeout}s: {cmd[0]}")
        return 124, ""

def tool_ok(path: str) -> bool:
    exe = path.split()[0]
    return shutil.which(exe) is not None or Path(exe).exists()

def _nuclei_templates_present() -> bool:
    """Nuclei silently returns 0 findings when templates aren't installed.
    Check the common template locations so we can warn instead."""
    candidates = [
        Path.home() / "nuclei-templates",
        Path.home() / ".config" / "nuclei" / "nuclei-templates",
        Path.home() / "Library" / "Application Support" / "nuclei" / "nuclei-templates",
    ]
    for c in candidates:
        if c.is_dir() and any(c.glob("**/*.yaml")):
            return True
    return False

# ------------------------------------------------------------------ #
#  Resilience — don't hammer a server that's already falling over
# ------------------------------------------------------------------ #
import concurrent.futures, time, urllib.request, urllib.error, urllib.parse

def _http_status(url: str, headers: dict, timeout=10) -> int:
    """Return HTTP status code, or 0 on connection error / timeout."""
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

def _auth_headers_dict(cfg) -> dict:
    hdrs = {}
    auth = cfg.get("auth", {}) or {}
    if auth.get("enabled"):
        for h in auth.get("headers", []):
            if "PASTE_YOUR" in h or ":" not in h:
                continue
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return hdrs

def preflight(cfg) -> bool:
    """Check the target is healthy before we start. Returns False if it's
    already erroring (so we don't generate a garbage report)."""
    r = cfg.get("resilience", {})
    url = r.get("health_url") or ("https://" + cfg["target"]["scope_domain"])
    banner("Pre-flight health check")
    codes = []
    for _ in range(3):
        c = _http_status(url, _auth_headers_dict(cfg), r.get("timeout", 10))
        codes.append(c); time.sleep(1)
    healthy = sum(1 for c in codes if 200 <= c < 400 or c in (401, 403))
    info(f"{url} -> status codes {codes}")
    if healthy == 0:
        warn("Target is not responding healthily (5xx / timeouts). "
             "Aborting — fix the server or lower the rate first.")
        return False
    ok("Target healthy — proceeding")
    return True

class HealthMonitor:
    """Background sampler. While a scan phase runs, it pings the health URL;
    if it sees sustained 5xx/timeouts it records that the scan window was
    unstable, so the report can flag findings from that window as unreliable."""
    def __init__(self, cfg):
        r = cfg.get("resilience", {})
        self.url = r.get("health_url") or ("https://" + cfg["target"]["scope_domain"])
        self.headers = _auth_headers_dict(cfg)
        self.interval = r.get("monitor_interval", 15)
        self.max_consecutive = r.get("max_consecutive_5xx", 5)
        self.timeout = r.get("timeout", 10)
        self._stop = threading.Event()
        self._thread = None
        self.unstable = False
        self.consecutive = 0
        self.samples = []

    def _run(self):
        while not self._stop.is_set():
            c = _http_status(self.url, self.headers, self.timeout)
            self.samples.append(c)
            if c == 0 or c >= 500:
                self.consecutive += 1
                if self.consecutive >= self.max_consecutive:
                    if not self.unstable:
                        warn(f"Server instability detected ({self.consecutive} "
                             f"consecutive 5xx/timeouts) — findings from this "
                             f"window may be unreliable.")
                    self.unstable = True
            else:
                self.consecutive = 0
            self._stop.wait(self.interval)

    def start(self):
        if self._thread: return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

# ------------------------------------------------------------------ #
#  Phases
# ------------------------------------------------------------------ #
def header_args(cfg, flag="-H"):
    out = []
    if cfg["auth"].get("enabled"):
        for h in cfg["auth"].get("headers", []):
            if "PASTE_YOUR" in h:
                continue  # skip unfilled placeholders
            out += [flag, h]
    return out

# ------------------------------------------------------------------ #
#  Built-in crawler — zero external dependencies
# ------------------------------------------------------------------ #
# Katana is a Go binary most users don't have. Without it every
# endpoint-driven phase (triage, fuzz, secrets, depscan, IDOR, CORS, CSRF)
# gets an empty input and silently finds nothing — so "no tools installed"
# looked like "clean app". This crawler removes that cliff: it uses only the
# standard library and emits the SAME urls.jsonl schema katana does, so every
# downstream phase consumes it unchanged.
_CRAWL_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 DAST-Harness/1.0")
_CRAWL_MAX_BYTES = 2_000_000          # don't pull whole video/bundle blobs into RAM
_HREF_RE  = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)["']""", re.I)
_ABS_RE   = re.compile(r"""["'](https?://[^"'\s<>]{4,300})["']""")
_SCHEME_SKIP_RE = re.compile(r"^(?:mailto|tel|javascript|data|blob|ftp|sms):", re.I)
# Unrendered template markers — `${...}` from JS template literals, `{{...}}`
# from Vue/Angular/Handlebars, `<%...%>` from server templates. These are not
# real URLs; fetching them burns requests and pollutes the endpoint list with
# guaranteed 404s.
_TEMPLATE_RE = re.compile(r"\$\{|\{\{|\}\}|<%|%>|__[A-Z_]+__")
# Binary assets carry no links and no secrets — never worth a request.
_BIN_SKIP_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|mp4|mp3|wav|avi|mov|"
    r"zip|rar|7z|gz|tgz|pdf|docx?|xlsx?|pptx?)(?:\?|#|$)", re.I)


class _RateLimiter:
    """Pacer shared across crawler threads.

    Concurrency without this multiplies the request rate at the target, which
    is exactly what trips WAF/CDN rate rules (and what `resilience:` exists to
    avoid). Threads speed up waiting on I/O, not hammering the server.
    """
    def __init__(self, per_sec: float):
        self.interval = 1.0 / max(float(per_sec), 0.1)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.interval
        if delay:
            time.sleep(delay)


def _crawl_norm(url: str) -> str:
    """Normalise for dedup: drop the fragment, keep the query (params are the
    whole point of an endpoint list), and strip a trailing slash."""
    try:
        u, _ = urllib.parse.urldefrag(url)
    except Exception:
        u = url
    return u.rstrip("/") or u


def _crawl_get(url: str, headers: dict, timeout: int):
    """GET a URL. Returns (status, content_type, body). Never raises —
    a dead link must not abort the crawl."""
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(_CRAWL_MAX_BYTES).decode("utf-8", "replace")
            return r.status, r.headers.get("Content-Type", ""), body
    except urllib.error.HTTPError as e:
        # 4xx/5xx bodies still carry links and error detail worth keeping.
        try:
            body = e.read(_CRAWL_MAX_BYTES).decode("utf-8", "replace")
            ctype = e.headers.get("Content-Type", "") if e.headers else ""
        except Exception:
            body, ctype = "", ""
        return e.code, ctype, body
    except Exception:
        return 0, "", ""


def _extract_links(base_url: str, body: str, is_js: bool) -> list[str]:
    """Pull candidate URLs out of a response body.

    HTML: href/src/action attributes, resolved against the page URL.
    JS:   absolute http(s) URLs in string literals — this is where SPA API
          routes live, and the only reason to fetch bundles at all.
    """
    found = []
    if is_js:
        found += _ABS_RE.findall(body)
    else:
        for raw in _HREF_RE.findall(body):
            raw = raw.strip()
            if not raw or raw.startswith("#") or _SCHEME_SKIP_RE.match(raw):
                continue
            try:
                found.append(urllib.parse.urljoin(base_url, raw))
            except Exception:
                continue
        found += _ABS_RE.findall(body)          # inline <script> API calls
    return found


def phase_crawl_builtin(cfg, d: Path) -> Path:
    """Dependency-free crawl. Bounded by pages, depth AND wall-clock, so it
    always terminates and always leaves usable output behind."""
    banner("Crawl — built-in crawler (no external tools required)")
    s = cfg.get("scan", {}) or {}
    scope = cfg["target"]["scope_domain"]
    headers = dict(_auth_headers_dict(cfg))
    headers.setdefault("User-Agent", _CRAWL_UA)
    headers.setdefault("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

    max_pages = int(s.get("builtin_max_pages", 150))
    max_depth = int(s.get("builtin_max_depth", min(int(s.get("crawl_depth", 5) or 5), 3)))
    budget    = float(s.get("builtin_budget_secs", 120))
    max_js    = int(s.get("builtin_max_js", 25))
    timeout   = int(s.get("request_timeout", 10))
    workers   = max(1, min(int(s.get("concurrency", 5) or 5), 12))
    limiter   = _RateLimiter(s.get("rate_limit", 10))

    seeds_file = d / "seeds.txt"
    if cfg["target"].get("seeds_file"):
        shutil.copy(cfg["target"]["seeds_file"], seeds_file)
        seeds = [l.strip() for l in seeds_file.read_text().splitlines() if l.strip()]
    else:
        seeds = [u for u in cfg["target"]["seeds"] if u]
        seeds_file.write_text("\n".join(seeds) + "\n")

    out = d / "crawl" / "urls.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)

    records: dict[str, dict] = {}     # normalised url -> katana-shaped record
    seen: set[str] = set()
    js_budget = [max_js]
    deadline = time.monotonic() + budget

    def note(url: str, **extra):
        """Record an in-scope URL whether or not we ever fetch it — triage
        wants the parameterised ones regardless."""
        if not url.startswith("http") or not _host_in_scope(url, scope):
            return None
        if _TEMPLATE_RE.search(url):
            return None
        key = _crawl_norm(url)
        rec = records.get(key)
        if rec is None:
            rec = {"endpoint": url, "method": "GET", "source": "builtin-crawler"}
            records[key] = rec
        rec.update({k: v for k, v in extra.items() if v not in (None, "")})
        return key

    frontier = []
    for u in seeds:
        k = note(u)
        if k and k not in seen:
            seen.add(k)
            frontier.append(u)
    if not frontier:
        warn(f"No seed URL is inside scope '{scope}' — nothing to crawl.")
        out.write_text("")
        return out

    def visit(url: str):
        if time.monotonic() > deadline:
            return url, 0, "", ""
        limiter.wait()
        st, ctype, body = _crawl_get(url, headers, timeout)
        return url, st, ctype, body

    fetched = 0
    for depth in range(max_depth + 1):
        if not frontier or fetched >= max_pages or time.monotonic() > deadline:
            break
        batch, frontier = frontier[:max_pages - fetched], []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for url, st, ctype, body in pool.map(visit, batch):
                fetched += 1
                is_js = url.lower().split("?")[0].endswith(".js") or "javascript" in ctype.lower()
                note(url, status=st, content_type=ctype)
                if not body or st == 0:
                    continue
                for cand in _extract_links(url, body, is_js):
                    key = note(cand)
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    low = cand.lower().split("?")[0]
                    if _BIN_SKIP_RE.search(cand):
                        continue                      # recorded, never fetched
                    if low.endswith(".js"):
                        if js_budget[0] <= 0:
                            continue
                        js_budget[0] -= 1
                    if depth < max_depth:
                        frontier.append(cand)

    with open(out, "w", encoding="utf-8") as w:
        for rec in records.values():
            w.write(json.dumps(rec) + "\n")

    if time.monotonic() > deadline:
        warn(f"Crawl budget ({budget:.0f}s) reached — reporting what was found so far.")
    if not records:
        warn("Built-in crawl found 0 in-scope URLs. If the app is a JS-rendered SPA "
             "behind a login wall, install katana and re-run for deeper discovery.")
    ok(f"Crawled {fetched} pages, recorded {len(records)} in-scope URLs -> {out.name}")
    return out

def phase_crawl(cfg, d: Path) -> Path:
    banner("Crawl — Katana")
    seeds_file = d / "seeds.txt"
    if cfg["target"].get("seeds_file"):
        shutil.copy(cfg["target"]["seeds_file"], seeds_file)
    else:
        seeds_file.write_text("\n".join(cfg["target"]["seeds"]) + "\n")
    out = d / "crawl" / "urls.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    # Bounded crawl: JS-heavy SPAs (large _next/static bundles under -jsluice) can
    # balloon katana's memory until the OS SIGKILLs it (exit 137), or stall on
    # redirect/auth walls and never terminate. A crawl-duration ceiling + per-request
    # timeout + rate limit make katana exit GRACEFULLY with whatever it captured,
    # so downstream phases still get targets instead of an empty file.
    s = cfg["scan"]
    cmd = [cfg["tools"]["katana"], "-list", str(seeds_file),
           "-js-crawl", "-jsluice",
           "-depth", str(s["crawl_depth"]),
           "-crawl-duration", str(s.get("crawl_duration", "10m")),
           "-timeout", str(s.get("request_timeout", 10)),
           "-rate-limit", str(s.get("rate_limit", 10)),
           "-concurrency", str(s.get("crawl_concurrency", 5)),
           "-jsonl", "-o", str(out),
           "-fs", "fqdn"]  # keep crawl within the seed's FQDN
    cmd += header_args(cfg, "-H")
    rc, _ = run(cmd, timeout=7200)
    n = sum(1 for _ in open(out)) if out.exists() else 0
    if n == 0:
        warn("Crawl captured 0 endpoints. Common causes: target behind a login wall, "
             "a JS-rendered SPA with no server-side links, or katana killed (OOM). "
             "Downstream endpoint-based phases will have nothing to scan — host-level "
             "phases (TLS/Nikto/templates) still run against the base URL.")
    ok(f"Crawled {n} endpoints -> {out.name}")
    return out

def triage_endpoints(cfg, crawl_jsonl: Path, d: Path) -> Path:
    """Keep in-scope + security-interesting endpoints, preserving JSONL
    (params + bodies) so the fuzzer has something to mutate."""
    banner("Triage — selecting security-relevant endpoints")
    scope = cfg["target"]["scope_domain"]
    kws = [k.lower() for k in cfg["scan"]["interesting_keywords"]]
    asset_re = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|mp3|avi|mov|pdf|zip|rar|7z)(\?|$)", re.I)
    out = d / "crawl" / "urls-security.jsonl"
    kept = 0
    with open(out, "w") as w:
        for line in _iter_jsonl(crawl_jsonl):
            url = _url_of(line)
            if not url:
                continue
            if not _host_in_scope(url, scope):
                continue
            has_param = ("?" in url) or bool(_body_of(line))
            interesting = any(k in url.lower() for k in kws)
            # keep JS assets aside for the secret scan, drop other static
            if asset_re.search(url) and not url.lower().endswith(".js"):
                continue
            if interesting or has_param:
                w.write(json.dumps(line) + "\n")
                kept += 1
    ok(f"Kept {kept} security-relevant endpoints -> {out.name}")
    return out

def phase_fuzz_dast(cfg, endpoints: Path, d: Path) -> Path:
    banner("Nuclei DAST — fuzzing for injection (SQLi/XSS/SSTI/LFI/SSRF/RCE...)")
    out = d / "reports" / "dast.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    scope = cfg["target"]["scope_domain"]
    targets, n = _build_nuclei_list(endpoints, scope)
    ok(f"Prepared {n} unique in-scope target(s) -> {targets.name}")
    if n == 0:
        warn("No in-scope targets after dedup/scope filter — skipping DAST.")
        out.touch()
        return out
    cmd = [cfg["tools"]["nuclei"], "-l", str(targets),
           "-dast",
           "-tags", ",".join(cfg["scan"]["dast_tags"]),
           "-rl", str(cfg["scan"]["rate_limit"]),
           "-c", str(cfg["scan"]["concurrency"]),
           "-jsonl", "-o", str(out)]
    cmd += header_args(cfg, "-H")
    run(cmd, timeout=10800)
    ok(f"DAST results -> {out.name}")
    return out

def phase_template_scan(cfg, endpoints: Path, d: Path) -> Path:
    banner("Nuclei templates — CVEs / exposures / misconfig / headers")
    out = d / "reports" / "templates.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    scope = cfg["target"]["scope_domain"]
    targets, n = _build_nuclei_list(endpoints, scope)
    if n == 0:
        # Template scanning (tech/version/headers/TLS/CVE) is valuable even with an
        # empty crawl — the base URL alone reveals the server/framework version and
        # header/cookie posture. Fall back to the seed/base URL instead of skipping.
        base = cfg["target"].get("seeds") or ["https://" + scope]
        targets.write_text("\n".join(base) + "\n")
        n = len(base)
        warn(f"Crawl empty — falling back to base URL(s) for template scan ({n} target).")
    ok(f"Prepared {n} unique in-scope target(s) -> {targets.name}")
    cmd = [cfg["tools"]["nuclei"], "-l", str(targets),
           "-tags", ",".join(cfg["scan"]["template_tags"]),
           "-severity", "critical,high,medium,low,info",
           "-rl", str(cfg["scan"]["rate_limit"]),
           "-c", str(cfg["scan"]["concurrency"]),
           "-jsonl", "-o", str(out)]
    cmd += header_args(cfg, "-H")
    run(cmd, timeout=10800)
    ok(f"Template results -> {out.name}")
    return out

def phase_secret_scan(cfg, crawl_jsonl: Path, d: Path) -> list[dict]:
    banner("Secret scan — leaked keys/tokens in frontend JS")
    findings, seen = [], set()
    js_urls = [ _url_of(l) for l in _iter_jsonl(crawl_jsonl)
               if _url_of(l) and _url_of(l).lower().split("?")[0].endswith(".js") ]
    info(f"Fetching {len(js_urls)} JS files for inspection")
    try:
        import urllib.request
        hdrs = {}
        for h in cfg["auth"].get("headers", []) if cfg["auth"].get("enabled") else []:
            if "PASTE_YOUR" in h or ":" not in h:
                continue
            k, v = h.split(":", 1); hdrs[k.strip()] = v.strip()
        for u in js_urls[:200]:
            try:
                req = urllib.request.Request(u, headers=hdrs)
                body = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
            except Exception:
                continue
            for f in scan_text_for_secrets(body, u):
                key = (f["type"], f["raw"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)
    except Exception as e:
        warn(f"Secret scan limited: {e}")
    ok(f"Found {len(findings)} candidate secret(s) in frontend")
    return findings

def phase_token_analysis(cfg, secret_findings: list[dict], d: Path) -> list[dict]:
    banner("Token analysis — expiration & lifetime of exposed tokens")
    results = []
    # analyse any JWTs found in JS ...
    for f in secret_findings:
        if f["type"] == "JWT":
            results.append({"where": f["source"], **analyse_token(f["raw"])})
    # ... and any token supplied in auth headers (your team's frontend key)
    if cfg["auth"].get("enabled"):
        for h in cfg["auth"].get("headers", []):
            if "PASTE_YOUR" in h:
                continue
            m = re.search(r"(?:Bearer|token=)\s*([A-Za-z0-9_\-\.]{20,})", h)
            if m:
                results.append({"where": "auth header (configured token)",
                                **analyse_token(m.group(1))})
    for r in results:
        sev = r["severity"].upper()
        (err if sev in ("CRITICAL", "HIGH") else info)(
            f"{sev}: {r['where']} — {r['issues'][0] if r['issues'] else ''}")
    ok(f"Analysed {len(results)} token(s)")
    return results

def phase_sqlmap(cfg, dast_jsonl: Path, d: Path) -> list[dict]:
    banner("Optional  sqlmap — confirming SQLi and measuring data-exposure impact")
    hits, confirmed = [], []
    for l in _iter_jsonl(dast_jsonl):
        tid = (l.get("template-id") or l.get("templateID") or "").lower()
        if "sqli" in tid or "sql-injection" in tid:
            u = l.get("matched-at") or l.get("host") or ""
            if u:
                hits.append(u)
    hits = list(dict.fromkeys(hits))[:10]
    info(f"{len(hits)} candidate SQLi URL(s) to confirm")
    sq = cfg.get("sqlmap", {})
    outdir = d / "reports" / "sqlmap"; outdir.mkdir(parents=True, exist_ok=True)
    for u in hits:
        cmd = cfg["tools"]["sqlmap"].split() + ["-u", u, "--batch",
              "--level", str(sq.get("level", 2)), "--risk", str(sq.get("risk", 1)),
              "--flush-session", "--output-dir", str(outdir)]
        # Data-extraction depth — only for demonstrating impact on YOUR OWN app.
        if sq.get("enumerate", False):
            cmd += ["--dbs", "--tables"]           # list databases + tables
        if sq.get("dump_table"):                   # dump one named table as evidence
            cmd += ["--dump", "-T", sq["dump_table"]]
        if sq.get("current_user", True):
            cmd += ["--current-user", "--current-db", "--is-dba"]
        if cfg["auth"].get("enabled"):
            for h in cfg["auth"].get("headers", []):
                if "PASTE_YOUR" not in h:
                    cmd += ["--header", h]
        rc, out = run(cmd, timeout=sq.get("timeout", 1800))
        vulnerable = "is vulnerable" in out or "sqlmap identified" in out.lower()
        extracted = "Database:" in out or "Table:" in out
        confirmed.append({"url": u, "vulnerable": vulnerable, "extracted": extracted})
    n_ok = sum(1 for c in confirmed if c["vulnerable"])
    ok(f"sqlmap confirmed {n_ok}/{len(confirmed)} injectable")
    return confirmed

def _docker_mem_gb():
    """Docker Desktop VM total memory in GiB, or None if docker is unavailable."""
    try:
        out = subprocess.run(["docker", "info", "--format", "{{.MemTotal}}"],
                             capture_output=True, text=True, timeout=15)
        b = int(out.stdout.strip())
        return b / (1024 ** 3) if b > 0 else None
    except Exception:
        return None

def _auto_heap(vm_gb):
    """JVM max heap sized to the Docker VM: ~45%, clamped to 2-6g. Leaves room
    for ZAP non-heap memory, the wrapper client, an AJAX browser, and the VM
    overhead so the daemon is not OOM-killed mid-scan."""
    if not vm_gb:
        return "4g"
    return f"{max(2, min(6, round(vm_gb * 0.45)))}g"

def _auto_cmem(vm_gb):
    """Container memory cap (-m): ~75% of the VM, clamped to 3-12g, so Docker
    enforces a boundary (clean OOM) without starving the VM itself."""
    if not vm_gb:
        return None
    return f"{max(3, min(12, int(vm_gb * 0.75)))}g"

def phase_zap(cfg, d: Path) -> Path:
    """OWASP ZAP full scan — spider + AJAX spider + active scanner.
    The active scanner fires ZAP's whole attack-payload set at every
    discovered endpoint (this is the 'test all the cases' engine)."""
    banner("ZAP — full active scan (spider + AJAX + active attack rules)")
    z = cfg.get("zap", {})
    target = z.get("target") or ("https://" + cfg["target"]["scope_domain"])
    out_json = d / "reports" / "zap.json"
    out_html = d / "reports" / "zap.html"
    mode = z.get("mode", "full")           # full | baseline | api
    script = {"full": "zap-full-scan.py", "baseline": "zap-baseline.py",
              "api": "zap-api-scan.py"}[mode]

    vm_gb = heap = mem = None
    if z.get("use_docker", True):
        # Current image (old owasp/zap2docker-* is retired).
        wrk = out_json.parent.resolve()
        # Size the JVM heap AND add a container memory cap so a full active scan
        # cannot push the JVM past the Docker VM ceiling. That OOM kills the ZAP
        # daemon mid-scan and surfaces as "Unable to connect to proxy" /
        # "connection reset by peer". Defaults auto-derive from the Docker VM.
        vm_gb = _docker_mem_gb()
        heap = z.get("jvm_heap") or _auto_heap(vm_gb)
        mem = z.get("docker_memory") or _auto_cmem(vm_gb)
        docker_flags = ["docker", "run", "--rm",
                        "-e", f"ZAP_JVM_OPTIONS=-Xmx{heap}",
                        "-v", f"{wrk}:/zap/wrk/:rw"]
        if mem:
            docker_flags += ["-m", str(mem)]
        if z.get("ajax_spider", True) and mode == "full":
            # The AJAX spider launches a headless browser; the default 64m
            # /dev/shm crashes it. Give it real shared memory.
            docker_flags += ["--shm-size", str(z.get("shm_size", "1g"))]
        cmd = docker_flags + [
               z.get("docker_image", "zaproxy/zap-stable"),
               script, "-t", target,
               "-J", out_json.name, "-r", out_html.name]
        if mode == "api":
            cmd += ["-f", z.get("api_format", "openapi")]
        if z.get("ajax_spider", True) and mode == "full":
            cmd += ["-j"]
        # authenticated scan: inject a header via ZAP's replacer rule
        for h in cfg["auth"].get("headers", []) if cfg["auth"].get("enabled") else []:
            if "PASTE_YOUR" in h or ":" not in h:
                continue
            k, v = h.split(":", 1)
            cmd += ["-z",
                    f"replacer.full_list(0).description=auth "
                    f"replacer.full_list(0).enabled=true "
                    f"replacer.full_list(0).matchtype=REQ_HEADER "
                    f"replacer.full_list(0).matchstr={k.strip()} "
                    f"replacer.full_list(0).replacement={v.strip()}"]
        cmd += z.get("extra_args", [])
    else:
        # Local ZAP install via zap.sh automation-framework plan (see zap-plan.yaml)
        cmd = [cfg["tools"].get("zap", "zap.sh"), "-cmd",
               "-autorun", z.get("plan", "zap-plan.yaml")]

    rc, _ = run(cmd, timeout=z.get("timeout", 10800))
    # A complete run writes a real JSON report. If it's missing/tiny, ZAP
    # crashed mid-scan (usually OOM or the AJAX-spider browser dying) — say so
    # instead of a misleading [OK].
    if out_json.exists() and out_json.stat().st_size > 50:
        ok(f"ZAP report -> {out_json.name} (+ {out_html.name})")
    else:
        docker = z.get("use_docker", True)
        vm_txt = f"{vm_gb:.1f}g" if (docker and vm_gb) else "unknown"
        detail = (f" [heap={heap}, container mem={mem or 'unset'}, "
                  f"Docker VM~={vm_txt}]" if docker else "")
        if rc == 137:
            warn("ZAP container was OOM-killed (exit 137)." + detail +
                 " Lower zap.jvm_heap, raise Docker Desktop memory "
                 "(Settings > Resources > Memory), or switch zap.mode to "
                 "baseline/api for backend/API targets.")
        else:
            warn("ZAP did not produce a complete report — it likely crashed or "
                 "ran out of memory mid-scan (the 'connection reset by peer' "
                 "error)." + detail + " Fixes: lower zap.jvm_heap so heap+browser "
                 "fit the Docker VM, raise Docker Desktop memory, set "
                 "zap.ajax_spider: false, or use zap.mode: baseline/api.")
    return out_json

def phase_nikto(cfg, d: Path) -> Path:
    """Nikto — web-SERVER scanner: dangerous files, outdated software,
    server misconfig. Complements the app-layer tools."""
    banner("Nikto — web server scan (dangerous files / outdated / misconfig)")
    out = d / "reports" / "nikto.json"
    host = cfg.get("nikto", {}).get("host") or ("https://" + cfg["target"]["scope_domain"])
    cmd = [cfg["tools"].get("nikto", "nikto"), "-h", host,
           "-Format", "json", "-output", str(out),
           "-maxtime", str(cfg.get("nikto", {}).get("maxtime", "30m")),
           "-nointeractive"]
    if cfg["auth"].get("enabled"):
        for h in cfg["auth"].get("headers", []):
            if "PASTE_YOUR" not in h:
                # Nikto sends arbitrary headers one per flag: none native; use -useproxy
                pass
    tuning = cfg.get("nikto", {}).get("tuning")
    if tuning:
        cmd += ["-Tuning", str(tuning)]
    run(cmd, timeout=cfg.get("nikto", {}).get("timeout", 3600))
    # Newer Nikto appends ".json" to -output, producing nikto.json.json.
    # Return whichever file actually got written so its findings aren't dropped.
    produced = out
    alt = Path(str(out) + ".json")
    if not out.exists() and alt.exists():
        produced = alt
    ok(f"Nikto report -> {produced.name}")
    return produced

def parse_zap(path: Path) -> list[dict]:
    RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    findings = []
    if not Path(path).exists():
        return findings
    try:
        data = json.load(open(path))
    except Exception:
        return findings
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            insts = a.get("instances", []) or [{}]
            findings.append({
                "category": "ZAP (app scanner)",
                "name": a.get("alert") or a.get("name", ""),
                "severity": RISK.get(str(a.get("riskcode", "0")), "info"),
                "location": insts[0].get("uri") or site.get("@name", ""),
                "detail": f"param={insts[0].get('param','')} plugin={a.get('pluginid','')}",
                "cweid": a.get("cweid", ""),
            })
    return findings

def parse_nikto(path: Path) -> list[dict]:
    findings = []
    if not Path(path).exists():
        return findings
    try:
        data = json.load(open(path))
    except Exception:
        return findings
    hosts = data if isinstance(data, list) else [data]
    for h in hosts:
        for v in h.get("vulnerabilities", []):
            msg = v.get("msg", "")
            sev = "medium" if any(k in msg.lower()
                                  for k in ("outdated", "vulnerable", "cve")) else "low"
            findings.append({
                "category": "Nikto (web server)",
                "name": msg[:90],
                "severity": sev,
                "location": h.get("host", "") + v.get("url", ""),
                "detail": f"method={v.get('method','GET')} id={v.get('id','')}",
            })
    return findings

def phase_testssl(cfg, d: Path) -> Path:
    """testssl.sh — deep TLS/crypto assessment (OWASP A02 / ASVS V12).
    Surface TLS checks in ZAP/Nuclei don't cover protocol/cipher depth."""
    banner("testssl.sh — deep TLS / cipher / certificate assessment")
    out = d / "reports" / "testssl.json"
    host = cfg.get("testssl", {}).get("host") or cfg["target"]["scope_domain"]
    cmd = [cfg["tools"].get("testssl", "testssl.sh"),
           "--jsonfile", str(out), "--quiet", "--color", "0",
           "--severity", cfg.get("testssl", {}).get("min_severity", "LOW"),
           host]
    run(cmd, timeout=cfg.get("testssl", {}).get("timeout", 1800))
    ok(f"testssl report -> {out.name}")
    return out

def parse_testssl(path: Path) -> list[dict]:
    """testssl.sh JSON is a flat list of {id, severity, finding, cve, ...}."""
    SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
           "LOW": "low", "WARN": "low", "INFO": "info", "OK": None}
    findings = []
    if not Path(path).exists():
        return findings
    try:
        data = json.load(open(path))
    except Exception:
        return findings
    items = data if isinstance(data, list) else data.get("scanResult", data)
    if isinstance(items, dict):
        items = [items]
    for it in items:
        sev = SEV.get(str(it.get("severity", "INFO")).upper(), "info")
        if sev is None:            # skip "OK" / passing lines
            continue
        findings.append({
            "category": "TLS (testssl.sh)",
            "name": (it.get("id", "") + ": " + it.get("finding", ""))[:100],
            "severity": sev,
            "location": f"{it.get('ip','')}:{it.get('port','')}",
            "detail": (it.get("cve") or it.get("finding") or "")[:150],
        })
    return findings

def phase_idor(cfg, endpoints: Path, d: Path, crawl_jsonl: Path | None = None) -> list[dict]:
    """Broken-access-control / IDOR probe (OWASP A01 / ASVS V8).

    Two modes, chosen automatically:
      • Two accounts (user_a_headers + user_b_headers): full cross-read — fetch
        each victim URL as B (baseline), as A, and anonymously; flag if A or anon
        can read B's resource (missing object-level authorization).
      • One account (or just the main configured auth): authed-vs-anon — flag any
        object URL that an UNAUTHENTICATED request can still read (missing authN).

    Victim URLs can be listed in config OR auto-discovered from the crawl
    (endpoints with numeric/UUID object ids). This is the class no template
    scanner catches."""
    banner("IDOR / access-control probe")
    idc = cfg.get("idor", {})
    if not idc.get("enabled"):
        info("IDOR probe disabled (set idor.enabled). Skipping.")
        return []

    def hdrs(lst):
        out = {}
        for h in lst or []:
            if "PASTE_YOUR" in h or ":" not in h:
                continue
            k, v = h.split(":", 1); out[k.strip()] = v.strip()
        return out

    # Account A = explicit user_a_headers, else the main configured auth headers.
    ha = hdrs(idc.get("user_a_headers")) or _auth_headers_dict(cfg)
    hb = hdrs(idc.get("user_b_headers"))          # optional second account
    tol = idc.get("similarity_tolerance", 0.15)

    # Victim URLs: config list + (optionally) auto-discovered from the crawl.
    test_urls = list(idc.get("victim_urls", []) or [])
    if idc.get("auto_discover", True):
        src = crawl_jsonl if (crawl_jsonl and Path(crawl_jsonl).exists()) else endpoints
        disc = discover_idor_candidates(src, cfg["target"]["scope_domain"])
        info(f"Auto-discovered {len(disc)} candidate object URL(s) from the crawl")
        test_urls += [u for u in disc if u not in test_urls]

    if not test_urls:
        info("No victim/object URLs to test (none configured or discovered).")
        return []

    two_account = bool(hb)
    if not two_account and not ha:
        # No auth at all: an "authenticated" request is identical to anonymous,
        # so we can't tell missing-authz from a legitimately public resource.
        info("Authed-vs-anon needs auth headers to distinguish from anonymous; "
             "none configured. Skipping (add a cookie/token, or two accounts).")
        return []
    results = []
    for u in test_urls:
        body_anon, code_anon = _fetch(u, {})
        lan = len(body_anon or "")
        if two_account:
            body_b, code_b = _fetch(u, hb)
            body_a, code_a = _fetch(u, ha)
            lb, la = len(body_b or ""), len(body_a or "")
            a_reads = code_a == 200 and lb > 0 and abs(la - lb) <= tol * lb
            anon_reads = code_anon == 200 and lb > 0 and abs(lan - lb) <= tol * lb
            who = []
            if a_reads: who.append("other authenticated user")
            if anon_reads: who.append("unauthenticated")
            codes = {"B": code_b, "A": code_a, "anon": code_anon}
        else:
            # authed-vs-anon: A is the legitimate owner; if anon reads the same
            # object, object-level authentication is missing.
            body_a, code_a = _fetch(u, ha)
            la = len(body_a or "")
            anon_reads = code_anon == 200 and la > 0 and abs(lan - la) <= tol * la
            who = ["unauthenticated"] if anon_reads else []
            codes = {"A": code_a, "anon": code_anon}
        verdict = "VULNERABLE" if who else "ok"
        results.append({"url": u, "verdict": verdict, "codes": codes, "who": who})
        (err if verdict == "VULNERABLE" else info)(
            f"{verdict}: {u}  {codes}"
            + (f"  <- readable by {', '.join(who)}" if who else ""))
    mode = "2-account cross-read" if two_account else "authed-vs-anonymous"
    ok(f"IDOR probe ({mode}) checked {len(test_urls)} object URL(s)")
    return results

def _fetch(url: str, headers: dict, timeout=15):
    if _budget_spent():
        return "", 0
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace"), r.status
    except urllib.error.HTTPError as e:
        try: body = e.read().decode("utf-8", "replace")
        except Exception: body = ""
        return body, e.code
    except Exception:
        return "", 0



def _iter_jsonl(p: Path):
    if not p or not Path(p).exists():
        return
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue

def _url_of(obj) -> str:
    if isinstance(obj, str):
        return obj
    for k in ("endpoint", "url", "matched-at", "host", "request"):
        v = obj.get(k)
        if isinstance(v, str) and v.startswith("http"):
            return v
    req = obj.get("request")
    if isinstance(req, dict):
        return req.get("endpoint") or req.get("url") or ""
    return ""

def _body_of(obj) -> str:
    if isinstance(obj, dict):
        req = obj.get("request")
        if isinstance(req, dict):
            return req.get("body") or ""
        return obj.get("body") or ""
    return ""

def _host_in_scope(url: str, scope: str) -> bool:
    """True only when the URL's HOST equals scope or is a subdomain of it.
    A substring test on the whole URL is unsafe: an off-scope host can carry
    the scope string inside a query param (e.g. an OAuth redirect_uri), which
    let third-party hosts (google/facebook) leak into the active scan set."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    scope = (scope or "").lower().strip()
    # Tolerate a port in the configured scope ("example.com:8443"); the host we
    # compare against never has one, so an unstripped port matches nothing.
    if ":" in scope and not scope.startswith("["):
        scope = scope.rsplit(":", 1)[0]
    if not host or not scope:
        return False
    return host == scope or host.endswith("." + scope)

def _build_nuclei_list(endpoints: Path, scope: str) -> tuple[Path, int]:
    """Convert the katana-style security JSONL into a deduped, in-scope, flat
    URL list that nuclei ingests in its default list mode. Nuclei's `-im jsonl`
    expects a different schema than katana emits, so feeding the raw JSONL loads
    zero targets and silently produces empty output. Returns (path, count)."""
    seen, urls = set(), []
    for line in _iter_jsonl(endpoints):
        u = _url_of(line)
        if not u or not u.startswith("http"):
            continue
        if not _host_in_scope(u, scope):
            continue
        if u in seen:
            continue
        seen.add(u)
        urls.append(u)
    out = endpoints.parent / "urls-nuclei.txt"
    with open(out, "w", encoding="utf-8") as w:
        w.write("\n".join(urls) + ("\n" if urls else ""))
    return out, len(urls)

def _http_get(url: str, headers: dict, timeout=15):
    """GET a URL. Returns (status, headers_dict, body_text). 0 status on error."""
    if _budget_spent():
        return 0, {}, ""
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        try:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
            body = e.read().decode("utf-8", "replace")
        except Exception:
            hdrs, body = {}, ""
        return e.code, hdrs, body
    except Exception:
        return 0, {}, ""

# ------------------------------------------------------------------ #
#  GAP-FILLER 1: Frontend dependency vulnerability scan (black-box SCA)
#  Fingerprints JS libraries actually loaded by the app and flags known-
#  vulnerable versions. This is the black-box equivalent of SCA — it maps to
#  OWASP A06 (Vulnerable & Outdated Components), the biggest DAST blind spot.
#  Uses retire.js if installed; otherwise a curated signature check.
# ------------------------------------------------------------------ #
# Which libraries to look for, and how to read their version from a URL/content.
JS_LIB_DETECT = {
    "jquery": [r"jquery[.\-]?v?(\d+\.\d+(?:\.\d+)?)",
               r"jQuery JavaScript Library v(\d+\.\d+(?:\.\d+)?)",
               r"/\*!\s*jQuery v(\d+\.\d+(?:\.\d+)?)"],
    "jquery-ui": [r"jquery[.\-]ui[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
    "bootstrap": [r"bootstrap[.\-]?v?(\d+\.\d+(?:\.\d+)?)",
                  r"Bootstrap v(\d+\.\d+(?:\.\d+)?)"],
    "angular": [r"angular[.\-](?:js[.\-])?v?(\d+\.\d+(?:\.\d+)?)",
                r"full\s*[:=]\s*[\"'](\d+\.\d+\.\d+)[\"']"],
    "lodash": [r"lodash[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
    "underscore": [r"underscore[.\-]?v?(\d+\.\d+(?:\.\d+)?)",
                   r"Underscore\.js (\d+\.\d+\.\d+)"],
    "moment": [r"moment[.\-]?v?(\d+\.\d+(?:\.\d+)?)",
               r"//!\s*version\s*:\s*(\d+\.\d+\.\d+)"],
    "handlebars": [r"handlebars[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
    "dompurify": [r"purify[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
    "axios": [r"axios[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
    "vue": [r"vue[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
    "react": [r"react[.\-]?v?(\d+\.\d+(?:\.\d+)?)"],
}
# Curated known-vulnerable ranges. "atleast" bounds a range so e.g. Bootstrap
# 4.x issues don't also flag 3.x. Honest, high-confidence subset — not exhaustive.
JS_LIB_VULNS = [
    {"lib": "jquery", "below": "1.9.0", "sev": "high",
     "ref": "CVE-2011-4969 / CVE-2012-6708", "desc": "jQuery <1.9 — multiple XSS / selector injection"},
    {"lib": "jquery", "atleast": "1.9.0", "below": "3.5.0", "sev": "medium",
     "ref": "CVE-2020-11022 / CVE-2020-11023", "desc": "jQuery <3.5 — XSS via .html()/DOM manipulation of untrusted HTML"},
    {"lib": "jquery-ui", "below": "1.13.2", "sev": "medium",
     "ref": "CVE-2022-31160", "desc": "jQuery UI <1.13.2 — XSS in checkboxradio widget"},
    {"lib": "bootstrap", "below": "3.4.1", "sev": "medium",
     "ref": "CVE-2019-8331 / CVE-2018-14040", "desc": "Bootstrap <3.4.1 — XSS in data-* attributes/tooltip"},
    {"lib": "bootstrap", "atleast": "4.0.0", "below": "4.3.1", "sev": "medium",
     "ref": "CVE-2019-8331", "desc": "Bootstrap 4 <4.3.1 — XSS in tooltip/popover data-template"},
    {"lib": "angular", "atleast": "1.0.0", "below": "1.8.0", "sev": "medium",
     "ref": "multiple", "desc": "AngularJS 1.x <1.8 — several XSS/sandbox-bypass issues; AngularJS is end-of-life"},
    {"lib": "lodash", "below": "4.17.21", "sev": "high",
     "ref": "CVE-2019-10744 / CVE-2020-8203", "desc": "lodash <4.17.21 — prototype pollution"},
    {"lib": "underscore", "below": "1.12.1", "sev": "high",
     "ref": "CVE-2021-23358", "desc": "underscore <1.12.1 — arbitrary code execution via template"},
    {"lib": "moment", "below": "2.29.4", "sev": "medium",
     "ref": "CVE-2022-24785 / CVE-2022-31129", "desc": "moment <2.29.4 — path traversal / ReDoS"},
    {"lib": "handlebars", "below": "4.7.7", "sev": "high",
     "ref": "CVE-2019-19919 / CVE-2021-23369", "desc": "handlebars <4.7.7 — prototype pollution / RCE in template compiler"},
    {"lib": "dompurify", "below": "2.4.0", "sev": "medium",
     "ref": "multiple mXSS", "desc": "DOMPurify <2.4.0 — known mutation-XSS sanitizer bypasses"},
    {"lib": "axios", "below": "0.21.2", "sev": "medium",
     "ref": "CVE-2021-3749", "desc": "axios <0.21.2 — ReDoS in trim; SSRF/redirect issues in older releases"},
]

def _ver_tuple(v: str):
    return tuple(int(p) for p in re.split(r"[^0-9]+", v) if p != "")

def _ver_lt(a: str, b: str) -> bool:
    try:
        return _ver_tuple(a) < _ver_tuple(b)
    except Exception:
        return False

def detect_js_libs(url: str, content: str) -> list[tuple[str, str]]:
    """Return [(library, version)] detected from a JS file's URL + content.
    Only trusts a match when the library name also appears in the URL/head."""
    found = {}
    hay_url = url.lower()
    head = content[:4000].lower()   # banners live at the top of the file
    for lib, patterns in JS_LIB_DETECT.items():
        token = lib.replace("-", "")
        if token not in hay_url.replace("-", "") and token not in head.replace("-", ""):
            continue
        for pat in patterns:
            m = re.search(pat, url, re.I) or re.search(pat, content[:6000], re.I)
            if m:
                found[lib] = m.group(1)
                break
    return list(found.items())

def vulns_for(lib: str, version: str) -> list[dict]:
    out = []
    for rule in JS_LIB_VULNS:
        if rule["lib"] != lib:
            continue
        if rule.get("atleast") and _ver_lt(version, rule["atleast"]):
            continue
        if _ver_lt(version, rule["below"]):
            out.append(rule)
    return out

def phase_depscan(cfg, crawl_jsonl: Path, d: Path) -> list[dict]:
    """Fingerprint frontend JS libraries and flag known-vulnerable versions."""
    banner("Dependency scan — vulnerable frontend JS libraries (black-box SCA / A06)")
    hdrs = _auth_headers_dict(cfg)
    js_urls = [u for u in (_url_of(l) for l in _iter_jsonl(crawl_jsonl))
               if u and u.lower().split("?")[0].endswith(".js")]
    js_urls = list(dict.fromkeys(js_urls))[:200]
    info(f"Inspecting {len(js_urls)} JS file(s) for known-vulnerable libraries")

    findings, seen = [], set()

    # Prefer retire.js if the operator has it installed (richer signature DB).
    use_retire = tool_ok("retire") and js_urls
    if use_retire:
        jsdir = d / "reports" / "jsfiles"; jsdir.mkdir(parents=True, exist_ok=True)
        saved = 0
        from urllib.parse import urlparse as _urlparse
        for i, u in enumerate(js_urls):
            _, _, body = _http_get(u, hdrs)
            if body:
                # Preserve the original filename — retire.js uses it for
                # filename-based detection (e.g. jquery-1.8.3.min.js).
                base = _urlparse(u).path.rsplit("/", 1)[-1] or "app.js"
                if not base.lower().endswith(".js"):
                    base += ".js"
                (jsdir / f"{i}_{base}").write_text(body, encoding="utf-8", errors="replace")
                saved += 1
        rc, out = run(["retire", "--jspath", str(jsdir), "--outputformat", "json"],
                      timeout=300)
        try:
            data = json.loads(out) if out.strip() else {}
            for entry in (data.get("data") or data if isinstance(data, list) else []):
                for res in entry.get("results", []):
                    comp, ver = res.get("component", "?"), res.get("version", "?")
                    for v in res.get("vulnerabilities", []):
                        sev = (v.get("severity") or "medium").lower()
                        ids = ", ".join(v.get("identifiers", {}).get("CVE", [])) or \
                              v.get("identifiers", {}).get("summary", "")
                        findings.append({
                            "category": "Vulnerable component (outdated JS lib)",
                            "name": f"{comp} {ver} — known-vulnerable (CVE)",
                            "severity": sev if sev in SEVERITY_ORDER else "medium",
                            "location": entry.get("file", ""),
                            "detail": f"{ids}"[:180], "cweid": "1104",
                        })
        except Exception as e:
            warn(f"retire.js output parse failed, falling back: {e}")
            use_retire = False

    if not use_retire:
        for u in js_urls:
            _, _, body = _http_get(u, hdrs)
            if not body:
                continue
            for lib, ver in detect_js_libs(u, body):
                for rule in vulns_for(lib, ver):
                    key = (lib, ver, rule["below"])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "category": "Vulnerable component (outdated JS lib)",
                        "name": f"{lib} {ver} — outdated / known-vulnerable",
                        "severity": rule["sev"],
                        "location": u,
                        "detail": f"{rule['desc']} ({rule['ref']}). "
                                  f"Detected version {ver}; fixed in >= {rule['below']}.",
                        "cweid": "1104",   # -> OWASP A06
                    })
    ok(f"Dependency scan flagged {len(findings)} vulnerable library instance(s)")
    return findings

# ------------------------------------------------------------------ #
#  GAP-FILLER 2: API spec ingestion (OpenAPI / Swagger / GraphQL)
#  Extracts endpoints from a spec and feeds them to the fuzzer + ZAP, so the
#  scan reaches endpoints no crawler would ever discover.
# ------------------------------------------------------------------ #
def _load_spec(src: str, cfg) -> dict | None:
    """Load a spec from a URL or local file; parse JSON or YAML."""
    text = ""
    if src.startswith(("http://", "https://")):
        _, _, text = _http_get(src, _auth_headers_dict(cfg))
    else:
        p = Path(src)
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except Exception:
        try:
            return yaml.safe_load(text)
        except Exception:
            return None

def phase_api_spec(cfg, endpoints: Path, d: Path) -> int:
    """Parse an API spec and APPEND its endpoints to the security-endpoints
    JSONL (katana-style {request:{method,endpoint,body}}). Returns count added."""
    banner("API spec ingestion — expanding coverage from OpenAPI/GraphQL")
    a = cfg.get("api_spec", {}) or {}
    src = a.get("source", "")
    if not src:
        info("No api_spec.source set. Skipping.")
        return 0
    spec = _load_spec(src, cfg)
    if not spec:
        warn(f"Could not load/parse API spec: {src}")
        return 0

    endpoints.parent.mkdir(parents=True, exist_ok=True)
    lines, fmt = [], (a.get("format") or "").lower()
    scheme_host = "https://" + cfg["target"]["scope_domain"]

    is_openapi = "openapi" in spec or "swagger" in spec or "paths" in spec
    if fmt in ("openapi", "swagger", "") and is_openapi:
        # base URL from servers[] (OpenAPI 3) or host+basePath (Swagger 2)
        base = scheme_host
        servers = spec.get("servers")
        if servers and isinstance(servers, list):
            u = servers[0].get("url", "")
            base = u if u.startswith("http") else scheme_host + u
        elif spec.get("host"):
            base = f"https://{spec['host']}{spec.get('basePath','')}"
        for path, item in (spec.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                # substitute {id}-style path params with a probe value
                concrete = re.sub(r"\{[^}]+\}", "1", path)
                url = base.rstrip("/") + "/" + concrete.lstrip("/")
                params = (op or {}).get("parameters", []) if isinstance(op, dict) else []
                qs = [p["name"] for p in params
                      if isinstance(p, dict) and p.get("in") == "query"]
                if qs:
                    url += "?" + "&".join(f"{n}=1" for n in qs)
                body = ""
                if method.lower() in ("post", "put", "patch"):
                    body = "{}"
                lines.append({"request": {"method": method.upper(),
                                          "endpoint": url, "body": body}})
    elif fmt == "graphql" or "graphql" in src.lower():
        gql = src if src.startswith("http") else scheme_host + "/graphql"
        lines.append({"request": {"method": "POST", "endpoint": gql,
                                  "body": '{"query":"{__typename}"}'}})
    else:
        warn("Spec format not recognised (need OpenAPI/Swagger/GraphQL).")
        return 0

    with open(endpoints, "a", encoding="utf-8") as w:
        for ln in lines:
            w.write(json.dumps(ln) + "\n")
    ok(f"Added {len(lines)} endpoint(s) from API spec -> {endpoints.name}")
    return len(lines)

# ------------------------------------------------------------------ #
#  GAP-FILLER 3: CORS misconfiguration probe (OWASP A05 / ASVS V3)
#  Sends crafted Origin headers and inspects the CORS response headers.
# ------------------------------------------------------------------ #
def _collect_test_urls(cfg, endpoints: Path, limit=40) -> list[str]:
    urls = list(cfg["target"].get("seeds", []))
    for l in _iter_jsonl(endpoints):
        u = _url_of(l)
        if u and cfg["target"]["scope_domain"] in u:
            urls.append(u.split("#")[0])
    return list(dict.fromkeys(urls))[:limit]

def phase_cors(cfg, endpoints: Path, d: Path) -> list[dict]:
    """Detect permissive CORS: reflected arbitrary origin, null origin, or
    wildcard-with-credentials. High impact and frequently missed."""
    banner("CORS misconfiguration probe (reflected origin / null / creds)")
    evil = "https://evil-cors-probe.example.com"
    base_hdrs = _auth_headers_dict(cfg)
    urls = _collect_test_urls(cfg, endpoints)
    info(f"Testing {len(urls)} URL(s) for permissive CORS")
    findings, seen = [], set()
    for u in urls:
        for origin in (evil, "null"):
            status, hdrs, _ = _http_get(u, {**base_hdrs, "Origin": origin})
            if status == 0:
                continue
            acao = (hdrs.get("access-control-allow-origin") or "").strip()
            acac = (hdrs.get("access-control-allow-credentials") or "").strip().lower()
            if not acao:
                continue
            sev, why = None, ""
            if acao == origin and origin == evil:
                sev = "high"; why = "reflects an arbitrary attacker Origin"
                if acac == "true":
                    sev = "critical"; why += " AND allows credentials (session-riding)"
            elif acao == "null" and origin == "null":
                sev = "high"; why = "trusts the 'null' Origin (sandboxed/file/redirect contexts)"
                if acac == "true":
                    sev = "critical"; why += " AND allows credentials"
            elif acao == "*" and acac == "true":
                sev = "high"; why = "wildcard ACAO combined with credentials (invalid but exploitable on some stacks)"
            if sev:
                key = (u.split("?")[0], sev)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "category": "CORS misconfiguration",
                    "name": "Permissive CORS policy",
                    "severity": sev,
                    "location": u,
                    "detail": f"Server {why}. Response ACAO='{acao}', "
                              f"Allow-Credentials='{acac or 'unset'}' for Origin='{origin}'.",
                    "cweid": "942",   # Permissive Cross-domain Policy -> A05
                })
                (err if sev in ("critical", "high") else info)(f"{sev.upper()}: CORS on {u}")
    ok(f"CORS probe flagged {len(findings)} issue(s)")
    return findings

# ------------------------------------------------------------------ #
#  GAP-FILLER 6: CSRF / cookie-security probe (OWASP A01/A05 · ASVS V3/V7)
#  Passive + GET-only: inspects Set-Cookie flags (SameSite/Secure/HttpOnly) and
#  checks crawled HTML POST forms for an anti-CSRF token. Never sends a
#  state-changing request, so it can't mutate the target.
# ------------------------------------------------------------------ #
_SESSION_COOKIE_RE = re.compile(
    r"sess|sid|auth|token|jwt|csrf|xsrf|login|remember|jsessionid|phpsessid|asp\.net", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
_CSRF_FIELD_RE = re.compile(
    r"""name\s*=\s*["']?[^"'>\s]*(csrf|xsrf|_token|authenticity_token|nonce|__requestverificationtoken)""",
    re.I)

def _fetch_setcookies(url: str, headers: dict, timeout=15):
    if _budget_spent():
        return 0, [], ""
    """GET a URL and return (status, [Set-Cookie strings], body). Preserves
    multiple Set-Cookie headers (a plain dict would collapse them)."""
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, (r.headers.get_all("Set-Cookie") or []), \
                   r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, (e.headers.get_all("Set-Cookie") or []), \
                   e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, [], ""
    except Exception:
        return 0, [], ""

def _parse_cookie(sc: str):
    parts = [p.strip() for p in sc.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1); attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = True
    return name, attrs

def phase_csrf(cfg, endpoints, crawl_jsonl, d) -> list[dict]:
    banner("CSRF / cookie-security probe (SameSite · Secure · HttpOnly · form tokens)")
    base_auth = _auth_headers_dict(cfg)
    https = any(str(u).startswith("https://") for u in cfg["target"].get("seeds", [])) or True
    urls = _collect_test_urls(cfg, endpoints, limit=30)
    info(f"Inspecting cookies + forms across {len(urls)} response(s)")
    findings, seen_cookies, seen = [], set(), set()

    def add(cat, name, sev, loc, detail, cwe):
        key = (cat, loc.split("?")[0])
        if key in seen:
            return
        seen.add(key)
        findings.append({"category": cat, "name": name, "severity": sev,
                         "location": loc, "detail": detail, "cweid": cwe})

    for u in urls:
        st, cookies, body = _fetch_setcookies(u, base_auth)

        # --- cookie flags ---
        for sc in cookies:
            cname, attrs = _parse_cookie(sc)
            if not cname or cname.lower() in seen_cookies:
                continue
            seen_cookies.add(cname.lower())
            sessiony = bool(_SESSION_COOKIE_RE.search(cname))
            samesite = str(attrs.get("samesite", "")).lower()
            secure = "secure" in attrs
            httponly = "httponly" in attrs
            if not samesite:
                add("CSRF exposure (cookie SameSite)",
                    f"Cookie '{cname}' has no SameSite attribute",
                    "high" if sessiony else "medium", u,
                    "No SameSite attribute — the cookie is attached to cross-site "
                    "requests, enabling CSRF on state-changing endpoints. Set "
                    "SameSite=Lax or Strict.", "352")
            elif samesite == "none" and not secure:
                add("CSRF exposure (cookie SameSite)",
                    f"Cookie '{cname}' is SameSite=None without Secure",
                    "high", u,
                    "SameSite=None must be paired with Secure; without it the cookie "
                    "rides cross-site requests and is sent over plaintext.", "352")
            if https and not secure:
                add("Insecure cookie (missing Secure)",
                    f"Cookie '{cname}' missing the Secure flag", "medium", u,
                    "Served over HTTPS but the cookie lacks Secure, so it can leak "
                    "over an http downgrade.", "614")
            if sessiony and not httponly:
                add("Insecure cookie (missing HttpOnly)",
                    f"Session cookie '{cname}' missing HttpOnly", "medium", u,
                    "A session cookie without HttpOnly is readable by JavaScript, so "
                    "an XSS can steal the session.", "1004")

        # --- CSRF token on state-changing HTML forms (heuristic) ---
        if body and "<form" in body.lower():
            for m in _FORM_RE.finditer(body):
                form = m.group(0)
                if re.search(r'method\s*=\s*["\']?post', form, re.I) \
                        and not _CSRF_FIELD_RE.search(form):
                    add("CSRF (form without anti-CSRF token)",
                        "POST form has no anti-CSRF token field", "medium", u,
                        "A state-changing (POST) form on this page carries no hidden "
                        "CSRF/authenticity-token field. HEURISTIC — confirm the server "
                        "doesn't enforce a token via header/cookie instead.", "352")
                    break   # one flag per page is enough

    ok(f"CSRF/cookie probe flagged {len(findings)} issue(s)")
    return findings

# ------------------------------------------------------------------ #
#  Malicious-file-upload probe (OWASP A04 / CWE-434 · WSTG-BUSL/INPV)
#
#  Replicates the manual EICAR test: submit the standard anti-malware test
#  file through an upload endpoint and see whether the app ACCEPTS it. If the
#  response (or a configured/echoed download URL) then serves the bytes back
#  unchanged, that's a *confirmed* "no malware scanning" finding; if it is only
#  accepted (with no observable download-back), it's *tentative* — a human must
#  confirm from the back office, exactly as a pentester would.
#
#  ACTIVE test: it writes a (harmless but AV-flagged) file to the target, so it
#  is OFF by default and must be enabled per authorised engagement.
# ------------------------------------------------------------------ #
# EICAR standard test string, assembled at runtime so THIS source file does not
# itself trip an on-disk antivirus scanner.
_EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}" +
          "$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*")
_FILE_INPUT_RE = re.compile(r'<input\b[^>]*type\s*=\s*["\']?file["\']?[^>]*>', re.I)
_NAME_ATTR_RE  = re.compile(r'name\s*=\s*["\']?([^"\'\s>]+)', re.I)
_ACTION_RE     = re.compile(r'<form\b[^>]*\baction\s*=\s*["\']([^"\']*)["\']', re.I)
_UPLOAD_REJECT_RE = re.compile(
    r"virus|malware|infected|not\s+allowed|disallowed|invalid\s+file|"
    r"file\s+type|unsupported|blocked|rejected|forbidden\s+extension|"
    r"could\s+not\s+be\s+uploaded|upload\s+failed", re.I)
# EICAR variants: a bare .com signature and a doc/pdf-masquerade to test both
# content scanning and extension/content-type filtering.
_UPLOAD_VARIANTS = [
    ("eicar.com",     "application/octet-stream"),
    ("invoice.pdf",   "application/pdf"),
]

def _multipart(fields: dict, file_field: str, filename: str,
               content: bytes, ctype: str) -> tuple[str, bytes]:
    """Build a multipart/form-data body. Fixed boundary (no RNG needed)."""
    b = "----dastharnessUploadProbe8f3b2c"
    crlf = "\r\n"
    buf = b""
    for k, v in fields.items():
        buf += (f"--{b}{crlf}"
                f'Content-Disposition: form-data; name="{k}"{crlf}{crlf}'
                f"{v}{crlf}").encode()
    buf += (f"--{b}{crlf}"
            f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{filename}"{crlf}'
            f"Content-Type: {ctype}{crlf}{crlf}").encode()
    buf += content + f"{crlf}--{b}--{crlf}".encode()
    return b, buf

def _post_multipart(url: str, headers: dict, boundary: str, body: bytes, timeout=20):
    if _budget_spent():
        return 0, ""
    hdrs = dict(headers)
    hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    try:
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""

def _upload_candidate_pages(cfg, endpoints, crawl_jsonl, cap):
    """Every in-scope, non-static HTML page worth checking for an upload form:
    seeds + the FULL crawl + triaged endpoints, deduped and scope-filtered.
    Full-crawl coverage is the point — a file input can live on any page, not
    just the security-interesting ones."""
    scope = cfg["target"]["scope_domain"]
    pages = []
    for u in cfg["target"].get("seeds", []):
        pages.append(str(u).split("#")[0])
    for src in (crawl_jsonl, endpoints):
        for l in _iter_jsonl(src):
            u = (_url_of(l) or "").split("#")[0]
            if u and _host_in_scope(u, scope) and not _STATIC_ASSET_RE.search(u):
                pages.append(u)
    pages = list(dict.fromkeys(pages))            # dedupe, keep order
    return pages[:cap], len(pages)

def _discover_upload_forms(cfg, endpoints, crawl_jsonl):
    """Return [(page_url, action_url, file_field, other_fields{})] for every
    HTML form ACROSS THE WHOLE CRAWLED SITE that carries a <input type=file>."""
    base_auth = _auth_headers_dict(cfg)
    scope = cfg["target"]["scope_domain"]
    cap = int((cfg.get("upload", {}) or {}).get("max_pages", 500))
    urls, total = _upload_candidate_pages(cfg, endpoints, crawl_jsonl, cap)
    if total > len(urls):
        warn(f"Upload discovery: crawl has {total} pages; checking the first "
             f"{len(urls)} for file-upload forms (raise upload.max_pages to cover more).")
    else:
        info(f"Upload discovery: scanning {len(urls)} crawled page(s) for file-upload forms")
    found, seen = [], set()
    for u in urls:
        _st, _c, body = _fetch_setcookies(u, base_auth)
        if not body or "<form" not in body.lower():
            continue
        for m in _FORM_RE.finditer(body):
            form = m.group(0)
            if not _FILE_INPUT_RE.search(form):
                continue
            fin = _FILE_INPUT_RE.search(form)
            fname_m = _NAME_ATTR_RE.search(fin.group(0))
            if not fname_m:
                continue
            file_field = fname_m.group(1)
            act = _ACTION_RE.search(form)
            action = urllib.parse.urljoin(u, act.group(1)) if act and act.group(1) else u
            if not _host_in_scope(action, scope):
                continue
            key = (action, file_field)
            if key in seen:
                continue
            seen.add(key)
            # fill the other visible inputs with a dummy value so the form validates
            others = {}
            for im in re.finditer(r'<(?:input|textarea)\b[^>]*>', form, re.I):
                tag = im.group(0)
                nm = _NAME_ATTR_RE.search(tag)
                if not nm or nm.group(1) == file_field:
                    continue
                t = re.search(r'type\s*=\s*["\']?(\w+)', tag, re.I)
                t = (t.group(1).lower() if t else "text")
                if t in ("submit", "button", "file", "image"):
                    continue
                others[nm.group(1)] = ("dast-probe@example.com" if t == "email"
                                       else "1" if t in ("number", "tel") else "dast upload test")
            found.append((u, action, file_field, others))
    return found

def phase_upload(cfg, endpoints, crawl_jsonl, d) -> list[dict]:
    banner("Malicious-file-upload probe (EICAR — CWE-434 / A04)")
    ucfg = cfg.get("upload", {}) or {}
    base_auth = _auth_headers_dict(cfg)
    findings, seen = [], set()

    def add(sev, conf, loc, detail):
        if loc in seen:
            return
        seen.add(loc)
        findings.append({
            "category": "Malicious file upload (no AV scanning)",
            "name": "Upload endpoint accepts a known-malicious test file (EICAR)",
            "severity": sev, "confidence": conf, "location": loc,
            "detail": detail, "cweid": "434",
        })

    # 1) targets: explicit config endpoints + auto-discovered file-upload forms
    targets = []   # (action_url, file_field, other_fields, page)
    for ep in ucfg.get("endpoints", []) or []:
        if isinstance(ep, dict):
            targets.append((ep.get("url"), ep.get("file_field", "file"),
                            ep.get("fields", {}) or {}, ep.get("url")))
        else:
            targets.append((ep, "file", {}, ep))
    if ucfg.get("auto_discover", True):
        for page, action, ff, others in _discover_upload_forms(cfg, endpoints, crawl_jsonl):
            targets.append((action, ff, others, page))

    if not targets:
        warn("No upload endpoints found (no file-input forms discovered and none "
             "configured under upload.endpoints) — upload probe had nothing to test.")
        ok("Upload probe flagged 0 issue(s)")
        return findings
    info(f"Testing {len(targets)} upload endpoint(s) with the EICAR test file")

    dl_url = ucfg.get("download_url_template", "")  # optional {filename} template
    for action, file_field, others, page in targets:
        if not action:
            continue
        accepted = False
        for filename, ctype in _UPLOAD_VARIANTS:
            boundary, body = _multipart(others, file_field, filename,
                                        _EICAR.encode(), ctype)
            st, resp = _post_multipart(action, base_auth, boundary, body)
            rejected = _UPLOAD_REJECT_RE.search(resp or "")
            if 200 <= st < 400 and not rejected:
                accepted = True
                # 2) try to prove the round-trip: fetch the file back unchanged
                confirmed_url = None
                cand = []
                if dl_url:
                    cand.append(dl_url.replace("{filename}", filename))
                # echoed path in the response body (best-effort)
                for m in re.finditer(r'https?://[^\s"\'<>]+' + re.escape(filename), resp or ""):
                    cand.append(m.group(0))
                for cu in cand:
                    back, _s = _fetch(cu, base_auth)
                    if back and _EICAR in back:
                        confirmed_url = cu
                        break
                if confirmed_url:
                    add("high", "confirmed", action,
                        f"EICAR uploaded via '{file_field}' (as {filename}) was stored and "
                        f"served back UNCHANGED from {confirmed_url} (HTTP {st}). The upload "
                        f"path performs no malware scanning. Discovered from form on {page}.")
                else:
                    add("high", "tentative", action,
                        f"EICAR uploaded via '{file_field}' (as {filename}) was ACCEPTED "
                        f"(HTTP {st}, no rejection in response). No public download URL was "
                        f"observed, so the round-trip could not be auto-confirmed — verify "
                        f"in the back office that the stored file is downloadable unchanged. "
                        f"Discovered from form on {page}.")
                break   # one accepted variant is enough per endpoint
        if not accepted:
            info(f"Upload endpoint rejected the test file (good): {action}")

    ok(f"Upload probe flagged {len(findings)} issue(s)")
    return findings

# ------------------------------------------------------------------ #
#  GAP-FILLER 4: auto-discover IDOR candidates from the crawl
#  Finds endpoints with numeric/UUID object ids so the access-control probe
#  doesn't need every victim URL hand-listed.
# ------------------------------------------------------------------ #
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_NUM_SEG_RE = re.compile(r"/(\d{2,})(?=/|$|\?)")
_NUM_PARAM_RE = re.compile(r"[?&](\w*id\w*|uid|user|account|employee|order|doc)=(\d{2,}|[0-9a-f-]{16,})", re.I)

def discover_idor_candidates(crawl_jsonl: Path, scope: str, limit=25) -> list[str]:
    out = []
    for l in _iter_jsonl(crawl_jsonl):
        u = _url_of(l)
        if not u or scope not in u:
            continue
        if _NUM_SEG_RE.search(urlparse_path(u)) or _UUID_RE.search(u) or _NUM_PARAM_RE.search(u):
            out.append(u.split("#")[0])
    return list(dict.fromkeys(out))[:limit]

def urlparse_path(u: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(u).path
    except Exception:
        return u

# ------------------------------------------------------------------ #
#  GAP-FILLER 5: Active token / broken-authentication probe
#  (OWASP API2:2023 Broken Authentication / A07 / ASVS V6+V9)
#
#  The passive token_analysis phase only DECODES a token. This phase actively
#  exercises the API with it — GET-only, read-only, but it forges auth, so
#  authorised targets ONLY. Four checks:
#    1. Replay a leaked static token (found in JS) against endpoints -> impact.
#    2. No-token / random-token acceptance -> token not validated (broken auth).
#    3. JWT tampering (alg=none, stripped signature, expired) -> signature not verified.
#    4. Claim tampering (role/admin/user-id) -> possible privilege escalation (heuristic).
# ------------------------------------------------------------------ #
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")

def _b64u_enc(d: dict) -> str:
    raw = json.dumps(d, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def _jwt_decode_parts(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    pad = lambda s: s + "=" * (-len(s) % 4)
    try:
        h = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        p = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    except Exception:
        return None
    return h, p, parts[2]

def _find_token_carrier(cfg):
    """Which configured auth header carries the token, and what is it?
    Returns {'key','token','is_jwt'} or None."""
    if not cfg["auth"].get("enabled"):
        return None
    hdrs = cfg["auth"].get("headers", [])
    for h in hdrs:                          # prefer a real JWT
        if "PASTE_YOUR" in h or ":" not in h:
            continue
        k, v = h.split(":", 1)
        m = _JWT_RE.search(v)
        if m:
            return {"key": k.strip(), "token": m.group(0), "is_jwt": True}
    for h in hdrs:                          # else an opaque bearer / cookie token
        if "PASTE_YOUR" in h or ":" not in h:
            continue
        k, v = h.split(":", 1)
        m = (re.search(r"Bearer\s+([A-Za-z0-9_\-\.]{16,})", v)
             or re.search(r"(?:token|session|jwt|auth)=([A-Za-z0-9_\-\.]{16,})", v, re.I))
        if m:
            return {"key": k.strip(), "token": m.group(1), "is_jwt": False}
    return None

def _swap_token(base_auth: dict, carrier, new_token: str) -> dict:
    out = dict(base_auth)
    if carrier and carrier["key"] in out:
        out[carrier["key"]] = out[carrier["key"]].replace(carrier["token"], new_token)
    return out

def _jwt_tamper_variants(token: str):
    parts = _jwt_decode_parts(token)
    if not parts:
        return []
    h, p, _ = parts
    hn = dict(h); hn["alg"] = "none"
    p_exp = dict(p); p_exp["exp"] = 1000000000    # year 2001 — clearly expired
    return [
        ("alg=none",           _b64u_enc(hn) + "." + _b64u_enc(p) + "."),
        ("stripped signature", _b64u_enc(h)  + "." + _b64u_enc(p) + ".AAAAAA"),
        ("expired token",      _b64u_enc(hn) + "." + _b64u_enc(p_exp) + "."),
    ]

def _jwt_claim_variants(token: str):
    parts = _jwt_decode_parts(token)
    if not parts:
        return []
    h, p, _ = parts
    hn = dict(h); hn["alg"] = "none"
    out = []
    for claim, val in [("role", "admin"), ("admin", True), ("is_admin", True), ("isAdmin", True)]:
        p2 = dict(p); p2[claim] = val
        out.append((f"{claim}={val}", _b64u_enc(hn) + "." + _b64u_enc(p2) + "."))
    for claim in ("sub", "user_id", "uid", "userId", "id"):
        if claim in p and str(p[claim]).strip():
            v = str(p[claim])
            nv = str(int(v) + 1) if v.isdigit() else v[::-1]
            p2 = dict(p); p2[claim] = nv
            out.append((f"{claim} {v}->{nv}", _b64u_enc(hn) + "." + _b64u_enc(p2) + "."))
            break
    return out

# Static assets are public by design — never treat them as "protected endpoints"
# (this caused false "missing auth" criticals on JS bundles / manifest.json / homepage).
_STATIC_ASSET_RE = re.compile(
    r"(\.(?:js|mjs|css|json|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|mp4|mp3|pdf|txt|xml)(?:\?|$))"
    r"|/_next/|/static/|/assets/|/_nuxt/|/build/", re.I)

# Endpoints that are PUBLIC BY DESIGN — testing them for "missing auth" always
# false-positives (the login page is meant to be reachable without a token).
_PUBLIC_ENDPOINT_RE = re.compile(
    r"/(?:user/)?(?:login|logout|log-?in|log-?out|signin|sign-?in|signup|sign-?up|"
    r"register|registration|forgot|reset|recover|verify|verify-mail|activate|"
    r"confirm|password|csrf|acrf|token|oauth|oidc|sso|saml|auth/callback|"
    r"health|healthz|status|ping|robots|sitemap|favicon|manifest|\.well-known)",
    re.I)

def _probe_targets(cfg, endpoints, crawl_jsonl, limit=8) -> list[str]:
    scope = cfg["target"]["scope_domain"]
    # Sensitive-data keywords — only meaningful together with an API/id signal.
    sensitive_kw = ("employee", "payslip", "salary", "payroll", "invoice",
                    "account", "document", "order", "profile", "customer")
    urls, src = [], (endpoints if Path(endpoints).exists() else crawl_jsonl)
    for l in _iter_jsonl(src):
        u = _url_of(l)
        if not u or scope not in u:
            continue
        path = urlparse_path(u)
        if path in ("", "/") or _STATIC_ASSET_RE.search(u) or _PUBLIC_ENDPOINT_RE.search(u):
            continue                     # homepage / static / login are public by design
        lu = u.lower()
        # Only test genuine DATA endpoints — this "no-token-returns-data" check
        # false-positives on public content pages, so require a real API/data signal:
        api_signal = any(k in lu for k in ("/api", "jsonapi", "/rest", "/graphql")) \
                     or "_format=json" in lu
        id_signal = bool(_NUM_SEG_RE.search(path) or _UUID_RE.search(u)
                         or re.search(r"[?&](?:\w*id|uid|entityid|user|account)=", lu))
        sensitive = any(k in lu for k in sensitive_kw) and "?" in u
        if api_signal or id_signal or sensitive:
            urls.append(u.split("#")[0])
    disc_src = crawl_jsonl if (crawl_jsonl and Path(crawl_jsonl).exists()) else endpoints
    urls += [u for u in discover_idor_candidates(disc_src, scope, limit=limit)
             if not _STATIC_ASSET_RE.search(u) and not _PUBLIC_ENDPOINT_RE.search(u)]
    return list(dict.fromkeys(urls))[:limit]

def _looks_like_public_page(body: str) -> bool:
    """True if the response is an HTML document / SPA shell / login page rather
    than protected data. Such pages are public by design, so identical
    authed/anon responses prove nothing about access control."""
    if not body:
        return False
    b = body.lstrip()[:2000].lower()
    if b.startswith("<!doctype html") or b.startswith("<html") or "<head" in b[:400]:
        return True
    # SPA shell markers (the login endpoint here returned exactly this)
    if any(m in b for m in ("/manifest.json", "<div id=\"root\"", "<div id=\"app\"",
                            "window.__", "text/javascript", "stylesheet")):
        return True
    # explicit login/auth form markup
    if ("<form" in b and any(m in b for m in ("password", "sign in", "log in", "login"))):
        return True
    return False

def phase_token_probe(cfg, endpoints, crawl_jsonl, secret_findings, d) -> list[dict]:
    banner("Token probe — active broken-authentication tests (GET-only; authorised targets)")
    base_auth = _auth_headers_dict(cfg)
    carrier = _find_token_carrier(cfg)
    if not base_auth:
        info("No auth token configured — active token probe needs a valid token "
             "to establish a baseline. Skipping (add a cookie/bearer).")
        return []
    tol = 0.15
    targets = _probe_targets(cfg, endpoints, crawl_jsonl)
    info(f"Probing {len(targets)} candidate protected endpoint(s)")
    findings, seen = [], set()

    def add(cat, name, sev, loc, detail, cwe):
        key = (cat, loc.split("?")[0])
        if key in seen:
            return
        seen.add(key)
        findings.append({"category": cat, "name": name, "severity": sev,
                         "location": loc, "detail": detail, "cweid": cwe})
        (err if sev in ("critical", "high") else info)(f"{sev.upper()}: {name} @ {loc}")

    for u in targets:
        st_base, _, body_base = _http_get(u, base_auth)
        lb = len(body_base or "")
        if st_base != 200 or lb == 0:
            continue                          # need an authenticated data baseline
        # A public HTML/SPA/login page is served identically with or without a
        # token BY DESIGN — flagging it as "auth not enforced" is a false Critical.
        # Only proceed when the baseline actually looks like protected DATA.
        if _looks_like_public_page(body_base):
            continue
        same = lambda b: lb > 0 and abs(len(b or "") - lb) <= tol * lb

        # 2) no-token / random-token acceptance
        st, _, bd = _http_get(u, {})          # no auth at all
        if st == 200 and same(bd):
            add("Broken authentication (missing auth check)",
                "Protected endpoint returns data with NO token", "critical", u,
                "Endpoint returned the same data unauthenticated as it did with a "
                "valid token — authentication is not enforced. Confirm it is meant "
                "to be protected.", "287")
        if carrier:
            st, _, bd = _http_get(u, _swap_token(base_auth, carrier, "invalid-" + "x" * 40))
            if st == 200 and same(bd):
                add("Broken authentication (token not validated)",
                    "Endpoint accepts a RANDOM/forged token", "critical", u,
                    "A garbage token returned the same data as the valid token — the "
                    "server is not validating the token at all (Broken Auth, API2).", "287")

        # 3) JWT tampering
        if carrier and carrier["is_jwt"]:
            for label, variant in _jwt_tamper_variants(carrier["token"]):
                st, _, bd = _http_get(u, _swap_token(base_auth, carrier, variant))
                if st == 200 and same(bd):
                    sev = "high" if label == "expired token" else "critical"
                    add("Broken authentication (JWT signature not verified)",
                        f"Server accepted a tampered JWT ({label})", sev, u,
                        f"A JWT modified with '{label}' was accepted and returned data. "
                        f"The signature/expiry is not being verified.", "287")

            # 4) claim-tampering privilege escalation (heuristic)
            for label, variant in _jwt_claim_variants(carrier["token"]):
                st, _, bd = _http_get(u, _swap_token(base_auth, carrier, variant))
                # DIFFERENT (not error) data suggests the tampered claim was honoured
                if st == 200 and len(bd or "") > 0 and not same(bd):
                    add("Broken access control (privilege escalation via token claim)",
                        f"Response changed when tampering claim [{label}]", "high", u,
                        f"Tampering the JWT claim '{label}' changed the response — possible "
                        f"privilege escalation / BOLA. HEURISTIC: verify this by hand.", "639")

    # 1) replay leaked static tokens found in the frontend JS (impact proof)
    for f in secret_findings:
        if f.get("type") != "JWT":
            continue
        for u in targets[:5]:
            st, _, bd = _http_get(u, {"Authorization": "Bearer " + f["raw"]})
            if st == 200 and len(bd or "") > 0:
                add("Exposed static token (exploitable)",
                    "Leaked static token grants live API access", "high", u,
                    f"A token exposed in frontend JS ({f.get('source','')}) returned live "
                    f"data from this endpoint — the leak is exploitable, not theoretical.", "798")
                break

    ok(f"Token probe produced {len(findings)} finding(s)")
    return findings

# ------------------------------------------------------------------ #
#  Remediation guidance — the "recommended fix" for each finding.
#  Category-specific text wins; otherwise fall back to the OWASP-category fix.
# ------------------------------------------------------------------ #
_REMEDIATION_BY_CATEGORY = {
    "cors misconfiguration":
        "Return Access-Control-Allow-Origin only for a strict allow-list of trusted "
        "origins. Never reflect an arbitrary Origin, and never combine a reflected/"
        "wildcard origin with Access-Control-Allow-Credentials: true.",
    "cookie samesite":
        "Set session cookies with SameSite=Lax or Strict (use SameSite=None only "
        "together with Secure), and add anti-CSRF tokens on state-changing requests.",
    "missing secure":
        "Add the Secure attribute so the cookie is only ever sent over HTTPS.",
    "missing httponly":
        "Add HttpOnly to session cookies so client-side JavaScript (and any XSS) "
        "cannot read them.",
    "form without anti-csrf":
        "Add a per-session anti-CSRF token (synchronizer or double-submit pattern) "
        "to every state-changing form and verify it server-side.",
    "missing auth check":
        "Require and verify a valid session/token on every protected endpoint. "
        "Deny by default; return 401/403 when authentication is absent.",
    "token not validated":
        "Verify the token signature/validity server-side on every request and reject "
        "unknown or malformed tokens with 401.",
    "jwt signature not verified":
        "Verify the JWT signature with the server key on every request. Reject "
        "alg=none, unsigned tokens, and expired tokens.",
    "privilege escalation via token claim":
        "Never trust client-supplied claims for authorization. Enforce roles and "
        "object ownership server-side against a trusted store.",
    "exposed static token":
        "Revoke and rotate the leaked token now. Move secrets server-side, issue "
        "short-lived per-user tokens, and never embed credentials in frontend JS.",
    "vulnerable component":
        "Upgrade the library to the fixed version and add dependency (SCA) scanning "
        "to CI so vulnerable versions are caught before release.",
    "access control (idor)":
        "Enforce object-level authorization on the server: confirm the current "
        "session owns/may access the requested object id before returning it.",
    "exposed secret":
        "Revoke and rotate the exposed secret immediately. Keep secrets server-side "
        "and scan frontend builds for leaks in CI.",
    "token / credential":
        "Use short-lived tokens with refresh + rotation and enforce an exp claim; "
        "never ship non-expiring tokens to the browser.",
    "injection":
        "Use parameterized queries / prepared statements and context-aware output "
        "encoding. Validate and allow-list input; never build queries or commands by "
        "string concatenation.",
}
_REMEDIATION_BY_OWASP = {
    "A01": "Enforce server-side authorization on every object and action; deny by "
           "default. Add anti-CSRF tokens and SameSite cookies.",
    "A02": "Use TLS 1.2+ with strong ciphers, enable HSTS, disable HTTP compression "
           "on sensitive responses, and encrypt sensitive data at rest.",
    "A03": "Use parameterized queries and context-aware output encoding; validate and "
           "allow-list all untrusted input.",
    "A04": "Address at design time: rate limits, workflow/state validation, and threat "
           "modeling of the business logic.",
    "A05": "Harden configuration: remove verbose errors/default pages, restrict CORS, "
           "set security headers, disable directory listing, remove exposed files.",
    "A06": "Upgrade the affected component to a patched version and track dependencies "
           "with SCA on a regular patch cadence.",
    "A07": "Enforce strong authentication: verify token signature and expiry server-"
           "side, reject alg=none, use short-lived rotating tokens, add lockout/MFA.",
    "A08": "Verify integrity of updates and deserialized data with signatures; avoid "
           "deserializing untrusted input; use SRI for third-party scripts.",
    "A09": "Log security-relevant events and monitor/alert on them; never log secrets.",
    "A10": "Allow-list outbound URLs, block requests to internal/metadata addresses, "
           "and route external fetches through a constrained proxy.",
    "NA":  "Review the finding and confirm whether it is exploitable in your context.",
}

def _remediation_for(f: dict) -> str:
    cat = (f.get("category") or "").lower()
    name = (f.get("name") or "").lower()
    for key, txt in _REMEDIATION_BY_CATEGORY.items():
        if key in cat or key in name:
            return txt
    return _REMEDIATION_BY_OWASP.get(f.get("owasp", "NA"), _REMEDIATION_BY_OWASP["NA"])

# ------------------------------------------------------------------ #
#  Signal refinement — the trust layer.
#
#  Every finding is passed through here before it can reach a report. The job
#  is to make the report defensible in front of a customer: drop what only
#  describes the scanner (not the target), drop signature "phantoms" for
#  software that isn't present, de-duplicate the same issue reported by two
#  tools, cap severities the raw tools habitually over-rate, and tag every
#  surviving finding with a CONFIDENCE tier so a candidate can never be
#  mistaken for a confirmed fact.
#
#  This is deliberately ONE place: all suppression is auditable here, nothing
#  is silently dropped inside the individual parsers.
# ------------------------------------------------------------------ #
CONFIDENCE_ORDER = ["confirmed", "firm", "tentative"]

# 1) Scanner ARTIFACTS — text that describes the tool's own state, never the
#    target. e.g. Nikto leaking a Perl "ARRAY(0x..)" ref instead of a header
#    value; testssl reporting a limitation of the LOCAL openssl build.
_ARTIFACT_RE = re.compile(
    r"ARRAY\(0x|HASH\(0x"                       # Nikto Perl reference leak
    r"|engine_problem|no engine or gost"        # testssl local OpenSSL engine
    r"|/opt/homebrew|/usr/local/opt|openssl@"   # local tool paths, not the target
    # testssl run-status rows: "scanTime: Scan interrupted", "scanProblem:
    # Can't connect to host:443". These describe how the SCAN went, not the
    # target's security, and they now appear routinely because the time budget
    # caps external tools on purpose. Reporting a budget cap as a finding would
    # make every bounded scan look like it found something.
    r"|scan interrupted|scanproblem|scantime"
    r"|can't connect to|make sure a firewall",
    re.I)

# 2) An INJECTED probe payload echoed back in the location — Nikto fires a
#    canned reflected-XSS string and matches a hard-coded "product X is
#    vulnerable" signature even when product X isn't here. On an app that
#    doesn't reflect the payload these are always false. Scoped to Nikto ONLY
#    so genuine Nuclei/ZAP reflected-XSS (which legitimately carry a payload in
#    matched-at) is never dropped.
_INJECTED_PROBE_RE = re.compile(r"<script|%3cscript|\"><|%22%3e|onmouseover=|alert\(", re.I)

# 3) INFORMATIONAL only — real observations, but not vulnerabilities. Kept in
#    the report (nothing hidden) but demoted to info + tentative so they sink
#    to the bottom instead of inflating the severity counts.
_INFO_ONLY_RE = re.compile(
    r"\bFS_KEMs\b|no kems offered"              # post-quantum KEMs (not required)
    r"|DNS_CAArecord|caa record"               # optional DNS hardening
    r"|dynamic-cache|x-drupal-dynamic-cache"   # cache hint header
    r"|uncommon header"                        # Nikto curiosity, not a vuln
    r"|allowed http methods|allowed methods",  # OPTIONS enumeration
    re.I)

# 4) THEORETICAL / needs-manual — keep, but force tentative + low. These are
#    the "potentially vulnerable" class the raw tools over-rate (BREACH is the
#    classic: only real if a secret AND reflected input share one compressed
#    response — which a scanner can't know).
_TENTATIVE_RE = re.compile(
    r"breach|compression|content-encoding|deflate|optionsbleed"
    r"|potentially vulnerable|may be vulnerable|might be vulnerable|possible ",
    re.I)

def _sev_cap(sev, cap):
    """Return sev, but no more severe than cap (uses SEVERITY_ORDER ranking)."""
    try:
        return cap if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(cap) else sev
    except ValueError:
        return sev

def _finding_host(loc):
    m = re.search(r"https?://([^/:]+)", loc or "")
    return m.group(1) if m else (loc or "").split("/")[0].split(":")[0]

def _finding_hay(f):
    return " ".join(str(f.get(k, "")) for k in
                    ("name", "detail", "location", "category", "evidence")).lower()

def _confidence_for(f):
    """confirmed = the tool actively proved it. firm = strong signal, spot-check.
    tentative = candidate; a human MUST verify before it goes in a client report."""
    cat, name = (f.get("category") or "").lower(), (f.get("name") or "").lower()
    hay = _finding_hay(f)
    if ("confirmed" in cat or "sqlmap" in name          # sqlmap-verified injection
            or "idor" in cat or "object-level" in name   # 2-account cross-read proof
            or "exposed secret" in cat):                 # a real key/token was found
        return "confirmed"
    if "nikto" in cat:                                   # signature scanner — always verify
        return "tentative"
    if _TENTATIVE_RE.search(hay):
        return "tentative"
    # A bare version-based CVE with no request/response proof is a guess.
    if re.search(r"cve-\d", name) and "matched at" not in (f.get("evidence") or "").lower() \
       and not re.search(r"exposure|exposed|misconfig|directory|panel|default|header", cat + name):
        return "tentative"
    return "firm"

def _canonical_key(f):
    """A semantic key so the SAME issue reported by two tools de-dupes to one
    (e.g. Nikto 'strict-transport-security missing' + testssl 'HSTS not offered')."""
    hay = _finding_hay(f)
    host = _finding_host(f.get("location", ""))
    for tag, key in (("strict-transport-security", "hsts"), ("hsts", "hsts"),
                     ("permissions-policy", "permissions-policy"),
                     ("content-security-policy", "csp"), ("frame-ancestors", "x-frame"),
                     ("x-frame-options", "x-frame"), ("clickjack", "x-frame"),
                     ("x-content-type-options", "x-content-type"),
                     ("access-control-allow-origin", "cors"), ("cors", "cors"),
                     # BREACH + "content-encoding deflate" are one compression issue
                     ("breach", "compression"), ("content-encoding", "compression"),
                     ("compression", "compression")):
        if tag in hay:
            return ("hdr", key, host)
    nm = re.sub(r"[^a-z0-9]+", "", (f.get("name") or "").lower())[:40]
    return ("f", nm, host)

def _refine_findings(findings):
    kept = []
    for f in findings:
        cat = (f.get("category") or "").lower()
        hay = _finding_hay(f)
        # (a) hard-drop scanner artifacts — they describe the tool, not the target
        if _ARTIFACT_RE.search(hay):
            continue
        # (b) hard-drop Nikto phantom reflected-XSS signatures (Nikto only)
        if "nikto" in cat and _INJECTED_PROBE_RE.search(f.get("location", "") + " " + f.get("name", "")):
            continue
        # (b2) broken/missing-auth claims on endpoints that are PUBLIC BY DESIGN
        #      (login, register, reset, oauth, health, ...) are false criticals:
        #      those pages serve the same content with or without a token on purpose.
        nm = (f.get("name") or "").lower()
        if _PUBLIC_ENDPOINT_RE.search(f.get("location", "")) \
           and re.search(r"auth|token|login", cat + nm) \
           and re.search(r"no token|missing auth|not enforced|broken auth|forged|random|tamper", cat + nm):
            continue
        # (c) informational noise -> keep but demote out of the way
        if _INFO_ONLY_RE.search(hay):
            f["severity"], f["confidence"] = "info", "tentative"
            kept.append(f)
            continue
        # (d) confidence + severity sanity. An ACTIVE probe that already proved
        #     (or couldn't prove) its finding sets confidence itself — keep it;
        #     only classify findings that arrive without a tier.
        if f.get("confidence") not in CONFIDENCE_ORDER:
            f["confidence"] = _confidence_for(f)
        if f["confidence"] == "tentative":
            f["severity"] = _sev_cap(f["severity"], "medium")
        if _TENTATIVE_RE.search(hay):                 # BREACH & friends -> low
            f["severity"] = _sev_cap(f["severity"], "low")
        if "nikto" in cat:                            # Nikto medium = version guess -> low
            f["severity"] = _sev_cap(f["severity"], "low")
        kept.append(f)
    # (e) de-duplicate — keep the strongest (most severe, then most confident)
    def strength(f):
        return (SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 5,
                CONFIDENCE_ORDER.index(f.get("confidence", "firm")))
    best = {}
    for f in sorted(kept, key=strength):
        k = _canonical_key(f)
        if k not in best:
            best[k] = f
        else:
            # remember that a second tool corroborated it (raises trust)
            b = best[k]
            other = f.get("category", "")
            if other and other not in (b.get("detail") or ""):
                b["detail"] = (b.get("detail") or "") + f"  |  also reported by: {other}"
                if b.get("confidence") == "tentative" and f.get("confidence") in ("firm", "confirmed"):
                    b["confidence"] = "firm"          # two independent tools agree
    return list(best.values())

# ------------------------------------------------------------------ #
#  Report aggregation
# ------------------------------------------------------------------ #
def collect_findings(dast, templates, secrets, tokens, sqlmap_res,
                     zap_json=None, nikto_json=None, testssl_json=None,
                     idor_res=None, dep_findings=None, cors_res=None,
                     token_probe_findings=None, csrf_findings=None,
                     upload_findings=None):
    """Normalise everything into one list of findings, each tagged with an
    OWASP Top 10 2021 category and an ASVS 5.0 chapter."""
    findings = []
    for l in _iter_jsonl(dast):
        inf = l.get("info", {})
        findings.append({
            "category": "Injection (DAST)",
            "name": inf.get("name") or l.get("template-id", "sqli/xss/etc"),
            "severity": (inf.get("severity") or "unknown").lower(),
            "location": l.get("matched-at") or _url_of(l),
            "detail": l.get("template-id", ""),
            "_raw": l,
        })
    for l in _iter_jsonl(templates):
        inf = l.get("info", {})
        findings.append({
            "category": "Template (CVE/exposure/misconfig)",
            "name": inf.get("name") or l.get("template-id", ""),
            "severity": (inf.get("severity") or "unknown").lower(),
            "location": l.get("matched-at") or _url_of(l),
            "detail": l.get("template-id", ""),
            "_raw": l,
        })
    if zap_json:
        findings += parse_zap(zap_json)
    if nikto_json:
        findings += parse_nikto(nikto_json)
    if testssl_json:
        findings += parse_testssl(testssl_json)
    for s in secrets:
        findings.append({
            "category": "Exposed secret",
            "name": f"{s['type']} in frontend",
            "severity": "high",
            "location": s["source"],
            "detail": s["match_preview"],
            "cweid": "798",  # use of hard-coded credentials -> A07
        })
    for t in tokens:
        findings.append({
            "category": "Token / credential",
            "name": f"{t['type'].upper()} token lifetime",
            "severity": t["severity"],
            "location": t["where"],
            "detail": " | ".join(t["issues"]),
        })
    for c in sqlmap_res:
        if c["vulnerable"]:
            det = "sqlmap verified this parameter is injectable."
            if c.get("extracted"):
                det += " Data extraction succeeded — real records reachable."
            findings.append({
                "category": "Injection (confirmed)",
                "name": "SQL injection confirmed by sqlmap",
                "severity": "critical",
                "location": c["url"],
                "detail": det,
            })
    for r in (idor_res or []):
        if r["verdict"] == "VULNERABLE":
            findings.append({
                "category": "Access control (IDOR)",
                "name": "Broken object-level authorization (IDOR)",
                "severity": "high",
                "location": r["url"],
                "detail": f"Resource readable by {', '.join(r['who'])}. "
                          f"Status codes {r['codes']}.",
                "cweid": "639",
            })
    # gap-filler findings are already in final finding shape
    findings += (dep_findings or [])
    findings += (cors_res or [])
    findings += (token_probe_findings or [])
    findings += (csrf_findings or [])
    findings += (upload_findings or [])
    # attach OWASP + ASVS + evidence + a recommended fix to every finding
    for f in findings:
        raw = f["_raw"] if isinstance(f.get("_raw"), dict) else {}
        src = {**raw, **f} if raw else dict(f)
        f["owasp"] = owasp.map_to_owasp(src)
        f["asvs"] = owasp.map_to_asvs(src, f["owasp"])
        # evidence = the concrete proof (what was sent/seen). For Nuclei/ZAP the
        # matched location + any extracted data; for the built-in probes the
        # detail string already describes the request/response.
        ev = (f.get("detail") or "").strip()
        ma = raw.get("matched-at") or raw.get("matched_at")
        xr = raw.get("extracted-results") or raw.get("extracted_results")
        if ma:
            ev = (ev + f"  |  matched at: {ma}").strip("| ").strip()
        if xr:
            ev = (ev + f"  |  extracted: {xr}").strip()
        f["evidence"] = ev or (f.get("location") or "")
        f["remediation"] = _remediation_for(f)
        f.pop("_raw", None)
    # trust layer: drop noise, de-dupe, tag confidence (see _refine_findings)
    findings = _refine_findings(findings)
    def rank(f):
        sev = SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 5
        conf = CONFIDENCE_ORDER.index(f.get("confidence", "firm"))
        return (sev, conf)          # confirmed criticals first; tentative info last
    findings.sort(key=rank)
    return findings

def _scan_was_authenticated(cfg) -> bool:
    """True only if real auth headers were supplied (not placeholders/none)."""
    auth = cfg.get("auth", {}) or {}
    if not auth.get("enabled"):
        return False
    for h in auth.get("headers", []) or []:
        if ":" in h and "PASTE_YOUR" not in h and "none=none" not in h:
            return True
    return False

def write_reports(cfg, d: Path, findings: list[dict], reliability="ok", partial=False):
    counts = {s: 0 for s in SEVERITY_ORDER}
    owasp_counts, asvs_counts = {}, {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        owasp_counts[f.get("owasp", "NA")] = owasp_counts.get(f.get("owasp", "NA"), 0) + 1
        ch = f.get("asvs", "")
        if ch:
            asvs_counts[ch] = asvs_counts.get(ch, 0) + 1
    meta = {
        "project": cfg["project"]["name"],
        "target": cfg["target"]["scope_domain"],
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total": len(findings),
        "counts": counts,
        "owasp": owasp_counts,
        "asvs": asvs_counts,
        "coverage": owasp.coverage_summary(),
        "reliability": reliability,
        "authenticated": _scan_was_authenticated(cfg),
        "partial": bool(partial),
        "preset": cfg.get("preset", ""),
    }
    (d / "report.json").write_text(json.dumps(
        {"meta": meta, "findings": findings}, indent=2))
    _write_markdown(d / "REPORT.md", meta, findings)
    _write_html(d / "REPORT.html", meta, findings)
    try:
        import sarif
        sarif.write_sarif(d / "report.sarif", meta, findings)
    except Exception as e:
        warn(f"SARIF export skipped: {e}")
    return meta

def _write_markdown(path, meta, findings):
    L = [f"# DAST Report — {meta['project']}", "",
         f"- Target: `{meta['target']}`", f"- Date: {meta['date']}",
         f"- Total findings: {meta['total']}",
         f"- Scan reliability: **{meta.get('reliability','ok').upper()}**",
         *( ["- ⚠ **PARTIAL — scan still in progress or stopped early; more findings may follow.**"]
            if meta.get("partial") else [] ),
         f"- Authenticated: **{'YES' if meta.get('authenticated') else 'NO'}**", ""]
    if not meta.get("authenticated"):
        L += ["> ⚠ **This scan was UNAUTHENTICATED** — it only tested the public "
              "surface (login/marketing pages), NOT the logged-in application. A clean "
              "result here does **not** mean the app is secure. Re-run with a valid "
              "session cookie or bearer token to test the real app.", ""]
    if meta.get("reliability") == "unstable":
        L += ["> ⚠ Server was unstable during the scan (sustained 5xx/timeouts). "
              "Results may be incomplete — re-run at a lower rate.", ""]
    L += ["## Severity", "", "| Severity | Count |", "|---|---|"]
    for s in SEVERITY_ORDER:
        if meta["counts"].get(s):
            L.append(f"| {s.title()} | {meta['counts'][s]} |")
    # OWASP Top 10 coverage
    L += ["", "## OWASP Top 10 (2021) — findings per category", "",
          "| Category | Findings |", "|---|---|"]
    for cid in list(owasp.OWASP_TOP10.keys()):
        n = meta["owasp"].get(cid, 0)
        L.append(f"| {owasp.owasp_label(cid)} | {'**'+str(n)+'**' if n else '0'} |")
    # ASVS 5.0 coverage
    L += ["", "## OWASP ASVS 5.0 — findings per chapter", "",
          "| Chapter | Findings |", "|---|---|"]
    for ch in owasp.ASVS_CHAPTERS:
        n = meta["asvs"].get(ch, 0)
        if n:
            L.append(f"| {owasp.asvs_label(ch)} | **{n}** |")
    # WSTG coverage checklist
    cov = meta["coverage"]
    L += ["", "## WSTG coverage — what is and isn't automated", "",
          f"Automated tools fully cover {cov['auto']} / {cov['total']} WSTG "
          f"categories, partial on {cov['part']}, manual-only on {cov['manual']}.", "",
          "| WSTG | Area | Coverage | Notes |", "|---|---|---|---|"]
    badge = {"auto": "AUTO", "part": "PARTIAL", "manual": "MANUAL"}
    for wid, name, lvl, note in owasp.WSTG_COVERAGE:
        L.append(f"| {wid} | {name} | {badge[lvl]} | {note} |")
    # findings
    L += ["", "## Findings", "",
          "**Confidence:** `confirmed` = tool actively proved it · `firm` = strong "
          "signal, spot-check · `tentative` = candidate, **verify manually before "
          "reporting to a client**.", "",
          "| Severity | Confidence | OWASP | ASVS | Name | Location | Evidence (proof) | Recommended fix |",
          "|---|---|---|---|---|---|---|---|"]
    for f in findings:
        loc = (f["location"] or "")[:70]
        ev = (f.get("evidence") or f.get("detail") or "").replace("|", "/").replace("\n", " ")[:160]
        fix = (f.get("remediation") or "").replace("|", "/").replace("\n", " ")[:200]
        L.append(f"| {f['severity'].title()} | {f.get('confidence','firm')} | {f.get('owasp','NA')} | "
                 f"{f.get('asvs','') or '—'} | {f['name']} | `{loc}` | {ev} | {fix} |")
    path.write_text("\n".join(L))

def _write_html(path, meta, findings):
    counts = meta["counts"]
    # Summary cards double as the severity filter — a count you can't act on is
    # just decoration, and "which 3 are the highs?" was the first question every
    # reader asked of the old table.
    cards = [f'<button class="scard" type="button" data-sev="" data-n="{meta["total"]}" '
             f'style="--c:var(--ash)"><span class="n">{meta["total"]}</span>'
             f'<span class="l">Total</span><span class="go">show all ↓</span></button>']
    for s in SEVERITY_ORDER:
        n = counts.get(s, 0)
        if not n and s in ("info", "unknown"):
            continue                      # don't show empty rows nobody asked about
        cards.append(
            f'<button class="scard{" zero" if not n else ""}" type="button" data-sev="{s}" '
            f'data-n="{n}" style="--c:var(--{s})"><span class="n">{n}</span>'
            f'<span class="l">{s}</span>'
            f'{"<span class=go>jump ↓</span>" if n else ""}</button>')

    owasp_cells = ""
    for cid in owasp.OWASP_TOP10:
        if cid == "NA":
            continue
        n = meta["owasp"].get(cid, 0)
        owasp_cells += (f'<div class="ocell {"hot" if n else ""}"><span class="oid">{cid}</span>'
                        f'<span class="oname">{_esc(owasp.OWASP_TOP10[cid])}</span>'
                        f'<span class="ocount">{f"{n} finding" + ("s" if n != 1 else "") if n else "none"}</span></div>')

    cov = meta["coverage"]
    lvlcls = {"auto": "cauto", "part": "cpart", "manual": "cman"}
    lvltxt = {"auto": "Automated", "part": "Partial", "manual": "Manual only"}
    wstg_rows = "".join(
        f'<tr><td class="mono">{wid}</td><td>{_esc(name)}</td>'
        f'<td><span class="cov {lvlcls[lvl]}">{lvltxt[lvl]}</span></td>'
        f'<td style="color:var(--mut)">{_esc(note)}</td></tr>'
        for wid, name, lvl, note in owasp.WSTG_COVERAGE)

    # One card per finding. The old 8-column table put the proof and the fix in
    # the same cramped cell as everything else; here the title and location are
    # always visible and the detail opens on demand.
    rows = ""
    for i, f in enumerate(findings):
        sev = f.get("severity", "unknown")
        conf = f.get("confidence", "firm")
        loc = f.get("location") or ""
        ev = f.get("evidence") or f.get("detail") or ""
        fix = f.get("remediation") or ""
        cat = f.get("category", "")
        ow, asvs = f.get("owasp", "NA"), f.get("asvs", "")
        hay = _esc(" ".join((f.get("name", ""), cat, loc, ev, fix, ow, asvs, sev, conf)).lower())
        short = loc if len(loc) <= 90 else loc[:88] + "…"
        badges = (f'<span class="badge sevb">{sev}</span>'
                  f'<span class="badge confb c-{conf}">{conf}</span>')
        if cat:
            badges += f'<span class="badge tagb">{_esc(cat)}</span>'
        if ow and ow != "NA":
            badges += f'<span class="badge tagb">{_esc(ow)}</span>'
        if asvs:
            badges += f'<span class="badge tagb">ASVS {_esc(asvs)}</span>'
        rows += (
            f'<details class="finding" id="f{i}" data-sev="{sev}" data-hay="{hay}" '
            f'style="--c:var(--{sev})"{" open" if sev in ("critical", "high") else ""}>'
            f'<summary><div class="fhead"><div class="txt">'
            f'<div class="fname">{_esc(f.get("name",""))}</div>'
            f'<div class="floc">{_esc(short)}</div>'
            f'<div class="fbadges">{badges}</div>'
            f'</div><div class="chev">›</div></div></summary>'
            f'<div class="fbody">'
            + (f'<div class="block"><div class="lbl">Location</div>'
               f'<div class="urlfull">{_esc(loc)}</div></div>' if len(loc) > 90 else '')
            + (f'<div class="block proof"><div class="lbl">Evidence</div>'
               f'<div class="val">{_esc(ev)}</div></div>' if ev else '')
            + (f'<div class="block fix"><div class="lbl">How to fix</div>'
               f'<div class="val">{_esc(fix)}</div></div>' if fix else '')
            + '</div></details>')
    if not findings:
        rows = ('<div class="empty"><div class="big">✓</div>'
                '<b>No findings on the surface that was tested.</b><br>'
                'Check the scan was authenticated and in scope before treating this as clean.</div>')

    rel = meta.get("reliability", "ok")
    banners = ""
    if rel != "ok":
        banners += ('<div class="banner danger"><span class="ic">⚠</span><div>'
                    '<b>The server was unstable during this scan</b> (sustained 5xx or timeouts). '
                    'Findings may be incomplete or false — re-run at a lower rate before '
                    'trusting this report.</div></div>')
    if meta.get("partial"):
        banners += ('<div class="banner warn"><span class="ic">⏱</span><div>'
                    '<b>Partial scan.</b> This report was written before every phase finished '
                    '(time budget reached, or the scan was interrupted). More findings may '
                    'exist.</div></div>')
    if not meta.get("authenticated"):
        banners += ('<div class="banner warn"><span class="ic">🔓</span><div>'
                    '<b>This scan was unauthenticated.</b> It tested only the public surface — '
                    'login and marketing pages — not the logged-in application. A clean result '
                    'here does <b>not</b> mean the app is secure. Re-run with a session cookie '
                    'or bearer token to test the real app.</div></div>')

    preset_meta = (f'<span class="dot">·</span><span>{_esc(meta["preset"])} scan</span>'
                   if meta.get("preset") else "")

    html = (_HTML.replace("{{project}}", _esc(meta["project"]))
                 .replace("{{target}}", _esc(meta["target"]))
                 .replace("{{date}}", meta["date"])
                 .replace("{{total}}", str(meta["total"]))
                 .replace("{{presetmeta}}", preset_meta)
                 .replace("{{relbanner}}", banners)
                 .replace("{{chips}}", "".join(cards))
                 .replace("{{owasp}}", owasp_cells)
                 .replace("{{covauto}}", str(cov["auto"]))
                 .replace("{{covpart}}", str(cov["part"]))
                 .replace("{{covman}}", str(cov["manual"]))
                 .replace("{{covtot}}", str(cov["total"]))
                 .replace("{{wstg}}", wstg_rows)
                 .replace("{{rows}}", rows))
    path.write_text(html, encoding="utf-8")

def _esc(s):
    return (str(s).replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))

_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {{project}}</title>
<style>
:root{
  --ash:#475969; --storm:#6C7A87; --yellow:#FFDD0A;
  --bg:#F4F5F7; --card:#FFFFFF; --line:#E6E8EC; --line-2:#EDEFF2;
  --ink:#1f2933; --mut:#6C7A87; --mut-2:#95a1ac;
  --critical:#B3123A; --high:#E4572E; --medium:#E0A106; --low:#3D86C6;
  --info:#7A8794; --unknown:#7A8794;
  --ok:#22A664;
  --radius:12px; --radius-sm:8px;
  --shadow:0 1px 2px rgba(16,24,40,.04), 0 1px 3px rgba(16,24,40,.07);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 80px}
a{color:#2f6fb0}

/* ---------- header ---------- */
header{margin-bottom:22px}
.eyebrow{letter-spacing:.16em;text-transform:uppercase;font-size:11px;
  color:var(--mut);font-weight:700}
h1{margin:.28em 0 .3em;font-size:29px;letter-spacing:-.02em;line-height:1.2}
.metaline{color:var(--mut);font-size:13.5px;display:flex;flex-wrap:wrap;gap:6px 16px}
.metaline b{color:var(--ink);font-weight:600}
.metaline .dot{color:var(--line)}

/* ---------- banners ---------- */
.banner{border-radius:var(--radius);padding:14px 16px;margin:16px 0;font-size:14px;
  display:flex;gap:11px;align-items:flex-start;border:1px solid}
.banner .ic{flex:none;font-size:15px;line-height:1.5}
.banner.warn{background:#FFF8E1;border-color:#F3DFA0;color:#6b5312}
.banner.danger{background:#FDECEF;border-color:#F2C2CD;color:#8a1733}
.banner b{font-weight:650}

/* ---------- summary cards ---------- */
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));
  gap:10px;margin:20px 0 10px}
.scard{position:relative;background:var(--card);border:1px solid var(--line);
  border-radius:var(--radius);padding:15px 16px;cursor:pointer;text-align:left;
  font:inherit;color:inherit;transition:border-color .15s,box-shadow .15s,transform .1s}
.scard::before{content:"";position:absolute;left:0;top:12px;bottom:12px;width:3px;
  border-radius:3px;background:var(--c,var(--line))}
.scard:hover{border-color:var(--c,var(--storm));box-shadow:var(--shadow);transform:translateY(-1px)}
.scard:focus-visible{outline:2px solid var(--ash);outline-offset:2px}
.scard.on{border-color:var(--c);background:color-mix(in srgb,var(--c) 6%,#fff);
  box-shadow:0 0 0 1px var(--c) inset}
.scard.zero{opacity:.45;cursor:default}
.scard.zero:hover{border-color:var(--line);box-shadow:none;transform:none}
.scard .n{display:block;font-size:27px;font-weight:700;line-height:1.1;color:var(--c,var(--ink))}
.scard .l{display:block;margin-top:2px;font-size:11.5px;text-transform:uppercase;
  letter-spacing:.09em;color:var(--mut);font-weight:600}
.scard .go{position:absolute;right:13px;top:13px;font-size:12px;color:var(--mut-2);opacity:0;
  transition:opacity .15s}
.scard:hover .go{opacity:1}
.hint{color:var(--mut);font-size:12.5px;margin:2px 0 26px}

/* ---------- sections ---------- */
h2{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);
  font-weight:700;margin:34px 0 12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  overflow:hidden}
details.panel summary{cursor:pointer;padding:14px 17px;font-weight:600;font-size:14px;
  list-style:none;display:flex;align-items:center;gap:9px}
details.panel summary::-webkit-details-marker{display:none}
details.panel summary::before{content:"›";font-size:17px;color:var(--mut);
  transition:transform .15s;display:inline-block}
details.panel[open] summary::before{transform:rotate(90deg)}
details.panel summary:hover{background:var(--line-2)}
details.panel .body{padding:4px 17px 17px;border-top:1px solid var(--line-2)}
summary .sub{color:var(--mut);font-weight:400;font-size:13px}

/* ---------- filter bar ---------- */
.filterbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
#q{flex:1 1 220px;min-width:180px;padding:9px 12px;border:1px solid var(--line);
  border-radius:var(--radius-sm);font:inherit;background:var(--card);color:var(--ink)}
#q:focus{outline:none;border-color:var(--storm);box-shadow:0 0 0 3px rgba(71,89,105,.1)}
.clearbtn{padding:9px 14px;border:1px solid var(--line);background:var(--card);
  border-radius:var(--radius-sm);cursor:pointer;font:inherit;font-size:13.5px;color:var(--mut)}
.clearbtn:hover{border-color:var(--storm);color:var(--ink)}
.count{color:var(--mut);font-size:13px}

/* ---------- finding cards ---------- */
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);
  border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow)}
.finding > summary{cursor:pointer;padding:15px 17px;list-style:none;display:block}
.finding > summary::-webkit-details-marker{display:none}
.finding > summary:hover{background:#FAFBFC}
.fhead{display:flex;align-items:flex-start;gap:12px}
.fhead .txt{min-width:0;flex:1}
.fname{font-weight:650;font-size:15.5px;letter-spacing:-.01em;margin-bottom:3px}
.floc{color:var(--mut);font-size:12.5px;word-break:break-all}
.fbadges{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px;align-items:center}
.badge{font-size:11px;font-weight:650;letter-spacing:.04em;padding:3px 8px;border-radius:999px;
  text-transform:uppercase;white-space:nowrap}
.sevb{background:var(--c);color:#fff}
.confb{border:1px solid currentColor;background:transparent}
.c-confirmed{color:#1a7f4b}.c-firm{color:#2f6fb0}.c-tentative{color:#96701a}
.tagb{background:var(--line-2);color:var(--mut);font-weight:600;text-transform:none;
  font-family:ui-monospace,Menlo,monospace;font-size:10.5px}
.chev{flex:none;color:var(--mut-2);font-size:19px;line-height:1;transition:transform .15s;
  margin-top:2px}
.finding[open] .chev{transform:rotate(90deg)}
.fbody{padding:2px 17px 17px;border-top:1px solid var(--line-2);margin-top:0}
.block{margin-top:14px}
.block .lbl{font-size:10.5px;font-weight:700;letter-spacing:.11em;text-transform:uppercase;
  color:var(--mut);margin-bottom:5px}
.block .val{font-size:14px;line-height:1.62;white-space:pre-wrap;word-break:break-word}
.block.fix .val{background:#F2FAF5;border:1px solid #CFE9DA;border-radius:var(--radius-sm);
  padding:11px 13px}
.block.proof .val{background:#FAFBFC;border:1px solid var(--line);border-radius:var(--radius-sm);
  padding:11px 13px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;line-height:1.6}
.urlfull{color:var(--mut);font-size:12.5px;word-break:break-all}

.empty{background:var(--card);border:1px dashed var(--line);border-radius:var(--radius);
  padding:40px 20px;text-align:center;color:var(--mut)}
.empty .big{font-size:34px;margin-bottom:8px}
#nomatch{display:none}

/* ---------- OWASP grid ---------- */
.ogrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}
.ocell{border:1px solid var(--line);border-radius:var(--radius-sm);padding:11px 13px;
  display:flex;flex-direction:column;gap:2px;background:#FCFCFD}
.ocell.hot{border-color:#F2C2CD;background:#FDF5F7}
.ocell .oid{font:700 11px/1 ui-monospace,Menlo,monospace;color:var(--mut)}
.ocell.hot .oid{color:var(--critical)}
.ocell .oname{font-size:12.5px;line-height:1.35}
.ocell .ocount{font-size:11px;color:var(--mut);margin-top:2px}
.ocell.hot .ocount{color:var(--critical);font-weight:650}

/* ---------- tables ---------- */
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--mut);font-weight:700;padding:9px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line-2);vertical-align:top}
tr:last-child td{border-bottom:none}
.cov{font-size:11px;font-weight:650;padding:2px 8px;border-radius:999px;white-space:nowrap}
.cauto{background:#E8F6EE;color:#1a7f4b}
.cpart{background:#FFF6DF;color:#8a6a10}
.cman{background:#FDECEF;color:#8a1733}

footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--mut-2);font-size:12.5px;line-height:1.7}

@media(max-width:640px){
  .wrap{padding:20px 14px 60px} h1{font-size:23px}
  .fhead{gap:9px} .summary{gap:8px}
}
@media print{
  body{background:#fff} .filterbar,.scard .go,.chev{display:none}
  .finding{break-inside:avoid;box-shadow:none} details{open:true}
  .finding > .fbody{display:block !important}
}
</style></head><body><div class="wrap">

<header>
  <div class="eyebrow">Security Assessment</div>
  <h1>{{project}}</h1>
  <div class="metaline">
    <span>Target <b>{{target}}</b></span><span class="dot">·</span>
    <span>{{date}}</span><span class="dot">·</span>
    <span><b>{{total}}</b> findings</span>{{presetmeta}}
  </div>
</header>

{{relbanner}}

<div class="summary" id="summary">{{chips}}</div>
<div class="hint">Click a card to jump to those issues.</div>

<h2>Findings</h2>
<div class="filterbar">
  <input id="q" type="search" placeholder="Search findings, locations, fixes…" autocomplete="off">
  <button class="clearbtn" id="clear" type="button">Show all</button>
  <button class="clearbtn" id="toggle" type="button">Expand all</button>
  <span class="count" id="count"></span>
</div>
<div id="findings">{{rows}}</div>
<div class="empty" id="nomatch"><div class="big">🔍</div>No findings match this filter.</div>

<h2>Coverage &amp; standards</h2>
<details class="panel" style="margin-bottom:10px">
  <summary>OWASP Top 10 — 2021 <span class="sub">— where these findings land</span></summary>
  <div class="body"><div class="ogrid">{{owasp}}</div></div>
</details>
<details class="panel">
  <summary>What automated testing does and doesn't cover
    <span class="sub">— {{covauto}} of {{covtot}} areas fully automated</span></summary>
  <div class="body">
    <p style="font-size:13.5px;color:var(--mut);margin:12px 0 14px">
      Automated tools fully cover <b>{{covauto}}</b> of {{covtot}} WSTG areas, partially cover
      <b>{{covpart}}</b>, and <b>{{covman}}</b> need manual testing. A clean automated report is
      not a clean application — the manual rows below (authorization/IDOR, business logic) are
      where real bugs hide.</p>
    <table><thead><tr><th>WSTG</th><th>Area</th><th>Coverage</th><th>Notes</th></tr></thead>
    <tbody>{{wstg}}</tbody></table>
  </div>
</details>

<footer>
  <b>Confidence:</b> <span class="badge confb c-confirmed">confirmed</span> the tool actively
  proved it · <span class="badge confb c-firm">firm</span> strong signal, spot-check ·
  <span class="badge confb c-tentative">tentative</span> candidate — verify manually before
  reporting to a client.<br>
  Generated by DAST Harness. Findings tagged to OWASP Top 10 (2021) and ASVS 5.0.
  Only test systems you are authorised to assess.
</footer>

</div>
<script>
(function(){
  var sev = "", q = "";
  var cards = [].slice.call(document.querySelectorAll('.scard'));
  var items = [].slice.call(document.querySelectorAll('.finding'));
  var countEl = document.getElementById('count');
  var noMatch = document.getElementById('nomatch');
  var qEl = document.getElementById('q');

  function apply(scroll){
    var shown = 0, needle = q.toLowerCase();
    items.forEach(function(el){
      var okSev = !sev || el.dataset.sev === sev;
      var okQ = !needle || el.dataset.hay.indexOf(needle) !== -1;
      var vis = okSev && okQ;
      el.hidden = !vis;
      if (vis) shown++;
    });
    cards.forEach(function(c){ c.classList.toggle('on', !!sev && c.dataset.sev === sev); });
    noMatch.style.display = shown ? 'none' : 'block';
    countEl.textContent = (sev || needle)
      ? shown + ' of ' + items.length + ' shown'
      : (items.length ? items.length + ' findings' : '');
    if (scroll) document.getElementById('findings').scrollIntoView({block:'start'});
  }

  cards.forEach(function(c){
    c.addEventListener('click', function(){
      var s = c.dataset.sev;
      if (s && +c.dataset.n === 0) return;     // nothing to jump to
      sev = (sev === s) ? "" : s;              // click again to clear
      apply(true);
    });
  });
  var tog = document.getElementById('toggle');
  if (tog) tog.addEventListener('click', function(){
    // Act on what's visible: "expand all" during a filter shouldn't silently
    // open the findings that filter is hiding.
    var vis = items.filter(function(el){ return !el.hidden; });
    var expand = vis.some(function(el){ return !el.open; });
    vis.forEach(function(el){ el.open = expand; });
    tog.textContent = expand ? 'Collapse all' : 'Expand all';
  });
  qEl.addEventListener('input', function(){ q = qEl.value; apply(false); });
  document.getElementById('clear').addEventListener('click', function(){
    sev = ""; q = ""; qEl.value = ""; apply(false);
  });
  // Expand every finding before printing so nothing is silently omitted.
  window.addEventListener('beforeprint', function(){
    items.forEach(function(el){ el.open = true; });
  });
  apply(false);
})();
</script>
</body></html>"""

# ------------------------------------------------------------------ #
#  Main
# ------------------------------------------------------------------ #
def _run_incomplete(run: Path) -> bool:
    """True if a run has no complete report (missing report.json, or partial)."""
    rj = run / "report.json"
    if not rj.exists():
        return True
    try:
        return bool(json.loads(rj.read_text()).get("meta", {}).get("partial"))
    except Exception:
        return True          # unreadable report => treat as failed

def _strip_crawl(run: Path) -> int:
    """Delete a run's heavy intermediates (crawl/ + any big non-report file),
    keeping the report deliverables. Returns bytes reclaimed."""
    keep = {"REPORT.html", "REPORT.md", "report.json", "report.sarif"}
    freed = 0
    crawl = run / "crawl"
    if crawl.is_dir():
        freed += sum(f.stat().st_size for f in crawl.rglob("*") if f.is_file())
        shutil.rmtree(crawl, ignore_errors=True)
    for f in list(run.rglob("*")):
        try:
            if f.is_file() and f.name not in keep and f.stat().st_size > 2 * 1024 * 1024:
                freed += f.stat().st_size
                f.unlink()
        except Exception:
            pass
    return freed

def reap_failed_runs(project_root: Path, current: Path, min_age_mins: int = 30) -> int:
    """Strip crawl data from earlier failed/interrupted runs so a crashing scan
    (even an un-catchable OOM SIGKILL) can't leave hundreds of MB behind — the
    NEXT scan reaps the dead one. Never touches the current run or anything
    modified within min_age_mins (a scan that may still be running). Best effort."""
    if not project_root.is_dir():
        return 0
    cutoff = time.time() - min_age_mins * 60
    freed = 0
    try:
        cur = current.resolve()
    except Exception:
        cur = current
    for run in project_root.glob("*/*"):
        try:
            if not run.is_dir() or run.resolve() == cur:
                continue
            if run.stat().st_mtime > cutoff:          # too fresh — may be in progress
                continue
            if (run / "crawl").is_dir() and _run_incomplete(run):
                freed += _strip_crawl(run)
        except Exception:
            continue
    return freed

def main():
    ap = argparse.ArgumentParser(description="DAST Harness")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--phase", help="run only this phase", default=None)
    ap.add_argument("--preset", default=None,
                    help="scan preset: " + " | ".join(PRESETS))
    ap.add_argument("--list-presets", action="store_true",
                    help="show the available presets and exit")
    args = ap.parse_args()

    if args.list_presets:
        for k, v in PRESETS.items():
            print(f"\n{_c(k, 'bold')}  —  {v['label']}")
            print(f"  {v['desc']}")
            print(f"  phases: {', '.join(v['phases'])}")
        print()
        return

    cfg = yaml.safe_load(open(args.config))
    # --preset beats a preset named in the config file.
    if args.preset or cfg.get("preset"):
        cfg = apply_preset(cfg, args.preset or cfg.get("preset"))
    ph = cfg["phases"]

    # project run folder
    date = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    d = Path(cfg["project"]["workdir"]) / cfg["project"]["name"] / date
    (d / "crawl").mkdir(parents=True, exist_ok=True)
    (d / "reports").mkdir(parents=True, exist_ok=True)

    print(_c(f"\nDAST Harness — {cfg['project']['name']}", "bold"))
    print(f"Target : {cfg['target']['scope_domain']}")
    if cfg.get("preset"):
        print(f"Preset : {cfg['preset']} — {PRESETS[cfg['preset']]['label']}")
    print(f"Run dir: {d}")

    # Resource guard: reap crawl data left by earlier failed/killed runs, then
    # refuse to start if the disk is critically low — a failed scan must never
    # burn the disk (the crawl phase alone can write hundreds of MB).
    workroot = Path(cfg["project"]["workdir"])
    reclaimed = reap_failed_runs(workroot, d)
    if reclaimed:
        info(f"Reclaimed {reclaimed/1e6:.0f} MB of crawl data from earlier "
             f"failed/interrupted runs before starting.")
    try:
        free_gb = shutil.disk_usage(workroot).free / (1024 ** 3)
    except Exception:
        free_gb = None
    min_free_gb = float((cfg.get("resilience", {}) or {}).get("min_free_gb", 2))
    if free_gb is not None and free_gb < min_free_gb:
        err(f"Only {free_gb:.1f} GB free on the scan volume (floor {min_free_gb} GB) — "
            "aborting before the scan fills the disk. Free space, run "
            "web/cleanup_runs.py, or lower resilience.min_free_gb, then re-run.")
        sys.exit(2)

    banner("Tool check")
    zap_via_docker = cfg.get("zap", {}).get("use_docker", True)
    for name, path in cfg["tools"].items():
        # When ZAP runs via Docker, the local zap.sh binary is irrelevant —
        # don't warn about it here; the Docker line below reports ZAP readiness.
        if name == "zap" and zap_via_docker:
            continue
        if name == "katana" and not tool_ok(path):
            info("katana: NOT found — falling back to the built-in crawler "
                 "(no install needed; less deep on JS-heavy SPAs)")
            continue
        (ok if tool_ok(path) else warn)(
            f"{name}: {'found' if tool_ok(path) else 'NOT found — related phase will be skipped'}")
    if cfg["phases"].get("zap") and zap_via_docker:
        (ok if tool_ok("docker") else warn)(
            "ZAP (via Docker): " + ("found — Docker present (ensure the daemon is running)"
             if tool_ok("docker") else "Docker NOT found — ZAP phase will be skipped"))
    if cfg["auth"].get("enabled") and all("PASTE_YOUR" in h for h in cfg["auth"]["headers"]):
        warn("Auth is enabled but headers still contain placeholders — "
             "scan will be UNAUTHENTICATED and miss most of the app.")
    # Nuclei is useless without its templates — and it fails SILENTLY (0 findings).
    # Warn loudly so a missing-template run is never mistaken for a clean app.
    _nuclei_phase = (args.phase in ("fuzz_dast", "template_scan")) or \
                    (args.phase is None and (ph.get("fuzz_dast") or ph.get("template_scan")))
    if tool_ok(cfg["tools"].get("nuclei", "nuclei")) and _nuclei_phase:
        if not _nuclei_templates_present():
            warn("Nuclei templates NOT found — DAST fuzzing + template scan will "
                 "return ZERO findings (this is NOT a clean result). Run once: "
                 "nuclei -update-templates")

    def want(p): return (args.phase is None and ph.get(p)) or args.phase == p

    # Pre-flight: abort if the server is already unhealthy (avoids junk reports)
    if cfg.get("resilience", {}).get("preflight", True) and args.phase is None:
        if not preflight(cfg):
            sys.exit(2)
    monitor = HealthMonitor(cfg) if cfg.get("resilience", {}).get("monitor", True) else None
    if monitor: monitor.start()

    crawl_jsonl = d / "crawl" / "urls.jsonl"
    endpoints   = d / "crawl" / "urls-security.jsonl"
    dast_out    = d / "reports" / "dast.jsonl"
    tmpl_out    = d / "reports" / "templates.jsonl"
    zap_out     = d / "reports" / "zap.json"
    nikto_out   = d / "reports" / "nikto.json"
    testssl_out = d / "reports" / "testssl.json"
    secrets, tokens, sqlmap_res, idor_res = [], [], [], []
    dep_findings, cors_res, token_probe_findings, csrf_findings = [], [], [], []
    upload_findings = []
    zap_used = nikto_used = testssl_used = False

    # ---------------------------------------------------------------- #
    #  Budget + checkpointing
    # ---------------------------------------------------------------- #
    # A scan that is interrupted — killed, timed out, Ctrl-C'd — used to
    # produce NOTHING, because the report was only written after the last
    # phase. Every phase now checkpoints, so whatever finished is on disk.
    lim = cfg.get("limits", {}) or {}
    budget = int(lim.get("budget_secs", 0) or 0)
    started = time.monotonic()
    deadline = (started + budget) if (budget > 0 and args.phase is None) else None
    global _SCAN_DEADLINE
    _SCAN_DEADLINE = deadline        # every subprocess is clamped to this
    parallel = bool(lim.get("parallel", True))
    over_budget = []

    def gate(label: str) -> bool:
        """False once the wall-clock budget is spent.

        The budget is checked BETWEEN phases: a phase already running is
        allowed to finish rather than being killed halfway through writing its
        output, so a run can overshoot by up to one phase. The crawler is the
        one long phase that gets the remaining budget handed to it directly
        (below), because it is usually the longest.
        """
        if deadline and time.monotonic() > deadline:
            if not over_budget:
                warn(f"Time budget ({budget}s) reached — skipping the remaining "
                     f"phases and reporting what has been collected so far.")
            over_budget.append(label)
            return False
        return True

    def checkpoint():
        """Refresh the on-disk report with everything collected so far."""
        try:
            f = collect_findings(dast_out, tmpl_out, secrets, tokens, sqlmap_res,
                                 zap_json=zap_out if zap_used else None,
                                 nikto_json=nikto_out if nikto_used else None,
                                 testssl_json=testssl_out if testssl_used else None,
                                 idor_res=idor_res, dep_findings=dep_findings,
                                 cors_res=cors_res,
                                 token_probe_findings=token_probe_findings,
                                 csrf_findings=csrf_findings,
                                 upload_findings=upload_findings)
            write_reports(cfg, d, f, reliability="ok", partial=True)
        except Exception as e:
            warn(f"Interim report refresh skipped: {e}")

    if want("crawl") and gate("crawl"):
        # crawler: auto (katana if installed, else built-in) | builtin | katana
        choice = str(cfg.get("scan", {}).get("crawler", "auto")).lower()
        have_katana = tool_ok(cfg["tools"].get("katana", "katana"))
        if choice == "katana" and not have_katana:
            warn("crawler: katana requested but not installed — using the built-in crawler.")
            choice = "builtin"
        use_katana = have_katana and choice in ("auto", "katana")
        # Don't let the crawler's own budget run past the scan's overall one.
        if deadline:
            left = max(5, int(deadline - time.monotonic()))
            sc = cfg.setdefault("scan", {})
            sc["builtin_budget_secs"] = min(int(sc.get("builtin_budget_secs", 120)), left)
        crawl_jsonl = phase_crawl(cfg, d) if use_katana else phase_crawl_builtin(cfg, d)
        endpoints = triage_endpoints(cfg, crawl_jsonl, d)
        # Crawl is the longest single phase of a quick scan; checkpoint here so
        # an interruption during the NEXT phase still leaves a readable report.
        checkpoint()

    # API spec ingestion — append spec endpoints so the fuzzer reaches routes
    # the crawler never would. Runs before the fuzzing phases that consume them.
    if want("api_spec") and cfg.get("api_spec", {}).get("source") and gate("api_spec"):
        if not endpoints.exists():
            endpoints.parent.mkdir(parents=True, exist_ok=True)
            endpoints.touch()
        phase_api_spec(cfg, endpoints, d)

    # ---------------------------------------------------------------- #
    #  Built-in probes — pure Python, I/O-bound, independent of each other
    # ---------------------------------------------------------------- #
    # These are all capped-size HTTP probes that share no state and write no
    # common file, so they overlap safely. They are the whole of a `quick`
    # scan, which is why this is where parallelism pays off most.
    probe_jobs = []
    if want("secret_scan") and gate("secret_scan"):
        probe_jobs.append(("secret_scan", lambda: phase_secret_scan(cfg, crawl_jsonl, d)))
    if want("idor_probe") and gate("idor_probe"):
        probe_jobs.append(("idor_probe", lambda: phase_idor(cfg, endpoints, d, crawl_jsonl)))
    if want("depscan") and gate("depscan"):
        probe_jobs.append(("depscan", lambda: phase_depscan(cfg, crawl_jsonl, d)))
    if want("cors") and gate("cors"):
        probe_jobs.append(("cors", lambda: phase_cors(cfg, endpoints, d)))
    if want("csrf") and gate("csrf"):
        probe_jobs.append(("csrf", lambda: phase_csrf(cfg, endpoints, crawl_jsonl, d)))
    if probe_jobs:
        res = run_parallel(probe_jobs) if parallel else {n: f() for n, f in probe_jobs}
        secrets       = res.get("secret_scan") or []
        idor_res      = res.get("idor_probe") or []
        dep_findings  = res.get("depscan") or []
        cors_res      = res.get("cors") or []
        csrf_findings = res.get("csrf") or []
        checkpoint()

    # token_analysis reads the secrets the scan just found, so it follows them.
    if want("token_analysis") and gate("token_analysis"):
        tokens = phase_token_analysis(cfg, secrets, d)
        checkpoint()

    # ---------------------------------------------------------------- #
    #  External scanners — the long poles, and mutually independent
    # ---------------------------------------------------------------- #
    # zap / nikto / testssl each drive their own binary and write their own
    # output file. Run serially they add up to hours; run together the group
    # costs whatever the slowest one costs.
    scanner_jobs = []
    if want("zap") and (tool_ok("docker") or tool_ok(cfg["tools"].get("zap", "zap.sh"))) and gate("zap"):
        scanner_jobs.append(("zap", lambda: phase_zap(cfg, d)))
    if want("nikto") and tool_ok(cfg["tools"].get("nikto", "nikto")) and gate("nikto"):
        scanner_jobs.append(("nikto", lambda: phase_nikto(cfg, d)))
    if want("testssl") and tool_ok(cfg["tools"].get("testssl", "testssl.sh")) and gate("testssl"):
        scanner_jobs.append(("testssl", lambda: phase_testssl(cfg, d)))
    if scanner_jobs:
        res = run_parallel(scanner_jobs) if parallel else {n: f() for n, f in scanner_jobs}
        if res.get("zap") is not None:
            zap_out, zap_used = res["zap"], True
        if res.get("nikto") is not None:
            nikto_out, nikto_used = res["nikto"], True
        if res.get("testssl") is not None:
            testssl_out, testssl_used = res["testssl"], True
        checkpoint()

    # Nuclei passes share the template cache and the endpoint list; keep them
    # sequential so one pass isn't starved of file handles by the other.
    if want("fuzz_dast") and tool_ok(cfg["tools"]["nuclei"]) and gate("fuzz_dast"):
        dast_out = phase_fuzz_dast(cfg, endpoints, d)
        checkpoint()
    if want("template_scan") and tool_ok(cfg["tools"]["nuclei"]) and gate("template_scan"):
        tmpl_out = phase_template_scan(cfg, endpoints, d)
        checkpoint()

    # Active phases that forge credentials or write to the target — always
    # explicit opt-ins, never part of a preset, and never parallelised.
    if want("token_probe") and gate("token_probe"):
        token_probe_findings = phase_token_probe(cfg, endpoints, crawl_jsonl, secrets, d)
        checkpoint()
    if want("upload") and gate("upload"):
        upload_findings = phase_upload(cfg, endpoints, crawl_jsonl, d)
        checkpoint()
    if want("sqlmap_confirm") and ph.get("sqlmap_confirm") and tool_ok(cfg["tools"]["sqlmap"]) and gate("sqlmap_confirm"):
        sqlmap_res = phase_sqlmap(cfg, dast_out, d)
        checkpoint()

    if over_budget:
        warn("Skipped for time budget: " + ", ".join(dict.fromkeys(over_budget)))


    if monitor: monitor.stop()
    reliability = "unstable" if (monitor and monitor.unstable) else "ok"

    banner("Building consolidated report")
    findings = collect_findings(dast_out, tmpl_out, secrets, tokens, sqlmap_res,
                                zap_json=zap_out if zap_used else None,
                                nikto_json=nikto_out if nikto_used else None,
                                testssl_json=testssl_out if testssl_used else None,
                                idor_res=idor_res,
                                dep_findings=dep_findings, cors_res=cors_res,
                                token_probe_findings=token_probe_findings,
                                csrf_findings=csrf_findings,
                                upload_findings=upload_findings)
    # A budget-truncated run is still incomplete, even though it finished
    # cleanly — say so in the report rather than implying full coverage.
    meta = write_reports(cfg, d, findings, reliability=reliability,
                         partial=bool(over_budget))

    banner("DONE")
    print(f"Elapsed: {time.monotonic() - started:.0f}s"
          + (f"  (preset: {cfg['preset']})" if cfg.get("preset") else ""))
    if meta["reliability"] == "unstable":
        warn("Server was UNSTABLE during the scan — treat results as provisional "
             "and re-run at a lower rate.")
    print(_c(f"Total findings: {meta['total']}", "bold"))
    for s in SEVERITY_ORDER:
        if meta["counts"].get(s):
            print(f"  {s:9} {meta['counts'][s]}")
    if any(v for k, v in meta["owasp"].items() if k != "NA"):
        print("\nOWASP Top 10 hits:")
        for cid in owasp.OWASP_TOP10:
            if meta["owasp"].get(cid) and cid != "NA":
                print(f"  {owasp.owasp_label(cid)}: {meta['owasp'][cid]}")
    print(f"\nHTML report : {d/'REPORT.html'}")
    print(f"Markdown    : {d/'REPORT.md'}")
    print(f"JSON        : {d/'report.json'}")
    print(f"SARIF       : {d/'report.sarif'}  (import into GitHub / DefectDojo)")

if __name__ == "__main__":
    main()
