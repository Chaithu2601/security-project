# DAST Harness — Operator Manual

A guide to the web UI (`http://127.0.0.1:8700`), what every option does, how each
scanner works, and how to read the results.

- **UI backend:** `web/app.py` (FastAPI, localhost-only). It never scans itself —
  it writes your form choices to a temp YAML and runs `python dast_scan.py --config <tmp>`.
- **Engine:** `dast_scan.py` orchestrates the external scanners + built-in probes,
  maps findings to OWASP Top 10 (2021) / ASVS 5.0, and writes
  `REPORT.html`, `REPORT.md`, `report.json`, `report.sarif`.
- **Only scan hosts you own or are authorised to test.**

---

## 0. The engines we use (scanner inventory)

The harness doesn't reinvent scanners — it orchestrates best-in-class open-source
tools plus its own lightweight probes. Verified working on this machine:

| Engine | Version | What it is | How it works | What we use it for |
|---|---|---|---|---|
| **nuclei** | v3.9.0 (templates v10.4.6) | Fast template-driven vulnerability scanner (ProjectDiscovery) | Reads YAML templates that describe a request + a match condition. In `-dast` mode it *fuzzes* crawled params with attack payloads and matches the response; in template mode it signature-matches known CVEs/exposures/misconfigs. | The two Nuclei phases: DAST injection fuzzing **and** CVE/exposure/misconfig scanning. |
| **katana** | latest | Fast web crawler (ProjectDiscovery) | Follows links/forms/JS to enumerate the app's URLs and parameters. | Discovering the endpoint list every other phase feeds on (the implicit crawl). |
| **nikto** | 2.6.0 | Classic web-server scanner | Requests a big list of known-bad paths/files and inspects banners/responses. | Dangerous files, outdated server software, server misconfig. |
| **testssl.sh** | 3.2.4 | Deep TLS/SSL auditor (bash) | Opens many TLS handshakes to enumerate protocols, ciphers, cert chain, and known TLS CVEs. | TLS/cert/cipher weaknesses (OWASP A02 / ASVS V12). |
| **sqlmap** | 1.10.7 | Automated SQL-injection exploitation | Takes a candidate injection point and runs boolean/time/error/UNION techniques to confirm and extract. | High-confidence confirmation of Nuclei's SQLi hits (optional). |
| **OWASP ZAP** | via Docker (`zaproxy/zap-stable`) | Full-featured web-app attack proxy | Spiders the app then fires active attack rules through a proxy. | Broad active scan as an alternative/complement to Nuclei DAST. |
| **Built-in probes** | (in `dast_scan.py`) | Custom Python checks | Direct HTTP requests + response analysis — no external tool. | Secret leaks, JWT/token analysis, IDOR/BOLA, CORS, CSRF/cookie flags, black-box SCA. |

The engine guards every phase with `tool_ok(...)` and a template-presence check, so a
missing tool is **skipped**, not fatal. Sections 2–3 below map each UI checkbox to
the engine it drives.

---

## 1. How a scan flows

```
Browser form ──POST /api/scan──> build_config() ──> web/runs/<job>.yaml
                                                        │
                                     subprocess: python dast_scan.py --config <yaml>
                                                        │
    crawl (katana or built-in) ──> phases run ──> _refine_findings() trust layer
                                                        │
                    web/runs/projects/<name>/<date>/{REPORT.html, report.json, ...}
```

- **Scan depth presets.** Quick / Standard / Deep set the phase list and the
  time budget in one choice; Custom exposes every phase individually.
  - **Quick** needs *no external tools at all* — a built-in stdlib crawler feeds
    the pure-Python checks (secrets, JWT lifetimes, vulnerable JS libs, CORS,
    cookie/CSRF flags, IDOR). Typically 1-3 minutes.
  - **Standard** adds katana, the Nuclei template pass and testssl.
  - **Deep** adds Nuclei DAST fuzzing, ZAP and Nikto — hours, real attack traffic.
  - No preset enables `token_probe`, `upload` or `sqlmap_confirm`; those forge
    credentials or write to the target and stay explicit opt-ins.
- **Crawl is implicit.** Any phase that needs discovered endpoints
  (`fuzz_dast, template_scan, secret_scan, token_analysis, depscan, idor_probe,
  cors, token_probe, csrf`) auto-enables the crawl first. Katana is used when
  installed; otherwise the built-in crawler runs, so a missing katana no longer
  produces an empty scan that looks like a clean application.
- **Phases run in parallel** where they are independent: the built-in probes as
  one group, zap/nikto/testssl as another. Each phase's log is buffered and
  replayed whole, so concurrent output still reads phase by phase. Untick
  *Run independent phases in parallel* for WAF-fronted targets — concurrency
  raises the request rate.
- **The report is refreshed after every phase.** A scan that is killed or times
  out still leaves a readable report of whatever finished, marked **PARTIAL**.
  `limits.budget_secs` caps total wall-clock and is passed down to the external
  tools, so a budget genuinely bounds the run rather than waiting out nuclei's
  own multi-hour timeout.
- **Live output** streams to the page via Server-Sent Events (`/api/scan/<id>/stream`).
- **Abort** sends SIGTERM to the engine subprocess (`/api/scan/<id>/abort`).

---

## 2. Scan types (the checkboxes)

| UI option | Phase key | Tool | Purpose | How it works |
|---|---|---|---|---|
| **Nuclei DAST fuzzing (injection)** | `fuzz_dast` | nuclei `-dast` | Find active injection bugs (SQLi/XSS/SSTI/LFI/SSRF/RCE/redirect/CRLF/XXE) | Takes crawled URLs, mutates each parameter with attack payloads, and matches on the response (error strings, reflected markers, time delays, OOB callbacks). Scoped by the injection-type tags you tick. **Heaviest load on the target.** |
| **Nuclei templates (CVE / exposure / misconfig)** | `template_scan` | nuclei | Known-CVE, exposed-panel, misconfig, missing-header checks | Runs the community nuclei-templates against discovered URLs — signature matching, not fuzzing. Passive-ish, low load. |
| **OWASP ZAP active scan** | `zap` | ZAP (Docker) | Full active web-app attack suite | Spiders + fires ZAP's active attack rules. Mode: `full` (active), `baseline` (passive only), `api` (drive from an API spec). Runs via `zaproxy/zap-stable` Docker image — no local install needed. |
| **Nikto web-server scan** | `nikto` | nikto | Dangerous files, outdated server software, server misconfig | Requests a large list of known-bad paths/files and checks banners. Noisy; the trust layer filters its known false patterns. |
| **testssl.sh TLS/cipher scan** | `testssl` | testssl.sh | TLS/cert/cipher weaknesses (OWASP A02 / ASVS V12) | Negotiates many TLS handshakes to enumerate protocols, ciphers, cert chain, and known TLS CVEs. Network-only, doesn't touch the app. |
| **Secret/key leak scan (frontend JS)** | `secret_scan` | built-in | Leaked API keys/tokens in JS & responses | Greps crawled JS and HTTP responses against secret regexes (AWS keys, tokens, etc.). Passive. |
| **JWT / token lifetime analysis (passive)** | `token_analysis` | built-in | Weak/long-lived/non-expiring JWTs | Decodes JWTs seen in traffic, flags missing/long `exp`, weak `alg`. Read-only. |
| **Active token / broken-auth probe** | `token_probe` | built-in | Broken auth (A01/A07) | Actively replays, forges, and tampers the session token against the API to see what's accepted. **Intrusive** — off by default. |
| **IDOR / access-control probe** | `idor_probe` | built-in | IDOR/BOLA (A01 / ASVS V8) | Auto-discovers object URLs (numeric/UUID ids) from the crawl, then compares an authenticated request vs. anonymous (or user A vs. user B). If A gets B's data within the similarity tolerance → flag. |
| **Vulnerable frontend JS libraries (SCA)** | `depscan` | built-in | Outdated JS libs with known CVEs (A06) | Black-box: fingerprints library names/versions from loaded JS and maps to known-vuln versions. |
| **CORS misconfiguration probe** | `cors` | built-in | Overly-permissive CORS (A05 / ASVS V3) | Sends crafted `Origin` headers and inspects `Access-Control-Allow-Origin/Credentials` reflection. |
| **CSRF / cookie-security check** | `csrf` | built-in | Missing CSRF tokens; weak cookie flags (A01/A05) | Checks `SameSite/Secure/HttpOnly` on cookies and looks for anti-CSRF tokens on state-changing forms. |
| **API spec ingestion (OpenAPI/GraphQL)** | `api_spec` | built-in | Expand coverage beyond what the crawler finds | Ingests an OpenAPI/Swagger/GraphQL spec (URL or file) and feeds its endpoints into the scanners. Needs a spec source or it's skipped. |
| **sqlmap confirmation of SQLi** | `sqlmap_confirm` | sqlmap | Confirm nuclei SQLi hits, extract proof | Re-tests nuclei's SQLi candidates with sqlmap for a high-confidence confirmation. Slow, writes to a local DB; off by default. |

---

## 3. Injection test types (only apply to **Nuclei DAST fuzzing**)

Tick which classes to fuzz; **none ticked = fuzz all**. Maps to nuclei `-dast` tags:

`sqli` SQL Injection · `xss` Cross-Site Scripting · `ssti` Server-Side Template
Injection · `lfi` Local File Inclusion · `ssrf` Server-Side Request Forgery ·
`rce` Remote Code Execution · `redirect` Open Redirect · `crlf` CRLF Injection ·
`xxe` XML External Entity.

> Note: the old `fuzzing-req-*` location tags no longer exist in nuclei-templates;
> `-dast` already scopes to fuzzing templates, so only the class tags above are used.

---

## 4. Other form fields

| Field | Meaning |
|---|---|
| **Target URL** | Seed to crawl from. Scheme + non-standard port are honoured (fixes http-only apps). |
| **Project name / Scope domain** | Report label + the domain fuzzing is allowed to stay within (defaults to the URL host). |
| **Auth: cookie / bearer / raw headers** | Sent on every crawl + fuzz request so you scan the app *logged in*. Bearer auto-prefixes `Authorization: Bearer`. |
| **ZAP mode** | `full` / `baseline` / `api`. |
| **API spec source / format** | OpenAPI/Swagger/GraphQL URL or path (only used if API-spec scan is on). |
| **Rate limit** | Max requests/sec to the target. **Lower this if the target 504s / falls over.** |
| **Concurrency** | Parallel workers. Lower it alongside rate limit to reduce load. |
| **Crawl depth** | How deep Katana follows links. Lower = faster, smaller scope. |

---

## 5. Trust layer (why the report is short but honest)

Before writing the report, `_refine_findings()`:
- drops scanner artifacts (Nikto `ARRAY(0x..)` noise, testssl local-OpenSSL errors),
- drops phantom-CMS XSS signatures Nikto invents,
- suppresses false broken-auth "criticals" on public endpoints,
- de-dupes and caps over-rated severities.

Each finding carries a **confidence** tier — `confirmed` / `firm` / `tentative`.
Tentatives are meant for human verification. No DAST tool is "100% accurate";
this harness trades raw volume for findings a customer can trust.

---

## 6. Reading / downloading results

- Live report: `/api/scan/<job_id>/report` (and `.json`)
- Past runs list: `/api/runs` → each has a `rel` = `<project>/<date>`
- Past report: `/api/run/report?path=<project>/<date>`
- Downloads: `/api/{scan/<id>|run}/download/{html|md|json|sarif}`
- On disk: `web/runs/projects/<project>/<date>/`

---

## 7. Troubleshooting

**Target returns 504 during a scan.** The 504 comes from the *target's* gateway
(e.g. AWS CloudFront/ELB — check the response `server:` header), **not** from this
tool. It means the origin can't answer in time. Usually the fuzzing load is too
high for the origin:
1. Abort the scan, wait ~60s, `curl` the site. Recovers → it was the load.
2. Re-run with a **lower rate limit + concurrency** and a shallower **crawl depth**.
3. Prefer `template_scan` (light) over `fuzz_dast` (heavy) for a first pass.
4. If it still 504s with no scan running, the site itself is down — not a tool issue.

**A scan returns zero findings.** Check the origin was actually up during the run
(a 504-ing origin returns errors to every fuzz request → nothing to match on).

**ZAP does nothing.** It needs Docker running (`use_docker: true`), no local install.

**Installed engines on this machine:** nuclei, katana, nikto, testssl.sh, sqlmap
in PATH; ZAP via Docker.
