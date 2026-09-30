# DAST Harness

One command to run a full **dynamic** security assessment against a web app you
own, mapped to **OWASP Top 10 (2021) + ASVS 5.0**, with resilience against
knocking the server over, and output in HTML, Markdown, JSON, and **SARIF**
(so it plugs into GitHub Security / DefectDojo / a SIEM).

> Only run this against systems you own or are explicitly authorised to test.

## What it runs — the full automatable surface

| Phase | Tool | Finds | Standard |
|-------|------|-------|----------|
| 1. Crawl | Katana | Endpoints, JS, params, POST bodies (authenticated) | — |
| 2. Triage | — | Narrows to in-scope injectable endpoints | — |
| 3. DAST fuzzing | Nuclei `-dast` | SQLi, XSS, SSTI, LFI, SSRF, RCE, XXE, CRLF, redirect | A03/A10 |
| 4. Template scan | Nuclei | CVEs, exposed files/panels, misconfig, headers, default logins | A05/A06 |
| 5. Active scan | OWASP ZAP | ZAP's *entire* attack-rule set (spider + AJAX + active) | A01–A10 |
| 6. Server scan | Nikto | Dangerous files, outdated software, server misconfig | A05/A06 |
| 7. **TLS scan** | **testssl.sh** | Weak protocols/ciphers, cert issues, BEAST/etc. | **A02 / V12** |
| 8. Secret scan | built-in | Keys/tokens/JWTs/private keys leaked in frontend JS | A07 |
| 9. Token analysis | built-in | Non-expiring / long-lived JWTs, `alg=none`, admin claims | A07 |
| 10. **IDOR probe** | **built-in** | 2-account cross-read test for broken access control | **A01 / V8** |
| (opt) Confirm | sqlmap | Confirms SQLi **and extracts data** to prove impact | A03 |

Every finding is tagged with its **OWASP Top 10 (2021)** category *and* its
**ASVS 5.0 chapter** (V1–V17). The report also shows **WSTG coverage** — which
test areas are automated vs. manual — so a clean run is never mistaken for a
clean app.

## What changed in this version (the gaps you flagged)

1. **503 / server-overload resilience.** A pre-flight health check aborts the
   scan if the target is already erroring, and a background monitor samples the
   server *during* the scan — if it sees sustained 5xx/timeouts, the report is
   stamped **UNSTABLE** so you don't trust bad data. Config: `resilience:`.
2. **ASVS 5.0 mapping.** Every finding now carries an ASVS chapter, not just a
   Top-10 category. ASVS is what audits and procurement actually reference.
3. **SARIF 2.1.0 output.** `report.sarif` imports straight into GitHub code
   scanning, DefectDojo, and most SIEMs.
4. **Deep TLS (testssl.sh).** Real protocol/cipher/cert analysis for A02, which
   ZAP/Nuclei only check at the surface.
5. **IDOR / access-control probe.** The one high-value class scanners miss —
   automated here with a two-account cross-read test.

Still genuinely manual (no tool can do it): **business logic** (approving your
own payroll, negative hours). The WSTG table flags it explicitly.

## Files

```
dast_scan.py     main orchestrator
owasp.py         OWASP Top 10 + ASVS 5.0 mapping + WSTG coverage
sarif.py         SARIF 2.1.0 exporter
config.yaml      per-project settings (edit this)
zap-plan.yaml    ZAP Automation Framework plan (authenticated LOCAL zap.sh runs)
requirements.txt
```

## Setup

```bash
pip install -r requirements.txt      # just pyyaml
nuclei -update-templates             # pull the DAST/fuzzing templates once
```

Tools needed: `katana`, `nuclei`, `nikto`, `sqlmap`, and **either** Docker (for
ZAP, easiest) **or** a local ZAP install. On Windows, point `config.yaml` at your
`.exe`/`.pl` files. Missing tools are skipped gracefully.

**ZAP via Docker** (default, nothing to install):
```bash
docker pull zaproxy/zap-stable
```

**retire.js — optional, upgrades the dependency scan (A06).** The `depscan`
phase flags vulnerable frontend JS libraries. Out of the box it uses a curated,
high-confidence signature set built into `dast_scan.py`. If you install
[retire.js](https://retirejs.github.io/retire.js/), the phase automatically
switches to retire.js's **full** vulnerability database instead:
```bash
npm install -g retire        # needs Node.js; then `retire --version` to verify
```
No config change needed — the phase detects `retire` on PATH and prefers it,
falling back to the built-in signatures when it's absent.

## Configure & run

Edit `config.yaml` (set scope, seeds, **auth headers**, tool paths, phase
toggles), then:

```bash
python dast_scan.py                       # full pipeline
python dast_scan.py --config payroll.yaml # a specific project
python dast_scan.py --phase zap           # run one phase
```

### Presets — pick a depth instead of 18 phases

```bash
python dast_scan.py --list-presets              # what each one covers
python dast_scan.py --preset quick              # no external tools, ~1-3 min
python dast_scan.py --preset standard           # + katana, Nuclei templates, testssl
python dast_scan.py --preset deep               # + Nuclei fuzzing, ZAP, Nikto (hours)
```

| Preset | Needs installed | Typical time | Covers |
|--------|-----------------|--------------|--------|
| `quick` | **nothing** — Python only | ~1-3 min | Built-in crawl, leaked secrets, JWT lifetimes, vulnerable JS libs, CORS, cookie/CSRF flags, IDOR |
| `standard` | katana, nuclei, testssl | ~10-20 min | Quick + deep crawl, CVE/exposure/misconfig templates, TLS |
| `authenticated` | + a session cookie / bearer token | ~15-25 min | Standard + **active broken-auth probe** (replays/forges/tampers your token). Supplying a token is your authorisation to actively test. |
| `deep` | + ZAP (Docker), nikto | hours | Standard + injection fuzzing, ZAP active scan, Nikto |

`api_spec` ingestion (OpenAPI/Swagger/GraphQL) runs under **any** preset when you
supply a spec — it only widens coverage and writes nothing. `sqlmap` confirmation
and file-upload probing remain explicit opt-ins (they write to / exploit the
target), reachable via **Custom**.

A preset never enables `token_probe`, `upload` or `sqlmap_confirm` — those
forge credentials or write to the target, so they stay explicit opt-ins.

### No tools installed? It still works

`quick` uses a built-in crawler that needs only the standard library, so the
endpoint-driven phases have something to scan without katana. Previously a
missing katana produced an empty endpoint list and every phase found nothing —
indistinguishable from a clean application. Set `scan.crawler` to `auto`
(default), `builtin`, or `katana`.

### Self-tests

```bash
./.venv/bin/python selftest.py      # no network, no external tools, ~3s
```

Covers the parts that fail silently rather than loudly: scope matching (a wrong
answer empties a scan and it looks clean), the built-in crawler's link
extraction, preset expansion, budget semantics, phase parallelism, and the
trust layer's noise filters.

### Interrupted scans keep their results

The report is refreshed after every phase, so a scan that is killed, times out
or is Ctrl-C'd still leaves a readable `REPORT.html` for whatever finished.
Interim reports are marked **PARTIAL** so they are never mistaken for a
complete assessment. `limits.budget_secs` caps total wall-clock; it is checked
between phases, so a run can overshoot by up to one phase rather than being
cut off mid-write.

Independent phases run concurrently (`limits.parallel`, default on): the
built-in probes as one group, zap/nikto/testssl as another. Turn it off for
targets behind a WAF or rate limiter — concurrency raises the request rate.

Each run creates `projects/<name>/<date>/` with `REPORT.html` (open this),
`REPORT.md`, `report.json`, and every tool's raw output.

## The report

`REPORT.html` (open this) has, top to bottom:

1. **Reliability banner** — appears only if the server went unstable mid-scan.
2. **Severity chips** — critical/high/medium/low counts.
3. **OWASP Top 10 (2021) grid** — which categories you have findings in.
4. **WSTG coverage table** — automated vs. partial vs. manual per test area.
5. **Findings table** — severity, **OWASP**, **ASVS**, category, location, detail.

Also written: `REPORT.md`, `report.json`, and `report.sarif`.

## Tuning for a fragile server (503s)

The `resilience:` block controls this:

- `preflight: true` — health-checks the target 3× before starting; aborts if it's
  already returning 5xx/timeouts (no point scanning a down server).
- `monitor: true` — samples a health URL every `monitor_interval` seconds during
  the scan; after `max_consecutive_5xx` failures in a row it marks the run
  UNSTABLE in the report.

If you *are* getting 503s: drop `scan.rate_limit` to 3–5 and `scan.concurrency`
to 2, and run heavy phases one at a time (`--phase fuzz_dast`, then
`--phase zap`) instead of stacking ZAP's active scan on top of Nuclei fuzzing.

## IDOR / access-control probe

Set `idor.enabled: true` and give it two real accounts plus URLs that return
**user B's** data:

```yaml
idor:
  enabled: true
  user_a_headers: ["Cookie: session=USER_A_SESSION"]
  user_b_headers: ["Cookie: session=USER_B_SESSION"]
  victim_urls:
    - "https://.../api/employee/1002"   # 1002 belongs to user B
    - "https://.../api/payslip/5567"
```

It fetches each URL as B (baseline), as A, and unauthenticated. If A or anon can
read B's resource, it's flagged as broken object-level authorization (A01 / V8).
This is the #1 real payroll flaw and no template scanner finds it.

## SARIF / pipeline integration

`report.sarif` is SARIF 2.1.0 with per-finding OWASP/ASVS tags and GitHub
`security-severity` scores. Upload it in a GitHub Action with
`github/codeql-action/upload-sarif`, or import into DefectDojo / your SIEM.

## Extracting data during injection (impact evidence)

With `phases.sqlmap_confirm: true`, confirmed SQLi is passed to sqlmap. Control
depth in the `sqlmap:` block: `current_user`, `enumerate` (`--dbs --tables`),
`dump_table` (`--dump` a named table). **Your own UAT only** — this reads/writes
real data.

## Authenticated ZAP (the important bit)

For a full authenticated scan with a local ZAP, set `zap.use_docker: false` and
edit `zap-plan.yaml` — put your token in the `replacer` rule. With Docker, the
harness injects your `auth.headers` automatically via ZAP's replacer.

## What still needs YOU (not the tools)

The WSTG table is explicit about this, but the two that matter most for a
payroll app:

- **Authorization / IDOR** — log in as employee A, change an `id`/`employeeId`
  to employee B's, see if you get their data. #1 real-world HR/payroll flaw.
- **Business logic** — e.g. approving your own payroll, submitting negative
  hours, replaying an approval. No scanner understands your business rules.

## Safety

- Fuzzing + ZAP active scan send real attacks that can mutate the DB — UAT only.
- Keep `rate_limit` low (default 10/s) so you don't DoS the app.
- Findings are candidates; verify before reporting (DAST has false positives).

