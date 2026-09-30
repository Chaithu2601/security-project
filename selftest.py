#!/usr/bin/env python3
"""Self-tests for the harness internals — no network, no external tools.

Covers the parts most likely to break silently: scope matching (a wrong answer
empties a scan and looks clean), the built-in crawler's link extraction, preset
expansion, budget semantics, phase parallelism, and the trust layer's noise
filters.

    ./.venv/bin/python selftest.py
"""
import sys, time

sys.argv = ["selftest"]          # dast_scan parses argv at import time
import dast_scan as ds

FAILED = []

def check(label, got, want):
    if got == want:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}\n         got:  {got!r}\n         want: {got.__class__.__name__} {want!r}")
        FAILED.append(label)

def section(t):
    print(f"\n{t}")


# ---------------------------------------------------------------- scope
section("scope matching")
check("exact host", ds._host_in_scope("https://a.com/x", "a.com"), True)
check("subdomain", ds._host_in_scope("https://api.a.com/x", "a.com"), True)
check("off-scope host", ds._host_in_scope("https://evil.com/x", "a.com"), False)
# A host that merely CONTAINS the scope must not match (OAuth redirect_uri).
check("scope inside query", ds._host_in_scope("https://evil.com/?r=https://a.com", "a.com"), False)
check("suffix trap", ds._host_in_scope("https://nota.com/x", "a.com"), False)
# Regression: a port in the configured scope used to match nothing, which
# emptied every scan against a non-default port.
check("port in scope", ds._host_in_scope("http://127.0.0.1:8799/x", "127.0.0.1:8799"), True)
check("port in scope, host-only URL", ds._host_in_scope("http://127.0.0.1/x", "127.0.0.1:8799"), True)


# ---------------------------------------------------- crawler internals
section("built-in crawler")
html = ('<a href="/login?next=/admin">l</a><a href="sub/p.html">s</a>'
        '<a href="mailto:x@y.z">m</a><a href="https://off.example/x">o</a>'
        '<form action="/auth/session"></form>'
        '<script>fetch("https://a.com/api/hidden?t=1")</script>')
links = ds._extract_links("https://a.com/page", html, is_js=False)
check("resolves relative href", "https://a.com/login?next=/admin" in links, True)
check("resolves relative path", "https://a.com/sub/p.html" in links, True)
check("captures form action", "https://a.com/auth/session" in links, True)
check("captures inline fetch URL", "https://a.com/api/hidden?t=1" in links, True)
check("skips mailto", any("mailto" in l for l in links), False)

js = 'const A="https://a.com/api/config?debug=1"; const B=`https://a.com/${id}/bad`;'
jlinks = ds._extract_links("https://a.com/app.js", js, is_js=True)
check("extracts API URL from JS", "https://a.com/api/config?debug=1" in jlinks, True)
check("template literal is rejected later",
      bool(ds._TEMPLATE_RE.search("https://a.com/${id}/bad")), True)
check("real URL not rejected as template",
      bool(ds._TEMPLATE_RE.search("https://a.com/api/x?id=1")), False)

check("norm drops fragment", ds._crawl_norm("https://a.com/x#frag"), "https://a.com/x")
check("norm keeps query", ds._crawl_norm("https://a.com/x?id=1"), "https://a.com/x?id=1")
check("norm strips trailing slash", ds._crawl_norm("https://a.com/x/"), "https://a.com/x")
check("binary assets skipped", bool(ds._BIN_SKIP_RE.search("/logo.png")), True)
check("js not treated as binary", bool(ds._BIN_SKIP_RE.search("/app.js")), False)


# ------------------------------------------------------------- presets
section("presets")
for name in ("quick", "standard", "authenticated", "deep"):
    cfg = {"phases": {k: True for k in ds.PRESETS["deep"]["phases"] + ["upload", "token_probe", "sqlmap_confirm"]},
           "idor": {"enabled": False, "victim_urls": ["https://OTHER-CUSTOMER.example/api/user/1"],
                    "user_b_headers": ["Cookie: session=PLACEHOLDER"]}}
    ds.apply_preset(cfg, name)
    on = {k for k, v in cfg["phases"].items() if v}
    check(f"{name}: phases match definition", on, set(ds.PRESETS[name]["phases"]))
    # Phases that WRITE to the target or exploit it must never be in a preset.
    # token_probe (forges a token you supplied) is allowed, but only in the
    # authenticated preset where supplying that token is the authorisation.
    check(f"{name}: no target-writing opt-ins enabled",
          {"upload", "sqlmap_confirm"} & on, set())
    if name != "authenticated":
        check(f"{name}: no active token probe", "token_probe" in on, False)
    check(f"{name}: idor armed", cfg["idor"]["enabled"], True)
    # Regression: victim URLs from a previous engagement must not survive.
    check(f"{name}: inherited victim URLs cleared", cfg["idor"]["victim_urls"], [])
    check(f"{name}: placeholder 2nd account cleared", cfg["idor"]["user_b_headers"], [])

# authenticated preset must include the active token probe; the others must not
check("authenticated includes token_probe", "token_probe" in ds.PRESETS["authenticated"]["phases"], True)
for n in ("quick", "standard", "deep"):
    check(f"{n} excludes token_probe", "token_probe" in ds.PRESETS[n]["phases"], False)

# api_spec rides along with any preset when a source is configured
cfg = {"phases": {}, "api_spec": {"source": "http://x/openapi.json"}}
ds.apply_preset(cfg, "quick")
check("api_spec auto-enabled when source given", cfg["phases"].get("api_spec"), True)
cfg = {"phases": {}, "api_spec": {"source": ""}}
ds.apply_preset(cfg, "quick")
check("api_spec stays off with no source", cfg["phases"].get("api_spec", False), False)

cfg = {"phases": {}, "limits": {"budget_secs": 42}}
ds.apply_preset(cfg, "quick")
check("explicit budget beats preset default", cfg["limits"]["budget_secs"], 42)
try:
    ds.apply_preset({"phases": {}}, "nonsense")
    check("unknown preset rejected", "no error", "SystemExit")
except SystemExit:
    check("unknown preset rejected", True, True)


# -------------------------------------------------------------- budget
section("budget semantics")
ds._SCAN_DEADLINE = None
check("uncapped: nothing spent", ds._budget_spent(), False)
check("uncapped: no limit reported", ds._budget_left(), None)
ds._SCAN_DEADLINE = time.monotonic() + 30
check("mid-run: not spent", ds._budget_spent(), False)
check("mid-run: seconds remain", 25 <= ds._budget_left() <= 30, True)
ds._SCAN_DEADLINE = time.monotonic() - 1
check("expired: spent", ds._budget_spent(), True)
check("expired: floors at 1s so no zero timeout", ds._budget_left(), 1)
# Probes must report no evidence rather than inventing a finding.
check("expired: _fetch returns no evidence", ds._fetch("https://a.com/", {}), ("", 0))
check("expired: _http_get returns no evidence", ds._http_get("https://a.com/", {}), (0, {}, ""))
check("expired: _fetch_setcookies returns no evidence",
      ds._fetch_setcookies("https://a.com/", {}), (0, [], ""))
ds._SCAN_DEADLINE = None


# ----------------------------------------------------------- parallelism
section("phase parallelism")
def slow(name, secs):
    def fn():
        time.sleep(secs)
        return f"{name}-ok"
    return (name, fn)

jobs = [slow("a", 1), slow("b", 1), slow("c", 1)]
t = time.monotonic(); res = ds.run_parallel(jobs); par = time.monotonic() - t
check("all phases returned", sorted(res), ["a", "b", "c"])
check("results correct", sorted(res.values()), ["a-ok", "b-ok", "c-ok"])
check(f"phases overlapped ({par:.2f}s for 3x1s)", par < 2.0, True)

def boom(): raise RuntimeError("simulated tool crash")
res = ds.run_parallel([("broken", boom), ("good", lambda: "fine")])
check("a crashing phase yields None", res["broken"], None)
check("siblings survive a crash", res["good"], "fine")

check("single job needs no pool", ds.run_parallel([("only", lambda: 7)]), {"only": 7})
check("empty job list is a no-op", ds.run_parallel([]), {})


# ---------------------------------------------------------- trust layer
section("trust layer noise filters")
def refine(**f):
    base = {"severity": "medium", "category": "test", "name": "", "location": "", "detail": ""}
    base.update(f)
    return ds._refine_findings([base])

check("Nikto Perl leak dropped", refine(name="ARRAY(0x7f)") , [])
check("testssl local OpenSSL error dropped", refine(name="engine_problem: no engine"), [])
check("testssl 'Scan interrupted' dropped", refine(name="scanTime: Scan interrupted"), [])
check("testssl connect failure dropped",
      refine(name="scanProblem", detail="Can't connect to '127.0.0.1:443'"), [])
kept = refine(name="POST form has no anti-CSRF token field", category="csrf")
check("a real finding survives the filters", len(kept), 1)
kept = refine(name="SQL injection in id parameter", category="sqli", severity="critical")
check("a real critical survives", len(kept), 1)


print("\n" + "=" * 60)
if FAILED:
    print(f"FAILED ({len(FAILED)}): " + ", ".join(FAILED))
    sys.exit(1)
print("all self-tests passed")
