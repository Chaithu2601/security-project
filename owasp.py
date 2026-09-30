#!/usr/bin/env python3
"""
OWASP mapping + coverage.

Two jobs:
  1. Map any finding (from Nuclei / ZAP / Nikto / sqlmap) to an OWASP Top 10
     2021 category, using its CWE id first and template/name keywords as a
     fallback. This turns a flat list of alerts into a standards-aligned view.
  2. Report WSTG (Web Security Testing Guide) coverage honestly: which test
     categories the automated tools actually cover, and which need manual work.
     This is the truthful answer to "are we testing all the cases" — automated
     DAST covers roughly half of WSTG; the rest (authorization/IDOR, business
     logic) is manual and the report says so instead of pretending.
"""
from __future__ import annotations

# ---- OWASP Top 10 2021 categories -------------------------------------------
OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    "NA":  "Unmapped / Informational",
}

# ---- CWE -> OWASP Top 10 (the CWEs each 2021 category officially includes) ---
CWE_TO_OWASP = {}
def _reg(cat, *cwes):
    for c in cwes:
        CWE_TO_OWASP[c] = cat
_reg("A01", 22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359,
     377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706,
     862, 863, 913, 922, 1275)
_reg("A02", 259, 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328,
     329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780,
     818, 916)
_reg("A03", 20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96,
     97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652,
     917, 943)
_reg("A04", 73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313,
     316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642,
     646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173)
_reg("A05", 2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756,
     776, 942, 1004, 1032, 1174)
_reg("A06", 937, 1035, 1104)
_reg("A07", 255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307,
     346, 384, 521, 613, 620, 640, 798, 940, 1216)
_reg("A08", 345, 353, 426, 494, 502, 565, 784, 829, 830, 915)
_reg("A09", 117, 223, 532, 778)
_reg("A10", 918)

# ---- keyword fallback (when a finding has no CWE) ---------------------------
KEYWORD_TO_OWASP = [
    ("A03", ("sqli", "sql-injection", "sql injection", "xss", "cross-site-scripting",
             "cross site scripting", "ssti", "template-injection", "rce",
             "command-injection", "command injection", "code-injection",
             "ldap-injection", "xpath", "crlf", "host-header-injection",
             "header-injection", "expression-language")),
    ("A10", ("ssrf", "server-side request")),
    ("A01", ("lfi", "local-file", "path-traversal", "path traversal", "directory-traversal",
             "idor", "insecure-direct", "open-redirect", "redirect", "access-control",
             "forbidden-bypass", "auth-bypass", "authorization")),
    ("A05", ("xxe", "xml-external", "misconfig", "missing-header", "security-header",
             "cors", "clickjack", "x-frame", "csp", "directory-listing",
             "directory indexing", "indexing", "index-of", "autoindex",
             "debug", "stacktrace", "default-page", "server-info", "exposed-config")),
    ("A06", ("cve-", "outdated", "vulnerable-version", "known-vuln", "eol-",
             "end-of-life", "vulnerable component")),
    ("A07", ("default-login", "default-credential", "weak-password", "brute",
             "session-fixation", "auth", "login", "jwt", "token")),
    ("A02", ("ssl", "tls", "cipher", "weak-crypto", "cleartext", "certificate",
             "mixed-content", "hsts")),
    ("A08", ("insecure-deserialization", "deserialization", "unsigned",
             "integrity", "subresource")),
    ("A09", ("logging", "monitoring", "audit")),
    ("A04", ("insecure-design",)),
]

def _extract_cwes(finding: dict) -> list[int]:
    out = []
    # Nuclei: info.classification.cwe-id = ["CWE-89", ...]
    cls = (finding.get("info", {}) or {}).get("classification", {}) or {}
    raw = cls.get("cwe-id") or cls.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    # ZAP alert: "cweid": "89"
    if finding.get("cweid"):
        raw = list(raw) + [finding["cweid"]]
    # generic 'cwe' field
    if finding.get("cwe"):
        raw = list(raw) + ([finding["cwe"]] if isinstance(finding["cwe"], str) else finding["cwe"])
    for r in raw:
        s = str(r).upper().replace("CWE-", "").strip()
        if s.isdigit():
            out.append(int(s))
    return out

def map_to_owasp(finding: dict) -> str:
    """Return an OWASP Top 10 category id (e.g. 'A03') for a finding."""
    for cwe in _extract_cwes(finding):
        if cwe in CWE_TO_OWASP:
            return CWE_TO_OWASP[cwe]
    # keyword fallback across common text fields
    hay = " ".join(str(finding.get(k, "")) for k in
                   ("name", "template-id", "templateID", "category", "detail",
                    "alert", "pluginId", "id")).lower()
    info = finding.get("info", {}) or {}
    hay += " " + str(info.get("name", "")).lower()
    for tag in (info.get("tags") or []):
        hay += " " + str(tag).lower()
    for cat, kws in KEYWORD_TO_OWASP:
        if any(k in hay for k in kws):
            return cat
    return "NA"

def owasp_label(cat: str) -> str:
    return f"{cat}:2021 {OWASP_TOP10.get(cat, 'Unmapped')}"

# ---- WSTG coverage matrix ---------------------------------------------------
# auto  = automated tools give meaningful coverage
# part  = partial; tools help but manual review needed
# manual= tools essentially can't test this; you must do it by hand
WSTG_COVERAGE = [
    ("WSTG-INFO", "Information Gathering",            "part",
     "Nikto + ZAP spider + Katana enumerate surface; leaked-info review is manual."),
    ("WSTG-CONF", "Configuration & Deploy Management", "auto",
     "Nikto, Nuclei misconfig/exposure, ZAP passive cover this well."),
    ("WSTG-IDNT", "Identity Management",              "manual",
     "Registration/role logic — test by hand."),
    ("WSTG-ATHN", "Authentication",                   "part",
     "Default-login/weak-cred checks are automated; lockout, MFA, reset flows are manual."),
    ("WSTG-ATHZ", "Authorization (IDOR, priv-esc)",   "part",
     "IDOR probe now auto-discovers object URLs and runs 2-account cross-read (or authed-vs-anon). Privilege-escalation and role logic still manual."),
    ("WSTG-SESS", "Session Management",               "part",
     "ZAP passive flags cookie flags/fixation; token lifetime handled by our token phase."),
    ("WSTG-INPV", "Input Validation (SQLi/XSS/etc)",  "auto",
     "Nuclei -dast, ZAP active scanner, sqlmap — this is the core injection coverage. "
     "Malicious-file-upload (EICAR) probe checks upload endpoints for AV scanning."),
    ("WSTG-ERRH", "Error Handling",                   "part",
     "Stack-trace/debug exposure is automated; logic-specific errors are manual."),
    ("WSTG-CRYP", "Cryptography (weak TLS/ciphers)",  "part",
     "ZAP + Nuclei ssl/tls templates; deep review needs testssl.sh."),
    ("WSTG-BUSL", "Business Logic",                   "manual",
     "e.g. approving your own payroll, negative amounts. Fully manual."),
    ("WSTG-CLNT", "Client-Side (DOM XSS, postMessage)", "part",
     "ZAP AJAX spider + DOM-XSS templates help; full DOM review is manual."),
    ("WSTG-APIT", "API Testing",                      "part",
     "API-spec ingestion feeds spec endpoints to the fuzzer + zap-api-scan; CORS probe automated; auth/business logic manual."),
]

def coverage_summary():
    tot = len(WSTG_COVERAGE)
    auto = sum(1 for a, b, lvl, d in WSTG_COVERAGE if lvl == "auto")
    part = sum(1 for a, b, lvl, d in WSTG_COVERAGE if lvl == "part")
    man  = sum(1 for a, b, lvl, d in WSTG_COVERAGE if lvl == "manual")
    return {"total": tot, "auto": auto, "part": part, "manual": man}

# ---- OWASP ASVS 5.0 (May 2025) — 17 chapters --------------------------------
ASVS_CHAPTERS = {
    "V1":  "Encoding and Sanitization",
    "V2":  "Validation and Business Logic",
    "V3":  "Web Frontend Security",
    "V4":  "API and Web Service",
    "V5":  "File Handling",
    "V6":  "Authentication",
    "V7":  "Session Management",
    "V8":  "Authorization",
    "V9":  "Self-contained Tokens",
    "V10": "OAuth and OIDC",
    "V11": "Cryptography",
    "V12": "Secure Communication",
    "V13": "Configuration",
    "V14": "Data Protection",
    "V15": "Secure Coding and Architecture",
    "V16": "Security Logging and Error Handling",
    "V17": "WebRTC",
}

# Primary ASVS chapter for each OWASP Top 10 category (best-fit).
OWASP_TO_ASVS = {
    "A01": "V8",   # Broken Access Control        -> Authorization (IDOR/BOLA)
    "A02": "V11",  # Cryptographic Failures       -> Cryptography
    "A03": "V1",   # Injection                    -> Encoding and Sanitization
    "A04": "V2",   # Insecure Design              -> Validation and Business Logic
    "A05": "V13",  # Security Misconfiguration    -> Configuration
    "A06": "V15",  # Vulnerable Components        -> Secure Coding and Architecture
    "A07": "V6",   # Auth Failures                -> Authentication
    "A08": "V15",  # Data Integrity Failures      -> Secure Coding and Architecture
    "A09": "V16",  # Logging Failures             -> Security Logging and Error Handling
    "A10": "V4",   # SSRF                         -> API and Web Service
    "NA":  "",
}

# Keyword refinements that override the OWASP-derived chapter for precision.
ASVS_KEYWORD_REFINE = [
    ("V12", ("ssl", "tls", "cipher", "hsts", "certificate", "mixed-content")),  # comms
    ("V9",  ("jwt", "self-contained token", "token signature", "alg")),          # tokens
    ("V10", ("oauth", "oidc", "openid")),                                        # oauth
    ("V3",  ("csp", "x-frame", "clickjack", "cookie", "cors", "content-type-options")),
    ("V5",  ("file-upload", "upload", "path-traversal", "directory-traversal")),
    ("V16", ("stacktrace", "stack trace", "verbose error", "debug", "logging")),
    ("V7",  ("session", "session-fixation", "cookie-without-secure")),
]

def map_to_asvs(finding: dict, owasp_cat: str | None = None) -> str:
    """Return an ASVS 5.0 chapter id (e.g. 'V1') for a finding."""
    hay = " ".join(str(finding.get(k, "")) for k in
                   ("name", "template-id", "templateID", "detail", "alert")).lower()
    info = finding.get("info", {}) or {}
    hay += " " + str(info.get("name", "")).lower()
    for tag in (info.get("tags") or []):
        hay += " " + str(tag).lower()
    for chap, kws in ASVS_KEYWORD_REFINE:
        if any(k in hay for k in kws):
            return chap
    cat = owasp_cat or map_to_owasp(finding)
    return OWASP_TO_ASVS.get(cat, "")

def asvs_label(chap: str) -> str:
    return f"{chap} {ASVS_CHAPTERS.get(chap, '')}".strip() if chap else "—"
