#!/usr/bin/env python3
"""
Generate a penetration-test report (.xlsx) from a completed
DAST-harness run. Reads <run>/report.json (and templates.jsonl for tech-stack
enrichment) and emits a 7-sheet workbook matching the reference layout:

  Executive Summary · Risk Overview · Detailed Findings ·
  Recommendations · Technology Stack · Scan Metadata · Access Control Test

Usage:
  python report_xlsx.py <run_dir> [-o output.xlsx]
  python report_xlsx.py web/runs/projects/TOkens/2026-08-03_1608
"""
from __future__ import annotations
import argparse, json, datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ---- palette (matches the reference report) ----------------------------- #
NAVY      = "FF1F4E79"   # sheet titles
HEADERBG  = "FF2F5496"   # table header fill
WHITE     = "FFFFFFFF"
SEV_FILL = {
    "critical": "FFC00000", "high": "FFED7D31", "medium": "FFFFC000",
    "low": "FFFFF2CC", "info": "FFD9E1F2", "unknown": "FFE7E6E6",
}
SEV_WHITE_TEXT = {"critical", "high"}   # dark fills need white text
THIN = Side(style="thin", color="FFBFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

OWASP_NAME = {
    "A01": "A01: Broken Access Control", "A02": "A02: Cryptographic Failures",
    "A03": "A03: Injection", "A04": "A04: Insecure Design",
    "A05": "A05: Security Misconfiguration", "A06": "A06: Vulnerable Components",
    "A07": "A07: Identification & Auth Failures", "A08": "A08: Software/Data Integrity",
    "A09": "A09: Logging & Monitoring Failures", "A10": "A10: SSRF",
    "NA": "Reconnaissance / Informational",
}
TOOL_BY_CATEGORY = [
    ("testssl", "testssl.sh"), ("nikto", "Nikto"), ("sqlmap", "sqlmap"),
    ("zap", "OWASP ZAP"), ("cors", "CORS probe"), ("csrf", "CSRF probe"),
    ("idor", "IDOR probe"), ("secret", "Secret scan"), ("depscan", "Dependency scan"),
    ("sca", "Dependency scan"), ("dast", "Nuclei"), ("template", "Nuclei"),
    ("nuclei", "Nuclei"), ("api", "API-spec fuzz"),
]

def source_tool(f: dict) -> str:
    cat = (f.get("category") or "").lower()
    for key, label in TOOL_BY_CATEGORY:
        if key in cat:
            return label
    return f.get("tool") or (cat.split("-")[0].title() if cat else "Harness")

def owasp_label(f: dict) -> str:
    code = (f.get("owasp") or "NA").split(":")[0].strip()
    return OWASP_NAME.get(code, f.get("owasp") or "Reconnaissance / Informational")

# ---- styling helpers ---------------------------------------------------- #
def title(ws, text, span_cols, size=14):
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=span_cols)
    c = ws.cell(1, 1, text)
    c.font = Font(bold=True, size=size, color=NAVY)
    c.alignment = Alignment(horizontal="center" if size >= 16 else "left", vertical="center")
    ws.row_dimensions[1].height = 26

def header_row(ws, row, headers):
    for i, h in enumerate(headers, 1):
        c = ws.cell(row, i, h)
        c.font = Font(bold=True, size=12, color=WHITE)
        c.fill = PatternFill("solid", fgColor=HEADERBG)
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = BORDER

def data_cell(ws, row, col, val, wrap=True, sev_fill=None, bold=False):
    c = ws.cell(row, col, val)
    c.alignment = Alignment(horizontal="left", vertical="top", wrap_text=wrap)
    c.border = BORDER
    fontkw = dict(bold=bold, size=11)
    if sev_fill:
        c.fill = PatternFill("solid", fgColor=sev_fill)
        if sev_fill == SEV_FILL["critical"] or sev_fill == SEV_FILL["high"]:
            fontkw["color"] = WHITE
            fontkw["bold"] = True
    c.font = Font(**fontkw)
    return c

def set_widths(ws, widths):
    for col, w in widths.items():
        ws.column_dimensions[col].width = w

# ---- data loading ------------------------------------------------------- #
def load_run(run_dir: Path):
    rj = run_dir / "report.json"
    if not rj.exists():
        raise SystemExit(f"No report.json in {run_dir} — run the scan first.")
    data = json.loads(rj.read_text())
    meta = data.get("meta", {})
    findings = data.get("findings", [])
    # severity order for sorting
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda f: order.get((f.get("severity") or "info").lower(), 9))
    return meta, findings

def tech_stack_from(run_dir: Path, findings: list) -> list:
    """Derive detected tech from nuclei 'tech' findings; fall back to templates.jsonl."""
    rows = []
    seen = set()
    def add(cat, tech, note):
        k = (cat, tech)
        if tech and k not in seen:
            seen.add(k); rows.append((cat, tech, note))
    for f in findings:
        cat = (f.get("category") or "").lower()
        if "tech" in cat or (f.get("owasp") in (None, "NA") and "detect" in (f.get("name","").lower())):
            add("Detected", f.get("name", ""), (f.get("detail") or "")[:60])
    tj = run_dir / "reports" / "templates.jsonl"
    if tj.exists():
        for line in tj.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = o.get("info", {})
            tags = ",".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [])
            if "tech" in tags or o.get("template-id", "").startswith("tech"):
                add("Technology", info.get("name") or o.get("template-id", ""),
                    o.get("matched-at", "")[:60])
    return rows

# ---- sheet builders ----------------------------------------------------- #
def sheet_exec(wb, meta, findings, org):
    ws = wb.create_sheet("Executive Summary")
    set_widths(ws, {"A": 24, "B": 62})
    title(ws, "PENETRATION TEST REPORT - EXECUTIVE SUMMARY", 2, size=16)
    ws.merge_cells("A2:B2")
    ws.cell(2, 1, f"{org} - {meta.get('target','')}").font = Font(italic=True, size=11, color=NAVY)
    counts = meta.get("counts", {})
    rating = ("CRITICAL" if counts.get("critical") else "HIGH" if counts.get("high")
              else "MEDIUM" if counts.get("medium") else "LOW" if counts.get("low") else "MINIMAL")
    rows = [
        ("Report Date", datetime.date.today().strftime("%B %d, %Y")),
        ("Assessment Date", meta.get("date", "")),
        ("Target Application", meta.get("target", "")),
        ("Organization", org),
        ("Assessment Type", "Dynamic Application Security Testing (DAST)"),
        ("Scan Mode", "Authenticated" if meta.get("authenticated") else "Unauthenticated (Public Surface)"),
        ("", ""),
        ("OVERALL RISK RATING", rating),
        ("Total Findings", str(meta.get("total", len(findings)))),
    ]
    r = 4
    for label, val in rows:
        a = ws.cell(r, 1, label); a.font = Font(bold=True, size=11)
        a.alignment = Alignment(vertical="top")
        b = ws.cell(r, 2, val); b.alignment = Alignment(wrap_text=True, vertical="top")
        if label == "OVERALL RISK RATING":
            fill = SEV_FILL.get(rating.lower(), SEV_FILL["low"])
            b.fill = PatternFill("solid", fgColor=fill)
            b.font = Font(bold=True, color=WHITE if rating in ("CRITICAL", "HIGH") else "FF000000")
        r += 1
    # narrative block
    ws.merge_cells(start_row=r+1, start_column=1, end_row=r+5, end_column=2)
    summary = (f"An unauthenticated dynamic security assessment was performed against "
               f"{meta.get('target','the target')}. The scan surfaced {meta.get('total',0)} "
               f"finding(s): {counts.get('critical',0)} critical, {counts.get('high',0)} high, "
               f"{counts.get('medium',0)} medium, {counts.get('low',0)} low, "
               f"{counts.get('info',0)} informational. Overall residual risk is rated {rating}.")
    n = ws.cell(r+1, 1, summary); n.alignment = Alignment(wrap_text=True, vertical="top")

def sheet_risk(wb, meta):
    ws = wb.create_sheet("Risk Overview")
    set_widths(ws, {"A": 20, "B": 12, "C": 13, "D": 52})
    title(ws, "VULNERABILITY SUMMARY BY SEVERITY", 4)
    header_row(ws, 3, ["Severity", "Count", "Percentage", "Description"])
    counts = meta.get("counts", {})
    total = sum(counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")) or 0
    desc = {
        "Critical": "Immediate exploitation possible; fix now",
        "High": "Significant risk requiring prompt remediation",
        "Medium": "Moderate risk; should be addressed",
        "Low": "Minor issues; address as part of hygiene",
        "Informational": "Best-practice recommendations",
    }
    r = 4
    for sev_label, key in [("Critical","critical"),("High","high"),("Medium","medium"),
                           ("Low","low"),("Informational","info")]:
        cnt = counts.get(key, 0)
        pct = f"{round(cnt/total*100)}%" if total else "0%"
        fill = SEV_FILL[key if key != "info" else "info"]
        data_cell(ws, r, 1, sev_label, sev_fill=fill, bold=True)
        data_cell(ws, r, 2, cnt); data_cell(ws, r, 3, pct)
        data_cell(ws, r, 4, desc[sev_label])
        r += 1
    data_cell(ws, r, 1, "TOTAL", bold=True); data_cell(ws, r, 2, total, bold=True)
    data_cell(ws, r, 3, "100%" if total else "0%", bold=True); data_cell(ws, r, 4, "")

def sheet_findings(wb, findings):
    ws = wb.create_sheet("Detailed Findings")
    set_widths(ws, {"A": 9, "B": 12, "C": 35, "D": 52, "E": 24, "F": 20})
    title(ws, "DETAILED VULNERABILITY FINDINGS", 6)
    header_row(ws, 3, ["ID", "Severity", "Finding", "Description", "OWASP Category", "Source Tool"])
    r = 4
    if not findings:
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=6)
        data_cell(ws, r, 1, "No findings recorded in this run. If the scan phases produced "
                            "empty output, verify the run completed successfully.")
        return
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "info").lower()
        data_cell(ws, r, 1, f"PEN-{i:03d}", bold=True)
        data_cell(ws, r, 2, sev.capitalize(), sev_fill=SEV_FILL.get(sev), bold=True)
        data_cell(ws, r, 3, f.get("name", ""))
        data_cell(ws, r, 4, (f.get("detail") or f.get("evidence") or "")[:400])
        data_cell(ws, r, 5, owasp_label(f))
        data_cell(ws, r, 6, source_tool(f))
        r += 1

def sheet_reco(wb, findings):
    ws = wb.create_sheet("Recommendations")
    set_widths(ws, {"A": 9, "B": 12, "C": 35, "D": 55, "E": 12})
    title(ws, "REMEDIATION RECOMMENDATIONS", 5)
    header_row(ws, 3, ["ID", "Priority", "Finding", "Recommendation", "Effort"])
    prio = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    r = 4
    if not findings:
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
        data_cell(ws, r, 1, "No findings — no remediation required from this run.")
        return
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "info").lower()
        data_cell(ws, r, 1, f"PEN-{i:03d}", bold=True)
        data_cell(ws, r, 2, prio.get(sev, "Low"), sev_fill=SEV_FILL.get(sev))
        data_cell(ws, r, 3, f.get("name", ""))
        data_cell(ws, r, 4, (f.get("remediation") or "Review and remediate per OWASP guidance.")[:400])
        eff = "High" if sev in ("critical", "high") else "Medium" if sev == "medium" else "Low"
        data_cell(ws, r, 5, eff)
        r += 1

def sheet_tech(wb, rows):
    ws = wb.create_sheet("Technology Stack")
    set_widths(ws, {"A": 22, "B": 30, "C": 45})
    title(ws, "DETECTED TECHNOLOGY STACK", 3)
    header_row(ws, 3, ["Category", "Technology", "Notes"])
    r = 4
    if not rows:
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=3)
        data_cell(ws, r, 1, "No technology fingerprints captured (nuclei 'tech' templates produced no output).")
        return
    for cat, tech, note in rows:
        data_cell(ws, r, 1, cat); data_cell(ws, r, 2, tech); data_cell(ws, r, 3, note)
        r += 1

def sheet_meta(wb, meta, run_dir, org):
    ws = wb.create_sheet("Scan Metadata")
    set_widths(ws, {"A": 26, "B": 55})
    title(ws, "ASSESSMENT METHODOLOGY & TOOLING", 2)
    cov = meta.get("coverage", {})
    blocks = [
        ("Assessment Type", "Dynamic Application Security Testing (DAST)"),
        ("Scan Mode", "Authenticated" if meta.get("authenticated") else "Unauthenticated / Black-box"),
        ("Assessment Date", meta.get("date", "")),
        ("Report Generation", datetime.date.today().strftime("%B %d, %Y")),
        ("Reliability", meta.get("reliability", "")),
        ("", ""),
        ("TARGET INFORMATION", ""),
        ("Primary Domain", meta.get("target", "")),
        ("Organization", org),
        ("", ""),
        ("COVERAGE", ""),
        ("Test Categories", str(cov.get("total", ""))),
        ("Automated", str(cov.get("auto", ""))),
        ("Partial", str(cov.get("part", ""))),
        ("Manual", str(cov.get("manual", ""))),
        ("Run Directory", str(run_dir)),
        ("Tooling", "Katana · Nuclei (DAST + templates) · testssl.sh · Nikto · custom probes"),
    ]
    r = 3
    for label, val in blocks:
        a = ws.cell(r, 1, label)
        a.font = Font(bold=True, size=11, color=(NAVY if val == "" and label else None))
        ws.cell(r, 2, val).alignment = Alignment(wrap_text=True, vertical="top")
        r += 1

def sheet_access(wb, meta, findings):
    ws = wb.create_sheet("Access Control Test")
    set_widths(ws, {"A": 24, "B": 16, "C": 24, "D": 40})
    title(ws, "DIRECTORY ENUMERATION & ACCESS CONTROL", 4)
    ac = [f for f in findings if "idor" in (f.get("category","").lower()) or
          "access" in (f.get("name","").lower())]
    summary = ("Access-control findings are listed below."
               if ac else "No broken-access-control findings in this run. "
               "Note: unauthenticated scans cannot fully exercise authorization — "
               "run an authenticated scan (session token) for complete coverage.")
    ws.merge_cells("A3:D3")
    ws.cell(3, 1, summary).alignment = Alignment(wrap_text=True)
    header_row(ws, 5, ["Test Category", "Location", "Result", "Assessment"])
    r = 6
    if not ac:
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
        data_cell(ws, r, 1, "No access-control probe findings recorded.")
        return
    for f in ac:
        data_cell(ws, r, 1, f.get("name", "")); data_cell(ws, r, 2, (f.get("location") or "")[:60])
        data_cell(ws, r, 3, (f.get("severity") or "").capitalize())
        data_cell(ws, r, 4, (f.get("detail") or "")[:200])
        r += 1

# ---- main --------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("-o", "--out")
    ap.add_argument("--org", default="Your Organization")
    args = ap.parse_args()
    run_dir = Path(args.run_dir).expanduser().resolve()
    meta, findings = load_run(run_dir)
    tech = tech_stack_from(run_dir, findings)

    wb = Workbook(); wb.remove(wb.active)
    sheet_exec(wb, meta, findings, args.org)
    sheet_risk(wb, meta)
    sheet_findings(wb, findings)
    sheet_reco(wb, findings)
    sheet_tech(wb, tech)
    sheet_meta(wb, meta, run_dir, args.org)
    sheet_access(wb, meta, findings)

    out = Path(args.out).expanduser() if args.out else (
        Path.home() / "Downloads" /
        f"PenTest_Report_{datetime.date.today().strftime('%d-%m-%Y')}.xlsx")
    wb.save(out)
    print(f"[OK] Wrote {out}")
    print(f"     findings={len(findings)}  tech_rows={len(tech)}  sheets={len(wb.sheetnames)}")

if __name__ == "__main__":
    main()
