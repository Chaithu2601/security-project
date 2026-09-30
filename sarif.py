#!/usr/bin/env python3
"""
SARIF 2.1.0 output.

SARIF (Static Analysis Results Interchange Format) is the OASIS-standard JSON
format that GitHub code scanning, DefectDojo, Azure DevOps, and most SIEMs
ingest directly. Emitting it means the harness plugs into existing pipelines
instead of being a dead-end HTML report.
"""
from __future__ import annotations
import json
from pathlib import Path

# our severities -> SARIF levels (SARIF only has error/warning/note/none)
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note", "unknown": "none"}
# and a numeric security-severity (GitHub uses this 0-10 scale to rank)
_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5",
          "low": "3.0", "info": "1.0", "unknown": "0.0"}

def write_sarif(path: Path, meta: dict, findings: list[dict]):
    # build a unique rule per (name) so viewers group sensibly
    rules, rule_index = [], {}
    for f in findings:
        rid = (f.get("name") or "finding").strip()[:120]
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": rid.replace(" ", ""),
                "shortDescription": {"text": rid},
                "properties": {
                    "owasp": f.get("owasp", "NA"),
                    "asvs": f.get("asvs", ""),
                    "security-severity": _SCORE.get(f.get("severity", "unknown"), "0.0"),
                    "tags": [t for t in ["security",
                             f.get("owasp", ""), f.get("asvs", "")] if t],
                },
            })

    results = []
    for f in findings:
        rid = (f.get("name") or "finding").strip()[:120]
        loc = f.get("location") or meta.get("target", "")
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _LEVEL.get(f.get("severity", "unknown"), "none"),
            "message": {"text": f"{f.get('detail') or rid} "
                                f"[{f.get('owasp','NA')} / ASVS {f.get('asvs','-')}] "
                                f"({f.get('category','')})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc},
                }
            }],
            "properties": {
                "severity": f.get("severity"),
                "owasp": f.get("owasp"),
                "asvs": f.get("asvs"),
                "category": f.get("category"),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DAST-Harness",
                "informationUri": "https://owasp.org",
                "version": "1.0.0",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "project": meta.get("project"),
                "target": meta.get("target"),
                "scanDate": meta.get("date"),
                "reliability": meta.get("reliability", "ok"),
            },
        }],
    }
    Path(path).write_text(json.dumps(sarif, indent=2))
    return sarif
