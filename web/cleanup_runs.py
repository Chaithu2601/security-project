#!/usr/bin/env python3
"""Prune and compact old DAST scan runs under web/runs/projects.

Two things, both keyed off --days (default 10):
  1. PRUNE  — within each project, keep the most recent run; delete any OTHER
              run older than --days.
  2. COMPACT — for every surviving run older than --days, delete the heavy raw
              intermediates (crawl/ and large dumps) but keep the report files
              (REPORT.html, REPORT.md, report.json, report.sarif).

Runs newer than --days are left completely untouched. Deletion is permanent
(no trash). Use --dry-run to preview. Safe to run repeatedly (idempotent).
"""
import argparse, datetime as dt, re, shutil, sys
from pathlib import Path

RUN_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})")
KEEP_FILES = {"REPORT.html", "REPORT.md", "report.json", "report.sarif"}
BIG_BYTES = 2 * 1024 * 1024          # strip any non-report file larger than this

def run_time(p: Path) -> float:
    m = RUN_RE.search(p.name)
    if m:
        y, mo, d, h, mi = map(int, m.groups())
        try:
            return dt.datetime(y, mo, d, h, mi).timestamp()
        except ValueError:
            pass
    return p.stat().st_mtime

def dir_size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())

def is_incomplete(run: Path) -> bool:
    """A run whose report is missing or marked partial = failed/interrupted."""
    rj = run / "report.json"
    if not rj.exists():
        return True
    try:
        import json
        return bool(json.loads(rj.read_text()).get("meta", {}).get("partial"))
    except Exception:
        return True

def compact(run: Path, dry: bool) -> int:
    """Remove crawl/ and any large non-report file; return bytes freed."""
    freed = 0
    crawl = run / "crawl"
    if crawl.is_dir():
        freed += dir_size(crawl)
        if not dry:
            shutil.rmtree(crawl)
    for f in run.rglob("*"):
        if crawl in f.parents:            # already accounted for above
            continue
        if f.is_file() and f.name not in KEEP_FILES and f.stat().st_size > BIG_BYTES:
            freed += f.stat().st_size
            if not dry:
                f.unlink()
    return freed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-dir", default=str(Path(__file__).resolve().parent / "runs" / "projects"))
    ap.add_argument("--days", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-compact", action="store_true", help="only prune duplicate runs, don't strip crawl data")
    ap.add_argument("--reap-failed", action="store_true",
                    help="also strip crawl data from failed/partial runs regardless of age")
    ap.add_argument("--reap-age-mins", type=int, default=30,
                    help="min age before a failed run is reaped (avoids touching an in-progress scan)")
    a = ap.parse_args()

    root = Path(a.runs_dir).resolve()
    if not root.is_dir():
        print(f"runs dir not found: {root}"); return 1
    cutoff = dt.datetime.now().timestamp() - a.days * 86400
    tag = "WOULD " if a.dry_run else ""
    freed = pruned = compacted = kept = 0

    for proj in sorted(p for p in root.iterdir() if p.is_dir()):
        runs = sorted((r for r in proj.iterdir() if r.is_dir()), key=run_time)
        if not runs:
            continue
        latest = runs[-1]
        reap_cut = dt.datetime.now().timestamp() - a.reap_age_mins * 60
        for r in runs:
            # Failed/partial runs are dead weight: strip their crawl data now,
            # not after --days. Skip very fresh ones (may still be running).
            if a.reap_failed and (r / "crawl").is_dir() and run_time(r) < reap_cut \
                    and r.stat().st_mtime < reap_cut and is_incomplete(r):
                got = compact(r, a.dry_run)
                if got:
                    print(f"{tag}REAP    {got/1e6:8.1f} MB  {proj.name}/{r.name} (failed/partial)")
                    freed += got; compacted += 1
                    continue
            old = run_time(r) < cutoff
            # 1. prune non-latest old runs entirely
            if old and r != latest:
                sz = dir_size(r)
                print(f"{tag}PRUNE   {sz/1e6:8.1f} MB  {proj.name}/{r.name}")
                if not a.dry_run:
                    shutil.rmtree(r)
                freed += sz; pruned += 1
                continue
            # 2. compact old survivors (incl. the latest if it's old)
            if old and not a.no_compact:
                got = compact(r, a.dry_run)
                if got:
                    print(f"{tag}COMPACT {got/1e6:8.1f} MB  {proj.name}/{r.name}")
                    freed += got; compacted += 1
                else:
                    kept += 1
            else:
                kept += 1

    print("-" * 64)
    verb = "Would free" if a.dry_run else "Freed"
    print(f"{verb}: {freed/1e6:.1f} MB  |  pruned {pruned} run(s), compacted {compacted}, untouched {kept}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
