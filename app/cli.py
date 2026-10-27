"""Quick command-line scan:  python -m app.cli path/to/project_or.zip [--json]"""
import json
import sys

from .loader import load_folder, load_zip
from .models import ScanResult
from .scanner import run_static_scan
from .scoring import finalize


def main(argv=None) -> int:
    args = [a for a in (argv or sys.argv[1:]) if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    target = args[0]
    files, notes = load_zip(open(target, "rb").read()) if target.endswith(".zip") else load_folder(target)
    findings, endpoints, more = run_static_scan(files)
    scan = ScanResult(scan_id="cli", project_name=target, created_at="", files_scanned=len(files),
                      findings=findings, endpoints=endpoints, notes=notes + more)
    finalize(scan)
    if "--json" in (argv or sys.argv[1:]):
        print(scan.model_dump_json(indent=2))
        return 0
    print(f"Score {scan.score}/100 ({scan.rating}) · {scan.counts.model_dump()}")
    for f in findings:
        print(f"{f.id} [{f.band:8}] {f.check_id:3} {f.file}:{f.line}  {f.title}  ({f.verdict})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
