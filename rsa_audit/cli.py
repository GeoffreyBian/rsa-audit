import argparse
from pathlib import Path

from . import checks, report
from .core import Scan


def run_scan(home: Path, sites: list[str]) -> tuple[list, Scan]:
    scan = Scan(home, sites)
    findings = []
    for check in checks.ALL_CHECKS:
        findings += check(scan)
    if sites:
        findings += checks.check_sites(scan)
    return findings, scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rsa-audit",
        description="Read-only check of what on this Mac would be exposed if RSA were broken.",
    )
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument(
        "--sites",
        default="",
        help="comma-separated sites to check (the only option that uses the network), "
        "e.g. github.com,mybank.com",
    )
    p.add_argument("--app", action="store_true", help="open the report as an app in your browser")
    p.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    args = p.parse_args(argv)

    if args.app:
        from .app import serve

        serve(args.home)
        return 0

    sites = [s.strip() for s in args.sites.split(",") if s.strip()]
    findings, scan = run_scan(args.home, sites)
    print(report.render_json(findings, scan) if args.json else report.render_text(findings, scan))
    return 0
