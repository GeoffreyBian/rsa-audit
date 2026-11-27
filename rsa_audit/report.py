import json
import os
import sys
import textwrap
from dataclasses import asdict

from .core import FIX, INFO, OTHERS, SAFE, Finding, Scan

ORDER = [FIX, OTHERS, INFO, SAFE]
LABELS = {
    FIX: ("RED", "Exposed - you can fix this", "31"),
    OTHERS: ("YELLOW", "Exposed - someone else has to fix this", "33"),
    INFO: ("NOTE", "Good to know", "2"),
    SAFE: ("GREEN", "Safe from an RSA break", "32"),
}


def _color(code: str, text: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=88, initial_indent=indent, subsequent_indent=indent)


def render_text(findings: list[Finding], scan: Scan) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in ORDER}
    out = [
        "",
        _color("1", "RSA exposure report"),
        f"{counts[FIX]} to fix yourself · {counts[OTHERS]} others must fix · "
        f"{counts[SAFE]} safe",
        "",
    ]
    for sev in ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        tag, heading, code = LABELS[sev]
        out.append(_color(code + ";1", f"{tag}  {heading}"))
        for f in group:
            out.append(_color(code, f"  [{f.area}] ") + f.title)
            if f.why:
                out.append(_wrap(f.why, "      "))
            for i, step in enumerate(f.fix, 1):
                out.append(_wrap(f"{i}. {step}", "      ").replace("      ", "    > ", 1))
            for d in f.details:
                out.append(_color("2", f"      - {d}"))
        out.append("")

    out.append(_color("1", "What this scan touched"))
    out.append("  Changes made to your computer: none (read-only)")
    out.append(f"  Network: {', '.join(scan.network) if scan.network else 'none'}")
    out.append(f"  Files read ({len(scan.files_read)}):")
    out += [f"    {p.replace(str(scan.home), '~')}" for p in scan.files_read]
    if any("PRIVATE" in p.upper() or "/.ssh/id_" in p for p in scan.files_read):
        out.append(_color("2", "    (private key files: only the public header is decoded; "
                               "nothing secret is printed or stored)"))
    out.append(f"  Commands run ({len(scan.commands_run)}, all read-only):")
    out += [f"    {' '.join(c).replace(str(scan.home), '~')}" for c in scan.commands_run]
    out.append("")
    out.append(_color("2", "Ed25519/EC keys aren't affected by a factoring break. A large quantum "
                           "computer would break those too; that's a separate, slower migration."))
    return "\n".join(out)


def render_json(findings: list[Finding], scan: Scan) -> str:
    return json.dumps(
        {
            "findings": [asdict(f) for f in findings],
            "touched": {
                "files_read": scan.files_read,
                "commands_run": scan.commands_run,
                "network": scan.network,
                "writes": [],
            },
        },
        indent=2,
    )
