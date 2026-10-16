"""Command line: `demo` builds everything from a fictional tenant, `report` runs on your own export."""
from __future__ import annotations

import argparse
from pathlib import Path

from . import report, simulate
from .checks import Thresholds, run_all
from .model import load


def run(export: Path, out: Path, title: str, t: Thresholds, horizon: int = 180) -> dict:
    inv = load(export)
    findings = run_all(inv, t)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(inv, findings, title), encoding="utf-8")
    report.write_findings(findings, out / "findings.csv")
    report.write_renewals(inv, out / "renewals.csv", horizon)
    (out / "review.md").write_text(report.review_md(inv, findings), encoding="utf-8")
    return report.summary(inv, findings)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ssoaudit", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="generate a fictional tenant and build the outputs")
    d.add_argument("--out", type=Path, default=Path("output"))
    d.add_argument("--data", type=Path, default=Path("sample_data"))
    r = sub.add_parser("report", help="build the outputs from your own export")
    r.add_argument("export", type=Path, help="JSON from scripts/Export-EntraAppInventory.ps1")
    r.add_argument("--out", type=Path, default=Path("output"))
    r.add_argument("--title", default="Entra SSO and app audit")
    r.add_argument("--warning-days", type=int, default=60)
    r.add_argument("--critical-days", type=int, default=14)
    r.add_argument("--unused-days", type=int, default=90)
    r.add_argument("--horizon-days", type=int, default=180, help="how far ahead renewals.csv looks")
    a = p.parse_args(argv)

    if a.cmd == "demo":
        sm = run(simulate.write_demo(a.data), a.out, "Entra SSO and app audit (demo data)", Thresholds())
    else:
        t = Thresholds(critical_days=a.critical_days, warning_days=a.warning_days, unused_days=a.unused_days)
        sm = run(a.export, a.out, a.title, t, a.horizon_days)
    print(f"{sm['apps']} enterprise apps ({sm['sso']} SSO) · {sm['registrations']} app registrations · "
          f"{sm['renewals_60']} renewals in 60 days · {sm['critical']} critical, {sm['warning']} warnings, "
          f"{sm['info']} clean-up. Outputs in {a.out}/")
    return 0
