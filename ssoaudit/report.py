"""Outputs: report.html, findings.csv, renewals.csv (credential calendar) and review.md (for the access review)."""
from __future__ import annotations

import csv
import html
from collections import Counter
from pathlib import Path

from .checks import AREAS, CRITICAL, INFO, WARNING, Finding, area_status, renewals
from .model import Inventory

e = html.escape


def write_findings(findings: list[Finding], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "area", "code", "app", "detail", "first_step"])
        for f in findings:
            w.writerow([f.severity, f.area, f.code, f.app, f.detail, f.fix])


def write_renewals(inv: Inventory, path: Path, horizon: int) -> int:
    rows = renewals(inv, horizon)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ends", "days_left", "app", "credential", "owners"])
        for r in rows:
            w.writerow([f"{r['ends']:%Y-%m-%d}", r["days"], r["app"], r["what"], r["owners"]])
    return len(rows)


def summary(inv: Inventory, findings: list[Finding]) -> dict:
    sev = Counter(f.severity for f in findings)
    sso = [a for a in inv.apps if a.is_sso and a.enabled]
    return {"apps": len(inv.apps), "sso": len(sso), "registrations": len(inv.registrations),
            "renewals_60": sum(1 for r in renewals(inv, 60)),
            "critical": sev.get(CRITICAL, 0), "warning": sev.get(WARNING, 0), "info": sev.get(INFO, 0)}


def review_md(inv: Inventory, findings: list[Finding]) -> str:
    sm = summary(inv, findings)
    st = area_status(findings)
    lines = [f"# App access review · {inv.tenant} · {inv.collected_at:%Y-%m-%d}", "",
             f"{sm['apps']} enterprise apps ({sm['sso']} with SSO) · {sm['registrations']} app registrations · "
             f"{sm['renewals_60']} credentials to renew in the next 60 days · {sm['critical']} critical, "
             f"{sm['warning']} warnings, {sm['info']} to tidy up.", "", "| Area | Status |", "|---|---|"]
    lines += [f"| {a} | {'OK' if st[a] == 'ok' else st[a].upper()} |" for a in AREAS]
    for sev, title in ((CRITICAL, "Act now"), (WARNING, "Decide at the review")):
        items = [f for f in findings if f.severity == sev]
        if items:
            lines += ["", f"## {title}", ""]
            lines += [f"- **{f.app}**: {f.detail}  \n  Next step: {f.fix}" for f in items]
    infos = [f for f in findings if f.severity == INFO]
    if infos:
        lines += ["", "## Clean-up", ""] + [f"- {f.app}: {f.detail}" for f in infos]
    rn = renewals(inv, 90)
    if rn:
        lines += ["", "## Renewal calendar (90 days)", "", "| Ends | App | Credential | Owners |", "|---|---|---|---|"]
        lines += [f"| {r['ends']:%Y-%m-%d} | {r['app']} | {r['what']} | {r['owners'] or '**none**'} |" for r in rn]
    lines += ["", "Read-only export; nothing was changed in the tenant. Full list: `findings.csv`.", ""]
    return "\n".join(lines)


CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:28px}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}.area.info{border-left-color:var(--info)}
.area span{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}
.area.critical,.area.warning,.area.info,.area.ok{color:inherit}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;min-width:120px}.bar i{display:block;height:100%;background:var(--ok)}
.bar i.warning{background:var(--warn)}.bar i.critical{background:var(--bad)}
td.fix{font-size:13px;color:var(--muted);max-width:380px}footer{margin-top:40px;font-size:13px}
"""

def render_html(inv: Inventory, findings: list[Finding], title: str) -> str:
    sm = summary(inv, findings)
    st = area_status(findings)
    tiles = (f"<div class='tile'><span class='muted'>Enterprise apps</span><b>{sm['apps']}</b></div>"
             f"<div class='tile'><span class='muted'>With SSO</span><b>{sm['sso']}</b></div>"
             f"<div class='tile'><span class='muted'>Renewals in 60 days</span><b>{sm['renewals_60']}</b></div>"
             f"<div class='tile'><span class='muted'>Critical</span><b class='critical'>{sm['critical']}</b></div>"
             f"<div class='tile'><span class='muted'>Warnings</span><b class='warning'>{sm['warning']}</b></div>")
    areas = "".join(f"<div class='area {st[a]}'><span>{e(a)}</span><b class='{st[a]}'>"
                    f"{'OK' if st[a] == 'ok' else st[a].capitalize()}</b></div>" for a in AREAS)
    per_app = Counter()
    worst: dict[str, str] = {}
    from .checks import SEV_ORDER
    for f in findings:
        per_app[f.app] += 1
        if f.app not in worst or SEV_ORDER[f.severity] < SEV_ORDER[worst[f.app]]:
            worst[f.app] = f.severity
    sso_rows = []
    for a in sorted((a for a in inv.apps if a.is_sso), key=lambda a: (SEV_ORDER.get(worst.get(a.name, ""), 9), a.name.lower())):
        last = "never" if a.last_sign_in is None else f"{(inv.collected_at - a.last_sign_in).days} d ago"
        s = worst.get(a.name, "ok")
        sso_rows.append(f"<tr><td><b>{e(a.name)}</b><br><span class='muted'>{e(a.publisher)}</span></td>"
                        f"<td>{e(a.sign_in_mode.upper())}</td><td>{'yes' if a.assignment_required else '<b class=warning>no</b>'}</td>"
                        f"<td>{len(a.owners) or '<b class=warning>0</b>'}</td><td>{last}</td>"
                        f"<td><span class='pill {s}'>{'OK' if s == 'ok' else s.upper()}</span></td></tr>")
    frows = "".join(f"<tr><td><span class='pill {f.severity}'>{f.severity.upper()}</span></td><td>{e(f.area)}</td>"
                    f"<td><b>{e(f.app)}</b><br>{e(f.detail)}</td><td class='fix'>{e(f.fix)}</td></tr>" for f in findings)
    rrows = "".join(f"<tr><td>{r['ends']:%Y-%m-%d}</td><td class='num'>{r['days']}</td><td>{e(r['app'])}</td>"
                    f"<td>{e(r['what'])}</td><td>{e(r['owners']) or '<b class=warning>none</b>'}</td></tr>"
                    for r in renewals(inv, 180))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><main>
<h1>{e(title)}</h1><p class="muted">{e(inv.tenant)} · {sm['registrations']} app registrations · {len(inv.policies)} Conditional Access policies ·
collected {inv.collected_at:%Y-%m-%d %H:%M} UTC</p>
<div class="tiles">{tiles}</div>
<h2>Areas</h2><div class="areas">{areas}</div>
<h2>SSO apps</h2><div class="wrap"><table><thead><tr><th>App</th><th>Protocol</th><th>Assignment required</th><th>Owners</th>
<th>Last sign-in</th><th>Status</th></tr></thead><tbody>{''.join(sso_rows)}</tbody></table></div>
<h2>Findings</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Area</th><th>What</th><th>Next step</th></tr></thead>
<tbody>{frows or "<tr><td colspan=4>Nothing to report.</td></tr>"}</tbody></table></div>
<h2>Renewal calendar · 180 days</h2><div class="wrap"><table><thead><tr><th>Ends</th><th class="num">Days</th><th>App</th>
<th>Credential</th><th>Owners</th></tr></thead><tbody>{rrows or "<tr><td colspan=5>Nothing ends in the period.</td></tr>"}</tbody></table></div>
<footer class="muted">Read-only check. What each finding means and the thresholds: README.md.</footer>
</main></body></html>"""
