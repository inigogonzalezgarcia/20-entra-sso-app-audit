"""The checks: credentials about to expire, who owns each app, who can sign in, what the app is allowed to do."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from .model import EnterpriseApp, Inventory

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
AREAS = ["Credentials", "Ownership", "Access", "Permissions", "Provisioning", "Lifecycle"]

# Application permissions (app-only, no user present) that amount to tenant takeover or mass data access
TAKEOVER = {"Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
            "Application.ReadWrite.All", "Domain.ReadWrite.All", "PrivilegedAccess.ReadWrite.AzureAD"}
DATA_WIDE = {"Mail.ReadWrite", "Mail.Read", "Mail.Send", "Files.ReadWrite.All", "Files.Read.All", "Sites.FullControl.All",
             "Sites.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "Calendars.ReadWrite",
             "Chat.Read.All", "full_access_as_app"}
# Delegated scopes that are worth a look when granted for every user to an outside app
RISKY_DELEGATED = {"Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All",
                   "Sites.Read.All", "Directory.Read.All", "Directory.AccessAsUser.All", "Contacts.Read",
                   "Calendars.Read", "Notes.Read.All", "offline_access"}

FIX = {
    "saml_cert_expiring": "Create a new SAML signing certificate, send the new metadata or certificate to the vendor, "
                          "agree a switch date and make it active. Keep the old one until the vendor confirms.",
    "credential_expiring": "Add a new secret or certificate, update it where the app stores it (Key Vault, config), "
                           "then remove the old one. Prefer certificates or managed identities over secrets.",
    "credential_expired_unused": "Remove the expired credential. If the app is not used either, plan its removal.",
    "credential_long_lived": "Secrets valid for years end up in scripts and wikis. Replace with one of 6–12 months, "
                             "or a certificate or managed identity.",
    "no_owner": "Name at least two owners (a person and a backup) who can approve access and renew credentials.",
    "open_to_all": "Any user in the tenant can sign in. Turn on 'Assignment required' and assign the groups that need it.",
    "no_mfa_policy": "No enabled Conditional Access policy requiring MFA covers this app. Include it in your baseline "
                     "policy (or check if an exclusion was meant to be temporary).",
    "app_perm_takeover": "This app can change the directory without a user present. Confirm the business need, the "
                         "owner and where its credential is stored; reduce to the narrowest permission.",
    "app_perm_data": "App-only access to everyone's mail, files or sites. Scope it (Exchange application access "
                     "policy, Sites.Selected) or confirm the need with the data owner.",
    "tenant_wide_consent": "An outside app has consent for every user to read data on their behalf. Check the "
                           "publisher, who consented and when; revoke if nobody owns the decision.",
    "unverified_publisher": "Third-party app from an unverified publisher with permissions in this tenant. Verify the "
                            "vendor or remove the app.",
    "scim_quarantine": "Provisioning is in quarantine: new joiners and leavers are not reaching the app. Check the "
                       "provisioning logs and the admin credential the connector uses, then restart the job.",
    "scim_failing": "The last provisioning cycle failed or had errors. Read the provisioning logs before the next "
                    "cycle; leavers may still have access in the app.",
    "insecure_redirect": "Redirect URI over plain HTTP or with a wildcard. Use HTTPS and exact URIs (localhost is fine "
                         "for development apps).",
    "unused_app": "No sign-ins in the period. Ask the owner; disable for 30 days, then delete.",
}


@dataclass
class Finding:
    code: str
    area: str
    severity: str
    app: str
    detail: str

    @property
    def fix(self) -> str:
        return FIX.get(self.code, "")


@dataclass
class Thresholds:
    critical_days: int = 14
    warning_days: int = 60
    unused_days: int = 90
    long_lived_days: int = 730
    trusted_publishers: set[str] = field(default_factory=lambda: {"Microsoft Corporation", "Microsoft Services"})


def days_left(now: datetime, end: datetime | None) -> float | None:
    return None if end is None else (end - now).total_seconds() / 86400


def is_signing(c) -> bool:
    """SAML apps hold certificate pairs: the private one is usage Sign, its public half is usage Verify."""
    return c.usage == "Sign" or (not c.usage and c.kind.lower().startswith("asym"))


def _recently_used(app: EnterpriseApp | None, now: datetime, t: Thresholds) -> bool:
    return bool(app and app.last_sign_in and (now - app.last_sign_in).days < t.unused_days)


def check_credentials(inv: Inventory, t: Thresholds) -> list[Finding]:
    out = []
    now = inv.collected_at
    by_app_id = {a.app_id: a for a in inv.apps}
    for app in inv.apps:
        if app.sign_in_mode != "saml":
            continue
        signing = [c for c in app.credentials if is_signing(c)]
        live = [c for c in signing if (days_left(now, c.end) or 0) > 0]
        if not live and signing:
            out.append(Finding("saml_cert_expiring", AREAS[0], CRITICAL, app.name, "SAML signing certificate expired."))
            continue
        nearest = min((days_left(now, c.end) for c in live), default=None)
        if nearest is not None and nearest <= t.warning_days and \
                not any((days_left(now, c.end) or 0) > t.warning_days for c in live):
            sev = CRITICAL if nearest <= t.critical_days else WARNING
            out.append(Finding("saml_cert_expiring", AREAS[0], sev, app.name,
                               f"SAML signing certificate expires in {nearest:.0f} days."))
    for reg in inv.registrations:
        used = _recently_used(by_app_id.get(reg.app_id), now, t)
        for c in reg.credentials:
            left = days_left(now, c.end)
            label = f"{c.kind} '{c.name}'" if c.name else c.kind
            if left is None:
                continue
            rotated = any(o is not c and o.start and c.start and o.start > c.start
                          and (days_left(now, o.end) or 0) > t.warning_days for o in reg.credentials)
            if left <= 0:
                if used and not rotated:
                    out.append(Finding("credential_expiring", AREAS[0], CRITICAL, reg.name,
                                       f"{label} expired {-left:.0f} days ago and the app still signs in."))
                else:
                    out.append(Finding("credential_expired_unused", AREAS[0], INFO, reg.name,
                                       f"{label} expired {-left:.0f} days ago."))
            elif left <= t.warning_days:
                if not rotated:                  # a newer credential already replaced it
                    sev = CRITICAL if left <= t.critical_days else WARNING
                    out.append(Finding("credential_expiring", AREAS[0], sev, reg.name, f"{label} expires in {left:.0f} days."))
            if c.kind == "secret" and c.start and c.end and (c.end - c.start).days > t.long_lived_days and left > 0:
                out.append(Finding("credential_long_lived", AREAS[0], WARNING, reg.name,
                                   f"Secret '{c.name or '?'}' is valid for {(c.end - c.start).days // 365} years."))
    return out


def check_ownership(inv: Inventory) -> list[Finding]:
    out = []
    for reg in inv.registrations:
        if not reg.owners:
            out.append(Finding("no_owner", AREAS[1], WARNING, reg.name, "App registration without owners."))
    regs = {r.app_id for r in inv.registrations}
    for app in inv.apps:
        if app.is_sso and app.enabled and not app.owners and app.app_id not in regs:
            out.append(Finding("no_owner", AREAS[1], WARNING, app.name, "SSO enterprise app without owners."))
    return out


def mfa_covered(app: EnterpriseApp, inv: Inventory) -> bool:
    for p in inv.policies:
        if p.state != "enabled" or "mfa" not in p.grant or not p.include_users:
            continue
        if app.app_id in p.exclude_apps:
            continue
        if "All" in p.include_apps or app.app_id in p.include_apps:
            return True
    return False


def check_access(inv: Inventory) -> list[Finding]:
    out = []
    for app in inv.apps:
        if not (app.is_sso and app.enabled):
            continue
        if not app.assignment_required:
            out.append(Finding("open_to_all", AREAS[2], WARNING, app.name,
                               f"{app.sign_in_mode.upper()} app with 'Assignment required' off."))
        if not mfa_covered(app, inv):
            out.append(Finding("no_mfa_policy", AREAS[2], WARNING, app.name, "Not covered by an enabled MFA policy."))
    return out


def check_permissions(inv: Inventory, t: Thresholds) -> list[Finding]:
    out = []
    for app in inv.apps:
        if not app.enabled:
            continue
        takeover = sorted(set(app.app_permissions) & TAKEOVER)
        data = sorted(set(app.app_permissions) & DATA_WIDE)
        if takeover:
            out.append(Finding("app_perm_takeover", AREAS[3], CRITICAL, app.name, "Application permissions: " + ", ".join(takeover)))
        if data:
            out.append(Finding("app_perm_data", AREAS[3], WARNING, app.name, "Application permissions: " + ", ".join(data)))
        if app.first_party:
            continue
        wide = sorted({s for g in app.grants if g.consent_type == "AllPrincipals"
                       for s in g.scope.split() if s in RISKY_DELEGATED})
        if wide:
            out.append(Finding("tenant_wide_consent", AREAS[3], WARNING, app.name,
                               f"Consented for all users: {', '.join(wide)} (publisher: {app.publisher or 'unknown'})."))
        has_access = bool(app.grants or app.app_permissions)
        if has_access and not app.verified_publisher and app.publisher not in t.trusted_publishers:
            out.append(Finding("unverified_publisher", AREAS[3], INFO, app.name,
                               f"Publisher '{app.publisher or 'unknown'}' is not verified."))
    for reg in inv.registrations:
        for uri in reg.redirect_uris:
            u = urlparse(uri)
            local = u.hostname in ("localhost", "127.0.0.1")
            if "*" in uri or (u.scheme == "http" and not local):
                out.append(Finding("insecure_redirect", AREAS[3], WARNING, reg.name, f"Redirect URI {uri}"))
    return out


def check_provisioning(inv: Inventory) -> list[Finding]:
    out = []
    for app in inv.apps:
        p = app.provisioning
        if not p or p.status.lower() == "paused":
            continue
        if p.status.lower() == "quarantine":
            out.append(Finding("scim_quarantine", AREAS[4], CRITICAL, app.name,
                               f"Provisioning in quarantine; {p.errors} failed cycles in a row."))
        elif p.last_run_state.lower() == "failed" or p.errors:
            out.append(Finding("scim_failing", AREAS[4], WARNING, app.name,
                               f"Last cycle {p.last_run_state.lower() or 'unknown'}; {p.errors} failed cycles in a row."))
    return out


def check_lifecycle(inv: Inventory, t: Thresholds) -> list[Finding]:
    out = []
    for app in inv.apps:
        if not (app.is_sso and app.enabled):
            continue
        if app.last_sign_in is None:
            out.append(Finding("unused_app", AREAS[5], INFO, app.name, "No sign-ins recorded."))
        elif (inv.collected_at - app.last_sign_in).days >= t.unused_days:
            out.append(Finding("unused_app", AREAS[5], INFO, app.name,
                               f"Last sign-in {(inv.collected_at - app.last_sign_in).days} days ago."))
    return out


def run_all(inv: Inventory, t: Thresholds | None = None) -> list[Finding]:
    t = t or Thresholds()
    findings = (check_credentials(inv, t) + check_ownership(inv) + check_access(inv) + check_permissions(inv, t)
                + check_provisioning(inv) + check_lifecycle(inv, t))
    return sorted(findings, key=lambda f: (SEV_ORDER[f.severity], AREAS.index(f.area), f.app.lower(), f.code))


def renewals(inv: Inventory, horizon_days: int = 180) -> list[dict]:
    """Every credential that ends in the next `horizon_days`, soonest first: the renewal calendar."""
    now = inv.collected_at
    rows = []
    for app in inv.apps:
        if app.sign_in_mode == "saml":
            for c in app.credentials:
                left = days_left(now, c.end)
                if left is not None and 0 < left <= horizon_days and is_signing(c):
                    rows.append({"app": app.name, "what": "SAML signing certificate", "ends": c.end, "days": int(left),
                                 "owners": ", ".join(app.owners)})
    for reg in inv.registrations:
        for c in reg.credentials:
            left = days_left(now, c.end)
            if left is not None and 0 < left <= horizon_days:
                rows.append({"app": reg.name, "what": f"{c.kind} {c.name}".strip(), "ends": c.end, "days": int(left),
                             "owners": ", ".join(reg.owners)})
    return sorted(rows, key=lambda r: r["ends"])


def area_status(findings: list[Finding]) -> dict[str, str]:
    status = {a: "ok" for a in AREAS}
    for f in findings:
        if status[f.area] == "ok" or SEV_ORDER[f.severity] < SEV_ORDER[status[f.area]]:
            status[f.area] = f.severity
    return status
