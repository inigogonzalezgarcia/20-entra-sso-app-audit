"""Fictional demo tenant (contoso.example): SaaS apps with SAML or OIDC, in-house apps, daemons and consented apps.

App names are well-known SaaS products used only as realistic labels; IDs, owners, dates and settings are invented.
Nothing here comes from a real tenant. Faults are placed on purpose so every check fires at least once.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEMO_NOW = datetime(2026, 10, 19, 7, 0, tzinfo=timezone.utc)


def _ts(**delta) -> str:
    return (DEMO_NOW + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name + ".contoso.example"))


def _saml_cert(days_left: int, issued_days_ago: int = 1000):
    end = _ts(days=days_left)
    start = _ts(days=-issued_days_ago)
    return [{"type": "AsymmetricX509Cert", "usage": "Sign", "displayName": "CN=Microsoft Azure Federated SSO Certificate",
             "startDateTime": start, "endDateTime": end},
            {"type": "AsymmetricX509Cert", "usage": "Verify", "displayName": "CN=Microsoft Azure Federated SSO Certificate",
             "startDateTime": start, "endDateTime": end}]


def _saas(name, mode="saml", cert=400, owners=("it-apps@contoso.example",), required=True, last=1, publisher=None,
          prov=None, verified=True):
    return {"id": _id("sp-" + name), "appId": _id(name), "displayName": name, "ownedByThisTenant": False,
            "publisherName": publisher or name.split()[0] + " Inc.", "verifiedPublisher": verified,
            "signInMode": mode, "appRoleAssignmentRequired": required, "accountEnabled": True, "owners": list(owners),
            "keyCredentials": _saml_cert(cert) if mode == "saml" else [], "passwordCredentials": [],
            "assignedPrincipals": 4, "lastSignIn": None if last is None else _ts(days=-last), "appPermissions": [],
            "delegatedGrants": [{"scope": "openid profile email", "consentType": "AllPrincipals"}] if mode == "oidc" else [],
            "provisioning": prov}


def _own(name, mode="", perms=(), last=1, owners=("platform-team@contoso.example",), required=True):
    """In-house app: an app registration here plus its service principal."""
    return {"id": _id("sp-" + name), "appId": _id(name), "displayName": name, "ownedByThisTenant": True,
            "publisherName": "Contoso", "verifiedPublisher": False, "signInMode": mode,
            "appRoleAssignmentRequired": required, "accountEnabled": True, "owners": list(owners),
            "keyCredentials": [], "passwordCredentials": [], "assignedPrincipals": 2 if mode else 0,
            "lastSignIn": None if last is None else _ts(days=-last), "appPermissions": list(perms),
            "delegatedGrants": [], "provisioning": None}


def _reg(name, secrets=(), certs=(), owners=("platform-team@contoso.example",), uris=()):
    return {"appId": _id(name), "displayName": name, "owners": list(owners), "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [{"displayName": n, "startDateTime": _ts(days=-age), "endDateTime": _ts(days=left)}
                                    for n, age, left in secrets],
            "keyCredentials": [{"type": "AsymmetricX509Cert", "usage": "Verify", "displayName": n,
                                "startDateTime": _ts(days=-age), "endDateTime": _ts(days=left)} for n, age, left in certs],
            "redirectUris": list(uris)}


def demo_inventory() -> dict:
    ok_prov = {"status": "Active", "lastRunState": "Succeeded", "lastRun": _ts(minutes=-35), "errors": 0}
    sps = [
        _saas("ServiceNow", cert=9, prov=ok_prov),                                   # signing cert in 9 days
        _saas("Salesforce", cert=45),
        _saas("Workday", cert=300, prov={"status": "Quarantine", "lastRunState": "Failed",
                                         "lastRun": _ts(hours=-30), "errors": 6}),  # leavers not reaching HR app
        _saas("Atlassian Cloud", cert=260, prov={"status": "Active", "lastRunState": "Failed",
                                                 "lastRun": _ts(minutes=-40), "errors": 2}),
        _saas("Zoom", cert=500, required=False),                                       # any user can sign in
        _saas("DocuSign", cert=350, owners=()),                                        # nobody owns it
        _saas("Expensify", cert=210, last=200),                                        # replaced last year
        _saas("Slack", cert=420),                                                      # excluded from MFA policy
        _saas("Box", cert=-6, last=6),                                                 # cert expired last week
        _saas("Miro", mode="oidc", publisher="Miro Inc."),
        _saas("Figma", cert=600),
        _saas("Adobe Admin Console", cert=330),
        _saas("Travel Portal (legacy)", mode="password", required=False, last=None, owners=(), publisher="Old travel agency"),
        _own("Contoso Intranet", mode="oidc"),
        _own("Contoso HR Portal", mode="oidc", required=False),
        _own("Payroll Export", perms=["User.Read.All"], last=0),
        _own("M365 Backup Connector", perms=["Mail.ReadWrite", "Files.ReadWrite.All", "Sites.FullControl.All"], last=0),
        _own("Old Automation", perms=["Directory.ReadWrite.All", "User.Read.All"], last=3, owners=()),
        _own("Reporting Dashboard", perms=["Reports.Read.All"], last=1),
    ]
    # Third-party apps users or admins consented to (no SSO configuration)
    sps.append({"id": _id("sp-pdf"), "appId": _id("pdfconv"), "displayName": "PDF Converter Pro", "ownedByThisTenant": False,
                "publisherName": "PDFTools Ltd", "verifiedPublisher": False, "signInMode": "",
                "appRoleAssignmentRequired": False, "accountEnabled": True, "owners": [], "keyCredentials": [],
                "passwordCredentials": [], "assignedPrincipals": 0, "lastSignIn": _ts(days=-2), "appPermissions": [],
                "delegatedGrants": [{"scope": "openid offline_access Mail.Read Files.Read.All", "consentType": "AllPrincipals"}],
                "provisioning": None})
    sps.append({"id": _id("sp-notes"), "appId": _id("notes"), "displayName": "MeetingNotes AI", "ownedByThisTenant": False,
                "publisherName": "MeetingNotes AI Inc.", "verifiedPublisher": True, "signInMode": "",
                "appRoleAssignmentRequired": False, "accountEnabled": True, "owners": [], "keyCredentials": [],
                "passwordCredentials": [], "assignedPrincipals": 0, "lastSignIn": _ts(days=-1), "appPermissions": [],
                "delegatedGrants": [{"scope": "User.Read Calendars.Read", "consentType": "AllPrincipals"},
                                    {"scope": "Notes.Read.All", "consentType": "Principal"}],
                "provisioning": None})
    regs = [
        _reg("Contoso Intranet", secrets=[("prod", 700, 20), ("legacy-2019", 2400, 1250)],
             uris=["https://intranet.contoso.example/signin-oidc"]),
        _reg("Contoso HR Portal", certs=[("hr-portal-2026", 200, 160)],
             uris=["https://hr.contoso.example/auth", "http://hr-test.contoso.example/auth", "https://localhost:5001/auth"]),
        _reg("Payroll Export", secrets=[("payroll-2025", 368, -3)]),                  # expired, job still runs
        _reg("M365 Backup Connector", certs=[("backup-2026", 100, 265)]),
        _reg("Old Automation", secrets=[("do-not-delete", 900, 2750)], owners=()),
        _reg("Reporting Dashboard", secrets=[("old", 400, -35), ("current", 35, 330)],
             uris=["https://*.contoso.example/reports"]),
    ]
    policies = [
        {"displayName": "CA001 - All users - All apps - Require MFA", "state": "enabled", "includeApplications": ["All"],
         "excludeApplications": [_id("Slack")], "grantControls": ["mfa"], "includeUsers": ["All"]},
        {"displayName": "CA002 - All users - Block legacy authentication", "state": "enabled",
         "includeApplications": ["All"], "excludeApplications": [], "grantControls": ["block"], "includeUsers": ["All"]},
        {"displayName": "CA010 - Admins - Phishing-resistant MFA (report-only)", "state": "enabledForReportingButNotEnforced",
         "includeApplications": ["All"], "excludeApplications": [], "grantControls": ["mfa"], "includeUsers": ["Admins"]},
    ]
    return {"collectedAt": DEMO_NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "tenant": "contoso.example",
            "servicePrincipals": sps, "applications": regs, "conditionalAccess": policies}


def write_demo(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "entra_apps.json"
    path.write_text(json.dumps(demo_inventory(), indent=1), encoding="utf-8")
    return path
