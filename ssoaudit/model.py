"""Inventory of a tenant's apps, as written by scripts/Export-EntraAppInventory.ps1 (one JSON file)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    v = str(value).strip()
    if v.startswith("/Date("):
        return datetime.fromtimestamp(int(v[6:].split(")")[0].split("+")[0]) / 1000, tz=timezone.utc)
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    if "." in v and "+" in v:                      # Graph sends 7 decimals; fromisoformat in 3.10 wants up to 6
        head, tail = v.split(".", 1)
        frac, zone = tail.split("+", 1)
        v = f"{head}.{frac[:6]}+{zone}"
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Credential:
    kind: str                 # "secret" or "certificate"
    usage: str                # "Sign", "Verify", "Encrypt" or "" for secrets
    name: str
    end: datetime | None
    start: datetime | None = None


@dataclass
class Grant:
    scope: str
    consent_type: str         # "AllPrincipals" (admin consent for everyone) or "Principal"


@dataclass
class Provisioning:
    status: str               # Active, Paused, Quarantine
    last_run_state: str       # Succeeded, Failed, Warning
    last_run: datetime | None
    errors: int


@dataclass
class EnterpriseApp:
    """A service principal: the app as it exists in this tenant."""
    id: str
    app_id: str
    name: str
    first_party: bool         # owned by this tenant (an app registration here)
    publisher: str
    verified_publisher: bool
    sign_in_mode: str         # saml, oidc, password, linked or "" (API / daemon)
    assignment_required: bool
    enabled: bool
    owners: list[str]
    credentials: list[Credential]
    assigned: int
    last_sign_in: datetime | None
    app_permissions: list[str]
    grants: list[Grant]
    provisioning: Provisioning | None

    @property
    def is_sso(self) -> bool:
        return self.sign_in_mode in ("saml", "oidc", "password")


@dataclass
class AppRegistration:
    app_id: str
    name: str
    owners: list[str]
    credentials: list[Credential]
    redirect_uris: list[str]
    audience: str


@dataclass
class CaPolicy:
    name: str
    state: str                # enabled, disabled, enabledForReportingButNotEnforced
    include_apps: list[str]
    exclude_apps: list[str]
    grant: list[str]
    include_users: list[str]


@dataclass
class Inventory:
    collected_at: datetime
    tenant: str
    apps: list[EnterpriseApp]
    registrations: list[AppRegistration]
    policies: list[CaPolicy] = field(default_factory=list)


def _creds(items, default_kind) -> list[Credential]:
    out = []
    for c in items or []:
        out.append(Credential(c.get("type", default_kind), c.get("usage", ""), c.get("displayName") or "",
                              parse_ts(c.get("endDateTime")), parse_ts(c.get("startDateTime"))))
    return out


def from_dict(d: dict) -> Inventory:
    apps = []
    for s in d.get("servicePrincipals") or []:
        prov = s.get("provisioning")
        apps.append(EnterpriseApp(
            id=s.get("id", ""), app_id=s.get("appId", ""), name=s.get("displayName", "?"),
            first_party=bool(s.get("ownedByThisTenant")), publisher=s.get("publisherName") or "",
            verified_publisher=bool(s.get("verifiedPublisher")), sign_in_mode=(s.get("signInMode") or "").lower(),
            assignment_required=bool(s.get("appRoleAssignmentRequired")), enabled=s.get("accountEnabled", True) is not False,
            owners=list(s.get("owners") or []),
            credentials=_creds(s.get("keyCredentials"), "certificate") + _creds(s.get("passwordCredentials"), "secret"),
            assigned=int(s.get("assignedPrincipals") or 0), last_sign_in=parse_ts(s.get("lastSignIn")),
            app_permissions=list(s.get("appPermissions") or []),
            grants=[Grant(g.get("scope", ""), g.get("consentType", "")) for g in s.get("delegatedGrants") or []],
            provisioning=None if not prov else Provisioning(prov.get("status", ""), prov.get("lastRunState", ""),
                                                            parse_ts(prov.get("lastRun")), int(prov.get("errors") or 0)),
        ))
    regs = [AppRegistration(
        app_id=a.get("appId", ""), name=a.get("displayName", "?"), owners=list(a.get("owners") or []),
        credentials=_creds(a.get("keyCredentials"), "certificate") + _creds(a.get("passwordCredentials"), "secret"),
        redirect_uris=list(a.get("redirectUris") or []), audience=a.get("signInAudience", "AzureADMyOrg"),
    ) for a in d.get("applications") or []]
    pols = [CaPolicy(p.get("displayName", "?"), p.get("state", ""), list(p.get("includeApplications") or []),
                     list(p.get("excludeApplications") or []), [g.lower() for g in p.get("grantControls") or []],
                     list(p.get("includeUsers") or []))
            for p in d.get("conditionalAccess") or []]
    return Inventory(parse_ts(d.get("collectedAt")) or datetime.now(timezone.utc), d.get("tenant", "tenant"),
                     apps, regs, pols)


def load(path: Path) -> Inventory:
    with open(path, encoding="utf-8-sig") as f:
        return from_dict(json.load(f))
