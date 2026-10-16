import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from ssoaudit import cli, simulate
from ssoaudit.checks import CRITICAL, INFO, WARNING, Thresholds, mfa_covered, renewals, run_all
from ssoaudit.model import from_dict, load, parse_ts

NOW = simulate.DEMO_NOW
MFA_ALL = {"displayName": "MFA", "state": "enabled", "includeApplications": ["All"], "excludeApplications": [],
           "grantControls": ["mfa"], "includeUsers": ["All"]}


def ts(**delta):
    return (NOW + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def sp(name="App", mode="saml", cert_days=400, **over):
    d = {"id": "sp-" + name, "appId": "id-" + name, "displayName": name, "ownedByThisTenant": False,
         "publisherName": "Vendor", "verifiedPublisher": True, "signInMode": mode, "appRoleAssignmentRequired": True,
         "accountEnabled": True, "owners": ["owner@x"], "keyCredentials": [], "passwordCredentials": [],
         "lastSignIn": ts(days=-1), "appPermissions": [], "delegatedGrants": [], "provisioning": None}
    if mode == "saml" and cert_days is not None:
        d["keyCredentials"] = [{"type": "AsymmetricX509Cert", "usage": u, "endDateTime": ts(days=cert_days)}
                               for u in ("Sign", "Verify")]
    d.update(over)
    return d


def reg(name="App", secrets=(), **over):
    d = {"appId": "id-" + name, "displayName": name, "owners": ["owner@x"], "redirectUris": [],
         "passwordCredentials": [{"displayName": n, "startDateTime": ts(days=-age), "endDateTime": ts(days=left)}
                                 for n, age, left in secrets]}
    d.update(over)
    return d


def inv(sps=(), regs=(), policies=(MFA_ALL,)):
    return from_dict({"collectedAt": ts(), "tenant": "t", "servicePrincipals": list(sps), "applications": list(regs),
                      "conditionalAccess": list(policies)})


def found(i, t=None):
    return [(f.code, f.severity, f.app) for f in run_all(i, t)]


class Clean(unittest.TestCase):
    def test_healthy_app_has_no_findings(self):
        self.assertEqual(found(inv([sp()])), [])


class SamlCertificates(unittest.TestCase):
    def test_thresholds(self):
        self.assertIn(("saml_cert_expiring", WARNING, "App"), found(inv([sp(cert_days=40)])))
        self.assertIn(("saml_cert_expiring", CRITICAL, "App"), found(inv([sp(cert_days=10)])))
        self.assertIn(("saml_cert_expiring", CRITICAL, "App"), found(inv([sp(cert_days=-1)])))

    def test_new_certificate_already_added(self):
        a = sp(cert_days=10)
        a["keyCredentials"].append({"type": "AsymmetricX509Cert", "usage": "Sign", "endDateTime": ts(days=1000)})
        self.assertEqual(found(inv([a])), [])

    def test_renewal_calendar_counts_the_signing_half_once(self):
        r = renewals(inv([sp(cert_days=30)]))
        self.assertEqual([(x["app"], x["days"]) for x in r], [("App", 30)])


class Secrets(unittest.TestCase):
    def test_expired_secret_critical_only_if_app_is_used_and_not_rotated(self):
        used = inv([sp(mode="", cert_days=None)], [reg(secrets=[("s", 400, -2)])])
        self.assertIn(("credential_expiring", CRITICAL, "App"), found(used))
        unused = inv([sp(mode="", cert_days=None, lastSignIn=ts(days=-200))], [reg(secrets=[("s", 400, -2)])])
        self.assertEqual(found(unused), [("credential_expired_unused", INFO, "App")])
        rotated = inv([sp(mode="", cert_days=None)], [reg(secrets=[("old", 400, -2), ("new", 10, 300)])])
        self.assertEqual(found(rotated), [("credential_expired_unused", INFO, "App")])

    def test_expiring_and_long_lived(self):
        r = found(inv([], [reg(secrets=[("short", 300, 30), ("forever", 900, 3000)])]))
        self.assertIn(("credential_expiring", WARNING, "App"), r)
        self.assertIn(("credential_long_lived", WARNING, "App"), r)


class OwnershipAndAccess(unittest.TestCase):
    def test_no_owner_open_to_all_and_mfa_exclusion(self):
        a = sp("Open", owners=[], appRoleAssignmentRequired=False)
        excl = dict(MFA_ALL, excludeApplications=["id-Open"])
        r = found(inv([a], policies=[excl]))
        self.assertIn(("no_owner", WARNING, "Open"), r)
        self.assertIn(("open_to_all", WARNING, "Open"), r)
        self.assertIn(("no_mfa_policy", WARNING, "Open"), r)

    def test_report_only_and_block_policies_do_not_count_as_mfa(self):
        a = from_dict({"servicePrincipals": [sp()]}).apps[0]
        report_only = dict(MFA_ALL, state="enabledForReportingButNotEnforced")
        block = dict(MFA_ALL, grantControls=["block"])
        self.assertFalse(mfa_covered(a, inv(policies=[report_only, block])))
        self.assertTrue(mfa_covered(a, inv(policies=[dict(MFA_ALL, includeApplications=["id-App"])])))

    def test_api_only_apps_are_not_access_checked(self):
        self.assertEqual(found(inv([sp(mode="", cert_days=None, appRoleAssignmentRequired=False, owners=[])], policies=[])), [])


class Permissions(unittest.TestCase):
    def test_application_permissions(self):
        a = sp("Daemon", mode="", cert_days=None, ownedByThisTenant=True,
               appPermissions=["Directory.ReadWrite.All", "Mail.Send", "User.Read.All"])
        r = found(inv([a]))
        self.assertIn(("app_perm_takeover", CRITICAL, "Daemon"), r)
        self.assertIn(("app_perm_data", WARNING, "Daemon"), r)

    def test_tenant_wide_consent_and_unverified_publisher(self):
        a = sp("Tool", mode="", cert_days=None, verifiedPublisher=False, publisherName="Someone",
               delegatedGrants=[{"scope": "openid Mail.Read", "consentType": "AllPrincipals"},
                                {"scope": "Files.Read.All", "consentType": "Principal"}])
        r = run_all(inv([a]))
        self.assertEqual([(f.code, f.severity) for f in r], [("tenant_wide_consent", WARNING), ("unverified_publisher", INFO)])
        self.assertIn("Mail.Read", r[0].detail)
        self.assertNotIn("Files.Read.All", r[0].detail)          # one user's own consent is not tenant-wide

    def test_redirect_uris(self):
        r = found(inv([], [reg(redirectUris=["https://ok.example/cb", "http://localhost:3000/cb",
                                             "http://test.example/cb", "https://*.example/cb"])]))
        self.assertEqual(r.count(("insecure_redirect", WARNING, "App")), 2)


class Provisioning(unittest.TestCase):
    def test_quarantine_failure_and_paused(self):
        q = sp("Q", provisioning={"status": "Quarantine", "lastRunState": "Failed", "errors": 5})
        f = sp("F", provisioning={"status": "Active", "lastRunState": "Failed", "errors": 0})
        p = sp("P", provisioning={"status": "Paused", "lastRunState": "Failed", "errors": 9})
        r = found(inv([q, f, p]))
        self.assertIn(("scim_quarantine", CRITICAL, "Q"), r)
        self.assertIn(("scim_failing", WARNING, "F"), r)
        self.assertNotIn("P", [a for _, _, a in r])


class Formats(unittest.TestCase):
    def test_graph_timestamps_and_bom(self):
        self.assertEqual(parse_ts("2026-10-19T07:00:00.1234567Z").microsecond, 123456)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.json"
            p.write_text("﻿" + json.dumps({"tenant": "t", "servicePrincipals": [sp()]}), encoding="utf-8")
            self.assertEqual(load(p).apps[0].name, "App")


class EndToEnd(unittest.TestCase):
    def test_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            self.assertEqual(cli.main(["demo", "--out", str(out), "--data", str(Path(tmp) / "data")]), 0)
            for name in ("report.html", "findings.csv", "renewals.csv", "review.md"):
                self.assertTrue((out / name).stat().st_size > 100, name)
            codes = {f.code for f in run_all(load(Path(tmp) / "data" / "entra_apps.json"), Thresholds())}
            self.assertEqual(len(codes), 15)              # every check fires at least once on the demo tenant


if __name__ == "__main__":
    unittest.main()
