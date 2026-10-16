# Monthly app access review · runbook

For the identity or workplace engineer who runs the audit, and the security owner who chairs the review.

## When

- **Monthly**, as part of the access review. Bring `review.md` to the meeting.
- **Weekly**, only the renewal calendar (`renewals.csv`) for the next 60 days: SAML certificates and secrets
  are the most common cause of "SSO stopped working this morning".
- **Before onboarding a new SaaS app** and after a vendor changes its SSO or SCIM integration.

## Run it

```powershell
.\scripts\Export-EntraAppInventory.ps1 -OutputPath .\entra_apps.json
```

```bash
python -m ssoaudit report entra_apps.json --out 2026-10
```

The export needs a role that can read applications, sign-in reports and Conditional Access
(Global Reader is enough). It reads dates of secrets and certificates, never their values.

## Renewing a SAML signing certificate without an outage

1. In the enterprise app, **create a new certificate**. Leave it inactive.
2. Send the vendor the new certificate or the new federation metadata URL, and **agree a switch time**.
3. At that time, **make the new certificate active**, test a sign-in with a non-admin account, keep the old
   one until the vendor confirms.
4. Remove the old certificate a few days later. Add the next expiry date to the calendar.

Some vendors accept two certificates at once (rollover); then there is no switch window at all.

## Rotating a client secret

Add the new secret, update it where the app reads it (Key Vault, pipeline variable, server config), check the
app signs in with it (the sign-in logs show the credential used), then delete the old one. If you find the
same secret pasted in several places, that is the reason to move the app to a certificate or a managed identity.

## Decisions the review should take

- **Owners**: every SSO app and app registration has a named owner and a backup. No owner, no renewal.
- **Assignment required**: on for every SSO app, with access through groups. Exceptions written down.
- **MFA**: every SSO app inside the baseline Conditional Access policy. Exclusions have an end date.
- **Application permissions**: anything that can write to the directory or read everyone's mail or files is
  justified, owned and scoped (Exchange application access policies, `Sites.Selected`).
- **Tenant-wide consent to outside apps**: revoke what nobody owns. Consider turning off user consent and
  using the admin consent workflow.
- **Provisioning**: a job in quarantine means leavers keep their account in that app. Same day.
- **Unused apps**: disable for 30 days, then delete.

## What the audit does not do

It does not change anything, does not read sign-in logs per user and does not test the vendor side of the SSO.
