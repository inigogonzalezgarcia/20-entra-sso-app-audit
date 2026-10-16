<#
.SYNOPSIS
    Exports the enterprise apps, app registrations and Conditional Access policies of a Microsoft Entra ID tenant
    into one JSON file that ssoaudit can read.

.DESCRIPTION
    For every service principal: sign-in mode, "assignment required", owners, SAML signing certificates,
    application permissions granted (app roles on Microsoft Graph and other APIs), delegated consents,
    last sign-in (servicePrincipalSignInActivities, beta) and the provisioning (SCIM) job status.
    For every app registration: owners, secrets and certificates (dates only, never values), redirect URIs.
    For Conditional Access: which apps each policy includes or excludes and whether it requires MFA.

    Read-only. Scopes requested: Application.Read.All, Directory.Read.All, AuditLog.Read.All, Policy.Read.All,
    Synchronization.Read.All. Microsoft first-party service principals are skipped unless -IncludeMicrosoftApps.

.EXAMPLE
    .\Export-EntraAppInventory.ps1 -OutputPath .\entra_apps.json
    .\Export-EntraAppInventory.ps1 -SkipSignInActivity -SkipProvisioning
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\entra_apps.json",
    [switch]$IncludeMicrosoftApps,
    [switch]$SkipSignInActivity,
    [switch]$SkipProvisioning
)

$ErrorActionPreference = "Stop"
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Install the Microsoft Graph PowerShell SDK first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Connect-MgGraph -NoWelcome -Scopes "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All",
    "Policy.Read.All", "Synchronization.Read.All"

function Get-All([string]$Uri) {
    $items = @()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri
        $items += $page.value
        $Uri = $page.'@odata.nextLink'
    }
    return $items
}
function Owners([string]$Path) {
    @(Get-All "https://graph.microsoft.com/v1.0/$Path/owners?`$select=userPrincipalName,displayName" |
      ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } })
}
function Dates($creds) {   # never export secret values or certificate blobs, only metadata
    @($creds | ForEach-Object { [ordered]@{ type = $_.type; usage = $_.usage; displayName = $_.displayName
                                            startDateTime = $_.startDateTime; endDateTime = $_.endDateTime } })
}

$org = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization").value[0]
$tenantId = $org.id
$microsoft = "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"

# Last sign-in per appId (beta report; needs Entra ID P1/P2)
$lastSignIn = @{}
if (-not $SkipSignInActivity) {
    try {
        foreach ($a in Get-All "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities") {
            $lastSignIn[$a.appId] = $a.lastSignInActivity.lastSignInDateTime
        }
    } catch { Write-Warning "Sign-in activity not available: $($_.Exception.Message)" }
}

# Names of app roles on the resource APIs (Graph, Exchange, SharePoint...) to turn role IDs into permission names
$roleNames = @{}
function RoleName([string]$ResourceId, [string]$RoleId) {
    if (-not $roleNames.ContainsKey($ResourceId)) {
        $r = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceId`?`$select=appRoles"
        $roleNames[$ResourceId] = @{}
        foreach ($role in $r.appRoles) { $roleNames[$ResourceId][$role.id] = $role.value }
    }
    return $roleNames[$ResourceId][$RoleId]
}

$select = "id,appId,displayName,appOwnerOrganizationId,publisherName,verifiedPublisher,preferredSingleSignOnMode," +
          "appRoleAssignmentRequired,accountEnabled,keyCredentials,passwordCredentials,tags"
$sps = @()
foreach ($sp in Get-All "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$select&`$top=999") {
    if (-not $IncludeMicrosoftApps -and $microsoft -contains $sp.appOwnerOrganizationId) { continue }
    $perms = @(Get-All "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" |
               ForEach-Object { RoleName $_.resourceId $_.appRoleId } | Where-Object { $_ })
    $grants = @(Get-All "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/oauth2PermissionGrants" |
                ForEach-Object { [ordered]@{ scope = "$($_.scope)".Trim(); consentType = $_.consentType } })
    $assigned = (Get-All "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=id").Count
    $prov = $null
    if (-not $SkipProvisioning) {
        try {
            $job = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/synchronization/jobs").value |
                   Select-Object -First 1
            if ($job) {
                $prov = [ordered]@{ status = $job.status.code; lastRunState = $job.status.lastExecution.state
                                    lastRun = $job.status.lastExecution.timeEnded
                                    errors = [int]$job.status.countSuccessiveCompleteFailures   # failed cycles in a row
                                    quarantineReason = $job.status.quarantine.reason }
            }
        } catch { }   # most apps have no provisioning job; the call returns 404 or 403 for them
    }
    $sps += [ordered]@{
        id = $sp.id; appId = $sp.appId; displayName = $sp.displayName
        ownedByThisTenant = ($sp.appOwnerOrganizationId -eq $tenantId)
        publisherName = $sp.publisherName; verifiedPublisher = [bool]$sp.verifiedPublisher.verifiedPublisherId
        signInMode = if ($sp.preferredSingleSignOnMode) { $sp.preferredSingleSignOnMode }
                     elseif ($sp.tags -contains "WindowsAzureActiveDirectoryIntegratedApp" -and $grants) { "oidc" } else { "" }
        appRoleAssignmentRequired = $sp.appRoleAssignmentRequired; accountEnabled = $sp.accountEnabled
        owners = Owners "servicePrincipals/$($sp.id)"
        keyCredentials = Dates $sp.keyCredentials; passwordCredentials = Dates $sp.passwordCredentials
        assignedPrincipals = $assigned; lastSignIn = $lastSignIn[$sp.appId]
        appPermissions = $perms; delegatedGrants = $grants; provisioning = $prov
    }
}

$apps = @()
foreach ($a in Get-All "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName,signInAudience,web,spa,publicClient,passwordCredentials,keyCredentials&`$top=999") {
    $uris = @($a.web.redirectUris) + @($a.spa.redirectUris) + @($a.publicClient.redirectUris) | Where-Object { $_ }
    $apps += [ordered]@{ appId = $a.appId; displayName = $a.displayName; signInAudience = $a.signInAudience
                         owners = Owners "applications/$($a.id)"; redirectUris = @($uris)
                         passwordCredentials = Dates $a.passwordCredentials; keyCredentials = Dates $a.keyCredentials }
}

$policies = @()
try {
    foreach ($p in Get-All "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies") {
        $policies += [ordered]@{ displayName = $p.displayName; state = $p.state
                                 includeApplications = @($p.conditions.applications.includeApplications)
                                 excludeApplications = @($p.conditions.applications.excludeApplications)
                                 grantControls = @($p.grantControls.builtInControls)
                                 includeUsers = @($p.conditions.users.includeUsers) + @($p.conditions.users.includeGroups) +
                                                @($p.conditions.users.includeRoles) }
    }
} catch { Write-Warning "Conditional Access policies not readable: $($_.Exception.Message)" }

[ordered]@{
    collectedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    tenant = ($org.verifiedDomains | Where-Object isDefault).name
    servicePrincipals = $sps; applications = $apps; conditionalAccess = $policies
} | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Wrote $OutputPath ($($sps.Count) enterprise apps, $($apps.Count) app registrations, $($policies.Count) CA policies)."
