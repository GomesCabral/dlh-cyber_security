# MedDefense Health Systems
# Task: 14 - Service Account Control
# Script: 14-service_accounts.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Audit and harden MedDefense Active Directory service accounts.
# Safety: AUDIT-ONLY by default. Remediation requires the explicit -Apply parameter.
# Output: Service-account posture, findings, remediation and verification evidence.
#
# Required assessment:
# - Group memberships / MemberOf
# - PasswordLastSet and password age
# - TrustedForDelegation
# - AccountNotDelegated
# - ServicePrincipalName / SPN
# - LastLogonDate
# - UseDESKeyOnly
#
# Required remediation:
# - Enable "Account is sensitive and cannot be delegated"
# - AccountNotDelegated = True
# - Disable unconstrained delegation
# - TrustedForDelegation = False
# - Deny interactive logon
# - SeDenyInteractiveLogonRight
# - SeDenyRemoteInteractiveLogonRight
# - Remove service accounts from unauthorized privileged groups
# - Remove-ADGroupMember
#
# VERIFY:
# Verify AccountNotDelegated=True, TrustedForDelegation=False,
# interactive logon denied and unauthorized privileged memberships removed.
#
# VERIFIED:
# All service accounts must meet the expected MedDefense service-account baseline.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$TargetDomain = "meddefense.local"

$PasswordAgeWarningDays = 90

$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "G_IT_Admins"
)

$TempDirectory = Join-Path `
    $env:TEMP `
    "MedDefense-ServiceAccounts"

$SecEditExport = Join-Path `
    $TempDirectory `
    "security-policy-export.inf"

$SecEditImport = Join-Path `
    $TempDirectory `
    "security-policy-import.inf"

$SecEditDatabase = Join-Path `
    $TempDirectory `
    "meddefense-secedit.sdb"

# ===========================================================================
# Helper functions
# ===========================================================================

function Write-Step {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[*] $Message"
}

function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-ServiceAccounts {

    return @(
        Get-ADUser `
            -Filter * `
            -Properties `
                Enabled,
                MemberOf,
                PasswordLastSet,
                PasswordNeverExpires,
                LastLogonDate,
                ServicePrincipalName,
                TrustedForDelegation,
                AccountNotDelegated,
                UseDESKeyOnly,
                msDS-SupportedEncryptionTypes,
                DistinguishedName,
                ObjectSid |
        Where-Object {
            $_.SamAccountName -match "(?i)^svc_" -or
            $_.DistinguishedName -match "(?i)OU=Service Accounts"
        } |
        Sort-Object SamAccountName
    )
}

function Get-GroupNames {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Account
    )

    $Groups = @()

    foreach ($GroupDN in @($Account.MemberOf)) {

        try {

            $Group = Get-ADGroup `
                -Identity $GroupDN `
                -ErrorAction Stop

            $Groups += $Group.Name
        }
        catch {
            # Continue if an individual group cannot be resolved.
        }
    }

    return @(
        $Groups |
        Sort-Object -Unique
    )
}

function Get-PasswordAgeDays {

    param(
        [AllowNull()]
        [object]$PasswordLastSet
    )

    if ($null -eq $PasswordLastSet) {
        return $null
    }

    return [int](
        (New-TimeSpan `
            -Start $PasswordLastSet `
            -End (Get-Date)
        ).TotalDays
    )
}

function Show-ServiceAccount {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Account
    )

    $Groups = @(
        Get-GroupNames -Account $Account
    )

    $PasswordAge = Get-PasswordAgeDays `
        -PasswordLastSet $Account.PasswordLastSet

    Write-Host ""
    Write-Host "$($Account.SamAccountName):"

    if ($null -eq $PasswordAge) {

        Write-Host "  Password age: UNKNOWN [!]"
    }
    elseif ($PasswordAge -gt $PasswordAgeWarningDays) {

        Write-Host "  Password age: $PasswordAge days [!]"
    }
    else {

        Write-Host "  Password age: $PasswordAge days [OK]"
    }

    Write-Host `
        "  PasswordLastSet: $($Account.PasswordLastSet)"

    Write-Host `
        "  PasswordNeverExpires: $($Account.PasswordNeverExpires)"

    if ($Groups.Count -eq 0) {

        Write-Host "  Group memberships: none"
    }
    else {

        Write-Host `
            "  Group memberships: $($Groups -join ', ')"
    }

    if ($Account.TrustedForDelegation) {

        Write-Host "  Delegation: Unconstrained [!]"
    }
    else {

        Write-Host "  TrustedForDelegation: False"
    }

    Write-Host `
        "  AccountNotDelegated: $($Account.AccountNotDelegated)"

    Write-Host `
        "  UseDESKeyOnly: $($Account.UseDESKeyOnly)"

    if ($null -eq $Account.LastLogonDate) {

        Write-Host "  Last logon: NEVER / UNKNOWN"
    }
    else {

        Write-Host `
            "  Last logon: $($Account.LastLogonDate)"
    }

    $SPNs = @(
        $Account.ServicePrincipalName
    )

    if ($SPNs.Count -eq 0) {

        Write-Host "  SPN configuration: none"
    }
    else {

        Write-Host "  SPN configuration:"

        foreach ($SPN in $SPNs) {

            Write-Host "    $SPN"
        }
    }
}

function Get-ServiceAccountFindings {

    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Accounts
    )

    $Findings = @()

    foreach ($Account in $Accounts) {

        $Groups = @(
            Get-GroupNames -Account $Account
        )

        $PasswordAge = Get-PasswordAgeDays `
            -PasswordLastSet $Account.PasswordLastSet

        if (
            $null -eq $PasswordAge -or
            $PasswordAge -gt $PasswordAgeWarningDays
        ) {

            $Findings += [PSCustomObject]@{
                Account  = $Account.SamAccountName
                Severity = "HIGH"
                Finding  = "old service-account password"
                Evidence = "Password age: $PasswordAge days"
            }
        }

        if ($Account.TrustedForDelegation) {

            $Findings += [PSCustomObject]@{
                Account  = $Account.SamAccountName
                Severity = "HIGH"
                Finding  = "Unconstrained delegation"
                Evidence = "TrustedForDelegation=True"
            }
        }

        if (-not $Account.AccountNotDelegated) {

            $Findings += [PSCustomObject]@{
                Account  = $Account.SamAccountName
                Severity = "HIGH"
                Finding  = "Account can be delegated"
                Evidence = "AccountNotDelegated=False"
            }
        }

        if ($Account.UseDESKeyOnly) {

            $Findings += [PSCustomObject]@{
                Account  = $Account.SamAccountName
                Severity = "HIGH"
                Finding  = "DES-only Kerberos flag"
                Evidence = "UseDESKeyOnly=True"
            }
        }

        foreach ($Group in $Groups) {

            if ($PrivilegedGroups -contains $Group) {

                $Findings += [PSCustomObject]@{
                    Account  = $Account.SamAccountName
                    Severity = "CRITICAL"
                    Finding  = "Excessive privileged-group membership"
                    Evidence = "MemberOf=$Group"
                }
            }
        }

        if (
            $null -ne $Account.LastLogonDate -and
            $Account.SamAccountName -eq "svc_ehr" -and
            $Account.LastLogonDate.Hour -eq 3
        ) {

            Write-Host `
                "  [!!!] svc_ehr suspicious 03:xx AM LastLogonDate requires investigation"
        }
    }

    return $Findings
}

function Get-DenyLogonRights {

    $Result = [ordered]@{
        SeDenyInteractiveLogonRight       = @()
        SeDenyRemoteInteractiveLogonRight = @()
    }

    if (-not (Test-Path $TempDirectory)) {

        New-Item `
            -Path $TempDirectory `
            -ItemType Directory `
            -Force |
        Out-Null
    }

    secedit.exe `
        /export `
        /cfg $SecEditExport `
        /areas USER_RIGHTS `
        /quiet

    if (
        $LASTEXITCODE -ne 0 -or
        -not (Test-Path $SecEditExport)
    ) {

        return [PSCustomObject]$Result
    }

    $PolicyLines = Get-Content `
        -Path $SecEditExport `
        -ErrorAction SilentlyContinue

    foreach ($Line in $PolicyLines) {

        if (
            $Line -match
            "^\s*SeDenyInteractiveLogonRight\s*=\s*(.*)$"
        ) {

            $Result.SeDenyInteractiveLogonRight = @(
                $Matches[1] -split "," |
                ForEach-Object {
                    $_.Trim()
                } |
                Where-Object {
                    $_
                }
            )
        }

        if (
            $Line -match
            "^\s*SeDenyRemoteInteractiveLogonRight\s*=\s*(.*)$"
        ) {

            $Result.SeDenyRemoteInteractiveLogonRight = @(
                $Matches[1] -split "," |
                ForEach-Object {
                    $_.Trim()
                } |
                Where-Object {
                    $_
                }
            )
        }
    }

    return [PSCustomObject]$Result
}

function Set-ServiceAccountDenyLogonRights {

    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Accounts
    )

    if (-not (Test-Path $TempDirectory)) {

        New-Item `
            -Path $TempDirectory `
            -ItemType Directory `
            -Force |
        Out-Null
    }

    secedit.exe `
        /export `
        /cfg $SecEditExport `
        /areas USER_RIGHTS `
        /quiet

    if ($LASTEXITCODE -ne 0) {

        throw "Unable to export current User Rights Assignment with secedit."
    }

    $ExistingPolicy = @(
        Get-Content `
            -Path $SecEditExport `
            -ErrorAction Stop
    )

    $ExistingRights = Get-DenyLogonRights

    $AccountSids = @(
        $Accounts |
        ForEach-Object {
            "*$($_.SID.Value)"
        }
    )

    $InteractiveValues = @(
        @($ExistingRights.SeDenyInteractiveLogonRight) +
        $AccountSids |
        Sort-Object -Unique
    )

    $RemoteInteractiveValues = @(
        @($ExistingRights.SeDenyRemoteInteractiveLogonRight) +
        $AccountSids |
        Sort-Object -Unique
    )

    $Output = @()
    $InteractiveFound = $false
    $RemoteFound = $false

    foreach ($Line in $ExistingPolicy) {

        if (
            $Line -match
            "^\s*SeDenyInteractiveLogonRight\s*="
        ) {

            $Output += (
                "SeDenyInteractiveLogonRight = " +
                ($InteractiveValues -join ",")
            )

            $InteractiveFound = $true
            continue
        }

        if (
            $Line -match
            "^\s*SeDenyRemoteInteractiveLogonRight\s*="
        ) {

            $Output += (
                "SeDenyRemoteInteractiveLogonRight = " +
                ($RemoteInteractiveValues -join ",")
            )

            $RemoteFound = $true
            continue
        }

        $Output += $Line
    }

    if (-not $InteractiveFound) {

        $SystemAccessIndex = [Array]::IndexOf(
            $Output,
            "[Privilege Rights]"
        )

        if ($SystemAccessIndex -lt 0) {

            $Output += ""
            $Output += "[Privilege Rights]"
        }

        $Output += (
            "SeDenyInteractiveLogonRight = " +
            ($InteractiveValues -join ",")
        )
    }

    if (-not $RemoteFound) {

        $Output += (
            "SeDenyRemoteInteractiveLogonRight = " +
            ($RemoteInteractiveValues -join ",")
        )
    }

    Set-Content `
        -Path $SecEditImport `
        -Value $Output `
        -Encoding Unicode

    secedit.exe `
        /configure `
        /db $SecEditDatabase `
        /cfg $SecEditImport `
        /areas USER_RIGHTS `
        /quiet

    if ($LASTEXITCODE -ne 0) {

        throw "secedit failed while configuring deny interactive logon rights."
    }
}

# ===========================================================================
# Environment
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Service Account Control"
Write-Host "=============================================="
Write-Host ""

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain
$CurrentDomain = [string]$ComputerSystem.Domain

$ADModuleAvailable = [bool](
    Get-Module `
        -ListAvailable `
        -Name ActiveDirectory
)

Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Domain joined: $PartOfDomain"
Write-Host "Current domain: $CurrentDomain"
Write-Host "Target domain: $TargetDomain"

if ($Apply) {

    Write-Host "Mode: APPLY"
}
else {

    Write-Host "Mode: AUDIT ONLY"
}

Write-Host ""

if (-not $PartOfDomain) {

    throw "This computer is not joined to Active Directory."
}

if (
    $CurrentDomain.ToLower() -ne
    $TargetDomain.ToLower()
) {

    throw "Expected '$TargetDomain', detected '$CurrentDomain'."
}

if (-not $ADModuleAvailable) {

    throw "ActiveDirectory PowerShell module is required."
}

Import-Module ActiveDirectory

# ===========================================================================
# Discovery
# ===========================================================================

Write-Step "Discovering MedDefense service accounts..."

$ServiceAccounts = @(
    Get-ServiceAccounts
)

if ($ServiceAccounts.Count -eq 0) {

    throw "No MedDefense service accounts were found."
}

Write-Host `
    "    Service accounts found: $($ServiceAccounts.Count)"

# ===========================================================================
# Current posture
# ===========================================================================

Write-Host ""
Write-Step "Current service-account security posture..."

foreach ($Account in $ServiceAccounts) {

    Show-ServiceAccount `
        -Account $Account
}

# ===========================================================================
# Findings
# ===========================================================================

Write-Host ""
Write-Step "Flagging service-account findings..."

$Findings = @(
    Get-ServiceAccountFindings `
        -Accounts $ServiceAccounts
)

if ($Findings.Count -eq 0) {

    Write-Host "    No findings detected."
}
else {

    foreach ($Finding in $Findings) {

        Write-Host `
            "    [$($Finding.Severity)] $($Finding.Account): $($Finding.Finding) - $($Finding.Evidence)"
    }
}

Write-Host ""
Write-Host "    Findings: $($Findings.Count)"

# ===========================================================================
# Current deny-logon rights
# ===========================================================================

Write-Host ""
Write-Step "Checking interactive logon restrictions..."

$CurrentDenyRights = Get-DenyLogonRights

Write-Host `
    "    SeDenyInteractiveLogonRight entries: $(@($CurrentDenyRights.SeDenyInteractiveLogonRight).Count)"

Write-Host `
    "    SeDenyRemoteInteractiveLogonRight entries: $(@($CurrentDenyRights.SeDenyRemoteInteractiveLogonRight).Count)"

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No Active Directory membership, delegation or User Rights Assignment will be changed."
    Write-Host ""

    Write-Step "Remediating..."

    foreach ($Account in $ServiceAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): AccountNotDelegated=True [WOULD SET]"

        Write-Host `
            "    $($Account.SamAccountName): TrustedForDelegation=False [WOULD SET]"

        Write-Host `
            "    $($Account.SamAccountName): Deny interactive logon [WOULD SET]"
    }

    foreach ($Account in $ServiceAccounts) {

        $Groups = @(
            Get-GroupNames -Account $Account
        )

        foreach ($Group in $Groups) {

            if ($PrivilegedGroups -contains $Group) {

                Write-Host `
                    "    $($Account.SamAccountName): Remove from $Group [WOULD REMOVE]"
            }
        }
    }

    Write-Host ""

    Write-Step "VERIFY target state..."

    Write-Host `
        "    Account is sensitive and cannot be delegated [WOULD VERIFY]"

    Write-Host `
        "    AccountNotDelegated=True [WOULD VERIFY]"

    Write-Host `
        "    TrustedForDelegation=False [WOULD VERIFY]"

    Write-Host `
        "    SeDenyInteractiveLogonRight [WOULD VERIFY]"

    Write-Host `
        "    SeDenyRemoteInteractiveLogonRight [WOULD VERIFY]"

    Write-Host `
        "    Unauthorized privileged groups removed [WOULD VERIFY]"

    Write-Host ""
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# APPLY safeguards
# ===========================================================================

if (-not (Test-IsAdministrator)) {

    throw "Apply mode requires an elevated PowerShell session."
}

# ===========================================================================
# Delegation hardening
# ===========================================================================

Write-Host ""
Write-Step "Hardening delegation..."

foreach ($Account in $ServiceAccounts) {

    # "Account is sensitive and cannot be delegated"
    Set-ADAccountControl `
        -Identity $Account.DistinguishedName `
        -AccountNotDelegated $true

    # Explicitly remove unconstrained delegation.
    Set-ADAccountControl `
        -Identity $Account.DistinguishedName `
        -TrustedForDelegation $false

    Write-Host `
        "    $($Account.SamAccountName): AccountNotDelegated=True [SET]"

    Write-Host `
        "    $($Account.SamAccountName): TrustedForDelegation=False [SET]"
}

# ===========================================================================
# Remove unauthorized privileged memberships
# ===========================================================================

Write-Host ""
Write-Step "Removing excessive privileged memberships..."

$MembershipsRemoved = 0

foreach ($Account in $ServiceAccounts) {

    $Groups = @(
        Get-GroupNames -Account $Account
    )

    foreach ($GroupName in $Groups) {

        if ($PrivilegedGroups -contains $GroupName) {

            try {

                Remove-ADGroupMember `
                    -Identity $GroupName `
                    -Members $Account `
                    -Confirm:$false `
                    -ErrorAction Stop

                Write-Host `
                    "    $($Account.SamAccountName): removed from $GroupName [DONE]"

                $MembershipsRemoved++
            }
            catch {

                Write-Host `
                    "    $($Account.SamAccountName): could not remove from $GroupName [WARNING]"
            }
        }
    }
}

if ($MembershipsRemoved -eq 0) {

    Write-Host `
        "    No unauthorized privileged memberships required removal [OK]"
}

# ===========================================================================
# Deny interactive logon rights
# ===========================================================================

Write-Host ""
Write-Step "Denying interactive logon rights..."

Set-ServiceAccountDenyLogonRights `
    -Accounts $ServiceAccounts

Write-Host `
    "    SeDenyInteractiveLogonRight [SET]"

Write-Host `
    "    SeDenyRemoteInteractiveLogonRight [SET]"

# ===========================================================================
# Refresh policy
# ===========================================================================

Write-Host ""
Write-Step "Refreshing security policy..."

gpupdate.exe /force |
    Out-Null

Write-Host "    gpupdate /force [COMPLETE]"

Start-Sleep -Seconds 3

# ===========================================================================
# VERIFY
# ===========================================================================

Write-Host ""
Write-Step "Verification..."

$VerificationFailures = 0

$VerifiedAccounts = @(
    Get-ServiceAccounts
)

# ---------------------------------------------------------------------------
# VERIFY delegation
# ---------------------------------------------------------------------------

foreach ($Account in $VerifiedAccounts) {

    if ($Account.AccountNotDelegated) {

        Write-Host `
            "    $($Account.SamAccountName): AccountNotDelegated=True [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): AccountNotDelegated=False [NOT VERIFIED]"

        $VerificationFailures++
    }

    if (-not $Account.TrustedForDelegation) {

        Write-Host `
            "    $($Account.SamAccountName): TrustedForDelegation=False [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): unconstrained delegation remains [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# VERIFY privileged memberships
# ---------------------------------------------------------------------------

foreach ($Account in $VerifiedAccounts) {

    $Groups = @(
        Get-GroupNames -Account $Account
    )

    $Unauthorized = @(
        $Groups |
        Where-Object {
            $PrivilegedGroups -contains $_
        }
    )

    if ($Unauthorized.Count -eq 0) {

        Write-Host `
            "    $($Account.SamAccountName): unauthorized privileged groups removed [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): privileged groups remain: $($Unauthorized -join ', ') [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# VERIFY interactive logon denial
# ---------------------------------------------------------------------------

$VerifiedRights = Get-DenyLogonRights

$InteractiveRights = @(
    $VerifiedRights.SeDenyInteractiveLogonRight
)

$RemoteInteractiveRights = @(
    $VerifiedRights.SeDenyRemoteInteractiveLogonRight
)

foreach ($Account in $VerifiedAccounts) {

    $SidEntry = "*$($Account.SID.Value)"

    if ($InteractiveRights -contains $SidEntry) {

        Write-Host `
            "    $($Account.SamAccountName): interactive logon denied [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): SeDenyInteractiveLogonRight [NOT VERIFIED]"

        $VerificationFailures++
    }

    if ($RemoteInteractiveRights -contains $SidEntry) {

        Write-Host `
            "    $($Account.SamAccountName): RDP interactive logon denied [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): SeDenyRemoteInteractiveLogonRight [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ===========================================================================
# Final status
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host `
        "[VERIFIED] Service account hardening: PASS"

    exit 0
}
else {

    Write-Host `
        "[NOT VERIFIED] Service account hardening: FAIL"

    Write-Host `
        "[!] Failed checks: $VerificationFailures"

    exit 1
}