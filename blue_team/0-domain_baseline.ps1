# MedDefense Health Systems - Windows Domain Security Baseline
#
# Task 0 - Domain Reconnaissance
#
# Purpose:
# Capture the current Windows / Active Directory security state before
# hardening activities begin.
#
# SAFETY:
# This script is READ-ONLY.
#
# It does NOT:
# - create or modify users
# - change passwords
# - modify Group Policy
# - change registry values
# - modify firewall rules
# - enable or disable services
# - alter domain configuration
#
# The script automatically detects whether the current computer is joined
# to an Active Directory domain and whether the required AD/GPO modules
# are available.
#
# Output:
# domain_baseline.json

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$OutputFile = Join-Path $ScriptDirectory "domain_baseline.json"

Write-Host "[*] MedDefense Domain Reconnaissance"
Write-Host "[*] Read-only security baseline"
Write-Host ""

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Convert-DateSafe {
    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([datetime]$Value).ToString("o")
    }
    catch {
        return [string]$Value
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Evidence,

        [Parameter(Mandatory)]
        [string]$Recommendation
    )

    $script:Findings += [PSCustomObject]@{
        severity       = $Severity
        title          = $Title
        evidence       = $Evidence
        recommendation = $Recommendation
    }
}

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

Write-Host "[*] Detecting Windows environment..."

$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$OperatingSystem = Get-CimInstance Win32_OperatingSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain

$ADModuleAvailable = [bool](
    Get-Module -ListAvailable -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module -ListAvailable -Name GroupPolicy
)

if ($PartOfDomain) {
    $EnvironmentMode = "active_directory"
}
else {
    $EnvironmentMode = "standalone_windows"
}

Write-Host "    Computer: $env:COMPUTERNAME"
Write-Host "    Domain joined: $PartOfDomain"
Write-Host "    ActiveDirectory module: $ADModuleAvailable"
Write-Host "    GroupPolicy module: $GPOModuleAvailable"

# ---------------------------------------------------------------------------
# Generic system identity
# ---------------------------------------------------------------------------

$SystemIdentity = [PSCustomObject]@{
    computer_name  = $env:COMPUTERNAME
    current_user   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    operating_system = $OperatingSystem.Caption
    os_version     = $OperatingSystem.Version
    architecture   = $OperatingSystem.OSArchitecture
    domain_joined  = $PartOfDomain
    reported_domain = $ComputerSystem.Domain
    environment_mode = $EnvironmentMode
}

# ---------------------------------------------------------------------------
# Initialise result collections
# ---------------------------------------------------------------------------

$DomainInformation = $null
$DomainControllers = @()
$Users = @()
$Groups = @()
$ServiceAccounts = @()
$GPOs = @()
$PasswordPolicy = $null
$LockoutPolicy = $null
$KerberosInformation = $null
$DomainAdmins = @()
$EnterpriseAdmins = @()
$Findings = @()

# ---------------------------------------------------------------------------
# Active Directory assessment
# ---------------------------------------------------------------------------

if ($PartOfDomain -and $ADModuleAvailable) {

    Write-Host ""
    Write-Host "[*] Active Directory detected."

    Import-Module ActiveDirectory

    # -----------------------------------------------------------------------
    # Domain information
    # -----------------------------------------------------------------------

    Write-Host "[*] Collecting domain information..."

    $Domain = Get-ADDomain
    $Forest = Get-ADForest

    $DomainInformation = [PSCustomObject]@{
        domain_name        = $Domain.DNSRoot
        netbios_name       = $Domain.NetBIOSName
        domain_mode        = [string]$Domain.DomainMode
        forest_name        = $Forest.Name
        forest_mode        = [string]$Forest.ForestMode
        domain_sid         = [string]$Domain.DomainSID
        infrastructure_master = $Domain.InfrastructureMaster
        pdc_emulator       = $Domain.PDCEmulator
        rid_master         = $Domain.RIDMaster
    }

    $DomainControllers = @(
        Get-ADDomainController -Filter * |
        ForEach-Object {
            [PSCustomObject]@{
                name          = $_.Name
                hostname      = $_.HostName
                ipv4_address  = $_.IPv4Address
                site          = $_.Site
                operating_system = $_.OperatingSystem
                global_catalog = $_.IsGlobalCatalog
            }
        }
    )

    # -----------------------------------------------------------------------
    # Users
    # -----------------------------------------------------------------------

    Write-Host "[*] Collecting user accounts..."

    $Users = @(
        Get-ADUser -Filter * -Properties `
            Enabled,
            LastLogonDate,
            PasswordLastSet,
            PasswordNeverExpires,
            ServicePrincipalName,
            TrustedForDelegation |
        ForEach-Object {

            [PSCustomObject]@{
                sam_account_name      = $_.SamAccountName
                name                  = $_.Name
                enabled               = $_.Enabled
                distinguished_name    = $_.DistinguishedName
                last_logon            = Convert-DateSafe $_.LastLogonDate
                password_last_set     = Convert-DateSafe $_.PasswordLastSet
                password_never_expires = $_.PasswordNeverExpires
                has_spn               = ($null -ne $_.ServicePrincipalName -and
                                         $_.ServicePrincipalName.Count -gt 0)
                unconstrained_delegation = $_.TrustedForDelegation
            }
        }
    )

    # -----------------------------------------------------------------------
    # Groups
    # -----------------------------------------------------------------------

    Write-Host "[*] Collecting groups and membership..."

    $Groups = @(
        Get-ADGroup -Filter * |
        ForEach-Object {

            $Group = $_

            $Members = @()

            try {
                $Members = @(
                    Get-ADGroupMember -Identity $Group.DistinguishedName |
                    Select-Object -ExpandProperty SamAccountName
                )
            }
            catch {
                $Members = @()
            }

            [PSCustomObject]@{
                name               = $Group.Name
                sam_account_name   = $Group.SamAccountName
                group_scope        = [string]$Group.GroupScope
                group_category     = [string]$Group.GroupCategory
                distinguished_name = $Group.DistinguishedName
                members            = $Members
                member_count       = $Members.Count
            }
        }
    )

    # -----------------------------------------------------------------------
    # Service accounts
    # -----------------------------------------------------------------------

    Write-Host "[*] Identifying service accounts..."

    $ServiceAccounts = @(
        Get-ADUser -Filter * -Properties `
            ServicePrincipalName,
            PasswordNeverExpires,
            TrustedForDelegation,
            Enabled |
        Where-Object {

            $_.SamAccountName -match "svc" -or
            $_.Name -match "svc" -or
            $_.DistinguishedName -match "OU=Service Accounts" -or
            (
                $null -ne $_.ServicePrincipalName -and
                $_.ServicePrincipalName.Count -gt 0
            )
        } |
        ForEach-Object {

            [PSCustomObject]@{
                sam_account_name = $_.SamAccountName
                name             = $_.Name
                enabled          = $_.Enabled
                distinguished_name = $_.DistinguishedName
                password_never_expires = $_.PasswordNeverExpires
                unconstrained_delegation = $_.TrustedForDelegation
                service_principal_names = @($_.ServicePrincipalName)
            }
        }
    )

    # -----------------------------------------------------------------------
    # Password and lockout policy
    # -----------------------------------------------------------------------

    Write-Host "[*] Reading password and account lockout policy..."

    $Policy = Get-ADDefaultDomainPasswordPolicy

    $PasswordPolicy = [PSCustomObject]@{
        minimum_length      = $Policy.MinPasswordLength
        complexity_enabled  = $Policy.ComplexityEnabled
        password_history    = $Policy.PasswordHistoryCount
        minimum_password_age_days = $Policy.MinPasswordAge.TotalDays
        maximum_password_age_days = $Policy.MaxPasswordAge.TotalDays
        reversible_encryption = $Policy.ReversibleEncryptionEnabled
    }

    if ($Policy.LockoutThreshold -eq 0) {

        $LockoutPolicy = [PSCustomObject]@{
            configured               = $false
            status                   = "NOT CONFIGURED"
            threshold                = 0
            lockout_duration_minutes = 0
            observation_window_minutes = 0
        }
    }
    else {

        $LockoutPolicy = [PSCustomObject]@{
            configured               = $true
            status                   = "CONFIGURED"
            threshold                = $Policy.LockoutThreshold
            lockout_duration_minutes = $Policy.LockoutDuration.TotalMinutes
            observation_window_minutes = $Policy.LockoutObservationWindow.TotalMinutes
        }
    }

    # -----------------------------------------------------------------------
    # Kerberos encryption
    # -----------------------------------------------------------------------

    Write-Host "[*] Assessing Kerberos encryption configuration..."

    $KerberosUsers = @(
        Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes |
        Where-Object {
            $null -ne $_.'msDS-SupportedEncryptionTypes'
        } |
        ForEach-Object {
            [PSCustomObject]@{
                sam_account_name = $_.SamAccountName
                supported_encryption_types = $_.'msDS-SupportedEncryptionTypes'
            }
        }
    )

    $KerberosInformation = [PSCustomObject]@{
        assessment = "Per-account encryption attributes collected"
        accounts_with_explicit_encryption_configuration = $KerberosUsers
    }

    # -----------------------------------------------------------------------
    # Privileged administrators
    # -----------------------------------------------------------------------

    Write-Host "[*] Identifying privileged administrators..."

    try {
        $DomainAdmins = @(
            Get-ADGroupMember -Identity "Domain Admins" -Recursive |
            Select-Object -ExpandProperty SamAccountName -Unique
        )
    }
    catch {
        $DomainAdmins = @()
    }

    try {
        $EnterpriseAdmins = @(
            Get-ADGroupMember -Identity "Enterprise Admins" -Recursive |
            Select-Object -ExpandProperty SamAccountName -Unique
        )
    }
    catch {
        $EnterpriseAdmins = @()
    }

    # -----------------------------------------------------------------------
    # Group Policy
    # -----------------------------------------------------------------------

    if ($GPOModuleAvailable) {

        Write-Host "[*] Collecting Group Policy Objects..."

        Import-Module GroupPolicy

        $AllGPOs = Get-GPO -All

        $GPOs = @(
            $AllGPOs |
            ForEach-Object {

                [PSCustomObject]@{
                    display_name   = $_.DisplayName
                    id             = [string]$_.Id
                    gpo_status     = [string]$_.GpoStatus
                    creation_time  = Convert-DateSafe $_.CreationTime
                    modification_time = Convert-DateSafe $_.ModificationTime
                    owner          = $_.Owner
                }
            }
        )
    }
    else {

        Add-Finding `
            -Severity "medium" `
            -Title "Group Policy module unavailable" `
            -Evidence "The GroupPolicy PowerShell module is not installed." `
            -Recommendation "Perform GPO enumeration from a management workstation with RSAT Group Policy tools."
    }

    # -----------------------------------------------------------------------
    # Security findings
    # -----------------------------------------------------------------------

    $NeverExpireUsers = @(
        $Users |
        Where-Object {
            $_.password_never_expires -eq $true -and
            $_.enabled -eq $true
        }
    )

    if ($NeverExpireUsers.Count -gt 0) {
        Add-Finding `
            -Severity "high" `
            -Title "Enabled accounts with passwords that never expire" `
            -Evidence "$($NeverExpireUsers.Count) enabled account(s) have PasswordNeverExpires configured." `
            -Recommendation "Review password-expiration exceptions and migrate service identities to managed service accounts where possible."
    }

    if ($PasswordPolicy.minimum_length -lt 14) {
        Add-Finding `
            -Severity "high" `
            -Title "Domain password minimum length below MedDefense baseline" `
            -Evidence "Current minimum password length is $($PasswordPolicy.minimum_length)." `
            -Recommendation "Increase domain password minimum length to at least 14 characters after testing."
    }

    if (-not $PasswordPolicy.complexity_enabled) {
        Add-Finding `
            -Severity "high" `
            -Title "Password complexity disabled" `
            -Evidence "Domain password complexity is disabled." `
            -Recommendation "Enable appropriate password-policy controls through tested domain policy."
    }

    if (-not $LockoutPolicy.configured) {
        Add-Finding `
            -Severity "critical" `
            -Title "Account lockout policy not configured" `
            -Evidence "Lockout threshold is zero." `
            -Recommendation "Define a tested account lockout policy to reduce password-guessing attacks."
    }

    $UnconstrainedAccounts = @(
        $ServiceAccounts |
        Where-Object {
            $_.unconstrained_delegation -eq $true
        }
    )

    if ($UnconstrainedAccounts.Count -gt 0) {
        Add-Finding `
            -Severity "critical" `
            -Title "Service accounts configured for unconstrained delegation" `
            -Evidence "$($UnconstrainedAccounts.Count) service account(s) allow unconstrained delegation." `
            -Recommendation "Review and remove unconstrained delegation where it is not explicitly required."
    }

    if ($DomainAdmins.Count -gt 5) {
        Add-Finding `
            -Severity "high" `
            -Title "Large Domain Admin membership" `
            -Evidence "$($DomainAdmins.Count) accounts are members of Domain Admins." `
            -Recommendation "Apply least privilege and reduce standing Domain Admin membership."
    }
}
else {

    # -----------------------------------------------------------------------
    # Standalone Windows fallback
    # -----------------------------------------------------------------------

    Write-Host ""
    Write-Host "[!] Active Directory domain assessment unavailable."
    Write-Host "[!] Running safe standalone Windows baseline instead."

    if (-not $PartOfDomain) {

        Add-Finding `
            -Severity "medium" `
            -Title "Active Directory domain not available for assessment" `
            -Evidence "This computer is not joined to an Active Directory domain." `
            -Recommendation "Run this script against the MedDefense Windows Server 2022 / domain environment when available."
    }

    if (-not $ADModuleAvailable) {

        Add-Finding `
            -Severity "medium" `
            -Title "ActiveDirectory PowerShell module unavailable" `
            -Evidence "The ActiveDirectory module is not installed on this workstation." `
            -Recommendation "Use a domain management workstation with RSAT Active Directory PowerShell tools for the full assessment."
    }

    # Local accounts are useful evidence but must not be confused with AD users.

    Write-Host "[*] Collecting local Windows accounts..."

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {

        $Users = @(
            Get-LocalUser |
            ForEach-Object {

                [PSCustomObject]@{
                    name                   = $_.Name
                    enabled                = $_.Enabled
                    last_logon             = Convert-DateSafe $_.LastLogon
                    password_last_set      = Convert-DateSafe $_.PasswordLastSet
                    password_never_expires = $_.PasswordNeverExpires
                    scope                  = "local"
                }
            }
        )
    }

    Write-Host "[*] Collecting local Windows groups..."

    if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {

        $Groups = @(
            Get-LocalGroup |
            ForEach-Object {

                $Group = $_
                $Members = @()

                try {
                    $Members = @(
                        Get-LocalGroupMember -Group $Group.Name |
                        ForEach-Object {
                            $_.Name
                        }
                    )
                }
                catch {
                    $Members = @()
                }

                [PSCustomObject]@{
                    name         = $Group.Name
                    description  = $Group.Description
                    members      = $Members
                    member_count = $Members.Count
                    scope        = "local"
                }
            }
        )
    }

    $ServiceAccounts = @(
        $Users |
        Where-Object {
            $_.name -match "svc"
        }
    )

    $PasswordPolicy = [PSCustomObject]@{
        status = "NOT ASSESSED - Active Directory domain unavailable"
    }

    $LockoutPolicy = [PSCustomObject]@{
        status = "NOT ASSESSED - Active Directory domain unavailable"
    }

    $KerberosInformation = [PSCustomObject]@{
        status = "NOT ASSESSED - Active Directory domain unavailable"
    }
}

# ---------------------------------------------------------------------------
# Findings summary
# ---------------------------------------------------------------------------

$CriticalCount = @(
    $Findings |
    Where-Object {
        $_.severity -eq "critical"
    }
).Count

$HighCount = @(
    $Findings |
    Where-Object {
        $_.severity -eq "high"
    }
).Count

$MediumCount = @(
    $Findings |
    Where-Object {
        $_.severity -eq "medium"
    }
).Count

$PasswordNeverExpiresCount = @(
    $Users |
    Where-Object {
        $_.password_never_expires -eq $true
    }
).Count

$UnconstrainedServiceAccounts = @(
    $ServiceAccounts |
    Where-Object {
        $_.PSObject.Properties.Name -contains "unconstrained_delegation" -and
        $_.unconstrained_delegation -eq $true
    }
).Count

# ---------------------------------------------------------------------------
# Structured output
# ---------------------------------------------------------------------------

$Report = [ordered]@{
    task = "0 - Domain Reconnaissance"

    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")

    system_identity = $SystemIdentity

    domain_information = $DomainInformation

    domain_controllers = $DomainControllers

    users = $Users

    groups = $Groups

    service_accounts = $ServiceAccounts

    group_policy_objects = $GPOs

    password_policy = $PasswordPolicy

    account_lockout_policy = $LockoutPolicy

    kerberos = $KerberosInformation

    privileged_accounts = [ordered]@{
        domain_admins     = $DomainAdmins
        enterprise_admins = $EnterpriseAdmins
    }

    summary = [ordered]@{
        user_accounts                = $Users.Count
        password_never_expires       = $PasswordNeverExpiresCount
        service_accounts             = $ServiceAccounts.Count
        unconstrained_delegation     = $UnconstrainedServiceAccounts
        groups                       = $Groups.Count
        gpos                         = $GPOs.Count
        domain_admins                = $DomainAdmins.Count
        enterprise_admins            = $EnterpriseAdmins.Count
        security_findings            = $Findings.Count
        critical_findings            = $CriticalCount
        high_findings                = $HighCount
        medium_findings              = $MediumCount
    }

    findings = $Findings
}

$Report |
    ConvertTo-Json -Depth 12 |
    Set-Content -Path $OutputFile -Encoding UTF8

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Security Baseline"
Write-Host "=============================================="

if ($PartOfDomain -and $ADModuleAvailable) {

    Write-Host "Domain: $($DomainInformation.domain_name)"

    if ($DomainControllers.Count -gt 0) {
        Write-Host "DC: $($DomainControllers[0].hostname)"
    }

    Write-Host "User Accounts: $($Users.Count)"
    Write-Host "  Password Never Expires: $PasswordNeverExpiresCount"

    Write-Host "Service Accounts: $($ServiceAccounts.Count)"
    Write-Host "  Unconstrained delegation: $UnconstrainedServiceAccounts"

    Write-Host "GPOs: $($GPOs.Count)"

    Write-Host "Password Minimum Length: $($PasswordPolicy.minimum_length)"
    Write-Host "Complexity: $($PasswordPolicy.complexity_enabled)"
    Write-Host "Lockout Threshold: $($LockoutPolicy.threshold)"

    Write-Host "Domain Admins: $($DomainAdmins -join ', ')"
}
else {

    Write-Host "Environment: Standalone Windows"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Local Accounts: $($Users.Count)"
    Write-Host "Active Directory: NOT AVAILABLE"
    Write-Host "Domain settings: NOT ASSESSED"
}

Write-Host ""
Write-Host "Findings: $($Findings.Count) (Critical: $CriticalCount, High: $HighCount, Medium: $MediumCount)"
Write-Host "Report saved to: domain_baseline.json"