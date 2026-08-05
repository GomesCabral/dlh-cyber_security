# MedDefense Health Systems - Domain Reconnaissance
# Task 0 - Windows / Active Directory Security Baseline
#
# PURPOSE:
# Capture the current Windows and Active Directory security state before
# any hardening changes are applied.
#
# SAFETY:
# THIS SCRIPT IS READ-ONLY.
#
# It does NOT:
# - create, delete, enable or disable users
# - change passwords
# - modify Active Directory
# - modify Group Policy
# - modify Registry values
# - change Windows Firewall
# - change services
# - change audit policies
# - change Kerberos settings
#
# When Active Directory is unavailable, domain-specific controls are
# explicitly reported as NOT ASSESSED.
#
# Output:
# domain_baseline.json

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputFile = Join-Path $ScriptDirectory "domain_baseline.json"

$Findings = @()

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Get-SafeProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $Property = $Object.PSObject.Properties[$PropertyName]

    if ($null -eq $Property) {
        return $null
    }

    return $Property.Value
}

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

function Add-SecurityFinding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("critical", "high", "medium")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation
    )

    $script:Findings += [PSCustomObject]@{
        severity       = $Severity
        title          = $Title
        evidence       = $Evidence
        recommendation = $Recommendation
    }
}

function Convert-KerberosEncryptionTypes {
    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    try {
        $Mask = [int]$Value
    }
    catch {
        return @()
    }

    $Types = @()

    if (($Mask -band 1) -ne 0) {
        $Types += "DES_CRC"
    }

    if (($Mask -band 2) -ne 0) {
        $Types += "DES_MD5"
    }

    if (($Mask -band 4) -ne 0) {
        $Types += "RC4"
    }

    if (($Mask -band 8) -ne 0) {
        $Types += "AES128"
    }

    if (($Mask -band 16) -ne 0) {
        $Types += "AES256"
    }

    return $Types
}

# ---------------------------------------------------------------------------
# Environment identification
# ---------------------------------------------------------------------------

Write-Host "[*] Starting MedDefense Domain Reconnaissance..."
Write-Host "[*] Mode: READ ONLY"
Write-Host ""

$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain

$ADModuleAvailable = [bool](
    Get-Module -ListAvailable -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module -ListAvailable -Name GroupPolicy
)

if ($PartOfDomain) {
    $EnvironmentMode = "DOMAIN_JOINED"
}
else {
    $EnvironmentMode = "STANDALONE_WINDOWS"
}

$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$SystemIdentity = [PSCustomObject]@{
    computer_name     = $env:COMPUTERNAME
    current_user      = $CurrentIdentity.Name
    operating_system  = $OperatingSystem.Caption
    os_version        = $OperatingSystem.Version
    os_build           = $OperatingSystem.BuildNumber
    architecture       = $OperatingSystem.OSArchitecture
    manufacturer       = $ComputerSystem.Manufacturer
    model              = $ComputerSystem.Model
    domain_joined      = $PartOfDomain
    reported_domain    = $ComputerSystem.Domain
    environment_mode   = $EnvironmentMode
    ad_module          = $ADModuleAvailable
    group_policy_module = $GPOModuleAvailable
}

Write-Host "[*] Environment detection:"
Write-Host "    Computer: $env:COMPUTERNAME"
Write-Host "    Domain joined: $PartOfDomain"
Write-Host "    Reported domain: $($ComputerSystem.Domain)"
Write-Host "    ActiveDirectory module: $ADModuleAvailable"
Write-Host "    GroupPolicy module: $GPOModuleAvailable"
Write-Host ""

# ---------------------------------------------------------------------------
# Initialise evidence collections
# ---------------------------------------------------------------------------

$DomainInformation = [PSCustomObject]@{
    status = "NOT ASSESSED"
    reason = "Active Directory domain unavailable"
}

$DomainControllers = @()
$Users = @()
$Groups = @()
$ServiceAccounts = @()
$GPOs = @()

$PasswordPolicy = [PSCustomObject]@{
    status = "NOT ASSESSED"
    reason = "Active Directory domain unavailable"
}

$LockoutPolicy = [PSCustomObject]@{
    status = "NOT ASSESSED"
    reason = "Active Directory domain unavailable"
}

$KerberosInformation = [PSCustomObject]@{
    status = "NOT ASSESSED"
    reason = "Active Directory domain unavailable"
}

$DomainAdmins = @()
$EnterpriseAdmins = @()

$AssessmentScope = "LOCAL_WINDOWS_ONLY"

# ===========================================================================
# ACTIVE DIRECTORY MODE
# ===========================================================================

if ($PartOfDomain -and $ADModuleAvailable) {

    Write-Host "[*] Active Directory environment detected."
    Write-Host "[*] Collecting domain security baseline..."

    Import-Module ActiveDirectory

    $AssessmentScope = "ACTIVE_DIRECTORY"

    # -----------------------------------------------------------------------
    # Domain and forest
    # -----------------------------------------------------------------------

    $Domain = Get-ADDomain
    $Forest = Get-ADForest

    $DomainInformation = [PSCustomObject]@{
        status                = "ASSESSED"
        domain_name           = $Domain.DNSRoot
        netbios_name          = $Domain.NetBIOSName
        domain_mode           = [string]$Domain.DomainMode
        forest_name           = $Forest.Name
        forest_mode           = [string]$Forest.ForestMode
        domain_sid            = [string]$Domain.DomainSID
        pdc_emulator          = $Domain.PDCEmulator
        rid_master            = $Domain.RIDMaster
        infrastructure_master = $Domain.InfrastructureMaster
    }

    # -----------------------------------------------------------------------
    # Domain Controllers
    # -----------------------------------------------------------------------

    Write-Host "[*] Enumerating Domain Controllers..."

    $DomainControllers = @(
        Get-ADDomainController -Filter * |
        ForEach-Object {

            [PSCustomObject]@{
                name             = $_.Name
                hostname         = $_.HostName
                ipv4_address     = $_.IPv4Address
                site             = $_.Site
                operating_system = $_.OperatingSystem
                global_catalog   = $_.IsGlobalCatalog
            }
        }
    )

    # -----------------------------------------------------------------------
    # Users
    # -----------------------------------------------------------------------

    Write-Host "[*] Enumerating domain user accounts..."

    $ADUsers = @(
        Get-ADUser `
            -Filter * `
            -Properties `
                Enabled,
                LastLogonDate,
                PasswordLastSet,
                PasswordNeverExpires,
                ServicePrincipalName,
                TrustedForDelegation,
                msDS-SupportedEncryptionTypes
    )

    $Users = @(
        $ADUsers |
        ForEach-Object {

            [PSCustomObject]@{
                name                     = $_.Name
                sam_account_name         = $_.SamAccountName
                enabled                  = $_.Enabled
                distinguished_name       = $_.DistinguishedName
                last_logon               = Convert-DateSafe $_.LastLogonDate
                password_last_set        = Convert-DateSafe $_.PasswordLastSet
                password_never_expires   = $_.PasswordNeverExpires
                has_spn                  = (@($_.ServicePrincipalName).Count -gt 0)
                unconstrained_delegation = $_.TrustedForDelegation
                kerberos_encryption      = @(
                    Convert-KerberosEncryptionTypes `
                        $_.'msDS-SupportedEncryptionTypes'
                )
            }
        }
    )

    # -----------------------------------------------------------------------
    # Groups and members
    # -----------------------------------------------------------------------

    Write-Host "[*] Enumerating groups and membership..."

    $Groups = @(
        Get-ADGroup -Filter * |
        ForEach-Object {

            $CurrentGroup = $_

            $Members = @()

            try {
                $Members = @(
                    Get-ADGroupMember `
                        -Identity $CurrentGroup.DistinguishedName |
                    ForEach-Object {
                        $_.SamAccountName
                    }
                )
            }
            catch {
                $Members = @(
                    "MEMBERSHIP_QUERY_FAILED"
                )
            }

            [PSCustomObject]@{
                name               = $CurrentGroup.Name
                sam_account_name   = $CurrentGroup.SamAccountName
                group_scope        = [string]$CurrentGroup.GroupScope
                group_category     = [string]$CurrentGroup.GroupCategory
                distinguished_name = $CurrentGroup.DistinguishedName
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
        $ADUsers |
        Where-Object {
            $_.SamAccountName -match "(?i)svc" -or
            $_.Name -match "(?i)svc" -or
            $_.DistinguishedName -match "(?i)OU=Service Accounts" -or
            @($_.ServicePrincipalName).Count -gt 0
        } |
        ForEach-Object {

            [PSCustomObject]@{
                name                     = $_.Name
                sam_account_name         = $_.SamAccountName
                enabled                  = $_.Enabled
                distinguished_name       = $_.DistinguishedName
                password_never_expires   = $_.PasswordNeverExpires
                unconstrained_delegation = $_.TrustedForDelegation
                service_principal_names  = @($_.ServicePrincipalName)
                kerberos_encryption      = @(
                    Convert-KerberosEncryptionTypes `
                        $_.'msDS-SupportedEncryptionTypes'
                )
            }
        }
    )

    # -----------------------------------------------------------------------
    # Password and account lockout policy
    # -----------------------------------------------------------------------

    Write-Host "[*] Reading domain password policy..."

    $Policy = Get-ADDefaultDomainPasswordPolicy

    $PasswordPolicy = [PSCustomObject]@{
        status                    = "ASSESSED"
        minimum_length            = $Policy.MinPasswordLength
        complexity_enabled        = $Policy.ComplexityEnabled
        password_history          = $Policy.PasswordHistoryCount
        minimum_password_age_days = $Policy.MinPasswordAge.TotalDays
        maximum_password_age_days = $Policy.MaxPasswordAge.TotalDays
        reversible_encryption     = $Policy.ReversibleEncryptionEnabled
    }

    if ($Policy.LockoutThreshold -eq 0) {

        $LockoutPolicy = [PSCustomObject]@{
            status                     = "NOT CONFIGURED"
            configured                 = $false
            threshold                  = 0
            lockout_duration_minutes   = 0
            observation_window_minutes = 0
        }
    }
    else {

        $LockoutPolicy = [PSCustomObject]@{
            status                     = "CONFIGURED"
            configured                 = $true
            threshold                  = $Policy.LockoutThreshold
            lockout_duration_minutes   = $Policy.LockoutDuration.TotalMinutes
            observation_window_minutes = $Policy.LockoutObservationWindow.TotalMinutes
        }
    }

    # -----------------------------------------------------------------------
    # Kerberos encryption
    # -----------------------------------------------------------------------

    Write-Host "[*] Assessing Kerberos encryption types..."

    $KerberosAccountEvidence = @(
        $ADUsers |
        Where-Object {
            $null -ne $_.'msDS-SupportedEncryptionTypes'
        } |
        ForEach-Object {

            [PSCustomObject]@{
                account = $_.SamAccountName
                raw_value = $_.'msDS-SupportedEncryptionTypes'
                encryption_types = @(
                    Convert-KerberosEncryptionTypes `
                        $_.'msDS-SupportedEncryptionTypes'
                )
            }
        }
    )

    $ObservedKerberosTypes = @(
        $KerberosAccountEvidence |
        ForEach-Object {
            $_.encryption_types
        } |
        Sort-Object -Unique
    )

    $KerberosInformation = [PSCustomObject]@{
        status                    = "ASSESSED"
        observed_encryption_types = $ObservedKerberosTypes
        account_evidence          = $KerberosAccountEvidence
        note = "Encryption types are derived from explicit AD account encryption attributes."
    }

    # -----------------------------------------------------------------------
    # Privileged groups
    # -----------------------------------------------------------------------

    Write-Host "[*] Enumerating privileged administrators..."

    try {
        $DomainAdmins = @(
            Get-ADGroupMember `
                -Identity "Domain Admins" `
                -Recursive |
            Select-Object `
                -ExpandProperty SamAccountName `
                -Unique
        )
    }
    catch {
        $DomainAdmins = @(
            "QUERY_FAILED"
        )
    }

    try {
        $EnterpriseAdmins = @(
            Get-ADGroupMember `
                -Identity "Enterprise Admins" `
                -Recursive |
            Select-Object `
                -ExpandProperty SamAccountName `
                -Unique
        )
    }
    catch {
        $EnterpriseAdmins = @(
            "QUERY_FAILED"
        )
    }

    # -----------------------------------------------------------------------
    # Group Policy Objects and links
    # -----------------------------------------------------------------------

    if ($GPOModuleAvailable) {

        Write-Host "[*] Enumerating Group Policy Objects..."

        Import-Module GroupPolicy

        $AllGPOs = @(Get-GPO -All)

        foreach ($CurrentGPO in $AllGPOs) {

            $Links = @()

            # Domain-level links
            try {
                $DomainInheritance = Get-GPInheritance `
                    -Target $Domain.DistinguishedName

                foreach ($Link in @($DomainInheritance.GpoLinks)) {
                    if ($Link.DisplayName -eq $CurrentGPO.DisplayName) {
                        $Links += [PSCustomObject]@{
                            target = $Domain.DistinguishedName
                            type   = "DOMAIN"
                            enabled = $Link.Enabled
                            enforced = $Link.Enforced
                        }
                    }
                }
            }
            catch {
                # Read-only query failure; continue.
            }

            # OU-level links
            $OUs = @(
                Get-ADOrganizationalUnit `
                    -Filter * `
                    -Properties DistinguishedName
            )

            foreach ($OU in $OUs) {

                try {
                    $Inheritance = Get-GPInheritance `
                        -Target $OU.DistinguishedName

                    foreach ($Link in @($Inheritance.GpoLinks)) {

                        if ($Link.DisplayName -eq $CurrentGPO.DisplayName) {

                            $Links += [PSCustomObject]@{
                                target = $OU.DistinguishedName
                                type   = "OU"
                                enabled = $Link.Enabled
                                enforced = $Link.Enforced
                            }
                        }
                    }
                }
                catch {
                    # Read-only query failure; continue.
                }
            }

            $GPOs += [PSCustomObject]@{
                display_name      = $CurrentGPO.DisplayName
                id                = [string]$CurrentGPO.Id
                status            = [string]$CurrentGPO.GpoStatus
                owner             = $CurrentGPO.Owner
                creation_time     = Convert-DateSafe $CurrentGPO.CreationTime
                modification_time = Convert-DateSafe $CurrentGPO.ModificationTime
                links             = $Links
                linked            = ($Links.Count -gt 0)
            }
        }
    }
    else {

        Add-SecurityFinding `
            -Severity "medium" `
            -Title "Group Policy module unavailable" `
            -Evidence "The GroupPolicy PowerShell module is unavailable." `
            -Recommendation "Run GPO enumeration from a system with RSAT Group Policy Management installed."
    }

    # -----------------------------------------------------------------------
    # Active Directory security findings
    # -----------------------------------------------------------------------

    $NeverExpire = @(
        $Users |
        Where-Object {
            $_.enabled -eq $true -and
            $_.password_never_expires -eq $true
        }
    )

    if ($NeverExpire.Count -gt 0) {

        Add-SecurityFinding `
            -Severity "high" `
            -Title "Enabled accounts with passwords that never expire" `
            -Evidence "$($NeverExpire.Count) enabled account(s) have PasswordNeverExpires enabled." `
            -Recommendation "Review exceptions and use managed service accounts where appropriate."
    }

    if ($PasswordPolicy.minimum_length -lt 14) {

        Add-SecurityFinding `
            -Severity "high" `
            -Title "Weak domain minimum password length" `
            -Evidence "Minimum password length is $($PasswordPolicy.minimum_length)." `
            -Recommendation "Increase the minimum password length to the MedDefense target after testing."
    }

    if (-not $PasswordPolicy.complexity_enabled) {

        Add-SecurityFinding `
            -Severity "high" `
            -Title "Domain password complexity disabled" `
            -Evidence "Password complexity is disabled." `
            -Recommendation "Enable an appropriate tested domain password policy."
    }

    if (-not $LockoutPolicy.configured) {

        Add-SecurityFinding `
            -Severity "critical" `
            -Title "Account lockout policy not configured" `
            -Evidence "The current domain lockout threshold is zero." `
            -Recommendation "Configure account lockout to reduce password guessing and credential attacks."
    }

    $UnconstrainedDelegation = @(
        $ServiceAccounts |
        Where-Object {
            $_.unconstrained_delegation -eq $true
        }
    )

    if ($UnconstrainedDelegation.Count -gt 0) {

        Add-SecurityFinding `
            -Severity "critical" `
            -Title "Service accounts using unconstrained delegation" `
            -Evidence "$($UnconstrainedDelegation.Count) service account(s) use unconstrained delegation." `
            -Recommendation "Remove unconstrained delegation unless explicitly required and approved."
    }

    if ($DomainAdmins.Count -gt 5) {

        Add-SecurityFinding `
            -Severity "high" `
            -Title "Excessive Domain Admin membership" `
            -Evidence "$($DomainAdmins.Count) accounts are members of Domain Admins." `
            -Recommendation "Apply least privilege and minimize standing Domain Admin membership."
    }

    if ($ObservedKerberosTypes -contains "RC4") {

        Add-SecurityFinding `
            -Severity "high" `
            -Title "RC4 observed in Kerberos encryption configuration" `
            -Evidence "One or more explicitly configured AD accounts support RC4." `
            -Recommendation "Review RC4 dependencies and migrate supported identities to AES Kerberos encryption."
    }
}

# ===========================================================================
# STANDALONE WINDOWS MODE
# ===========================================================================

else {

    Write-Host "[!] Active Directory environment unavailable."
    Write-Host "[*] Performing safe standalone Windows identity baseline."
    Write-Host ""

    if (-not $PartOfDomain) {

        Add-SecurityFinding `
            -Severity "medium" `
            -Title "Active Directory domain unavailable for assessment" `
            -Evidence "The current computer belongs to $($ComputerSystem.Domain) and is not joined to an Active Directory domain." `
            -Recommendation "Perform domain-specific assessment against the MedDefense Domain Controller when available."
    }

    if (-not $ADModuleAvailable) {

        Add-SecurityFinding `
            -Severity "medium" `
            -Title "ActiveDirectory PowerShell module unavailable" `
            -Evidence "The ActiveDirectory PowerShell module is not installed on this workstation." `
            -Recommendation "Use RSAT Active Directory tools when assessing an Active Directory environment."
    }

    # -----------------------------------------------------------------------
    # Local users
    # -----------------------------------------------------------------------

    Write-Host "[*] Enumerating local user accounts..."

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {

        $Users = @(
            Get-LocalUser |
            ForEach-Object {

                $LocalUser = $_

                $PasswordExpires = Get-SafeProperty `
                    -Object $LocalUser `
                    -PropertyName "PasswordExpires"

                $PasswordNeverExpires = $null

                if ($null -ne $PasswordExpires) {
                    $PasswordNeverExpires = $false
                }

                [PSCustomObject]@{
                    name                   = Get-SafeProperty $LocalUser "Name"
                    enabled                = Get-SafeProperty $LocalUser "Enabled"
                    last_logon             = Convert-DateSafe (
                        Get-SafeProperty $LocalUser "LastLogon"
                    )
                    password_last_set      = Convert-DateSafe (
                        Get-SafeProperty $LocalUser "PasswordLastSet"
                    )
                    password_expires       = Convert-DateSafe $PasswordExpires
                    password_never_expires = $PasswordNeverExpires
                    scope                  = "LOCAL"
                }
            }
        )
    }

    # -----------------------------------------------------------------------
    # Local groups
    # -----------------------------------------------------------------------

    Write-Host "[*] Enumerating local groups and members..."

    if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {

        $Groups = @(
            Get-LocalGroup |
            ForEach-Object {

                $LocalGroup = $_
                $Members = @()

                try {
                    $Members = @(
                        Get-LocalGroupMember `
                            -Group $LocalGroup.Name `
                            -ErrorAction Stop |
                        ForEach-Object {
                            $_.Name
                        }
                    )
                }
                catch {
                    $Members = @(
                        "MEMBERSHIP_QUERY_UNAVAILABLE"
                    )
                }

                [PSCustomObject]@{
                    name         = $LocalGroup.Name
                    description  = $LocalGroup.Description
                    members      = $Members
                    member_count = $Members.Count
                    scope        = "LOCAL"
                }
            }
        )
    }

    # -----------------------------------------------------------------------
    # Local service-account-like identities
    # -----------------------------------------------------------------------

    $ServiceAccounts = @(
        $Users |
        Where-Object {
            $_.name -match "(?i)svc"
        }
    )

    $DomainInformation = [PSCustomObject]@{
        status = "NOT ASSESSED"
        reason = "Computer is not joined to an Active Directory domain."
    }

    $PasswordPolicy = [PSCustomObject]@{
        status = "NOT ASSESSED"
        reason = "Domain password policy requires Active Directory."
    }

    $LockoutPolicy = [PSCustomObject]@{
        status = "NOT ASSESSED"
        reason = "Domain account lockout policy requires Active Directory."
    }

    $KerberosInformation = [PSCustomObject]@{
        status = "NOT ASSESSED"
        reason = "Domain Kerberos configuration requires Active Directory."
    }
}

# ---------------------------------------------------------------------------
# Summary calculations
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

        $Property = $_.PSObject.Properties["password_never_expires"]

        $null -ne $Property -and
        $Property.Value -eq $true
    }
).Count

$UnconstrainedDelegationCount = @(
    $ServiceAccounts |
    Where-Object {

        $Property = $_.PSObject.Properties["unconstrained_delegation"]

        $null -ne $Property -and
        $Property.Value -eq $true
    }
).Count

# ---------------------------------------------------------------------------
# Build structured report
# ---------------------------------------------------------------------------

$Report = [ordered]@{
    task = "0 - Domain Reconnaissance"

    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")

    assessment_scope = $AssessmentScope

    safety = [ordered]@{
        mode      = "READ_ONLY"
        modified_system = $false
    }

    system_identity = $SystemIdentity

    domain_information = $DomainInformation

    domain_controllers = $DomainControllers

    user_accounts = $Users

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
        user_accounts             = $Users.Count
        password_never_expires    = $PasswordNeverExpiresCount
        service_accounts          = $ServiceAccounts.Count
        unconstrained_delegation  = $UnconstrainedDelegationCount
        groups                    = $Groups.Count
        gpos                      = $GPOs.Count
        domain_controllers        = $DomainControllers.Count
        domain_admins             = $DomainAdmins.Count
        enterprise_admins         = $EnterpriseAdmins.Count
        security_findings         = $Findings.Count
        critical_findings         = $CriticalCount
        high_findings             = $HighCount
        medium_findings           = $MediumCount
    }

    findings = $Findings
}

# ---------------------------------------------------------------------------
# Save JSON
# ---------------------------------------------------------------------------

$Json = $Report | ConvertTo-Json -Depth 15

# UTF-8 JSON output.
[System.IO.File]::WriteAllText(
    $OutputFile,
    $Json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Domain Reconnaissance Summary"
Write-Host "=============================================="

if ($AssessmentScope -eq "ACTIVE_DIRECTORY") {

    Write-Host "Domain: $($DomainInformation.domain_name)"

    if ($DomainControllers.Count -gt 0) {
        Write-Host "DC: $($DomainControllers[0].hostname)"
    }

    Write-Host "User Accounts: $($Users.Count)"
    Write-Host "  Password Never Expires: $PasswordNeverExpiresCount"

    Write-Host "Service Accounts: $($ServiceAccounts.Count)"
    Write-Host "  Unconstrained delegation: $UnconstrainedDelegationCount"

    Write-Host "GPOs: $($GPOs.Count)"

    Write-Host "Password Minimum Length: $($PasswordPolicy.minimum_length)"
    Write-Host "Complexity: $($PasswordPolicy.complexity_enabled)"
    Write-Host "Lockout Threshold: $($LockoutPolicy.threshold)"

    if ($KerberosInformation.observed_encryption_types.Count -gt 0) {
        Write-Host "Kerberos: $($KerberosInformation.observed_encryption_types -join ', ')"
    }
    else {
        Write-Host "Kerberos: No explicit encryption types observed"
    }

    Write-Host "Domain Admins: $($DomainAdmins -join ', ')"
}
else {

    Write-Host "Environment: Standalone Windows"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Domain: NOT ASSESSED"
    Write-Host "Active Directory: NOT AVAILABLE"
    Write-Host "Local User Accounts: $($Users.Count)"
    Write-Host "Local Groups: $($Groups.Count)"
    Write-Host "Domain Password Policy: NOT ASSESSED"
    Write-Host "Kerberos: NOT ASSESSED"
}

Write-Host ""
Write-Host "Findings: $($Findings.Count) (Critical: $CriticalCount, High: $HighCount, Medium: $MediumCount)"
Write-Host "Report saved to: domain_baseline.json"