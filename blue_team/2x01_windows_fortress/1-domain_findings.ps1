# MedDefense Health Systems
# Task: 1 - Domain Risk Findings Extractor
# Script: 1-domain_findings.ps1
# Author: Pedro Cabral
# Purpose: Produce an actionable Windows and Active Directory security findings inventory.
# Safety: READ-ONLY. This script does not modify Windows or Active Directory security configuration.
# Output: domain_security_findings.json
#
# Target domain:
# meddefense.local
#
# Required areas:
# - PasswordNeverExpires
# - PasswordLastSet
# - MemberOf
# - privileged groups
# - stale computer objects
# - password and lockout policy
# - Kerberos DES/RC4
# - service accounts containing svc
# - TrustedForDelegation
# - UseDESKeyOnly
# - interactive logon
# - Advanced Audit Policy
# - PowerShell Script Block Logging
# - Sysmon readiness
# - Group Policy security posture
#
# Every finding contains:
# id
# severity
# category
# asset
# evidence
# risk
# recommended_remediation
# mapped_task

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputFile = Join-Path $ScriptDirectory "domain_security_findings.json"

$TargetDomain = "meddefense.local"

$Findings = @()
$FindingCounter = 0

# ===========================================================================
# Helper functions
# ===========================================================================

function Add-Finding {

    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("critical", "high", "medium")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Asset,

        [Parameter(Mandatory = $true)]
        [string]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Risk,

        [Parameter(Mandatory = $true)]
        [string]$RecommendedRemediation,

        [Parameter(Mandatory = $true)]
        [string]$MappedTask
    )

    $script:FindingCounter++

    $FindingId = "WIN-{0:D3}" -f $script:FindingCounter

    $script:Findings += [PSCustomObject]@{
        id                      = $FindingId
        severity                = $Severity
        category                = $Category
        asset                   = $Asset
        evidence                = $Evidence
        risk                    = $Risk
        recommended_remediation = $RecommendedRemediation
        mapped_task             = $MappedTask
    }
}


function Add-NotAssessedFinding {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$MappedTask
    )

    Add-Finding `
        -Severity "medium" `
        -Category $Category `
        -Asset $TargetDomain `
        -Evidence "NOT_ASSESSED: $Reason" `
        -Risk "The security state of this domain control cannot be verified from the current standalone Windows workstation." `
        -RecommendedRemediation "Re-run this assessment against the MedDefense domain from a Domain Controller or an authorized workstation with RSAT." `
        -MappedTask $MappedTask
}


function Test-ServiceAccount {

    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    # Service account identification:
    # - account name containing svc
    # - display name containing svc
    # - account in Service Accounts OU
    # - account with Service Principal Name (SPN)

    if ($User.SamAccountName -match "(?i)svc") {
        return $true
    }

    if ($User.Name -match "(?i)svc") {
        return $true
    }

    if ($User.DistinguishedName -match "(?i)OU=Service Accounts") {
        return $true
    }

    if (@($User.ServicePrincipalName).Count -gt 0) {
        return $true
    }

    return $false
}


function Get-MemberOf {

    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    try {

        $MemberOf = @(
            Get-ADPrincipalGroupMembership `
                -Identity $User `
                -ErrorAction Stop |
            Select-Object -ExpandProperty Name
        )

        return $MemberOf
    }
    catch {

        return @()
    }
}


function Convert-DateSafe {

    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return "NEVER"
    }

    try {
        return ([datetime]$Value).ToString("o")
    }
    catch {
        return [string]$Value
    }
}


function Get-AuditPolicyText {

    try {

        return (
            auditpol.exe /get /category:* 2>$null |
            Out-String
        )
    }
    catch {

        return ""
    }
}


function Test-InteractiveLogonVisibility {

    # This is a READ-ONLY assessment of interactive logon policy.
    #
    # Security concepts checked:
    # - interactive logon
    # - Allow log on locally
    # - Allow log on through Remote Desktop Services
    # - Deny log on locally
    # - Deny log on through Remote Desktop Services
    #
    # secedit /export does NOT change the security policy.
    # It only exports the current policy to a temporary file.

    $TemporaryPolicy = Join-Path `
        $env:TEMP `
        "meddefense-security-policy.inf"

    $Result = [ordered]@{
        available                       = $false
        interactive_logon               = "NOT_ASSESSED"
        local_logon_rule                = $null
        remote_interactive_logon_rule   = $null
        deny_local_logon_rule           = $null
        deny_remote_interactive_rule    = $null
    }

    try {

        secedit.exe `
            /export `
            /cfg $TemporaryPolicy `
            /quiet |
        Out-Null

        if (Test-Path $TemporaryPolicy) {

            $PolicyText = Get-Content `
                $TemporaryPolicy `
                -ErrorAction SilentlyContinue

            $Result.available = $true

            $Result.local_logon_rule = (
                $PolicyText |
                Select-String `
                    -Pattern "^SeInteractiveLogonRight" |
                Select-Object -First 1
            ).Line

            $Result.remote_interactive_logon_rule = (
                $PolicyText |
                Select-String `
                    -Pattern "^SeRemoteInteractiveLogonRight" |
                Select-Object -First 1
            ).Line

            $Result.deny_local_logon_rule = (
                $PolicyText |
                Select-String `
                    -Pattern "^SeDenyInteractiveLogonRight" |
                Select-Object -First 1
            ).Line

            $Result.deny_remote_interactive_rule = (
                $PolicyText |
                Select-String `
                    -Pattern "^SeDenyRemoteInteractiveLogonRight" |
                Select-Object -First 1
            ).Line

            $Result.interactive_logon = "REVIEW_REQUIRED"
        }
    }
    catch {

        $Result.interactive_logon = "NOT_ASSESSED"
    }
    finally {

        Remove-Item `
            $TemporaryPolicy `
            -Force `
            -ErrorAction SilentlyContinue
    }

    return [PSCustomObject]$Result
}


# ===========================================================================
# Environment detection
# ===========================================================================

Write-Host "[*] MedDefense Domain Risk Findings Extractor"
Write-Host "[*] Target domain: $TargetDomain"
Write-Host "[*] Mode: READ ONLY"
Write-Host ""

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain

$ADModuleAvailable = [bool](
    Get-Module `
        -ListAvailable `
        -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module `
        -ListAvailable `
        -Name GroupPolicy
)

$AssessmentMode = "STANDALONE_WINDOWS"

if ($PartOfDomain -and $ADModuleAvailable) {
    $AssessmentMode = "ACTIVE_DIRECTORY"
}

Write-Host "[*] Environment:"
Write-Host "    Computer: $env:COMPUTERNAME"
Write-Host "    Domain joined: $PartOfDomain"
Write-Host "    Reported domain: $($ComputerSystem.Domain)"
Write-Host "    ActiveDirectory module: $ADModuleAvailable"
Write-Host "    GroupPolicy module: $GPOModuleAvailable"
Write-Host ""


# ===========================================================================
# ACTIVE DIRECTORY MODE
# ===========================================================================

if ($AssessmentMode -eq "ACTIVE_DIRECTORY") {

    Import-Module ActiveDirectory

    $Domain = Get-ADDomain
    $DomainName = $Domain.DNSRoot

    Write-Host "[*] Auditing Active Directory domain: $DomainName"
    Write-Host ""

    # -----------------------------------------------------------------------
    # Collect all users once
    # -----------------------------------------------------------------------

    $AllUsers = @(
        Get-ADUser `
            -Filter * `
            -Properties `
                Enabled,
                PasswordNeverExpires,
                PasswordLastSet,
                LastLogonDate,
                MemberOf,
                ServicePrincipalName,
                TrustedForDelegation,
                UseDESKeyOnly,
                UserAccountControl,
                DistinguishedName
    )

    # =======================================================================
    # PasswordNeverExpires accounts
    # =======================================================================

    Write-Host "[*] Checking PasswordNeverExpires accounts..."

    $PasswordNeverExpiresAccounts = @(
        $AllUsers |
        Where-Object {
            $_.PasswordNeverExpires -eq $true
        }
    )

    foreach ($User in $PasswordNeverExpiresAccounts) {

        $MemberOf = @(
            Get-MemberOf -User $User
        )

        $IsServiceAccount = Test-ServiceAccount `
            -User $User

        $EvidenceObject = [ordered]@{
            Account              = $User.SamAccountName
            Enabled              = $User.Enabled
            PasswordNeverExpires = $User.PasswordNeverExpires
            PasswordLastSet      = Convert-DateSafe $User.PasswordLastSet
            MemberOf             = $MemberOf
            ServiceAccount       = $IsServiceAccount
        }

        $Evidence = (
            $EvidenceObject |
            ConvertTo-Json `
                -Compress `
                -Depth 5
        )

        Add-Finding `
            -Severity "high" `
            -Category "PasswordNeverExpires" `
            -Asset $User.SamAccountName `
            -Evidence $Evidence `
            -Risk "Long-lived credentials increase exposure to credential theft, password cracking and persistence." `
            -RecommendedRemediation "Remove unnecessary PasswordNeverExpires settings and migrate eligible service identities to gMSA." `
            -MappedTask "Password policy and service account hardening"
    }


    # =======================================================================
    # Disabled accounts in privileged groups
    # =======================================================================

    Write-Host "[*] Checking disabled accounts in privileged groups..."

    $PrivilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "G_IT_Admins"
    )

    foreach ($GroupName in $PrivilegedGroups) {

        try {

            $GroupMembers = @(
                Get-ADGroupMember `
                    -Identity $GroupName `
                    -Recursive `
                    -ErrorAction Stop
            )
        }
        catch {

            $GroupMembers = @()
        }

        foreach ($Member in $GroupMembers) {

            if ($Member.objectClass -ne "user") {
                continue
            }

            try {

                $PrivilegedUser = Get-ADUser `
                    -Identity $Member.DistinguishedName `
                    -Properties Enabled `
                    -ErrorAction Stop
            }
            catch {

                continue
            }

            if (-not $PrivilegedUser.Enabled) {

                Add-Finding `
                    -Severity "high" `
                    -Category "Disabled Privileged Account" `
                    -Asset $PrivilegedUser.SamAccountName `
                    -Evidence "Enabled=False; MemberOf=$GroupName" `
                    -Risk "Dormant privileged identities retain unnecessary administrative access and may be re-enabled or abused." `
                    -RecommendedRemediation "Remove disabled accounts from privileged groups and review them for approved deletion." `
                    -MappedTask "Privileged access and stale object cleanup"
            }
        }
    }


    # =======================================================================
    # Stale computers - 90+ days
    # =======================================================================

    Write-Host "[*] Checking stale computer objects..."

    $StaleCutoff = (Get-Date).AddDays(-90)

    $StaleComputers = @(
        Get-ADComputer `
            -Filter * `
            -Properties `
                LastLogonDate,
                Enabled |
        Where-Object {

            $null -eq $_.LastLogonDate -or
            $_.LastLogonDate -lt $StaleCutoff
        }
    )

    if ($StaleComputers.Count -gt 0) {

        $StaleComputerNames = @(
            $StaleComputers |
            Select-Object -ExpandProperty Name
        )

        Add-Finding `
            -Severity "medium" `
            -Category "Stale Computer Objects" `
            -Asset $DomainName `
            -Evidence "$($StaleComputers.Count) computer object(s) have no logon/authentication activity for 90+ days: $($StaleComputerNames -join ', ')." `
            -Risk "Stale computer objects increase attack surface and may retain valid machine credentials and permissions." `
            -RecommendedRemediation "Investigate, disable and later remove confirmed unused computer objects." `
            -MappedTask "Stale object cleanup"
    }


    # =======================================================================
    # Password and lockout policy
    # =======================================================================

    Write-Host "[*] Checking password and account lockout policy..."

    $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy

    # Windows Fortress target:
    # Minimum length = 14

    if ($PasswordPolicy.MinPasswordLength -lt 14) {

        Add-Finding `
            -Severity "critical" `
            -Category "Password Policy" `
            -Asset $DomainName `
            -Evidence "Password policy minimum length: $($PasswordPolicy.MinPasswordLength); expected: 14." `
            -Risk "Short passwords increase exposure to password guessing, spraying and offline cracking." `
            -RecommendedRemediation "Set domain minimum password length to 14 after compatibility testing." `
            -MappedTask "Password policy hardening"
    }

    # Complexity enabled

    if (-not $PasswordPolicy.ComplexityEnabled) {

        Add-Finding `
            -Severity "high" `
            -Category "Password Policy" `
            -Asset $DomainName `
            -Evidence "Password complexity: disabled; expected: enabled." `
            -Risk "Weak passwords increase credential compromise risk." `
            -RecommendedRemediation "Enable domain password complexity." `
            -MappedTask "Password policy hardening"
    }

    # Password history = 24

    if ($PasswordPolicy.PasswordHistoryCount -lt 24) {

        Add-Finding `
            -Severity "high" `
            -Category "Password Policy" `
            -Asset $DomainName `
            -Evidence "Password history: $($PasswordPolicy.PasswordHistoryCount); expected: 24." `
            -Risk "Insufficient password history allows users to rapidly reuse previous passwords." `
            -RecommendedRemediation "Configure password history to remember 24 passwords." `
            -MappedTask "Password policy hardening"
    }

    # Account lockout threshold = 5

    if ($PasswordPolicy.LockoutThreshold -eq 0) {

        Add-Finding `
            -Severity "critical" `
            -Category "Account Lockout" `
            -Asset $DomainName `
            -Evidence "Account lockout: not configured; threshold=0; expected=5." `
            -Risk "Unlimited authentication attempts increase password spraying and brute-force risk." `
            -RecommendedRemediation "Configure an account lockout threshold of 5 failed attempts." `
            -MappedTask "Account lockout hardening"
    }
    elseif ($PasswordPolicy.LockoutThreshold -ne 5) {

        Add-Finding `
            -Severity "high" `
            -Category "Account Lockout" `
            -Asset $DomainName `
            -Evidence "Account lockout threshold=$($PasswordPolicy.LockoutThreshold); expected=5." `
            -Risk "The current account lockout threshold does not match the Windows Fortress baseline." `
            -RecommendedRemediation "Set the account lockout threshold to 5 after operational testing." `
            -MappedTask "Account lockout hardening"
    }


    # =======================================================================
    # Service account security
    # =======================================================================

    Write-Host "[*] Checking service account security..."

    $ServiceAccounts = @(
        $AllUsers |
        Where-Object {
            Test-ServiceAccount -User $_
        }
    )

    $StalePasswordCutoff = (Get-Date).AddDays(-180)
    $StaleLogonCutoff = (Get-Date).AddDays(-90)

    $InteractiveLogonPolicy = Test-InteractiveLogonVisibility

    foreach ($ServiceAccount in $ServiceAccounts) {

        $MemberOf = @(
            Get-MemberOf `
                -User $ServiceAccount
        )

        # -------------------------------------------------------------------
        # TrustedForDelegation
        # -------------------------------------------------------------------

        if ($ServiceAccount.TrustedForDelegation -eq $true) {

            Add-Finding `
                -Severity "high" `
                -Category "Service Account - Unconstrained Delegation" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "TrustedForDelegation=True" `
                -Risk "Unconstrained delegation may expose reusable Kerberos credentials if the service host is compromised." `
                -RecommendedRemediation "Remove unconstrained delegation and use constrained or resource-based constrained delegation where required." `
                -MappedTask "Kerberos and service account hardening"
        }

        # -------------------------------------------------------------------
        # UseDESKeyOnly
        # -------------------------------------------------------------------

        $UseDESKeyOnly = $false

        if ($null -ne $ServiceAccount.UseDESKeyOnly) {

            $UseDESKeyOnly = [bool]$ServiceAccount.UseDESKeyOnly
        }
        else {

            # ADS_UF_USE_DES_KEY_ONLY = 0x200000
            $UserAccountControl = [int64]$ServiceAccount.UserAccountControl

            $UseDESKeyOnly = (
                ($UserAccountControl -band 0x200000) -ne 0
            )
        }

        if ($UseDESKeyOnly) {

            Add-Finding `
                -Severity "critical" `
                -Category "Kerberos DES" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "UseDESKeyOnly=True" `
                -Risk "DES is obsolete cryptography and significantly weakens Kerberos authentication." `
                -RecommendedRemediation "Disable DES-only authentication and migrate the service account to AES-compatible Kerberos encryption." `
                -MappedTask "Kerberos hardening"
        }

        # -------------------------------------------------------------------
        # Privileged membership
        # -------------------------------------------------------------------

        $PrivilegedMemberOf = @(
            $MemberOf |
            Where-Object {
                $_ -in @(
                    "Domain Admins",
                    "Enterprise Admins",
                    "G_IT_Admins"
                )
            }
        )

        if ($PrivilegedMemberOf.Count -gt 0) {

            Add-Finding `
                -Severity "high" `
                -Category "Privileged Service Account" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "MemberOf=$($PrivilegedMemberOf -join ', ')" `
                -Risk "Compromise of a privileged service account may provide immediate administrative access." `
                -RecommendedRemediation "Remove unnecessary privileged group membership and apply least privilege." `
                -MappedTask "Service account hardening"
        }

        # -------------------------------------------------------------------
        # Stale password
        # -------------------------------------------------------------------

        if (
            $null -eq $ServiceAccount.PasswordLastSet -or
            $ServiceAccount.PasswordLastSet -lt $StalePasswordCutoff
        ) {

            Add-Finding `
                -Severity "high" `
                -Category "Service Account Stale Password" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "PasswordLastSet=$(Convert-DateSafe $ServiceAccount.PasswordLastSet); older than 180-day review threshold." `
                -Risk "Long-lived service-account credentials provide attackers with an extended opportunity for credential abuse." `
                -RecommendedRemediation "Rotate the credential or migrate the identity to a Group Managed Service Account (gMSA)." `
                -MappedTask "Service account hardening"
        }

        # -------------------------------------------------------------------
        # Suspicious/stale last logon
        # -------------------------------------------------------------------

        if (
            $null -eq $ServiceAccount.LastLogonDate -or
            $ServiceAccount.LastLogonDate -lt $StaleLogonCutoff
        ) {

            Add-Finding `
                -Severity "medium" `
                -Category "Service Account Suspicious Last Logon" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "LastLogonDate=$(Convert-DateSafe $ServiceAccount.LastLogonDate); no recent authentication within 90 days." `
                -Risk "Unused service identities may retain credentials and permissions long after the associated service is retired." `
                -RecommendedRemediation "Confirm the account is still required and disable unused service identities after dependency review." `
                -MappedTask "Service account hardening"
        }

        # -------------------------------------------------------------------
        # interactive logon
        # -------------------------------------------------------------------

        if ($InteractiveLogonPolicy.interactive_logon -eq "REVIEW_REQUIRED") {

            Add-Finding `
                -Severity "high" `
                -Category "Service Account Interactive Logon" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "interactive logon rights require review. Effective Allow/Deny logon rights must be correlated with the service account SID and group memberships." `
                -Risk "Allowing a service account to perform interactive logon increases credential exposure and may facilitate lateral movement." `
                -RecommendedRemediation "Deny interactive logon and Remote Desktop logon for service accounts unless explicitly required and documented." `
                -MappedTask "Service account hardening"
        }
    }


    # =======================================================================
    # Advanced Audit Policy
    # =======================================================================

    Write-Host "[*] Checking Advanced Audit Policy..."

    $AuditPolicy = Get-AuditPolicyText

    $AuditRequirements = @(
        "Process Creation",
        "Special Logon",
        "User Account Management",
        "Computer Account Management",
        "Security Group Management",
        "File System"
    )

    $MissingAuditVisibility = @()

    foreach ($AuditRequirement in $AuditRequirements) {

        if (
            $AuditPolicy -notmatch
            [regex]::Escape($AuditRequirement)
        ) {

            $MissingAuditVisibility += $AuditRequirement
        }
    }

    if ($MissingAuditVisibility.Count -gt 0) {

        Add-Finding `
            -Severity "high" `
            -Category "Advanced Audit Policy" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Missing audit visibility for: $($MissingAuditVisibility -join ', ')." `
            -Risk "Missing process creation, special logon, account management or object access telemetry limits SOC detection and investigation." `
            -RecommendedRemediation "Configure Advanced Audit Policy through the MedDefense hardening GPO." `
            -MappedTask "Audit policy hardening"
    }


    # =======================================================================
    # PowerShell Script Block Logging
    # =======================================================================

    Write-Host "[*] Checking PowerShell logging readiness..."

    $ScriptBlockLoggingPath = `
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

    $ScriptBlockLoggingEnabled = $false

    if (Test-Path $ScriptBlockLoggingPath) {

        try {

            $ScriptBlockLogging = Get-ItemProperty `
                -Path $ScriptBlockLoggingPath `
                -Name EnableScriptBlockLogging `
                -ErrorAction Stop

            if (
                $ScriptBlockLogging.EnableScriptBlockLogging -eq 1
            ) {

                $ScriptBlockLoggingEnabled = $true
            }
        }
        catch {

            $ScriptBlockLoggingEnabled = $false
        }
    }

    if (-not $ScriptBlockLoggingEnabled) {

        Add-Finding `
            -Severity "high" `
            -Category "PowerShell Script Block Logging" `
            -Asset $env:COMPUTERNAME `
            -Evidence "PowerShell Script Block Logging is disabled or not configured." `
            -Risk "PowerShell commands may execute without detailed Event ID 4104 telemetry." `
            -RecommendedRemediation "Enable PowerShell Script Block Logging through Group Policy." `
            -MappedTask "PowerShell logging hardening"
    }


    # =======================================================================
    # Sysmon readiness
    # =======================================================================

    Write-Host "[*] Checking Sysmon readiness..."

    $SysmonService = Get-Service `
        -Name "Sysmon*" `
        -ErrorAction SilentlyContinue

    if ($null -eq $SysmonService) {

        Add-Finding `
            -Severity "high" `
            -Category "Sysmon Readiness" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Sysmon service is not installed." `
            -Risk "Detailed process, network, file and registry telemetry may be unavailable to the SOC." `
            -RecommendedRemediation "Deploy Sysmon using the approved MedDefense configuration." `
            -MappedTask "Sysmon deployment"
    }


    # =======================================================================
    # Group Policy posture
    # =======================================================================

    Write-Host "[*] Checking GPO security posture..."

    if ($GPOModuleAvailable) {

        Import-Module GroupPolicy

        $GPOs = @(
            Get-GPO -All
        )

        $DefaultGPOs = @(
            $GPOs |
            Where-Object {

                $_.DisplayName -in @(
                    "Default Domain Policy",
                    "Default Domain Controllers Policy"
                )
            }
        )

        $HardeningGPOs = @(
            $GPOs |
            Where-Object {

                $_.DisplayName -match `
                    "(?i)(MedDefense|Hardening|Security|Audit|Firewall|Sysmon|AppLocker)"
            }
        )

        if (
            $GPOs.Count -le 2 -and
            $DefaultGPOs.Count -eq $GPOs.Count
        ) {

            Add-Finding `
                -Severity "medium" `
                -Category "GPO Security Posture" `
                -Asset $DomainName `
                -Evidence "Only default GPOs are present." `
                -Risk "Security configuration is not separated into purpose-built centrally managed hardening policies." `
                -RecommendedRemediation "Create dedicated MedDefense security hardening GPOs." `
                -MappedTask "GPO hardening"
        }

        if ($HardeningGPOs.Count -eq 0) {

            Add-Finding `
                -Severity "medium" `
                -Category "GPO Security Posture" `
                -Asset $DomainName `
                -Evidence "No MedDefense hardening GPOs with a clear security purpose were identified." `
                -Risk "Windows security configuration may remain inconsistent across endpoints." `
                -RecommendedRemediation "Create clearly named and scoped GPOs for Windows hardening, audit policy, Sysmon, AppLocker and firewall controls." `
                -MappedTask "GPO hardening"
        }
    }
    else {

        Add-Finding `
            -Severity "medium" `
            -Category "GPO Security Posture" `
            -Asset $DomainName `
            -Evidence "GroupPolicy PowerShell module is unavailable." `
            -Risk "GPO security posture cannot be fully verified." `
            -RecommendedRemediation "Run GPO assessment from a system with Group Policy Management tools installed." `
            -MappedTask "GPO hardening"
    }
}


# ===========================================================================
# STANDALONE WINDOWS MODE
# ===========================================================================

else {

    Write-Host "[!] Active Directory / meddefense.local unavailable."
    Write-Host "[*] Domain-specific controls will be marked NOT_ASSESSED."
    Write-Host "[*] Local telemetry readiness will still be assessed."
    Write-Host ""

    # -----------------------------------------------------------------------
    # Domain-only controls
    # -----------------------------------------------------------------------

    Add-NotAssessedFinding `
        -Category "PasswordNeverExpires Accounts" `
        -Reason "PasswordNeverExpires, PasswordLastSet and MemberOf domain information requires Get-ADUser." `
        -MappedTask "Password policy and service account hardening"

    Add-NotAssessedFinding `
        -Category "Privileged Groups" `
        -Reason "Domain Admins, Enterprise Admins and G_IT_Admins are unavailable without Active Directory." `
        -MappedTask "Privileged access cleanup"

    Add-NotAssessedFinding `
        -Category "Stale Computer Objects" `
        -Reason "Stale domain computers require Get-ADComputer and domain authentication data." `
        -MappedTask "Stale object cleanup"

    Add-NotAssessedFinding `
        -Category "Domain Password Policy" `
        -Reason "Minimum length 14, complexity, history 24 and lockout threshold 5 require Get-ADDefaultDomainPasswordPolicy." `
        -MappedTask "Password policy hardening"

    Add-NotAssessedFinding `
        -Category "Kerberos Security" `
        -Reason "RC4, DES, TrustedForDelegation and UseDESKeyOnly require Active Directory account information." `
        -MappedTask "Kerberos hardening"

    Add-NotAssessedFinding `
        -Category "Service Account Security" `
        -Reason "Domain svc accounts, interactive logon, SPNs, delegation and privileged MemberOf information require Active Directory." `
        -MappedTask "Service account hardening"

    Add-NotAssessedFinding `
        -Category "GPO Security Posture" `
        -Reason "meddefense.local Group Policy Objects cannot be queried from this standalone workstation." `
        -MappedTask "GPO hardening"


    # -----------------------------------------------------------------------
    # Local Advanced Audit Policy
    # READ ONLY
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking local Advanced Audit Policy..."

    $LocalAuditPolicy = Get-AuditPolicyText

    if ([string]::IsNullOrWhiteSpace($LocalAuditPolicy)) {

        Add-Finding `
            -Severity "high" `
            -Category "Advanced Audit Policy" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Advanced Audit Policy could not be collected using auditpol." `
            -Risk "Security event visibility cannot be confirmed." `
            -RecommendedRemediation "Review Advanced Audit Policy on the intended Windows laboratory environment. Do not automatically modify this personal workstation." `
            -MappedTask "Audit policy hardening"
    }
    else {

        $RequiredAuditVisibility = @(
            "Process Creation",
            "Special Logon",
            "User Account Management",
            "Computer Account Management",
            "Security Group Management",
            "File System"
        )

        $MissingLocalAuditVisibility = @()

        foreach ($RequiredAuditItem in $RequiredAuditVisibility) {

            if (
                $LocalAuditPolicy -notmatch
                [regex]::Escape($RequiredAuditItem)
            ) {

                $MissingLocalAuditVisibility += $RequiredAuditItem
            }
        }

        if ($MissingLocalAuditVisibility.Count -gt 0) {

            Add-Finding `
                -Severity "high" `
                -Category "Advanced Audit Policy" `
                -Asset $env:COMPUTERNAME `
                -Evidence "Missing or unconfirmed audit visibility for: $($MissingLocalAuditVisibility -join ', ')." `
                -Risk "Important security events may not be available for SOC analysis." `
                -RecommendedRemediation "Review and enable required auditing only in the approved Windows laboratory or managed environment." `
                -MappedTask "Audit policy hardening"
        }
    }


    # -----------------------------------------------------------------------
    # Local PowerShell Script Block Logging
    # READ ONLY
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking PowerShell Script Block Logging..."

    $ScriptBlockLoggingPath = `
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

    $ScriptBlockLoggingEnabled = $false

    if (Test-Path $ScriptBlockLoggingPath) {

        try {

            $ScriptBlockLogging = Get-ItemProperty `
                -Path $ScriptBlockLoggingPath `
                -Name EnableScriptBlockLogging `
                -ErrorAction Stop

            if (
                $ScriptBlockLogging.EnableScriptBlockLogging -eq 1
            ) {

                $ScriptBlockLoggingEnabled = $true
            }
        }
        catch {

            $ScriptBlockLoggingEnabled = $false
        }
    }

    if (-not $ScriptBlockLoggingEnabled) {

        Add-Finding `
            -Severity "high" `
            -Category "PowerShell Script Block Logging" `
            -Asset $env:COMPUTERNAME `
            -Evidence "PowerShell Script Block Logging is not enabled or cannot be confirmed." `
            -Risk "PowerShell execution may lack detailed Event ID 4104 telemetry for SOC investigation." `
            -RecommendedRemediation "Do not modify the personal workstation automatically. Enable Script Block Logging in the intended MedDefense/lab environment." `
            -MappedTask "PowerShell logging hardening"
    }


    # -----------------------------------------------------------------------
    # Local Sysmon readiness
    # READ ONLY
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking Sysmon readiness..."

    $SysmonService = Get-Service `
        -Name "Sysmon*" `
        -ErrorAction SilentlyContinue

    if ($null -eq $SysmonService) {

        Add-Finding `
            -Severity "high" `
            -Category "Sysmon Readiness" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Sysmon service is not installed." `
            -Risk "Enhanced endpoint process, network and file telemetry is unavailable." `
            -RecommendedRemediation "Deploy Sysmon only in the approved laboratory or managed Windows environment." `
            -MappedTask "Sysmon deployment"
    }
}


# ===========================================================================
# Summary calculations
# ===========================================================================

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


# ===========================================================================
# Structured JSON report
# ===========================================================================

$Report = [ordered]@{

    task = "1 - Domain Risk Findings Extractor"

    generated_at_utc = (
        Get-Date
    ).ToUniversalTime().ToString("o")

    target_domain = $TargetDomain

    assessment_mode = $AssessmentMode

    safety = [ordered]@{
        mode            = "READ_ONLY"
        modified_system = $false
    }

    summary = [ordered]@{
        findings = $Findings.Count
        critical = $CriticalCount
        high     = $HighCount
        medium   = $MediumCount
    }

    findings = $Findings
}


$Json = $Report |
    ConvertTo-Json `
        -Depth 15


[System.IO.File]::WriteAllText(
    $OutputFile,
    $Json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)


# ===========================================================================
# Console output
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Domain Security Findings"
Write-Host "=============================================="

foreach ($Finding in $Findings) {

    $SeverityLabel = $Finding.severity.ToUpper()

    Write-Host "[$SeverityLabel] $($Finding.category): $($Finding.asset)"
}

Write-Host ""
Write-Host "Findings: $($Findings.Count)"
Write-Host "Critical: $CriticalCount"
Write-Host "High: $HighCount"
Write-Host "Medium: $MediumCount"
Write-Host "Report saved to: domain_security_findings.json"