# MedDefense Health Systems
# Task: 1 - Domain Risk Findings Extractor
# Script: 1-domain_findings.ps1
# Author: Pedro Cabral
# Purpose: Produce an actionable Windows and Active Directory security findings inventory.
# Safety: READ-ONLY. This script does not modify system or domain configuration.
# Output: domain_security_findings.json
#
# The script audits meddefense.local when Active Directory is available.
# On a standalone Windows workstation, domain-specific checks are recorded
# as NOT_ASSESSED rather than fabricated.
#
# Required finding fields:
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
$BaselineFile = Join-Path $ScriptDirectory "domain_baseline.json"

$TargetDomain = "meddefense.local"

$Findings = @()
$FindingCounter = 0

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

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

    $Id = "WIN-{0:D3}" -f $script:FindingCounter

    $script:Findings += [PSCustomObject]@{
        id                      = $Id
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
        -Risk "The security state of this domain control cannot be verified from the current standalone workstation." `
        -RecommendedRemediation "Re-run this assessment from the MedDefense Domain Controller or a domain management workstation with RSAT." `
        -MappedTask $MappedTask
}

function Test-ServiceAccount {
    param(
        [object]$User
    )

    if ($null -eq $User) {
        return $false
    }

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

function Get-GroupMembershipNames {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    try {
        return @(
            Get-ADPrincipalGroupMembership `
                -Identity $User `
                -ErrorAction Stop |
            Select-Object -ExpandProperty Name
        )
    }
    catch {
        return @()
    }
}

function Get-LocalAuditPolicyText {
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

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

Write-Host "[*] MedDefense Domain Risk Findings Extractor"
Write-Host "[*] Mode: READ ONLY"
Write-Host ""

$ComputerSystem = Get-CimInstance Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain

$ADModuleAvailable = [bool](
    Get-Module -ListAvailable -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module -ListAvailable -Name GroupPolicy
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
# ACTIVE DIRECTORY ASSESSMENT
# ===========================================================================

if ($AssessmentMode -eq "ACTIVE_DIRECTORY") {

    Import-Module ActiveDirectory

    $Domain = Get-ADDomain
    $DomainName = $Domain.DNSRoot

    Write-Host "[*] Auditing domain: $DomainName"

    # -----------------------------------------------------------------------
    # Accounts with PasswordNeverExpires
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking PasswordNeverExpires accounts..."

    $AllUsers = @(
        Get-ADUser `
            -Filter * `
            -Properties `
                Enabled,
                PasswordNeverExpires,
                PasswordLastSet,
                LastLogonDate,
                ServicePrincipalName,
                TrustedForDelegation,
                UserAccountControl,
                DistinguishedName
    )

    $PasswordNeverExpiresUsers = @(
        $AllUsers |
        Where-Object {
            $_.PasswordNeverExpires -eq $true
        }
    )

    foreach ($User in $PasswordNeverExpiresUsers) {

        $Groups = @(Get-GroupMembershipNames -User $User)
        $IsServiceAccount = Test-ServiceAccount -User $User

        $MemberOf = @($Groups)

        $Evidence = @(
            "Account=$($User.SamAccountName)"
            "Enabled=$($User.Enabled)"
            "PasswordLastSet=$($User.PasswordLastSet)"
            "PasswordNeverExpires=$($User.PasswordNeverExpires)"
            "ServiceAccount=$IsServiceAccount"
            "MemberOf=$($MemberOf -join ', ')"
        ) -join "; "

        Add-Finding `
            -Severity "high" `
            -Category "PasswordNeverExpires" `
            -Asset $User.SamAccountName `
            -Evidence $Evidence `
            -Risk "Long-lived credentials increase the impact of credential theft and password cracking." `
            -RecommendedRemediation "Remove unnecessary PasswordNeverExpires settings and migrate eligible service identities to managed service accounts." `
            -MappedTask "Password policy and service account hardening"
    }

    # -----------------------------------------------------------------------
    # Disabled accounts in privileged groups
    # Domain Admins, Enterprise Admins, G_IT_Admins
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking disabled accounts in privileged groups..."

    $PrivilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "G_IT_Admins"
    )

    foreach ($GroupName in $PrivilegedGroups) {

        try {
            $Members = @(
                Get-ADGroupMember `
                    -Identity $GroupName `
                    -Recursive `
                    -ErrorAction Stop
            )
        }
        catch {
            $Members = @()
        }

        foreach ($Member in $Members) {

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
                    -Category "Privileged Disabled Account" `
                    -Asset $PrivilegedUser.SamAccountName `
                    -Evidence "Disabled account remains a member of privileged group '$GroupName'." `
                    -Risk "Dormant privileged memberships can be re-enabled or abused and increase unnecessary administrative exposure." `
                    -RecommendedRemediation "Remove disabled accounts from privileged groups and review whether the account should be deleted after retention requirements." `
                    -MappedTask "Stale object and privileged access cleanup"
            }
        }
    }

    # -----------------------------------------------------------------------
    # Stale computer objects - 90+ days
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking stale computer objects..."

    $StaleCutoff = (Get-Date).AddDays(-90)

    $StaleComputers = @(
        Get-ADComputer `
            -Filter * `
            -Properties LastLogonDate,Enabled |
        Where-Object {
            $null -eq $_.LastLogonDate -or
            $_.LastLogonDate -lt $StaleCutoff
        }
    )

    if ($StaleComputers.Count -gt 0) {

        $ComputerNames = @(
            $StaleComputers |
            Select-Object -ExpandProperty Name
        )

        Add-Finding `
            -Severity "medium" `
            -Category "Stale Computer Objects" `
            -Asset $DomainName `
            -Evidence "$($StaleComputers.Count) computer object(s) show no authentication/logon activity within 90 days: $($ComputerNames -join ', ')." `
            -Risk "Stale computer accounts increase attack surface and may retain outdated credentials or permissions." `
            -RecommendedRemediation "Investigate stale systems, disable verified unused computer accounts, and remove them after the approved retention period." `
            -MappedTask "Stale object cleanup"
    }

    # -----------------------------------------------------------------------
    # Password and lockout policy
    #
    # Windows Fortress targets:
    # Minimum length = 14
    # Complexity = enabled
    # History = 24
    # Lockout threshold = 5
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking password and lockout policy..."

    $Policy = Get-ADDefaultDomainPasswordPolicy

    if ($Policy.MinPasswordLength -lt 14) {

        Add-Finding `
            -Severity "critical" `
            -Category "Password Policy" `
            -Asset $DomainName `
            -Evidence "Password policy minimum length: $($Policy.MinPasswordLength); target: 14." `
            -Risk "Short passwords increase exposure to password guessing, cracking, and credential attacks." `
            -RecommendedRemediation "Configure the MedDefense domain password policy with a minimum length of 14 characters." `
            -MappedTask "Password policy hardening"
    }

    if (-not $Policy.ComplexityEnabled) {

        Add-Finding `
            -Severity "high" `
            -Category "Password Policy" `
            -Asset $DomainName `
            -Evidence "Password complexity is disabled; target: enabled." `
            -Risk "Weak password composition increases credential compromise risk." `
            -RecommendedRemediation "Enable domain password complexity after compatibility testing." `
            -MappedTask "Password policy hardening"
    }

    if ($Policy.PasswordHistoryCount -lt 24) {

        Add-Finding `
            -Severity "high" `
            -Category "Password Policy" `
            -Asset $DomainName `
            -Evidence "Password history: $($Policy.PasswordHistoryCount); target: 24." `
            -Risk "Insufficient password history allows rapid password reuse." `
            -RecommendedRemediation "Configure password history to remember 24 passwords." `
            -MappedTask "Password policy hardening"
    }

    if ($Policy.LockoutThreshold -eq 0) {

        Add-Finding `
            -Severity "critical" `
            -Category "Account Lockout" `
            -Asset $DomainName `
            -Evidence "Account lockout: not configured; LockoutThreshold=0; target: 5." `
            -Risk "Attackers can perform repeated password guessing without triggering account lockout." `
            -RecommendedRemediation "Configure an account lockout threshold of 5 failed attempts with an approved observation and lockout period." `
            -MappedTask "Account lockout hardening"
    }
    elseif ($Policy.LockoutThreshold -gt 5) {

        Add-Finding `
            -Severity "high" `
            -Category "Account Lockout" `
            -Asset $DomainName `
            -Evidence "LockoutThreshold=$($Policy.LockoutThreshold); target: 5." `
            -Risk "A high lockout threshold permits excessive authentication attempts." `
            -RecommendedRemediation "Reduce the account lockout threshold to the Windows Fortress target of 5." `
            -MappedTask "Account lockout hardening"
    }

    # -----------------------------------------------------------------------
    # Kerberos weak encryption / service account risks
    # DES-only flag = ADS_UF_USE_DES_KEY_ONLY = 0x200000
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking Kerberos and service account risks..."

    $ServiceAccounts = @(
        $AllUsers |
        Where-Object {
            Test-ServiceAccount -User $_
        }
    )

    $StalePasswordCutoff = (Get-Date).AddDays(-180)
    $SuspiciousLogonCutoff = (Get-Date).AddDays(-90)

    foreach ($ServiceAccount in $ServiceAccounts) {

        $Groups = @(Get-GroupMembershipNames -User $ServiceAccount)

        $PrivilegedMembership = @(
            $Groups |
            Where-Object {
                $_ -in @(
                    "Domain Admins",
                    "Enterprise Admins",
                    "G_IT_Admins"
                )
            }
        )

        if ($ServiceAccount.TrustedForDelegation) {

            Add-Finding `
                -Severity "high" `
                -Category "Service Account - Unconstrained Delegation" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "TrustedForDelegation=True." `
                -Risk "Unconstrained delegation may expose reusable Kerberos credentials if the service host is compromised." `
                -RecommendedRemediation "Remove unconstrained delegation and use constrained or resource-based constrained delegation where required." `
                -MappedTask "Kerberos and service account hardening"
        }

        $UserAccountControl = [int64]$ServiceAccount.UserAccountControl

        # ADS_UF_USE_DES_KEY_ONLY = 0x200000
        $UseDESKeyOnly = (($UserAccountControl -band 0x200000) -ne 0)

        if ($UseDESKeyOnly) {

            Add-Finding `
                -Severity "critical" `
                -Category "Kerberos DES" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "UseDESKeyOnly=True; DES-only Kerberos flag detected in UserAccountControl." `
                -Risk "DES is obsolete cryptography and materially weakens Kerberos authentication." `
                -RecommendedRemediation "Remove the DES-only flag and migrate compatible accounts to AES Kerberos encryption." `
                -MappedTask "Kerberos hardening"
        }

        if ($PrivilegedMembership.Count -gt 0) {

            Add-Finding `
                -Severity "high" `
                -Category "Privileged Service Account" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "Service account belongs to privileged group(s): $($PrivilegedMembership -join ', ')." `
                -Risk "Compromise of the service account may provide immediate privileged access." `
                -RecommendedRemediation "Remove unnecessary privileged group membership and apply least privilege." `
                -MappedTask "Service account hardening"
        }

        if (
            $null -eq $ServiceAccount.PasswordLastSet -or
            $ServiceAccount.PasswordLastSet -lt $StalePasswordCutoff
        ) {

            Add-Finding `
                -Severity "high" `
                -Category "Service Account Stale Password" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "PasswordLastSet=$($ServiceAccount.PasswordLastSet); threshold: 180 days." `
                -Risk "Old service-account credentials provide attackers with longer-lived opportunities for credential abuse." `
                -RecommendedRemediation "Rotate stale credentials or migrate the service account to gMSA where supported." `
                -MappedTask "Service account hardening"
        }

        if (
            $null -eq $ServiceAccount.LastLogonDate -or
            $ServiceAccount.LastLogonDate -lt $SuspiciousLogonCutoff
        ) {

            Add-Finding `
                -Severity "medium" `
                -Category "Service Account Suspicious Last Logon" `
                -Asset $ServiceAccount.SamAccountName `
                -Evidence "LastLogonDate=$($ServiceAccount.LastLogonDate)." `
                -Risk "Inactive service accounts may be obsolete yet still retain permissions and credentials." `
                -RecommendedRemediation "Confirm whether the service account is still required and disable unused identities after dependency review." `
                -MappedTask "Service account hardening"
        }

        # Interactive logon rights require local/domain security policy
        # correlation. Flag visibility if explicit evidence is unavailable.
        #
        # This script intentionally does not alter User Rights Assignment.
    }

    # -----------------------------------------------------------------------
    # Advanced Audit Policy
    # process creation, special logon, account management, object access
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking audit visibility..."

    $AuditPolicyText = Get-LocalAuditPolicyText

    $RequiredAuditTerms = @(
        "Process Creation",
        "Special Logon",
        "User Account Management",
        "Computer Account Management",
        "Security Group Management",
        "File System"
    )

    $MissingAuditTerms = @()

    foreach ($AuditTerm in $RequiredAuditTerms) {

        if ($AuditPolicyText -notmatch [regex]::Escape($AuditTerm)) {
            $MissingAuditTerms += $AuditTerm
        }
    }

    if ($MissingAuditTerms.Count -gt 0) {

        Add-Finding `
            -Severity "high" `
            -Category "Advanced Audit Policy" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Advanced Audit Policy visibility could not be confirmed for: $($MissingAuditTerms -join ', ')." `
            -Risk "Missing process, logon, account-management or object-access events reduce SOC visibility and investigation capability." `
            -RecommendedRemediation "Configure Advanced Audit Policy through the MedDefense security GPO and validate generated Windows Events." `
            -MappedTask "Audit policy hardening"
    }

    # -----------------------------------------------------------------------
    # PowerShell Script Block Logging readiness
    # Read-only Registry query
    # -----------------------------------------------------------------------

    $ScriptBlockLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

    $ScriptBlockLoggingEnabled = $false

    if (Test-Path $ScriptBlockLoggingPath) {

        try {
            $SBL = Get-ItemProperty `
                -Path $ScriptBlockLoggingPath `
                -Name EnableScriptBlockLogging `
                -ErrorAction Stop

            $ScriptBlockLoggingEnabled = (
                $SBL.EnableScriptBlockLogging -eq 1
            )
        }
        catch {
            $ScriptBlockLoggingEnabled = $false
        }
    }

    if (-not $ScriptBlockLoggingEnabled) {

        Add-Finding `
            -Severity "high" `
            -Category "PowerShell Logging" `
            -Asset $env:COMPUTERNAME `
            -Evidence "PowerShell Script Block Logging is not confirmed as enabled." `
            -Risk "Malicious or suspicious PowerShell activity may execute without sufficient command-level telemetry." `
            -RecommendedRemediation "Enable PowerShell Script Block Logging through Group Policy and forward Event ID 4104 to the SIEM." `
            -MappedTask "PowerShell logging hardening"
    }

    # -----------------------------------------------------------------------
    # Sysmon readiness
    # -----------------------------------------------------------------------

    $SysmonService = Get-Service `
        -Name "Sysmon*" `
        -ErrorAction SilentlyContinue

    if ($null -eq $SysmonService) {

        Add-Finding `
            -Severity "high" `
            -Category "Sysmon Readiness" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Sysmon service was not detected." `
            -Risk "Process creation, network connections and other endpoint telemetry may be unavailable to the SOC." `
            -RecommendedRemediation "Deploy Sysmon using the approved MedDefense configuration and forward Microsoft-Windows-Sysmon/Operational events." `
            -MappedTask "Sysmon deployment"
    }

    # -----------------------------------------------------------------------
    # GPO security posture
    # -----------------------------------------------------------------------

    if ($GPOModuleAvailable) {

        Import-Module GroupPolicy

        $GPOs = @(Get-GPO -All)

        $DefaultGPOs = @(
            $GPOs |
            Where-Object {
                $_.DisplayName -in @(
                    "Default Domain Policy",
                    "Default Domain Controllers Policy"
                )
            }
        )

        $MedDefenseHardeningGPOs = @(
            $GPOs |
            Where-Object {
                $_.DisplayName -match "(?i)(MedDefense|Hardening|Security|Audit|Firewall|Sysmon|AppLocker)"
            }
        )

        if (
            $GPOs.Count -le 2 -and
            $GPOs.Count -eq $DefaultGPOs.Count
        ) {

            Add-Finding `
                -Severity "medium" `
                -Category "GPO Security Posture" `
                -Asset $DomainName `
                -Evidence "Only default GPOs are present." `
                -Risk "Security controls are not centrally separated into purpose-built hardening policies." `
                -RecommendedRemediation "Create dedicated MedDefense security GPOs for baseline hardening, auditing, firewall, PowerShell logging, Sysmon and application control." `
                -MappedTask "GPO hardening"
        }

        if ($MedDefenseHardeningGPOs.Count -eq 0) {

            Add-Finding `
                -Severity "medium" `
                -Category "GPO Security Posture" `
                -Asset $DomainName `
                -Evidence "No MedDefense hardening GPOs were identified." `
                -Risk "Security configuration may remain inconsistent across domain endpoints." `
                -RecommendedRemediation "Create clearly named and scoped security GPOs with documented purpose and ownership." `
                -MappedTask "GPO hardening"
        }
    }
    else {

        Add-Finding `
            -Severity "medium" `
            -Category "GPO Security Posture" `
            -Asset $DomainName `
            -Evidence "GroupPolicy PowerShell module is unavailable." `
            -Risk "GPO security posture cannot be independently verified." `
            -RecommendedRemediation "Perform GPO assessment from a host with Group Policy Management tools installed." `
            -MappedTask "GPO hardening"
    }
}

# ===========================================================================
# STANDALONE WINDOWS ASSESSMENT
# ===========================================================================

else {

    Write-Host "[!] meddefense.local is not available from this workstation."
    Write-Host "[*] Domain-specific findings will be marked NOT_ASSESSED."
    Write-Host "[*] Safe local visibility checks will still be performed."
    Write-Host ""

    Add-NotAssessedFinding `
        -Category "PasswordNeverExpires Accounts" `
        -Reason "Get-ADUser cannot be used because Active Directory is unavailable." `
        -MappedTask "Password policy and service account hardening"

    Add-NotAssessedFinding `
        -Category "Privileged Group Membership" `
        -Reason "Domain Admins, Enterprise Admins and G_IT_Admins cannot be queried without Active Directory." `
        -MappedTask "Privileged access cleanup"

    Add-NotAssessedFinding `
        -Category "Stale Computer Objects" `
        -Reason "Get-ADComputer cannot be used because Active Directory is unavailable." `
        -MappedTask "Stale object cleanup"

    Add-NotAssessedFinding `
        -Category "Domain Password and Lockout Policy" `
        -Reason "Get-ADDefaultDomainPasswordPolicy requires Active Directory." `
        -MappedTask "Password policy hardening"

    Add-NotAssessedFinding `
        -Category "Kerberos Domain Security" `
        -Reason "Domain Kerberos encryption and delegation cannot be fully assessed without meddefense.local." `
        -MappedTask "Kerberos hardening"

    Add-NotAssessedFinding `
        -Category "Service Account Domain Risks" `
        -Reason "Domain service accounts, SPNs and delegation settings cannot be queried." `
        -MappedTask "Service account hardening"

    Add-NotAssessedFinding `
        -Category "GPO Security Posture" `
        -Reason "Domain GPOs cannot be queried because Group Policy domain context is unavailable." `
        -MappedTask "GPO hardening"

    # -----------------------------------------------------------------------
    # Safe local audit visibility checks
    # -----------------------------------------------------------------------

    Write-Host "[*] Checking local audit telemetry readiness..."

    $AuditPolicyText = Get-LocalAuditPolicyText

    if ([string]::IsNullOrWhiteSpace($AuditPolicyText)) {

        Add-Finding `
            -Severity "high" `
            -Category "Advanced Audit Policy" `
            -Asset $env:COMPUTERNAME `
            -Evidence "auditpol output could not be collected." `
            -Risk "Security-event visibility cannot be verified." `
            -RecommendedRemediation "Review Advanced Audit Policy on the intended Windows lab system before enabling any settings." `
            -MappedTask "Audit policy hardening"
    }

    # -----------------------------------------------------------------------
    # PowerShell Script Block Logging - read only
    # -----------------------------------------------------------------------

    $ScriptBlockLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $ScriptBlockLoggingEnabled = $false

    if (Test-Path $ScriptBlockLoggingPath) {

        try {
            $Value = Get-ItemProperty `
                -Path $ScriptBlockLoggingPath `
                -Name EnableScriptBlockLogging `
                -ErrorAction Stop

            $ScriptBlockLoggingEnabled = (
                $Value.EnableScriptBlockLogging -eq 1
            )
        }
        catch {
            $ScriptBlockLoggingEnabled = $false
        }
    }

    if (-not $ScriptBlockLoggingEnabled) {

        Add-Finding `
            -Severity "high" `
            -Category "PowerShell Logging" `
            -Asset $env:COMPUTERNAME `
            -Evidence "PowerShell Script Block Logging is not enabled or cannot be confirmed." `
            -Risk "PowerShell execution may lack the detailed Event ID 4104 telemetry required for SOC investigation." `
            -RecommendedRemediation "Do not modify the personal workstation automatically. Validate and deploy Script Block Logging only in the intended Windows lab/MedDefense environment." `
            -MappedTask "PowerShell logging hardening"
    }

    # -----------------------------------------------------------------------
    # Sysmon readiness - read only
    # -----------------------------------------------------------------------

    $SysmonService = Get-Service `
        -Name "Sysmon*" `
        -ErrorAction SilentlyContinue

    if ($null -eq $SysmonService) {

        Add-Finding `
            -Severity "high" `
            -Category "Sysmon Readiness" `
            -Asset $env:COMPUTERNAME `
            -Evidence "Sysmon service is not installed." `
            -Risk "Enhanced process, network and file telemetry is unavailable." `
            -RecommendedRemediation "Install Sysmon only in the approved laboratory or managed endpoint environment using a reviewed configuration." `
            -MappedTask "Sysmon deployment"
    }
}

# ---------------------------------------------------------------------------
# Summary
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

# ---------------------------------------------------------------------------
# Structured JSON report
# ---------------------------------------------------------------------------

$Report = [ordered]@{
    task = "1 - Domain Risk Findings Extractor"

    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")

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

$Json = $Report | ConvertTo-Json -Depth 12

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