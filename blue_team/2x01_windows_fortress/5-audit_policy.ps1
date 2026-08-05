# MedDefense Health Systems
# Task: 5 - Advanced Audit Policy
# Script: 5-audit_policy.ps1
# Author: Pedro Cabral
# Date: 2026-08-05
# Purpose: Configure and validate MedDefense Advanced Audit Policy through Group Policy.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Console evidence of audit-policy configuration and verification.
#
# GPO:
# MedDefense - Advanced Audit Policy
#
# Required Advanced Audit Policy:
#
# Account Logon
# - Credential Validation: Success and Failure
# - Kerberos Authentication Service: Success and Failure
#
# Logon/Logoff
# - Logon: Success and Failure
# - Logoff: Success
# - Special Logon: Success
#
# Account Management
# - User Account Management: Success and Failure
#
# Privilege Use
# - Sensitive Privilege Use: Success and Failure
#
# Object Access
# - File System: Success and Failure
# - Registry: Success and Failure
#
# Process Tracking
# - Process Creation: Success
#
# Additional controls:
# - Include command line in Event ID 4688
# - Restrict Security log clearing
# - Security log maximum size: 1 GB
#
# VERIFY:
# auditpol /get /category:*
#
# VERIFIED:
# All required audit subcategories must match the expected state.
#
# IMPORTANT:
# Do not use -Apply on a personal standalone Windows workstation.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - Advanced Audit Policy"

$SecurityLogSizeBytes = 1073741824

# ===========================================================================
# Audit target definition
# ===========================================================================

$AuditTargets = @(

    [PSCustomObject]@{
        Category        = "Account Logon"
        Subcategory     = "Credential Validation"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Account Logon"
        Subcategory     = "Kerberos Authentication Service"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Logon/Logoff"
        Subcategory     = "Logon"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Logon/Logoff"
        Subcategory     = "Logoff"
        Expected        = "Success"
        SuccessEnabled  = $true
        FailureEnabled  = $false
    }

    [PSCustomObject]@{
        Category        = "Logon/Logoff"
        Subcategory     = "Special Logon"
        Expected        = "Success"
        SuccessEnabled  = $true
        FailureEnabled  = $false
    }

    [PSCustomObject]@{
        Category        = "Account Management"
        Subcategory     = "User Account Management"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Privilege Use"
        Subcategory     = "Sensitive Privilege Use"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Object Access"
        Subcategory     = "File System"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Object Access"
        Subcategory     = "Registry"
        Expected        = "Success and Failure"
        SuccessEnabled  = $true
        FailureEnabled  = $true
    }

    [PSCustomObject]@{
        Category        = "Process Tracking"
        Subcategory     = "Process Creation"
        Expected        = "Success"
        SuccessEnabled  = $true
        FailureEnabled  = $false
    }
)

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


function Write-WouldSet {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "    $Message [WOULD SET]"
}


function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


function Get-AuditPolicySafe {

    try {

        return @(
            auditpol.exe /get /category:* 2>$null
        )
    }
    catch {

        return @()
    }
}


function Test-AuditSetting {

    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AuditPolicy,

        [Parameter(Mandatory = $true)]
        [string]$Subcategory,

        [Parameter(Mandatory = $true)]
        [bool]$RequireSuccess,

        [Parameter(Mandatory = $true)]
        [bool]$RequireFailure
    )

    $MatchingLine = @(
        $AuditPolicy |
        Where-Object {
            $_ -match [regex]::Escape($Subcategory)
        }
    ) |
    Select-Object -First 1

    if ($null -eq $MatchingLine) {

        return [PSCustomObject]@{
            Found  = $false
            Passed = $false
            Actual = "NOT FOUND"
        }
    }

    $Actual = $MatchingLine.Trim()

    $HasSuccess = (
        $Actual -match "(?i)Success" -or
        $Actual -match "(?i)Êxito"
    )

    $HasFailure = (
        $Actual -match "(?i)Failure" -or
        $Actual -match "(?i)Falha"
    )

    $SuccessPassed = (
        (-not $RequireSuccess) -or
        $HasSuccess
    )

    $FailurePassed = (
        (-not $RequireFailure) -or
        $HasFailure
    )

    return [PSCustomObject]@{
        Found  = $true
        Passed = ($SuccessPassed -and $FailurePassed)
        Actual = $Actual
    }
}

# ===========================================================================
# Environment detection
# ===========================================================================

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain
$CurrentDomain = [string]$ComputerSystem.Domain

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

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Advanced Audit Policy"
Write-Host "=============================================="
Write-Host ""

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

# ===========================================================================
# AUDIT-ONLY MODE
# ===========================================================================

if (-not $Apply) {

    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No audit policy, GPO, Registry or Event Log settings will be modified."
    Write-Host ""

    Write-Step "Creating GPO: `"$GpoName`"..."

    if ($PartOfDomain -and $GPOModuleAvailable) {

        try {

            Import-Module GroupPolicy

            $ExistingGPO = Get-GPO `
                -Name $GpoName `
                -ErrorAction SilentlyContinue

            if ($null -ne $ExistingGPO) {

                Write-Host "    GPO already exists [DETECTED]"
            }
            else {

                Write-Host "    GPO not present [WOULD CREATE]"
            }
        }
        catch {

            Write-Host "    GPO state [NOT ASSESSED]"
        }
    }
    else {

        Write-Host "    Active Directory / Group Policy unavailable [WOULD CREATE]"
    }

    Write-Host ""

    Write-Step "Configuring Audit Categories..."

    foreach ($Target in $AuditTargets) {

        Write-WouldSet `
            "$($Target.Subcategory): $($Target.Expected)"
    }

    Write-Host ""

    Write-Step "Enabling command-line in process creation events..."

    Write-WouldSet `
        "Include command line in process creation events"

    Write-Host ""

    Write-Step "Restricting Security log clearing..."

    Write-WouldSet `
        "Security log clearing restricted to Domain Admins"

    Write-Host ""

    Write-Step "Setting Security log max size to 1 GB..."

    Write-WouldSet `
        "Security log maximum size = 1073741824 bytes"

    Write-Host ""

    Write-Step "Linking GPO and forcing update..."

    Write-Host "    Domain root: $TargetDomain [WOULD LINK]"
    Write-Host "    gpupdate /force [WOULD RUN]"

    Write-Host ""

    # -----------------------------------------------------------------------
    # VERIFY current local audit state
    # -----------------------------------------------------------------------

    Write-Step "VERIFY current audit policy using auditpol /get /category:*"

    $CurrentAuditPolicy = @(
        Get-AuditPolicySafe
    )

    if (@($CurrentAuditPolicy).Count -eq 0) {

        Write-Host "    Current audit policy [NOT ASSESSED]"
    }
    else {

        foreach ($Target in $AuditTargets) {

            $Result = Test-AuditSetting `
                -AuditPolicy $CurrentAuditPolicy `
                -Subcategory $Target.Subcategory `
                -RequireSuccess $Target.SuccessEnabled `
                -RequireFailure $Target.FailureEnabled

            if ($Result.Passed) {

                Write-Host "    $($Target.Subcategory): [VERIFIED]"
            }
            else {

                Write-Host "    $($Target.Subcategory): [NOT VERIFIED]"
            }
        }
    }

    Write-Host ""
    Write-Host "[*] Audit-only assessment complete."
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# APPLY MODE SAFETY CHECKS
# ===========================================================================

Write-Host "[!] APPLY mode requested."
Write-Host ""

if (-not (Test-IsAdministrator)) {

    throw "Apply mode requires an elevated PowerShell session."
}

if (-not $PartOfDomain) {

    throw "Refusing changes: this computer is not joined to Active Directory."
}

if (
    $CurrentDomain.ToLower() -ne
    $TargetDomain.ToLower()
) {

    throw "Refusing changes: expected '$TargetDomain', detected '$CurrentDomain'."
}

if (-not $ADModuleAvailable) {

    throw "ActiveDirectory PowerShell module is required."
}

if (-not $GPOModuleAvailable) {

    throw "GroupPolicy PowerShell module is required."
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Domain = Get-ADDomain
$DomainName = $Domain.DNSRoot
$DomainDN = $Domain.DistinguishedName

if ($DomainName.ToLower() -ne $TargetDomain.ToLower()) {

    throw "Refusing changes: Get-ADDomain returned '$DomainName'."
}

# ===========================================================================
# Create GPO idempotently
# ===========================================================================

Write-Step "Creating GPO: `"$GpoName`"..."

$GPO = Get-GPO `
    -Name $GpoName `
    -ErrorAction SilentlyContinue

if ($null -eq $GPO) {

    $GPO = New-GPO `
        -Name $GpoName `
        -Comment "MedDefense Advanced Audit Policy and Windows security telemetry baseline."

    Write-Host "    CREATED"
}
else {

    Write-Host "    ALREADY EXISTS"
}

# ===========================================================================
# Advanced Audit Policy GPO storage
#
# Advanced Audit Policy configuration is stored inside the GPO in:
#
# Machine\Microsoft\Windows NT\Audit\audit.csv
#
# This allows granular Advanced Audit Policy configuration to be distributed
# through Group Policy rather than modifying only the local audit policy.
# ===========================================================================

$GpoGuid = $GPO.Id.ToString("B").ToUpper()

$GpoPath = "\\$DomainName\SYSVOL\$DomainName\Policies\$GpoGuid"

$AuditDirectory = Join-Path `
    $GpoPath `
    "Machine\Microsoft\Windows NT\Audit"

$AuditCsv = Join-Path `
    $AuditDirectory `
    "audit.csv"

if (-not (Test-Path $AuditDirectory)) {

    New-Item `
        -Path $AuditDirectory `
        -ItemType Directory `
        -Force |
    Out-Null
}

# ---------------------------------------------------------------------------
# Audit CSV content
#
# The GPO consumes audit.csv to distribute Advanced Audit Policy.
# Success=1 and Failure=1 enable the corresponding audit direction.
# ---------------------------------------------------------------------------

$AuditRows = @(
    '"Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting","Setting Value"'
)

foreach ($Target in $AuditTargets) {

    if (
        $Target.SuccessEnabled -and
        $Target.FailureEnabled
    ) {

        $SettingValue = 3
        $Inclusion = "Success and Failure"
    }
    elseif ($Target.SuccessEnabled) {

        $SettingValue = 1
        $Inclusion = "Success"
    }
    elseif ($Target.FailureEnabled) {

        $SettingValue = 2
        $Inclusion = "Failure"
    }
    else {

        $SettingValue = 0
        $Inclusion = "No Auditing"
    }

    $AuditRows += (
        '"","System","{0}","","{1}","","{2}"' -f `
            $Target.Subcategory,
            $Inclusion,
            $SettingValue
    )
}

[System.IO.File]::WriteAllLines(
    $AuditCsv,
    $AuditRows,
    [System.Text.UTF8Encoding]::new($true)
)

Write-Host ""

Write-Step "Configuring Audit Categories..."

foreach ($Target in $AuditTargets) {

    Write-Host `
        "    $($Target.Subcategory): $($Target.Expected) [SET]"
}

# ===========================================================================
# Enable command-line logging for Event ID 4688
# ===========================================================================

Write-Host ""

Write-Step "Enabling command-line in process creation events..."

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
    -Type DWord `
    -Value 1

Write-Host "    Include command line in process creation events [SET]"

# ===========================================================================
# Force Advanced Audit Policy over legacy/basic policy
# ===========================================================================

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "SCENoApplyLegacyAuditPolicy" `
    -Type DWord `
    -Value 1

Write-Host "    Advanced Audit Policy override enabled [SET]"

# ===========================================================================
# Restrict Security log clearing
#
# The Security Event Log channel access descriptor is centrally controlled
# through Group Policy.
#
# This prevents ordinary users from receiving permissions that would allow
# Security log management or clearing.
# ===========================================================================

Write-Host ""

Write-Step "Restricting Security log clearing..."

$SecurityChannelSDDL = `
    "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)"

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
    -ValueName "ChannelAccess" `
    -Type String `
    -Value $SecurityChannelSDDL

Write-Host "    Security log clearing restricted to authorized administrators [SET]"

# ===========================================================================
# Security log maximum size - 1 GB
# ===========================================================================

Write-Host ""

Write-Step "Setting Security log max size to 1 GB..."

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" `
    -ValueName "MaxSize" `
    -Type DWord `
    -Value $SecurityLogSizeBytes

Write-Host "    Security log max size: 1 GB [SET]"

# ===========================================================================
# Link GPO idempotently
# ===========================================================================

Write-Host ""

Write-Step "Linking GPO to domain root..."

$Inheritance = Get-GPInheritance `
    -Target $DomainDN

$ExistingLink = @(
    $Inheritance.GpoLinks |
    Where-Object {
        $_.DisplayName -eq $GpoName
    }
)

if ($ExistingLink.Count -eq 0) {

    New-GPLink `
        -Name $GpoName `
        -Target $DomainDN `
        -LinkEnabled Yes |
    Out-Null

    Write-Host "    LINKED"
}
else {

    Write-Host "    ALREADY LINKED"
}

# ===========================================================================
# Force Group Policy update
# ===========================================================================

Write-Step "Forcing Group Policy update..."

gpupdate.exe /force |
    Out-Null

Write-Host "    COMPLETE"

# ===========================================================================
# VERIFY applied configuration
# ===========================================================================

Write-Host ""
Write-Step "VERIFY audit policy using auditpol /get /category:*"

Start-Sleep -Seconds 2

$EffectiveAuditPolicy = @(
    Get-AuditPolicySafe
)

$VerificationFailures = 0

foreach ($Target in $AuditTargets) {

    $Result = Test-AuditSetting `
        -AuditPolicy $EffectiveAuditPolicy `
        -Subcategory $Target.Subcategory `
        -RequireSuccess $Target.SuccessEnabled `
        -RequireFailure $Target.FailureEnabled

    if ($Result.Passed) {

        Write-Host `
            "    $($Target.Subcategory): $($Target.Expected) [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Target.Subcategory): expected $($Target.Expected) [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# VERIFY command-line logging
# ---------------------------------------------------------------------------

try {

    $CommandLineLogging = Get-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -ErrorAction Stop

    if (
        $CommandLineLogging.ProcessCreationIncludeCmdLine_Enabled -eq 1
    ) {

        Write-Host "    Command-line process logging [VERIFIED]"
    }
    else {

        Write-Host "    Command-line process logging [NOT VERIFIED]"
        $VerificationFailures++
    }
}
catch {

    Write-Host "    Command-line process logging [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY Security log size
# ---------------------------------------------------------------------------

try {

    $SecurityLog = Get-WinEvent `
        -ListLog Security `
        -ErrorAction Stop

    if (
        $SecurityLog.MaximumSizeInBytes -ge
        $SecurityLogSizeBytes
    ) {

        Write-Host "    Security log max size >= 1 GB [VERIFIED]"
    }
    else {

        Write-Host "    Security log max size [NOT VERIFIED]"
        $VerificationFailures++
    }
}
catch {

    Write-Host "    Security log max size [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# Final status
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host "[VERIFIED] MedDefense Advanced Audit Policy validation: PASS"
    exit 0
}
else {

    Write-Host "[NOT VERIFIED] MedDefense Advanced Audit Policy validation: FAIL"
    Write-Host "[!] Failed checks: $VerificationFailures"

    exit 1
}