# MedDefense Health Systems
# Task: 4 - Password and Lockout Policy
# Script: 4-password_policy.ps1
# Author: Pedro Cabral
# Date: 2026-08-05
# Purpose: Deploy and validate the MedDefense password and account lockout policy.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Console validation of the configured password and lockout policy.
#
# GPO:
# MedDefense - Password and Lockout Policy
#
# Password Policy:
# Minimum Length: 14
# Complexity: Enabled
# History: 24
# Maximum Age: 0
# Minimum Age: 1 day
#
# Account Lockout:
# Lockout Threshold: 5 attempts
# Lockout Duration: 15 minutes
# Reset Counter: 15 minutes
#
# IMPORTANT:
# Do NOT run this script with -Apply on a personal standalone workstation.
#
# Safe execution:
# powershell.exe -ExecutionPolicy Bypass -File .\4-password_policy.ps1
#
# Production/lab execution:
# powershell.exe -ExecutionPolicy Bypass -File .\4-password_policy.ps1 -Apply

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - Password and Lockout Policy"

# ---------------------------------------------------------------------------
# Target state
# ---------------------------------------------------------------------------

$MinimumPasswordLength = 14
$PasswordComplexity = 1
$PasswordHistorySize = 24
$MaximumPasswordAge = 0
$MinimumPasswordAge = 1

$LockoutThreshold = 5
$LockoutDuration = 15
$ResetLockoutCount = 15

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Write-Step {
    param(
        [string]$Message
    )

    Write-Host "[*] $Message"
}

function Write-Set {
    param(
        [string]$Message
    )

    Write-Host "    $Message [SET]"
}

function Write-WouldSet {
    param(
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

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

$ComputerSystem = Get-CimInstance Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain
$CurrentDomain = [string]$ComputerSystem.Domain

$ADModuleAvailable = [bool](
    Get-Module -ListAvailable -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module -ListAvailable -Name GroupPolicy
)

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Password and Lockout Policy"
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

# ---------------------------------------------------------------------------
# AUDIT-ONLY MODE
# ---------------------------------------------------------------------------

if (-not $Apply) {

    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No Group Policy, password policy, account lockout policy,"
    Write-Host "[!] Active Directory or Windows security settings will be changed."
    Write-Host ""

    Write-Step "Creating GPO: `"$GpoName`"..."

    if ($GPOModuleAvailable -and $PartOfDomain) {

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
            Write-Host "    GPO status could not be assessed [NOT ASSESSED]"
        }
    }
    else {
        Write-Host "    Active Directory / Group Policy unavailable [WOULD CREATE]"
    }

    Write-Host ""

    Write-Step "Configuring Password Policy..."

    Write-WouldSet "Minimum Length: 14"
    Write-WouldSet "Complexity: Enabled"
    Write-WouldSet "History: 24"
    Write-WouldSet "Maximum Age: 0"
    Write-WouldSet "Minimum Age: 1 day"

    Write-Host ""

    Write-Step "Configuring Account Lockout..."

    Write-WouldSet "Threshold: 5 attempts"
    Write-WouldSet "Duration: 15 minutes"
    Write-WouldSet "Reset Counter: 15 minutes"

    Write-Host ""

    Write-Step "Linking GPO to domain root..."
    Write-Host "    $TargetDomain [WOULD LINK]"

    Write-Step "Forcing Group Policy update..."
    Write-Host "    gpupdate /force [WOULD RUN]"

    Write-Host ""

    Write-Step "Effective policy verification..."

    if (
        $PartOfDomain -and
        $ADModuleAvailable
    ) {

        try {

            Import-Module ActiveDirectory

            $CurrentPolicy = Get-ADDefaultDomainPasswordPolicy

            Write-Host "    Current Minimum Length: $($CurrentPolicy.MinPasswordLength)"
            Write-Host "    Current Complexity: $($CurrentPolicy.ComplexityEnabled)"
            Write-Host "    Current History: $($CurrentPolicy.PasswordHistoryCount)"
            Write-Host "    Current Maximum Age: $($CurrentPolicy.MaxPasswordAge.TotalDays)"
            Write-Host "    Current Minimum Age: $($CurrentPolicy.MinPasswordAge.TotalDays)"
            Write-Host "    Current Lockout Threshold: $($CurrentPolicy.LockoutThreshold)"
            Write-Host "    Current Lockout Duration: $($CurrentPolicy.LockoutDuration.TotalMinutes)"
            Write-Host "    Current Reset Counter: $($CurrentPolicy.LockoutObservationWindow.TotalMinutes)"
        }
        catch {

            Write-Host "    Effective domain policy [NOT ASSESSED]"
        }
    }
    else {

        Write-Host "    Effective domain policy [NOT ASSESSED]"
        Write-Host "    Reason: meddefense.local is unavailable."
    }

    Write-Host ""
    Write-Host "[*] Audit complete."
    Write-Host "[*] System modified: False"

    exit 0
}

# ---------------------------------------------------------------------------
# APPLY MODE SAFETY CHECKS
# ---------------------------------------------------------------------------

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

    throw "Refusing changes: expected domain '$TargetDomain', detected '$CurrentDomain'."
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

if ($DomainName.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Refusing changes: Get-ADDomain returned '$DomainName'."
}

# ---------------------------------------------------------------------------
# Create GPO idempotently
# ---------------------------------------------------------------------------

Write-Step "Creating GPO: `"$GpoName`"..."

$GPO = Get-GPO `
    -Name $GpoName `
    -ErrorAction SilentlyContinue

if ($null -eq $GPO) {

    $GPO = New-GPO `
        -Name $GpoName `
        -Comment "MedDefense CIS-aligned password and account lockout baseline."

    Write-Host "    CREATED"
}
else {

    Write-Host "    ALREADY EXISTS"
}

# ---------------------------------------------------------------------------
# Configure GPO security template
#
# Password/account policies are Security Settings, not ordinary registry-
# based Administrative Template values. They are stored in the GPO security
# template (GptTmpl.inf).
# ---------------------------------------------------------------------------

$GpoGuid = $GPO.Id.ToString("B").ToUpper()

$PolicyPath = "\\$DomainName\SYSVOL\$DomainName\Policies\$GpoGuid"

$SecurityDirectory = Join-Path `
    $PolicyPath `
    "Machine\Microsoft\Windows NT\SecEdit"

$SecurityTemplate = Join-Path `
    $SecurityDirectory `
    "GptTmpl.inf"

if (-not (Test-Path $SecurityDirectory)) {

    New-Item `
        -Path $SecurityDirectory `
        -ItemType Directory `
        -Force |
    Out-Null
}

# ---------------------------------------------------------------------------
# Desired GPO security template
# ---------------------------------------------------------------------------

$SecurityTemplateContent = @"
[Unicode]
Unicode=yes

[Version]
signature="`$CHICAGO`$"
Revision=1

[System Access]
MinimumPasswordAge = $MinimumPasswordAge
MaximumPasswordAge = $MaximumPasswordAge
MinimumPasswordLength = $MinimumPasswordLength
PasswordComplexity = $PasswordComplexity
PasswordHistorySize = $PasswordHistorySize
LockoutBadCount = $LockoutThreshold
ResetLockoutCount = $ResetLockoutCount
LockoutDuration = $LockoutDuration
"@

[System.IO.File]::WriteAllText(
    $SecurityTemplate,
    $SecurityTemplateContent + [Environment]::NewLine,
    [System.Text.UnicodeEncoding]::new()
)

Write-Host ""

Write-Step "Configuring Password Policy..."

Write-Set "Minimum Length: 14"
Write-Set "Complexity: Enabled"
Write-Set "History: 24"
Write-Set "Maximum Age: 0"
Write-Set "Minimum Age: 1 day"

Write-Host ""

Write-Step "Configuring Account Lockout..."

Write-Set "Threshold: 5 attempts"
Write-Set "Duration: 15 minutes"
Write-Set "Reset Counter: 15 minutes"

# ---------------------------------------------------------------------------
# Ensure GPO version changes
# ---------------------------------------------------------------------------

$GPTIni = Join-Path $PolicyPath "GPT.INI"

if (Test-Path $GPTIni) {

    $GPTContent = Get-Content $GPTIni

    $VersionLine = (
        $GPTContent |
        Select-String "^Version=" |
        Select-Object -First 1
    )

    if ($null -ne $VersionLine) {

        $CurrentVersion = [int](
            $VersionLine.Line.Split("=")[1]
        )

        $NewVersion = $CurrentVersion + 1

        $GPTContent = $GPTContent -replace `
            "^Version=.*", `
            "Version=$NewVersion"

        Set-Content `
            -Path $GPTIni `
            -Value $GPTContent `
            -Encoding Unicode
    }
}

# ---------------------------------------------------------------------------
# Link GPO to domain root idempotently
# ---------------------------------------------------------------------------

Write-Host ""
Write-Step "Linking GPO to domain root..."

$DomainDN = $Domain.DistinguishedName

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

# ---------------------------------------------------------------------------
# Force policy update
# ---------------------------------------------------------------------------

Write-Step "Forcing Group Policy update..."

gpupdate.exe /force |
    Out-Null

Write-Host "    COMPLETE"

# ---------------------------------------------------------------------------
# VERIFY effective password and lockout policy
# ---------------------------------------------------------------------------

Write-Host ""
Write-Step "Verifying effective policy..."

Start-Sleep -Seconds 2

$EffectivePolicy = Get-ADDefaultDomainPasswordPolicy

$VerificationFailures = 0

if ($EffectivePolicy.MinPasswordLength -eq 14) {
    Write-Host "    Minimum Length: 14 [PASS]"
}
else {
    Write-Host "    Minimum Length: $($EffectivePolicy.MinPasswordLength) [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.ComplexityEnabled -eq $true) {
    Write-Host "    Complexity: Enabled [PASS]"
}
else {
    Write-Host "    Complexity: Disabled [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.PasswordHistoryCount -eq 24) {
    Write-Host "    History: 24 [PASS]"
}
else {
    Write-Host "    History: $($EffectivePolicy.PasswordHistoryCount) [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.MaxPasswordAge.TotalDays -eq 0) {
    Write-Host "    Maximum Age: 0 [PASS]"
}
else {
    Write-Host "    Maximum Age: $($EffectivePolicy.MaxPasswordAge.TotalDays) [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.MinPasswordAge.TotalDays -eq 1) {
    Write-Host "    Minimum Age: 1 day [PASS]"
}
else {
    Write-Host "    Minimum Age: $($EffectivePolicy.MinPasswordAge.TotalDays) [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.LockoutThreshold -eq 5) {
    Write-Host "    Lockout Threshold: 5 [PASS]"
}
else {
    Write-Host "    Lockout Threshold: $($EffectivePolicy.LockoutThreshold) [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.LockoutDuration.TotalMinutes -eq 15) {
    Write-Host "    Lockout Duration: 15 minutes [PASS]"
}
else {
    Write-Host "    Lockout Duration: $($EffectivePolicy.LockoutDuration.TotalMinutes) [FAIL]"
    $VerificationFailures++
}

if ($EffectivePolicy.LockoutObservationWindow.TotalMinutes -eq 15) {
    Write-Host "    Reset Counter: 15 minutes [PASS]"
}
else {
    Write-Host "    Reset Counter: $($EffectivePolicy.LockoutObservationWindow.TotalMinutes) [FAIL]"
    $VerificationFailures++
}

Write-Host ""

# VERIFIED state is reached only when all effective policy checks pass.
if ($VerificationFailures -eq 0) {

    Write-Host "[VERIFIED] Password and lockout policy validation: PASS"
    exit 0
}
else {

    Write-Host "[NOT VERIFIED] Password and lockout policy validation: FAIL"
    Write-Host "[!] Failed checks: $VerificationFailures"

    exit 1
}