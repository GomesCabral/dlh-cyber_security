# MedDefense Health Systems
# Task: 13 - RDP and Remote Access Reduction
# Script: 13-rdp_hardening.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Harden Remote Desktop access, session controls, encryption and redirection settings.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Before/after RDP security state and verification evidence.
#
# Required controls:
# - Enable Network Level Authentication (NLA)
# - UserAuthentication = 1
# - Restrict RDP access to G_IT_Admins
# - Remove Domain Users from Remote Desktop Users
# - Idle timeout = 15 minutes
# - Maximum session = 8 hours
# - Highest RDP encryption level
# - Disable clipboard redirection
# - Disable drive redirection
# - Disable Remote Assistance
#
# Registry values:
# UserAuthentication
# MaxIdleTime
# MaxConnectionTime
# MinEncryptionLevel
# SecurityLayer
# fDisableClip
# fDisableCdm
# fAllowToGetHelp
#
# VERIFY:
# Verify NLA, G_IT_Admins membership, session limits, encryption,
# clipboard, drive redirection and Remote Assistance settings.
#
# VERIFIED:
# All expected RDP security settings must match the MedDefense baseline.

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

$RdpTcpPath = `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$TerminalServicesPolicyPath = `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$AuthorizedRdpGroup = "G_IT_Admins"

$RemoteDesktopUsersGroup = "Remote Desktop Users"

$DomainUsersGroup = "Domain Users"

# 15 minutes in milliseconds.
$IdleTimeoutMilliseconds = 15 * 60 * 1000

# 8 hours in milliseconds.
$MaxSessionMilliseconds = 8 * 60 * 60 * 1000

# RDP encryption:
# MinEncryptionLevel = 3 -> High
# SecurityLayer = 2      -> SSL/TLS
$HighEncryptionLevel = 3
$SslSecurityLayer = 2

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

function Get-RegistryValueSafe {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {

        $Property = Get-ItemProperty `
            -Path $Path `
            -Name $Name `
            -ErrorAction Stop

        return $Property.$Name
    }
    catch {

        return $null
    }
}

function Set-DwordPolicy {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$Value
    )

    if (-not (Test-Path $Path)) {

        New-Item `
            -Path $Path `
            -Force |
        Out-Null
    }

    New-ItemProperty `
        -Path $Path `
        -Name $Name `
        -PropertyType DWord `
        -Value $Value `
        -Force |
    Out-Null
}

function Get-RdpState {

    $State = [ordered]@{}

    # NLA
    $State.UserAuthentication = Get-RegistryValueSafe `
        -Path $RdpTcpPath `
        -Name "UserAuthentication"

    # Session limits
    $State.MaxIdleTime = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "MaxIdleTime"

    $State.MaxConnectionTime = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "MaxConnectionTime"

    # Encryption
    $State.MinEncryptionLevel = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "MinEncryptionLevel"

    $State.SecurityLayer = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "SecurityLayer"

    # Redirection
    $State.fDisableClip = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "fDisableClip"

    $State.fDisableCdm = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "fDisableCdm"

    # Remote Assistance
    $State.fAllowToGetHelp = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "fAllowToGetHelp"

    return [PSCustomObject]$State
}

function Show-RdpState {

    param(
        [Parameter(Mandatory = $true)]
        [object]$State,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Host ""
    Write-Host "[$Label] RDP Security State"

    Write-Host `
        "    UserAuthentication (NLA): $($State.UserAuthentication)"

    Write-Host `
        "    MaxIdleTime: $($State.MaxIdleTime)"

    Write-Host `
        "    MaxConnectionTime: $($State.MaxConnectionTime)"

    Write-Host `
        "    MinEncryptionLevel: $($State.MinEncryptionLevel)"

    Write-Host `
        "    SecurityLayer: $($State.SecurityLayer)"

    Write-Host `
        "    fDisableClip: $($State.fDisableClip)"

    Write-Host `
        "    fDisableCdm: $($State.fDisableCdm)"

    Write-Host `
        "    fAllowToGetHelp: $($State.fAllowToGetHelp)"
}

# ===========================================================================
# Environment validation
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense RDP and Remote Access Hardening"
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

if ($CurrentDomain.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Expected '$TargetDomain', detected '$CurrentDomain'."
}

if (-not $ADModuleAvailable) {
    throw "ActiveDirectory PowerShell module is required."
}

Import-Module ActiveDirectory

# ===========================================================================
# Validate AD groups
# ===========================================================================

$AuthorizedGroup = Get-ADGroup `
    -Identity $AuthorizedRdpGroup `
    -ErrorAction SilentlyContinue

if ($null -eq $AuthorizedGroup) {

    throw "Required Active Directory group '$AuthorizedRdpGroup' was not found."
}

$RdpGroup = Get-ADGroup `
    -Identity $RemoteDesktopUsersGroup `
    -ErrorAction SilentlyContinue

if ($null -eq $RdpGroup) {

    throw "The '$RemoteDesktopUsersGroup' group was not found."
}

# ===========================================================================
# BEFORE
# ===========================================================================

$Before = Get-RdpState

Show-RdpState `
    -State $Before `
    -Label "BEFORE"

Write-Host ""
Write-Step "Current Remote Desktop Users membership..."

$BeforeMembers = @(
    Get-ADGroupMember `
        -Identity $RemoteDesktopUsersGroup `
        -ErrorAction SilentlyContinue
)

if ($BeforeMembers.Count -eq 0) {

    Write-Host "    No explicit members"
}
else {

    foreach ($Member in $BeforeMembers) {

        Write-Host `
            "    $($Member.Name)"
    }
}

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No RDP, Registry, Active Directory or Remote Assistance settings will be changed."
    Write-Host ""

    Write-Step "Enabling NLA..."
    Write-WouldSet "UserAuthentication = 1"

    Write-Host ""

    Write-Step "Restricting to G_IT_Admins..."

    Write-Host `
        "    Remove: Domain Users from Remote Desktop Users [WOULD REMOVE]"

    Write-Host `
        "    Add: G_IT_Admins to Remote Desktop Users [WOULD ADD]"

    Write-Host ""

    Write-Step "Session limits..."

    Write-WouldSet `
        "Idle timeout: 15 min (MaxIdleTime=900000)"

    Write-WouldSet `
        "Max session: 8 hours (MaxConnectionTime=28800000)"

    Write-Host ""

    Write-Step "Encryption..."

    Write-WouldSet `
        "MinEncryptionLevel = 3 (High)"

    Write-WouldSet `
        "SecurityLayer = 2 (SSL/TLS)"

    Write-Host ""

    Write-Step "Clipboard..."

    Write-WouldSet `
        "fDisableClip = 1"

    Write-Host ""

    Write-Step "Drive redirection..."

    Write-WouldSet `
        "fDisableCdm = 1"

    Write-Host ""

    Write-Step "Remote Assistance..."

    Write-WouldSet `
        "fAllowToGetHelp = 0"

    Write-Host ""

    Write-Step "VERIFY target state..."

    Write-Host "    NLA: Required [WOULD VERIFY]"
    Write-Host "    Access: G_IT_Admins only [WOULD VERIFY]"
    Write-Host "    Idle timeout: 15 min [WOULD VERIFY]"
    Write-Host "    Max session: 8 hours [WOULD VERIFY]"
    Write-Host "    Encryption: High/SSL [WOULD VERIFY]"
    Write-Host "    Clipboard: Disabled [WOULD VERIFY]"
    Write-Host "    Drive redirection: Disabled [WOULD VERIFY]"
    Write-Host "    Remote Assistance: Disabled [WOULD VERIFY]"

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
# Enable Network Level Authentication
# ===========================================================================

Write-Host ""
Write-Step "Enabling NLA..."

Set-DwordPolicy `
    -Path $RdpTcpPath `
    -Name "UserAuthentication" `
    -Value 1

Write-Host `
    "    UserAuthentication = 1 [SET]"

# ===========================================================================
# Restrict Remote Desktop Users membership
# ===========================================================================

Write-Host ""
Write-Step "Restricting to G_IT_Admins..."

# ---------------------------------------------------------------------------
# Remove Domain Users if currently present.
# ---------------------------------------------------------------------------

$CurrentMembers = @(
    Get-ADGroupMember `
        -Identity $RemoteDesktopUsersGroup `
        -ErrorAction SilentlyContinue
)

$DomainUsersMember = @(
    $CurrentMembers |
    Where-Object {
        $_.Name -eq $DomainUsersGroup
    }
)

if ($DomainUsersMember.Count -gt 0) {

    Remove-ADGroupMember `
        -Identity $RemoteDesktopUsersGroup `
        -Members $DomainUsersMember `
        -Confirm:$false

    Write-Host `
        "    Removed: Domain Users from Remote Desktop Users [DONE]"
}
else {

    Write-Host `
        "    Domain Users not present in Remote Desktop Users [OK]"
}

# ---------------------------------------------------------------------------
# Add G_IT_Admins.
# ---------------------------------------------------------------------------

$CurrentMembers = @(
    Get-ADGroupMember `
        -Identity $RemoteDesktopUsersGroup `
        -ErrorAction SilentlyContinue
)

$AuthorizedAlreadyMember = @(
    $CurrentMembers |
    Where-Object {
        $_.Name -eq $AuthorizedRdpGroup
    }
)

if ($AuthorizedAlreadyMember.Count -eq 0) {

    Add-ADGroupMember `
        -Identity $RemoteDesktopUsersGroup `
        -Members $AuthorizedGroup

    Write-Host `
        "    Added: G_IT_Admins [SET]"
}
else {

    Write-Host `
        "    G_IT_Admins already present [OK]"
}

# ===========================================================================
# Session limits
# ===========================================================================

Write-Host ""
Write-Step "Session limits..."

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "MaxIdleTime" `
    -Value $IdleTimeoutMilliseconds

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "MaxConnectionTime" `
    -Value $MaxSessionMilliseconds

Write-Host `
    "    Idle timeout: 15 min [SET]"

Write-Host `
    "    Max session: 8 hours [SET]"

# ===========================================================================
# Encryption
# ===========================================================================

Write-Host ""
Write-Step "Encryption..."

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "MinEncryptionLevel" `
    -Value $HighEncryptionLevel

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "SecurityLayer" `
    -Value $SslSecurityLayer

Write-Host `
    "    Encryption: High/SSL [SET]"

# ===========================================================================
# Clipboard redirection
# ===========================================================================

Write-Host ""
Write-Step "Clipboard..."

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "fDisableClip" `
    -Value 1

Write-Host `
    "    Clipboard: Disabled [SET]"

# ===========================================================================
# Drive redirection
# ===========================================================================

Write-Host ""
Write-Step "Drive redirection..."

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "fDisableCdm" `
    -Value 1

Write-Host `
    "    Drive redirection: Disabled [SET]"

# ===========================================================================
# Disable Remote Assistance
# ===========================================================================

Write-Host ""
Write-Step "Remote Assistance..."

Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "fAllowToGetHelp" `
    -Value 0

# Also disable unsolicited Remote Assistance.
Set-DwordPolicy `
    -Path $TerminalServicesPolicyPath `
    -Name "fAllowUnsolicited" `
    -Value 0

Write-Host `
    "    Remote Assistance: Disabled [SET]"

# ===========================================================================
# Group Policy refresh
# ===========================================================================

Write-Host ""
Write-Step "Refreshing policy..."

gpupdate.exe /force |
    Out-Null

Write-Host "    gpupdate /force [COMPLETE]"

Start-Sleep -Seconds 2

# ===========================================================================
# AFTER
# ===========================================================================

$After = Get-RdpState

Show-RdpState `
    -State $After `
    -Label "AFTER"

# ===========================================================================
# VERIFY
# ===========================================================================

Write-Host ""
Write-Step "Verification..."

$VerificationFailures = 0

# ---------------------------------------------------------------------------
# NLA
# ---------------------------------------------------------------------------

if ($After.UserAuthentication -eq 1) {

    Write-Host "    NLA: Required [VERIFIED]"
}
else {

    Write-Host "    NLA [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Remote Desktop Users membership
# ---------------------------------------------------------------------------

$FinalMembers = @(
    Get-ADGroupMember `
        -Identity $RemoteDesktopUsersGroup `
        -ErrorAction SilentlyContinue
)

$AuthorizedFound = @(
    $FinalMembers |
    Where-Object {
        $_.Name -eq $AuthorizedRdpGroup
    }
)

$DomainUsersFound = @(
    $FinalMembers |
    Where-Object {
        $_.Name -eq $DomainUsersGroup
    }
)

if (
    $AuthorizedFound.Count -gt 0 -and
    $DomainUsersFound.Count -eq 0
) {

    Write-Host `
        "    Access: G_IT_Admins only [VERIFIED]"
}
else {

    Write-Host `
        "    Access restriction [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Idle timeout
# ---------------------------------------------------------------------------

if (
    [int64]$After.MaxIdleTime -eq
    $IdleTimeoutMilliseconds
) {

    Write-Host `
        "    Idle timeout: 15 min [VERIFIED]"
}
else {

    Write-Host `
        "    Idle timeout [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Maximum session
# ---------------------------------------------------------------------------

if (
    [int64]$After.MaxConnectionTime -eq
    $MaxSessionMilliseconds
) {

    Write-Host `
        "    Max session: 8 hours [VERIFIED]"
}
else {

    Write-Host `
        "    Max session [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

if (
    [int]$After.MinEncryptionLevel -eq 3 -and
    [int]$After.SecurityLayer -eq 2
) {

    Write-Host `
        "    Encryption: High/SSL [VERIFIED]"
}
else {

    Write-Host `
        "    Encryption [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

if ([int]$After.fDisableClip -eq 1) {

    Write-Host `
        "    Clipboard: Disabled [VERIFIED]"
}
else {

    Write-Host `
        "    Clipboard [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Drive redirection
# ---------------------------------------------------------------------------

if ([int]$After.fDisableCdm -eq 1) {

    Write-Host `
        "    Drive redirection: Disabled [VERIFIED]"
}
else {

    Write-Host `
        "    Drive redirection [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Remote Assistance
# ---------------------------------------------------------------------------

if ([int]$After.fAllowToGetHelp -eq 0) {

    Write-Host `
        "    Remote Assistance: Disabled [VERIFIED]"
}
else {

    Write-Host `
        "    Remote Assistance [NOT VERIFIED]"

    $VerificationFailures++
}

# ===========================================================================
# Before / After comparison
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Before / After RDP Security Delta"
Write-Host "=============================================="

Write-Host `
    "NLA: $($Before.UserAuthentication) -> $($After.UserAuthentication)"

Write-Host `
    "Idle timeout: $($Before.MaxIdleTime) -> $($After.MaxIdleTime)"

Write-Host `
    "Max session: $($Before.MaxConnectionTime) -> $($After.MaxConnectionTime)"

Write-Host `
    "Encryption level: $($Before.MinEncryptionLevel) -> $($After.MinEncryptionLevel)"

Write-Host `
    "Clipboard disabled: $($Before.fDisableClip) -> $($After.fDisableClip)"

Write-Host `
    "Drive redirection disabled: $($Before.fDisableCdm) -> $($After.fDisableCdm)"

Write-Host `
    "Remote Assistance: $($Before.fAllowToGetHelp) -> $($After.fAllowToGetHelp)"

# ===========================================================================
# Final result
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host `
        "[VERIFIED] RDP and remote access hardening: PASS"

    exit 0
}
else {

    Write-Host `
        "[NOT VERIFIED] RDP and remote access hardening: FAIL"

    Write-Host `
        "[!] Failed checks: $VerificationFailures"

    exit 1
}