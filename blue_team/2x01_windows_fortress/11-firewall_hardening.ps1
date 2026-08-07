# MedDefense Health Systems
# Task: 11 - Windows Firewall Lockdown
# Script: 11-firewall_hardening.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Harden Windows Firewall using default-deny inbound policies and explicit service allow rules.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Before/after Windows Firewall state and verification evidence.
#
# Required profiles:
# - Domain
# - Private
# - Public
#
# Required target:
# - Enabled = True
# - DefaultInboundAction = Block
#
# Required allow rules:
# - RDP TCP 3389 from 10.10.3.0/24
# - DNS TCP/UDP 53
# - LDAP TCP 389
# - Kerberos TCP/UDP 88
# - SMB TCP 445 from 10.10.1.0/24
# - WinRM TCP 5985/5986 from 10.10.3.0/24
#
# Additional controls:
# - Enable dropped packet logging
# - Disable legacy allow rules that conflict with the MedDefense baseline
#
# VERIFY:
# Verify all 3 firewall profiles are enabled with DefaultInboundAction=Block
# and verify all MedDefense allow rules are active.
#
# VERIFIED:
# All required profiles and custom rules must match the target state.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"

$ManagementSubnet = "10.10.3.0/24"
$ServerSubnet = "10.10.1.0/24"

$RulePrefix = "MedDef-"

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

function Get-FirewallState {

    $Profiles = @(
        Get-NetFirewallProfile |
        Sort-Object Name
    )

    $Results = @()

    foreach ($Profile in $Profiles) {

        $Results += [PSCustomObject]@{
            Name                 = $Profile.Name
            Enabled              = [bool]$Profile.Enabled
            DefaultInboundAction = [string]$Profile.DefaultInboundAction
            DefaultOutboundAction = [string]$Profile.DefaultOutboundAction
            LogBlocked           = [bool]$Profile.LogBlocked
            LogAllowed           = [bool]$Profile.LogAllowed
            LogFileName          = [string]$Profile.LogFileName
            LogMaxSizeKilobytes  = [int]$Profile.LogMaxSizeKilobytes
        }
    }

    return $Results
}

function Show-FirewallState {

    param(
        [Parameter(Mandatory = $true)]
        [object[]]$State,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Host ""
    Write-Host "[$Label] Firewall State"

    foreach ($Profile in $State) {

        $OnOff = if ($Profile.Enabled) {
            "ON"
        }
        else {
            "OFF"
        }

        Write-Host `
            "    $($Profile.Name): $OnOff, DefaultInbound: $($Profile.DefaultInboundAction)"
    }
}

function Remove-MedDefenseRuleIfExists {

    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $Existing = Get-NetFirewallRule `
        -DisplayName $DisplayName `
        -ErrorAction SilentlyContinue

    if ($null -ne $Existing) {

        Remove-NetFirewallRule `
            -DisplayName $DisplayName `
            -ErrorAction SilentlyContinue
    }
}

function New-MedDefenseFirewallRule {

    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP","UDP")]
        [string]$Protocol,

        [Parameter(Mandatory = $true)]
        [string]$LocalPort,

        [string]$RemoteAddress = "Any"
    )

    Remove-MedDefenseRuleIfExists `
        -DisplayName $DisplayName

    New-NetFirewallRule `
        -DisplayName $DisplayName `
        -Direction Inbound `
        -Action Allow `
        -Enabled True `
        -Profile Any `
        -Protocol $Protocol `
        -LocalPort $LocalPort `
        -RemoteAddress $RemoteAddress |
    Out-Null
}

# ===========================================================================
# Environment validation
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Firewall Lockdown"
Write-Host "=============================================="
Write-Host ""

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain
$CurrentDomain = [string]$ComputerSystem.Domain

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

# ===========================================================================
# BEFORE
# ===========================================================================

Write-Step "Current Firewall State..."

$Before = @(
    Get-FirewallState
)

Show-FirewallState `
    -State $Before `
    -Label "BEFORE"

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No firewall rules or profiles will be modified."
    Write-Host ""

    Write-Step "Setting default-deny on all profiles..."

    Write-WouldSet "Domain: Enabled=True, DefaultInbound=Block"
    Write-WouldSet "Private: Enabled=True, DefaultInbound=Block"
    Write-WouldSet "Public: Enabled=True, DefaultInbound=Block"

    Write-Host ""

    Write-Step "Creating allow rules..."

    Write-Host "    MedDef-RDP-Mgmt: TCP 3389 from 10.10.3.0/24 [WOULD CREATE]"
    Write-Host "    MedDef-DNS-TCP: TCP 53 [WOULD CREATE]"
    Write-Host "    MedDef-DNS-UDP: UDP 53 [WOULD CREATE]"
    Write-Host "    MedDef-LDAP: TCP 389 [WOULD CREATE]"
    Write-Host "    MedDef-Kerberos-TCP: TCP 88 [WOULD CREATE]"
    Write-Host "    MedDef-Kerberos-UDP: UDP 88 [WOULD CREATE]"
    Write-Host "    MedDef-SMB: TCP 445 from 10.10.1.0/24 [WOULD CREATE]"
    Write-Host "    MedDef-WinRM-HTTP: TCP 5985 from 10.10.3.0/24 [WOULD CREATE]"
    Write-Host "    MedDef-WinRM-HTTPS: TCP 5986 from 10.10.3.0/24 [WOULD CREATE]"

    Write-Host ""

    Write-Step "Enabling dropped packet logging..."

    Write-WouldSet "LogBlocked=True"

    Write-Host ""

    Write-Step "Disabling legacy allow rules..."

    $LegacyAllowRules = @(
        Get-NetFirewallRule `
            -Direction Inbound `
            -Action Allow `
            -Enabled True `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -notlike "$RulePrefix*"
        }
    )

    Write-Host `
        "    Legacy enabled inbound allow rules detected: $($LegacyAllowRules.Count)"

    Write-Host ""

    Write-Step "VERIFY target state..."

    Write-Host "    All 3 profiles: ON, DefaultInbound: Block [WOULD VERIFY]"
    Write-Host "    RDP 3389 management-only [WOULD VERIFY]"
    Write-Host "    DNS TCP/UDP 53 [WOULD VERIFY]"
    Write-Host "    LDAP TCP 389 [WOULD VERIFY]"
    Write-Host "    Kerberos TCP/UDP 88 [WOULD VERIFY]"
    Write-Host "    SMB TCP 445 server-subnet only [WOULD VERIFY]"
    Write-Host "    WinRM TCP 5985/5986 management-only [WOULD VERIFY]"
    Write-Host "    dropped packets logging [WOULD VERIFY]"

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
# Enable all profiles + default deny inbound
# ===========================================================================

Write-Host ""
Write-Step "Setting default-deny on all profiles..."

Set-NetFirewallProfile `
    -Profile Domain,Private,Public `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

Write-Host "    Domain: ON, DefaultInbound: Block [SET]"
Write-Host "    Private: ON, DefaultInbound: Block [SET]"
Write-Host "    Public: ON, DefaultInbound: Block [SET]"

# ===========================================================================
# Create required allow rules
# ===========================================================================

Write-Host ""
Write-Step "Creating allow rules..."

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-RDP-Mgmt" `
    -Protocol TCP `
    -LocalPort "3389" `
    -RemoteAddress $ManagementSubnet

Write-Host `
    "    MedDef-RDP-Mgmt: TCP 3389 from 10.10.3.0/24 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-DNS-TCP" `
    -Protocol TCP `
    -LocalPort "53"

Write-Host `
    "    MedDef-DNS-TCP: TCP 53 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-DNS-UDP" `
    -Protocol UDP `
    -LocalPort "53"

Write-Host `
    "    MedDef-DNS-UDP: UDP 53 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-LDAP" `
    -Protocol TCP `
    -LocalPort "389"

Write-Host `
    "    MedDef-LDAP: TCP 389 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-Kerberos-TCP" `
    -Protocol TCP `
    -LocalPort "88"

Write-Host `
    "    MedDef-Kerberos-TCP: TCP 88 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-Kerberos-UDP" `
    -Protocol UDP `
    -LocalPort "88"

Write-Host `
    "    MedDef-Kerberos-UDP: UDP 88 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-SMB" `
    -Protocol TCP `
    -LocalPort "445" `
    -RemoteAddress $ServerSubnet

Write-Host `
    "    MedDef-SMB: TCP 445 from 10.10.1.0/24 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-WinRM-HTTP" `
    -Protocol TCP `
    -LocalPort "5985" `
    -RemoteAddress $ManagementSubnet

Write-Host `
    "    MedDef-WinRM-HTTP: TCP 5985 from 10.10.3.0/24 [CREATED]"

New-MedDefenseFirewallRule `
    -DisplayName "MedDef-WinRM-HTTPS" `
    -Protocol TCP `
    -LocalPort "5986" `
    -RemoteAddress $ManagementSubnet

Write-Host `
    "    MedDef-WinRM-HTTPS: TCP 5986 from 10.10.3.0/24 [CREATED]"

# ===========================================================================
# Enable dropped packet logging
# ===========================================================================

Write-Host ""
Write-Step "Enabling dropped packet logging..."

Set-NetFirewallProfile `
    -Profile Domain,Private,Public `
    -LogBlocked True `
    -LogAllowed False `
    -LogMaxSizeKilobytes 32767

Write-Host "    dropped packets logging: Enabled [SET]"

# ===========================================================================
# Disable legacy allow rules
#
# IMPORTANT:
# Instead of disabling every Windows built-in rule blindly, this section
# disables enabled inbound ALLOW rules that expose the same ports/services
# already covered by the MedDefense baseline.
#
# This avoids destroying unrelated AD/DC functionality.
# ===========================================================================

Write-Host ""
Write-Step "Disabling legacy allow rules that conflict with the new policy..."

$ProtectedPorts = @(
    "53",
    "88",
    "389",
    "445",
    "3389",
    "5985",
    "5986"
)

$LegacyRulesDisabled = 0

$CandidateRules = @(
    Get-NetFirewallRule `
        -Direction Inbound `
        -Action Allow `
        -Enabled True `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -notlike "$RulePrefix*"
    }
)

foreach ($Rule in $CandidateRules) {

    $PortFilters = @(
        $Rule |
        Get-NetFirewallPortFilter `
            -ErrorAction SilentlyContinue
    )

    $Conflict = $false

    foreach ($PortFilter in $PortFilters) {

        $Ports = @(
            [string]$PortFilter.LocalPort -split ","
        )

        foreach ($Port in $Ports) {

            if ($ProtectedPorts -contains $Port.Trim()) {
                $Conflict = $true
            }
        }
    }

    if ($Conflict) {

        Disable-NetFirewallRule `
            -Name $Rule.Name

        $LegacyRulesDisabled++
    }
}

Write-Host `
    "    Disabling $LegacyRulesDisabled legacy allow rules... [DONE]"

# ===========================================================================
# AFTER
# ===========================================================================

$After = @(
    Get-FirewallState
)

Show-FirewallState `
    -State $After `
    -Label "AFTER"

# ===========================================================================
# VERIFY
# ===========================================================================

Write-Host ""
Write-Step "Verification..."

$VerificationFailures = 0

# ---------------------------------------------------------------------------
# Verify all profiles
# ---------------------------------------------------------------------------

$BadProfiles = @(
    $After |
    Where-Object {
        -not $_.Enabled -or
        $_.DefaultInboundAction -ne "Block"
    }
)

if ($BadProfiles.Count -eq 0) {

    Write-Host `
        "    All 3 profiles: ON, DefaultInbound: Block [VERIFIED]"
}
else {

    Write-Host `
        "    One or more profiles not hardened [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Verify logging
# ---------------------------------------------------------------------------

$BadLoggingProfiles = @(
    $After |
    Where-Object {
        -not $_.LogBlocked
    }
)

if ($BadLoggingProfiles.Count -eq 0) {

    Write-Host `
        "    dropped packets logging: Enabled [VERIFIED]"
}
else {

    Write-Host `
        "    dropped packets logging [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Verify custom rules
# ---------------------------------------------------------------------------

$ExpectedRules = @(
    "MedDef-RDP-Mgmt",
    "MedDef-DNS-TCP",
    "MedDef-DNS-UDP",
    "MedDef-LDAP",
    "MedDef-Kerberos-TCP",
    "MedDef-Kerberos-UDP",
    "MedDef-SMB",
    "MedDef-WinRM-HTTP",
    "MedDef-WinRM-HTTPS"
)

$ActiveRules = @(
    Get-NetFirewallRule `
        -Enabled True `
        -Direction Inbound `
        -Action Allow `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "$RulePrefix*"
    }
)

foreach ($RuleName in $ExpectedRules) {

    $Found = @(
        $ActiveRules |
        Where-Object {
            $_.DisplayName -eq $RuleName
        }
    )

    if ($Found.Count -gt 0) {

        Write-Host `
            "    $RuleName [VERIFIED]"
    }
    else {

        Write-Host `
            "    $RuleName [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# Expected output calls them 6 service rules.
# Implementation uses separate protocol/port rules for TCP/UDP and WinRM.
# Logical services remain:
#
# 1 RDP
# 2 DNS
# 3 LDAP
# 4 Kerberos
# 5 SMB
# 6 WinRM
# ---------------------------------------------------------------------------

$LogicalServices = 6

if ($VerificationFailures -eq 0) {

    Write-Host `
        "    Custom rules: $LogicalServices active services [VERIFIED]"
}

# ===========================================================================
# Before / After comparison
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Before / After Firewall Delta"
Write-Host "=============================================="

foreach ($BeforeProfile in $Before) {

    $AfterProfile = $After |
        Where-Object {
            $_.Name -eq $BeforeProfile.Name
        } |
        Select-Object -First 1

    Write-Host `
        "$($BeforeProfile.Name): Enabled $($BeforeProfile.Enabled) -> $($AfterProfile.Enabled), DefaultInbound $($BeforeProfile.DefaultInboundAction) -> $($AfterProfile.DefaultInboundAction)"
}

# ===========================================================================
# Final result
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host `
        "[VERIFIED] Windows Firewall hardening: PASS"

    exit 0
}
else {

    Write-Host `
        "[NOT VERIFIED] Windows Firewall hardening: FAIL"

    Write-Host `
        "[!] Failed checks: $VerificationFailures"

    exit 1
}