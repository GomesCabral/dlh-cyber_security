# MedDefense Health Systems
# Task: 8 - SMB and Protocol Hardening
# Script: 8-smb_hardening.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Disable SMBv1, enforce SMB signing and encryption, and disable legacy name-resolution protocols.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Console before/after comparison and verification evidence.
#
# Required controls:
# - Check current SMB configuration
# - Disable SMBv1 server
# - Disable SMBv1 client
# - Signing Required
# - SMB Encryption
# - Disable NetBIOS over TCP/IP
# - Disable LLMNR through Group Policy
# - before / after comparison
#
# GPO:
# MedDefense - SMB and Protocol Hardening
#
# VERIFY:
# Verify SMBv1 disabled, SMB Signing required, SMB Encryption enabled,
# NetBIOS over TCP/IP disabled and LLMNR disabled.
#
# VERIFIED:
# Every hardening control must match the target state.
#
# IMPORTANT:
# Run without -Apply first.
# Use -Apply only in the authorized meddefense.local laboratory.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - SMB and Protocol Hardening"

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

function Get-Smb1FeatureState {

    $Result = [ordered]@{
        SMB1Protocol = "UNKNOWN"
        SMB1Client   = "UNKNOWN"
        SMB1Server   = "UNKNOWN"
    }

    try {

        $Feature = Get-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol `
            -ErrorAction Stop

        $Result.SMB1Protocol = [string]$Feature.State
    }
    catch {
        $Result.SMB1Protocol = "NOT AVAILABLE"
    }

    try {

        $Feature = Get-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol-Client `
            -ErrorAction Stop

        $Result.SMB1Client = [string]$Feature.State
    }
    catch {
        $Result.SMB1Client = "NOT AVAILABLE"
    }

    try {

        $Feature = Get-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol-Server `
            -ErrorAction Stop

        $Result.SMB1Server = [string]$Feature.State
    }
    catch {
        $Result.SMB1Server = "NOT AVAILABLE"
    }

    return [PSCustomObject]$Result
}

function Get-NetBIOSState {

    $Adapters = @(
        Get-CimInstance `
            -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "IPEnabled=True" `
            -ErrorAction SilentlyContinue
    )

    $Results = @()

    foreach ($Adapter in $Adapters) {

        $State = switch ($Adapter.TcpipNetbiosOptions) {

            0 { "DEFAULT" }
            1 { "ENABLED" }
            2 { "DISABLED" }

            default {
                "UNKNOWN"
            }
        }

        $Results += [PSCustomObject]@{
            Description           = $Adapter.Description
            TcpipNetbiosOptions   = $Adapter.TcpipNetbiosOptions
            NetBIOS               = $State
        }
    }

    return $Results
}

function Get-LLMNRState {

    $Path = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"

    try {

        $Value = Get-ItemProperty `
            -Path $Path `
            -Name "EnableMulticast" `
            -ErrorAction Stop

        if ($Value.EnableMulticast -eq 0) {
            return "DISABLED"
        }

        return "ENABLED"
    }
    catch {

        return "NOT CONFIGURED"
    }
}

function Get-HardeningState {

    $ServerConfiguration = Get-SmbServerConfiguration
    $ClientConfiguration = Get-SmbClientConfiguration
    $SMB1Features = Get-Smb1FeatureState
    $NetBIOS = @(Get-NetBIOSState)
    $LLMNR = Get-LLMNRState

    return [PSCustomObject]@{

        SMBv1ServerEnabled = [bool]$ServerConfiguration.EnableSMB1Protocol

        SMBv1Feature = $SMB1Features.SMB1Protocol

        SMBv1ClientFeature = $SMB1Features.SMB1Client

        SMBv1ServerFeature = $SMB1Features.SMB1Server

        ServerSigningEnabled = [bool]$ServerConfiguration.EnableSecuritySignature

        ServerSigningRequired = [bool]$ServerConfiguration.RequireSecuritySignature

        ClientSigningEnabled = [bool]$ClientConfiguration.EnableSecuritySignature

        ClientSigningRequired = [bool]$ClientConfiguration.RequireSecuritySignature

        EncryptionEnabled = [bool]$ServerConfiguration.EncryptData

        NetBIOS = $NetBIOS

        LLMNR = $LLMNR
    }
}

function Show-State {

    param(
        [Parameter(Mandatory = $true)]
        [object]$State,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Host ""
    Write-Host "[$Label] SMB Configuration"

    if ($State.SMBv1ServerEnabled) {
        Write-Host "    SMBv1: Enabled [!]"
    }
    else {
        Write-Host "    SMBv1: Disabled"
    }

    Write-Host "    SMBv1 client feature: $($State.SMBv1ClientFeature)"
    Write-Host "    SMBv1 server feature: $($State.SMBv1ServerFeature)"

    Write-Host "    Server Signing Enabled: $($State.ServerSigningEnabled)"
    Write-Host "    Server Signing Required: $($State.ServerSigningRequired)"

    Write-Host "    Client Signing Enabled: $($State.ClientSigningEnabled)"
    Write-Host "    Client Signing Required: $($State.ClientSigningRequired)"

    Write-Host "    Encryption: $($State.EncryptionEnabled)"

    foreach ($Adapter in @($State.NetBIOS)) {

        Write-Host `
            "    NetBIOS over TCP/IP [$($Adapter.Description)]: $($Adapter.NetBIOS)"
    }

    Write-Host "    LLMNR: $($State.LLMNR)"
}

# ===========================================================================
# Environment validation
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense SMB and Protocol Hardening"
Write-Host "=============================================="
Write-Host ""

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain
$CurrentDomain = [string]$ComputerSystem.Domain

$ADModuleAvailable = [bool](
    Get-Module -ListAvailable -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module -ListAvailable -Name GroupPolicy
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

# ===========================================================================
# BEFORE state
# ===========================================================================

Write-Step "Current SMB Configuration..."

$Before = Get-HardeningState

Show-State `
    -State $Before `
    -Label "BEFORE"

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No SMB, NetBIOS, LLMNR, GPO or Registry configuration will be changed."
    Write-Host ""

    Write-Step "Disabling SMBv1 (server + client)..."

    Write-WouldSet "SMBv1 server disabled"
    Write-WouldSet "SMBv1 client disabled"

    Write-Host ""

    Write-Step "Enforcing SMB Signing..."

    Write-WouldSet "Server Signing Required = True"
    Write-WouldSet "Client Signing Required = True"

    Write-Host ""

    Write-Step "Enabling SMB Encryption..."

    Write-WouldSet "EncryptData = True"

    Write-Host ""

    Write-Step "Disabling NetBIOS over TCP/IP..."

    Write-WouldSet "TcpipNetbiosOptions = 2"

    Write-Host ""

    Write-Step "Disabling LLMNR via GPO..."

    Write-WouldSet "EnableMulticast = 0"

    Write-Host ""

    Write-Step "VERIFY expected target state..."

    Write-Host "    SMBv1: Disabled [WOULD VERIFY]"
    Write-Host "    Signing: Required [WOULD VERIFY]"
    Write-Host "    Encryption: Enabled [WOULD VERIFY]"
    Write-Host "    NetBIOS over TCP/IP: Disabled [WOULD VERIFY]"
    Write-Host "    LLMNR: Disabled [WOULD VERIFY]"

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

if (-not $ADModuleAvailable) {
    throw "ActiveDirectory PowerShell module is required."
}

if (-not $GPOModuleAvailable) {
    throw "GroupPolicy PowerShell module is required."
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Domain = Get-ADDomain

if ($Domain.DNSRoot.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Get-ADDomain returned '$($Domain.DNSRoot)'."
}

$DomainDN = $Domain.DistinguishedName

# ===========================================================================
# Disable SMBv1 server
# ===========================================================================

Write-Host ""
Write-Step "Disabling SMBv1 (server + client)..."

if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {

    Set-SmbServerConfiguration `
        -EnableSMB1Protocol $false `
        -Force

    Write-Host "    SMBv1 server [DONE]"
}
else {

    Write-Host "    SMBv1 server already disabled [OK]"
}

# ===========================================================================
# Disable SMBv1 optional features
# ===========================================================================

$SMB1Features = Get-Smb1FeatureState

if ($SMB1Features.SMB1Server -eq "Enabled") {

    Disable-WindowsOptionalFeature `
        -Online `
        -FeatureName SMB1Protocol-Server `
        -NoRestart `
        -ErrorAction Stop |
    Out-Null

    Write-Host "    SMBv1 server feature [DONE]"
}
else {

    Write-Host "    SMBv1 server feature already disabled/not installed [OK]"
}

if ($SMB1Features.SMB1Client -eq "Enabled") {

    Disable-WindowsOptionalFeature `
        -Online `
        -FeatureName SMB1Protocol-Client `
        -NoRestart `
        -ErrorAction Stop |
    Out-Null

    Write-Host "    SMBv1 client feature [DONE]"
}
else {

    Write-Host "    SMBv1 client feature already disabled/not installed [OK]"
}

# ===========================================================================
# Enforce SMB Signing
# ===========================================================================

Write-Host ""
Write-Step "Enforcing SMB Signing..."

Set-SmbServerConfiguration `
    -EnableSecuritySignature $true `
    -RequireSecuritySignature $true `
    -Force

Set-SmbClientConfiguration `
    -EnableSecuritySignature $true `
    -RequireSecuritySignature $true `
    -Force

Write-Host "    SMB server Signing Required [SET]"
Write-Host "    SMB client Signing Required [SET]"

# ===========================================================================
# Enable SMB Encryption
# ===========================================================================

Write-Host ""
Write-Step "Enabling SMB Encryption..."

Set-SmbServerConfiguration `
    -EncryptData $true `
    -Force

Write-Host "    SMB Encryption = Enabled [SET]"

# ===========================================================================
# Disable NetBIOS over TCP/IP
# ===========================================================================

Write-Host ""
Write-Step "Disabling NetBIOS over TCP/IP..."

$IPAdapters = @(
    Get-CimInstance `
        -ClassName Win32_NetworkAdapterConfiguration `
        -Filter "IPEnabled=True"
)

foreach ($Adapter in $IPAdapters) {

    if ($Adapter.TcpipNetbiosOptions -ne 2) {

        $Result = Invoke-CimMethod `
            -InputObject $Adapter `
            -MethodName SetTcpipNetbios `
            -Arguments @{
                TcpipNetbiosOptions = 2
            }

        if (
            $Result.ReturnValue -eq 0 -or
            $Result.ReturnValue -eq 1
        ) {

            Write-Host `
                "    $($Adapter.Description): NetBIOS disabled [SET]"
        }
        else {

            Write-Host `
                "    $($Adapter.Description): NetBIOS disable returned $($Result.ReturnValue) [WARNING]"
        }
    }
    else {

        Write-Host `
            "    $($Adapter.Description): NetBIOS already disabled [OK]"
    }
}

# ===========================================================================
# Create LLMNR GPO
# ===========================================================================

Write-Host ""
Write-Step "Disabling LLMNR via GPO..."

$GPO = Get-GPO `
    -Name $GpoName `
    -ErrorAction SilentlyContinue

if ($null -eq $GPO) {

    $GPO = New-GPO `
        -Name $GpoName `
        -Comment "MedDefense SMB signing, SMB encryption and legacy name resolution hardening."

    Write-Host "    GPO created [CREATED]"
}
else {

    Write-Host "    GPO already exists [OK]"
}

# Turn off multicast name resolution.
# EnableMulticast = 0 disables LLMNR.

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" `
    -Type DWord `
    -Value 0

Write-Host "    LLMNR EnableMulticast = 0 [SET]"

# ===========================================================================
# Also enforce SMB security through GPO
# ===========================================================================

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RequireSecuritySignature" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" `
    -Type DWord `
    -Value 0

# ===========================================================================
# Link GPO to domain root
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

Start-Sleep -Seconds 3

# ===========================================================================
# AFTER state
# ===========================================================================

$After = Get-HardeningState

Show-State `
    -State $After `
    -Label "AFTER"

# ===========================================================================
# VERIFY before/after comparison
# ===========================================================================

Write-Host ""
Write-Step "Verification..."

$VerificationFailures = 0

# ---------------------------------------------------------------------------
# VERIFY SMBv1
# ---------------------------------------------------------------------------

if (-not $After.SMBv1ServerEnabled) {

    Write-Host "    SMBv1: Disabled [VERIFIED]"
}
else {

    Write-Host "    SMBv1: Enabled [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY Signing Required
# ---------------------------------------------------------------------------

if (
    $After.ServerSigningRequired -and
    $After.ClientSigningRequired
) {

    Write-Host "    Signing: Required [VERIFIED]"
}
else {

    Write-Host "    Signing: Not Required [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY SMB Encryption
# ---------------------------------------------------------------------------

if ($After.EncryptionEnabled) {

    Write-Host "    Encryption: Enabled [VERIFIED]"
}
else {

    Write-Host "    Encryption: Disabled [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY NetBIOS over TCP/IP
# ---------------------------------------------------------------------------

$NetBIOSFailures = @(
    $After.NetBIOS |
    Where-Object {
        $_.TcpipNetbiosOptions -ne 2
    }
)

if ($NetBIOSFailures.Count -eq 0) {

    Write-Host "    NetBIOS over TCP/IP: Disabled [VERIFIED]"
}
else {

    Write-Host "    NetBIOS over TCP/IP: Enabled on one or more adapters [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY LLMNR
# ---------------------------------------------------------------------------

if ($After.LLMNR -eq "DISABLED") {

    Write-Host "    LLMNR: Disabled [VERIFIED]"
}
else {

    Write-Host "    LLMNR: $($After.LLMNR) [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# before / after summary
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Before / After Security Delta"
Write-Host "=============================================="

Write-Host `
    "SMBv1: $($Before.SMBv1ServerEnabled) -> $($After.SMBv1ServerEnabled)"

Write-Host `
    "Server Signing Required: $($Before.ServerSigningRequired) -> $($After.ServerSigningRequired)"

Write-Host `
    "Client Signing Required: $($Before.ClientSigningRequired) -> $($After.ClientSigningRequired)"

Write-Host `
    "Encryption: $($Before.EncryptionEnabled) -> $($After.EncryptionEnabled)"

Write-Host `
    "LLMNR: $($Before.LLMNR) -> $($After.LLMNR)"

# ===========================================================================
# Final result
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host "[VERIFIED] SMB and protocol hardening: PASS"
    exit 0
}
else {

    Write-Host "[NOT VERIFIED] SMB and protocol hardening: FAIL"
    Write-Host "[!] Failed checks: $VerificationFailures"

    exit 1
}