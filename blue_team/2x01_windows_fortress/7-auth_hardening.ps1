# MedDefense Health Systems
# Task: 7 - Kerberos and Authentication Hardening
# Script: 7-auth_hardening.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Audit, harden and verify Kerberos and Windows authentication security.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Console evidence of Kerberos, SPN, DES, RC4, NTLM and Credential Guard status.
#
# Target domain:
# meddefense.local
#
# Security objectives:
# - Identify service accounts with ServicePrincipalName (SPN)
# - Identify Kerberoastable service accounts
# - Identify UseDESKeyOnly accounts
# - Disable DES
# - Disable RC4 Kerberos at the domain controller policy level
# - Allow AES128 and AES256 only
# - Set LmCompatibilityLevel = 5 to refuse LM and NTLMv1
# - Assess Credential Guard readiness/status
#
# Kerberos encryption bit values:
# DES_CRC  = 0x01
# DES_MD5  = 0x02
# RC4      = 0x04
# AES128   = 0x08
# AES256   = 0x10
#
# AES128 + AES256:
# 0x08 + 0x10 = 0x18 = 24
#
# VERIFY:
# Verify UseDESKeyOnly, ServicePrincipalName, SupportedEncryptionTypes,
# LmCompatibilityLevel and Credential Guard state.
#
# VERIFIED:
# Kerberos should permit AES128 and AES256 only and NTLMv1 should be refused.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - Authentication Hardening"

# AES128 = 8
# AES256 = 16
# AES128 + AES256 = 24
$AESOnlyValue = 24

# NTLMv2 only. Refuse LM and NTLMv1.
$LmCompatibilityLevel = 5

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


function Convert-KerberosEncryptionTypes {

    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {

        return @(
            "DEFAULT / NOT EXPLICITLY SET"
        )
    }

    try {

        $EncryptionMask = [int]$Value
    }
    catch {

        return @(
            "UNKNOWN"
        )
    }

    $Types = @()

    if (($EncryptionMask -band 1) -ne 0) {
        $Types += "DES_CRC"
    }

    if (($EncryptionMask -band 2) -ne 0) {
        $Types += "DES_MD5"
    }

    if (($EncryptionMask -band 4) -ne 0) {
        $Types += "RC4"
    }

    if (($EncryptionMask -band 8) -ne 0) {
        $Types += "AES128"
    }

    if (($EncryptionMask -band 16) -ne 0) {
        $Types += "AES256"
    }

    if ($Types.Count -eq 0) {
        $Types += "NONE / UNKNOWN"
    }

    return $Types
}


function Get-CredentialGuardStatus {

    $Result = [ordered]@{
        available                    = $false
        virtualization_based_security = "UNKNOWN"
        credential_guard             = "UNKNOWN"
        services_running             = @()
        services_configured          = @()
    }

    try {

        $DeviceGuard = Get-CimInstance `
            -Namespace "root\Microsoft\Windows\DeviceGuard" `
            -ClassName Win32_DeviceGuard `
            -ErrorAction Stop

        $Result.available = $true

        $Result.services_running = @(
            $DeviceGuard.SecurityServicesRunning
        )

        $Result.services_configured = @(
            $DeviceGuard.SecurityServicesConfigured
        )

        if ($DeviceGuard.VirtualizationBasedSecurityStatus -eq 2) {
            $Result.virtualization_based_security = "RUNNING"
        }
        elseif ($DeviceGuard.VirtualizationBasedSecurityStatus -eq 1) {
            $Result.virtualization_based_security = "ENABLED_NOT_RUNNING"
        }
        else {
            $Result.virtualization_based_security = "NOT_ENABLED"
        }

        # Security service value 1 represents Credential Guard.
        if (@($DeviceGuard.SecurityServicesRunning) -contains 1) {
            $Result.credential_guard = "RUNNING"
        }
        elseif (@($DeviceGuard.SecurityServicesConfigured) -contains 1) {
            $Result.credential_guard = "CONFIGURED_NOT_RUNNING"
        }
        else {
            $Result.credential_guard = "NOT_CONFIGURED"
        }
    }
    catch {

        $Result.available = $false
        $Result.credential_guard = "NOT_ASSESSED"
    }

    return [PSCustomObject]$Result
}

# ===========================================================================
# Environment detection
# ===========================================================================

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
Write-Host "MedDefense Kerberos and Authentication Hardening"
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
# Prerequisite check
# ===========================================================================

if (-not $PartOfDomain) {
    throw "This computer is not joined to an Active Directory domain."
}

if ($CurrentDomain.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Expected '$TargetDomain', detected '$CurrentDomain'."
}

if (-not $ADModuleAvailable) {
    throw "ActiveDirectory PowerShell module is required."
}

Import-Module ActiveDirectory

$Domain = Get-ADDomain

if ($Domain.DNSRoot.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Get-ADDomain returned unexpected domain '$($Domain.DNSRoot)'."
}

# ===========================================================================
# Query domain and service accounts
# ===========================================================================

Write-Step "Querying current Kerberos configuration..."

$ServiceAccounts = @(
    Get-ADUser `
        -Filter * `
        -Properties `
            Enabled,
            ServicePrincipalName,
            UseDESKeyOnly,
            TrustedForDelegation,
            PasswordLastSet,
            msDS-SupportedEncryptionTypes |
    Where-Object {
        $_.SamAccountName -match "(?i)^svc_" -or
        $_.DistinguishedName -match "(?i)OU=Service Accounts"
    }
)

Write-Host ""

# ===========================================================================
# Current Kerberos encryption types
# ===========================================================================

$ObservedTypes = @()

foreach ($Account in $ServiceAccounts) {

    $AccountTypes = @(
        Convert-KerberosEncryptionTypes `
            $Account.'msDS-SupportedEncryptionTypes'
    )

    foreach ($Type in $AccountTypes) {

        if (
            $Type -notmatch "DEFAULT" -and
            $Type -notmatch "UNKNOWN"
        ) {
            $ObservedTypes += $Type
        }
    }
}

$ObservedTypes = @(
    $ObservedTypes |
    Sort-Object -Unique
)

if ($ObservedTypes.Count -gt 0) {

    Write-Host "[*] Current Kerberos types: $($ObservedTypes -join ', ')"
}
else {

    Write-Host "[*] Current Kerberos types: domain/account defaults in use"
}

if ($ObservedTypes -match "DES") {
    Write-Host "    [!] DES enabled - trivially breakable"
}

if ($ObservedTypes -contains "RC4") {
    Write-Host "    [!] RC4 enabled - Kerberoastable"
}

# ===========================================================================
# DES accounts
# ===========================================================================

Write-Host ""
Write-Step "Accounts with DES flag..."

$DESAccounts = @(
    $ServiceAccounts |
    Where-Object {
        $_.UseDESKeyOnly -eq $true
    }
)

if ($DESAccounts.Count -eq 0) {

    Write-Host "    No UseDESKeyOnly service accounts detected."
}
else {

    foreach ($Account in $DESAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): UseDESKeyOnly = True [!]"
    }
}

# ===========================================================================
# SPN assessment
# ===========================================================================

Write-Host ""
Write-Step "Service Principal Names..."

$SPNAccounts = @(
    $ServiceAccounts |
    Where-Object {
        @($_.ServicePrincipalName).Count -gt 0
    }
)

foreach ($Account in $SPNAccounts) {

    foreach ($SPN in @($Account.ServicePrincipalName)) {

        Write-Host "    $($Account.SamAccountName): $SPN"
    }
}

if ($SPNAccounts.Count -gt 0) {

    Write-Host ""
    Write-Host "    [!] $($SPNAccounts.Count) account(s) with SPNs are Kerberoastable targets."
    Write-Host "    [!] An SPN does not mean compromise; it means the account can receive service tickets."
}

# ===========================================================================
# Credential Guard awareness
# ===========================================================================

Write-Host ""
Write-Step "Credential Guard awareness..."

$CredentialGuard = Get-CredentialGuardStatus

Write-Host "    Credential Guard: $($CredentialGuard.credential_guard)"
Write-Host "    VBS: $($CredentialGuard.virtualization_based_security)"

# ===========================================================================
# AUDIT-ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No Kerberos, NTLM, Active Directory or GPO setting will be changed."
    Write-Host ""

    Write-Step "Remediating..."

    foreach ($Account in $DESAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): Clearing DES flag [WOULD DO]"
    }

    Write-WouldSet "Supported encryption: AES128 + AES256"
    Write-WouldSet "RC4 disabled"
    Write-WouldSet "DES disabled"
    Write-WouldSet "LmCompatibilityLevel=5 - NTLMv1 refused"

    Write-Host ""

    Write-Step "VERIFY target state..."

    Write-Host "    Kerberos: AES128, AES256 only [WOULD VERIFY]"
    Write-Host "    NTLM: v2 only [WOULD VERIFY]"
    Write-Host "    UseDESKeyOnly = False [WOULD VERIFY]"
    Write-Host "    Credential Guard awareness [CHECKED]"

    Write-Host ""
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# APPLY safety
# ===========================================================================

if (-not (Test-IsAdministrator)) {
    throw "Apply mode requires PowerShell running as Administrator."
}

if (-not $GPOModuleAvailable) {
    throw "GroupPolicy PowerShell module is required for Apply mode."
}

Import-Module GroupPolicy

$DomainDN = $Domain.DistinguishedName

Write-Host ""
Write-Step "Remediating..."

# ===========================================================================
# Disable DES for flagged service accounts
# ===========================================================================

foreach ($Account in $DESAccounts) {

    Write-Host `
        "    $($Account.SamAccountName): Clearing DES flag..."

    Set-ADAccountControl `
        -Identity $Account.DistinguishedName `
        -UseDESKeyOnly $false

    Write-Host `
        "    $($Account.SamAccountName): UseDESKeyOnly = False [DONE]"
}

# ===========================================================================
# Explicit AES support on SPN service accounts
#
# 24 decimal = AES128 (8) + AES256 (16)
#
# WARNING:
# Legacy services that only support RC4 may fail authentication after this
# change. This is why discovery is performed before remediation.
# ===========================================================================

foreach ($Account in $SPNAccounts) {

    Set-ADUser `
        -Identity $Account.DistinguishedName `
        -Replace @{
            "msDS-SupportedEncryptionTypes" = $AESOnlyValue
        }

    Write-Host `
        "    $($Account.SamAccountName): AES128 + AES256 [SET]"
}

# ===========================================================================
# Create authentication hardening GPO
# ===========================================================================

Write-Host ""

Write-Step "Creating GPO: `"$GpoName`"..."

$GPO = Get-GPO `
    -Name $GpoName `
    -ErrorAction SilentlyContinue

if ($null -eq $GPO) {

    $GPO = New-GPO `
        -Name $GpoName `
        -Comment "MedDefense Kerberos AES-only and NTLMv2 authentication baseline."

    Write-Host "    CREATED"
}
else {

    Write-Host "    ALREADY EXISTS"
}

# ===========================================================================
# Kerberos SupportedEncryptionTypes
#
# 0x18 = AES128 + AES256
#
# DES and RC4 are intentionally excluded.
# ===========================================================================

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -ValueName "SupportedEncryptionTypes" `
    -Type DWord `
    -Value $AESOnlyValue

Write-Host "    Supported encryption: AES128 + AES256 [SET]"
Write-Host "    DES: disabled [SET]"
Write-Host "    RC4: disabled [SET]"

# ===========================================================================
# NTLMv1 hardening
#
# LmCompatibilityLevel = 5
#
# Send NTLMv2 response only.
# Refuse LM.
# Refuse NTLMv1.
# ===========================================================================

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LmCompatibilityLevel" `
    -Type DWord `
    -Value $LmCompatibilityLevel

Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"
Write-Host "    NTLMv2: fallback allowed [SET]"

# ===========================================================================
# Credential Guard awareness
#
# Credential Guard is assessed but not blindly enabled here because it
# depends on VBS, virtualization and platform compatibility.
#
# Enabling Credential Guard on infrastructure systems without validating
# hypervisor/VBS support can create operational impact.
# ===========================================================================

Write-Host ""
Write-Step "Configuring Credential Guard awareness..."

$CredentialGuard = Get-CredentialGuardStatus

Write-Host "    Credential Guard: $($CredentialGuard.credential_guard)"
Write-Host "    VBS: $($CredentialGuard.virtualization_based_security)"
Write-Host "    Credential Guard readiness/status recorded [OK]"

# ===========================================================================
# Link GPO
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
# VERIFY
# ===========================================================================

Write-Host ""
Write-Step "VERIFY Kerberos and authentication configuration..."

$VerificationFailures = 0

# ---------------------------------------------------------------------------
# Verify DES flags
# ---------------------------------------------------------------------------

foreach ($Account in $DESAccounts) {

    $VerifiedAccount = Get-ADUser `
        -Identity $Account.DistinguishedName `
        -Properties UseDESKeyOnly

    if (-not $VerifiedAccount.UseDESKeyOnly) {

        Write-Host `
            "    $($Account.SamAccountName): UseDESKeyOnly = False [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): UseDESKeyOnly = True [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# Verify SPN service-account encryption
# ---------------------------------------------------------------------------

foreach ($Account in $SPNAccounts) {

    $VerifiedAccount = Get-ADUser `
        -Identity $Account.DistinguishedName `
        -Properties msDS-SupportedEncryptionTypes

    $EncryptionValue = [int](
        $VerifiedAccount.'msDS-SupportedEncryptionTypes'
    )

    if ($EncryptionValue -eq $AESOnlyValue) {

        Write-Host `
            "    $($Account.SamAccountName): AES128, AES256 only [VERIFIED]"
    }
    else {

        $CurrentTypes = Convert-KerberosEncryptionTypes `
            $EncryptionValue

        Write-Host `
            "    $($Account.SamAccountName): $($CurrentTypes -join ', ') [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# Verify effective Kerberos registry policy
# ---------------------------------------------------------------------------

try {

    $KerberosPolicy = Get-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "SupportedEncryptionTypes" `
        -ErrorAction Stop

    if (
        [int]$KerberosPolicy.SupportedEncryptionTypes -eq
        $AESOnlyValue
    ) {

        Write-Host "    Kerberos: AES128, AES256 only [VERIFIED]"
    }
    else {

        Write-Host "    Kerberos encryption policy [NOT VERIFIED]"
        $VerificationFailures++
    }
}
catch {

    Write-Host "    Kerberos encryption policy [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Verify NTLM
# ---------------------------------------------------------------------------

try {

    $NTLMPolicy = Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" `
        -ErrorAction Stop

    if (
        [int]$NTLMPolicy.LmCompatibilityLevel -eq 5
    ) {

        Write-Host "    NTLM: v2 only / NTLMv1 refused [VERIFIED]"
    }
    else {

        Write-Host `
            "    LmCompatibilityLevel=$($NTLMPolicy.LmCompatibilityLevel) [NOT VERIFIED]"

        $VerificationFailures++
    }
}
catch {

    Write-Host "    NTLM policy [NOT VERIFIED]"
    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Credential Guard verification
# ---------------------------------------------------------------------------

$CredentialGuard = Get-CredentialGuardStatus

Write-Host `
    "    Credential Guard: $($CredentialGuard.credential_guard) [CHECKED]"

# ===========================================================================
# Final result
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host "[VERIFIED] Kerberos and authentication hardening: PASS"
    exit 0
}
else {

    Write-Host "[NOT VERIFIED] Kerberos and authentication hardening: FAIL"
    Write-Host "[!] Failed checks: $VerificationFailures"

    exit 1
}