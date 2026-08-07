# MedDefense Health Systems
# Task: 7 - Kerberos and Authentication Hardening
# Script: 7-auth_hardening.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Harden Kerberos encryption, service-account authentication, NTLM and Credential Guard configuration.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Console evidence of Kerberos, SPN, DES, RC4, AES, NTLM and Credential Guard state.
#
# Target domain:
# meddefense.local
#
# Required controls:
# - Query current Kerberos encryption types
# - Identify UseDESKeyOnly service accounts
# - Check each service account ServicePrincipalName / SPN
# - Disable DES
# - Disable RC4
# - Configure AES128 and AES256 only
# - Disable NTLMv1
# - LmCompatibilityLevel = 5
# - Credential Guard awareness
# - DeviceGuard status
# - LsaCfgFlags
#
# Kerberos encryption bitmask:
# DES_CRC = 0x01
# DES_MD5 = 0x02
# RC4     = 0x04
# AES128  = 0x08
# AES256  = 0x10
#
# AES128 + AES256 = 0x18 = 24
#
# VERIFY:
# Verify UseDESKeyOnly=False, AES128/AES256 only,
# RC4 absent, LmCompatibilityLevel=5 and Credential Guard state.
#
# VERIFIED:
# Kerberos and authentication hardening passes only if the expected
# effective security state can be confirmed.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - Authentication Hardening"

# AES128 (8) + AES256 (16)
$AESOnlyValue = 24

# Send NTLMv2 response only. Refuse LM and NTLMv1.
$TargetLmCompatibilityLevel = 5

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

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent

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
        return @("DEFAULT")
    }

    try {
        $Mask = [int]$Value
    }
    catch {
        return @("UNKNOWN")
    }

    $Types = @()

    if (($Mask -band 0x01) -ne 0) {
        $Types += "DES_CRC"
    }

    if (($Mask -band 0x02) -ne 0) {
        $Types += "DES_MD5"
    }

    if (($Mask -band 0x04) -ne 0) {
        $Types += "RC4"
    }

    if (($Mask -band 0x08) -ne 0) {
        $Types += "AES128"
    }

    if (($Mask -band 0x10) -ne 0) {
        $Types += "AES256"
    }

    if ($Types.Count -eq 0) {
        $Types += "NONE"
    }

    return $Types
}

function Get-CredentialGuardStatus {

    $Result = [ordered]@{
        deviceguard_available            = $false
        virtualization_based_security    = "UNKNOWN"
        credential_guard                 = "UNKNOWN"
        services_running                 = @()
        services_configured              = @()
        LsaCfgFlags                      = $null
    }

    # -----------------------------------------------------------------------
    # DeviceGuard / Credential Guard effective state
    # -----------------------------------------------------------------------

    try {

        $DeviceGuard = Get-CimInstance `
            -Namespace "root\Microsoft\Windows\DeviceGuard" `
            -ClassName Win32_DeviceGuard `
            -ErrorAction Stop

        $Result.deviceguard_available = $true

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

        # DeviceGuard Security Service 1 = Credential Guard
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

        $Result.deviceguard_available = $false
        $Result.virtualization_based_security = "NOT_ASSESSED"
        $Result.credential_guard = "NOT_ASSESSED"
    }

    # -----------------------------------------------------------------------
    # LsaCfgFlags - Credential Guard policy awareness
    # -----------------------------------------------------------------------

    try {

        $LsaPolicy = Get-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LsaCfgFlags" `
            -ErrorAction Stop

        $Result.LsaCfgFlags = $LsaPolicy.LsaCfgFlags
    }
    catch {

        $Result.LsaCfgFlags = $null
    }

    return [PSCustomObject]$Result
}

# ===========================================================================
# Environment detection
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Kerberos and Authentication Hardening"
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

# ===========================================================================
# Safety prerequisites
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
# Query service accounts
# ===========================================================================

Write-Step "Querying current Kerberos encryption types..."

$ServiceAccounts = @(
    Get-ADUser `
        -Filter * `
        -Properties `
            Enabled,
            ServicePrincipalName,
            UseDESKeyOnly,
            TrustedForDelegation,
            PasswordLastSet,
            LastLogonDate,
            msDS-SupportedEncryptionTypes,
            DistinguishedName |
    Where-Object {
        $_.SamAccountName -match "(?i)^svc_" -or
        $_.DistinguishedName -match "(?i)OU=Service Accounts"
    }
)

# ===========================================================================
# Current Kerberos encryption state
# ===========================================================================

$ObservedTypes = @()

foreach ($Account in $ServiceAccounts) {

    $Types = @(
        Convert-KerberosEncryptionTypes `
            $Account.'msDS-SupportedEncryptionTypes'
    )

    foreach ($Type in $Types) {

        if (
            $Type -ne "DEFAULT" -and
            $Type -ne "UNKNOWN"
        ) {
            $ObservedTypes += $Type
        }
    }
}

$ObservedTypes = @(
    $ObservedTypes |
    Sort-Object -Unique
)

Write-Host ""

if ($ObservedTypes.Count -gt 0) {

    Write-Host "[*] Current Kerberos types: $($ObservedTypes -join ', ')"
}
else {

    Write-Host "[*] Current Kerberos types: domain/account defaults in use"
}

if ($ObservedTypes -match "DES") {

    Write-Host "    [!] DES enabled - weak legacy encryption"
}

if ($ObservedTypes -contains "RC4") {

    Write-Host "    [!] RC4 enabled - Kerberoasting risk"
}

# ===========================================================================
# Accounts with DES flag
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

    Write-Host "    No service account with UseDESKeyOnly=True detected."
}
else {

    foreach ($Account in $DESAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): UseDESKeyOnly = True [!]"
    }
}

# ===========================================================================
# Service Principal Names / SPNs
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

        Write-Host `
            "    $($Account.SamAccountName): $SPN"
    }
}

if ($SPNAccounts.Count -gt 0) {

    Write-Host ""
    Write-Host `
        "    [!] $($SPNAccounts.Count) service account(s) with SPNs are Kerberoastable targets."

    Write-Host `
        "    [!] SPNs are legitimate, but weak encryption/passwords increase Kerberoasting risk."
}

# ===========================================================================
# TrustedForDelegation awareness
# ===========================================================================

Write-Host ""
Write-Step "Checking unconstrained delegation..."

$DelegationAccounts = @(
    $ServiceAccounts |
    Where-Object {
        $_.TrustedForDelegation -eq $true
    }
)

if ($DelegationAccounts.Count -eq 0) {

    Write-Host "    TrustedForDelegation=True: none detected"
}
else {

    foreach ($Account in $DelegationAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): TrustedForDelegation=True [!]"
    }
}

# ===========================================================================
# NTLM current policy
# ===========================================================================

Write-Host ""
Write-Step "Checking NTLM configuration..."

$CurrentLmCompatibilityLevel = $null

try {

    $NTLMPolicy = Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" `
        -ErrorAction Stop

    $CurrentLmCompatibilityLevel = [int]$NTLMPolicy.LmCompatibilityLevel

    Write-Host `
        "    LmCompatibilityLevel=$CurrentLmCompatibilityLevel"
}
catch {

    Write-Host `
        "    LmCompatibilityLevel not explicitly configured"
}

# ===========================================================================
# Credential Guard awareness
# ===========================================================================

Write-Host ""
Write-Step "Credential Guard awareness..."

$CredentialGuard = Get-CredentialGuardStatus

Write-Host `
    "    DeviceGuard available: $($CredentialGuard.deviceguard_available)"

Write-Host `
    "    Credential Guard: $($CredentialGuard.credential_guard)"

Write-Host `
    "    VBS: $($CredentialGuard.virtualization_based_security)"

if ($null -eq $CredentialGuard.LsaCfgFlags) {

    Write-Host "    LsaCfgFlags: NOT CONFIGURED"
}
else {

    Write-Host `
        "    LsaCfgFlags: $($CredentialGuard.LsaCfgFlags)"
}

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] No Active Directory, Kerberos, RC4, DES, NTLM or GPO settings will be changed."
    Write-Host ""

    Write-Step "Remediating..."

    foreach ($Account in $DESAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): Clearing UseDESKeyOnly [WOULD DO]"
    }

    foreach ($Account in $SPNAccounts) {

        Write-Host `
            "    $($Account.SamAccountName): SupportedEncryptionTypes = AES128 + AES256 [WOULD SET]"
    }

    Write-WouldSet "Domain Kerberos SupportedEncryptionTypes = AES128 + AES256"
    Write-WouldSet "DES disabled"
    Write-WouldSet "RC4 disabled"
    Write-WouldSet "LmCompatibilityLevel=5"
    Write-WouldSet "NTLMv1 refused; NTLMv2 fallback only"

    Write-Host ""

    Write-Step "VERIFY target state..."

    Write-Host "    UseDESKeyOnly = False [WOULD VERIFY]"
    Write-Host "    Kerberos: AES128, AES256 only [WOULD VERIFY]"
    Write-Host "    RC4 absent [WOULD VERIFY]"
    Write-Host "    DES absent [WOULD VERIFY]"
    Write-Host "    LmCompatibilityLevel = 5 [WOULD VERIFY]"
    Write-Host "    NTLM: v2 only [WOULD VERIFY]"
    Write-Host "    Credential Guard / DeviceGuard / LsaCfgFlags [CHECKED]"

    Write-Host ""
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# APPLY mode safeguards
# ===========================================================================

if (-not (Test-IsAdministrator)) {
    throw "Apply mode requires PowerShell running as Administrator."
}

if (-not $GPOModuleAvailable) {
    throw "GroupPolicy PowerShell module is required."
}

Import-Module GroupPolicy

$DomainDN = $Domain.DistinguishedName

# ===========================================================================
# Disable DES on flagged service accounts
# ===========================================================================

Write-Host ""
Write-Step "Remediating..."

foreach ($Account in $DESAccounts) {

    Set-ADAccountControl `
        -Identity $Account.DistinguishedName `
        -UseDESKeyOnly $false

    Write-Host `
        "    $($Account.SamAccountName): Clearing DES flag [DONE]"
}

# ===========================================================================
# Set AES128 + AES256 on service accounts with SPNs
# ===========================================================================

foreach ($Account in $SPNAccounts) {

    Set-ADUser `
        -Identity $Account.DistinguishedName `
        -Replace @{
            "msDS-SupportedEncryptionTypes" = $AESOnlyValue
        }

    Write-Host `
        "    $($Account.SamAccountName): Supported encryption = AES128 + AES256 [SET]"
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
        -Comment "MedDefense AES-only Kerberos and NTLMv2 authentication baseline."

    Write-Host "    CREATED"
}
else {

    Write-Host "    ALREADY EXISTS"
}

# ===========================================================================
# Kerberos AES-only
#
# SupportedEncryptionTypes:
# 24 decimal = 0x18 = AES128 + AES256
#
# DES and RC4 are omitted.
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
# NTLM hardening
#
# LmCompatibilityLevel = 5
# Send NTLMv2 response only.
# Refuse LM.
# Refuse NTLMv1.
# ===========================================================================

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LmCompatibilityLevel" `
    -Type DWord `
    -Value $TargetLmCompatibilityLevel

Write-Host `
    "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"

Write-Host `
    "    NTLMv2: allowed as fallback [SET]"

# ===========================================================================
# Credential Guard awareness
#
# This task configures awareness/validation only.
#
# LsaCfgFlags is inspected, but Credential Guard is NOT blindly enabled
# because VBS / hypervisor compatibility must be validated first.
# ===========================================================================

Write-Host ""
Write-Step "Configuring Credential Guard awareness..."

$CredentialGuard = Get-CredentialGuardStatus

Write-Host `
    "    DeviceGuard available: $($CredentialGuard.deviceguard_available)"

Write-Host `
    "    Credential Guard: $($CredentialGuard.credential_guard)"

Write-Host `
    "    VBS: $($CredentialGuard.virtualization_based_security)"

if ($null -eq $CredentialGuard.LsaCfgFlags) {

    Write-Host "    LsaCfgFlags: NOT CONFIGURED"
}
else {

    Write-Host `
        "    LsaCfgFlags: $($CredentialGuard.LsaCfgFlags)"
}

Write-Host `
    "    Credential Guard awareness recorded [OK]"

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
# VERIFY
# ===========================================================================

Write-Host ""
Write-Step "VERIFY Kerberos and authentication configuration..."

$VerificationFailures = 0

# ---------------------------------------------------------------------------
# VERIFY UseDESKeyOnly
# ---------------------------------------------------------------------------

foreach ($Account in $DESAccounts) {

    $VerifiedAccount = Get-ADUser `
        -Identity $Account.DistinguishedName `
        -Properties UseDESKeyOnly

    if ($VerifiedAccount.UseDESKeyOnly -eq $false) {

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
# VERIFY AES128 + AES256 for SPN service accounts
# ---------------------------------------------------------------------------

foreach ($Account in $SPNAccounts) {

    $VerifiedAccount = Get-ADUser `
        -Identity $Account.DistinguishedName `
        -Properties msDS-SupportedEncryptionTypes

    $EncryptionValue = [int](
        $VerifiedAccount.'msDS-SupportedEncryptionTypes'
    )

    $CurrentTypes = @(
        Convert-KerberosEncryptionTypes `
            $EncryptionValue
    )

    if (
        $EncryptionValue -eq $AESOnlyValue -and
        $CurrentTypes -contains "AES128" -and
        $CurrentTypes -contains "AES256" -and
        $CurrentTypes -notcontains "RC4" -and
        $CurrentTypes -notmatch "DES"
    ) {

        Write-Host `
            "    $($Account.SamAccountName): AES128, AES256 only [VERIFIED]"
    }
    else {

        Write-Host `
            "    $($Account.SamAccountName): $($CurrentTypes -join ', ') [NOT VERIFIED]"

        $VerificationFailures++
    }
}

# ---------------------------------------------------------------------------
# VERIFY domain Kerberos policy
# ---------------------------------------------------------------------------

try {

    $KerberosPolicy = Get-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "SupportedEncryptionTypes" `
        -ErrorAction Stop

    $KerberosValue = [int]$KerberosPolicy.SupportedEncryptionTypes

    $KerberosTypes = @(
        Convert-KerberosEncryptionTypes `
            $KerberosValue
    )

    if (
        $KerberosValue -eq $AESOnlyValue -and
        $KerberosTypes -contains "AES128" -and
        $KerberosTypes -contains "AES256" -and
        $KerberosTypes -notcontains "RC4" -and
        $KerberosTypes -notmatch "DES"
    ) {

        Write-Host `
            "    Kerberos: AES128, AES256 only [VERIFIED]"
    }
    else {

        Write-Host `
            "    Kerberos: $($KerberosTypes -join ', ') [NOT VERIFIED]"

        $VerificationFailures++
    }
}
catch {

    Write-Host `
        "    Kerberos SupportedEncryptionTypes [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY NTLMv1 / LmCompatibilityLevel
# ---------------------------------------------------------------------------

try {

    $NTLMPolicy = Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" `
        -ErrorAction Stop

    if (
        [int]$NTLMPolicy.LmCompatibilityLevel -eq
        $TargetLmCompatibilityLevel
    ) {

        Write-Host `
            "    NTLM: v2 only / NTLMv1 refused [VERIFIED]"

        Write-Host `
            "    LmCompatibilityLevel = 5 [VERIFIED]"
    }
    else {

        Write-Host `
            "    LmCompatibilityLevel=$($NTLMPolicy.LmCompatibilityLevel) [NOT VERIFIED]"

        $VerificationFailures++
    }
}
catch {

    Write-Host `
        "    LmCompatibilityLevel [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# VERIFY Credential Guard awareness
# ---------------------------------------------------------------------------

$CredentialGuard = Get-CredentialGuardStatus

Write-Host `
    "    DeviceGuard: $($CredentialGuard.deviceguard_available) [CHECKED]"

Write-Host `
    "    Credential Guard: $($CredentialGuard.credential_guard) [CHECKED]"

Write-Host `
    "    VBS: $($CredentialGuard.virtualization_based_security) [CHECKED]"

if ($null -eq $CredentialGuard.LsaCfgFlags) {

    Write-Host `
        "    LsaCfgFlags: NOT CONFIGURED [CHECKED]"
}
else {

    Write-Host `
        "    LsaCfgFlags=$($CredentialGuard.LsaCfgFlags) [CHECKED]"
}

# ===========================================================================
# Final verification result
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host `
        "[VERIFIED] Kerberos and authentication hardening: PASS"

    exit 0
}
else {

    Write-Host `
        "[NOT VERIFIED] Kerberos and authentication hardening: FAIL"

    Write-Host `
        "[!] Failed checks: $VerificationFailures"

    exit 1
}