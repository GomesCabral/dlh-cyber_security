# MedDefense Health Systems
# Task: 6 - PowerShell Security
# Script: 6-powershell_security.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Configure and validate PowerShell security logging through Group Policy.
# Safety: AUDIT-ONLY by default. Changes require the explicit -Apply parameter.
# Output: Console evidence of PowerShell logging, AMSI, GPO deployment and Event ID 4104 validation.
#
# GPO:
# MedDefense - PowerShell Security
#
# Controls:
# - Script Block Logging
# - Event ID 4104
# - Module Logging
# - Event ID 4103
# - ModuleNames = *
# - Transcription
# - OutputDirectory = C:\PSTranscripts
# - AMSI
# - encoded PowerShell validation
#
# VERIFY:
# Verify GPO settings, AMSI availability, Event ID 4104 and decoded script content.
#
# VERIFIED:
# Event ID 4104 must contain the decoded content of the controlled encoded command.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - PowerShell Security"
$TranscriptDirectory = "C:\PSTranscripts"

# Unique harmless marker used during Event ID 4104 validation.
$TestMarker = "MEDDEFENSE_PS4104_TEST"

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

function Test-AMSI {

    # PowerShell 5.x integrates with AMSI.
    # We verify that amsi.dll is available and attempt to confirm that
    # it is loaded in the current PowerShell process.

    $AmsiDllPath = Join-Path $env:WINDIR "System32\amsi.dll"

    $DllExists = Test-Path $AmsiDllPath

    $DllLoaded = $false

    try {

        $LoadedModules = @(
            (Get-Process -Id $PID -ErrorAction Stop).Modules
        )

        $DllLoaded = @(
            $LoadedModules |
            Where-Object {
                $_.ModuleName -ieq "amsi.dll"
            }
        ).Count -gt 0
    }
    catch {
        $DllLoaded = $false
    }

    return [PSCustomObject]@{
        amsi_dll_exists = $DllExists
        amsi_dll_loaded = $DllLoaded
        path            = $AmsiDllPath
    }
}

function Get-PolicyRegistryValue {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {

        $Result = Get-ItemProperty `
            -Path $Path `
            -Name $Name `
            -ErrorAction Stop

        return $Result.$Name
    }
    catch {

        return $null
    }
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
Write-Host "MedDefense PowerShell Security"
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
    Write-Host "[!] No GPO, Registry, logging or PowerShell security setting will be changed."
    Write-Host ""

    Write-Step "Creating GPO: `"$GpoName`"..."

    if ($PartOfDomain -and $GPOModuleAvailable) {

        try {

            Import-Module GroupPolicy

            $ExistingGPO = Get-GPO `
                -Name $GpoName `
                -ErrorAction SilentlyContinue

            if ($null -eq $ExistingGPO) {
                Write-Host "    GPO not present [WOULD CREATE]"
            }
            else {
                Write-Host "    GPO already exists [DETECTED]"
            }
        }
        catch {
            Write-Host "    GPO state [NOT ASSESSED]"
        }
    }
    else {
        Write-Host "    Group Policy unavailable [NOT ASSESSED]"
    }

    Write-Host ""

    Write-Step "Configuring Script Block Logging..."
    Write-WouldSet "EnableScriptBlockLogging = 1"
    Write-Host "    -> Event ID 4104 captures decoded scripts"

    Write-Host ""

    Write-Step "Configuring Module Logging..."
    Write-WouldSet "EnableModuleLogging = 1"
    Write-WouldSet "ModuleNames = *"
    Write-Host "    -> Event ID 4103 captures module invocations"

    Write-Host ""

    Write-Step "Configuring Transcription..."
    Write-WouldSet "EnableTranscripting = 1"
    Write-WouldSet "OutputDirectory = C:\PSTranscripts"
    Write-WouldSet "EnableInvocationHeader = 1"

    Write-Host ""

    Write-Step "Verifying AMSI..."

    $AmsiStatus = Test-AMSI

    if ($AmsiStatus.amsi_dll_exists) {

        if ($AmsiStatus.amsi_dll_loaded) {
            Write-Host "    AMSI DLL loaded [OK]"
        }
        else {
            Write-Host "    amsi.dll present; current process load state not confirmed [AVAILABLE]"
        }
    }
    else {
        Write-Host "    amsi.dll not found [NOT VERIFIED]"
    }

    Write-Host ""

    Write-Step "Linking GPO and forcing update..."
    Write-Host "    meddefense.local [WOULD LINK]"
    Write-Host "    gpupdate /force [WOULD RUN]"

    Write-Host ""

    Write-Step "Testing encoded command..."
    Write-Host "    Test not executed in AUDIT-ONLY mode [WOULD TEST]"
    Write-Host "    Event ID 4104 decoded content [WOULD VERIFY]"

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

if ($CurrentDomain.ToLower() -ne $TargetDomain.ToLower()) {
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

if ($Domain.DNSRoot.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Refusing changes: Get-ADDomain returned '$($Domain.DNSRoot)'."
}

$DomainDN = $Domain.DistinguishedName

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
        -Comment "MedDefense PowerShell logging, transcription and security telemetry baseline."

    Write-Host "    CREATED"
}
else {
    Write-Host "    ALREADY EXISTS"
}

# ===========================================================================
# Script Block Logging
# Event ID 4104
# ===========================================================================

Write-Host ""
Write-Step "Configuring Script Block Logging..."

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" `
    -Type DWord `
    -Value 1

Write-Host "    EnableScriptBlockLogging = 1 [SET]"
Write-Host "    -> Event ID 4104 captures decoded scripts"

# ===========================================================================
# Module Logging
# Event ID 4103
# ===========================================================================

Write-Host ""
Write-Step "Configuring Module Logging..."

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -ValueName "EnableModuleLogging" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -ValueName "*" `
    -Type String `
    -Value "*"

Write-Host "    EnableModuleLogging = 1 [SET]"
Write-Host "    ModuleNames = * [SET]"
Write-Host "    -> Event ID 4103 captures module invocations"

# ===========================================================================
# PowerShell Transcription
# ===========================================================================

Write-Host ""
Write-Step "Configuring Transcription..."

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableTranscripting" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "OutputDirectory" `
    -Type String `
    -Value $TranscriptDirectory

Set-GPRegistryValue `
    -Name $GpoName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableInvocationHeader" `
    -Type DWord `
    -Value 1

Write-Host "    EnableTranscripting = 1 [SET]"
Write-Host "    OutputDirectory = C:\PSTranscripts [SET]"
Write-Host "    EnableInvocationHeader = 1 [SET]"

# Create local transcript directory idempotently.
if (-not (Test-Path $TranscriptDirectory)) {

    New-Item `
        -Path $TranscriptDirectory `
        -ItemType Directory `
        -Force |
    Out-Null
}

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

# Give policy processing a short moment before verification.
Start-Sleep -Seconds 3

# ===========================================================================
# VERIFY effective registry policy
# ===========================================================================

Write-Host ""
Write-Step "VERIFY effective PowerShell security policy..."

$VerificationFailures = 0

$ScriptBlockValue = Get-PolicyRegistryValue `
    -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging"

if ($ScriptBlockValue -eq 1) {
    Write-Host "    EnableScriptBlockLogging = 1 [VERIFIED]"
}
else {
    Write-Host "    EnableScriptBlockLogging [NOT VERIFIED]"
    $VerificationFailures++
}

$ModuleLoggingValue = Get-PolicyRegistryValue `
    -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging"

if ($ModuleLoggingValue -eq 1) {
    Write-Host "    EnableModuleLogging = 1 [VERIFIED]"
}
else {
    Write-Host "    EnableModuleLogging [NOT VERIFIED]"
    $VerificationFailures++
}

$ModuleNamesValue = Get-PolicyRegistryValue `
    -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -Name "*"

if ($ModuleNamesValue -eq "*") {
    Write-Host "    ModuleNames = * [VERIFIED]"
}
else {
    Write-Host "    ModuleNames = * [NOT VERIFIED]"
    $VerificationFailures++
}

$TranscriptionValue = Get-PolicyRegistryValue `
    -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting"

if ($TranscriptionValue -eq 1) {
    Write-Host "    EnableTranscripting = 1 [VERIFIED]"
}
else {
    Write-Host "    EnableTranscripting [NOT VERIFIED]"
    $VerificationFailures++
}

$OutputDirectoryValue = Get-PolicyRegistryValue `
    -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory"

if ($OutputDirectoryValue -eq $TranscriptDirectory) {
    Write-Host "    OutputDirectory = C:\PSTranscripts [VERIFIED]"
}
else {
    Write-Host "    OutputDirectory [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# VERIFY AMSI
# ===========================================================================

Write-Host ""
Write-Step "Verifying AMSI..."

$AmsiStatus = Test-AMSI

if ($AmsiStatus.amsi_dll_exists) {

    if ($AmsiStatus.amsi_dll_loaded) {
        Write-Host "    AMSI DLL loaded [OK]"
    }
    else {
        Write-Host "    amsi.dll present [OK]"
    }
}
else {

    Write-Host "    AMSI [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# Controlled encoded PowerShell test
#
# Harmless command:
# Write-Host "MEDDEFENSE_PS4104_TEST"
#
# PowerShell -EncodedCommand expects UTF-16LE / Unicode Base64.
# ===========================================================================

Write-Host ""
Write-Step "Testing encoded PowerShell command..."

$DecodedCommand = "Write-Host `"$TestMarker`""

$EncodedCommand = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes(
        $DecodedCommand
    )
)

$TestStartTime = Get-Date

Write-Host "    Decoded input: $DecodedCommand"
Write-Host "    Encoded input: $EncodedCommand"

powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $EncodedCommand |
Out-Null

Start-Sleep -Seconds 3

# ===========================================================================
# VERIFY Event ID 4104
# ===========================================================================

Write-Step "VERIFY Event ID 4104..."

$PowerShellLog = "Microsoft-Windows-PowerShell/Operational"

$Event4104 = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName   = $PowerShellLog
            Id        = 4104
            StartTime = $TestStartTime
        } `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match [regex]::Escape($TestMarker)
    }
)

if ($Event4104.Count -gt 0) {

    Write-Host "    Event ID 4104 found"
    Write-Host "    Decoded content found: $DecodedCommand [VERIFIED]"
}
else {

    Write-Host "    Event ID 4104 decoded content [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# Optional Event ID 4103 verification
# ===========================================================================

Write-Step "Checking Event ID 4103 Module Logging..."

$Event4103 = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName   = $PowerShellLog
            Id        = 4103
            StartTime = $TestStartTime
        } `
        -ErrorAction SilentlyContinue
)

if ($Event4103.Count -gt 0) {

    Write-Host "    Event ID 4103 generated [VERIFIED]"
}
else {

    Write-Host "    Event ID 4103 not observed during controlled test [INFO]"
}

# ===========================================================================
# Final status
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host "[VERIFIED] MedDefense PowerShell Security validation: PASS"
    exit 0
}
else {

    Write-Host "[NOT VERIFIED] MedDefense PowerShell Security validation: FAIL"
    Write-Host "[!] Failed checks: $VerificationFailures"

    exit 1
}