# MedDefense Health Systems
# Task: 9 - Sysmon Deployment
# Script: 9-sysmon_deploy.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Download, install, configure and validate Sysmon telemetry.
# Safety: AUDIT-ONLY by default. Installation requires the explicit -Apply parameter.
# Output: Sysmon deployment and Event ID 11 validation evidence.
#
# Required deliverables:
# - 9-sysmon_deploy.ps1
# - sysmonconfig.xml
#
# Required controls:
# - Download Sysmon from Microsoft Sysinternals
# - Download SwiftOnSecurity Sysmon configuration
# - Install Sysmon with sysmonconfig.xml
# - Sysmon64.exe -accepteula -i sysmonconfig.xml
# - Verify Sysmon64 service is Running
# - Verify SysmonDrv driver is Loaded
# - Verify Sysmon events are generating
# - Create C:\Windows\Temp\sysmon_test.txt
# - Verify Sysmon Event ID 11 FileCreate
#
# VERIFY:
# Sysmon64 service, SysmonDrv driver, Sysmon Operational events,
# and Event ID 11 FileCreate test.
#
# VERIFIED:
# Event ID 11 must contain the controlled sysmon_test.txt file creation.
#
# OFFLINE LAB SUPPORT:
# DC01 may not have Internet access.
# The script therefore supports files staged beside this script:
# - Sysmon.zip
# - sysmonconfig.xml
#
# In online mode the script uses Invoke-WebRequest.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Paths
# ===========================================================================

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$WorkingDirectory = Join-Path `
    $env:TEMP `
    "MedDefense-Sysmon"

$SysmonZip = Join-Path `
    $WorkingDirectory `
    "Sysmon.zip"

$ExtractDirectory = Join-Path `
    $WorkingDirectory `
    "Sysmon"

$SysmonExecutable = Join-Path `
    $ExtractDirectory `
    "Sysmon64.exe"

$ConfigFile = Join-Path `
    $ScriptDirectory `
    "sysmonconfig.xml"

$LocalSysmonZip = Join-Path `
    $ScriptDirectory `
    "Sysmon.zip"

$TestFile = "C:\Windows\Temp\sysmon_test.txt"

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

# ===========================================================================
# Download sources
# ===========================================================================

# Microsoft Sysinternals Sysmon download.
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"

# SwiftOnSecurity baseline configuration.
$SwiftConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

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

function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-InternetConnection {

    try {

        $Connection = Test-NetConnection `
            -ComputerName "download.sysinternals.com" `
            -Port 443 `
            -WarningAction SilentlyContinue

        return [bool]$Connection.TcpTestSucceeded
    }
    catch {

        return $false
    }
}

function Get-SysmonService {

    $Service = Get-Service `
        -Name "Sysmon64" `
        -ErrorAction SilentlyContinue

    if ($null -eq $Service) {

        $Service = Get-Service `
            -Name "Sysmon" `
            -ErrorAction SilentlyContinue
    }

    return $Service
}

function Get-SysmonDriverState {

    # Sysmon driver normally appears as SysmonDrv.
    try {

        $Driver = Get-CimInstance `
            -ClassName Win32_SystemDriver `
            -Filter "Name='SysmonDrv'" `
            -ErrorAction Stop

        return [PSCustomObject]@{
            Found = $true
            Name = $Driver.Name
            State = $Driver.State
            Started = $Driver.Started
        }
    }
    catch {

        return [PSCustomObject]@{
            Found = $false
            Name = "SysmonDrv"
            State = "NOT FOUND"
            Started = $false
        }
    }
}

# ===========================================================================
# Environment
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Sysmon Deployment"
Write-Host "=============================================="
Write-Host ""

Write-Host "Computer: $env:COMPUTERNAME"

if ($Apply) {
    Write-Host "Mode: APPLY"
}
else {
    Write-Host "Mode: AUDIT ONLY"
}

Write-Host ""

$InternetAvailable = Test-InternetConnection

Write-Host "Internet access: $InternetAvailable"

# ===========================================================================
# Existing state
# ===========================================================================

Write-Step "Checking existing Sysmon installation..."

$ExistingService = Get-SysmonService
$ExistingDriver = Get-SysmonDriverState

if ($null -ne $ExistingService) {

    Write-Host `
        "    Service: $($ExistingService.Name) - $($ExistingService.Status)"
}
else {

    Write-Host "    Service: Sysmon64 - NOT INSTALLED"
}

Write-Host `
    "    Driver: $($ExistingDriver.Name) - $($ExistingDriver.State)"

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] Sysmon will not be downloaded or installed."
    Write-Host ""

    if ($InternetAvailable) {

        Write-Host "[*] Downloading Sysmon... [WOULD DOWNLOAD]"
        Write-Host "    Invoke-WebRequest $SysmonUrl"

        Write-Host "[*] Downloading SwiftOnSecurity config... [WOULD DOWNLOAD]"
        Write-Host "    Invoke-WebRequest $SwiftConfigUrl"
    }
    else {

        Write-Host "[*] Internet unavailable."
        Write-Host "[*] Offline installation will use:"
        Write-Host "    $LocalSysmonZip"
        Write-Host "    $ConfigFile"
    }

    Write-Host ""

    Write-Step "Installing Sysmon with config..."

    Write-Host `
        "    Sysmon64.exe -accepteula -i sysmonconfig.xml [WOULD RUN]"

    Write-Host ""

    Write-Step "VERIFY expected state..."

    Write-Host "    Service: Sysmon64 - Running [WOULD VERIFY]"
    Write-Host "    Driver: SysmonDrv - Loaded [WOULD VERIFY]"
    Write-Host "    Sysmon events generating [WOULD VERIFY]"
    Write-Host "    Event ID 11 FileCreate [WOULD VERIFY]"

    Write-Host ""
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# Apply safeguards
# ===========================================================================

if (-not (Test-IsAdministrator)) {

    throw "Apply mode requires PowerShell running as Administrator."
}

# ===========================================================================
# Create work directory
# ===========================================================================

if (-not (Test-Path $WorkingDirectory)) {

    New-Item `
        -Path $WorkingDirectory `
        -ItemType Directory `
        -Force |
    Out-Null
}

# ===========================================================================
# Obtain Sysmon
# ===========================================================================

Write-Host ""
Write-Step "Downloading Sysmon..."

if ($InternetAvailable) {

    Invoke-WebRequest `
        -Uri $SysmonUrl `
        -OutFile $SysmonZip `
        -UseBasicParsing

    Write-Host "    Downloading Sysmon... OK"
}
elseif (Test-Path $LocalSysmonZip) {

    Copy-Item `
        -Path $LocalSysmonZip `
        -Destination $SysmonZip `
        -Force

    Write-Host "    Internet unavailable - using local Sysmon.zip [OK]"
}
else {

    throw @"
Sysmon cannot be obtained.

DC01 has no Internet access and no local Sysmon.zip was found.

Download Sysmon.zip on the Windows host and place it beside:
9-sysmon_deploy.ps1

Expected path:
$LocalSysmonZip
"@
}

# ===========================================================================
# Obtain SwiftOnSecurity configuration
# ===========================================================================

Write-Step "Downloading SwiftOnSecurity config..."

if ($InternetAvailable) {

    Invoke-WebRequest `
        -Uri $SwiftConfigUrl `
        -OutFile $ConfigFile `
        -UseBasicParsing

    Write-Host "    Downloading SwiftOnSecurity config... OK"
}
elseif (Test-Path $ConfigFile) {

    Write-Host "    Internet unavailable - using local sysmonconfig.xml [OK]"
}
else {

    throw @"
sysmonconfig.xml is missing.

Download SwiftOnSecurity sysmonconfig-export.xml on the Windows host,
rename it to sysmonconfig.xml, and place it beside this script.
"@
}

# ===========================================================================
# Validate XML before installation
# ===========================================================================

Write-Step "Validating sysmonconfig.xml..."

try {

    [xml]$SysmonConfig = Get-Content `
        -Path $ConfigFile `
        -Raw `
        -ErrorAction Stop

    if ($null -eq $SysmonConfig.Sysmon) {

        throw "The XML does not contain a Sysmon root element."
    }

    Write-Host "    sysmonconfig.xml valid [OK]"
}
catch {

    throw "sysmonconfig.xml validation failed: $($_.Exception.Message)"
}

# ===========================================================================
# Extract Sysmon
# ===========================================================================

if (Test-Path $ExtractDirectory) {

    Remove-Item `
        -Path $ExtractDirectory `
        -Recurse `
        -Force
}

Expand-Archive `
    -Path $SysmonZip `
    -DestinationPath $ExtractDirectory `
    -Force

if (-not (Test-Path $SysmonExecutable)) {

    throw "Sysmon64.exe was not found after extracting Sysmon.zip."
}

# ===========================================================================
# Install or update Sysmon
# ===========================================================================

Write-Host ""
Write-Step "Installing Sysmon with config..."

$ExistingService = Get-SysmonService

if ($null -eq $ExistingService) {

    Write-Host `
        "    Sysmon64.exe -accepteula -i sysmonconfig.xml"

    & $SysmonExecutable `
        -accepteula `
        -i $ConfigFile

    if ($LASTEXITCODE -ne 0) {

        throw "Sysmon installation returned exit code $LASTEXITCODE."
    }
}
else {

    Write-Host "    Sysmon already installed - updating configuration"

    & $SysmonExecutable `
        -c $ConfigFile

    if ($LASTEXITCODE -ne 0) {

        throw "Sysmon configuration update returned exit code $LASTEXITCODE."
    }
}

Start-Sleep -Seconds 3

# ===========================================================================
# VERIFY service
# ===========================================================================

Write-Host ""
Write-Step "Verifying Sysmon service and driver..."

$VerificationFailures = 0

$SysmonService = Get-SysmonService

if (
    $null -ne $SysmonService -and
    $SysmonService.Status -eq "Running"
) {

    Write-Host `
        "    Service: $($SysmonService.Name) - Running [OK]"
}
else {

    Write-Host "    Service: Sysmon64 - NOT RUNNING [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# VERIFY driver
# ===========================================================================

$Driver = Get-SysmonDriverState

if (
    $Driver.Found -and
    (
        $Driver.State -eq "Running" -or
        $Driver.Started
    )
) {

    Write-Host "    Driver: SysmonDrv - Loaded [OK]"
}
else {

    Write-Host `
        "    Driver: SysmonDrv - $($Driver.State) [NOT VERIFIED]"

    $VerificationFailures++
}

# ===========================================================================
# VERIFY event generation
# ===========================================================================

Write-Host ""
Write-Step "Verifying event generation..."

$SixtySecondsAgo = (Get-Date).AddSeconds(-60)

$RecentEvents = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName   = $SysmonLog
            StartTime = $SixtySecondsAgo
        } `
        -ErrorAction SilentlyContinue
)

if ($RecentEvents.Count -gt 0) {

    Write-Host `
        "    Events in last 60 seconds: $($RecentEvents.Count) [OK]"
}
else {

    Write-Host `
        "    Events in last 60 seconds: 0 [WARNING]"
}

# ===========================================================================
# Controlled Event ID 11 FileCreate test
# ===========================================================================

Write-Host ""
Write-Step "Testing FileCreate detection..."

$TestStart = Get-Date

if (Test-Path $TestFile) {

    Remove-Item `
        -Path $TestFile `
        -Force `
        -ErrorAction SilentlyContinue
}

"MedDefense Sysmon FileCreate validation $(Get-Date -Format o)" |
    Set-Content `
        -Path $TestFile `
        -Encoding UTF8

Write-Host "    Created: $TestFile"

Start-Sleep -Seconds 3

# ===========================================================================
# VERIFY Event ID 11
# ===========================================================================

$Event11 = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName   = $SysmonLog
            Id        = 11
            StartTime = $TestStart
        } `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match [regex]::Escape($TestFile)
    }
)

if ($Event11.Count -gt 0) {

    Write-Host "    Event ID 11 captured [VERIFIED]"
}
else {

    Write-Host "    Event ID 11 not captured [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# Cleanup controlled test file
# ===========================================================================

Remove-Item `
    -Path $TestFile `
    -Force `
    -ErrorAction SilentlyContinue

# ===========================================================================
# Final verification
# ===========================================================================

Write-Host ""

if ($VerificationFailures -eq 0) {

    Write-Host "[VERIFIED] Sysmon deployment validation: PASS"
    exit 0
}
else {

    Write-Host "[NOT VERIFIED] Sysmon deployment validation: FAIL"
    Write-Host "[!] Failed checks: $VerificationFailures"

    exit 1
}