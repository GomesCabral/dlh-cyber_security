# name: 9-windows_attack_sim.ps1
# purpose: Execute a controlled Windows attacker simulation, record precise ground truth, and clean all test artifacts.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 9 - Windows Attacker Simulation
#
# Controlled actions:
# 1. Create support_update account
# 2. Add support_update to Administrators
# 3. Run encoded PowerShell
# 4. Create scheduled task using schtasks /create
# 5. Initiate outbound connection using Test-NetConnection
# 6. Drop harmless file in Startup directory
#
# Output:
# - windows_attack_log.json
#
# Safety:
# - Harmless payloads only
# - No destructive commands
# - No credential theft
# - No external payload download
# - All created artifacts are removed
#
# DC compatibility:
# Domain Controllers do not have normal local SAM accounts.
# On a DC, the simulation creates a temporary domain account instead.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$SimulationUser = "support_update"

$TaskName = "MedDefense-Sim-Persistence"

$StartupDirectory = `
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

$StartupFile = Join-Path `
    $StartupDirectory `
    "meddefense_simulation.txt"

$OutputFile = Join-Path `
    $PSScriptRoot `
    "windows_attack_log.json"

$SafeDestination = "1.1.1.1"
$SafeDestinationPort = 443

$Actions = @()

$AccountCreated = $false
$AdminMembershipAdded = $false
$ScheduledTaskCreated = $false
$StartupFileCreated = $false

# ============================================================================
# Helper Functions
# ============================================================================

function Get-UtcTimestamp {

    return (Get-Date).ToUniversalTime().ToString("o")
}


function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


function Test-IsDomainController {

    try {

        $ComputerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ErrorAction Stop

        # DomainRole:
        # 4 = Backup Domain Controller
        # 5 = Primary Domain Controller

        return ($ComputerSystem.DomainRole -in @(4, 5))
    }
    catch {

        return $false
    }
}


function Add-GroundTruthAction {

    param(
        [Parameter(Mandatory = $true)]
        [int]$ActionNumber,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Timestamp,

        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedDetectionSource,

        [Parameter(Mandatory = $true)]
        [string]$MitreTechnique,

        [Parameter(Mandatory = $true)]
        [string]$MitreTechniqueName,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [hashtable]$Details = @{}
    )

    $script:Actions += [PSCustomObject]@{
        action_number = $ActionNumber
        description = $Description
        timestamp = $Timestamp
        expected_detection_source = $ExpectedDetectionSource
        mitre_attack = [PSCustomObject]@{
            technique_id = $MitreTechnique
            technique_name = $MitreTechniqueName
        }
        status = $Status
        details = $Details
    }
}


function Write-ActionLine {

    param(
        [int]$Number,
        [string]$Description,
        [string]$Timestamp
    )

    Write-Host (
        "    [{0}/6] {1,-44} {2}" -f `
        $Number,
        $Description,
        $Timestamp
    )
}

# ============================================================================
# Preconditions
# ============================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Attacker Simulation"
Write-Host "=============================================="
Write-Host ""

if (-not (Test-IsAdministrator)) {

    Write-Host "[FAIL] Run this script from an elevated PowerShell session."

    exit 1
}

$IsDomainController = Test-IsDomainController

Write-Host "[*] Running Windows attacker simulation..."

if ($IsDomainController) {

    Write-Host "    Host type: Domain Controller"
    Write-Host "    Account mode: temporary DOMAIN account"
}
else {

    Write-Host "    Host type: Member server/workstation"
    Write-Host "    Account mode: temporary LOCAL account"
}

Write-Host ""

# ============================================================================
# ACTION 1
# Create user
#
# Expected telemetry:
# Security Event ID 4720 - User account created
#
# MITRE:
# T1136 - Create Account
# ============================================================================

try {

    if ($IsDomainController) {

        Import-Module ActiveDirectory `
            -ErrorAction Stop

        $ExistingUser = Get-ADUser `
            -Filter "SamAccountName -eq '$SimulationUser'" `
            -ErrorAction SilentlyContinue

        if ($null -ne $ExistingUser) {

            throw "Account '$SimulationUser' already exists."
        }

        $RandomPassword = ConvertTo-SecureString `
            (
                "MdSim!" +
                [guid]::NewGuid().ToString("N").Substring(0, 16) +
                "9a"
            ) `
            -AsPlainText `
            -Force

        New-ADUser `
            -Name $SimulationUser `
            -SamAccountName $SimulationUser `
            -AccountPassword $RandomPassword `
            -Enabled $true `
            -PasswordNeverExpires $false `
            -ChangePasswordAtLogon $false `
            -Description "MedDefense controlled telemetry simulation" `
            -ErrorAction Stop

        $AccountMethod = "domain"
    }
    else {

        if (
            Get-LocalUser `
                -Name $SimulationUser `
                -ErrorAction SilentlyContinue
        ) {

            throw "Local account '$SimulationUser' already exists."
        }

        $RandomPassword = ConvertTo-SecureString `
            (
                "MdSim!" +
                [guid]::NewGuid().ToString("N").Substring(0, 16) +
                "9a"
            ) `
            -AsPlainText `
            -Force

        New-LocalUser `
            -Name $SimulationUser `
            -Password $RandomPassword `
            -Description "MedDefense controlled telemetry simulation" `
            -AccountNeverExpires `
            -ErrorAction Stop

        $AccountMethod = "local"
    }

    $AccountCreated = $true

    $Timestamp = Get-UtcTimestamp

    Write-ActionLine `
        -Number 1 `
        -Description "Creating user 'support_update'..." `
        -Timestamp $Timestamp

    Add-GroundTruthAction `
        -ActionNumber 1 `
        -Description "Created temporary support_update account" `
        -Timestamp $Timestamp `
        -ExpectedDetectionSource @(
            "Security Event ID 4720",
            "Sysmon Event ID 1"
        ) `
        -MitreTechnique "T1136" `
        -MitreTechniqueName "Create Account" `
        -Status "executed" `
        -Details @{
            account = $SimulationUser
            account_type = $AccountMethod
        }
}
catch {

    Write-Host "    [FAIL] Action 1: $($_.Exception.Message)"
    throw
}

# ============================================================================
# ACTION 2
# Add account to Administrators
#
# Expected telemetry:
# Security Event ID 4732
#
# MITRE:
# T1098 - Account Manipulation
# ============================================================================

try {

    if ($IsDomainController) {

        $AdministratorsGroup = Get-ADGroup `
            -Identity "Administrators" `
            -ErrorAction Stop

        Add-ADGroupMember `
            -Identity $AdministratorsGroup `
            -Members $SimulationUser `
            -ErrorAction Stop
    }
    else {

        Add-LocalGroupMember `
            -Group "Administrators" `
            -Member $SimulationUser `
            -ErrorAction Stop
    }

    $AdminMembershipAdded = $true

    $Timestamp = Get-UtcTimestamp

    Write-ActionLine `
        -Number 2 `
        -Description "Adding to Administrators group..." `
        -Timestamp $Timestamp

    Add-GroundTruthAction `
        -ActionNumber 2 `
        -Description "Added support_update to Administrators group" `
        -Timestamp $Timestamp `
        -ExpectedDetectionSource @(
            "Security Event ID 4732",
            "Sysmon Event ID 1"
        ) `
        -MitreTechnique "T1098" `
        -MitreTechniqueName "Account Manipulation" `
        -Status "executed" `
        -Details @{
            account = $SimulationUser
            group = "Administrators"
        }
}
catch {

    Write-Host "    [FAIL] Action 2: $($_.Exception.Message)"
    throw
}

# ============================================================================
# ACTION 3
# Encoded PowerShell
#
# Harmless payload:
# Write-Host "C2 beacon"
#
# Expected telemetry:
# Sysmon Event ID 1
# PowerShell Event ID 4104
# Security Event ID 4688
#
# MITRE:
# T1059.001 - PowerShell
# T1027 - Obfuscated/Compressed Files and Information
# ============================================================================

try {

    $Payload = 'Write-Host "C2 beacon"'

    $EncodedPayload = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Payload)
    )

    $PowerShellExecutable = Join-Path `
        $PSHOME `
        "powershell.exe"

    & $PowerShellExecutable `
        -NoProfile `
        -NonInteractive `
        -enc $EncodedPayload

    if ($LASTEXITCODE -ne 0) {

        throw "Encoded PowerShell returned exit code $LASTEXITCODE."
    }

    $Timestamp = Get-UtcTimestamp

    Write-ActionLine `
        -Number 3 `
        -Description "Running encoded PowerShell..." `
        -Timestamp $Timestamp

    Add-GroundTruthAction `
        -ActionNumber 3 `
        -Description "Executed harmless encoded PowerShell payload" `
        -Timestamp $Timestamp `
        -ExpectedDetectionSource @(
            "Sysmon Event ID 1",
            "PowerShell Event ID 4104",
            "Security Event ID 4688"
        ) `
        -MitreTechnique "T1059.001" `
        -MitreTechniqueName "PowerShell" `
        -Status "executed" `
        -Details @{
            payload = $Payload
            encoded_command = $EncodedPayload
        }
}
catch {

    Write-Host "    [FAIL] Action 3: $($_.Exception.Message)"
    throw
}

# ============================================================================
# ACTION 4
# Scheduled Task Persistence
#
# Required trigger:
# schtasks /create
#
# The task only executes:
# cmd.exe /c exit 0
#
# Expected telemetry:
# Security Event ID 4698
# Sysmon Event ID 1
#
# MITRE:
# T1053.005 - Scheduled Task
# ============================================================================

try {

    $TaskCommand = "cmd.exe /c exit 0"

    $null = & "$env:SystemRoot\System32\schtasks.exe" `
        /Create `
        /TN $TaskName `
        /SC ONLOGON `
        /TR $TaskCommand `
        /F

    if ($LASTEXITCODE -ne 0) {

        throw "schtasks /create returned exit code $LASTEXITCODE."
    }

    $ScheduledTaskCreated = $true

    $Timestamp = Get-UtcTimestamp

    Write-ActionLine `
        -Number 4 `
        -Description "Creating scheduled task..." `
        -Timestamp $Timestamp

    Add-GroundTruthAction `
        -ActionNumber 4 `
        -Description "Created controlled scheduled task persistence artifact" `
        -Timestamp $Timestamp `
        -ExpectedDetectionSource @(
            "Security Event ID 4698",
            "Sysmon Event ID 1"
        ) `
        -MitreTechnique "T1053.005" `
        -MitreTechniqueName "Scheduled Task/Job: Scheduled Task" `
        -Status "executed" `
        -Details @{
            task_name = $TaskName
            command = $TaskCommand
        }
}
catch {

    Write-Host "    [FAIL] Action 4: $($_.Exception.Message)"
    throw
}

# ============================================================================
# ACTION 5
# Outbound Network Connection
#
# Safe test destination:
# 1.1.1.1 TCP/443
#
# Expected telemetry:
# Sysmon Event ID 3
#
# MITRE:
# T1071 - Application Layer Protocol
# ============================================================================

try {

    $NetworkResult = Test-NetConnection `
        -ComputerName $SafeDestination `
        -Port $SafeDestinationPort `
        -InformationLevel Detailed `
        -WarningAction SilentlyContinue

    $Timestamp = Get-UtcTimestamp

    Write-ActionLine `
        -Number 5 `
        -Description "Outbound network connection..." `
        -Timestamp $Timestamp

    Add-GroundTruthAction `
        -ActionNumber 5 `
        -Description "Initiated controlled outbound TCP connection" `
        -Timestamp $Timestamp `
        -ExpectedDetectionSource @(
            "Sysmon Event ID 3"
        ) `
        -MitreTechnique "T1071" `
        -MitreTechniqueName "Application Layer Protocol" `
        -Status "executed" `
        -Details @{
            destination_ip = $SafeDestination
            destination_port = $SafeDestinationPort
            tcp_test_succeeded = [bool]$NetworkResult.TcpTestSucceeded
        }
}
catch {

    Write-Host "    [FAIL] Action 5: $($_.Exception.Message)"
    throw
}

# ============================================================================
# ACTION 6
# Startup Directory File
#
# Expected telemetry:
# Sysmon Event ID 11
#
# MITRE:
# T1547.001 - Registry Run Keys / Startup Folder
# ============================================================================

try {

    if (-not (Test-Path $StartupDirectory)) {

        throw "Startup directory does not exist: $StartupDirectory"
    }

    $SimulationContent = @"
MedDefense controlled telemetry simulation.
This file is harmless and will be deleted automatically.
Created: $(Get-UtcTimestamp)
"@

    Set-Content `
        -Path $StartupFile `
        -Value $SimulationContent `
        -Encoding UTF8 `
        -Force

    $StartupFileCreated = $true

    $Timestamp = Get-UtcTimestamp

    Write-ActionLine `
        -Number 6 `
        -Description "Dropping file in Startup..." `
        -Timestamp $Timestamp

    Add-GroundTruthAction `
        -ActionNumber 6 `
        -Description "Dropped harmless file in Windows Startup directory" `
        -Timestamp $Timestamp `
        -ExpectedDetectionSource @(
            "Sysmon Event ID 11"
        ) `
        -MitreTechnique "T1547.001" `
        -MitreTechniqueName "Registry Run Keys / Startup Folder" `
        -Status "executed" `
        -Details @{
            target_file = $StartupFile
        }
}
catch {

    Write-Host "    [FAIL] Action 6: $($_.Exception.Message)"
    throw
}

# ============================================================================
# Build Ground Truth BEFORE Cleanup
# ============================================================================

$SimulationEnd = Get-UtcTimestamp

$Report = [ordered]@{

    metadata = [ordered]@{

        simulation = "MedDefense Windows Attacker Simulation"

        hostname = $env:COMPUTERNAME

        platform = "Windows"

        host_type = if ($IsDomainController) {
            "Domain Controller"
        }
        else {
            "Member Server or Workstation"
        }

        generated_at = $SimulationEnd

        action_count = $Actions.Count

        controlled_simulation = $true
    }

    actions = $Actions
}

$Report |
    ConvertTo-Json `
        -Depth 10 |
    Set-Content `
        -Path $OutputFile `
        -Encoding UTF8

# Validate JSON before cleanup.

$null = Get-Content `
    -Path $OutputFile `
    -Raw |
    ConvertFrom-Json

# ============================================================================
# Cleanup
# ============================================================================

Write-Host ""
Write-Host "[*] Cleaning up artifacts..."

$CleanupErrors = @()

# ---------------------------------------------------------------------------
# Startup file
# ---------------------------------------------------------------------------

if ($StartupFileCreated -and (Test-Path $StartupFile)) {

    try {

        Remove-Item `
            -Path $StartupFile `
            -Force `
            -ErrorAction Stop
    }
    catch {

        $CleanupErrors += "Startup file: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Scheduled task
# ---------------------------------------------------------------------------

if ($ScheduledTaskCreated) {

    try {

        $null = & "$env:SystemRoot\System32\schtasks.exe" `
            /Delete `
            /TN $TaskName `
            /F

        if ($LASTEXITCODE -ne 0) {

            throw "schtasks /delete returned exit code $LASTEXITCODE."
        }
    }
    catch {

        $CleanupErrors += "Scheduled task: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Administrators membership
# ---------------------------------------------------------------------------

if ($AdminMembershipAdded) {

    try {

        if ($IsDomainController) {

            Remove-ADGroupMember `
                -Identity "Administrators" `
                -Members $SimulationUser `
                -Confirm:$false `
                -ErrorAction Stop
        }
        else {

            Remove-LocalGroupMember `
                -Group "Administrators" `
                -Member $SimulationUser `
                -ErrorAction Stop
        }
    }
    catch {

        $CleanupErrors += "Administrator membership: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Temporary account
# ---------------------------------------------------------------------------

if ($AccountCreated) {

    try {

        if ($IsDomainController) {

            Remove-ADUser `
                -Identity $SimulationUser `
                -Confirm:$false `
                -ErrorAction Stop
        }
        else {

            Remove-LocalUser `
                -Name $SimulationUser `
                -ErrorAction Stop
        }
    }
    catch {

        $CleanupErrors += "User account: $($_.Exception.Message)"
    }
}

# ============================================================================
# Cleanup Summary
# ============================================================================

if ($CleanupErrors.Count -eq 0) {

    Write-Host `
        "    User removed, task deleted, file removed           [CLEAN]"
}
else {

    Write-Host "    Cleanup completed with warnings:"

    foreach ($CleanupError in $CleanupErrors) {

        Write-Host "    [WARN] $CleanupError"
    }
}

# ============================================================================
# Final Output
# ============================================================================

Write-Host ""
Write-Host "Actions executed: $($Actions.Count)"
Write-Host "Ground truth saved to: windows_attack_log.json"
Write-Host ""

if ($CleanupErrors.Count -gt 0) {

    exit 1
}

exit 0