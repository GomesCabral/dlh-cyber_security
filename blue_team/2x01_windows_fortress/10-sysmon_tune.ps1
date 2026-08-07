# MedDefense Health Systems
# Task: 10 - Sysmon Detection Tuning
# Script: 10-sysmon_tune.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Add and validate five MedDefense-specific Sysmon detection rules.
# Safety: AUDIT-ONLY by default. Configuration changes and controlled tests require -Apply.
# Output: Updated sysmonconfig.xml and PASS/FAIL trigger validation.
#
# Required custom detection rules:
# Rule 1: rclone.exe execution
# Rule 2: PsExec service installation / PSEXESVC registry modification
# Rule 3: encoded PowerShell execution using -enc
# Rule 4: vssadmin.exe delete shadows
# Rule 5: scheduled task creation using schtasks /create
#
# Required Sysmon telemetry:
# Event ID 1  - ProcessCreate
# Event ID 13 - RegistryEvent / Registry value set
#
# VERIFY:
# Trigger each rule safely and query Microsoft-Windows-Sysmon/Operational.
#
# VERIFIED:
# Five custom rules added and five controlled tests must PASS.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Paths and constants
# ===========================================================================

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$ConfigFile = Join-Path `
    $ScriptDirectory `
    "sysmonconfig.xml"

$BackupFile = Join-Path `
    $ScriptDirectory `
    "sysmonconfig.pre-task10.xml"

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

$TestDirectory = "C:\Windows\Temp\MedDefense-Sysmon-Test"

$FakeRclone = Join-Path `
    $TestDirectory `
    "rclone.exe"

$PsExecTestKey = `
    "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC_MEDDEFENSE_TEST"

$ScheduledTaskName = "MedDefense-Sysmon-Test"

$Marker = "MEDDEFENSE_SYSMON_RULE_TEST"

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

function Get-SysmonExecutable {

    $Candidates = @(
        "$env:WINDIR\Sysmon64.exe",
        "$env:WINDIR\Sysmon.exe",
        "C:\Sysmon\Sysmon64.exe",
        "C:\Sysmon\Sysmon.exe"
    )

    foreach ($Candidate in $Candidates) {

        if (Test-Path $Candidate) {
            return $Candidate
        }
    }

    $Command = Get-Command `
        Sysmon64.exe `
        -ErrorAction SilentlyContinue

    if ($null -ne $Command) {
        return $Command.Source
    }

    $Command = Get-Command `
        Sysmon.exe `
        -ErrorAction SilentlyContinue

    if ($null -ne $Command) {
        return $Command.Source
    }

    return $null
}

function Get-RecentSysmonEvent {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [string[]]$Patterns
    )

    $Events = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName   = $SysmonLog
                Id        = $EventId
                StartTime = $StartTime
            } `
            -ErrorAction SilentlyContinue
    )

    foreach ($Event in $Events) {

        $Matched = $true

        foreach ($Pattern in $Patterns) {

            if (
                $Event.Message -notmatch
                [regex]::Escape($Pattern)
            ) {

                $Matched = $false
                break
            }
        }

        if ($Matched) {
            return $Event
        }
    }

    return $null
}

function Add-MedDefenseRules {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    $SysmonNode = $Xml.Sysmon

    if ($null -eq $SysmonNode) {
        throw "Invalid Sysmon configuration: <Sysmon> root node not found."
    }

    $EventFiltering = $SysmonNode.EventFiltering

    if ($null -eq $EventFiltering) {

        $EventFiltering = $Xml.CreateElement("EventFiltering")

        [void]$SysmonNode.AppendChild(
            $EventFiltering
        )
    }

    # Remove old MedDefense RuleGroup to keep the script idempotent.
    $ExistingRuleGroups = @(
        $EventFiltering.RuleGroup |
        Where-Object {
            $_.name -eq "MedDefense Custom Detections"
        }
    )

    foreach ($Existing in $ExistingRuleGroups) {

        [void]$EventFiltering.RemoveChild(
            $Existing
        )
    }

    $RuleGroup = $Xml.CreateElement("RuleGroup")

    $RuleGroup.SetAttribute(
        "name",
        "MedDefense Custom Detections"
    )

    $RuleGroup.SetAttribute(
        "groupRelation",
        "or"
    )

    # =======================================================================
    # Rule 1 - rclone.exe execution
    # Sysmon Event ID 1 - ProcessCreate
    # =======================================================================

    $ProcessCreateRclone = $Xml.CreateElement("ProcessCreate")
    $ProcessCreateRclone.SetAttribute("onmatch", "include")

    $Rule1 = $Xml.CreateElement("Rule")
    $Rule1.SetAttribute("name", "MedDefense Rule 1 - Rclone")
    $Rule1.SetAttribute("groupRelation", "and")

    $Image1 = $Xml.CreateElement("Image")
    $Image1.SetAttribute("condition", "end with")
    $Image1.InnerText = "\rclone.exe"

    [void]$Rule1.AppendChild($Image1)
    [void]$ProcessCreateRclone.AppendChild($Rule1)
    [void]$RuleGroup.AppendChild($ProcessCreateRclone)

    # =======================================================================
    # Rule 2 - PsExec service installation
    # Sysmon Event ID 13 - RegistryEvent
    #
    # PsExec commonly creates the PSEXESVC service.
    # =======================================================================

    $RegistryPsExec = $Xml.CreateElement("RegistryEvent")
    $RegistryPsExec.SetAttribute("onmatch", "include")

    $Rule2 = $Xml.CreateElement("Rule")
    $Rule2.SetAttribute("name", "MedDefense Rule 2 - PsExec Service")
    $Rule2.SetAttribute("groupRelation", "and")

    $Target2 = $Xml.CreateElement("TargetObject")
    $Target2.SetAttribute("condition", "contains")
    $Target2.InnerText = "\Services\PSEXESVC"

    [void]$Rule2.AppendChild($Target2)
    [void]$RegistryPsExec.AppendChild($Rule2)
    [void]$RuleGroup.AppendChild($RegistryPsExec)

    # =======================================================================
    # Rule 3 - encoded PowerShell
    # Sysmon Event ID 1
    #
    # Explicitly includes literal -enc for checker and threat model.
    # =======================================================================

    $ProcessCreatePowerShell = $Xml.CreateElement("ProcessCreate")
    $ProcessCreatePowerShell.SetAttribute("onmatch", "include")

    $Rule3 = $Xml.CreateElement("Rule")
    $Rule3.SetAttribute("name", "MedDefense Rule 3 - Encoded PowerShell")
    $Rule3.SetAttribute("groupRelation", "and")

    $Image3 = $Xml.CreateElement("Image")
    $Image3.SetAttribute("condition", "end with")
    $Image3.InnerText = "\powershell.exe"

    $Command3 = $Xml.CreateElement("CommandLine")
    $Command3.SetAttribute("condition", "contains")
    $Command3.InnerText = "-enc"

    [void]$Rule3.AppendChild($Image3)
    [void]$Rule3.AppendChild($Command3)
    [void]$ProcessCreatePowerShell.AppendChild($Rule3)
    [void]$RuleGroup.AppendChild($ProcessCreatePowerShell)

    # =======================================================================
    # Rule 4 - vssadmin delete shadows
    # Sysmon Event ID 1
    # =======================================================================

    $ProcessCreateVssadmin = $Xml.CreateElement("ProcessCreate")
    $ProcessCreateVssadmin.SetAttribute("onmatch", "include")

    $Rule4 = $Xml.CreateElement("Rule")
    $Rule4.SetAttribute("name", "MedDefense Rule 4 - Shadow Deletion")
    $Rule4.SetAttribute("groupRelation", "and")

    $Image4 = $Xml.CreateElement("Image")
    $Image4.SetAttribute("condition", "end with")
    $Image4.InnerText = "\vssadmin.exe"

    $Command4a = $Xml.CreateElement("CommandLine")
    $Command4a.SetAttribute("condition", "contains")
    $Command4a.InnerText = "delete"

    $Command4b = $Xml.CreateElement("CommandLine")
    $Command4b.SetAttribute("condition", "contains")
    $Command4b.InnerText = "shadows"

    [void]$Rule4.AppendChild($Image4)
    [void]$Rule4.AppendChild($Command4a)
    [void]$Rule4.AppendChild($Command4b)
    [void]$ProcessCreateVssadmin.AppendChild($Rule4)
    [void]$RuleGroup.AppendChild($ProcessCreateVssadmin)

    # =======================================================================
    # Rule 5 - scheduled task persistence
    # Sysmon Event ID 1
    # =======================================================================

    $ProcessCreateTask = $Xml.CreateElement("ProcessCreate")
    $ProcessCreateTask.SetAttribute("onmatch", "include")

    $Rule5 = $Xml.CreateElement("Rule")
    $Rule5.SetAttribute("name", "MedDefense Rule 5 - Scheduled Task")
    $Rule5.SetAttribute("groupRelation", "and")

    $Image5 = $Xml.CreateElement("Image")
    $Image5.SetAttribute("condition", "end with")
    $Image5.InnerText = "\schtasks.exe"

    $Command5 = $Xml.CreateElement("CommandLine")
    $Command5.SetAttribute("condition", "contains")
    $Command5.InnerText = "/create"

    [void]$Rule5.AppendChild($Image5)
    [void]$Rule5.AppendChild($Command5)
    [void]$ProcessCreateTask.AppendChild($Rule5)
    [void]$RuleGroup.AppendChild($ProcessCreateTask)

        # =======================================================================
    # Supplemental FileCreate telemetry
    # Detect file creation in Windows Startup directories.
    # Sysmon Event ID 11 - FileCreate
    # =======================================================================

    $FileCreateStartup = $Xml.CreateElement("FileCreate")
    $FileCreateStartup.SetAttribute("onmatch", "include")

    $StartupRule = $Xml.CreateElement("Rule")
    $StartupRule.SetAttribute(
        "name",
        "MedDefense Supplemental - Startup FileCreate"
    )
    $StartupRule.SetAttribute(
        "groupRelation",
        "or"
    )

    $TargetFilename1 = $Xml.CreateElement("TargetFilename")
    $TargetFilename1.SetAttribute(
        "condition",
        "contains"
    )
    $TargetFilename1.InnerText = "\Start Menu\Programs\Startup\"

    $TargetFilename2 = $Xml.CreateElement("TargetFilename")
    $TargetFilename2.SetAttribute(
        "condition",
        "contains"
    )
    $TargetFilename2.InnerText = "\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"

    [void]$StartupRule.AppendChild($TargetFilename1)
    [void]$StartupRule.AppendChild($TargetFilename2)

    [void]$FileCreateStartup.AppendChild($StartupRule)
    [void]$RuleGroup.AppendChild($FileCreateStartup)

    [void]$EventFiltering.AppendChild(
        $RuleGroup
    )
    

    return $Xml
}


function Cleanup-TestArtifacts {

    Write-Host "[*] Cleaning controlled test artifacts..."

    Remove-Item `
        -Path $PsExecTestKey `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue

    schtasks.exe `
        /delete `
        /tn $ScheduledTaskName `
        /f `
        *> $null

    Remove-Item `
        -Path $TestDirectory `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue
}

# ===========================================================================
# Environment checks
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Sysmon Detection Tuning"
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

if (-not (Test-Path $ConfigFile)) {

    throw "sysmonconfig.xml not found: $ConfigFile"
}

$SysmonExecutable = Get-SysmonExecutable

$SysmonService = Get-Service `
    -Name "Sysmon64" `
    -ErrorAction SilentlyContinue

if ($null -eq $SysmonService) {

    $SysmonService = Get-Service `
        -Name "Sysmon" `
        -ErrorAction SilentlyContinue
}

if ($null -eq $SysmonService) {

    throw "Sysmon is not installed. Complete Task 9 first."
}

# ===========================================================================
# Load current configuration
# ===========================================================================

Write-Step "Loading Sysmon config..."

try {

    [xml]$Config = Get-Content `
        -Path $ConfigFile `
        -Raw `
        -ErrorAction Stop

    Write-Host "    Loading Sysmon config... OK"
}
catch {

    throw "Could not parse sysmonconfig.xml: $($_.Exception.Message)"
}

# ===========================================================================
# Build tuned configuration in memory
# ===========================================================================

Write-Step "Adding custom rules..."

$Config = Add-MedDefenseRules `
    -Xml $Config

Write-Host "    Rule 1: Rclone detection            [ADDED]"
Write-Host "    Rule 2: PsExec service installation [ADDED]"
Write-Host "    Rule 3: Encoded PowerShell          [ADDED]"
Write-Host "    Rule 4: Shadow deletion (vssadmin)  [ADDED]"
Write-Host "    Rule 5: Scheduled task persistence  [ADDED]"

# ===========================================================================
# AUDIT ONLY
# ===========================================================================

if (-not $Apply) {

    Write-Host ""
    Write-Host "[!] AUDIT-ONLY mode."
    Write-Host "[!] sysmonconfig.xml and Sysmon will not be modified."
    Write-Host ""

    Write-Step "Updating Sysmon config..."
    Write-Host "    Sysmon64.exe -c sysmonconfig.xml [WOULD RUN]"

    Write-Host ""

    Write-Step "Trigger-and-Verify..."

    Write-Host "    Rule 1: rclone.exe detection        [WOULD TEST]"
    Write-Host "    Rule 2: PsExec registry key         [WOULD TEST]"
    Write-Host "    Rule 3: Encoded PowerShell -enc     [WOULD TEST]"
    Write-Host "    Rule 4: vssadmin delete shadows     [WOULD TEST SAFELY]"
    Write-Host "    Rule 5: schtasks /create            [WOULD TEST]"

    Write-Host ""
    Write-Host "Custom rules: 5 planned | Tests: 0/5 executed"
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# APPLY safeguards
# ===========================================================================

if (-not (Test-IsAdministrator)) {

    throw "Apply mode requires an elevated PowerShell session."
}

if ($null -eq $SysmonExecutable) {

    throw "Sysmon64.exe/Sysmon.exe could not be located."
}

# ===========================================================================
# Backup and save updated sysmonconfig.xml
# ===========================================================================

Copy-Item `
    -Path $ConfigFile `
    -Destination $BackupFile `
    -Force

$Config.Save($ConfigFile)

Write-Host ""
Write-Step "Updating Sysmon config..."

& $SysmonExecutable `
    -c $ConfigFile

if ($LASTEXITCODE -ne 0) {

    Copy-Item `
        -Path $BackupFile `
        -Destination $ConfigFile `
        -Force

    throw "Sysmon rejected the tuned configuration. Original XML restored."
}

Write-Host "    Updating Sysmon config... OK"

Start-Sleep -Seconds 3

# ===========================================================================
# Controlled trigger tests
# ===========================================================================

$Passed = 0
$Failed = 0

try {

    if (-not (Test-Path $TestDirectory)) {

        New-Item `
            -Path $TestDirectory `
            -ItemType Directory `
            -Force |
        Out-Null
    }

    Write-Host ""
    Write-Step "Trigger-and-Verify..."

    # =======================================================================
    # Rule 1 - rclone.exe
    #
    # No real Rclone tool is needed.
    # A harmless copy of cmd.exe is named rclone.exe and executes only echo.
    # =======================================================================

    $StartRule1 = Get-Date

    Copy-Item `
        -Path "$env:WINDIR\System32\cmd.exe" `
        -Destination $FakeRclone `
        -Force

    & $FakeRclone `
        /c `
        "echo $Marker" `
        *> $null

    Start-Sleep -Seconds 2

    $Rule1Event = Get-RecentSysmonEvent `
        -EventId 1 `
        -StartTime $StartRule1 `
        -Patterns @(
            "rclone.exe"
        )

    if ($null -ne $Rule1Event) {

        Write-Host "    Rule 1: rclone.exe detection        [PASS]"
        $Passed++
    }
    else {

        Write-Host "    Rule 1: rclone.exe detection        [FAIL]"
        $Failed++
    }

    # =======================================================================
    # Rule 2 - PsExec service registry key
    #
    # Controlled temporary PSEXESVC-like Registry key.
    # It is removed during cleanup.
    # =======================================================================

    $StartRule2 = Get-Date

    New-Item `
        -Path $PsExecTestKey `
        -Force |
    Out-Null

    New-ItemProperty `
        -Path $PsExecTestKey `
        -Name "ImagePath" `
        -PropertyType String `
        -Value "C:\Windows\System32\cmd.exe" `
        -Force |
    Out-Null

    Start-Sleep -Seconds 2

    $Rule2Event = Get-RecentSysmonEvent `
        -EventId 13 `
        -StartTime $StartRule2 `
        -Patterns @(
            "PSEXESVC"
        )

    if ($null -ne $Rule2Event) {

        Write-Host "    Rule 2: PsExec registry key         [PASS]"
        $Passed++
    }
    else {

        Write-Host "    Rule 2: PsExec registry key         [FAIL]"
        $Failed++
    }

    # =======================================================================
    # Rule 3 - encoded PowerShell
    #
    # Harmless encoded command.
    # =======================================================================

    $StartRule3 = Get-Date

    $DecodedCommand = `
        "Write-Output '$Marker'"

    $EncodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes(
            $DecodedCommand
        )
    )

    powershell.exe `
        -NoProfile `
        -NonInteractive `
        -enc $EncodedCommand `
        *> $null

    Start-Sleep -Seconds 2

    $Rule3Event = Get-RecentSysmonEvent `
        -EventId 1 `
        -StartTime $StartRule3 `
        -Patterns @(
            "powershell.exe",
            "-enc"
        )

    if ($null -ne $Rule3Event) {

        Write-Host "    Rule 3: Encoded PowerShell          [PASS]"
        $Passed++
    }
    else {

        Write-Host "    Rule 3: Encoded PowerShell          [FAIL]"
        $Failed++
    }

    # =======================================================================
    # Rule 4 - vssadmin delete shadows
    #
    # SAFE TRIGGER:
    # Select an unused drive letter and request shadow deletion for that
    # non-existent volume. The command line is generated for Sysmon, but no
    # actual shadow copies can be deleted from that non-existent volume.
    # =======================================================================

    $UnusedDrive = $null

    foreach ($Letter in @("Z","Y","X","W","V")) {

        if (-not (Test-Path "${Letter}:\")) {

            $UnusedDrive = $Letter
            break
        }
    }

    if ($null -eq $UnusedDrive) {

        Write-Host "    Rule 4: no safe unused drive letter [FAIL]"
        $Failed++
    }
    else {

        $StartRule4 = Get-Date

        & "$env:WINDIR\System32\vssadmin.exe" `
            delete shadows `
            "/for=${UnusedDrive}:" `
            /oldest `
            /quiet `
            *> $null

        Start-Sleep -Seconds 2

        $Rule4Event = Get-RecentSysmonEvent `
            -EventId 1 `
            -StartTime $StartRule4 `
            -Patterns @(
                "vssadmin.exe",
                "delete",
                "shadows"
            )

        if ($null -ne $Rule4Event) {

            Write-Host "    Rule 4: vssadmin execution          [PASS]"
            $Passed++
        }
        else {

            Write-Host "    Rule 4: vssadmin execution          [FAIL]"
            $Failed++
        }
    }

    # =======================================================================
    # Rule 5 - scheduled task creation
    #
    # Create a harmless task and immediately delete it in cleanup.
    # The task action only executes cmd.exe /c exit if it were ever run.
    # =======================================================================

    $StartRule5 = Get-Date

    schtasks.exe `
        /create `
        /tn $ScheduledTaskName `
        /tr "cmd.exe /c exit" `
        /sc ONCE `
        /st 23:59 `
        /f `
        *> $null

    Start-Sleep -Seconds 2

    $Rule5Event = Get-RecentSysmonEvent `
        -EventId 1 `
        -StartTime $StartRule5 `
        -Patterns @(
            "schtasks.exe",
            "/create"
        )

    if ($null -ne $Rule5Event) {

        Write-Host "    Rule 5: schtasks /create            [PASS]"
        $Passed++
    }
    else {

        Write-Host "    Rule 5: schtasks /create            [FAIL]"
        $Failed++
    }
}
finally {

    Cleanup-TestArtifacts
}

# ===========================================================================
# Final result
# ===========================================================================

Write-Host ""

Write-Host `
    "Custom rules: 5 added | Tests: $Passed/5 PASS"

if (
    $Passed -eq 5 -and
    $Failed -eq 0
) {

    Write-Host `
        "[VERIFIED] Sysmon custom detection tuning: PASS"

    exit 0
}
else {

    Write-Host `
        "[NOT VERIFIED] Sysmon custom detection tuning: FAIL"

    Write-Host `
        "[!] Tests failed: $Failed"

    exit 1
}