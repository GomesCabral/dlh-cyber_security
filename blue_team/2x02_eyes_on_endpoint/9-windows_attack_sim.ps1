<#
.SYNOPSIS
    Controlled Windows attacker-simulation ("Crimson Tide" playbook) for telemetry validation.

.DESCRIPTION
    Executes a benign, self-contained sequence of attacker-like actions against the LOCAL
    hardened endpoint only, timestamps each action precisely, and writes a ground-truth
    JSON file mapping every action to its expected detection source and MITRE ATT&CK
    technique. All artifacts created during the run are removed at the end, regardless
    of whether the run succeeded or failed partway through.

    This script performs NO malicious activity: no external payload download/execution,
    no lateral movement, no credential theft, no persistence that survives the run
    (everything is deleted in cleanup), and network egress is a single benign
    Test-NetConnection probe.

.NOTES
    Run this only on a system you own/control, and only for detection-engineering /
    telemetry-validation purposes. Requires an elevated (Administrator) PowerShell session.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$SimUser       = "support_update",
    [string]$ScheduledTask = "WindowsUpdateHelper",
    [string]$StartupFile   = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update_helper.vbs",
    [string]$OutFile       = "windows_attack_log.json",
    [string]$ProbeTarget   = "1.1.1.1"   # Cloudflare DNS - safe, well-known external IP
)

$ErrorActionPreference = "Stop"
$results = @()
$actionsExecuted = 0

function Get-UtcStamp {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Write-Step {
    param([string]$Label, [string]$Stamp)
    "    {0,-52}{1}" -f $Label, $Stamp | Write-Host
}

function Add-Result {
    param(
        [int]$ActionNumber,
        [string]$Description,
        [string]$Timestamp,
        [string]$SysmonEventId,
        [string]$SecurityEventId,
        [string]$MitreTechnique,
        [string]$MitreName,
        [string]$Status
    )
    $script:results += [pscustomobject]@{
        action_number             = $ActionNumber
        description               = $Description
        timestamp_utc              = $Timestamp
        expected_detection_source = [pscustomobject]@{
            sysmon_event_id   = $SysmonEventId
            security_event_id = $SecurityEventId
        }
        mitre_attack = [pscustomobject]@{
            technique_id = $MitreTechnique
            technique    = $MitreName
        }
        status = $Status
    }
}

Write-Host "[*] Running Windows attacker simulation..."

try {
    # ---------------------------------------------------------------
    # 1. Create local user account
    # ---------------------------------------------------------------
    $pwd = (New-Guid).ToString() + "!Aa1"
    $securePwd = ConvertTo-SecureString $pwd -AsPlainText -Force
    New-LocalUser -Name $SimUser -Password $securePwd -FullName "Support Update" `
        -Description "Telemetry validation account (temporary)" -AccountNeverExpires | Out-Null
    $stamp1 = Get-UtcStamp
    Write-Step "[1/6] Creating local user '$SimUser'..." $stamp1
    Add-Result 1 "Create local user account '$SimUser'" $stamp1 `
        "N/A (Sysmon EID 1 for net.exe/PowerShell process if used)" "4720" `
        "T1136.001" "Create Account: Local Account" "executed"
    $actionsExecuted++

    # ---------------------------------------------------------------
    # 2. Add user to Administrators group (privilege escalation)
    # ---------------------------------------------------------------
    Add-LocalGroupMember -Group "Administrators" -Member $SimUser
    $stamp2 = Get-UtcStamp
    Write-Step "[2/6] Adding to Administrators group..." $stamp2
    Add-Result 2 "Add '$SimUser' to local Administrators group" $stamp2 `
        "N/A" "4732" `
        "T1098" "Account Manipulation" "executed"
    $actionsExecuted++

    # ---------------------------------------------------------------
    # 3. Run encoded PowerShell command (harmless payload)
    # ---------------------------------------------------------------
    $payload = 'Write-Host "C2 beacon"'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded | Out-Null
    $stamp3 = Get-UtcStamp
    Write-Step "[3/6] Running encoded PowerShell..." $stamp3
    Add-Result 3 "Execute base64-encoded PowerShell command (harmless payload)" $stamp3 `
        "1 (Process Creation)" "4688 (+4104 Script Block Logging)" `
        "T1059.001" "Command and Scripting Interpreter: PowerShell" "executed"
    $actionsExecuted++

    # ---------------------------------------------------------------
    # 4. Create scheduled task for persistence
    # ---------------------------------------------------------------
    schtasks /create /tn $ScheduledTask /tr "cmd.exe /c exit" /sc onstart /ru SYSTEM /f | Out-Null
    $stamp4 = Get-UtcStamp
    Write-Step "[4/6] Creating scheduled task..." $stamp4
    Add-Result 4 "Create scheduled task '$ScheduledTask' for persistence" $stamp4 `
        "1 (Process Creation for schtasks.exe)" "4698 (Scheduled Task Created)" `
        "T1053.005" "Scheduled Task/Job: Scheduled Task" "executed"
    $actionsExecuted++

    # ---------------------------------------------------------------
    # 5. Initiate outbound network connection
    # ---------------------------------------------------------------
    Test-NetConnection -ComputerName $ProbeTarget -Port 443 -WarningAction SilentlyContinue | Out-Null
    $stamp5 = Get-UtcStamp
    Write-Step "[5/6] Outbound network connection..." $stamp5
    Add-Result 5 "Outbound network connection to $ProbeTarget:443" $stamp5 `
        "3 (Network Connection)" "5156 (Windows Filtering Platform Allowed Connection)" `
        "T1071" "Application Layer Protocol" "executed"
    $actionsExecuted++

    # ---------------------------------------------------------------
    # 6. Drop file in Startup directory
    # ---------------------------------------------------------------
    $startupDir = Split-Path $StartupFile -Parent
    if (-not (Test-Path $startupDir)) { New-Item -ItemType Directory -Path $startupDir -Force | Out-Null }
    Set-Content -Path $StartupFile -Value "' telemetry validation artifact - safe to delete" -Encoding ASCII
    $stamp6 = Get-UtcStamp
    Write-Step "[6/6] Dropping file in Startup..." $stamp6
    Add-Result 6 "Drop file in Startup folder ($StartupFile)" $stamp6 `
        "11 (File Create)" "N/A (may correlate with 4663 if object auditing enabled)" `
        "T1547.001" "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" "executed"
    $actionsExecuted++
}
finally {
    # ---------------------------------------------------------------
    # Cleanup - always attempt, even on partial failure
    # ---------------------------------------------------------------
    Write-Host "[*] Cleaning up artifacts..."
    $cleanupNotes = @()

    try {
        if (Get-LocalUser -Name $SimUser -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $SimUser -ErrorAction Stop
            $cleanupNotes += "User removed"
        }
    } catch { $cleanupNotes += "User cleanup FAILED: $_" }

    try {
        schtasks /query /tn $ScheduledTask 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            schtasks /delete /tn $ScheduledTask /f | Out-Null
            $cleanupNotes += "task deleted"
        }
    } catch { $cleanupNotes += "Task cleanup FAILED: $_" }

    try {
        if (Test-Path $StartupFile) {
            Remove-Item -Path $StartupFile -Force -ErrorAction Stop
            $cleanupNotes += "file removed"
        }
    } catch { $cleanupNotes += "File cleanup FAILED: $_" }

    $cleanStatus = if ($cleanupNotes -notmatch "FAILED") { "[CLEAN]" } else { "[INCOMPLETE]" }
    Write-Host ("    " + ($cleanupNotes -join ", ") + "           $cleanStatus")

    # -----------------------------------------------------------
    # Ground truth JSON
    # -----------------------------------------------------------
    $groundTruth = [pscustomobject]@{
        simulation_name = "Crimson Tide Attacker Playbook Simulation"
        host            = $env:COMPUTERNAME
        run_started_utc = if ($results.Count -gt 0) { $results[0].timestamp_utc } else { Get-UtcStamp }
        run_ended_utc   = Get-UtcStamp
        actions         = $results
        cleanup = [pscustomobject]@{
            status = $cleanStatus.Trim("[","]")
            notes  = $cleanupNotes
        }
    }
    $groundTruth | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8

    Write-Host "Actions executed: $actionsExecuted"
    Write-Host "Ground truth saved to: $OutFile"
}