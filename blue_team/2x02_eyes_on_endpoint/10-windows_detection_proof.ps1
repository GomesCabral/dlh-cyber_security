<#
.SYNOPSIS
    Correlates the Task 9 attacker-simulation ground truth (windows_attack_log.json)
    against captured Windows telemetry (Security, Sysmon, PowerShell Operational logs)
    and produces a detection matrix proving what was captured, by which source, and
    at what level of detail.

.DESCRIPTION
    For every action recorded in the ground truth:
      1. Opens a +/- $WindowSeconds window around the action's recorded timestamp.
      2. For each source the ground truth expects to see the action in (e.g.
         "Sysmon Event ID 1"), queries that Windows Event Log for matching events
         in the window.
      3. Uses the contextual details captured in Task 9 (account name, task name,
         destination IP, target file path, encoded command, etc.) to confirm the
         candidate event is actually the one produced by the simulation, not
         unrelated noise in the same window.
      4. Classifies the match as Full / Partial / Missing detail depending on
         whether the fields expected for that Event ID are actually populated.

    Output mirrors Task 9's format: a console table plus a
    windows_detection_matrix.json report with the full per-source breakdown.

.NOTES
    - Run this on the SAME host, soon after 9-windows_attack_sim.ps1, before the
      relevant logs wrap or age out.
    - Requires elevation (reading the Security log requires admin rights).
    - Full detection depends on audit policy / Sysmon config being in place:
        * Security 4720/4732/4698 require the relevant Account Management /
          Other Object Access audit subcategories to be enabled.
        * Security 4688 with a populated CommandLine requires "Include command
          line in process creation events" (GPO) to be enabled.
        * Sysmon EIDs 1/3/11 require Sysmon installed with a config that logs
          process creation, network connections, and file creation.
        * PowerShell EID 4104 requires "Turn on PowerShell Script Block Logging"
          (GPO) to be enabled.
      Where these are not enabled, the corresponding source will legitimately
      show as [MISSED] - that is itself useful proof of an instrumentation gap.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$GroundTruthFile,
    [string]$OutputFile,
    [int]$WindowSeconds = 30
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Resolve the script's own directory.
# $PSScriptRoot can come back empty when a script is launched via
# `powershell -File` from a UNC path (e.g. a VirtualBox shared folder),
# because the child process cannot set its working directory to a UNC path.
# Fall back to $MyInvocation, then to the current location, so the script
# still works from mapped drives, UNC paths, and local paths alike.
# ============================================================================

$ScriptDir =
    if ($PSScriptRoot) { $PSScriptRoot }
    elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
    else { (Get-Location).ProviderPath }

if (-not $GroundTruthFile) { $GroundTruthFile = Join-Path $ScriptDir "windows_attack_log.json" }
if (-not $OutputFile)      { $OutputFile      = Join-Path $ScriptDir "windows_detection_matrix.json" }

# ============================================================================
# Static mappings
# ============================================================================

# Short display labels for the console table (mirrors the task's expected output).
$DisplayNames = @{
    1 = "Create user"
    2 = "Add to Administrators"
    3 = "Encoded PowerShell"
    4 = "Scheduled task"
    5 = "Outbound connection"
    6 = "Startup file drop"
}

# Maps the "source" word parsed out of expected_detection_source strings
# (e.g. "Security Event ID 4720" -> "Security") to the real Windows Event Log
# path and the label used in the printed table.
$LogMap = @{
    "Security"   = @{ LogName = "Security";                               Display = "Security" }
    "Sysmon"     = @{ LogName = "Microsoft-Windows-Sysmon/Operational";    Display = "Sysmon" }
    "PowerShell" = @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Display = "PS ScriptBlock" }
}

# Fields that must be present (non-empty) for a match to count as "Full" detail,
# per "Source:EventId" key. Anything else present but incomplete is "Partial".
$RequiredFieldsMap = @{
    "Security:4720"    = @("TargetUserName", "SubjectUserName")
    "Security:4732"    = @("MemberName", "TargetUserName")
    "Security:4688"    = @("NewProcessName", "CommandLine")
    "Security:4698"    = @("TaskName", "SubjectUserName")
    "Sysmon:1"         = @("Image", "CommandLine", "User")
    "Sysmon:3"         = @("DestinationIp", "DestinationPort", "Image")
    "Sysmon:11"        = @("TargetFilename", "Image")
    "PowerShell:4104"  = @("ScriptBlockText")
}

# ============================================================================
# Helper functions
# ============================================================================

function ConvertFrom-ExpectedSource {
    # Parses "Security Event ID 4720" -> @{ Name = "Security"; Id = 4720 }
    param([string]$Text)

    if ($Text -match '^(?<name>.+?)\s+Event ID\s+(?<id>\d+)$') {
        return [pscustomobject]@{
            Name = $Matches['name'].Trim()
            Id   = [int]$Matches['id']
        }
    }
    return $null
}

function Get-EventDataHashtable {
    # Flattens an event's <EventData><Data Name="..">value</Data></EventData>
    # into a simple hashtable so fields can be looked up by name.
    param($Event)

    $data = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) {
                $data[$node.Name] = $node.'#text'
            }
        }
    }
    catch {
        # Some providers (rare) don't expose structured EventData; leave $data empty.
    }
    return $data
}

function Get-DetailLevel {
    param(
        [string]$SourceName,
        [int]$EventId,
        [hashtable]$Fields
    )

    $key = "$SourceName`:$EventId"

    if (-not $RequiredFieldsMap.ContainsKey($key)) {
        return "Partial"
    }

    $required = $RequiredFieldsMap[$key]
    $present  = @(
        $required | Where-Object {
            $Fields.ContainsKey($_) -and
            -not [string]::IsNullOrWhiteSpace([string]$Fields[$_])
        }
    )

    if ($present.Count -eq $required.Count) { return "Full" }
    elseif ($present.Count -gt 0)           { return "Partial" }
    else                                     { return "Missing" }
}

function Find-MatchingEvent {
    # Searches the log for $SourceName/$EventId in the time window, then uses
    # the action's own recorded details to confirm the right event was found.
    param(
        [pscustomobject]$Action,
        [string]$SourceName,
        [int]$EventId,
        [datetime]$Start,
        [datetime]$End
    )

    if (-not $LogMap.ContainsKey($SourceName)) { return $null }
    $logInfo = $LogMap[$SourceName]

    try {
        $candidates = Get-WinEvent -FilterHashtable @{
            LogName   = $logInfo.LogName
            Id        = $EventId
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction Stop
    }
    catch {
        # Log doesn't exist, provider not registered, no events in window,
        # or access denied - all treated the same: no match found.
        return $null
    }

    if (-not $candidates) { return $null }

    $details = $Action.details

    foreach ($evt in ($candidates | Sort-Object TimeCreated)) {

        $fields = Get-EventDataHashtable -Event $evt

        $isMatch = switch ([int]$Action.action_number) {

            1 {
                # Create local/domain user - match on the account name.
                $fields['TargetUserName'] -eq $details.account
            }

            2 {
                # Add to Administrators - match on target group, or member name
                # containing the account (MemberName is often a full DN/SID string).
                ($fields['TargetUserName'] -eq $details.group) -or
                ($fields['MemberName'] -and $fields['MemberName'] -match [regex]::Escape($details.account))
            }

            3 {
                # Encoded PowerShell - match differently per source.
                switch ($EventId) {
                    1    { $fields['CommandLine']  -and ($fields['CommandLine'] -match [regex]::Escape($details.encoded_command) -or $fields['CommandLine'] -match '(?i)-enc\b') }
                    4688 { $fields['CommandLine']  -and ($fields['CommandLine'] -match [regex]::Escape($details.encoded_command) -or $fields['CommandLine'] -match '(?i)-enc\b') }
                    4104 { $fields['ScriptBlockText'] -and $fields['ScriptBlockText'] -match [regex]::Escape($details.payload) }
                    default { $true }
                }
            }

            4 {
                # Scheduled task persistence - match on the task name.
                switch ($EventId) {
                    4698 { $fields['TaskName'] -and $fields['TaskName'] -match [regex]::Escape($details.task_name) }
                    1    { $fields['CommandLine'] -and $fields['CommandLine'] -match [regex]::Escape($details.task_name) }
                    default { $true }
                }
            }

            5 {
                # Outbound connection - match on destination IP (and port if present).
                ($fields['DestinationIp'] -eq $details.destination_ip) -and
                (-not $details.destination_port -or [string]$fields['DestinationPort'] -eq [string]$details.destination_port)
            }

            6 {
                # Startup file drop - match on the exact target path.
                $fields['TargetFilename'] -and ($fields['TargetFilename'] -eq $details.target_file)
            }

            default { $true }
        }

        if ($isMatch) {
            return [pscustomobject]@{
                Event  = $evt
                Fields = $fields
            }
        }
    }

    return $null
}

# ============================================================================
# Load ground truth
# ============================================================================

if (-not (Test-Path $GroundTruthFile)) {
    Write-Host "[FAIL] Ground truth file not found: $GroundTruthFile"
    exit 1
}

$groundTruth = Get-Content -Path $GroundTruthFile -Raw | ConvertFrom-Json
$actions     = @($groundTruth.actions | Sort-Object action_number)

Write-Host "[*] Loading ground truth ($($actions.Count) actions)..."
Write-Host "[*] Searching telemetry for each action..."
Write-Host ""

# ============================================================================
# Correlate each action against telemetry
# ============================================================================

$matrixRows          = @()   # full detail, every attempted source, for the JSON report
$printRows            = @()  # rows shown in the console table
$capturedActionCount  = 0
$multiSourceCount     = 0

foreach ($action in $actions) {

    $timestamp = [datetime]::Parse(
        $action.timestamp,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    )

    # Get-WinEvent's StartTime/EndTime are compared against TimeCreated, which
    # Get-WinEvent exposes in local time - convert the UTC ground-truth
    # timestamp to local time so the window lines up regardless of the box's
    # time zone configuration.
    $start = $timestamp.AddSeconds(-$WindowSeconds).ToLocalTime()
    $end   = $timestamp.AddSeconds($WindowSeconds).ToLocalTime()

    $label = $DisplayNames[[int]$action.action_number]
    if (-not $label) { $label = $action.description }

    $capturedSourcesForAction = @()

    foreach ($srcText in $action.expected_detection_source) {

        $parsed = ConvertFrom-ExpectedSource -Text $srcText
        if (-not $parsed) { continue }

        $logInfo = $LogMap[$parsed.Name]
        if (-not $logInfo) { continue }

        $match = Find-MatchingEvent `
            -Action $action `
            -SourceName $parsed.Name `
            -EventId $parsed.Id `
            -Start $start `
            -End $end

        if ($match) {
            $detail = Get-DetailLevel -SourceName $parsed.Name -EventId $parsed.Id -Fields $match.Fields
            $status = "[CAPTURED]"
            $capturedSourcesForAction += $logInfo.Display
        }
        else {
            $detail = "None"
            $status = "[MISSED]"
        }

        $keyFields = @{}
        if ($match) {
            $wantedKeys = $RequiredFieldsMap["$($parsed.Name):$($parsed.Id)"]
            if ($wantedKeys) {
                foreach ($k in $wantedKeys) {
                    if ($match.Fields.ContainsKey($k)) {
                        $keyFields[$k] = $match.Fields[$k]
                    }
                }
            }
        }

        # Every attempted source goes into the JSON report, captured or not.
        $matrixRows += [pscustomobject]@{
            action_number = $action.action_number
            action        = $label
            source        = $logInfo.Display
            log_name      = $logInfo.LogName
            event_id      = $parsed.Id
            detail        = $detail
            status        = $status
            key_fields    = $keyFields
            matched_time_utc = if ($match) { $match.Event.TimeCreated.ToUniversalTime().ToString("o") } else { $null }
        }

        # Only sources that actually captured the action get a console row.
        if ($match) {
            $printRows += [pscustomobject]@{
                action   = $label
                source   = $logInfo.Display
                event_id = $parsed.Id
                detail   = $detail
                status   = $status
            }
        }
    }

    if ($capturedSourcesForAction.Count -gt 0) {
        $capturedActionCount++
        if (@($capturedSourcesForAction | Select-Object -Unique).Count -gt 1) {
            $multiSourceCount++
        }
    }
    else {
        # No expected source captured this action at all - still show one row.
        $printRows += [pscustomobject]@{
            action   = $label
            source   = "-"
            event_id = "-"
            detail   = "None"
            status   = "[MISSED]"
        }
    }
}

# ============================================================================
# Print the detection table
# ============================================================================

$fmt = "{0,-26} {1,-14} {2,-10} {3,-9} {4}"

Write-Host ($fmt -f "Action", "Source", "Event ID", "Detail", "Status")
Write-Host ($fmt -f "------", "------", "--------", "------", "------")

$lastAction = $null
foreach ($row in $printRows) {

    $actionCell = if ($row.action -eq $lastAction) { "" } else { $row.action }
    $lastAction = $row.action

    Write-Host ($fmt -f $actionCell, $row.source, $row.event_id, $row.detail, $row.status)
}

# ============================================================================
# Summary + report
# ============================================================================

$totalActions = $actions.Count
$pct = if ($totalActions -gt 0) {
    [math]::Round(($capturedActionCount / $totalActions) * 100)
} else {
    0
}

Write-Host ""
Write-Host "Actions: $totalActions | Captured: $capturedActionCount/$totalActions ($pct%) | Multi-source: $multiSourceCount"

$report = [ordered]@{
    metadata = [ordered]@{
        generated_at_utc     = (Get-Date).ToUniversalTime().ToString("o")
        ground_truth_file    = $GroundTruthFile
        window_seconds       = $WindowSeconds
        total_actions        = $totalActions
        captured_actions     = $capturedActionCount
        capture_rate_percent = $pct
        multi_source_actions = $multiSourceCount
    }
    detections = $matrixRows
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputFile -Encoding UTF8

Write-Host "Report saved to: windows_detection_matrix.json"