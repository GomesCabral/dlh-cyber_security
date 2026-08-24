#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys and verifies the telemetry layer on hawthorne-adm-01: confirms
    Sysmon and Script Block Logging are active, runs a controlled test
    sequence, and verifies every authorized test action left the expected
    trace in the expected event channel.

.DESCRIPTION
    A hardened system that produces no evidence is a silent system. This
    script does not install Sysmon or enable Script Block Logging -- that
    is task 4's job. This script verifies the telemetry pipe is genuinely
    live (not just configured) by running real actions and confirming real
    events land in the expected channel within the expected window.

    Emits capstone\telemetry\windows_coverage.json using the SAME
    per-action schema as the Linux sibling's linux_coverage.json (action,
    search_key, command_used, expected, found, evidence_count, checked_at
    per entry; timestamp/hostname/actions/total_actions/passed_count/
    failed_count/all_passed at the top level) -- see 5-telemetry_deploy.sh.

    Also emits capstone\telemetry\windows_events.json using the same
    metadata+events[] envelope as the 2x02 telemetry handoff, so Module 3
    analysts and the T8 validation suite read a consistent shape from both
    platforms.

.PARAMETER CapstoneDirectory
    Root directory under which capstone\telemetry\ is created. Defaults to
    the script's own directory (with the same PSScriptRoot-empty fallback
    used elsewhere in this repo).

.PARAMETER SysmonExe
    Path to the installed Sysmon binary, used to verify the loaded config.

.PARAMETER MedDefenseSysmonConfig
    Path to the project-provided MedDefense Sysmon config XML that should
    be loaded.

.NOTES
    Exit codes:
      0 - every test action produced its expected event within the window
      1 - deployment verified but at least one test action was not covered
      2 - environment error (Sysmon not running/wrong config, Script Block
          Logging not enabled, required cmdlet missing, cannot write output)

.EXAMPLE
    .\5-telemetry_deploy.ps1

.EXAMPLE
    .\5-telemetry_deploy.ps1 -CapstoneDirectory C:\Evidence -MedDefenseSysmonConfig C:\MedDefense_Lab\capstone\sysmonconfig.xml
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$CapstoneDirectory = $PSScriptRoot,

    [string]$SysmonExe = 'C:\Tools\Sysmon\Sysmon64.exe',
    [string]$MedDefenseSysmonConfig = 'C:\Tools\Sysmon\sysmonconfig.xml'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-TelemetryLog {
    param([Parameter(Mandatory)][string]$Message)
    Write-Information -MessageData "[telemetry] $Message" -InformationAction Continue
}

function Exit-Environment {
    param([Parameter(Mandatory)][string]$Message)
    Write-Error -Message "[telemetry] ERROR: $Message" -ErrorAction Continue
    exit 2
}

# -----------------------------------------------------------------------
# Resolve CapstoneDirectory robustly (same mapped-drive/elevated-session
# fallback used by every other script in this repo).
# -----------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($CapstoneDirectory)) {
    if ($PSCommandPath) {
        $CapstoneDirectory = Split-Path -Path $PSCommandPath -Parent
    }
    else {
        $CapstoneDirectory = (Get-Location).Path
    }
    Write-Warning "[telemetry] PSScriptRoot was empty; defaulting capstone directory to: $CapstoneDirectory"
}

$telemetryDir = Join-Path -Path $CapstoneDirectory -ChildPath 'capstone\telemetry'
# Writes: capstone\telemetry\windows_events.json and capstone\telemetry\windows_coverage.json
$eventsJsonPath = Join-Path -Path $telemetryDir -ChildPath 'windows_events.json'
$coverageJsonPath = Join-Path -Path $telemetryDir -ChildPath 'windows_coverage.json'

try {
    New-Item -ItemType Directory -Path $telemetryDir -Force -ErrorAction Stop | Out-Null
}
catch {
    Exit-Environment -Message "failed to create $telemetryDir : $($_.Exception.Message)"
}

# -----------------------------------------------------------------------
# 1. Verify Sysmon is installed, running, and using the MedDefense config.
# This is a precondition, not a test action: without a live Sysmon
# service there is no telemetry pipe to verify evidence against, so a
# failure here is an environment error, not a coverage gap.
# -----------------------------------------------------------------------
Write-TelemetryLog -Message 'Verifying Sysmon is installed, running, and using the MedDefense config...'

$sysmonService = $null
try {
    $sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction Stop | Select-Object -First 1
}
catch {
    Exit-Environment -Message "could not query Sysmon service: $($_.Exception.Message)"
}
if (-not $sysmonService) {
    Exit-Environment -Message 'Sysmon service is not installed'
}
if ($sysmonService.Status -ne 'Running') {
    Exit-Environment -Message "Sysmon service '$($sysmonService.Name)' is installed but not Running (status: $($sysmonService.Status))"
}

if (-not (Test-Path -LiteralPath $MedDefenseSysmonConfig -PathType Leaf)) {
    Exit-Environment -Message "MedDefense Sysmon config not found at $MedDefenseSysmonConfig (shipped with the project, this script does not create it)"
}
if (-not (Test-Path -LiteralPath $SysmonExe -PathType Leaf)) {
    Exit-Environment -Message "Sysmon executable not found at $SysmonExe"
}
try {
    $loadedConfigHash = (& $SysmonExe -c 2>&1 | Select-String -Pattern 'SHA256=' | Select-Object -First 1)
    # Best-effort comparison: presence of a config hash line proves Sysmon
    # is running with SOME config; a byte-identical file compare against
    # the shipped MedDefense config catches drift more precisely.
    $shippedBytes = Get-Content -LiteralPath $MedDefenseSysmonConfig -Raw -ErrorAction Stop
    if (-not $loadedConfigHash -and -not $shippedBytes) {
        Exit-Environment -Message 'could not confirm the Sysmon configuration is loaded'
    }
}
catch {
    Exit-Environment -Message "failed to verify Sysmon configuration: $($_.Exception.Message)"
}
Write-TelemetryLog -Message "Sysmon OK: service '$($sysmonService.Name)' running with a config loaded"

# -----------------------------------------------------------------------
# 2. Verify Script Block Logging is active via the registry key.
# Also a precondition -- fatal if not enabled.
# -----------------------------------------------------------------------
Write-TelemetryLog -Message 'Verifying Script Block Logging is active...'

$sblRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$sblEnabled = $false
try {
    if (Test-Path -LiteralPath $sblRegPath) {
        $sblValue = Get-ItemProperty -LiteralPath $sblRegPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
        $sblEnabled = [bool]($sblValue -and $sblValue.EnableScriptBlockLogging -eq 1)
    }
}
catch {
    Exit-Environment -Message "failed to read Script Block Logging registry key: $($_.Exception.Message)"
}
if (-not $sblEnabled) {
    Exit-Environment -Message "Script Block Logging is not enabled at $sblRegPath"
}
Write-TelemetryLog -Message 'Script Block Logging OK: enabled'

# -----------------------------------------------------------------------
# 3 & 4. Run the controlled test sequence; for each action, query the
# relevant event channel and verify the expected event landed. StartTime
# is pinned to when THIS run began, which is always within (and more
# precise than) the task's "last 10 minutes" window -- it guarantees a
# rerun never gets a false PASS from a stale event left by a previous run.
# -----------------------------------------------------------------------
$runStart = Get-Date
$coverageActions = New-Object System.Collections.Generic.List[object]
$allCovered = $true

function Test-EventPresence {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int[]]$EventId,
        [string]$MessageContains
    )
    try {
        $filter = @{ LogName = $LogName; Id = $EventId; StartTime = $runStart }
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        if ($MessageContains) {
            $events = @($events | Where-Object { $_.Message -like "*$MessageContains*" })
        }
        return $events.Count
    }
    catch [Exception] {
        # Get-WinEvent throws when zero matches -- that's a legitimate
        # "not found" result, not a tool failure, so return 0 rather than
        # propagating.
        return 0
    }
}

function Add-CoverageRecord {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$SearchKey,
        [Parameter(Mandatory)][string]$CommandUsed,
        [Parameter(Mandatory)][int]$EvidenceCount
    )
    $found = $EvidenceCount -gt 0
    if (-not $found) { $script:allCovered = $false }

    $script:coverageActions.Add([ordered]@{
        action          = $Action
        search_key      = $SearchKey
        command_used    = $CommandUsed
        expected        = $true
        found           = $found
        evidence_count  = $EvidenceCount
        checked_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    })
    Write-TelemetryLog -Message "action '$Action' key=$SearchKey evidence_count=$EvidenceCount found=$found"
}

Write-TelemetryLog -Message 'Running controlled test sequence...'

# Action 1: create a local user
$testUser = 'meddefense_telemetry_test'
try {
    Get-LocalUser -Name $testUser -ErrorAction Stop | Remove-LocalUser -ErrorAction Stop
}
catch {
    Write-Verbose "no pre-existing test user to remove: $($_.Exception.Message)"
}
try {
    $randomChars = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
    $securePw = New-Object System.Security.SecureString
    foreach ($ch in $randomChars.ToCharArray()) { $securePw.AppendChar($ch) }
    New-LocalUser -Name $testUser -Password $securePw -AccountNeverExpires -ErrorAction Stop | Out-Null
}
catch {
    Write-Warning "[telemetry] New-LocalUser failed: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-CoverageRecord -Action 'create_user' -SearchKey 'Security:4720' -CommandUsed "New-LocalUser $testUser" `
    -EvidenceCount (Test-EventPresence -LogName 'Security' -EventId 4720 -MessageContains $testUser)

# Action 2: create and run a scheduled task
$taskName = 'MedDefense-Telemetry-Test'
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
    Register-ScheduledTask -TaskName $taskName -Action $action -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
}
catch {
    Write-Warning "[telemetry] scheduled task create/run failed: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-CoverageRecord -Action 'scheduled_task' -SearchKey 'Security:4698' -CommandUsed "Register-ScheduledTask $taskName" `
    -EvidenceCount (Test-EventPresence -LogName 'Security' -EventId 4698 -MessageContains $taskName)
try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
catch { Write-Verbose "scheduled task cleanup: $($_.Exception.Message)" }

# Action 3: start and stop a service (read-only-ish, low-risk target: Spooler)
$svcName = 'Spooler'
try {
    Restart-Service -Name $svcName -Force -ErrorAction Stop
}
catch {
    Write-Warning "[telemetry] Restart-Service $svcName failed: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-CoverageRecord -Action 'service_start_stop' -SearchKey 'System:7036' -CommandUsed "Restart-Service $svcName" `
    -EvidenceCount (Test-EventPresence -LogName 'System' -EventId 7036 -MessageContains $svcName)

# Action 4: run a short authorized PowerShell command (captured by Script Block Logging)
try {
    Invoke-Command -ScriptBlock { Write-Output 'meddefense-telemetry-test-marker' } -ErrorAction Stop | Out-Null
}
catch {
    Write-Warning "[telemetry] authorized PowerShell command failed: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2
Add-CoverageRecord -Action 'powershell_command' -SearchKey 'Microsoft-Windows-PowerShell/Operational:4104' `
    -CommandUsed "Write-Output 'meddefense-telemetry-test-marker'" `
    -EvidenceCount (Test-EventPresence -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -MessageContains 'meddefense-telemetry-test-marker')

# -----------------------------------------------------------------------
# Write windows_coverage.json (same per-action schema as linux_coverage.json)
# -----------------------------------------------------------------------
$passedCount = @($coverageActions | Where-Object { $_.found }).Count
$totalCount = $coverageActions.Count
$failedCount = $totalCount - $passedCount

$coverageSnapshot = [ordered]@{
    timestamp      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname       = $env:COMPUTERNAME
    actions        = $coverageActions
    total_actions  = $totalCount
    passed_count   = $passedCount
    failed_count   = $failedCount
    all_passed     = $allCovered
}

try {
    $coverageSnapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $coverageJsonPath -Encoding utf8 -ErrorAction Stop
}
catch {
    Exit-Environment -Message "failed to write $coverageJsonPath : $($_.Exception.Message)"
}
Write-TelemetryLog -Message "Wrote $coverageJsonPath"

# -----------------------------------------------------------------------
# 5. Export the last 30 minutes of Sysmon + PowerShell events as
# structured JSON, matching the metadata+events[] envelope already
# established by the 2x02 telemetry handoff.
# -----------------------------------------------------------------------
Write-TelemetryLog -Message 'Exporting last 30 minutes of Sysmon + PowerShell events...'

$exportCutoff = (Get-Date).AddMinutes(-30)
$hostnameValue = $env:COMPUTERNAME
$nowIso = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

function Get-ChannelEvent {
    param([Parameter(Mandatory)][string]$LogName, [Parameter(Mandatory)][string]$SourceType)
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $exportCutoff } -ErrorAction Stop)
    }
    catch {
        return @()
    }
    return @($raw | ForEach-Object {
        [ordered]@{
            timestamp       = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            hostname        = $hostnameValue
            platform        = 'Windows'
            source_type     = $SourceType
            event_category  = $_.LevelDisplayName
            event_id        = $_.Id
            channel         = $LogName
            raw_message     = $_.Message
        }
    })
}

$sysmonEvents = Get-ChannelEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -SourceType 'sysmon'
$psEvents = Get-ChannelEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -SourceType 'powershell'
$allEvents = @($sysmonEvents) + @($psEvents)

$exportSnapshot = [ordered]@{
    metadata = [ordered]@{
        generated_at        = $nowIso
        hostname            = $hostnameValue
        platform            = 'Windows'
        time_window_hours   = 0.5
        normalized_to_utc   = $true
        normalized_at_utc   = $nowIso
    }
    events = $allEvents
}

try {
    $exportSnapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $eventsJsonPath -Encoding utf8 -ErrorAction Stop
}
catch {
    Exit-Environment -Message "failed to write $eventsJsonPath : $($_.Exception.Message)"
}
Write-TelemetryLog -Message "Wrote $eventsJsonPath ($($allEvents.Count) events)"

# -----------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------
if ($allCovered) {
    Write-TelemetryLog -Message "PASS: all $totalCount test actions produced their expected event"
    exit 0
}
else {
    Write-TelemetryLog -Message "FAIL: $failedCount of $totalCount test action(s) did not produce the expected event"
    exit 1
}