# name: 4-windows_telemetry_quality.ps1
# purpose: Assess completeness, continuity and analyst usefulness of normalized Windows telemetry.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 4 - Windows Telemetry Quality Gate
#
# Input:
# - windows_events_export.json
#
# Output:
# - windows_telemetry_quality.json
#
# Quality dimensions:
# 1. Event distribution
# 2. Channel distribution
# 3. Time coverage
# 4. Gap detection
# 5. Field completeness
# 6. Weighted quality score
#
# Assessments:
# - good
# - acceptable
# - poor
#
# Gap threshold:
# - periods longer than 30 minutes with no events
#
# Safety:
# READ-ONLY with respect to Windows telemetry and configuration.
# The script reads JSON and writes a quality report only.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Paths
# ===========================================================================

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$InputPath = Join-Path `
    $ScriptDirectory `
    "windows_events_export.json"

$OutputPath = Join-Path `
    $ScriptDirectory `
    "windows_telemetry_quality.json"

# ===========================================================================
# Configuration
# ===========================================================================

$GapThresholdMinutes = 30

# Weighted score:
# - Time coverage       25%
# - Gap continuity      20%
# - Command line        20%
# - Source IP           15%
# - Script block        15%
# - Channel presence     5%

$WeightTimeCoverage = 25
$WeightGapContinuity = 20
$WeightCommandLine = 20
$WeightSourceIp = 15
$WeightScriptBlock = 15
$WeightChannelPresence = 5

# ===========================================================================
# Helper functions
# ===========================================================================

function Get-Percentage {

    param(
        [Parameter(Mandatory = $true)]
        [double]$Part,

        [Parameter(Mandatory = $true)]
        [double]$Total
    )

    if ($Total -le 0) {
        return 0.0
    }

    return [math]::Round(
        ($Part / $Total) * 100,
        2
    )
}


function Test-FieldPopulated {

    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $false
    }

    if (
        [string]::IsNullOrWhiteSpace(
            [string]$Value
        )
    ) {
        return $false
    }

    return $true
}


function Get-PropertyValueSafe {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $Property = $Object.PSObject.Properties[$PropertyName]

    if ($null -eq $Property) {
        return $null
    }

    return $Property.Value
}


function Get-QualityAssessment {

    param(
        [Parameter(Mandatory = $true)]
        [double]$Score
    )

    if ($Score -ge 85) {
        return "good"
    }

    if ($Score -ge 65) {
        return "acceptable"
    }

    return "poor"
}

# ===========================================================================
# Validate input
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Telemetry Quality Gate"
Write-Host "=============================================="
Write-Host ""

Write-Host "[*] Analyzing windows_events_export.json..."

if (-not (Test-Path $InputPath)) {

    Write-Host "[FAIL] windows_events_export.json not found."
    Write-Host "       Expected: $InputPath"

    exit 1
}

# ===========================================================================
# Load JSON
# ===========================================================================

try {

    $Export = Get-Content `
        -Path $InputPath `
        -Raw `
        -ErrorAction Stop |
        ConvertFrom-Json
}
catch {

    Write-Host "[FAIL] Unable to parse windows_events_export.json."
    exit 1
}

# ===========================================================================
# Validate events collection
# ===========================================================================

$Events = @(
    $Export.events
)

$TotalEvents = $Events.Count

if ($TotalEvents -eq 0) {

    Write-Host "[FAIL] Export contains no events."

    $EmptyReport = [ordered]@{
        metadata = [ordered]@{
            timestamp = (Get-Date).ToString("o")
            source_file = "windows_events_export.json"
        }

        total_events = 0
        assessment = "poor"
        quality_score = 0
        reason = "No telemetry events were available for analysis."
    }

    $EmptyReport |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -Path $OutputPath `
            -Encoding UTF8

    exit 1
}

# ===========================================================================
# Determine export time window
# ===========================================================================

$MetadataStart = Get-PropertyValueSafe `
    -Object $Export.metadata `
    -PropertyName "StartTime"

if ($null -eq $MetadataStart) {

    $MetadataStart = Get-PropertyValueSafe `
        -Object $Export.metadata `
        -PropertyName "window_start"
}

$MetadataEnd = Get-PropertyValueSafe `
    -Object $Export.metadata `
    -PropertyName "EndTime"

if ($null -eq $MetadataEnd) {

    $MetadataEnd = Get-PropertyValueSafe `
        -Object $Export.metadata `
        -PropertyName "window_end"
}

try {

    $WindowStart = [datetime]$MetadataStart
    $WindowEnd = [datetime]$MetadataEnd
}
catch {

    # Fallback to actual telemetry range if export metadata is unavailable.
    $ParsedTimes = @(
        $Events |
        ForEach-Object {
            [datetime]$_.timestamp
        } |
        Sort-Object
    )

    $WindowStart = $ParsedTimes[0]
    $WindowEnd = $ParsedTimes[-1]
}

# ===========================================================================
# EVENT DISTRIBUTION
# ===========================================================================

$EventDistribution = @()

$EventGroups = @(
    $Events |
    Group-Object source_type,event_id |
    Sort-Object Count -Descending
)

foreach ($Group in $EventGroups) {

    $Sample = $Group.Group |
        Select-Object -First 1

    $EventDistribution += [PSCustomObject]@{
        source_type = $Sample.source_type
        event_id = [int]$Sample.event_id
        count = $Group.Count
        percentage_of_total = Get-Percentage `
            -Part $Group.Count `
            -Total $TotalEvents
    }
}

# ===========================================================================
# CHANNEL DISTRIBUTION
# ===========================================================================

$ChannelDistribution = @()

$ExpectedChannels = @(
    "Security",
    "Sysmon",
    "PowerShell"
)

foreach ($Source in $ExpectedChannels) {

    $Count = @(
        $Events |
        Where-Object {
            $_.source_type -eq $Source
        }
    ).Count

    $ChannelDistribution += [PSCustomObject]@{
        source_type = $Source
        count = $Count
        percentage_of_total = Get-Percentage `
            -Part $Count `
            -Total $TotalEvents
    }
}

# ===========================================================================
# TIME COVERAGE - events per hour
# ===========================================================================

$HourlyBuckets = @()

$BucketStart = [datetime]::new(
    $WindowStart.Year,
    $WindowStart.Month,
    $WindowStart.Day,
    $WindowStart.Hour,
    0,
    0,
    $WindowStart.Kind
)

$BucketEnd = $BucketStart.AddHours(1)

while ($BucketStart -lt $WindowEnd) {

    $Count = @(
        $Events |
        Where-Object {

            $EventTime = [datetime]$_.timestamp

            $EventTime -ge $BucketStart -and
            $EventTime -lt $BucketEnd
        }
    ).Count

    $HourlyBuckets += [PSCustomObject]@{
        hour_start = $BucketStart.ToString("o")
        hour_end = $BucketEnd.ToString("o")
        event_count = $Count
        has_events = ($Count -gt 0)
    }

    $BucketStart = $BucketStart.AddHours(1)
    $BucketEnd = $BucketEnd.AddHours(1)
}

$HoursWithEvents = @(
    $HourlyBuckets |
    Where-Object {
        $_.has_events
    }
).Count

$HoursWithoutEvents = @(
    $HourlyBuckets |
    Where-Object {
        -not $_.has_events
    }
).Count

$TotalHours = $HourlyBuckets.Count

$TimeCoveragePercent = Get-Percentage `
    -Part $HoursWithEvents `
    -Total $TotalHours

# ===========================================================================
# GAP DETECTION
# ===========================================================================

$SortedEvents = @(
    $Events |
    Sort-Object {
        [datetime]$_.timestamp
    }
)

$Gaps = @()
$LargestGapMinutes = 0.0

for ($Index = 1; $Index -lt $SortedEvents.Count; $Index++) {

    $PreviousTime = [datetime]$SortedEvents[$Index - 1].timestamp
    $CurrentTime = [datetime]$SortedEvents[$Index].timestamp

    $GapMinutes = (
        New-TimeSpan `
            -Start $PreviousTime `
            -End $CurrentTime
    ).TotalMinutes

    if ($GapMinutes -gt $LargestGapMinutes) {

        $LargestGapMinutes = $GapMinutes
    }

    if ($GapMinutes -gt $GapThresholdMinutes) {

        $Gaps += [PSCustomObject]@{
            start = $PreviousTime.ToString("o")
            end = $CurrentTime.ToString("o")
            duration_minutes = [math]::Round(
                $GapMinutes,
                2
            )
        }
    }
}

# Include beginning-of-window gap.
$FirstEventTime = [datetime]$SortedEvents[0].timestamp

$InitialGapMinutes = (
    New-TimeSpan `
        -Start $WindowStart `
        -End $FirstEventTime
).TotalMinutes

if ($InitialGapMinutes -gt $LargestGapMinutes) {
    $LargestGapMinutes = $InitialGapMinutes
}

if ($InitialGapMinutes -gt $GapThresholdMinutes) {

    $Gaps += [PSCustomObject]@{
        start = $WindowStart.ToString("o")
        end = $FirstEventTime.ToString("o")
        duration_minutes = [math]::Round(
            $InitialGapMinutes,
            2
        )
    }
}

# Include end-of-window gap.
$LastEventTime = [datetime]$SortedEvents[-1].timestamp

$FinalGapMinutes = (
    New-TimeSpan `
        -Start $LastEventTime `
        -End $WindowEnd
).TotalMinutes

if ($FinalGapMinutes -gt $LargestGapMinutes) {
    $LargestGapMinutes = $FinalGapMinutes
}

if ($FinalGapMinutes -gt $GapThresholdMinutes) {

    $Gaps += [PSCustomObject]@{
        start = $LastEventTime.ToString("o")
        end = $WindowEnd.ToString("o")
        duration_minutes = [math]::Round(
            $FinalGapMinutes,
            2
        )
    }
}

$LargestGapMinutes = [math]::Round(
    $LargestGapMinutes,
    2
)

# ===========================================================================
# FIELD COMPLETENESS - process command lines
# ===========================================================================

$ProcessEvents = @(
    $Events |
    Where-Object {

        (
            $_.source_type -eq "Security" -and
            $_.event_id -eq 4688
        ) -or
        (
            $_.source_type -eq "Sysmon" -and
            $_.event_id -eq 1
        )
    }
)

$ProcessCommandLinePopulated = 0

foreach ($Event in $ProcessEvents) {

    $CommandLine = Get-PropertyValueSafe `
        -Object $Event `
        -PropertyName "command_line"

    if (Test-FieldPopulated $CommandLine) {
        $ProcessCommandLinePopulated++
    }
}

$CommandLineCompleteness = Get-Percentage `
    -Part $ProcessCommandLinePopulated `
    -Total $ProcessEvents.Count

# ===========================================================================
# FIELD COMPLETENESS - source IP for logon events
# ===========================================================================

$LogonEvents = @(
    $Events |
    Where-Object {
        $_.source_type -eq "Security" -and
        (
            $_.event_id -eq 4624 -or
            $_.event_id -eq 4625
        )
    }
)

$SourceIpPopulated = 0

foreach ($Event in $LogonEvents) {

    $SourceIp = Get-PropertyValueSafe `
        -Object $Event `
        -PropertyName "source_ip"

    if (Test-FieldPopulated $SourceIp) {

        # "-" is a common Windows placeholder and does not count as useful IP.
        if ([string]$SourceIp -ne "-") {

            $SourceIpPopulated++
        }
    }
}

$SourceIpCompleteness = Get-Percentage `
    -Part $SourceIpPopulated `
    -Total $LogonEvents.Count

# ===========================================================================
# FIELD COMPLETENESS - PowerShell ScriptBlock
# ===========================================================================

$ScriptBlockEvents = @(
    $Events |
    Where-Object {
        $_.source_type -eq "PowerShell" -and
        $_.event_id -eq 4104
    }
)

$ScriptBlockPopulated = 0

foreach ($Event in $ScriptBlockEvents) {

    $ScriptBlockText = Get-PropertyValueSafe `
        -Object $Event `
        -PropertyName "script_block_text"

    if (Test-FieldPopulated $ScriptBlockText) {
        $ScriptBlockPopulated++
    }
}

$ScriptBlockCompleteness = Get-Percentage `
    -Part $ScriptBlockPopulated `
    -Total $ScriptBlockEvents.Count

# ===========================================================================
# Generic required field completeness per key event type
# ===========================================================================

$RequiredFieldDefinitions = @(
    [PSCustomObject]@{
        source_type = "Security"
        event_id = 4624
        required_fields = @(
            "target_user",
            "logon_type",
            "source_ip",
            "workstation"
        )
    },

    [PSCustomObject]@{
        source_type = "Security"
        event_id = 4625
        required_fields = @(
            "target_user",
            "failure_reason",
            "source_ip"
        )
    },

    [PSCustomObject]@{
        source_type = "Security"
        event_id = 4672
        required_fields = @(
            "privileged_account"
        )
    },

    [PSCustomObject]@{
        source_type = "Security"
        event_id = 4688
        required_fields = @(
            "process_name",
            "command_line"
        )
    },

    [PSCustomObject]@{
        source_type = "PowerShell"
        event_id = 4104
        required_fields = @(
            "script_block_text"
        )
    },

    [PSCustomObject]@{
        source_type = "Sysmon"
        event_id = 1
        required_fields = @(
            "image",
            "command_line",
            "parent_image",
            "hashes"
        )
    },

    [PSCustomObject]@{
        source_type = "Sysmon"
        event_id = 3
        required_fields = @(
            "destination_ip",
            "destination_port",
            "process"
        )
    },

    [PSCustomObject]@{
        source_type = "Sysmon"
        event_id = 11
        required_fields = @(
            "target_filename",
            "creating_process"
        )
    },

    [PSCustomObject]@{
        source_type = "Sysmon"
        event_id = 13
        required_fields = @(
            "registry_key",
            "registry_value_name"
        )
    },

    [PSCustomObject]@{
        source_type = "Sysmon"
        event_id = 22
        required_fields = @(
            "query_name",
            "query_results"
        )
    }
)

$FieldCompleteness = @()

foreach ($Definition in $RequiredFieldDefinitions) {

    $MatchingEvents = @(
        $Events |
        Where-Object {
            $_.source_type -eq $Definition.source_type -and
            $_.event_id -eq $Definition.event_id
        }
    )

    foreach ($FieldName in $Definition.required_fields) {

        $Populated = 0

        foreach ($Event in $MatchingEvents) {

            $Value = Get-PropertyValueSafe `
                -Object $Event `
                -PropertyName $FieldName

            if (Test-FieldPopulated $Value) {

                if ([string]$Value -ne "-") {
                    $Populated++
                }
            }
        }

        $EmptyCount = $MatchingEvents.Count - $Populated

        $FieldCompleteness += [PSCustomObject]@{
            source_type = $Definition.source_type
            event_id = $Definition.event_id
            field = $FieldName
            total_events = $MatchingEvents.Count
            populated = $Populated
            empty_or_null = $EmptyCount
            completeness_percentage = Get-Percentage `
                -Part $Populated `
                -Total $MatchingEvents.Count
        }
    }
}

# ===========================================================================
# Channel presence score
# ===========================================================================

$ChannelsPresent = @(
    $ChannelDistribution |
    Where-Object {
        $_.count -gt 0
    }
).Count

$ChannelPresencePercent = Get-Percentage `
    -Part $ChannelsPresent `
    -Total 3

# ===========================================================================
# Gap continuity score
# ===========================================================================

if ($LargestGapMinutes -le 30) {

    $GapContinuityPercent = 100
}
elseif ($LargestGapMinutes -le 60) {

    $GapContinuityPercent = 80
}
elseif ($LargestGapMinutes -le 120) {

    $GapContinuityPercent = 60
}
elseif ($LargestGapMinutes -le 240) {

    $GapContinuityPercent = 40
}
else {

    $GapContinuityPercent = 20
}

# ===========================================================================
# Handle absence of particular event classes for scoring
# ===========================================================================

# If an event class does not exist at all, it is a telemetry coverage gap.
# It therefore contributes 0 rather than artificially receiving 100%.

if ($ProcessEvents.Count -eq 0) {
    $CommandLineCompleteness = 0
}

if ($LogonEvents.Count -eq 0) {
    $SourceIpCompleteness = 0
}

if ($ScriptBlockEvents.Count -eq 0) {
    $ScriptBlockCompleteness = 0
}

# ===========================================================================
# QUALITY SCORE
# ===========================================================================

$QualityScore = (
    ($TimeCoveragePercent / 100) * $WeightTimeCoverage +
    ($GapContinuityPercent / 100) * $WeightGapContinuity +
    ($CommandLineCompleteness / 100) * $WeightCommandLine +
    ($SourceIpCompleteness / 100) * $WeightSourceIp +
    ($ScriptBlockCompleteness / 100) * $WeightScriptBlock +
    ($ChannelPresencePercent / 100) * $WeightChannelPresence
)

$QualityScore = [math]::Round(
    $QualityScore,
    2
)

$Assessment = Get-QualityAssessment `
    -Score $QualityScore

# ===========================================================================
# Detect noisy dominant event type
# ===========================================================================

$DominantEvent = $null

if ($EventDistribution.Count -gt 0) {

    $DominantEvent = $EventDistribution |
        Sort-Object percentage_of_total -Descending |
        Select-Object -First 1
}

$NoiseAssessment = if (
    $null -ne $DominantEvent -and
    $DominantEvent.percentage_of_total -ge 70
) {

    "high_concentration"
}
elseif (
    $null -ne $DominantEvent -and
    $DominantEvent.percentage_of_total -ge 50
) {

    "moderate_concentration"
}
else {

    "balanced"
}

# ===========================================================================
# Build quality report
# ===========================================================================

$QualityReport = [ordered]@{

    metadata = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        source_file = "windows_events_export.json"
        gap_threshold_minutes = $GapThresholdMinutes
        window_start = $WindowStart.ToUniversalTime().ToString("o")
        window_end = $WindowEnd.ToUniversalTime().ToString("o")
    }

    total_events = $TotalEvents

    event_distribution = $EventDistribution

    channel_distribution = $ChannelDistribution

    time_coverage = [ordered]@{
        total_hours = $TotalHours
        hours_with_events = $HoursWithEvents
        hours_without_events = $HoursWithoutEvents
        coverage_percentage = $TimeCoveragePercent
        events_per_hour = $HourlyBuckets
    }

    gap_detection = [ordered]@{
        threshold_minutes = $GapThresholdMinutes
        gap_count = $Gaps.Count
        largest_gap_minutes = $LargestGapMinutes
        gaps = $Gaps
    }

    field_completeness = [ordered]@{

        required_fields = $FieldCompleteness

        command_line = [ordered]@{
            total_process_events = $ProcessEvents.Count
            populated = $ProcessCommandLinePopulated
            completeness_percentage = $CommandLineCompleteness
        }

        source_ip = [ordered]@{
            total_logon_events = $LogonEvents.Count
            populated = $SourceIpPopulated
            completeness_percentage = $SourceIpCompleteness
        }

        script_block = [ordered]@{
            total_4104_events = $ScriptBlockEvents.Count
            populated = $ScriptBlockPopulated
            completeness_percentage = $ScriptBlockCompleteness
        }
    }

    noise_analysis = [ordered]@{
        assessment = $NoiseAssessment
        dominant_event = $DominantEvent
    }

    quality_score = [ordered]@{
        score = $QualityScore
        assessment = $Assessment

        weights = [ordered]@{
            time_coverage = $WeightTimeCoverage
            gap_continuity = $WeightGapContinuity
            command_line_completeness = $WeightCommandLine
            source_ip_completeness = $WeightSourceIp
            script_block_completeness = $WeightScriptBlock
            channel_presence = $WeightChannelPresence
        }

        component_scores = [ordered]@{
            time_coverage = $TimeCoveragePercent
            gap_continuity = $GapContinuityPercent
            command_line_completeness = $CommandLineCompleteness
            source_ip_completeness = $SourceIpCompleteness
            script_block_completeness = $ScriptBlockCompleteness
            channel_presence = $ChannelPresencePercent
        }
    }
}

# ===========================================================================
# Write JSON
# ===========================================================================

try {

    $Json = $QualityReport |
        ConvertTo-Json `
            -Depth 15

    Set-Content `
        -Path $OutputPath `
        -Value $Json `
        -Encoding UTF8
}
catch {

    Write-Host "[FAIL] Unable to write windows_telemetry_quality.json."
    exit 1
}

# ===========================================================================
# Validate JSON
# ===========================================================================

try {

    $null = Get-Content `
        -Path $OutputPath `
        -Raw |
        ConvertFrom-Json
}
catch {

    Write-Host "[FAIL] windows_telemetry_quality.json is invalid."
    exit 1
}

# ===========================================================================
# Console output
# ===========================================================================

Write-Host ""
Write-Host "Total events: $TotalEvents"

Write-Host `
    "Hours with events: $HoursWithEvents/$TotalHours"

Write-Host `
    "Hours without events: $HoursWithoutEvents/$TotalHours"

Write-Host `
    "Largest gap: $LargestGapMinutes minutes"

Write-Host `
    "Command-line completeness: $CommandLineCompleteness%"

Write-Host `
    "Source IP completeness: $SourceIpCompleteness%"

Write-Host `
    "Script block completeness: $ScriptBlockCompleteness%"

Write-Host `
    "Quality score: $QualityScore% ($Assessment)"

Write-Host ""
Write-Host "Report saved to: windows_telemetry_quality.json"
Write-Host ""

exit 0