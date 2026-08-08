# name: 3-windows_telemetry_export.ps1
# purpose: Export and normalize Windows Security, Sysmon and PowerShell telemetry into analyst-ready JSON.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 3 - Windows Telemetry Normalizer
#
# Default time window:
# - Last 24 hours
#
# Time window:
# - StartTime
# - EndTime
#
# Input channels:
# - Security
# - Microsoft-Windows-Sysmon/Operational
# - Microsoft-Windows-PowerShell/Operational
#
# Output:
# - windows_events_export.json
#
# Normalized common fields:
# - timestamp
# - hostname
# - platform
# - source_type
# - channel
# - event_id
# - event_category
# - provider
# - raw_message
#
# Enriched Security Event IDs:
# - 4624 successful logon
# - 4625 failed logon
# - 4672 privileged logon
# - 4688 process creation
#
# Enriched PowerShell Event ID:
# - 4104 ScriptBlock
#
# Enriched Sysmon Event IDs:
# - 1 process creation
# - 3 network connection
# - 11 file creation
# - 13 registry modification
# - 22 DNS query
#
# Safety:
# READ-ONLY.
# The script reads Windows Event Logs and writes JSON only.

[CmdletBinding()]
param(
    [int]$Hours = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Validate time window
# ===========================================================================

if ($Hours -le 0) {
    throw "Hours must be greater than 0."
}

# ===========================================================================
# Paths and time range
# ===========================================================================

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$OutputPath = Join-Path `
    $ScriptDirectory `
    "windows_events_export.json"

$EndTime = Get-Date

$StartTime = $EndTime.AddHours(
    -1 * $Hours
)

$ExportTimestamp = Get-Date

# ===========================================================================
# General metadata
# ===========================================================================

$HostnameValue = $env:COMPUTERNAME

$PlatformValue = "Windows"

# ===========================================================================
# Channels
# ===========================================================================

$SecurityChannel = "Security"

$SysmonChannel = "Microsoft-Windows-Sysmon/Operational"

$PowerShellChannel = "Microsoft-Windows-PowerShell/Operational"

# ===========================================================================
# Helper: EventData
# ===========================================================================

function Get-EventDataMap {

    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $Fields = [ordered]@{}

    try {

        [xml]$EventXml = $Event.ToXml()

        $DataNodes = @(
            $EventXml.Event.EventData.Data
        )

        foreach ($Node in $DataNodes) {

            $Name = [string]$Node.Name

            if ([string]::IsNullOrWhiteSpace($Name)) {
                continue
            }

            $Fields[$Name] = [string]$Node.'#text'
        }
    }
    catch {
    }

    return $Fields
}

# ===========================================================================
# Helper: safe field lookup
# ===========================================================================

function Get-FieldValue {

    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Map,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {

        if ($Map.Contains($Name)) {

            $Value = $Map[$Name]

            if (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$Value
                )
            ) {

                return $Value
            }
        }
    }

    return $null
}

# ===========================================================================
# Helper: event category
# ===========================================================================

function Get-EventCategory {

    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceType,

        [Parameter(Mandatory = $true)]
        [int]$EventId
    )

    switch ($SourceType) {

        "Security" {

            switch ($EventId) {

                4624 { return "authentication_success" }
                4625 { return "authentication_failure" }
                4672 { return "privileged_logon" }
                4688 { return "process_creation" }
                4720 { return "account_created" }
                4726 { return "account_deleted" }
                4732 { return "group_membership_change" }
                1102 { return "audit_log_cleared" }

                default {
                    return "windows_security"
                }
            }
        }

        "PowerShell" {

            switch ($EventId) {

                4103 { return "powershell_module_logging" }
                4104 { return "powershell_script_block" }

                default {
                    return "powershell"
                }
            }
        }

        "Sysmon" {

            switch ($EventId) {

                1  { return "process_creation" }
                3  { return "network_connection" }
                7  { return "image_load" }
                8  { return "remote_thread_creation" }
                10 { return "process_access" }
                11 { return "file_creation" }
                13 { return "registry_modification" }
                22 { return "dns_query" }

                default {
                    return "sysmon"
                }
            }
        }

        default {
            return "unknown"
        }
    }
}

# ===========================================================================
# Helper: normalized common event
# ===========================================================================

function New-NormalizedEvent {

    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,

        [Parameter(Mandatory = $true)]
        [string]$SourceType
    )

    $TimestampValue = if ($null -ne $Event.TimeCreated) {

        $Event.TimeCreated.ToUniversalTime().ToString("o")
    }
    else {

        $null
    }

    return [ordered]@{

        timestamp = $TimestampValue

        hostname = $HostnameValue

        platform = $PlatformValue

        source_type = $SourceType

        channel = [string]$Event.LogName

        event_id = [int]$Event.Id

        event_category = Get-EventCategory `
            -SourceType $SourceType `
            -EventId $Event.Id

        provider = [string]$Event.ProviderName

        raw_message = [string]$Event.Message
    }
}

# ===========================================================================
# Security enrichment
# ===========================================================================

function Add-SecurityEnrichment {

    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Normalized,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $Data = Get-EventDataMap `
        -Event $Event

    switch ($Event.Id) {

        # ===================================================================
        # 4624 - Successful logon
        # ===================================================================

        4624 {

            $Normalized.target_user = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "TargetUserName"
                )

            $Normalized.logon_type = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "LogonType"
                )

            $Normalized.source_ip = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "IpAddress",
                    "SourceNetworkAddress"
                )

            $Normalized.workstation = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "WorkstationName"
                )

            break
        }

        # ===================================================================
        # 4625 - Failed logon
        # ===================================================================

        4625 {

            $Normalized.target_user = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "TargetUserName"
                )

            $Normalized.failure_reason = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "FailureReason",
                    "Status",
                    "SubStatus"
                )

            $Normalized.source_ip = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "IpAddress",
                    "SourceNetworkAddress"
                )

            break
        }

        # ===================================================================
        # 4672 - Special privileges
        # ===================================================================

        4672 {

            $Normalized.privileged_account = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "SubjectUserName"
                )

            break
        }

        # ===================================================================
        # 4688 - Process creation
        # ===================================================================

        4688 {

            $Normalized.process_name = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "NewProcessName"
                )

            $Normalized.command_line = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "CommandLine",
                    "ProcessCommandLine"
                )

            $Normalized.parent_process = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "ParentProcessName",
                    "CreatorProcessName"
                )

            break
        }
    }
}

# ===========================================================================
# PowerShell enrichment
# ===========================================================================

function Add-PowerShellEnrichment {

    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Normalized,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $Data = Get-EventDataMap `
        -Event $Event

    if ($Event.Id -eq 4104) {

        # ScriptBlock Event ID 4104 contains decoded script content.
        $ScriptBlockText = Get-FieldValue `
            -Map $Data `
            -Names @(
                "ScriptBlockText",
                "Message"
            )

        if (
            [string]::IsNullOrWhiteSpace(
                [string]$ScriptBlockText
            )
        ) {

            $ScriptBlockText = [string]$Event.Message
        }

        $Normalized.script_block_text = $ScriptBlockText

        $Normalized.script_block_decoded = $true
    }
}

# ===========================================================================
# Sysmon enrichment
# ===========================================================================

function Add-SysmonEnrichment {

    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Normalized,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $Data = Get-EventDataMap `
        -Event $Event

    switch ($Event.Id) {

        # ===================================================================
        # Sysmon Event ID 1 - ProcessCreate
        # ===================================================================

        1 {

            $Normalized.image = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "Image"
                )

            $Normalized.command_line = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "CommandLine"
                )

            $Normalized.parent_image = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "ParentImage"
                )

            $Normalized.hashes = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "Hashes"
                )

            break
        }

        # ===================================================================
        # Sysmon Event ID 3 - NetworkConnect
        # ===================================================================

        3 {

            $Normalized.destination_ip = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "DestinationIp"
                )

            $Normalized.destination_port = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "DestinationPort"
                )

            $Normalized.process = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "Image"
                )

            break
        }

        # ===================================================================
        # Sysmon Event ID 11 - FileCreate
        # ===================================================================

        11 {

            $Normalized.target_filename = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "TargetFilename"
                )

            $Normalized.creating_process = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "Image"
                )

            break
        }

        # ===================================================================
        # Sysmon Event ID 13 - Registry modification
        # ===================================================================

        13 {

            $TargetObject = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "TargetObject"
                )

            $Normalized.registry_key = $TargetObject

            $Normalized.registry_operation = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "EventType"
                )

            if (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$TargetObject
                )
            ) {

                $LastSlash = $TargetObject.LastIndexOf("\")

                if ($LastSlash -ge 0) {

                    $Normalized.registry_value_name = `
                        $TargetObject.Substring(
                            $LastSlash + 1
                        )
                }
                else {

                    $Normalized.registry_value_name = $null
                }
            }
            else {

                $Normalized.registry_value_name = $null
            }

            break
        }

        # ===================================================================
        # Sysmon Event ID 22 - DNSQuery
        # ===================================================================

        22 {

            $Normalized.query_name = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "QueryName"
                )

            $Normalized.query_results = Get-FieldValue `
                -Map $Data `
                -Names @(
                    "QueryResults"
                )

            break
        }
    }
}

# ===========================================================================
# Read one event channel
# ===========================================================================

function Get-ChannelEvents {

    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    try {

        $LogInfo = Get-WinEvent `
            -ListLog $LogName `
            -ErrorAction Stop

        if (-not $LogInfo.IsEnabled) {

            Write-Host `
                "[WARN] Channel disabled: $LogName"

            return @()
        }

        return @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = $LogName
                    StartTime = $StartTime
                    EndTime   = $EndTime
                } `
                -ErrorAction SilentlyContinue
        )
    }
    catch {

        Write-Host `
            "[WARN] Channel unavailable: $LogName"

        return @()
    }
}

# ===========================================================================
# Begin export
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Telemetry Normalizer"
Write-Host "=============================================="
Write-Host ""

if ($Hours -eq 24) {

    Write-Host `
        "[*] Exporting Windows telemetry from last 24 hours..."
}
else {

    Write-Host `
        "[*] Exporting Windows telemetry from last $Hours hours..."
}

Write-Host `
    "    StartTime: $($StartTime.ToString('o'))"

Write-Host `
    "    EndTime:   $($EndTime.ToString('o'))"

# ===========================================================================
# Security
# ===========================================================================

$SecurityEvents = @(
    Get-ChannelEvents `
        -LogName $SecurityChannel `
        -StartTime $StartTime `
        -EndTime $EndTime
)

# ===========================================================================
# Sysmon
# ===========================================================================

$SysmonEvents = @(
    Get-ChannelEvents `
        -LogName $SysmonChannel `
        -StartTime $StartTime `
        -EndTime $EndTime
)

# ===========================================================================
# PowerShell
# ===========================================================================

$PowerShellEvents = @(
    Get-ChannelEvents `
        -LogName $PowerShellChannel `
        -StartTime $StartTime `
        -EndTime $EndTime
)

# ===========================================================================
# Normalize all events
# ===========================================================================

$NormalizedEvents = @()

# ---------------------------------------------------------------------------
# Security events
# ---------------------------------------------------------------------------

foreach ($Event in $SecurityEvents) {

    $Normalized = New-NormalizedEvent `
        -Event $Event `
        -SourceType "Security"

    Add-SecurityEnrichment `
        -Normalized $Normalized `
        -Event $Event

    $NormalizedEvents += [PSCustomObject]$Normalized
}

# ---------------------------------------------------------------------------
# Sysmon events
# ---------------------------------------------------------------------------

foreach ($Event in $SysmonEvents) {

    $Normalized = New-NormalizedEvent `
        -Event $Event `
        -SourceType "Sysmon"

    Add-SysmonEnrichment `
        -Normalized $Normalized `
        -Event $Event

    $NormalizedEvents += [PSCustomObject]$Normalized
}

# ---------------------------------------------------------------------------
# PowerShell events
# ---------------------------------------------------------------------------

foreach ($Event in $PowerShellEvents) {

    $Normalized = New-NormalizedEvent `
        -Event $Event `
        -SourceType "PowerShell"

    Add-PowerShellEnrichment `
        -Normalized $Normalized `
        -Event $Event

    $NormalizedEvents += [PSCustomObject]$Normalized
}

# ===========================================================================
# Sort by normalized timestamp
# ===========================================================================

$NormalizedEvents = @(
    $NormalizedEvents |
    Sort-Object timestamp
)

# ===========================================================================
# Counts
# ===========================================================================

$SecurityCount = $SecurityEvents.Count

$SysmonCount = $SysmonEvents.Count

$PowerShellCount = $PowerShellEvents.Count

$TotalEvents = $NormalizedEvents.Count

# ===========================================================================
# Top Event IDs
# ===========================================================================

$TopGroups = @(
    $NormalizedEvents |
    Group-Object source_type,event_id |
    Sort-Object Count -Descending |
    Select-Object -First 10
)

$TopEventIds = @()

foreach ($Group in $TopGroups) {

    $Sample = $Group.Group |
        Select-Object -First 1

    if ($Sample.source_type -eq "Sysmon") {

        $DisplayName = "Sysmon-$($Sample.event_id)"
    }
    else {

        $DisplayName = [string]$Sample.event_id
    }

    $TopEventIds += [PSCustomObject]@{

        event = $DisplayName

        source_type = $Sample.source_type

        event_id = [int]$Sample.event_id

        count = $Group.Count
    }
}

# ===========================================================================
# Build JSON report
# ===========================================================================

$Report = [ordered]@{

    metadata = [ordered]@{

        generated_at = `
            $ExportTimestamp.ToUniversalTime().ToString("o")

        hostname = $HostnameValue

        platform = $PlatformValue

        time_window_hours = $Hours

        StartTime = `
            $StartTime.ToUniversalTime().ToString("o")

        EndTime = `
            $EndTime.ToUniversalTime().ToString("o")

        window_start = `
            $StartTime.ToUniversalTime().ToString("o")

        window_end = `
            $EndTime.ToUniversalTime().ToString("o")

        output_file = "windows_events_export.json"
    }

    channel_counts = [ordered]@{

        Security = $SecurityCount

        Sysmon = $SysmonCount

        PowerShell = $PowerShellCount

        total = $TotalEvents
    }

    top_event_ids = $TopEventIds

    events = $NormalizedEvents
}

# ===========================================================================
# Export JSON
# ===========================================================================

try {

    $Json = $Report |
        ConvertTo-Json `
            -Depth 15

    Set-Content `
        -Path $OutputPath `
        -Value $Json `
        -Encoding UTF8
}
catch {

    Write-Host `
        "[FAIL] Unable to create windows_events_export.json"

    throw
}

# ===========================================================================
# Validate JSON
# ===========================================================================

try {

    $null = Get-Content `
        -Path $OutputPath `
        -Raw `
        -ErrorAction Stop |
        ConvertFrom-Json
}
catch {

    Write-Host `
        "[FAIL] windows_events_export.json is invalid."

    exit 1
}

# ===========================================================================
# Console summary
# ===========================================================================

Write-Host ""
Write-Host "Security events: $SecurityCount"
Write-Host "Sysmon events: $SysmonCount"
Write-Host "PowerShell events: $PowerShellCount"
Write-Host "Total events: $TotalEvents"

Write-Host ""

if ($TopEventIds.Count -gt 0) {

    $TopFour = @(
        $TopEventIds |
        Select-Object -First 4 |
        ForEach-Object {
            $_.event
        }
    )

    Write-Host `
        "Top Event IDs: $($TopFour -join ', ')"
}
else {

    Write-Host "Top Event IDs: none"
}

Write-Host ""
Write-Host "Output: windows_events_export.json"
Write-Host ""

exit 0