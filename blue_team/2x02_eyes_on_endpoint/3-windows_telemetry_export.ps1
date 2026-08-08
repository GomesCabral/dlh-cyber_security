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
# Enriched event types:
# Security:
# - 4624
# - 4625
# - 4672
# - 4688
#
# PowerShell:
# - 4104
#
# Sysmon:
# - 1
# - 3
# - 11
# - 13
# - 22
#
# Safety:
# READ-ONLY.
# The script reads Windows Event Logs and writes a JSON export only.

[CmdletBinding()]
param(
    [int]$Hours = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

if ($Hours -le 0) {
    throw "Hours must be greater than 0."
}

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$OutputPath = Join-Path `
    $ScriptDirectory `
    "windows_events_export.json"

$HostnameValue = $env:COMPUTERNAME

$PlatformValue = "Windows"

$StartTime = (Get-Date).AddHours(
    -1 * $Hours
)

$ExportTimestamp = Get-Date

$SecurityChannel = "Security"

$SysmonChannel = "Microsoft-Windows-Sysmon/Operational"

$PowerShellChannel = "Microsoft-Windows-PowerShell/Operational"

# ===========================================================================
# Helper: XML EventData extraction
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
# Helper: UserData extraction
# ===========================================================================

function Get-UserDataMap {

    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $Fields = [ordered]@{}

    try {

        [xml]$EventXml = $Event.ToXml()

        if ($null -ne $EventXml.Event.UserData) {

            $Nodes = @(
                $EventXml.Event.UserData.SelectNodes(
                    ".//*[not(*)]"
                )
            )

            foreach ($Node in $Nodes) {

                $Name = [string]$Node.LocalName

                if (
                    -not [string]::IsNullOrWhiteSpace($Name)
                ) {

                    $Fields[$Name] = [string]$Node.InnerText
                }
            }
        }
    }
    catch {
    }

    return $Fields
}

# ===========================================================================
# Helper: safe field lookup
# ===========================================================================

function Get-Field {

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

    if ($SourceType -eq "Security") {

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

    if ($SourceType -eq "PowerShell") {

        switch ($EventId) {

            4103 { return "powershell_module_logging" }
            4104 { return "powershell_script_block" }

            default {
                return "powershell"
            }
        }
    }

    if ($SourceType -eq "Sysmon") {

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

    return "unknown"
}

# ===========================================================================
# Helper: common normalized event
# ===========================================================================

function New-NormalizedEvent {

    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,

        [Parameter(Mandatory = $true)]
        [string]$SourceType
    )

    return [ordered]@{
        timestamp = if ($null -ne $Event.TimeCreated) {
            $Event.TimeCreated.ToUniversalTime().ToString("o")
        }
        else {
            $null
        }

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
# Helper: Security event enrichment
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

        # -------------------------------------------------------------------
        # 4624 - Successful logon
        # -------------------------------------------------------------------

        4624 {

            $Normalized.target_user = Get-Field `
                -Map $Data `
                -Names @(
                    "TargetUserName"
                )

            $Normalized.logon_type = Get-Field `
                -Map $Data `
                -Names @(
                    "LogonType"
                )

            $Normalized.source_ip = Get-Field `
                -Map $Data `
                -Names @(
                    "IpAddress",
                    "SourceNetworkAddress"
                )

            $Normalized.workstation = Get-Field `
                -Map $Data `
                -Names @(
                    "WorkstationName"
                )

            break
        }

        # -------------------------------------------------------------------
        # 4625 - Failed logon
        # -------------------------------------------------------------------

        4625 {

            $Normalized.target_user = Get-Field `
                -Map $Data `
                -Names @(
                    "TargetUserName"
                )

            $Normalized.failure_reason = Get-Field `
                -Map $Data `
                -Names @(
                    "FailureReason"
                )

            $Normalized.source_ip = Get-Field `
                -Map $Data `
                -Names @(
                    "IpAddress",
                    "SourceNetworkAddress"
                )

            break
        }

        # -------------------------------------------------------------------
        # 4672 - Special privileges assigned
        # -------------------------------------------------------------------

        4672 {

            $Normalized.privileged_account = Get-Field `
                -Map $Data `
                -Names @(
                    "SubjectUserName"
                )

            break
        }

        # -------------------------------------------------------------------
        # 4688 - Process creation
        # -------------------------------------------------------------------

        4688 {

            $Normalized.process_name = Get-Field `
                -Map $Data `
                -Names @(
                    "NewProcessName"
                )

            $Normalized.command_line = Get-Field `
                -Map $Data `
                -Names @(
                    "CommandLine",
                    "ProcessCommandLine"
                )

            $Normalized.parent_process = Get-Field `
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
# Helper: PowerShell enrichment
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

        # Script Block Logging stores the decoded script block text.
        $Normalized.script_block_text = Get-Field `
            -Map $Data `
            -Names @(
                "ScriptBlockText",
                "Message"
            )

        if (
            [string]::IsNullOrWhiteSpace(
                [string]$Normalized.script_block_text
            )
        ) {

            # Fallback to the rendered event message if ScriptBlockText
            # was not exposed as a named EventData field.
            $Normalized.script_block_text = [string]$Event.Message
        }

        $Normalized.script_block_decoded = $true
    }
}

# ===========================================================================
# Helper: Sysmon enrichment
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

        # -------------------------------------------------------------------
        # Sysmon 1 - ProcessCreate
        # -------------------------------------------------------------------

        1 {

            $Normalized.image = Get-Field `
                -Map $Data `
                -Names @(
                    "Image"
                )

            $Normalized.command_line = Get-Field `
                -Map $Data `
                -Names @(
                    "CommandLine"
                )

            $Normalized.parent_image = Get-Field `
                -Map $Data `
                -Names @(
                    "ParentImage"
                )

            $Normalized.hashes = Get-Field `
                -Map $Data `
                -Names @(
                    "Hashes"
                )

            break
        }

        # -------------------------------------------------------------------
        # Sysmon 3 - NetworkConnect
        # -------------------------------------------------------------------

        3 {

            $Normalized.destination_ip = Get-Field `
                -Map $Data `
                -Names @(
                    "DestinationIp"
                )

            $Normalized.destination_port = Get-Field `
                -Map $Data `
                -Names @(
                    "DestinationPort"
                )

            $Normalized.process = Get-Field `
                -Map $Data `
                -Names @(
                    "Image"
                )

            break
        }

        # -------------------------------------------------------------------
        # Sysmon 11 - FileCreate
        # -------------------------------------------------------------------

        11 {

            $Normalized.target_filename = Get-Field `
                -Map $Data `
                -Names @(
                    "TargetFilename"
                )

            $Normalized.creating_process = Get-Field `
                -Map $Data `
                -Names @(
                    "Image"
                )

            break
        }

        # -------------------------------------------------------------------
        # Sysmon 13 - RegistryEvent / Value Set
        # -------------------------------------------------------------------

        13 {

            $TargetObject = Get-Field `
                -Map $Data `
                -Names @(
                    "TargetObject"
                )

            $Normalized.registry_key = $TargetObject

            if (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$TargetObject
                )
            ) {

                $LastSeparator = $TargetObject.LastIndexOf("\")

                if ($LastSeparator -ge 0) {

                    $Normalized.registry_value_name = `
                        $TargetObject.Substring(
                            $LastSeparator + 1
                        )
                }
                else {

                    $Normalized.registry_value_name = $null
                }
            }
            else {

                $Normalized.registry_value_name = $null
            }

            $Normalized.registry_operation = Get-Field `
                -Map $Data `
                -Names @(
                    "EventType"
                )

            break
        }

        # -------------------------------------------------------------------
        # Sysmon 22 - DNSQuery
        # -------------------------------------------------------------------

        22 {

            $Normalized.query_name = Get-Field `
                -Map $Data `
                -Names @(
                    "QueryName"
                )

            $Normalized.query_results = Get-Field `
                -Map $Data `
                -Names @(
                    "QueryResults"
                )

            break
        }
    }
}

# ===========================================================================
# Helper: retrieve channel
# ===========================================================================

function Get-ChannelEvents {

    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
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
# Start
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
    "    Start timestamp: $($StartTime.ToString('o'))"

Write-Host `
    "    Export timestamp: $($ExportTimestamp.ToString('o'))"

# ===========================================================================
# Read Security
# ===========================================================================

$SecurityEvents = @(
    Get-ChannelEvents `
        -LogName $SecurityChannel `
        -StartTime $StartTime
)

# ===========================================================================
# Read Sysmon
# ===========================================================================

$SysmonEvents = @(
    Get-ChannelEvents `
        -LogName $SysmonChannel `
        -StartTime $StartTime
)

# ===========================================================================
# Read PowerShell
# ===========================================================================

$PowerShellEvents = @(
    Get-ChannelEvents `
        -LogName $PowerShellChannel `
        -StartTime $StartTime
)

# ===========================================================================
# Normalize events
# ===========================================================================

$NormalizedEvents = @()

# ---------------------------------------------------------------------------
# Security
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
# Sysmon
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
# PowerShell
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
# Sort into analyst timeline
# ===========================================================================

$NormalizedEvents = @(
    $NormalizedEvents |
    Sort-Object timestamp
)

# ===========================================================================
# Count per channel
# ===========================================================================

$SecurityCount = $SecurityEvents.Count
$SysmonCount = $SysmonEvents.Count
$PowerShellCount = $PowerShellEvents.Count

$TotalEvents = $NormalizedEvents.Count

# ===========================================================================
# Top Event IDs
# ===========================================================================

$TopEventGroups = @(
    $NormalizedEvents |
    Group-Object source_type,event_id |
    Sort-Object Count -Descending |
    Select-Object -First 10
)

$TopEventIds = @()

foreach ($Group in $TopEventGroups) {

    $Sample = $Group.Group |
        Select-Object -First 1

    $DisplayId = if ($Sample.source_type -eq "Sysmon") {

        "Sysmon-$($Sample.event_id)"
    }
    elseif ($Sample.source_type -eq "PowerShell") {

        [string]$Sample.event_id
    }
    else {

        [string]$Sample.event_id
    }

    $TopEventIds += [PSCustomObject]@{
        event = $DisplayId
        source_type = $Sample.source_type
        event_id = [int]$Sample.event_id
        count = $Group.Count
    }
}

# ===========================================================================
# JSON document
# ===========================================================================

$Report = [ordered]@{

    metadata = [ordered]@{
        generated_at = $ExportTimestamp.ToUniversalTime().ToString("o")
        hostname = $HostnameValue
        platform = $PlatformValue
        time_window_hours = $Hours
        window_start = $StartTime.ToUniversalTime().ToString("o")
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
# Write windows_events_export.json
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
        "[FAIL] Unable to write windows_events_export.json"

    throw
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

    Write-Host `
        "[FAIL] windows_events_export.json is not valid JSON."

    exit 1
}

# ===========================================================================
# Console output
# ===========================================================================

Write-Host ""
Write-Host "Security events: $SecurityCount"
Write-Host "Sysmon events: $SysmonCount"
Write-Host "PowerShell events: $PowerShellCount"
Write-Host "Total events: $TotalEvents"

Write-Host ""

if ($TopEventIds.Count -gt 0) {

    $TopDisplay = @(
        $TopEventIds |
        Select-Object -First 4 |
        ForEach-Object {
            $_.event
        }
    )

    Write-Host `
        "Top Event IDs: $($TopDisplay -join ', ')"
}
else {

    Write-Host "Top Event IDs: none"
}

Write-Host ""
Write-Host "Output: windows_events_export.json"
Write-Host ""

exit 0