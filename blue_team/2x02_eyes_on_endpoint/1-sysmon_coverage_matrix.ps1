# name: 1-sysmon_coverage_matrix.ps1
# purpose: Parse sysmonconfig.xml and generate an ATT&CK-aligned Sysmon telemetry coverage matrix.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 1 - Sysmon ATT&CK Coverage Matrix
#
# Input:
# - sysmonconfig.xml
#
# Output:
# - sysmon_coverage_matrix.json
#
# The script evaluates Sysmon coverage in three dimensions:
# 1. Whether the required Event IDs are enabled
# 2. Whether EventFiltering include/exclude rules may suppress activity
# 3. Whether the event type provides the evidence fields required for triage
#
# Coverage states:
# - covered
# - partial
# - blind
#
# Required ATT&CK mappings:
# T1059     Command and Scripting Interpreter    -> Sysmon EID 1
# T1053     Scheduled Task/Job                   -> Sysmon EID 1
# T1547     Boot or Logon Autostart Execution    -> Sysmon EID 13
# T1055     Process Injection                    -> Sysmon EID 8, 10
# T1071     Application Layer Protocol           -> Sysmon EID 3, 22
# T1574.002 DLL Side-Loading                     -> Sysmon EID 7
# T1027     Obfuscated or Compressed Files       -> Sysmon EID 11, 15
#
# Required matrix fields:
# - technique_id
# - technique_name
# - required_event_ids
# - enabled_event_ids
# - filter_conflicts
# - coverage_status
# - evidence_fields_expected
# - recommendation
#
# Safety:
# READ-ONLY. The script does not modify Sysmon, Windows, Registry,
# Group Policy or security configuration.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Paths
# ===========================================================================

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$SysmonConfigPath = Join-Path `
    $ScriptDirectory `
    "sysmonconfig.xml"

$OutputPath = Join-Path `
    $ScriptDirectory `
    "sysmon_coverage_matrix.json"

# ===========================================================================
# Sysmon Event ID mapping
# ===========================================================================

# Sysmon configuration XML uses event names rather than Event IDs.
#
# RegistryEvent represents:
# 12 = Registry object create/delete
# 13 = Registry value set
# 14 = Registry object rename
#
# PipeEvent represents:
# 17 = Pipe created
# 18 = Pipe connected
#
# WmiEvent represents:
# 19 = WMI filter
# 20 = WMI consumer
# 21 = WMI consumer-to-filter binding

$SysmonEventMap = [ordered]@{

    ProcessCreate            = @(1)
    FileCreateTime           = @(2)
    NetworkConnect           = @(3)
    SysmonServiceStateChange = @(4)
    ProcessTerminate         = @(5)
    DriverLoad               = @(6)
    ImageLoad                = @(7)
    CreateRemoteThread       = @(8)
    RawAccessRead            = @(9)
    ProcessAccess            = @(10)
    FileCreate               = @(11)
    RegistryEvent            = @(12, 13, 14)
    FileCreateStreamHash     = @(15)
    PipeEvent                = @(17, 18)
    WmiEvent                 = @(19, 20, 21)
    DNSQuery                 = @(22)
    FileDelete               = @(23)
    ClipboardChange          = @(24)
    ProcessTampering         = @(25)
    FileDeleteDetected       = @(26)
}

# ===========================================================================
# Expected Sysmon evidence fields
# ===========================================================================

$SysmonEvidenceFields = @{

    1 = @(
        "Image",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "User",
        "ProcessId",
        "ParentProcessId",
        "Hashes"
    )

    3 = @(
        "Image",
        "User",
        "Protocol",
        "SourceIp",
        "SourcePort",
        "DestinationIp",
        "DestinationPort"
    )

    7 = @(
        "Image",
        "ImageLoaded",
        "Hashes",
        "Signed",
        "Signature",
        "SignatureStatus"
    )

    8 = @(
        "SourceImage",
        "TargetImage",
        "SourceProcessId",
        "TargetProcessId",
        "StartAddress"
    )

    10 = @(
        "SourceImage",
        "TargetImage",
        "SourceProcessId",
        "TargetProcessId",
        "GrantedAccess"
    )

    11 = @(
        "Image",
        "TargetFilename",
        "CreationUtcTime"
    )

    13 = @(
        "EventType",
        "TargetObject",
        "Details",
        "Image",
        "User"
    )

    15 = @(
        "Image",
        "TargetFilename",
        "Hash",
        "Contents"
    )

    22 = @(
        "Image",
        "QueryName",
        "QueryStatus",
        "QueryResults"
    )
}

# ===========================================================================
# ATT&CK mappings
# ===========================================================================

$AttackMappings = @(

    [PSCustomObject]@{
        technique_id = "T1059"
        technique_name = "Command and Scripting Interpreter"
        required_event_ids = @(1)

        threat_example = (
            "PowerShell, cmd.exe, wscript.exe or another command " +
            "interpreter used for attacker execution."
        )
    },

    [PSCustomObject]@{
        technique_id = "T1053"
        technique_name = "Scheduled Task/Job"
        required_event_ids = @(1)

        threat_example = (
            "schtasks.exe /create used to establish persistence " +
            "or execute a payload."
        )
    },

    [PSCustomObject]@{
        technique_id = "T1547"
        technique_name = "Boot or Logon Autostart Execution"
        required_event_ids = @(13)

        threat_example = (
            "Registry Run or RunOnce key modified so malware " +
            "executes during user logon."
        )
    },

    [PSCustomObject]@{
        technique_id = "T1055"
        technique_name = "Process Injection"
        required_event_ids = @(8, 10)

        threat_example = (
            "A malicious process accesses another process or creates " +
            "a remote thread for code injection."
        )
    },

    [PSCustomObject]@{
        technique_id = "T1071"
        technique_name = "Application Layer Protocol"
        required_event_ids = @(3, 22)

        threat_example = (
            "Malware performs a DNS query for command-and-control " +
            "infrastructure and then establishes a network connection."
        )
    },

    [PSCustomObject]@{
        technique_id = "T1574.002"
        technique_name = "DLL Side-Loading"
        required_event_ids = @(7)

        threat_example = (
            "A trusted application loads a malicious DLL from an " +
            "unexpected directory."
        )
    },

    [PSCustomObject]@{
        technique_id = "T1027"
        technique_name = "Obfuscated or Compressed Files"
        required_event_ids = @(11, 15)

        threat_example = (
            "An attacker writes encoded, packed or alternate-data-stream " +
            "content to disk."
        )
    }
)

# ===========================================================================
# Helper: find EventFiltering
# ===========================================================================

function Get-EventFilteringNode {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    # Sysmon rules are stored under the EventFiltering element.
    $EventFiltering = $Xml.SelectSingleNode(
        "//*[local-name()='EventFiltering']"
    )

    return $EventFiltering
}

# ===========================================================================
# Helper: get XML event names
# ===========================================================================

function Get-ConfiguredEventTypes {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    $EventFiltering = Get-EventFilteringNode `
        -Xml $Xml

    if ($null -eq $EventFiltering) {
        return @()
    }

    $FoundEventTypes = @()

    foreach ($EventType in $SysmonEventMap.Keys) {

        $Nodes = @(
            $EventFiltering.SelectNodes(
                ".//*[local-name()='$EventType']"
            )
        )

        if ($Nodes.Count -gt 0) {

            $FoundEventTypes += $EventType
        }
    }

    return @(
        $FoundEventTypes |
        Sort-Object -Unique
    )
}

# ===========================================================================
# Helper: enabled Event IDs
# ===========================================================================

function Get-EnabledEventIds {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    $ConfiguredEventTypes = @(
        Get-ConfiguredEventTypes `
            -Xml $Xml
    )

    $EnabledIds = @()

    foreach ($EventType in $ConfiguredEventTypes) {

        foreach ($EventId in @($SysmonEventMap[$EventType])) {

            $EnabledIds += [int]$EventId
        }
    }

    return @(
        $EnabledIds |
        Sort-Object -Unique
    )
}

# ===========================================================================
# Helper: Event ID -> XML event name
# ===========================================================================

function Get-EventTypesForId {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId
    )

    $Names = @()

    foreach ($EventType in $SysmonEventMap.Keys) {

        if (
            @($SysmonEventMap[$EventType]) -contains
            $EventId
        ) {

            $Names += $EventType
        }
    }

    return @($Names)
}

# ===========================================================================
# Helper: collect filter information
# ===========================================================================

function Get-FilterAssessment {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml,

        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds
    )

    $EventFiltering = Get-EventFilteringNode `
        -Xml $Xml

    $FilterInventory = @()
    $Conflicts = @()

    if ($null -eq $EventFiltering) {

        return [PSCustomObject]@{
            filters = @()
            conflicts = @(
                "EventFiltering section is missing"
            )
        }
    }

    foreach ($EventId in $RequiredEventIds) {

        $EventTypes = @(
            Get-EventTypesForId `
                -EventId $EventId
        )

        foreach ($EventType in $EventTypes) {

            $Nodes = @(
                $EventFiltering.SelectNodes(
                    ".//*[local-name()='$EventType']"
                )
            )

            foreach ($Node in $Nodes) {

                $OnMatch = [string]$Node.GetAttribute(
                    "onmatch"
                )

                if ([string]::IsNullOrWhiteSpace($OnMatch)) {
                    $OnMatch = "not_specified"
                }

                # -----------------------------------------------------------
                # Record all include/exclude filters for evidence.
                # -----------------------------------------------------------

                $Conditions = @(
                    $Node.SelectNodes(
                        ".//*[not(*)]"
                    )
                )

                if ($Conditions.Count -eq 0) {

                    $FilterInventory += [PSCustomObject]@{
                        event_id = $EventId
                        event_type = $EventType
                        onmatch = $OnMatch
                        field = $null
                        condition = $null
                        value = $null
                    }
                }

                foreach ($ConditionNode in $Conditions) {

                    $ConditionName = [string]$ConditionNode.LocalName

                    # Ignore Rule wrapper elements.
                    if ($ConditionName -eq "Rule") {
                        continue
                    }

                    $ConditionType = [string]$ConditionNode.GetAttribute(
                        "condition"
                    )

                    $ConditionValue = [string]$ConditionNode.InnerText

                    $FilterInventory += [PSCustomObject]@{
                        event_id = $EventId
                        event_type = $EventType
                        onmatch = $OnMatch
                        field = $ConditionName
                        condition = $ConditionType
                        value = $ConditionValue
                    }

                    # -------------------------------------------------------
                    # Detect potentially dangerous broad exclusions.
                    #
                    # We do NOT classify every normal exclude rule as a
                    # conflict because high-quality Sysmon configs contain
                    # many noise-reduction exclusions.
                    #
                    # Broad/wildcard exclusions are considered conflicts.
                    # -------------------------------------------------------

                    if ($OnMatch -ieq "exclude") {

                        $BroadExclusion = $false

                        if (
                            [string]::IsNullOrWhiteSpace(
                                $ConditionValue
                            )
                        ) {

                            $BroadExclusion = $true
                        }

                        if ($ConditionValue -eq "*") {

                            $BroadExclusion = $true
                        }

                        if (
                            $ConditionType -match
                            "(?i)^is any$"
                        ) {

                            $BroadExclusion = $true
                        }

                        if ($BroadExclusion) {

                            $Conflicts += (
                                "EID $EventId / $EventType has a broad " +
                                "exclude rule that may suppress security-relevant activity."
                            )
                        }
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        filters = @(
            $FilterInventory
        )

        conflicts = @(
            $Conflicts |
            Sort-Object -Unique
        )
    }
}

# ===========================================================================
# Helper: expected evidence fields
# ===========================================================================

function Get-EvidenceFields {

    param(
        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds
    )

    $Fields = @()

    foreach ($EventId in $RequiredEventIds) {

        if ($SysmonEvidenceFields.ContainsKey($EventId)) {

            $Fields += @(
                $SysmonEvidenceFields[$EventId]
            )
        }
    }

    return @(
        $Fields |
        Sort-Object -Unique
    )
}

# ===========================================================================
# Helper: calculate coverage
# ===========================================================================

function Get-CoverageStatus {

    param(
        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$EnabledEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$FilterConflicts
    )

    $EnabledRequiredIds = @(
        $RequiredEventIds |
        Where-Object {
            $EnabledEventIds -contains $_
        }
    )

    # No required telemetry at all.
    if ($EnabledRequiredIds.Count -eq 0) {

        return "blind"
    }

    # Some required telemetry is missing.
    if (
        $EnabledRequiredIds.Count -lt
        $RequiredEventIds.Count
    ) {

        return "partial"
    }

    # All required telemetry exists, but an obvious filter conflict exists.
    if ($FilterConflicts.Count -gt 0) {

        return "partial"
    }

    return "covered"
}

# ===========================================================================
# Helper: reason
# ===========================================================================

function Get-CoverageReason {

    param(
        [Parameter(Mandatory = $true)]
        [string]$CoverageStatus,

        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$EnabledEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$FilterConflicts
    )

    $MissingIds = @(
        $RequiredEventIds |
        Where-Object {
            $EnabledEventIds -notcontains $_
        }
    )

    if ($CoverageStatus -eq "covered") {

        return (
            "All required Sysmon Event IDs are enabled and no broad " +
            "filter conflict was identified. Expected event fields " +
            "are available in the Sysmon event schema for triage."
        )
    }

    if ($CoverageStatus -eq "blind") {

        return (
            "None of the required Sysmon Event IDs are enabled. " +
            "The technique currently has no required Sysmon telemetry."
        )
    }

    $Reasons = @()

    if ($MissingIds.Count -gt 0) {

        $Reasons += (
            "Missing required Sysmon Event ID(s): " +
            ($MissingIds -join ", ")
        )
    }

    if ($FilterConflicts.Count -gt 0) {

        $Reasons += (
            "One or more EventFiltering rules may suppress " +
            "security-relevant telemetry."
        )
    }

    return ($Reasons -join "; ")
}

# ===========================================================================
# Helper: recommendation
# ===========================================================================

function Get-Recommendation {

    param(
        [Parameter(Mandatory = $true)]
        [string]$CoverageStatus,

        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$EnabledEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$FilterConflicts
    )

    if ($CoverageStatus -eq "covered") {

        return (
            "Maintain the current Sysmon configuration and periodically " +
            "validate the telemetry with controlled ATT&CK-aligned tests."
        )
    }

    $MissingIds = @(
        $RequiredEventIds |
        Where-Object {
            $EnabledEventIds -notcontains $_
        }
    )

    $Actions = @()

    if ($MissingIds.Count -gt 0) {

        $Actions += (
            "Enable missing Sysmon Event ID(s): " +
            ($MissingIds -join ", ")
        )
    }

    if ($FilterConflicts.Count -gt 0) {

        $Actions += (
            "Review EventFiltering include/exclude rules and narrow " +
            "filters that may suppress attacker activity"
        )
    }

    $Actions += (
        "Run a controlled trigger and verify that the expected " +
        "evidence fields are present"
    )

    return ($Actions -join "; ")
}

# ===========================================================================
# Start
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Sysmon ATT&CK Coverage Matrix"
Write-Host "=============================================="
Write-Host ""

Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"

# ===========================================================================
# Validate input
# ===========================================================================

if (-not (Test-Path $SysmonConfigPath)) {

    Write-Host "[FAIL] sysmonconfig.xml not found."
    Write-Host "       Expected path: $SysmonConfigPath"

    exit 1
}

# ===========================================================================
# Parse XML
# ===========================================================================

try {

    [xml]$SysmonConfig = Get-Content `
        -Path $SysmonConfigPath `
        -Raw `
        -ErrorAction Stop
}
catch {

    Write-Host (
        "[FAIL] Unable to parse sysmonconfig.xml: " +
        $_.Exception.Message
    )

    exit 1
}

# ===========================================================================
# Validate EventFiltering
# ===========================================================================

$EventFiltering = Get-EventFilteringNode `
    -Xml $SysmonConfig

if ($null -eq $EventFiltering) {

    Write-Host `
        "[FAIL] EventFiltering section not found in sysmonconfig.xml"

    exit 1
}

Write-Host "[*] EventFiltering section found."

# ===========================================================================
# Discover configured events
# ===========================================================================

$ConfiguredEventTypes = @(
    Get-ConfiguredEventTypes `
        -Xml $SysmonConfig
)

$EnabledEventIds = @(
    Get-EnabledEventIds `
        -Xml $SysmonConfig
)

if ($EnabledEventIds.Count -eq 0) {

    Write-Host "[WARN] No recognized Sysmon Event IDs found."
}
else {

    Write-Host (
        "Enabled Event IDs: " +
        ($EnabledEventIds -join ", ")
    )
}

# ===========================================================================
# Build coverage matrix
# ===========================================================================

$CoverageMatrix = @()

foreach ($Technique in $AttackMappings) {

    $RequiredIds = @(
        $Technique.required_event_ids
    )

    $EnabledRequiredIds = @(
        $RequiredIds |
        Where-Object {
            $EnabledEventIds -contains $_
        }
    )

    $FilterAssessment = Get-FilterAssessment `
        -Xml $SysmonConfig `
        -RequiredEventIds $RequiredIds

    $FilterConflicts = @(
        $FilterAssessment.conflicts
    )

    $EvidenceFields = @(
        Get-EvidenceFields `
            -RequiredEventIds $RequiredIds
    )

    $CoverageStatus = Get-CoverageStatus `
        -RequiredEventIds $RequiredIds `
        -EnabledEventIds $EnabledRequiredIds `
        -FilterConflicts $FilterConflicts

    $Reason = Get-CoverageReason `
        -CoverageStatus $CoverageStatus `
        -RequiredEventIds $RequiredIds `
        -EnabledEventIds $EnabledRequiredIds `
        -FilterConflicts $FilterConflicts

    $Recommendation = Get-Recommendation `
        -CoverageStatus $CoverageStatus `
        -RequiredEventIds $RequiredIds `
        -EnabledEventIds $EnabledRequiredIds `
        -FilterConflicts $FilterConflicts

    $CoverageMatrix += [PSCustomObject]@{

        technique_id = $Technique.technique_id

        technique_name = $Technique.technique_name

        required_event_ids = $RequiredIds

        enabled_event_ids = $EnabledRequiredIds

        filter_conflicts = $FilterConflicts

        coverage_status = $CoverageStatus

        reason = $Reason

        evidence_fields_expected = $EvidenceFields

        recommendation = $Recommendation

        threat_example = $Technique.threat_example

        filter_inventory = @(
            $FilterAssessment.filters
        )
    }
}

# ===========================================================================
# Coverage summary
# ===========================================================================

$CoveredCount = @(
    $CoverageMatrix |
    Where-Object {
        $_.coverage_status -eq "covered"
    }
).Count

$PartialCount = @(
    $CoverageMatrix |
    Where-Object {
        $_.coverage_status -eq "partial"
    }
).Count

$BlindCount = @(
    $CoverageMatrix |
    Where-Object {
        $_.coverage_status -eq "blind"
    }
).Count

$Summary = [ordered]@{

    timestamp = (Get-Date).ToString("o")

    source_config = "sysmonconfig.xml"

    EventFiltering_found = $true

    configured_event_types = $ConfiguredEventTypes

    enabled_event_ids = $EnabledEventIds

    techniques_assessed = $CoverageMatrix.Count

    covered = $CoveredCount

    partial = $PartialCount

    blind = $BlindCount
}

# ===========================================================================
# Build report
# ===========================================================================

$Report = [ordered]@{

    metadata = [ordered]@{

        project = "2x02_eyes_on_endpoint"

        task = "1 - Sysmon ATT&CK Coverage Matrix"

        timestamp = (Get-Date).ToString("o")

        computer = $env:COMPUTERNAME

        script = "1-sysmon_coverage_matrix.ps1"

        input_file = "sysmonconfig.xml"

        output_file = "sysmon_coverage_matrix.json"
    }

    summary = $Summary

    coverage_matrix = $CoverageMatrix
}

# ===========================================================================
# Write JSON
# ===========================================================================

try {

    $Json = $Report |
        ConvertTo-Json `
            -Depth 15

    # Set-Content terminates the file with a newline.
    Set-Content `
        -Path $OutputPath `
        -Value $Json `
        -Encoding UTF8
}
catch {

    Write-Host (
        "[FAIL] Could not write sysmon_coverage_matrix.json: " +
        $_.Exception.Message
    )

    exit 1
}

# ===========================================================================
# Validate generated JSON
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
        "[FAIL] sysmon_coverage_matrix.json is not valid JSON."

    exit 1
}

# ===========================================================================
# Console summary
# ===========================================================================

Write-Host ""
Write-Host "Techniques assessed: $($CoverageMatrix.Count)"
Write-Host "Covered: $CoveredCount"
Write-Host "Partial: $PartialCount"
Write-Host "Blind: $BlindCount"

Write-Host ""
Write-Host "Report saved to: sysmon_coverage_matrix.json"
Write-Host ""

exit 0