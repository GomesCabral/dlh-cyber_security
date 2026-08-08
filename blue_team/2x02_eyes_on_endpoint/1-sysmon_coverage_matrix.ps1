# name: 1-sysmon_coverage_matrix.ps1
# purpose: Parse the active Sysmon configuration and generate an ATT&CK-aligned telemetry coverage matrix.
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
# Required coverage statuses:
# - covered
# - partial
# - blind
#
# Required ATT&CK mappings:
# - T1059 Command and Scripting Interpreter -> Sysmon EID 1
# - T1053 Scheduled Task/Job -> Sysmon EID 1
# - T1547 Boot or Logon Autostart Execution -> Sysmon EID 13
# - T1055 Process Injection -> Sysmon EID 8, 10
# - T1071 Application Layer Protocol -> Sysmon EID 3, 22
# - T1574.002 DLL Side-Loading -> Sysmon EID 7
# - T1027 Obfuscated or Compressed Files -> Sysmon EID 11, 15
#
# Each matrix row includes:
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
# READ-ONLY.
# This script does not modify Sysmon configuration or Windows security settings.

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
# Sysmon event map
# ===========================================================================

# XML event type -> Sysmon Event ID
#
# RegistryEvent represents multiple Sysmon Event IDs:
# 12 = Registry object create/delete
# 13 = Registry value set
# 14 = Registry object rename

$SysmonEventMap = [ordered]@{
    ProcessCreate          = @(1)
    FileCreateTime         = @(2)
    NetworkConnect         = @(3)
    SysmonServiceStateChange = @(4)
    ProcessTerminate       = @(5)
    DriverLoad             = @(6)
    ImageLoad              = @(7)
    CreateRemoteThread     = @(8)
    RawAccessRead          = @(9)
    ProcessAccess          = @(10)
    FileCreate             = @(11)
    RegistryEvent          = @(12,13,14)
    FileCreateStreamHash   = @(15)
    PipeEvent              = @(17,18)
    WmiEvent               = @(19,20,21)
    DNSQuery               = @(22)
    FileDelete             = @(23)
    ClipboardChange        = @(24)
    ProcessTampering       = @(25)
    FileDeleteDetected     = @(26)
}

# ===========================================================================
# ATT&CK coverage requirements
# ===========================================================================

$AttackMappings = @(
    [PSCustomObject]@{
        technique_id = "T1059"
        technique_name = "Command and Scripting Interpreter"
        required_event_ids = @(1)

        evidence_fields_expected = @(
            "Image",
            "CommandLine",
            "ParentImage",
            "ParentCommandLine",
            "User",
            "ProcessId",
            "ParentProcessId",
            "Hashes"
        )

        threat_example = `
            "PowerShell, cmd.exe, wscript.exe or another interpreter used for attacker execution."
    },

    [PSCustomObject]@{
        technique_id = "T1053"
        technique_name = "Scheduled Task/Job"
        required_event_ids = @(1)

        evidence_fields_expected = @(
            "Image",
            "CommandLine",
            "ParentImage",
            "User",
            "ProcessId"
        )

        threat_example = `
            "schtasks.exe /create used by an attacker to establish persistence."
    },

    [PSCustomObject]@{
        technique_id = "T1547"
        technique_name = "Boot or Logon Autostart Execution"
        required_event_ids = @(13)

        evidence_fields_expected = @(
            "TargetObject",
            "Details",
            "Image",
            "User",
            "ProcessId"
        )

        threat_example = `
            "Registry Run or RunOnce keys modified to launch malware after user logon."
    },

    [PSCustomObject]@{
        technique_id = "T1055"
        technique_name = "Process Injection"
        required_event_ids = @(8,10)

        evidence_fields_expected = @(
            "SourceImage",
            "TargetImage",
            "SourceProcessId",
            "TargetProcessId",
            "GrantedAccess",
            "StartAddress"
        )

        threat_example = `
            "Malicious process accesses or creates a remote thread inside another process."
    },

    [PSCustomObject]@{
        technique_id = "T1071"
        technique_name = "Application Layer Protocol"
        required_event_ids = @(3,22)

        evidence_fields_expected = @(
            "Image",
            "DestinationIp",
            "DestinationPort",
            "Protocol",
            "QueryName",
            "QueryResults",
            "User"
        )

        threat_example = `
            "Malware resolves a command-and-control domain and connects to it over TCP."
    },

    [PSCustomObject]@{
        technique_id = "T1574.002"
        technique_name = "DLL Side-Loading"
        required_event_ids = @(7)

        evidence_fields_expected = @(
            "Image",
            "ImageLoaded",
            "Hashes",
            "Signed",
            "Signature",
            "SignatureStatus"
        )

        threat_example = `
            "A trusted executable loads a malicious DLL from an unexpected directory."
    },

    [PSCustomObject]@{
        technique_id = "T1027"
        technique_name = "Obfuscated or Compressed Files"
        required_event_ids = @(11,15)

        evidence_fields_expected = @(
            "Image",
            "TargetFilename",
            "Hash",
            "Contents"
        )

        threat_example = `
            "Malware writes encoded, packed or alternate-data-stream content to disk."
    }
)

# ===========================================================================
# Helper functions
# ===========================================================================

function Get-EventElementNames {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    $Found = @()

    foreach ($EventType in $SysmonEventMap.Keys) {

        $Nodes = @(
            $Xml.SelectNodes(
                "//*[local-name()='$EventType']"
            )
        )

        if ($Nodes.Count -gt 0) {

            $Found += $EventType
        }
    }

    return @(
        $Found |
        Sort-Object -Unique
    )
}


function Get-EnabledEventIds {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    $EventNames = @(
        Get-EventElementNames `
            -Xml $Xml
    )

    $Ids = @()

    foreach ($EventName in $EventNames) {

        foreach ($Id in $SysmonEventMap[$EventName]) {

            $Ids += [int]$Id
        }
    }

    return @(
        $Ids |
        Sort-Object -Unique
    )
}


function Get-EventNamesForId {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId
    )

    $Names = @()

    foreach ($Name in $SysmonEventMap.Keys) {

        if (
            @($SysmonEventMap[$Name]) -contains
            $EventId
        ) {

            $Names += $Name
        }
    }

    return $Names
}


function Get-FilterConflicts {

    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml,

        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds
    )

    $Conflicts = @()

    foreach ($EventId in $RequiredEventIds) {

        $EventNames = @(
            Get-EventNamesForId `
                -EventId $EventId
        )

        foreach ($EventName in $EventNames) {

            $Nodes = @(
                $Xml.SelectNodes(
                    "//*[local-name()='$EventName']"
                )
            )

            foreach ($Node in $Nodes) {

                $OnMatch = [string]$Node.GetAttribute("onmatch")

                # -----------------------------------------------------------
                # Exclude rules
                #
                # Any exclude rule may suppress relevant activity if the
                # attack matches the excluded condition.
                # -----------------------------------------------------------

                if (
                    $OnMatch -match "(?i)^exclude$"
                ) {

                    $RuleNames = @(
                        $Node.SelectNodes(".//*[@name]") |
                        ForEach-Object {
                            [string]$_.GetAttribute("name")
                        } |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_)
                        }
                    )

                    if ($RuleNames.Count -gt 0) {

                        foreach ($RuleName in $RuleNames) {

                            $Conflicts += `
                                "EID $EventId / $EventName has exclude filtering: $RuleName"
                        }
                    }
                    else {

                        $Conflicts += `
                            "EID $EventId / $EventName has an onmatch=exclude rule that may suppress relevant telemetry"
                    }
                }

                # -----------------------------------------------------------
                # Include-only filtering
                #
                # If include rules exist, events not matching the included
                # conditions may not be logged.
                # -----------------------------------------------------------

                if (
                    $OnMatch -match "(?i)^include$"
                ) {

                    $ChildConditions = @(
                        $Node.SelectNodes(".//*")
                    )

                    if ($ChildConditions.Count -gt 0) {

                        $Conflicts += `
                            "EID $EventId / $EventName uses include filtering; unmatched attacker activity may be suppressed"
                    }
                }
            }
        }
    }

    return @(
        $Conflicts |
        Sort-Object -Unique
    )
}


function Get-CoverageStatus {

    param(
        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds,

        [Parameter(Mandatory = $true)]
        [int[]]$EnabledEventIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$FilterConflicts
    )

    $RequiredCount = $RequiredEventIds.Count

    $EnabledRequired = @(
        $RequiredEventIds |
        Where-Object {
            $EnabledEventIds -contains $_
        }
    )

    if ($EnabledRequired.Count -eq 0) {
        return "blind"
    }

    if ($EnabledRequired.Count -lt $RequiredCount) {
        return "partial"
    }

    if ($FilterConflicts.Count -gt 0) {
        return "partial"
    }

    return "covered"
}


function Get-Recommendation {

    param(
        [Parameter(Mandatory = $true)]
        [string]$CoverageStatus,

        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds,

        [Parameter(Mandatory = $true)]
        [int[]]$EnabledRequiredIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$FilterConflicts
    )

    $MissingIds = @(
        $RequiredEventIds |
        Where-Object {
            $EnabledRequiredIds -notcontains $_
        }
    )

    if ($CoverageStatus -eq "covered") {

        return `
            "Maintain current Sysmon coverage and validate the event fields with controlled telemetry tests."
    }

    if ($CoverageStatus -eq "blind") {

        return (
            "Enable Sysmon Event ID(s) " +
            ($RequiredEventIds -join ", ") +
            " and validate the resulting telemetry with a controlled trigger."
        )
    }

    $Actions = @()

    if ($MissingIds.Count -gt 0) {

        $Actions += (
            "Enable missing Sysmon Event ID(s): " +
            ($MissingIds -join ", ")
        )
    }

    if ($FilterConflicts.Count -gt 0) {

        $Actions += `
            "Review include/exclude filters and remove or narrow rules that suppress security-relevant attacker activity"
    }

    $Actions += `
        "Validate that required evidence fields are populated during a controlled test"

    return ($Actions -join "; ")
}


function Get-CoverageReason {

    param(
        [Parameter(Mandatory = $true)]
        [string]$CoverageStatus,

        [Parameter(Mandatory = $true)]
        [int[]]$RequiredEventIds,

        [Parameter(Mandatory = $true)]
        [int[]]$EnabledRequiredIds,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$FilterConflicts
    )

    $MissingIds = @(
        $RequiredEventIds |
        Where-Object {
            $EnabledRequiredIds -notcontains $_
        }
    )

    switch ($CoverageStatus) {

        "covered" {

            return (
                "All required Sysmon Event IDs are enabled and no obvious conflicting filters were identified."
            )
        }

        "partial" {

            $Reasons = @()

            if ($MissingIds.Count -gt 0) {

                $Reasons += (
                    "Missing required Event ID(s): " +
                    ($MissingIds -join ", ")
                )
            }

            if ($FilterConflicts.Count -gt 0) {

                $Reasons += `
                    "Filtering may suppress relevant telemetry"
            }

            return ($Reasons -join "; ")
        }

        "blind" {

            return (
                "None of the required Sysmon Event IDs are enabled for this ATT&CK technique."
            )
        }
    }

    return "Unknown coverage state."
}

# ===========================================================================
# Validate input
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Sysmon ATT&CK Coverage Matrix"
Write-Host "=============================================="
Write-Host ""

Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"

if (-not (Test-Path $SysmonConfigPath)) {

    Write-Host "[FAIL] sysmonconfig.xml not found:"
    Write-Host "       $SysmonConfigPath"

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

    Write-Host `
        "[FAIL] Unable to parse sysmonconfig.xml: $($_.Exception.Message)"

    exit 1
}

# ===========================================================================
# Enabled event types
# ===========================================================================

$EnabledEventIds = @(
    Get-EnabledEventIds `
        -Xml $SysmonConfig
)

Write-Host `
    "Enabled Event IDs: $($EnabledEventIds -join ', ')"

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

    $FilterConflicts = @(
        Get-FilterConflicts `
            -Xml $SysmonConfig `
            -RequiredEventIds $RequiredIds
    )

    $CoverageStatus = Get-CoverageStatus `
        -RequiredEventIds $RequiredIds `
        -EnabledEventIds $EnabledEventIds `
        -FilterConflicts $FilterConflicts

    $Reason = Get-CoverageReason `
        -CoverageStatus $CoverageStatus `
        -RequiredEventIds $RequiredIds `
        -EnabledRequiredIds $EnabledRequiredIds `
        -FilterConflicts $FilterConflicts

    $Recommendation = Get-Recommendation `
        -CoverageStatus $CoverageStatus `
        -RequiredEventIds $RequiredIds `
        -EnabledRequiredIds $EnabledRequiredIds `
        -FilterConflicts $FilterConflicts

    $CoverageMatrix += [PSCustomObject]@{

        technique_id = $Technique.technique_id

        technique_name = $Technique.technique_name

        required_event_ids = $RequiredIds

        enabled_event_ids = $EnabledRequiredIds

        filter_conflicts = $FilterConflicts

        coverage_status = $CoverageStatus

        reason = $Reason

        evidence_fields_expected = `
            $Technique.evidence_fields_expected

        recommendation = $Recommendation

        threat_example = $Technique.threat_example
    }
}

# ===========================================================================
# Summary
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

    source_config = $SysmonConfigPath

    enabled_event_ids = $EnabledEventIds

    techniques_assessed = $CoverageMatrix.Count

    covered = $CoveredCount

    partial = $PartialCount

    blind = $BlindCount
}

# ===========================================================================
# Final JSON document
# ===========================================================================

$Report = [ordered]@{
    metadata = [ordered]@{
        project = "2x02_eyes_on_endpoint"
        task = "1 - Sysmon ATT&CK Coverage Matrix"
        timestamp = (Get-Date).ToString("o")
        computer = $env:COMPUTERNAME
        script = "1-sysmon_coverage_matrix.ps1"
    }

    summary = $Summary

    coverage_matrix = $CoverageMatrix
}

# ===========================================================================
# Write JSON
# ===========================================================================

$Report |
    ConvertTo-Json `
        -Depth 12 |
    Set-Content `
        -Path $OutputPath `
        -Encoding UTF8

# Ensure a newline exists at the end of the JSON file.
Add-Content `
    -Path $OutputPath `
    -Value ""

# ===========================================================================
# Validate generated JSON
# ===========================================================================

try {

    $null = Get-Content `
        -Path $OutputPath `
        -Raw |
        ConvertFrom-Json
}
catch {

    Write-Host "[FAIL] Generated JSON is invalid."

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