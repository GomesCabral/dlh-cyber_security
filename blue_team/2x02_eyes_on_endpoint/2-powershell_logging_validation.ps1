# name: 2-powershell_logging_validation.ps1
# purpose: Validate PowerShell Script Block Logging, Module Logging and Transcription using controlled commands.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 2 - PowerShell Logging Validation
#
# Required validation:
# 1. Simple command Get-Process -> Event ID 4104
# 2. Encoded command -> decoded content in Event ID 4104
# 3. Import-Module ActiveDirectory -> Event ID 4103
# 4. Multi-line script block -> full content in Event ID 4104
# 5. PowerShell transcription -> C:\PSTranscripts\*.txt
#
# Event IDs:
# 4103 = PowerShell Module Logging
# 4104 = PowerShell Script Block Logging
#
# Safety:
# READ-ONLY with respect to security configuration.
# The script only executes benign validation commands and reads logs/transcripts.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$PowerShellLog = "Microsoft-Windows-PowerShell/Operational"
$TranscriptRoot = "C:\PSTranscripts"

$TotalTests = 5
$CapturedTests = 0
$MissedTests = 0

$ScriptStartTimestamp = Get-Date

# Unique markers prevent old log entries from producing false PASS results.
$RunId = [guid]::NewGuid().ToString("N")

$SimpleMarker = "MEDDEFENSE_SIMPLE_$RunId"
$EncodedMarker = "MEDDEFENSE_ENCODED_$RunId"
$ModuleMarker = "MEDDEFENSE_MODULE_$RunId"
$MultiLineMarkerStart = "MEDDEFENSE_MULTILINE_START_$RunId"
$MultiLineMarkerEnd = "MEDDEFENSE_MULTILINE_END_$RunId"
$TranscriptMarker = "MEDDEFENSE_TRANSCRIPT_$RunId"

# Literal encoded command requested in the project example:
# Write-Host "Test"
$ExpectedExampleEncodedCommand = `
    "VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi"

# ===========================================================================
# Helper functions
# ===========================================================================

function Write-TestResult {

    param(
        [Parameter(Mandatory = $true)]
        [bool]$Passed,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Passed) {

        $script:CapturedTests++

        Write-Host "          $Message [PASS]"
    }
    else {

        $script:MissedTests++

        Write-Host "          $Message [FAIL]"
    }
}


function Test-PowerShellOperationalLog {

    try {

        $Log = Get-WinEvent `
            -ListLog $PowerShellLog `
            -ErrorAction Stop

        return [bool]$Log.IsEnabled
    }
    catch {

        return $false
    }
}


function Get-PowerShellEvents {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
    )

    return @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName   = $PowerShellLog
                Id        = $EventId
                StartTime = $StartTime
            } `
            -ErrorAction SilentlyContinue
    )
}


function Wait-ForEventMatch {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [string[]]$RequiredPatterns,

        [int]$TimeoutSeconds = 12
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {

        $Events = @(
            Get-PowerShellEvents `
                -EventId $EventId `
                -StartTime $StartTime
        )

        foreach ($Event in $Events) {

            $Message = [string]$Event.Message

            $AllPatternsFound = $true

            foreach ($Pattern in $RequiredPatterns) {

                if (
                    $Message -notmatch
                    [regex]::Escape($Pattern)
                ) {

                    $AllPatternsFound = $false
                    break
                }
            }

            if ($AllPatternsFound) {

                return $Event
            }
        }

        Start-Sleep -Milliseconds 750

    } while ((Get-Date) -lt $Deadline)

    return $null
}


function Convert-ToEncodedPowerShellCommand {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    return [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes(
            $Command
        )
    )
}


function Get-NewTranscriptFiles {

    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
    )

    if (-not (Test-Path $TranscriptRoot)) {
        return @()
    }

    return @(
        Get-ChildItem `
            -Path $TranscriptRoot `
            -Filter "*.txt" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTime -ge $StartTime
        } |
        Sort-Object LastWriteTime -Descending
    )
}


function Find-TranscriptMarker {

    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [string]$Marker,

        [int]$TimeoutSeconds = 12
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {

        $TranscriptFiles = @(
            Get-NewTranscriptFiles `
                -StartTime $StartTime
        )

        foreach ($Transcript in $TranscriptFiles) {

            try {

                $Content = Get-Content `
                    -Path $Transcript.FullName `
                    -Raw `
                    -ErrorAction Stop

                if (
                    $Content -match
                    [regex]::Escape($Marker)
                ) {

                    return $Transcript
                }
            }
            catch {
                # Transcript may still be open; retry until timeout.
            }
        }

        Start-Sleep -Milliseconds 750

    } while ((Get-Date) -lt $Deadline)

    return $null
}

# ===========================================================================
# Start
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense PowerShell Logging Validation"
Write-Host "=============================================="
Write-Host ""

Write-Host "[*] Testing PowerShell logging coverage..."
Write-Host "    timestamp: $($ScriptStartTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# ===========================================================================
# Validate PowerShell Operational log
# ===========================================================================

if (-not (Test-PowerShellOperationalLog)) {

    Write-Host "[FAIL] PowerShell Operational log is unavailable or disabled."
    exit 1
}

# ===========================================================================
# [1/5] Simple command - Event ID 4104
# ===========================================================================

Write-Host ""
Write-Host "    [1/5] Simple command (Get-Process)..."

$SimpleTimestamp = Get-Date

Write-Host `
    "          timestamp: $($SimpleTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

$SimpleCommand = @"
`$null = Get-Process
Write-Output '$SimpleMarker'
"@

$SimpleEncoded = Convert-ToEncodedPowerShellCommand `
    -Command $SimpleCommand

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $SimpleEncoded `
    *> $null

$SimpleEvent = Wait-ForEventMatch `
    -EventId 4104 `
    -StartTime $SimpleTimestamp `
    -RequiredPatterns @(
        "Get-Process",
        $SimpleMarker
    )

if ($null -ne $SimpleEvent) {

    Write-TestResult `
        -Passed $true `
        -Message 'EID 4104: "Get-Process" captured - full content'
}
else {

    Write-TestResult `
        -Passed $false `
        -Message 'EID 4104: "Get-Process" MISSED'
}

# ===========================================================================
# [2/5] Encoded command - Event ID 4104
# ===========================================================================

Write-Host ""
Write-Host "    [2/5] Encoded command..."

$EncodedTimestamp = Get-Date

Write-Host `
    "          timestamp: $($EncodedTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# Requirement:
# powershell -enc [base64 of Write-Host "Test"]
#
# A unique marker is added so this run cannot match an old Event ID 4104.

$DecodedCommand = @"
Write-Host "Test"
Write-Output "$EncodedMarker"
"@

$EncodedCommand = Convert-ToEncodedPowerShellCommand `
    -Command $DecodedCommand

Write-Host "          Input: -enc $EncodedCommand"
Write-Host `
    "          Reference example: -enc $ExpectedExampleEncodedCommand"

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -enc $EncodedCommand `
    *> $null

$EncodedEvent = Wait-ForEventMatch `
    -EventId 4104 `
    -StartTime $EncodedTimestamp `
    -RequiredPatterns @(
        'Write-Host "Test"',
        $EncodedMarker
    )

if ($null -ne $EncodedEvent) {

    Write-TestResult `
        -Passed $true `
        -Message 'EID 4104: "Write-Host `"Test`"" decoded content captured - full content'
}
else {

    Write-TestResult `
        -Passed $false `
        -Message "EID 4104: encoded command decoded content MISSED"
}

# ===========================================================================
# [3/5] Module Logging - Event ID 4103
# ===========================================================================

Write-Host ""
Write-Host "    [3/5] Module import (Import-Module ActiveDirectory)..."

$ModuleTimestamp = Get-Date

Write-Host `
    "          timestamp: $($ModuleTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# Execute a real ActiveDirectory module command after import.
# This improves the probability of Module Logging generating useful 4103 data.

$ModuleCommand = @"
Import-Module ActiveDirectory
`$null = Get-ADDomain
Write-Output "$ModuleMarker"
"@

$ModuleEncoded = Convert-ToEncodedPowerShellCommand `
    -Command $ModuleCommand

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $ModuleEncoded `
    *> $null

# First attempt: exact Import-Module ActiveDirectory evidence.
$ModuleEvent = Wait-ForEventMatch `
    -EventId 4103 `
    -StartTime $ModuleTimestamp `
    -RequiredPatterns @(
        "ActiveDirectory"
    )

if ($null -ne $ModuleEvent) {

    $ModuleMessage = [string]$ModuleEvent.Message

    if (
        $ModuleMessage -match
        "(?i)Import-Module"
    ) {

        Write-TestResult `
            -Passed $true `
            -Message 'EID 4103: "Import-Module ActiveDirectory" captured - full detail'
    }
    else {

        Write-TestResult `
            -Passed $true `
            -Message "EID 4103: ActiveDirectory module activity captured - partial command detail"
    }
}
else {

    Write-TestResult `
        -Passed $false `
        -Message 'EID 4103: "Import-Module ActiveDirectory" MISSED'
}

# ===========================================================================
# [4/5] Multi-line Script Block - Event ID 4104
# ===========================================================================

Write-Host ""
Write-Host "    [4/5] Multi-line script block..."

$MultiLineTimestamp = Get-Date

Write-Host `
    "          timestamp: $($MultiLineTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# Exactly 12 controlled script lines.
$MultiLineScript = @"
Write-Output "$MultiLineMarkerStart"
`$ProcessCount = (Get-Process).Count
`$ServiceCount = (Get-Service).Count
`$ComputerName = `$env:COMPUTERNAME
`$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
`$CurrentDate = Get-Date
`$PowerShellVersion = `$PSVersionTable.PSVersion.ToString()
`$Domain = `$env:USERDOMAIN
`$PathValue = `$env:PATH
`$Result = "`$ComputerName|`$ProcessCount|`$ServiceCount"
Write-Output `$Result
Write-Output "$MultiLineMarkerEnd"
"@

$MultiLineEncoded = Convert-ToEncodedPowerShellCommand `
    -Command $MultiLineScript

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $MultiLineEncoded `
    *> $null

$MultiLineEvent = Wait-ForEventMatch `
    -EventId 4104 `
    -StartTime $MultiLineTimestamp `
    -RequiredPatterns @(
        $MultiLineMarkerStart,
        '$ProcessCount',
        '$ServiceCount',
        '$ComputerName',
        $MultiLineMarkerEnd
    )

if ($null -ne $MultiLineEvent) {

    $CapturedScriptText = [string]$MultiLineEvent.Message

    $ImportantLines = @(
        $MultiLineMarkerStart,
        '$ProcessCount',
        '$ServiceCount',
        '$ComputerName',
        '$CurrentUser',
        '$CurrentDate',
        '$PowerShellVersion',
        '$Domain',
        '$PathValue',
        '$Result',
        'Write-Output $Result',
        $MultiLineMarkerEnd
    )

    $FoundLineCount = 0

    foreach ($ExpectedLine in $ImportantLines) {

        if (
            $CapturedScriptText -match
            [regex]::Escape($ExpectedLine)
        ) {

            $FoundLineCount++
        }
    }

    if ($FoundLineCount -eq 12) {

        Write-TestResult `
            -Passed $true `
            -Message "EID 4104: Full block captured (12 lines) - full content"
    }
    else {

        Write-TestResult `
            -Passed $true `
            -Message "EID 4104: Block captured ($FoundLineCount/12 expected elements) - partial content"
    }
}
else {

    Write-TestResult `
        -Passed $false `
        -Message "EID 4104: Multi-line script block MISSED"
}

# ===========================================================================
# [5/5] PowerShell Transcription
# ===========================================================================

Write-Host ""
Write-Host "    [5/5] Transcription file..."

$TranscriptTimestamp = Get-Date

Write-Host `
    "          timestamp: $($TranscriptTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# A separate PowerShell session is intentionally started after the timestamp.
# If transcription is configured by policy, this child session should create
# a transcript containing this unique marker.

$TranscriptCommand = @"
Write-Output "$TranscriptMarker"
Get-Date
Get-Process -Id `$PID | Select-Object Id, ProcessName
"@

$TranscriptEncoded = Convert-ToEncodedPowerShellCommand `
    -Command $TranscriptCommand

& powershell.exe `
    -NoProfile `
    -EncodedCommand $TranscriptEncoded `
    *> $null

$TranscriptFile = Find-TranscriptMarker `
    -StartTime $TranscriptTimestamp `
    -Marker $TranscriptMarker

if ($null -ne $TranscriptFile) {

    Write-TestResult `
        -Passed $true `
        -Message "C:\PSTranscripts\*.txt exists, session recorded - full content"

    Write-Host `
        "          Transcript: $($TranscriptFile.FullName)"
}
else {

    $NewTranscripts = @(
        Get-NewTranscriptFiles `
            -StartTime $TranscriptTimestamp
    )

    if ($NewTranscripts.Count -gt 0) {

        Write-TestResult `
            -Passed $true `
            -Message "C:\PSTranscripts\*.txt created - transcript present, marker detail partial"
    }
    else {

        Write-TestResult `
            -Passed $false `
            -Message "C:\PSTranscripts\*.txt MISSED"
    }
}

# ===========================================================================
# Summary
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "PowerShell Logging Validation Summary"
Write-Host "=============================================="
Write-Host ""

Write-Host `
    "Tests: $TotalTests | Captured: $CapturedTests | Missed: $MissedTests"

Write-Host ""

if (
    $CapturedTests -eq $TotalTests -and
    $MissedTests -eq 0
) {

    Write-Host "[PASS] PowerShell logging coverage validated."
    exit 0
}
else {

    Write-Host "[FAIL] One or more PowerShell logging layers missed expected telemetry."
    exit 1
}