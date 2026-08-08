# name: 2-powershell_logging_validation.ps1
# purpose: Validate PowerShell ScriptBlock Logging, ModuleLogging and Transcription using controlled commands.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 2 - PowerShell Logging Validation
#
# Required validation:
# 1. Simple command Get-Process -> Event ID 4104 ScriptBlock
# 2. Encoded command using powershell -enc -> decoded content in Event ID 4104
# 3. Import-Module ActiveDirectory -> Event ID 4103 ModuleLogging
# 4. Multi-line ScriptBlock -> full content in Event ID 4104
# 5. Transcription -> C:\PSTranscripts\*.txt
#
# Result states:
# - CAPTURED
# - MISSED
#
# Detail levels:
# - full content
# - partial
#
# Safety:
# This script does not change PowerShell logging configuration.
# It only executes benign commands and validates telemetry.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$PowerShellOperationalLog = "Microsoft-Windows-PowerShell/Operational"

$ScriptBlockEventId = 4104
$ModuleLoggingEventId = 4103

$TranscriptDirectory = "C:\PSTranscripts"

$TotalTests = 5
$CapturedTests = 0
$MissedTests = 0

$ValidationStartTimestamp = Get-Date

# Unique run marker prevents matching old log events.
$RunId = [guid]::NewGuid().ToString("N")

$SimpleMarker = "MEDDEFENSE_SIMPLE_$RunId"
$EncodedMarker = "MEDDEFENSE_ENCODED_$RunId"
$ModuleMarker = "MEDDEFENSE_MODULE_$RunId"
$MultiLineStartMarker = "MEDDEFENSE_MULTILINE_START_$RunId"
$MultiLineEndMarker = "MEDDEFENSE_MULTILINE_END_$RunId"
$TranscriptMarker = "MEDDEFENSE_TRANSCRIPT_$RunId"

# Literal project example:
# Write-Host "Test"
$ExampleEncodedCommand = `
    "VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi"

# ===========================================================================
# Helper functions
# ===========================================================================

function Write-TestResult {

    param(
        [Parameter(Mandatory = $true)]
        [bool]$Captured,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet("full content", "partial", "none")]
        [string]$DetailLevel
    )

    if ($Captured) {

        $script:CapturedTests++

        Write-Host `
            "          $Message | CAPTURED | Detail: $DetailLevel [PASS]"
    }
    else {

        $script:MissedTests++

        Write-Host `
            "          $Message | MISSED | Detail: $DetailLevel [FAIL]"
    }
}


function Test-PowerShellOperationalLog {

    try {

        $Log = Get-WinEvent `
            -ListLog $PowerShellOperationalLog `
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
                LogName   = $PowerShellOperationalLog
                Id        = $EventId
                StartTime = $StartTime
            } `
            -ErrorAction SilentlyContinue
    )
}


function Wait-ForEvent {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$RequiredPatterns,

        [int]$TimeoutSeconds = 15
    )

    $Deadline = (Get-Date).AddSeconds(
        $TimeoutSeconds
    )

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


function Convert-ToPowerShellEncodedCommand {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes(
        $Command
    )

    return [Convert]::ToBase64String(
        $Bytes
    )
}


function Get-NewTranscriptFiles {

    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
    )

    if (-not (Test-Path $TranscriptDirectory)) {

        return @()
    }

    return @(
        Get-ChildItem `
            -Path $TranscriptDirectory `
            -File `
            -Filter "*.txt" `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTime -ge $StartTime
        } |
        Sort-Object LastWriteTime -Descending
    )
}


function Wait-ForTranscript {

    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [string]$Marker,

        [int]$TimeoutSeconds = 15
    )

    $Deadline = (Get-Date).AddSeconds(
        $TimeoutSeconds
    )

    do {

        $Files = @(
            Get-NewTranscriptFiles `
                -StartTime $StartTime
        )

        foreach ($File in $Files) {

            try {

                $Content = Get-Content `
                    -Path $File.FullName `
                    -Raw `
                    -ErrorAction Stop

                if (
                    $Content -match
                    [regex]::Escape($Marker)
                ) {

                    return $File
                }
            }
            catch {
                # Transcript may still be open.
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

Write-Host `
    "    timestamp: $($ValidationStartTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# ===========================================================================
# Prerequisite check
# ===========================================================================

if (-not (Test-PowerShellOperationalLog)) {

    Write-Host `
        "[FAIL] Microsoft-Windows-PowerShell/Operational is unavailable or disabled."

    exit 1
}

# ===========================================================================
# [1/5] Simple command - Get-Process - ScriptBlock Event ID 4104
# ===========================================================================

Write-Host ""
Write-Host "    [1/5] Simple command (Get-Process)..."

$SimpleTimestamp = Get-Date

Write-Host `
    "          timestamp: $($SimpleTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

$SimpleScriptBlock = @"
Get-Process | Out-Null
Write-Output "$SimpleMarker"
"@

$SimpleEncodedCommand = Convert-ToPowerShellEncodedCommand `
    -Command $SimpleScriptBlock

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $SimpleEncodedCommand `
    *> $null

$SimpleEvent = Wait-ForEvent `
    -EventId $ScriptBlockEventId `
    -StartTime $SimpleTimestamp `
    -RequiredPatterns @(
        "Get-Process",
        $SimpleMarker
    )

if ($null -ne $SimpleEvent) {

    Write-TestResult `
        -Captured $true `
        -Message 'EID 4104 ScriptBlock: "Get-Process" captured' `
        -DetailLevel "full content"
}
else {

    Write-TestResult `
        -Captured $false `
        -Message 'EID 4104 ScriptBlock: "Get-Process"' `
        -DetailLevel "none"
}

# ===========================================================================
# [2/5] Encoded command - decoded ScriptBlock Event ID 4104
# ===========================================================================

Write-Host ""
Write-Host "    [2/5] Encoded command..."

$EncodedTimestamp = Get-Date

Write-Host `
    "          timestamp: $($EncodedTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

$DecodedCommand = @"
Write-Host "Test"
Write-Output "$EncodedMarker"
"@

$EncodedCommand = Convert-ToPowerShellEncodedCommand `
    -Command $DecodedCommand

Write-Host `
    "          Input: powershell -enc $EncodedCommand"

Write-Host `
    "          Reference: -enc $ExampleEncodedCommand"

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -enc $EncodedCommand `
    *> $null

$EncodedEvent = Wait-ForEvent `
    -EventId $ScriptBlockEventId `
    -StartTime $EncodedTimestamp `
    -RequiredPatterns @(
        'Write-Host "Test"',
        $EncodedMarker
    )

if ($null -ne $EncodedEvent) {

    Write-TestResult `
        -Captured $true `
        -Message 'EID 4104 ScriptBlock: decoded "Write-Host `"Test`"" captured' `
        -DetailLevel "full content"
}
else {

    Write-TestResult `
        -Captured $false `
        -Message "EID 4104 ScriptBlock: decoded encoded command" `
        -DetailLevel "none"
}

# ===========================================================================
# [3/5] ModuleLogging - Import-Module ActiveDirectory - Event ID 4103
# ===========================================================================

Write-Host ""
Write-Host "    [3/5] Module import (Import-Module ActiveDirectory)..."

$ModuleTimestamp = Get-Date

Write-Host `
    "          timestamp: $($ModuleTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

$ModuleScript = @"
Import-Module ActiveDirectory
Get-ADDomain | Out-Null
Write-Output "$ModuleMarker"
"@

$ModuleEncodedCommand = Convert-ToPowerShellEncodedCommand `
    -Command $ModuleScript

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $ModuleEncodedCommand `
    *> $null

$ModuleEvent = Wait-ForEvent `
    -EventId $ModuleLoggingEventId `
    -StartTime $ModuleTimestamp `
    -RequiredPatterns @(
        "ActiveDirectory"
    )

if ($null -ne $ModuleEvent) {

    $ModuleMessage = [string]$ModuleEvent.Message

    if (
        $ModuleMessage -match "(?i)Import-Module" -and
        $ModuleMessage -match "(?i)ActiveDirectory"
    ) {

        Write-TestResult `
            -Captured $true `
            -Message 'EID 4103 ModuleLogging: "Import-Module ActiveDirectory" captured' `
            -DetailLevel "full content"
    }
    else {

        Write-TestResult `
            -Captured $true `
            -Message "EID 4103 ModuleLogging: ActiveDirectory module activity captured" `
            -DetailLevel "partial"
    }
}
else {

    Write-TestResult `
        -Captured $false `
        -Message 'EID 4103 ModuleLogging: "Import-Module ActiveDirectory"' `
        -DetailLevel "none"
}

# ===========================================================================
# [4/5] Multi-line ScriptBlock - Event ID 4104
# ===========================================================================

Write-Host ""
Write-Host "    [4/5] Multi-line ScriptBlock..."

$MultiLineTimestamp = Get-Date

Write-Host `
    "          timestamp: $($MultiLineTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

# 12 controlled lines.
$MultiLineScriptBlock = @"
Write-Output "$MultiLineStartMarker"
`$ProcessCount = (Get-Process).Count
`$ServiceCount = (Get-Service).Count
`$ComputerName = `$env:COMPUTERNAME
`$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
`$CurrentDate = Get-Date
`$PowerShellVersion = `$PSVersionTable.PSVersion.ToString()
`$DomainName = `$env:USERDOMAIN
`$PathValue = `$env:PATH
`$Summary = "`$ComputerName|`$ProcessCount|`$ServiceCount"
Write-Output `$Summary
Write-Output "$MultiLineEndMarker"
"@

$MultiLineEncodedCommand = Convert-ToPowerShellEncodedCommand `
    -Command $MultiLineScriptBlock

& powershell.exe `
    -NoProfile `
    -NonInteractive `
    -EncodedCommand $MultiLineEncodedCommand `
    *> $null

$MultiLineEvent = Wait-ForEvent `
    -EventId $ScriptBlockEventId `
    -StartTime $MultiLineTimestamp `
    -RequiredPatterns @(
        $MultiLineStartMarker,
        '$ProcessCount',
        '$ServiceCount',
        '$ComputerName',
        $MultiLineEndMarker
    )

if ($null -ne $MultiLineEvent) {

    $MultiLineMessage = [string]$MultiLineEvent.Message

    $ExpectedElements = @(
        $MultiLineStartMarker,
        '$ProcessCount',
        '$ServiceCount',
        '$ComputerName',
        '$CurrentUser',
        '$CurrentDate',
        '$PowerShellVersion',
        '$DomainName',
        '$PathValue',
        '$Summary',
        'Write-Output $Summary',
        $MultiLineEndMarker
    )

    $FoundElements = 0

    foreach ($ExpectedElement in $ExpectedElements) {

        if (
            $MultiLineMessage -match
            [regex]::Escape($ExpectedElement)
        ) {

            $FoundElements++
        }
    }

    if ($FoundElements -eq 12) {

        Write-TestResult `
            -Captured $true `
            -Message "EID 4104 ScriptBlock: Full block captured (12 lines)" `
            -DetailLevel "full content"
    }
    else {

        Write-TestResult `
            -Captured $true `
            -Message "EID 4104 ScriptBlock: block captured ($FoundElements/12 expected elements)" `
            -DetailLevel "partial"
    }
}
else {

    Write-TestResult `
        -Captured $false `
        -Message "EID 4104 ScriptBlock: multi-line block" `
        -DetailLevel "none"
}

# ===========================================================================
# [5/5] Transcription
# ===========================================================================

Write-Host ""
Write-Host "    [5/5] Transcription file..."

$TranscriptTimestamp = Get-Date

Write-Host `
    "          timestamp: $($TranscriptTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))"

$TranscriptScript = @"
Write-Output "$TranscriptMarker"
Get-Date
Get-Process -Id `$PID | Select-Object Id,ProcessName
"@

$TranscriptEncodedCommand = Convert-ToPowerShellEncodedCommand `
    -Command $TranscriptScript

& powershell.exe `
    -NoProfile `
    -EncodedCommand $TranscriptEncodedCommand `
    *> $null

$TranscriptFile = Wait-ForTranscript `
    -StartTime $TranscriptTimestamp `
    -Marker $TranscriptMarker

if ($null -ne $TranscriptFile) {

    Write-TestResult `
        -Captured $true `
        -Message "C:\PSTranscripts\*.txt exists, session recorded" `
        -DetailLevel "full content"

    Write-Host `
        "          Transcript: $($TranscriptFile.FullName)"
}
else {

    $NewTranscriptFiles = @(
        Get-NewTranscriptFiles `
            -StartTime $TranscriptTimestamp
    )

    if ($NewTranscriptFiles.Count -gt 0) {

        Write-TestResult `
            -Captured $true `
            -Message "C:\PSTranscripts\*.txt created but session marker not confirmed" `
            -DetailLevel "partial"
    }
    else {

        Write-TestResult `
            -Captured $false `
            -Message "C:\PSTranscripts\*.txt" `
            -DetailLevel "none"
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

    Write-Host `
        "[FAIL] One or more PowerShell logging tests were MISSED."

    exit 1
}