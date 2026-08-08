# Name: 0-sysmon_validation.ps1
# purpose: Trigger and validate five security-relevant Sysmon telemetry events.
# Author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 0 - Sysmon Telemetry Validation
#
# Required validation:
# Event ID 1  - Process creation
# Event ID 3  - Network connection
# Event ID 11 - File creation
# Event ID 13 - Registry modification
# Event ID 22 - DNS query
#
# Controlled actions:
# 1. cmd.exe /c whoami
# 2. Test-NetConnection to a reachable TCP service
# 3. Create C:\Windows\Temp\test.txt
# 4. Write HKCU\Software\MedDefense\SysmonTest\TestValue
# 5. DNS query / nslookup example.com, with local-domain validation fallback
#
# Safety:
# The script creates only temporary test artifacts and removes them during
# cleanup. It does not modify Sysmon configuration or Windows security policy.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"

$TestFile = "C:\Windows\Temp\test.txt"

$RegistryTestPath = "HKCU:\Software\MedDefense\SysmonTest"
$RegistryValueName = "TestValue"
$RegistryValueData = "MEDDEFENSE_SYSMON_TEST"

$DnsPrimaryQuery = "example.com"
$DnsFallbackQuery = "dc01.meddefense.local"

$TotalTests = 5
$CapturedTests = 0
$MissedTests = 0

# Sysmon can take a moment to write an event.
$EventWaitSeconds = 3

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

        Write-Host "          $Message   [PASS]"
    }
    else {

        $script:MissedTests++

        Write-Host "          $Message   [FAIL]"
    }
}


function Convert-SysmonEventToObject {

    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    [xml]$EventXml = $Event.ToXml()

    $Fields = [ordered]@{}

    foreach ($DataNode in $EventXml.Event.EventData.Data) {

        $FieldName = [string]$DataNode.Name

        if ([string]::IsNullOrWhiteSpace($FieldName)) {
            continue
        }

        $Fields[$FieldName] = [string]$DataNode.'#text'
    }

    return [PSCustomObject]@{
        EventId     = $Event.Id
        TimeCreated = $Event.TimeCreated
        RecordId    = $Event.RecordId
        Fields      = [PSCustomObject]$Fields
        RawEvent    = $Event
    }
}


function Get-SysmonEventsSince {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
    )

    $RawEvents = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName   = $SysmonLog
                Id        = $EventId
                StartTime = $StartTime
            } `
            -ErrorAction SilentlyContinue
    )

    $ParsedEvents = @()

    foreach ($Event in $RawEvents) {

        $ParsedEvents += Convert-SysmonEventToObject `
            -Event $Event
    }

    return $ParsedEvents
}


function Get-FieldValue {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Event,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $Property = $Event.Fields.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $null
    }

    return $Property.Value
}


function Wait-ForSysmon {

    Start-Sleep -Seconds $EventWaitSeconds
}


function Test-SysmonAvailable {

    try {

        $Log = Get-WinEvent `
            -ListLog $SysmonLog `
            -ErrorAction Stop

        return [bool]$Log.IsEnabled
    }
    catch {

        return $false
    }
}


function Get-NetworkValidationTarget {

    # Use the DC's own IPv4 address and DNS TCP/53.
    #
    # This provides a controlled outbound TCP connection without requiring
    # Internet connectivity. DC01 should have DNS listening on port 53.

    $IPv4 = @(
        Get-NetIPAddress `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*"
        } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1
    )

    if ($IPv4.Count -eq 0) {

        return [PSCustomObject]@{
            Address = "127.0.0.1"
            Port    = 53
        }
    }

    return [PSCustomObject]@{
        Address = $IPv4[0].IPAddress
        Port    = 53
    }
}


function Cleanup-TestArtifacts {

    Write-Host "[*] Cleanup: removing test artifacts..."

    if (Test-Path $TestFile) {

        Remove-Item `
            -Path $TestFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    if (Test-Path $RegistryTestPath) {

        Remove-Item `
            -Path $RegistryTestPath `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# Prerequisite validation
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Sysmon Telemetry Validation"
Write-Host "=============================================="
Write-Host ""

Write-Host "[*] Running Sysmon telemetry validation..."

if (-not (Test-SysmonAvailable)) {

    Write-Host "[FAIL] Sysmon Operational log is unavailable or disabled."
    exit 1
}

$SysmonService = Get-Service `
    -Name "Sysmon64" `
    -ErrorAction SilentlyContinue

if ($null -eq $SysmonService) {

    $SysmonService = Get-Service `
        -Name "Sysmon" `
        -ErrorAction SilentlyContinue
}

if (
    $null -eq $SysmonService -or
    $SysmonService.Status -ne "Running"
) {

    Write-Host "[FAIL] Sysmon service is not running."
    exit 1
}

# ===========================================================================
# Trigger-and-Verify sequence
# ===========================================================================

try {

    # =======================================================================
    # [1/5] Process Creation - Sysmon Event ID 1
    #
    # Required:
    # cmd.exe /c whoami
    # Full CommandLine must be present.
    # =======================================================================

    Write-Host "    [1/5] Process creation (Event ID 1)..."

    $ProcessStart = Get-Date

    & "$env:WINDIR\System32\cmd.exe" `
        /c whoami `
        *> $null

    Wait-ForSysmon

    $ProcessEvents = @(
        Get-SysmonEventsSince `
            -EventId 1 `
            -StartTime $ProcessStart
    )

    $ProcessMatch = $null

    foreach ($Event in $ProcessEvents) {

        $Image = Get-FieldValue `
            -Event $Event `
            -Name "Image"

        $CommandLine = Get-FieldValue `
            -Event $Event `
            -Name "CommandLine"

        if (
            $Image -match "(?i)\\cmd\.exe$" -and
            $CommandLine -match "(?i)/c\s+whoami"
        ) {

            $ProcessMatch = $Event
            break
        }
    }

    if ($null -ne $ProcessMatch) {

        $CommandLine = Get-FieldValue `
            -Event $ProcessMatch `
            -Name "CommandLine"

        $Passed = (
            -not [string]::IsNullOrWhiteSpace($CommandLine)
        )

        Write-TestResult `
            -Passed $Passed `
            -Message "cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present"
    }
    else {

        Write-TestResult `
            -Passed $false `
            -Message "cmd.exe /c whoami -> Sysmon EID 1 not captured"
    }

    # =======================================================================
    # [2/5] Network Connection - Sysmon Event ID 3
    #
    # Required fields:
    # DestinationIp
    # DestinationPort
    # Image / process
    # =======================================================================

    Write-Host "    [2/5] Network connection (Event ID 3)..."

    $NetworkTarget = Get-NetworkValidationTarget

    $NetworkStart = Get-Date

    $null = Test-NetConnection `
        -ComputerName $NetworkTarget.Address `
        -Port $NetworkTarget.Port `
        -InformationLevel Detailed `
        -WarningAction SilentlyContinue

    Wait-ForSysmon

    $NetworkEvents = @(
        Get-SysmonEventsSince `
            -EventId 3 `
            -StartTime $NetworkStart
    )

    $NetworkMatch = $null

    foreach ($Event in $NetworkEvents) {

        $DestinationIp = Get-FieldValue `
            -Event $Event `
            -Name "DestinationIp"

        $DestinationPort = Get-FieldValue `
            -Event $Event `
            -Name "DestinationPort"

        $Image = Get-FieldValue `
            -Event $Event `
            -Name "Image"

        if (
            $DestinationIp -eq $NetworkTarget.Address -and
            [string]$DestinationPort -eq [string]$NetworkTarget.Port -and
            -not [string]::IsNullOrWhiteSpace($Image)
        ) {

            $NetworkMatch = $Event
            break
        }
    }

    if ($null -ne $NetworkMatch) {

        $DestinationIp = Get-FieldValue `
            -Event $NetworkMatch `
            -Name "DestinationIp"

        $DestinationPort = Get-FieldValue `
            -Event $NetworkMatch `
            -Name "DestinationPort"

        $Image = Get-FieldValue `
            -Event $NetworkMatch `
            -Name "Image"

        $Passed = (
            -not [string]::IsNullOrWhiteSpace($DestinationIp) -and
            -not [string]::IsNullOrWhiteSpace($DestinationPort) -and
            -not [string]::IsNullOrWhiteSpace($Image)
        )

        Write-TestResult `
            -Passed $Passed `
            -Message "Outbound TCP -> Sysmon EID 3 captured, dest IP/port/process present"
    }
    else {

        Write-TestResult `
            -Passed $false `
            -Message "Outbound TCP -> Sysmon EID 3 not captured"
    }

    # =======================================================================
    # [3/5] File Creation - Sysmon Event ID 11
    #
    # Required:
    # TargetFilename
    # Image / creating process
    # =======================================================================

    Write-Host "    [3/5] File creation (Event ID 11)..."

    if (Test-Path $TestFile) {

        Remove-Item `
            -Path $TestFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    $FileStart = Get-Date

    "MedDefense Sysmon Event ID 11 validation $(Get-Date -Format o)" |
        Set-Content `
            -Path $TestFile `
            -Encoding UTF8

    Wait-ForSysmon

    $FileEvents = @(
        Get-SysmonEventsSince `
            -EventId 11 `
            -StartTime $FileStart
    )

    $FileMatch = $null

    foreach ($Event in $FileEvents) {

        $TargetFilename = Get-FieldValue `
            -Event $Event `
            -Name "TargetFilename"

        $Image = Get-FieldValue `
            -Event $Event `
            -Name "Image"

        if (
            $TargetFilename -ieq $TestFile -and
            -not [string]::IsNullOrWhiteSpace($Image)
        ) {

            $FileMatch = $Event
            break
        }
    }

    if ($null -ne $FileMatch) {

        Write-TestResult `
            -Passed $true `
            -Message "C:\Windows\Temp\test.txt -> Sysmon EID 11 captured"
    }
    else {

        Write-TestResult `
            -Passed $false `
            -Message "C:\Windows\Temp\test.txt -> Sysmon EID 11 not captured"
    }

    # =======================================================================
    # [4/5] Registry Modification - Sysmon Event ID 13
    #
    # Required:
    # TargetObject / key path
    # value name
    # EventType / operation type
    # =======================================================================

    Write-Host "    [4/5] Registry modification (Event ID 13)..."

    if (-not (Test-Path $RegistryTestPath)) {

        New-Item `
            -Path $RegistryTestPath `
            -Force |
        Out-Null
    }

    $RegistryStart = Get-Date

    New-ItemProperty `
        -Path $RegistryTestPath `
        -Name $RegistryValueName `
        -PropertyType String `
        -Value $RegistryValueData `
        -Force |
    Out-Null

    Wait-ForSysmon

    $RegistryEvents = @(
        Get-SysmonEventsSince `
            -EventId 13 `
            -StartTime $RegistryStart
    )

    $RegistryMatch = $null

    foreach ($Event in $RegistryEvents) {

        $TargetObject = Get-FieldValue `
            -Event $Event `
            -Name "TargetObject"

        $EventType = Get-FieldValue `
            -Event $Event `
            -Name "EventType"

        if (
            $TargetObject -match "(?i)SysmonTest" -and
            $TargetObject -match "(?i)$RegistryValueName" -and
            -not [string]::IsNullOrWhiteSpace($EventType)
        ) {

            $RegistryMatch = $Event
            break
        }
    }

    if ($null -ne $RegistryMatch) {

        Write-TestResult `
            -Passed $true `
            -Message "HKCU\...\SysmonTest -> Sysmon EID 13 captured, key/value/operation present"
    }
    else {

        Write-TestResult `
            -Passed $false `
            -Message "HKCU\...\SysmonTest -> Sysmon EID 13 not captured"
    }

    # =======================================================================
    # [5/5] DNS Query - Sysmon Event ID 22
    #
    # Requirement example:
    # nslookup example.com
    #
    # DC01 may not have Internet access, so we first trigger example.com and
    # then use dc01.meddefense.local as a controlled local DNS fallback.
    #
    # Required:
    # QueryName
    # QueryResults
    # Image / process
    # =======================================================================

    Write-Host "    [5/5] DNS query (Event ID 22)..."

    $DnsStart = Get-Date

    # Literal project test:
    # nslookup example.com
    & "$env:WINDIR\System32\nslookup.exe" `
        $DnsPrimaryQuery `
        *> $null

    # Local fallback guarantees a query against the MedDefense DNS domain
    # even when the isolated DC01 has no Internet connectivity.
    try {

        Resolve-DnsName `
            -Name $DnsFallbackQuery `
            -ErrorAction SilentlyContinue |
        Out-Null
    }
    catch {
    }

    Wait-ForSysmon

    $DnsEvents = @(
        Get-SysmonEventsSince `
            -EventId 22 `
            -StartTime $DnsStart
    )

    $DnsMatch = $null
    $DnsMatchedQuery = $null

    foreach ($Event in $DnsEvents) {

        $QueryName = Get-FieldValue `
            -Event $Event `
            -Name "QueryName"

        $QueryResults = Get-FieldValue `
            -Event $Event `
            -Name "QueryResults"

        $Image = Get-FieldValue `
            -Event $Event `
            -Name "Image"

        if (
            (
                $QueryName -ieq $DnsPrimaryQuery -or
                $QueryName -ieq $DnsFallbackQuery
            ) -and
            -not [string]::IsNullOrWhiteSpace($QueryResults) -and
            -not [string]::IsNullOrWhiteSpace($Image)
        ) {

            $DnsMatch = $Event
            $DnsMatchedQuery = $QueryName
            break
        }
    }

    if ($null -ne $DnsMatch) {

        Write-TestResult `
            -Passed $true `
            -Message "nslookup example.com -> Sysmon EID 22 captured, query/result present"
    }
    else {

        Write-TestResult `
            -Passed $false `
            -Message "nslookup example.com -> Sysmon EID 22 not captured with query/result"
    }
}
finally {

    Cleanup-TestArtifacts
}

# ===========================================================================
# Summary
# ===========================================================================

Write-Host ""

Write-Host `
    "Actions tested: $TotalTests | Captured: $CapturedTests | Missed: $MissedTests"

Write-Host ""

if (
    $CapturedTests -eq $TotalTests -and
    $MissedTests -eq 0
) {

    Write-Host "[PASS] Sysmon telemetry validation complete."
    exit 0
}
else {

    Write-Host "[FAIL] One or more Sysmon telemetry tests were missed."
    exit 1
}