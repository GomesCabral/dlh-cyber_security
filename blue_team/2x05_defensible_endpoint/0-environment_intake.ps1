#Requires -Version 5.1
<#
.SYNOPSIS
    Captures a complete, deterministic snapshot of an unhardened Windows
    endpoint (hawthorne-adm-01) BEFORE any hardening action, and writes it
    as structured JSON.

.DESCRIPTION
    This script is read-only: it inspects system state, it never changes
    it. Idempotency is therefore automatic -- running it twice never
    corrupts anything and never "re-applies" anything, because nothing is
    applied. Every later task in this capstone measures its success by the
    delta between this snapshot and the post-hardening state.

.PARAMETER OutputDirectory
    Directory to write environment_intake.json into. Defaults to the
    script's own directory.

.OUTPUTS
    Writes environment_intake.json to -OutputDirectory.

.NOTES
    Exit codes:
      0 - success, snapshot captured and written
      1 - controlled failure (a required capture could not be completed)
      2 - environment error (missing required module/cmdlet, cannot write output)

.EXAMPLE
    .\0-environment_intake.ps1
    Captures the local machine's baseline into .\environment_intake.json

.EXAMPLE
    .\0-environment_intake.ps1 -OutputDirectory C:\Evidence
    Captures the baseline into C:\Evidence\environment_intake.json
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputDirectory = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WarningCount = 0

function Write-IntakeLog {
    param([Parameter(Mandatory)][string]$Message)
    Write-Information -MessageData "[intake] $Message" -InformationAction Continue
}

function Write-IntakeWarning {
    param([Parameter(Mandatory)][string]$Message)
    Write-Warning -Message "[intake] $Message"
    $script:WarningCount++
}

function Exit-Environment {
    param([Parameter(Mandatory)][string]$Message)
    Write-Error -Message "[intake] ERROR: $Message" -ErrorAction Continue
    exit 2
}

# -----------------------------------------------------------------------
# Resolve OutputDirectory robustly. $PSScriptRoot can resolve to an empty
# string when the script runs from a mapped network drive under a session
# (e.g. an elevated/Administrator session) that does not see that drive
# mapping -- a well-known PowerShell quirk, not a script bug. Fall back to
# $PSCommandPath, then to the current working directory, rather than
# crashing on Test-Path with an empty LiteralPath.
# -----------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    if ($PSCommandPath) {
        $OutputDirectory = Split-Path -Path $PSCommandPath -Parent
    }
    else {
        $OutputDirectory = (Get-Location).Path
    }
    Write-Warning "[intake] PSScriptRoot was empty (common with mapped drives under an elevated session); defaulting output directory to: $OutputDirectory"
    $script:WarningCount++
}

# -----------------------------------------------------------------------
# Environment preconditions
# -----------------------------------------------------------------------
if (-not (Get-Command -Name 'ConvertTo-Json' -ErrorAction SilentlyContinue)) {
    Exit-Environment -Message 'ConvertTo-Json is unavailable; PowerShell 5.1+ is required'
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    Exit-Environment -Message "output directory does not exist: $OutputDirectory"
}

$outputJsonPath = Join-Path -Path $OutputDirectory -ChildPath 'environment_intake.json'
$capturedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

Write-IntakeLog -Message "Capturing environment intake for $env:COMPUTERNAME at $capturedAt"

# -----------------------------------------------------------------------
# Host / OS identity
# -----------------------------------------------------------------------
$osInfo = $null
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
}
catch {
    Write-IntakeWarning -Message "Get-CimInstance Win32_OperatingSystem failed: $($_.Exception.Message)"
}

$hostRecord = [ordered]@{
    hostname       = $env:COMPUTERNAME
    os_caption     = if ($osInfo) { $osInfo.Caption } else { $null }
    os_build       = if ($osInfo) { $osInfo.BuildNumber } else { $null }
    os_version     = if ($osInfo) { $osInfo.Version } else { $null }
    install_date   = if ($osInfo -and $osInfo.InstallDate) { $osInfo.InstallDate.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

$patchLevel = @()
try {
    $patchLevel = @(
        Get-HotFix -ErrorAction Stop |
            Sort-Object -Property InstalledOn -Descending |
            Select-Object -First 20 -ExpandProperty HotFixID
    )
}
catch {
    Write-IntakeWarning -Message "Get-HotFix failed: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------
# Installed feature count (server: Get-WindowsFeature, client: Get-WindowsOptionalFeature)
# -----------------------------------------------------------------------
$featureCount = $null
$featureSource = $null
if (Get-Command -Name 'Get-WindowsFeature' -ErrorAction SilentlyContinue) {
    try {
        $featureCount = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed }).Count
        $featureSource = 'Get-WindowsFeature'
    }
    catch {
        Write-IntakeWarning -Message "Get-WindowsFeature failed: $($_.Exception.Message)"
    }
}
elseif (Get-Command -Name 'Get-WindowsOptionalFeature' -ErrorAction SilentlyContinue) {
    try {
        $featureCount = @(
            Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                Where-Object { $_.State -eq 'Enabled' }
        ).Count
        $featureSource = 'Get-WindowsOptionalFeature'
    }
    catch {
        Write-IntakeWarning -Message "Get-WindowsOptionalFeature failed: $($_.Exception.Message)"
    }
}
else {
    Write-IntakeWarning -Message 'neither Get-WindowsFeature nor Get-WindowsOptionalFeature is available'
}

# -----------------------------------------------------------------------
# Running services
# -----------------------------------------------------------------------
$runningServices = @()
try {
    $runningServices = @(
        Get-Service -ErrorAction Stop |
            Where-Object { $_.Status -eq 'Running' } |
            Select-Object -ExpandProperty Name
    )
}
catch {
    Write-IntakeWarning -Message "Get-Service failed: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------
# Local user accounts
# -----------------------------------------------------------------------
$localUsers = @()
try {
    $localUsers = @(
        Get-LocalUser -ErrorAction Stop |
            Select-Object -Property Name, Enabled, PasswordRequired, PasswordExpires |
            ForEach-Object {
                [ordered]@{
                    name              = $_.Name
                    enabled           = [bool]$_.Enabled
                    password_required = [bool]$_.PasswordRequired
                    password_expires  = if ($_.PasswordExpires) { $_.PasswordExpires.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
                }
            }
    )
}
catch {
    Write-IntakeWarning -Message "Get-LocalUser failed: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------
# Windows Firewall state per profile
# -----------------------------------------------------------------------
$firewallProfiles = @()
try {
    $firewallProfiles = @(
        Get-NetFirewallProfile -ErrorAction Stop |
            ForEach-Object {
                [ordered]@{
                    profile = $_.Name
                    enabled = [bool]$_.Enabled
                }
            }
    )
}
catch {
    Write-IntakeWarning -Message "Get-NetFirewallProfile failed: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------
# Audit policy summary (auditpol /get /category:*)
# -----------------------------------------------------------------------
$auditPolicyLines = @()
if (Get-Command -Name 'auditpol.exe' -ErrorAction SilentlyContinue) {
    try {
        $raw = & auditpol.exe /get /category:* 2>&1
        if ($LASTEXITCODE -eq 0) {
            $auditPolicyLines = @(
                $raw |
                    Where-Object { $_ -match '\S' } |
                    ForEach-Object { $_.Trim() }
            )
        }
        else {
            Write-IntakeWarning -Message "auditpol.exe exited with code $LASTEXITCODE"
        }
    }
    catch {
        Write-IntakeWarning -Message "auditpol.exe invocation failed: $($_.Exception.Message)"
    }
}
else {
    Write-IntakeWarning -Message 'auditpol.exe not found'
}

# -----------------------------------------------------------------------
# Sysmon presence, version, event channel size
# -----------------------------------------------------------------------
$sysmonPresent = $false
$sysmonVersion = $null
$sysmonChannelSizeBytes = $null

$sysmonService = $null
try {
    $sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction Stop | Select-Object -First 1
}
catch {
    Write-IntakeWarning -Message "Get-Service (Sysmon lookup) failed: $($_.Exception.Message)"
}
if ($sysmonService) {
    $sysmonPresent = $true
    try {
        $sysmonBinary = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($sysmonService.Name)'" -ErrorAction Stop).PathName
        if ($sysmonBinary -match '"?([^"]+\.exe)"?') {
            $exePath = $Matches[1]
            if (Test-Path -LiteralPath $exePath) {
                $sysmonVersion = (Get-Item -LiteralPath $exePath).VersionInfo.ProductVersion
            }
        }
    }
    catch {
        Write-IntakeWarning -Message "could not resolve Sysmon binary version: $($_.Exception.Message)"
    }

    try {
        $channel = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        $sysmonChannelSizeBytes = $channel.MaximumSizeInBytes
    }
    catch {
        Write-IntakeWarning -Message "could not read Sysmon event channel size: $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------
# PowerShell Script Block Logging state (registry)
# -----------------------------------------------------------------------
$scriptBlockLoggingEnabled = $false
$sblRegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if (Test-Path -LiteralPath $sblRegistryPath) {
    try {
        $sblValue = Get-ItemProperty -LiteralPath $sblRegistryPath -Name 'EnableScriptBlockLogging' -ErrorAction Stop
        $scriptBlockLoggingEnabled = [bool]($sblValue.EnableScriptBlockLogging -eq 1)
    }
    catch {
        Write-IntakeWarning -Message "could not read ScriptBlockLogging registry value: $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------
# Account lockout and password policy (net accounts)
# -----------------------------------------------------------------------
$accountPolicyLines = @()
try {
    $raw = & net.exe accounts 2>&1
    if ($LASTEXITCODE -eq 0) {
        $accountPolicyLines = @(
            $raw |
                Where-Object { $_ -match '\S' } |
                ForEach-Object { $_.Trim() }
        )
    }
    else {
        Write-IntakeWarning -Message "net accounts exited with code $LASTEXITCODE"
    }
}
catch {
    Write-IntakeWarning -Message "net accounts invocation failed: $($_.Exception.Message)"
}

# -----------------------------------------------------------------------
# Assemble and write the JSON snapshot
# -----------------------------------------------------------------------
$snapshot = [ordered]@{
    schema_version = '1.0'
    captured_at    = $capturedAt
    host           = $hostRecord
    patches        = [ordered]@{
        recent_hotfix_ids = $patchLevel
    }
    features       = [ordered]@{
        installed_count = $featureCount
        source          = $featureSource
    }
    services       = [ordered]@{
        running_services = $runningServices
    }
    local_users    = $localUsers
    firewall       = [ordered]@{
        profiles = $firewallProfiles
    }
    audit_policy   = [ordered]@{
        summary_lines = $auditPolicyLines
    }
    telemetry      = [ordered]@{
        sysmon_present            = $sysmonPresent
        sysmon_version             = $sysmonVersion
        sysmon_channel_size_bytes  = $sysmonChannelSizeBytes
        script_block_logging_enabled = $scriptBlockLoggingEnabled
    }
    account_policy = [ordered]@{
        net_accounts_summary = $accountPolicyLines
    }
    capture_warning_count = $script:WarningCount
}

try {
    $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outputJsonPath -Encoding utf8 -ErrorAction Stop
}
catch {
    Exit-Environment -Message "failed to write $outputJsonPath : $($_.Exception.Message)"
}

Write-IntakeLog -Message "Wrote $outputJsonPath"
Write-IntakeLog -Message "services_running=$($runningServices.Count) local_users=$($localUsers.Count) warnings=$script:WarningCount"

if ($script:WarningCount -gt 0) {
    Write-IntakeLog -Message "completed with $script:WarningCount warning(s) -- see above"
    exit 1
}

exit 0