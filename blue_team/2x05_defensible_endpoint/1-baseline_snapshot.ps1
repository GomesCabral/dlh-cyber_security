#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the project-provided CIS Level 1 audit helper against the Windows
    endpoint and persists the raw baseline output plus the extracted pass
    rate. This number is the denominator of the delta reported at the end
    of the capstone.

.DESCRIPTION
    Task 0 (environment intake) says what is on the host. This baseline
    says how far it is from hardened. The audit helper walks a fixed list
    of CIS Level 1 controls and prints one line per control ending in
    PASS, FAIL, or NOT_APPLICABLE; this script counts those outcomes and
    computes a pass rate over the controls that actually applied.

.PARAMETER CapstoneDirectory
    Root directory under which capstone/baseline/ is created. Defaults to
    the script's own directory (with a PSScriptRoot-empty fallback, same
    as 0-environment_intake.ps1, for mapped-drive/elevated-session cases).

.PARAMETER AuditHelperPath
    Path to the project-provided win_audit.ps1. Defaults to the path
    specified in the task instructions; override if the real deployment
    path differs on a given host.

.NOTES
    Exit codes:
      0 - success, baseline captured and written
      1 - controlled failure (audit ran but some lines could not be parsed)
      2 - environment error (audit helper missing, cannot write output)

.EXAMPLE
    .\1-baseline_snapshot.ps1

.EXAMPLE
    .\1-baseline_snapshot.ps1 -CapstoneDirectory C:\Evidence -AuditHelperPath C:\MedDefense_Lab\capstone\win_audit.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$CapstoneDirectory = $PSScriptRoot,

    [Parameter(Position = 1)]
    [string]$AuditHelperPath = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WarningCount = 0

function Write-BaselineLog {
    param([Parameter(Mandatory)][string]$Message)
    Write-Information -MessageData "[baseline] $Message" -InformationAction Continue
}

function Write-BaselineWarning {
    param([Parameter(Mandatory)][string]$Message)
    Write-Warning -Message "[baseline] $Message"
    $script:WarningCount++
}

function Exit-Environment {
    param([Parameter(Mandatory)][string]$Message)
    Write-Error -Message "[baseline] ERROR: $Message" -ErrorAction Continue
    exit 2
}

# -----------------------------------------------------------------------
# Resolve CapstoneDirectory robustly (same mapped-drive/elevated-session
# fallback as 0-environment_intake.ps1 -- see that script for rationale).
# -----------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($CapstoneDirectory)) {
    if ($PSCommandPath) {
        $CapstoneDirectory = Split-Path -Path $PSCommandPath -Parent
    }
    else {
        $CapstoneDirectory = (Get-Location).Path
    }
    Write-Warning "[baseline] PSScriptRoot was empty; defaulting capstone directory to: $CapstoneDirectory"
    $script:WarningCount++
}

$baselineDir = Join-Path -Path $CapstoneDirectory -ChildPath 'capstone\baseline'
$logPath = Join-Path -Path $baselineDir -ChildPath 'windows_baseline.log'
$outputJsonPath = Join-Path -Path $baselineDir -ChildPath 'baseline_windows.json'

# -----------------------------------------------------------------------
# Preconditions
# -----------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $AuditHelperPath -PathType Leaf)) {
    Exit-Environment -Message "audit helper not found: $AuditHelperPath (shipped with the project, this script does not create it)"
}

try {
    New-Item -ItemType Directory -Path $baselineDir -Force -ErrorAction Stop | Out-Null
}
catch {
    Exit-Environment -Message "failed to create $baselineDir : $($_.Exception.Message)"
}

$timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$hostnameValue = $env:COMPUTERNAME

# -----------------------------------------------------------------------
# Run the audit helper and capture its full raw output.
# -----------------------------------------------------------------------
Write-BaselineLog -Message "Running audit helper: $AuditHelperPath"

$rawLines = @()
try {
    $rawLines = @(& $AuditHelperPath 2>&1 | ForEach-Object { $_.ToString() })
}
catch {
    Exit-Environment -Message "audit helper invocation failed: $($_.Exception.Message)"
}

try {
    $rawLines | Set-Content -LiteralPath $logPath -Encoding utf8 -ErrorAction Stop
}
catch {
    Exit-Environment -Message "failed to write $logPath : $($_.Exception.Message)"
}

if ($rawLines.Count -eq 0) {
    Exit-Environment -Message "audit helper produced no output"
}

Write-BaselineLog -Message "audit helper exited; full log at $logPath ($($rawLines.Count) lines)"

# -----------------------------------------------------------------------
# Parse PASS / FAIL / NOT_APPLICABLE counts. Each control line ends in
# one of these three tokens (control id and description may vary in
# format, so the match anchors on the trailing verdict token only).
# -----------------------------------------------------------------------
$passCount = 0
$failCount = 0
$naCount = 0
$unparsedCount = 0

foreach ($line in $rawLines) {
    if ($line -match '\bPASS\s*$') {
        $passCount++
    }
    elseif ($line -match '\bFAIL\s*$') {
        $failCount++
    }
    elseif ($line -match '\bNOT_APPLICABLE\s*$') {
        $naCount++
    }
    elseif ($line.Trim().Length -gt 0) {
        $unparsedCount++
    }
}

if ($unparsedCount -gt 0) {
    Write-BaselineWarning -Message "$unparsedCount line(s) did not end in PASS/FAIL/NOT_APPLICABLE and were not counted"
}

$controlsTotal = $passCount + $failCount + $naCount
if ($controlsTotal -eq 0) {
    Write-BaselineWarning -Message "no PASS/FAIL/NOT_APPLICABLE lines were found in the audit helper output"
}

# Pass rate is computed over controls that actually applied (PASS+FAIL),
# excluding NOT_APPLICABLE from the denominator -- an N/A control (e.g. a
# Bluetooth policy on a host with no Bluetooth hardware) should not count
# against the host, the same way Lynis excludes skipped tests from its
# hardening index.
$applicableCount = $passCount + $failCount
if ($applicableCount -gt 0) {
    $passRatePercent = [Math]::Round(($passCount / $applicableCount) * 100, 2)
}
else {
    Write-BaselineWarning -Message "no applicable (PASS+FAIL) controls found; pass_rate_percent recorded as null"
    $passRatePercent = $null
}

# -----------------------------------------------------------------------
# Emit baseline_windows.json
# -----------------------------------------------------------------------
$snapshot = [ordered]@{
    timestamp          = $timestamp
    hostname           = $hostnameValue
    controls_total     = $controlsTotal
    pass_count         = $passCount
    fail_count         = $failCount
    na_count           = $naCount
    pass_rate_percent  = $passRatePercent
    log_path           = $logPath
}

try {
    $snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outputJsonPath -Encoding utf8 -ErrorAction Stop
}
catch {
    Exit-Environment -Message "failed to write $outputJsonPath : $($_.Exception.Message)"
}

Write-BaselineLog -Message "Wrote $outputJsonPath"
Write-BaselineLog -Message "controls_total=$controlsTotal pass=$passCount fail=$failCount na=$naCount pass_rate_percent=$passRatePercent"

if ($script:WarningCount -gt 0) {
    Write-BaselineLog -Message "completed with $script:WarningCount warning(s) -- see above"
    exit 1
}

exit 0