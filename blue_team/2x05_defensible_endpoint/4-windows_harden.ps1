#Requires -Version 5.1
<#
.SYNOPSIS
    Orchestrates the Windows hardening pass against hawthorne-adm-01.

.DESCRIPTION
    This script does not reinvent hardening logic -- it composes the
    existing hardening scripts in a deterministic order, captures every
    sub-step as structured evidence, re-runs the CIS Level 1 audit helper,
    and measures the result against the Windows controls already declared
    in capstone\target_state.json (task 2). A missing or corrupted
    target_state.json is fatal, per that contract -- there is no
    meaningful pass/fail verdict without it.

    Emits the SAME JSON schema as the Linux sibling (3-linux_harden.sh's
    linux_harden.json) so the T8 validation suite can read either file
    without branching on platform. Concretely this means the Windows
    JSON reuses the field names lynis_before / lynis_after / index_delta
    even though this side has no Lynis involved -- on Windows these hold
    the CIS Level 1 pass-rate percentage before/after hardening, not a
    Lynis hardening index. This is a deliberate cross-platform naming
    choice, not a copy-paste mistake; see the task 4 instructions.

.PARAMETER CapstoneDirectory
    Root directory under which capstone\exec\ is created and
    capstone\target_state.json / capstone\baseline\baseline_windows.json
    are read from. Defaults to the script's own directory (with the same
    PSScriptRoot-empty fallback used by the other scripts in this repo).

.PARAMETER AuditHelperPath
    Path to the project-provided win_audit.ps1 CIS Level 1 audit helper.

.NOTES
    IMPORTANT: the *Script parameters below default to this repo's test
    fixtures (test_fixtures\hardening_win\*.ps1), used to validate this
    orchestrator end-to-end. Before running against the real Hawthorne
    server, override each with the actual hardening script from the 2x01
    / 2x02 (Windows hardening / instrumentation) projects.

    Exit codes:
      0 - every sub-step exited 0 AND post_pass_rate >= target pass rate
      1 - orchestration completed but the pass criterion above was not met
      2 - environment error (missing target_state.json/control, missing
          baseline_windows.json, missing audit helper, cannot write output)

.EXAMPLE
    .\4-windows_harden.ps1

.EXAMPLE
    .\4-windows_harden.ps1 -CapstoneDirectory C:\Evidence -AuditHelperPath C:\MedDefense_Lab\capstone\win_audit.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$CapstoneDirectory = $PSScriptRoot,

    [Parameter(Position = 1)]
    [string]$AuditHelperPath = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1',

    [string]$AccountPolicyScript,
    [string]$AuditPolicyScript,
    [string]$FirewallScript,
    [string]$SysmonScript,
    [string]$ScriptBlockLoggingScript,
    [string]$AppControlScript,
    [string]$ServiceMinimizationScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WarningCount = 0

function Write-HardenLog {
    param([Parameter(Mandatory)][string]$Message)
    Write-Information -MessageData "[windows_harden] $Message" -InformationAction Continue
}

function Exit-Environment {
    param([Parameter(Mandatory)][string]$Message)
    Write-Error -Message "[windows_harden] ERROR: $Message" -ErrorAction Continue
    exit 2
}

# -----------------------------------------------------------------------
# Resolve CapstoneDirectory robustly (same mapped-drive/elevated-session
# fallback as 0-environment_intake.ps1 / 1-baseline_snapshot.ps1).
# -----------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($CapstoneDirectory)) {
    if ($PSCommandPath) {
        $CapstoneDirectory = Split-Path -Path $PSCommandPath -Parent
    }
    else {
        $CapstoneDirectory = (Get-Location).Path
    }
    Write-Warning "[windows_harden] PSScriptRoot was empty; defaulting capstone directory to: $CapstoneDirectory"
    $script:WarningCount++
}
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($PSCommandPath) { Split-Path -Path $PSCommandPath -Parent } else { (Get-Location).Path }

$fixtureDir = Join-Path -Path $scriptDir -ChildPath 'test_fixtures\hardening_win'
if (-not $AccountPolicyScript)        { $AccountPolicyScript        = Join-Path $fixtureDir 'account_policy.ps1' }
if (-not $AuditPolicyScript)          { $AuditPolicyScript          = Join-Path $fixtureDir 'audit_policy.ps1' }
if (-not $FirewallScript)             { $FirewallScript             = Join-Path $fixtureDir 'windows_firewall_baseline.ps1' }
if (-not $SysmonScript)               { $SysmonScript               = Join-Path $fixtureDir 'sysmon_install.ps1' }
if (-not $ScriptBlockLoggingScript)   { $ScriptBlockLoggingScript   = Join-Path $fixtureDir 'powershell_sbl_enable.ps1' }
if (-not $AppControlScript)           { $AppControlScript           = Join-Path $fixtureDir 'applocker_defender_baseline.ps1' }
if (-not $ServiceMinimizationScript)  { $ServiceMinimizationScript  = Join-Path $fixtureDir 'service_minimization.ps1' }

$execDir = Join-Path -Path $CapstoneDirectory -ChildPath 'capstone\exec'
# Writes: capstone\exec\windows_harden.log (structured execution evidence)
$logPath = Join-Path -Path $execDir -ChildPath 'windows_harden.log'
$outputJsonPath = Join-Path -Path $execDir -ChildPath 'windows_harden.json'
$targetStatePath = Join-Path -Path $CapstoneDirectory -ChildPath 'capstone\target_state.json'
$baselinePath = Join-Path -Path $CapstoneDirectory -ChildPath 'capstone\baseline\baseline_windows.json'

# -----------------------------------------------------------------------
# Preconditions. Per task 2's own documented contract: a missing or
# corrupted target_state.json is fatal for every downstream script.
# -----------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $targetStatePath -PathType Leaf)) {
    Exit-Environment -Message "target_state.json not found at $targetStatePath -- run 2-target_state.sh first"
}
$targetState = $null
try {
    $targetState = Get-Content -LiteralPath $targetStatePath -Raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Exit-Environment -Message "target_state.json at $targetStatePath is corrupted (invalid JSON): $($_.Exception.Message)"
}

$cisControl = $targetState.controls | Where-Object { $_.id -eq 'WIN-CIS-01' } | Select-Object -First 1
if (-not $cisControl -or $null -eq $cisControl.expected_value) {
    Exit-Environment -Message "target_state.json does not declare control WIN-CIS-01 (CIS Level 1 pass-rate target)"
}
$targetPassRate = [double]$cisControl.expected_value

if (-not (Test-Path -LiteralPath $baselinePath -PathType Leaf)) {
    Exit-Environment -Message "$baselinePath not found -- run 1-baseline_snapshot.ps1 first"
}
$baseline = $null
try {
    $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Exit-Environment -Message "$baselinePath is corrupted (invalid JSON): $($_.Exception.Message)"
}
if ($null -eq $baseline.pass_rate_percent) {
    Exit-Environment -Message "$baselinePath has no pass_rate_percent; run 1-baseline_snapshot.ps1 first"
}
$passRateBefore = [double]$baseline.pass_rate_percent

if (-not (Test-Path -LiteralPath $AuditHelperPath -PathType Leaf)) {
    Exit-Environment -Message "audit helper not found: $AuditHelperPath (shipped with the project, this script does not create it)"
}

try {
    New-Item -ItemType Directory -Path $execDir -Force -ErrorAction Stop | Out-Null
}
catch {
    Exit-Environment -Message "failed to create $execDir : $($_.Exception.Message)"
}

Set-Content -LiteralPath $logPath -Value '' -Encoding utf8
$runStartedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Add-Content -LiteralPath $logPath -Value "===== 4-windows_harden.ps1 run started: $runStartedAt ====="
Add-Content -LiteralPath $logPath -Value "target pass rate (WIN-CIS-01): $targetPassRate"
Add-Content -LiteralPath $logPath -Value "pass_rate_before (from baseline_windows.json): $passRateBefore"
Add-Content -LiteralPath $logPath -Value ''

# -----------------------------------------------------------------------
# Per-step target-state control ID mapping (documented, static). Steps
# with no currently-declared control in target_state.json map to an
# empty list -- expected today for account_policy / applocker_defender
# baseline / service_minimization, not a bug.
# -----------------------------------------------------------------------
$controlsMap = @{
    account_policy         = @()
    audit_policy            = @('WIN-AUD-01', 'WIN-AUD-02', 'WIN-AUD-03', 'WIN-AUD-04')
    windows_firewall        = @('WIN-FW-01')
    sysmon_installation     = @('WIN-SYSMON-01')
    powershell_sbl_enable   = @('WIN-PSLOG-01')
    app_control_baseline    = @()
    service_minimization    = @()
}

$steps = New-Object System.Collections.Generic.List[object]
$allStepsOk = $true

# -----------------------------------------------------------------------
# Wrapper: runs one sub-step, times it, appends its full stdout+stderr
# and exit code to $logPath, and records structured evidence. "changed"
# is derived from the same documented convention as the Linux
# orchestrator: a step prints a line starting with "CHANGED:" to stdout
# for each modification it made.
# -----------------------------------------------------------------------
function Invoke-HardeningStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ScriptPath
    )

    Add-Content -LiteralPath $logPath -Value "===== STEP: $Name ====="
    Add-Content -LiteralPath $logPath -Value "script_path: $ScriptPath"
    Add-Content -LiteralPath $logPath -Value "started_at: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $output = @()
    $exitCode = 0

    if (Test-Path -LiteralPath $ScriptPath -PathType Leaf) {
        try {
            $output = @(& $ScriptPath 2>&1 | ForEach-Object { $_.ToString() })
            $exitCode = $LASTEXITCODE
            if ($null -eq $exitCode) { $exitCode = 0 }
        }
        catch {
            $output = @("EXCEPTION: $($_.Exception.Message)")
            $exitCode = 1
        }
    }
    else {
        $output = @("sub-step script not found: $ScriptPath")
        $exitCode = 127
    }

    $stopwatch.Stop()
    $duration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)

    $output | ForEach-Object { Add-Content -LiteralPath $logPath -Value $_ }
    Add-Content -LiteralPath $logPath -Value "exit_code: $exitCode"
    Add-Content -LiteralPath $logPath -Value "duration_seconds: $duration"
    Add-Content -LiteralPath $logPath -Value ''

    $changed = [bool]($output | Where-Object { $_ -like 'CHANGED:*' })

    $controlsTouched = @()
    if ($controlsMap.ContainsKey($Name)) { $controlsTouched = $controlsMap[$Name] }

    $script:steps.Add([ordered]@{
        name              = $Name
        script_path       = $ScriptPath
        exit_code         = $exitCode
        duration_seconds  = $duration
        changed           = $changed
        controls_touched  = @($controlsTouched)
    })

    if ($exitCode -ne 0) { $script:allStepsOk = $false }
    Write-HardenLog -Message "step '$Name' exit=$exitCode duration=${duration}s changed=$changed"
}

# -----------------------------------------------------------------------
# Run the composition in deterministic order: account policy, audit
# policy, Windows Firewall baseline, Sysmon installation with the
# MedDefense config, PowerShell Script Block Logging enable, AppLocker
# or Defender Application Control baseline, service minimization.
# -----------------------------------------------------------------------
Invoke-HardeningStep -Name 'account_policy'       -ScriptPath $AccountPolicyScript
Invoke-HardeningStep -Name 'audit_policy'         -ScriptPath $AuditPolicyScript
Invoke-HardeningStep -Name 'windows_firewall'     -ScriptPath $FirewallScript
Invoke-HardeningStep -Name 'sysmon_installation'  -ScriptPath $SysmonScript
Invoke-HardeningStep -Name 'powershell_sbl_enable' -ScriptPath $ScriptBlockLoggingScript
Invoke-HardeningStep -Name 'app_control_baseline' -ScriptPath $AppControlScript
Invoke-HardeningStep -Name 'service_minimization' -ScriptPath $ServiceMinimizationScript

# -----------------------------------------------------------------------
# Re-run the CIS Level 1 audit helper and compute the new pass rate.
# Same PASS/FAIL/NOT_APPLICABLE parsing convention as 1-baseline_snapshot.ps1.
# -----------------------------------------------------------------------
Write-HardenLog -Message "Re-running audit helper: $AuditHelperPath"
Add-Content -LiteralPath $logPath -Value '===== STEP: win_audit_reaudit ====='
Add-Content -LiteralPath $logPath -Value "started_at: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

$auditLines = @()
try {
    $auditLines = @(& $AuditHelperPath 2>&1 | ForEach-Object { $_.ToString() })
}
catch {
    Exit-Environment -Message "audit helper invocation failed: $($_.Exception.Message)"
}
$auditLines | ForEach-Object { Add-Content -LiteralPath $logPath -Value $_ }
Add-Content -LiteralPath $logPath -Value ''

$passCount = 0
$failCount = 0
foreach ($line in $auditLines) {
    if ($line -match '\bPASS\s*$') { $passCount++ }
    elseif ($line -match '\bFAIL\s*$') { $failCount++ }
}
$applicable = $passCount + $failCount
if ($applicable -eq 0) {
    Exit-Environment -Message 'post-hardening audit produced no PASS/FAIL lines to compute a pass rate from'
}
$passRateAfter = [Math]::Round(($passCount / $applicable) * 100, 2)
$indexDelta = [Math]::Round($passRateAfter - $passRateBefore, 2)

Write-HardenLog -Message "pass_rate_before=$passRateBefore pass_rate_after=$passRateAfter index_delta=$indexDelta target=$targetPassRate"

# -----------------------------------------------------------------------
# Assemble controls_touched (deduplicated union) and write windows_harden.json
# using the SAME schema as linux_harden.json -- see the header note on
# lynis_before/lynis_after/index_delta field-name reuse.
# -----------------------------------------------------------------------
$allControlsTouched = @($controlsMap.Values | ForEach-Object { $_ } | Sort-Object -Unique)

$snapshot = [ordered]@{
    timestamp         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname          = $env:COMPUTERNAME
    steps             = $steps
    lynis_before      = $passRateBefore
    lynis_after       = $passRateAfter
    index_delta       = $indexDelta
    controls_touched  = $allControlsTouched
}

try {
    $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outputJsonPath -Encoding utf8 -ErrorAction Stop
}
catch {
    Exit-Environment -Message "failed to write $outputJsonPath : $($_.Exception.Message)"
}

Write-HardenLog -Message "Wrote $outputJsonPath"
Write-HardenLog -Message "Full step log at $logPath"

# -----------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------
if ($allStepsOk -and ($passRateAfter -ge $targetPassRate)) {
    Write-HardenLog -Message "PASS: all steps succeeded and pass_rate_after ($passRateAfter) >= target ($targetPassRate)"
    exit 0
}
else {
    Write-HardenLog -Message "FAIL: all_steps_ok=$allStepsOk pass_rate_after=$passRateAfter target=$targetPassRate"
    exit 1
}