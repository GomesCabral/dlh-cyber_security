# MedDefense Health Systems
# Task: 2 - Windows Event Log Assessment
# Script: 2-eventlog_assessment.ps1
# Author: Pedro Cabral
# Purpose: Assess Windows audit policy and critical Security Event ID visibility.
# Safety: READ-ONLY. This script does not modify audit policy or Windows Event Logs.
# Output: Console assessment of critical Windows Security Event IDs.
#
# Critical Event IDs:
# 4624 - Successful Logon
# 4625 - Failed Logon
# 4648 - Logon using explicit credentials
# 4688 - Process Creation
# 4720 - User Account Created
# 4726 - User Account Deleted
# 4732 - Member Added to Local Security Group
# 4672 - Special privileges assigned to new logon
# 1102 - Security Audit Log Cleared
#
# This script checks:
# 1. Current audit policy using auditpol /get /category:*
# 2. Required audit subcategory for each Event ID
# 3. Whether the Security log generated each Event ID during the last 24 hours
#
# No audit configuration is changed.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$HoursToCheck = 24

# Required 24-hour assessment window.
$StartTime = (Get-Date).AddHours(-24)

$IsElevated = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsElevated) {
    Write-Host "[!] Warning: PowerShell is not running as Administrator."
    Write-Host "[!] Security log and audit policy visibility may be incomplete."
    Write-Host ""
}

# ===========================================================================
# Event definitions
# ===========================================================================

$EventDefinitions = @(

    [PSCustomObject]@{
        EventID           = 4624
        Description       = "Successful Logon"
        AuditCategory     = "Logon"
        AuditSubcategory  = "Logon"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 4625
        Description       = "Failed Logon"
        AuditCategory     = "Logon"
        AuditSubcategory  = "Logon"
        RequiredSetting   = "Failure"
    }

    [PSCustomObject]@{
        EventID           = 4648
        Description       = "Explicit Credentials"
        AuditCategory     = "Logon"
        AuditSubcategory  = "Logon"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 4688
        Description       = "Process Creation"
        AuditCategory     = "Process Tracking"
        AuditSubcategory  = "Process Creation"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 4720
        Description       = "Account Created"
        AuditCategory     = "Account Management"
        AuditSubcategory  = "User Account Management"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 4726
        Description       = "Account Deleted"
        AuditCategory     = "Account Management"
        AuditSubcategory  = "User Account Management"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 4732
        Description       = "Member Added to Group"
        AuditCategory     = "Account Management"
        AuditSubcategory  = "Security Group Management"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 4672
        Description       = "Special Logon"
        AuditCategory     = "Special Logon"
        AuditSubcategory  = "Special Logon"
        RequiredSetting   = "Success"
    }

    [PSCustomObject]@{
        EventID           = 1102
        Description       = "Audit Log Cleared"
        AuditCategory     = "System Integrity"
        AuditSubcategory  = "Security System Extension"
        RequiredSetting   = "Success"
    }
)

# ===========================================================================
# Helper functions
# ===========================================================================

function Get-AuditPolicy {

    Write-Host "[*] Reading current Advanced Audit Policy..."

    try {

        $AuditPolicyRaw = @(
            auditpol.exe /get /category:* 2>$null
        )

        if ($LASTEXITCODE -ne 0) {
            throw "auditpol returned exit code $LASTEXITCODE"
        }

        return ,$AuditPolicyRaw
    }
    catch {

        Write-Host "[!] Could not read audit policy: $($_.Exception.Message)"

        return ,@()
    }
}


function Test-AuditSubcategory {

    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AuditPolicy,

        [Parameter(Mandatory = $true)]
        [string]$Subcategory,

        [Parameter(Mandatory = $true)]
        [string]$RequiredSetting
    )

    $MatchingLine = $AuditPolicy |
        Where-Object {
            $_ -match [regex]::Escape($Subcategory)
        } |
        Select-Object -First 1

    if ($null -eq $MatchingLine) {

        return [PSCustomObject]@{
            Found       = $false
            Configured  = $false
            Setting     = "NOT FOUND"
        }
    }

    $Setting = $MatchingLine.Trim()

    $Configured = $false

    if ($RequiredSetting -eq "Success") {

        if (
            $Setting -match "Success" -or
            $Setting -match "Success and Failure"
        ) {

            $Configured = $true
        }
    }

    elseif ($RequiredSetting -eq "Failure") {

        if (
            $Setting -match "Failure" -or
            $Setting -match "Success and Failure"
        ) {

            $Configured = $true
        }
    }

    return [PSCustomObject]@{
        Found       = $true
        Configured  = $Configured
        Setting     = $Setting
    }
}


function Get-RecentEventCount {

    param(
        [Parameter(Mandatory = $true)]
        [int]$EventID,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
    )

    try {

        $Events = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = "Security"
                    Id        = $EventID
                    StartTime = $StartTime
                } `
                -ErrorAction SilentlyContinue
        )

        return $Events.Count
    }
    catch {

        return 0
    }
}


# ===========================================================================
# Environment information
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Event Log Assessment"
Write-Host "=============================================="
Write-Host ""

Write-Host "[*] Computer: $env:COMPUTERNAME"
Write-Host "[*] Assessment window: last $HoursToCheck hours"
Write-Host "[*] Start time: $StartTime"
Write-Host "[*] Mode: READ ONLY"
Write-Host ""

# ===========================================================================
# Check audit policy
# ===========================================================================

$AuditPolicy = @(
    Get-AuditPolicy
)

if (@($AuditPolicy).Count -eq 0) {

    Write-Host "[!] Audit policy could not be collected."
    Write-Host "[!] Run PowerShell as Administrator if Security policy access is restricted."
}

# ===========================================================================
# Assess Event IDs
# ===========================================================================

Write-Host ""
Write-Host "[*] Checking critical Windows Security Event IDs..."
Write-Host ""

$Results = @()

foreach ($Definition in $EventDefinitions) {

    $AuditCheck = Test-AuditSubcategory `
        -AuditPolicy $AuditPolicy `
        -Subcategory $Definition.AuditSubcategory `
        -RequiredSetting $Definition.RequiredSetting

    $EventCount = Get-RecentEventCount `
        -EventID $Definition.EventID `
        -StartTime $StartTime

    if (-not $AuditCheck.Configured) {

        $Status = "NOT CONFIGURED"
    }
    elseif ($EventCount -gt 0) {

        $Status = "GENERATING"
    }
    else {

        $Status = "CONFIGURED - NO EVENTS"
    }

    $Results += [PSCustomObject]@{
        EventID          = $Definition.EventID
        Description      = $Definition.Description
        AuditSubcategory = $Definition.AuditSubcategory
        RequiredSetting  = $Definition.RequiredSetting
        AuditConfigured  = $AuditCheck.Configured
        EventsLast24h    = $EventCount
        Status           = $Status
    }
}

# ===========================================================================
# Console table
# ===========================================================================

$Results |
    Select-Object `
        @{Name="Event ID"; Expression={$_.EventID}},
        Description,
        @{Name="Audit Subcategory"; Expression={$_.AuditSubcategory}},
        @{Name="Events 24h"; Expression={$_.EventsLast24h}},
        @{Name="Status"; Expression={"[$($_.Status)]"}} |
    Format-Table -AutoSize

# ===========================================================================
# Visibility gap summary
# ===========================================================================

$GeneratingCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "GENERATING"
    }
).Count

$NotConfiguredCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "NOT CONFIGURED"
    }
).Count

$ConfiguredNoEventsCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "CONFIGURED - NO EVENTS"
    }
).Count

Write-Host ""
Write-Host "=============================================="
Write-Host "Visibility Summary"
Write-Host "=============================================="

Write-Host "Critical Event IDs assessed: $($Results.Count)"
Write-Host "Generating: $GeneratingCount"
Write-Host "Not configured: $NotConfiguredCount"
Write-Host "Configured but no events in 24h: $ConfiguredNoEventsCount"

Write-Host ""
Write-Host "[*] Assessment complete."
Write-Host "[*] No Windows security settings were modified."