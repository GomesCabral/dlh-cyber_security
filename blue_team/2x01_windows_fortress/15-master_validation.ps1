# MedDefense Health Systems
# Task: 15 - Master Validation Script
# Script: 15-master_validation.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Perform a read-only weekly validation of all Windows Fortress hardening controls.
# Safety: READ-ONLY. This script does not modify Active Directory, GPO, Registry, Firewall or security settings.
# Output: PASS / WARN / FAIL compliance dashboard and process exit code.
#
# Exit codes:
# exit 0 = all critical checks PASS
# exit 1 = one or more critical checks FAIL
#
# Validates hardening from:
# Task 4  - Password and Lockout Policy
# Task 5  - Advanced Audit Policy
# Task 6  - PowerShell Security
# Task 7  - Kerberos and Authentication Hardening
# Task 8  - SMB and Protocol Hardening
# Task 9  - Sysmon Deployment
# Task 10 - Sysmon Detection Tuning
# Task 11 - Windows Firewall Lockdown
# Task 12 - AppLocker Policy
# Task 13 - RDP and Remote Access Reduction
# Task 14 - Service Account Control
#
# PASS = expected state confirmed
# WARN = non-critical issue or review item
# FAIL = critical hardening control does not match expected state
#
# VERIFY:
# Every critical Windows Fortress control is independently checked.
#
# service accounts validation:
# verify delegation restrictions, interactive logon denial,
# privileged group membership and password age for all service accounts.

# VERIFIED:
# Script exits with code 0 only when all critical controls PASS.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$TargetDomain = "meddefense.local"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$SysmonConfigFile = Join-Path `
    $ScriptDirectory `
    "sysmonconfig.xml"

$ExpectedMinimumPasswordLength = 14
$ExpectedPasswordHistory = 24
$ExpectedMaximumPasswordAgeDays = 0
$ExpectedMinimumPasswordAgeDays = 1

$ExpectedLockoutThreshold = 5
$ExpectedLockoutDurationMinutes = 15
$ExpectedLockoutObservationMinutes = 15

$ExpectedKerberosEncryptionValue = 24
$ExpectedLmCompatibilityLevel = 5

$ExpectedIdleTimeout = 900000
$ExpectedMaxSession = 28800000

$ManagementSubnet = "10.10.3.0/24"
$ServerSubnet = "10.10.1.0/24"

$PasswordAgeWarningDays = 90

$TerminalServicesPolicyPath = `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$RdpTcpPath = `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$PowerShellPolicyBase = `
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"

$UnauthorizedPrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "G_IT_Admins"
)

# ===========================================================================
# Result counters
# ===========================================================================

$PassCount = 0
$WarnCount = 0
$FailCount = 0
$CriticalFailures = 0

# ===========================================================================
# Helper functions
# ===========================================================================

function Write-Section {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Write-Host ""
    Write-Host "--- $Name ---"
}

function Write-Pass {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:PassCount++

    Write-Host "[PASS] $Message"
}

function Write-Warn {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:WarnCount++

    Write-Host "[WARN] $Message"
}

function Write-Fail {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [bool]$Critical = $true
    )

    $script:FailCount++

    if ($Critical) {
        $script:CriticalFailures++
    }

    Write-Host "[FAIL] $Message"
}

function Get-RegistryValueSafe {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {

        $Value = Get-ItemProperty `
            -Path $Path `
            -Name $Name `
            -ErrorAction Stop

        return $Value.$Name
    }
    catch {

        return $null
    }
}

function Test-AuditPolicy {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Subcategory,

        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Success",
            "Failure",
            "Success and Failure"
        )]
        [string]$Expected
    )

    try {

        $Output = @(
            auditpol.exe `
                /get `
                "/subcategory:$Subcategory" `
                2>$null
        )

        $Text = $Output -join " "

        switch ($Expected) {

            "Success and Failure" {

                return (
                    $Text -match "(?i)Success" -and
                    $Text -match "(?i)Failure"
                )
            }

            "Success" {

                return (
                    $Text -match "(?i)Success"
                )
            }

            "Failure" {

                return (
                    $Text -match "(?i)Failure"
                )
            }
        }
    }
    catch {

        return $false
    }

    return $false
}

function Get-ServiceAccounts {

    return @(
        Get-ADUser `
            -Filter * `
            -Properties `
                MemberOf,
                PasswordLastSet,
                PasswordNeverExpires,
                ServicePrincipalName,
                TrustedForDelegation,
                AccountNotDelegated,
                UseDESKeyOnly,
                msDS-SupportedEncryptionTypes,
                DistinguishedName,
                SID |
        Where-Object {
            $_.SamAccountName -match "(?i)^svc_" -or
            $_.DistinguishedName -match "(?i)OU=Service Accounts"
        } |
        Sort-Object SamAccountName
    )
}

function Get-ADGroupNames {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Account
    )

    $Names = @()

    foreach ($DN in @($Account.MemberOf)) {

        try {

            $Names += (
                Get-ADGroup `
                    -Identity $DN `
                    -ErrorAction Stop
            ).Name
        }
        catch {
        }
    }

    return @(
        $Names |
        Sort-Object -Unique
    )
}

function Get-DenyLogonRights {

    $TempFile = Join-Path `
        $env:TEMP `
        "meddefense-validation-rights.inf"

    $Result = [ordered]@{
        Interactive = @()
        RemoteInteractive = @()
    }

    try {

        secedit.exe `
            /export `
            /cfg $TempFile `
            /areas USER_RIGHTS `
            /quiet

        if (Test-Path $TempFile) {

            $Lines = Get-Content $TempFile

            foreach ($Line in $Lines) {

                if (
                    $Line -match
                    "^\s*SeDenyInteractiveLogonRight\s*=\s*(.*)$"
                ) {

                    $Result.Interactive = @(
                        $Matches[1] -split "," |
                        ForEach-Object {
                            $_.Trim()
                        } |
                        Where-Object {
                            $_
                        }
                    )
                }

                if (
                    $Line -match
                    "^\s*SeDenyRemoteInteractiveLogonRight\s*=\s*(.*)$"
                ) {

                    $Result.RemoteInteractive = @(
                        $Matches[1] -split "," |
                        ForEach-Object {
                            $_.Trim()
                        } |
                        Where-Object {
                            $_
                        }
                    )
                }
            }
        }
    }
    finally {

        Remove-Item `
            $TempFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    return [PSCustomObject]$Result
}

# ===========================================================================
# Environment
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Windows Fortress Master Validation"
Write-Host "=============================================="
Write-Host ""

$ComputerSystem = Get-CimInstance `
    Win32_ComputerSystem

Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Domain: $($ComputerSystem.Domain)"
Write-Host "Validation time: $(Get-Date)"
Write-Host "Mode: READ ONLY"

if (
    -not $ComputerSystem.PartOfDomain -or
    $ComputerSystem.Domain.ToLower() -ne
    $TargetDomain.ToLower()
) {

    Write-Fail `
        "Domain validation: expected meddefense.local"

    Write-Host ""
    Write-Host "Critical failures: $CriticalFailures"
    exit 1
}

if (
    -not (
        Get-Module `
            -ListAvailable `
            -Name ActiveDirectory
    )
) {

    Write-Fail `
        "ActiveDirectory PowerShell module unavailable"

    exit 1
}

Import-Module ActiveDirectory

# ===========================================================================
# Password & Lockout
# ===========================================================================

Write-Section "Password & Lockout"

$PasswordPolicy = Get-ADDefaultDomainPasswordPolicy

if (
    $PasswordPolicy.MinPasswordLength -eq
    $ExpectedMinimumPasswordLength
) {

    Write-Pass "Minimum length: 14"
}
else {

    Write-Fail `
        "Minimum length: $($PasswordPolicy.MinPasswordLength) (expected: 14)"
}

if ($PasswordPolicy.ComplexityEnabled) {

    Write-Pass "Complexity: Enabled"
}
else {

    Write-Fail "Complexity: Disabled"
}

if (
    $PasswordPolicy.PasswordHistoryCount -eq
    $ExpectedPasswordHistory
) {

    Write-Pass "Password history: 24"
}
else {

    Write-Fail `
        "Password history: $($PasswordPolicy.PasswordHistoryCount) (expected: 24)"
}

if (
    $PasswordPolicy.MaxPasswordAge.TotalDays -eq
    $ExpectedMaximumPasswordAgeDays
) {

    Write-Pass "Maximum age: 0"
}
else {

    Write-Fail `
        "Maximum age: $($PasswordPolicy.MaxPasswordAge.TotalDays) days (expected: 0)"
}

if (
    $PasswordPolicy.MinPasswordAge.TotalDays -eq
    $ExpectedMinimumPasswordAgeDays
) {

    Write-Pass "Minimum age: 1 day"
}
else {

    Write-Fail `
        "Minimum age: $($PasswordPolicy.MinPasswordAge.TotalDays) days (expected: 1)"
}

if (
    $PasswordPolicy.LockoutThreshold -eq
    $ExpectedLockoutThreshold
) {

    Write-Pass "Lockout threshold: 5"
}
else {

    Write-Fail `
        "Lockout threshold: $($PasswordPolicy.LockoutThreshold) (expected: 5)"
}

if (
    $PasswordPolicy.LockoutDuration.TotalMinutes -eq
    $ExpectedLockoutDurationMinutes
) {

    Write-Pass "Lockout duration: 15 minutes"
}
else {

    Write-Fail `
        "Lockout duration: $($PasswordPolicy.LockoutDuration.TotalMinutes) minutes (expected: 15)"
}

if (
    $PasswordPolicy.LockoutObservationWindow.TotalMinutes -eq
    $ExpectedLockoutObservationMinutes
) {

    Write-Pass "Reset counter: 15 minutes"
}
else {

    Write-Fail `
        "Reset counter: $($PasswordPolicy.LockoutObservationWindow.TotalMinutes) minutes (expected: 15)"
}

# ===========================================================================
# Audit Policy
# ===========================================================================

Write-Section "Audit Policy"

$AuditChecks = @(
    @{
        Name = "Credential Validation"
        Expected = "Success and Failure"
    },
    @{
        Name = "Kerberos Authentication Service"
        Expected = "Success and Failure"
    },
    @{
        Name = "Logon"
        Expected = "Success and Failure"
    },
    @{
        Name = "Logoff"
        Expected = "Success"
    },
    @{
        Name = "Special Logon"
        Expected = "Success"
    },
    @{
        Name = "User Account Management"
        Expected = "Success and Failure"
    },
    @{
        Name = "Sensitive Privilege Use"
        Expected = "Success and Failure"
    },
    @{
        Name = "File System"
        Expected = "Success and Failure"
    },
    @{
        Name = "Registry"
        Expected = "Success and Failure"
    },
    @{
        Name = "Process Creation"
        Expected = "Success"
    }
)

foreach ($Check in $AuditChecks) {

    if (
        Test-AuditPolicy `
            -Subcategory $Check.Name `
            -Expected $Check.Expected
    ) {

        Write-Pass `
            "$($Check.Name): $($Check.Expected)"
    }
    else {

        Write-Fail `
            "$($Check.Name): expected $($Check.Expected)"
    }
}

$CommandLineLogging = Get-RegistryValueSafe `
    -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled"

if ($CommandLineLogging -eq 1) {

    Write-Pass "Command-line logging: Enabled"
}
else {

    Write-Fail "Command-line logging: Disabled"
}

try {

    $SecurityLog = Get-WinEvent `
        -ListLog Security `
        -ErrorAction Stop

    if (
        $SecurityLog.MaximumSizeInBytes -ge
        1073741824
    ) {

        Write-Pass "Security log: 1 GB"
    }
    else {

        Write-Fail `
            "Security log size: $([math]::Round($SecurityLog.MaximumSizeInBytes / 1GB,2)) GB (expected >= 1 GB)"
    }
}
catch {

    Write-Fail "Security log size could not be verified"
}

# ===========================================================================
# PowerShell
# ===========================================================================

Write-Section "PowerShell"

$ScriptBlockLogging = Get-RegistryValueSafe `
    -Path "$PowerShellPolicyBase\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging"

if ($ScriptBlockLogging -eq 1) {

    Write-Pass "Script Block Logging: Enabled"
}
else {

    Write-Fail "Script Block Logging: Disabled"
}

$ModuleLogging = Get-RegistryValueSafe `
    -Path "$PowerShellPolicyBase\ModuleLogging" `
    -Name "EnableModuleLogging"

if ($ModuleLogging -eq 1) {

    Write-Pass "Module Logging: Enabled"
}
else {

    Write-Fail "Module Logging: Disabled"
}

$ModuleNames = Get-RegistryValueSafe `
    -Path "$PowerShellPolicyBase\ModuleLogging\ModuleNames" `
    -Name "*"

if ($ModuleNames -eq "*") {

    Write-Pass "ModuleNames: *"
}
else {

    Write-Fail "ModuleNames: not configured for all modules"
}

$Transcription = Get-RegistryValueSafe `
    -Path "$PowerShellPolicyBase\Transcription" `
    -Name "EnableTranscripting"

if ($Transcription -eq 1) {

    Write-Pass "Transcription: Enabled"
}
else {

    Write-Fail "Transcription: Disabled"
}

$TranscriptDirectory = Get-RegistryValueSafe `
    -Path "$PowerShellPolicyBase\Transcription" `
    -Name "OutputDirectory"

if ($TranscriptDirectory -eq "C:\PSTranscripts") {

    Write-Pass "Transcript directory: C:\PSTranscripts"
}
else {

    Write-Fail `
        "Transcript directory: $TranscriptDirectory"
}

if (Test-Path "$env:WINDIR\System32\amsi.dll") {

    Write-Pass "AMSI: Available"
}
else {

    Write-Fail "AMSI: amsi.dll missing"
}

# ===========================================================================
# Sysmon
# ===========================================================================

Write-Section "Sysmon"

$SysmonService = Get-Service `
    -Name Sysmon64 `
    -ErrorAction SilentlyContinue

if ($null -eq $SysmonService) {

    $SysmonService = Get-Service `
        -Name Sysmon `
        -ErrorAction SilentlyContinue
}

if (
    $null -ne $SysmonService -and
    $SysmonService.Status -eq "Running"
) {

    Write-Pass "Service: Running"
}
else {

    Write-Fail "Service: Not running"
}

$SysmonDriver = Get-CimInstance `
    Win32_SystemDriver `
    -Filter "Name='SysmonDrv'" `
    -ErrorAction SilentlyContinue

if (
    $null -ne $SysmonDriver -and
    (
        $SysmonDriver.Started -or
        $SysmonDriver.State -eq "Running"
    )
) {

    Write-Pass "Driver: SysmonDrv loaded"
}
else {

    Write-Fail "Driver: SysmonDrv not loaded"
}

try {

    $RecentSysmonEvents = @(
        Get-WinEvent `
            -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"
                StartTime = (Get-Date).AddHours(-24)
            } `
            -ErrorAction SilentlyContinue
    )

    if ($RecentSysmonEvents.Count -gt 0) {

        Write-Pass `
            "Telemetry: $($RecentSysmonEvents.Count) events in last 24 hours"
    }
    else {

        Write-Warn "Sysmon: no events found in last 24 hours"
    }
}
catch {

    Write-Warn "Sysmon event generation could not be checked"
}

if (Test-Path $SysmonConfigFile) {

    $SysmonText = Get-Content `
        $SysmonConfigFile `
        -Raw

    $RequiredCustomRules = @(
        "MedDefense Rule 1 - Rclone",
        "MedDefense Rule 2 - PsExec Service",
        "MedDefense Rule 3 - Encoded PowerShell",
        "MedDefense Rule 4 - Shadow Deletion",
        "MedDefense Rule 5 - Scheduled Task"
    )

    $FoundRules = 0

    foreach ($Rule in $RequiredCustomRules) {

        if (
            $SysmonText -match
            [regex]::Escape($Rule)
        ) {

            $FoundRules++
        }
    }

    if ($FoundRules -eq 5) {

        Write-Pass "Custom rules: 5 present"
    }
    else {

        Write-Fail `
            "Custom rules: $FoundRules/5 present"
    }

    if ($SysmonText -match "FileCreate") {

        Write-Pass "FileCreate telemetry: Present"
    }
    else {

        Write-Warn "FileCreate telemetry not found in sysmonconfig.xml"
    }
}
else {

    Write-Fail "sysmonconfig.xml not found"
}

# ===========================================================================
# Kerberos & Authentication
# ===========================================================================

Write-Section "Kerberos"

$ServiceAccounts = @(
    Get-ServiceAccounts
)

$BadDESAccounts = @(
    $ServiceAccounts |
    Where-Object {
        $_.UseDESKeyOnly
    }
)

if ($BadDESAccounts.Count -eq 0) {

    Write-Pass "DES: Disabled"
}
else {

    Write-Fail `
        "DES: enabled on $($BadDESAccounts.SamAccountName -join ', ')"
}

$WeakEncryptionAccounts = @(
    $ServiceAccounts |
    Where-Object {

        $Value = $_.'msDS-SupportedEncryptionTypes'

        if ($null -eq $Value) {
            return $true
        }

        $Mask = [int]$Value

        return (
            ($Mask -band 1) -ne 0 -or
            ($Mask -band 2) -ne 0 -or
            ($Mask -band 4) -ne 0 -or
            $Mask -ne $ExpectedKerberosEncryptionValue
        )
    }
)

if ($WeakEncryptionAccounts.Count -eq 0) {

    Write-Pass "RC4: Disabled"
    Write-Pass "Kerberos: AES128 + AES256 only"
}
else {

    Write-Fail `
        "RC4/DES or non-AES-only encryption remains on: $($WeakEncryptionAccounts.SamAccountName -join ', ')"
}

$KerberosRegistry = Get-RegistryValueSafe `
    -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -Name "SupportedEncryptionTypes"

if ($KerberosRegistry -eq 24) {

    Write-Pass "Domain Kerberos SupportedEncryptionTypes: 24"
}
else {

    Write-Fail `
        "Kerberos SupportedEncryptionTypes: $KerberosRegistry (expected: 24)"
}

$LmCompatibilityLevel = Get-RegistryValueSafe `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel"

if ($LmCompatibilityLevel -eq 5) {

    Write-Pass "NTLM: v2 only"
}
else {

    Write-Fail `
        "LmCompatibilityLevel: $LmCompatibilityLevel (expected: 5)"
}

try {

    $DeviceGuard = Get-CimInstance `
        -Namespace "root\Microsoft\Windows\DeviceGuard" `
        -ClassName Win32_DeviceGuard `
        -ErrorAction Stop

    if (
        @($DeviceGuard.SecurityServicesRunning) -contains 1
    ) {

        Write-Pass "Credential Guard: Running"
    }
    else {

        Write-Warn "Credential Guard: Not running"
    }
}
catch {

    Write-Warn "Credential Guard / DeviceGuard status unavailable"
}

$LsaCfgFlags = Get-RegistryValueSafe `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags"

if ($null -eq $LsaCfgFlags) {

    Write-Warn "LsaCfgFlags: Not configured"
}
else {

    Write-Pass "LsaCfgFlags: $LsaCfgFlags"
}

# ===========================================================================
# SMB
# ===========================================================================

Write-Section "SMB"

$SmbServer = Get-SmbServerConfiguration
$SmbClient = Get-SmbClientConfiguration

if (-not $SmbServer.EnableSMB1Protocol) {

    Write-Pass "SMBv1: Disabled"
}
else {

    Write-Fail "SMBv1: Enabled"
}

if (
    $SmbServer.RequireSecuritySignature -and
    $SmbClient.RequireSecuritySignature
) {

    Write-Pass "Signing: Required"
}
else {

    Write-Fail "Signing: Not required on client/server"
}

if ($SmbServer.EncryptData) {

    Write-Pass "Encryption: Enabled"
}
else {

    Write-Fail "Encryption: Disabled"
}

$Llmnr = Get-RegistryValueSafe `
    -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast"

if ($Llmnr -eq 0) {

    Write-Pass "LLMNR: Disabled"
}
else {

    Write-Fail "LLMNR: Enabled or not configured"
}

$NetBIOSAdapters = @(
    Get-CimInstance `
        Win32_NetworkAdapterConfiguration `
        -Filter "IPEnabled=True"
)

$BadNetBIOS = @(
    $NetBIOSAdapters |
    Where-Object {
        $_.TcpipNetbiosOptions -ne 2
    }
)

if ($BadNetBIOS.Count -eq 0) {

    Write-Pass "NetBIOS over TCP/IP: Disabled"
}
else {

    Write-Fail `
        "NetBIOS over TCP/IP: enabled/default on $($BadNetBIOS.Count) adapter(s)"
}

# ===========================================================================
# Firewall
# ===========================================================================

Write-Section "Firewall"

$FirewallProfiles = @(
    Get-NetFirewallProfile
)

$BadFirewallProfiles = @(
    $FirewallProfiles |
    Where-Object {
        -not $_.Enabled -or
        $_.DefaultInboundAction -ne "Block"
    }
)

if ($BadFirewallProfiles.Count -eq 0) {

    Write-Pass `
        "All profiles: ON, DefaultInbound: Block"
}
else {

    Write-Fail `
        "One or more firewall profiles are disabled or not DefaultInbound=Block"
}

$BadFirewallLogging = @(
    $FirewallProfiles |
    Where-Object {
        -not $_.LogBlocked
    }
)

if ($BadFirewallLogging.Count -eq 0) {

    Write-Pass "Dropped packet logging: Enabled"
}
else {

    Write-Fail "Dropped packet logging: Disabled on one or more profiles"
}

$ExpectedFirewallRules = @(
    "MedDef-RDP-Mgmt",
    "MedDef-DNS-TCP",
    "MedDef-DNS-UDP",
    "MedDef-LDAP",
    "MedDef-Kerberos-TCP",
    "MedDef-Kerberos-UDP",
    "MedDef-SMB",
    "MedDef-WinRM-HTTP",
    "MedDef-WinRM-HTTPS"
)

$FirewallRuleFailures = 0

foreach ($RuleName in $ExpectedFirewallRules) {

    $Rule = Get-NetFirewallRule `
        -DisplayName $RuleName `
        -ErrorAction SilentlyContinue

    if (
        $null -ne $Rule -and
        $Rule.Enabled -eq "True"
    ) {

        Write-Pass "Firewall rule: $RuleName"
    }
    else {

        Write-Fail "Firewall rule missing/disabled: $RuleName"
        $FirewallRuleFailures++
    }
}

# ===========================================================================
# AppLocker
# ===========================================================================

Write-Section "AppLocker"

$AppIdSvc = Get-Service `
    AppIDSvc `
    -ErrorAction SilentlyContinue

if (
    $null -ne $AppIdSvc -and
    $AppIdSvc.Status -eq "Running"
) {

    Write-Pass "AppIDSvc: Running"
}
else {

    Write-Fail "AppIDSvc: Not running"
}

try {

    [xml]$AppLockerXml = Get-AppLockerPolicy `
        -Effective `
        -Xml

    $ExeCollection = @(
        $AppLockerXml.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Exe"
        }
    ) |
    Select-Object -First 1

    $ScriptCollection = @(
        $AppLockerXml.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Script"
        }
    ) |
    Select-Object -First 1

    if (
        $null -ne $ExeCollection -and
        $ExeCollection.EnforcementMode -eq "AuditOnly"
    ) {

        Write-Pass "Executable policy: Audit Only"
    }
    else {

        Write-Fail "Executable AppLocker policy not AuditOnly"
    }

    if (
        $null -ne $ScriptCollection -and
        $ScriptCollection.EnforcementMode -eq "AuditOnly"
    ) {

        Write-Pass "Script policy: Audit Only"
    }
    else {

        Write-Fail "Script AppLocker policy not AuditOnly"
    }

    $AppLockerText = $AppLockerXml.OuterXml

    foreach ($RequiredText in @(
        "Windows",
        "Program Files",
        "DicomViewer",
        "MedDefense_Lab"
    )) {

        if (
            $AppLockerText -match
            [regex]::Escape($RequiredText)
        ) {

            Write-Pass `
                "AppLocker rule present: $RequiredText"
        }
        else {

            Write-Fail `
                "AppLocker rule missing: $RequiredText"
        }
    }
}
catch {

    Write-Fail "Effective AppLocker policy could not be validated"
}

# ===========================================================================
# RDP
# ===========================================================================

Write-Section "RDP"

$Nla = Get-RegistryValueSafe `
    -Path $RdpTcpPath `
    -Name "UserAuthentication"

if ($Nla -eq 1) {

    Write-Pass "NLA: Required"
}
else {

    Write-Fail "NLA: Not required"
}

$MaxIdleTime = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "MaxIdleTime"

if ($MaxIdleTime -eq $ExpectedIdleTimeout) {

    Write-Pass "Idle timeout: 15 min"
}
else {

    Write-Fail `
        "Idle timeout: $MaxIdleTime (expected: 900000)"
}

$MaxConnectionTime = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "MaxConnectionTime"

if (
    $MaxConnectionTime -eq
    $ExpectedMaxSession
) {

    Write-Pass "Max session: 8 hours"
}
else {

    Write-Fail `
        "Max session: $MaxConnectionTime (expected: 28800000)"
}

$MinEncryptionLevel = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "MinEncryptionLevel"

$SecurityLayer = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "SecurityLayer"

if (
    $MinEncryptionLevel -eq 3 -and
    $SecurityLayer -eq 2
) {

    Write-Pass "Encryption: High/SSL"
}
else {

    Write-Fail `
        "RDP encryption does not match High/SSL"
}

$Clipboard = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "fDisableClip"

if ($Clipboard -eq 1) {

    Write-Pass "Clipboard: Disabled"
}
else {

    Write-Fail "Clipboard redirection: Enabled"
}

$DriveRedirection = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "fDisableCdm"

if ($DriveRedirection -eq 1) {

    Write-Pass "Drive redirection: Disabled"
}
else {

    Write-Fail "Drive redirection: Enabled"
}

$RemoteAssistance = Get-RegistryValueSafe `
    -Path $TerminalServicesPolicyPath `
    -Name "fAllowToGetHelp"

if ($RemoteAssistance -eq 0) {

    Write-Pass "Remote Assistance: Disabled"
}
else {

    Write-Fail "Remote Assistance: Enabled/not explicitly disabled"
}

try {

    $RdpMembers = @(
        Get-ADGroupMember `
            -Identity "Remote Desktop Users" `
            -ErrorAction Stop
    )

    $Authorized = @(
        $RdpMembers |
        Where-Object {
            $_.Name -eq "G_IT_Admins"
        }
    )

    $Unauthorized = @(
        $RdpMembers |
        Where-Object {
            $_.Name -ne "G_IT_Admins"
        }
    )

    if (
        $Authorized.Count -eq 1 -and
        $Unauthorized.Count -eq 0
    ) {

        Write-Pass "Access: G_IT_Admins only"
    }
    else {

        Write-Fail `
            "Remote Desktop Users membership does not equal G_IT_Admins only"
    }
}
catch {

    Write-Fail "Remote Desktop Users membership could not be validated"
}

# ===========================================================================
# Service Accounts
# ===========================================================================

Write-Host "Validating service accounts..."

$RestrictedDelegation = 0

foreach ($Account in $ServiceAccounts) {

    if (
        $Account.AccountNotDelegated -and
        -not $Account.TrustedForDelegation
    ) {

        $RestrictedDelegation++
    }
    else {

        Write-Fail `
            "$($Account.SamAccountName): delegation not restricted"
    }
}

if (
    $RestrictedDelegation -eq
    $ServiceAccounts.Count
) {

    Write-Pass `
        "Delegation restricted: $RestrictedDelegation/$($ServiceAccounts.Count)"
}

$Rights = Get-DenyLogonRights

foreach ($Account in $ServiceAccounts) {

    $Sid = "*$($Account.SID.Value)"

    if ($Rights.Interactive -contains $Sid) {

        Write-Pass `
            "$($Account.SamAccountName): interactive logon denied"
    }
    else {

        Write-Fail `
            "$($Account.SamAccountName): interactive logon not denied"
    }

    if ($Rights.RemoteInteractive -contains $Sid) {

        Write-Pass `
            "$($Account.SamAccountName): RDP logon denied"
    }
    else {

        Write-Fail `
            "$($Account.SamAccountName): RDP logon not denied"
    }

    $GroupNames = @(
        Get-ADGroupNames `
            -Account $Account
    )

    $BadGroups = @(
        $GroupNames |
        Where-Object {
            $UnauthorizedPrivilegedGroups -contains $_
        }
    )

    if ($BadGroups.Count -eq 0) {

        Write-Pass `
            "$($Account.SamAccountName): no excessive privileged memberships"
    }
    else {

        Write-Fail `
            "$($Account.SamAccountName): privileged membership $($BadGroups -join ', ')"
    }

    if ($null -eq $Account.PasswordLastSet) {

        Write-Warn `
            "$($Account.SamAccountName) password age: UNKNOWN"
    }
    else {

        $PasswordAge = [int](
            (
                New-TimeSpan `
                    -Start $Account.PasswordLastSet `
                    -End (Get-Date)
            ).TotalDays
        )

        if (
            $PasswordAge -gt
            $PasswordAgeWarningDays
        ) {

            Write-Warn `
                "$($Account.SamAccountName) password age: $PasswordAge days"
        }
        else {

            Write-Pass `
                "$($Account.SamAccountName) password age: $PasswordAge days"
        }
    }
}

# ===========================================================================
# Final compliance dashboard
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Compliance Summary"
Write-Host "=============================================="

$TotalChecks = `
    $PassCount +
    $WarnCount +
    $FailCount

if ($TotalChecks -gt 0) {

    $CompliancePercentage = [math]::Round(
        (
            $PassCount /
            $TotalChecks
        ) * 100,
        1
    )
}
else {

    $CompliancePercentage = 0
}

Write-Host "PASS: $PassCount"
Write-Host "WARN: $WarnCount"
Write-Host "FAIL: $FailCount"
Write-Host "Critical failures: $CriticalFailures"
Write-Host "Compliance: $CompliancePercentage%"

Write-Host ""

# ===========================================================================
# Required exit behavior
# ===========================================================================

if ($CriticalFailures -eq 0) {

    Write-Host `
        "[PASS] All critical Windows Fortress controls validated."

    Write-Host `
        "Exit code: 0"

    exit 0
}
else {

    Write-Host `
        "[FAIL] One or more critical Windows Fortress controls failed."

    Write-Host `
        "Exit code: 1"

    exit 1
}