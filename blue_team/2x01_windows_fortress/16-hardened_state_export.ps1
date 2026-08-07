# MedDefense Health Systems
# Task: 16 - Hardened Windows State Export
# Script: 16-hardened_state_export.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Export the final hardened MedDefense Windows domain state as machine-readable JSON evidence.
# Safety: READ-ONLY. This script makes no security configuration changes.
# Output: windows_hardened_state.json
#
# Required JSON sections:
# - domain_metadata
# - gpo_inventory
# - audit_policy
# - powershell_logging
# - sysmon_posture
# - firewall_posture
# - applocker_posture
# - rdp_posture
# - authentication_protocols
# - service_account_posture
# - validation_summary
#
# Telemetry references:
# - PowerShell Event ID 4103
# - PowerShell Event ID 4104
# - Sysmon active Event IDs
#
# Authentication posture:
# - DES
# - RC4
# - AES
# - NTLMv1
# - SMBv1
# - SMB signing
#
# service accounts:
# delegation, password age, privileged membership and interactive logon risk
#
# validation_summary:
# Load Task 15 validation results if available.
# Otherwise return status = not_found.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$TargetDomain = "meddefense.local"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$OutputFile = Join-Path `
    $ScriptDirectory `
    "windows_hardened_state.json"

$SysmonConfigFile = Join-Path `
    $ScriptDirectory `
    "sysmonconfig.xml"

$AppLockerPolicyFile = Join-Path `
    $ScriptDirectory `
    "applocker_policy.xml"

$ValidationCandidates = @(
    (Join-Path $ScriptDirectory "validation_results.json"),
    (Join-Path $ScriptDirectory "master_validation_results.json"),
    (Join-Path $ScriptDirectory "15-validation_results.json")
)

$PowerShellPolicyBase = `
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"

$TerminalServicesPolicyPath = `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$RdpTcpPath = `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$KerberosPolicyPath = `
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

$LsaPath = `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$UnauthorizedPrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "G_IT_Admins"
)

# ===========================================================================
# Helper functions
# ===========================================================================

function Write-Step {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[*] $Message"
}

function Get-RegistryValueSafe {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {

        $Property = Get-ItemProperty `
            -Path $Path `
            -Name $Name `
            -ErrorAction Stop

        return $Property.$Name
    }
    catch {

        return $null
    }
}

function Convert-KerberosEncryptionTypes {

    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @("DEFAULT")
    }

    try {
        $Mask = [int]$Value
    }
    catch {
        return @("UNKNOWN")
    }

    $Types = @()

    if (($Mask -band 1) -ne 0) {
        $Types += "DES_CRC"
    }

    if (($Mask -band 2) -ne 0) {
        $Types += "DES_MD5"
    }

    if (($Mask -band 4) -ne 0) {
        $Types += "RC4"
    }

    if (($Mask -band 8) -ne 0) {
        $Types += "AES128"
    }

    if (($Mask -band 16) -ne 0) {
        $Types += "AES256"
    }

    if ($Types.Count -eq 0) {
        $Types += "NONE"
    }

    return $Types
}

function Get-AuditSubcategoryStatus {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Subcategory
    )

    try {

        $Output = @(
            auditpol.exe `
                /get `
                "/subcategory:$Subcategory" `
                2>$null
        )

        $Text = ($Output -join " ").Trim()

        $Success = (
            $Text -match "(?i)Success" -or
            $Text -match "(?i)Êxito"
        )

        $Failure = (
            $Text -match "(?i)Failure" -or
            $Text -match "(?i)Falha"
        )

        if ($Success -and $Failure) {
            $Status = "Success and Failure"
        }
        elseif ($Success) {
            $Status = "Success"
        }
        elseif ($Failure) {
            $Status = "Failure"
        }
        else {
            $Status = "No Auditing / Unknown"
        }

        return [PSCustomObject]@{
            subcategory = $Subcategory
            status      = $Status
            raw         = $Text
        }
    }
    catch {

        return [PSCustomObject]@{
            subcategory = $Subcategory
            status      = "not_found"
            raw         = $null
        }
    }
}

function Get-ServiceAccounts {

    return @(
        Get-ADUser `
            -Filter * `
            -Properties `
                Enabled,
                MemberOf,
                PasswordLastSet,
                PasswordNeverExpires,
                LastLogonDate,
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

function Get-GroupNames {

    param(
        [Parameter(Mandatory = $true)]
        [object]$Account
    )

    $Groups = @()

    foreach ($GroupDN in @($Account.MemberOf)) {

        try {

            $Groups += (
                Get-ADGroup `
                    -Identity $GroupDN `
                    -ErrorAction Stop
            ).Name
        }
        catch {
        }
    }

    return @(
        $Groups |
        Sort-Object -Unique
    )
}

function Get-DenyLogonRights {

    $TempFile = Join-Path `
        $env:TEMP `
        "meddefense-state-export-rights.inf"

    $Result = [ordered]@{
        interactive        = @()
        remote_interactive = @()
    }

    try {

        secedit.exe `
            /export `
            /cfg $TempFile `
            /areas USER_RIGHTS `
            /quiet

        if (Test-Path $TempFile) {

            foreach ($Line in Get-Content $TempFile) {

                if (
                    $Line -match
                    "^\s*SeDenyInteractiveLogonRight\s*=\s*(.*)$"
                ) {

                    $Result.interactive = @(
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

                    $Result.remote_interactive = @(
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
            -Path $TempFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    return [PSCustomObject]$Result
}

# ===========================================================================
# Environment validation
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense Hardened Windows State Export"
Write-Host "=============================================="
Write-Host ""

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

if (-not $ComputerSystem.PartOfDomain) {
    throw "This computer is not joined to Active Directory."
}

if (
    $ComputerSystem.Domain.ToLower() -ne
    $TargetDomain.ToLower()
) {

    throw "Expected '$TargetDomain', detected '$($ComputerSystem.Domain)'."
}

if (
    -not (
        Get-Module `
            -ListAvailable `
            -Name ActiveDirectory
    )
) {

    throw "ActiveDirectory PowerShell module is required."
}

Import-Module ActiveDirectory

$GPOModuleAvailable = [bool](
    Get-Module `
        -ListAvailable `
        -Name GroupPolicy
)

if ($GPOModuleAvailable) {
    Import-Module GroupPolicy
}

$Domain = Get-ADDomain
$Forest = Get-ADForest

# ===========================================================================
# domain_metadata
# ===========================================================================

Write-Step "Exporting domain metadata..."

$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$DomainMetadata = [ordered]@{
    domain_name       = $Domain.DNSRoot
    netbios_name      = $Domain.NetBIOSName
    domain_controller = $Domain.PDCEmulator
    computer_name     = $env:COMPUTERNAME
    forest_name       = $Forest.Name
    domain_mode       = [string]$Domain.DomainMode
    forest_mode       = [string]$Forest.ForestMode
    timestamp         = (Get-Date).ToString("o")
    script_runner     = $CurrentIdentity.Name
    script_name       = "16-hardened_state_export.ps1"
}

Write-Host "    Domain metadata... OK"

# ===========================================================================
# gpo_inventory
# ===========================================================================

Write-Step "Exporting GPO settings..."

$GpoInventory = @()

if ($GPOModuleAvailable) {

    $MedDefenseGpos = @(
        Get-GPO -All |
        Where-Object {
            $_.DisplayName -like "MedDefense -*"
        } |
        Sort-Object DisplayName
    )

    foreach ($GPO in $MedDefenseGpos) {

        $Links = @()

        try {

            [xml]$Report = Get-GPOReport `
                -Guid $GPO.Id `
                -ReportType Xml

            $ScopeNodes = @(
                $Report.GPO.LinksTo
            )

            foreach ($Scope in $ScopeNodes) {

                if ($null -ne $Scope) {

                    $Links += [PSCustomObject]@{
                        scope   = [string]$Scope.SOMPath
                        enabled = [string]$Scope.Enabled
                    }
                }
            }

            $KeySettings = @()

            $RegistryNodes = @(
                $Report.SelectNodes("//*[local-name()='RegistrySetting']")
            )

            foreach ($Node in $RegistryNodes) {

                $KeySettings += [PSCustomObject]@{
                    name  = [string]$Node.Name
                    value = [string]$Node.Value
                }
            }
        }
        catch {

            $KeySettings = @()
        }

        $GpoInventory += [PSCustomObject]@{
            name            = $GPO.DisplayName
            id              = $GPO.Id.ToString()
            gpo_status      = [string]$GPO.GpoStatus
            enabled         = (
                $GPO.GpoStatus -ne "AllSettingsDisabled"
            )
            creation_time   = $GPO.CreationTime
            modification_time = $GPO.ModificationTime
            linked_scopes   = $Links
            key_settings    = $KeySettings
        }
    }
}

Write-Host "    Exporting GPO settings... $($GpoInventory.Count) GPOs"

# ===========================================================================
# audit_policy
# ===========================================================================

Write-Step "Exporting audit policy..."

$AuditRaw = @(
    auditpol.exe `
        /get `
        /category:* `
        2>$null
)

$RequiredAuditSubcategories = @(
    "Credential Validation",
    "Kerberos Authentication Service",
    "Logon",
    "Logoff",
    "Special Logon",
    "User Account Management",
    "Sensitive Privilege Use",
    "File System",
    "Registry",
    "Process Creation",
    "Security System Extension"
)

$AuditStatuses = @()

foreach ($Subcategory in $RequiredAuditSubcategories) {

    $AuditStatuses += Get-AuditSubcategoryStatus `
        -Subcategory $Subcategory
}

$AuditPolicy = [ordered]@{
    raw_auditpol_output = $AuditRaw

    required_subcategories = $AuditStatuses

    required_subcategory_count = $AuditStatuses.Count

    # Expected Windows Security telemetry for Module 3 analysts.
    expected_event_ids = @(
        [PSCustomObject]@{
            event_id = 4624
            name = "Successful Logon"
        },
        [PSCustomObject]@{
            event_id = 4625
            name = "Failed Logon"
        },
        [PSCustomObject]@{
            event_id = 4648
            name = "Logon Using Explicit Credentials"
        },
        [PSCustomObject]@{
            event_id = 4672
            name = "Special Privileges Assigned to New Logon"
        },
        [PSCustomObject]@{
            event_id = 4688
            name = "Process Creation"
        },
        [PSCustomObject]@{
            event_id = 4720
            name = "User Account Created"
        },
        [PSCustomObject]@{
            event_id = 4726
            name = "User Account Deleted"
        },
        [PSCustomObject]@{
            event_id = 4732
            name = "Member Added to Security-Enabled Local Group"
        },
        [PSCustomObject]@{
            event_id = 1102
            name = "Audit Log Cleared"
        }
    )

    process_command_line_logging = Get-RegistryValueSafe `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled"

    security_log_max_size_bytes = $null
}

try {

    $SecurityLog = Get-WinEvent `
        -ListLog Security `
        -ErrorAction Stop

    $AuditPolicy.security_log_max_size_bytes = `
        $SecurityLog.MaximumSizeInBytes
}
catch {
}

Write-Host `
    "    Exporting audit policy... $($AuditStatuses.Count) subcategories"

# ===========================================================================
# powershell_logging
# ===========================================================================

Write-Step "Exporting PowerShell logging..."

$PowerShellLogging = [ordered]@{
    script_block_logging = Get-RegistryValueSafe `
        -Path "$PowerShellPolicyBase\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging"

    module_logging = Get-RegistryValueSafe `
        -Path "$PowerShellPolicyBase\ModuleLogging" `
        -Name "EnableModuleLogging"

    module_names = Get-RegistryValueSafe `
        -Path "$PowerShellPolicyBase\ModuleLogging\ModuleNames" `
        -Name "*"

    transcription = Get-RegistryValueSafe `
        -Path "$PowerShellPolicyBase\Transcription" `
        -Name "EnableTranscripting"

    transcript_directory = Get-RegistryValueSafe `
        -Path "$PowerShellPolicyBase\Transcription" `
        -Name "OutputDirectory"

    amsi_available = Test-Path `
        "$env:WINDIR\System32\amsi.dll"

    event_ids = @(
        [PSCustomObject]@{
            event_id = 4103
            meaning  = "PowerShell Module Logging"
        },
        [PSCustomObject]@{
            event_id = 4104
            meaning  = "PowerShell Script Block Logging"
        }
    )
}

Write-Host "    Exporting PowerShell logging... OK"

# ===========================================================================
# sysmon_posture
# ===========================================================================

Write-Step "Exporting Sysmon config..."

$SysmonService = Get-Service `
    -Name Sysmon64 `
    -ErrorAction SilentlyContinue

if ($null -eq $SysmonService) {

    $SysmonService = Get-Service `
        -Name Sysmon `
        -ErrorAction SilentlyContinue
}

$SysmonDriver = Get-CimInstance `
    -ClassName Win32_SystemDriver `
    -Filter "Name='SysmonDrv'" `
    -ErrorAction SilentlyContinue

$CustomRuleCount = 0
$ActiveSysmonEventIds = @()
$SysmonConfigStatus = "not_found"

if (Test-Path $SysmonConfigFile) {

    $SysmonConfigStatus = "found"

    try {

        [xml]$SysmonXml = Get-Content `
            -Path $SysmonConfigFile `
            -Raw

        $CustomRuleNodes = @(
            $SysmonXml.SelectNodes(
                "//*[@name and starts-with(@name,'MedDefense Rule ')]"
            )
        )

        $CustomRuleCount = $CustomRuleNodes.Count

        $EventMap = @{
            ProcessCreate        = 1
            FileCreateTime       = 2
            NetworkConnect       = 3
            SysmonServiceStateChange = 4
            ProcessTerminate     = 5
            DriverLoad           = 6
            ImageLoad            = 7
            CreateRemoteThread   = 8
            RawAccessRead        = 9
            ProcessAccess        = 10
            FileCreate           = 11
            RegistryEvent        = 13
            FileCreateStreamHash = 15
            PipeEvent            = 17
            WmiEvent             = 19
            DNSQuery             = 22
            FileDelete           = 23
        }

        foreach ($ElementName in $EventMap.Keys) {

            $Nodes = @(
                $SysmonXml.SelectNodes(
                    "//*[local-name()='$ElementName']"
                )
            )

            if ($Nodes.Count -gt 0) {

                $ActiveSysmonEventIds += `
                    $EventMap[$ElementName]
            }
        }

        $ActiveSysmonEventIds = @(
            $ActiveSysmonEventIds |
            Sort-Object -Unique
        )
    }
    catch {

        $SysmonConfigStatus = "parse_error"
    }
}

$SysmonPosture = [ordered]@{
    service_name = if ($null -ne $SysmonService) {
        $SysmonService.Name
    }
    else {
        $null
    }

    service_status = if ($null -ne $SysmonService) {
        [string]$SysmonService.Status
    }
    else {
        "not_found"
    }

    driver_name = "SysmonDrv"

    driver_status = if ($null -ne $SysmonDriver) {
        [string]$SysmonDriver.State
    }
    else {
        "not_found"
    }

    driver_started = if ($null -ne $SysmonDriver) {
        [bool]$SysmonDriver.Started
    }
    else {
        $false
    }

    config_path       = $SysmonConfigFile
    config_status     = $SysmonConfigStatus
    custom_rule_count = $CustomRuleCount
    active_event_ids  = $ActiveSysmonEventIds
}

Write-Host `
    "    Exporting Sysmon config... $CustomRuleCount custom rules"

# ===========================================================================
# firewall_posture
# ===========================================================================

Write-Step "Exporting firewall rules..."

$FirewallProfiles = @(
    Get-NetFirewallProfile |
    ForEach-Object {

        [PSCustomObject]@{
            name                    = $_.Name
            enabled                 = [bool]$_.Enabled
            default_inbound_action  = [string]$_.DefaultInboundAction
            default_outbound_action = [string]$_.DefaultOutboundAction
            dropped_packet_logging  = [bool]$_.LogBlocked
            log_path                = [string]$_.LogFileName
        }
    }
)

$MedDefenseFirewallRules = @()

$FirewallRulesRaw = @(
    Get-NetFirewallRule `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "MedDef-*"
    }
)

foreach ($Rule in $FirewallRulesRaw) {

    $PortFilter = $Rule |
        Get-NetFirewallPortFilter `
            -ErrorAction SilentlyContinue

    $AddressFilter = $Rule |
        Get-NetFirewallAddressFilter `
            -ErrorAction SilentlyContinue

    $MedDefenseFirewallRules += [PSCustomObject]@{
        name          = $Rule.DisplayName
        enabled       = [string]$Rule.Enabled
        direction     = [string]$Rule.Direction
        action        = [string]$Rule.Action
        protocol      = [string]$PortFilter.Protocol
        local_port    = [string]$PortFilter.LocalPort
        remote_address = @($AddressFilter.RemoteAddress)
    }
}

$LogicalFirewallServices = @(
    "RDP",
    "DNS",
    "LDAP",
    "Kerberos",
    "SMB",
    "WinRM"
)

$FirewallPosture = [ordered]@{
    profiles = $FirewallProfiles
    meddefense_rules = $MedDefenseFirewallRules
    physical_rule_count = $MedDefenseFirewallRules.Count
    logical_services = $LogicalFirewallServices
    logical_service_count = $LogicalFirewallServices.Count
}

Write-Host `
    "    Exporting firewall rules... $($LogicalFirewallServices.Count) rules"

# ===========================================================================
# applocker_posture
# ===========================================================================

Write-Step "Exporting AppLocker policy..."

$AppLockerPosture = [ordered]@{
    service_status       = "not_found"
    executable_mode      = "not_found"
    script_mode          = "not_found"
    executable_rules     = @()
    script_rules         = @()
    executable_rule_count = 0
    script_rule_count     = 0
    total_rule_count      = 0
    exported_policy_path = $AppLockerPolicyFile
}

$AppIdSvc = Get-Service `
    -Name AppIDSvc `
    -ErrorAction SilentlyContinue

if ($null -ne $AppIdSvc) {

    $AppLockerPosture.service_status = `
        [string]$AppIdSvc.Status
}

try {

    [xml]$EffectiveAppLocker = Get-AppLockerPolicy `
        -Effective `
        -Xml

    $ExeCollection = @(
        $EffectiveAppLocker.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Exe"
        }
    ) |
    Select-Object -First 1

    $ScriptCollection = @(
        $EffectiveAppLocker.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Script"
        }
    ) |
    Select-Object -First 1

    if ($null -ne $ExeCollection) {

        $AppLockerPosture.executable_mode = `
            [string]$ExeCollection.EnforcementMode

        $ExeRules = @(
            $ExeCollection.ChildNodes |
            Where-Object {
                $_.NodeType -eq "Element"
            } |
            ForEach-Object {

                [PSCustomObject]@{
                    name   = [string]$_.Name
                    action = [string]$_.Action
                    type   = [string]$_.LocalName
                }
            }
        )

        $AppLockerPosture.executable_rules = $ExeRules
        $AppLockerPosture.executable_rule_count = $ExeRules.Count
    }

    if ($null -ne $ScriptCollection) {

        $AppLockerPosture.script_mode = `
            [string]$ScriptCollection.EnforcementMode

        $ScriptRules = @(
            $ScriptCollection.ChildNodes |
            Where-Object {
                $_.NodeType -eq "Element"
            } |
            ForEach-Object {

                [PSCustomObject]@{
                    name   = [string]$_.Name
                    action = [string]$_.Action
                    type   = [string]$_.LocalName
                }
            }
        )

        $AppLockerPosture.script_rules = $ScriptRules
        $AppLockerPosture.script_rule_count = $ScriptRules.Count
    }

    $AppLockerPosture.total_rule_count = (
        $AppLockerPosture.executable_rule_count +
        $AppLockerPosture.script_rule_count
    )
}
catch {
}

Write-Host `
    "    Exporting AppLocker policy... $($AppLockerPosture.total_rule_count) rules"

# ===========================================================================
# rdp_posture
# ===========================================================================

Write-Step "Exporting remote access posture..."

$RdpMembers = @()

try {

    $RdpMembers = @(
        Get-ADGroupMember `
            -Identity "Remote Desktop Users" |
        Select-Object `
            Name,
            SamAccountName,
            ObjectClass
    )
}
catch {
}

# RDP / NLA posture
# NLA = Network Level Authentication
# Expected state: NLA Required (UserAuthentication = 1)

$NLAValue = Get-RegistryValueSafe `
    -Path $RdpTcpPath `
    -Name "UserAuthentication"

$RdpPosture = [ordered]@{
    NLA = [ordered]@{
        required = ($NLAValue -eq 1)
        UserAuthentication = $NLAValue
        expected = 1
        status = if ($NLAValue -eq 1) {
            "Required"
        }
        else {
            "Not Required"
        }
    }

    allowed_group = "G_IT_Admins"

    remote_desktop_users_members = $RdpMembers

    idle_timeout_ms = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "MaxIdleTime"

    max_session_ms = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "MaxConnectionTime"

    min_encryption_level = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "MinEncryptionLevel"

    security_layer = Get-RegistryValueSafe `
        -Path $TerminalServicesPolicyPath `
        -Name "SecurityLayer"

    clipboard_redirection_disabled = (
        (Get-RegistryValueSafe `
            -Path $TerminalServicesPolicyPath `
            -Name "fDisableClip") -eq 1
    )

    drive_redirection_disabled = (
        (Get-RegistryValueSafe `
            -Path $TerminalServicesPolicyPath `
            -Name "fDisableCdm") -eq 1
    )

    remote_assistance_disabled = (
        (Get-RegistryValueSafe `
            -Path $TerminalServicesPolicyPath `
            -Name "fAllowToGetHelp") -eq 0
    )
}

Write-Host "    Exporting remote access posture... OK"

# ===========================================================================
# authentication_protocols
# ===========================================================================

Write-Step "Exporting authentication protocol posture..."

$ServiceAccounts = @(
    Get-ServiceAccounts
)

$KerberosAccounts = @()

foreach ($Account in $ServiceAccounts) {

    $EncryptionValue = `
        $Account.'msDS-SupportedEncryptionTypes'

    $Types = @(
        Convert-KerberosEncryptionTypes `
            -Value $EncryptionValue
    )

    $KerberosAccounts += [PSCustomObject]@{
        account                    = $Account.SamAccountName
        encryption_value           = $EncryptionValue
        encryption_types           = $Types
        DES_enabled                = (
            $Types -match "^DES"
        )
        RC4_enabled                = (
            $Types -contains "RC4"
        )
        AES128_enabled             = (
            $Types -contains "AES128"
        )
        AES256_enabled             = (
            $Types -contains "AES256"
        )
        UseDESKeyOnly              = [bool]$Account.UseDESKeyOnly
    }
}

$KerberosPolicyValue = Get-RegistryValueSafe `
    -Path $KerberosPolicyPath `
    -Name "SupportedEncryptionTypes"

$LmCompatibilityLevel = Get-RegistryValueSafe `
    -Path $LsaPath `
    -Name "LmCompatibilityLevel"

$SmbServer = Get-SmbServerConfiguration
$SmbClient = Get-SmbClientConfiguration

$AuthenticationProtocols = [ordered]@{
    kerberos_policy_value = $KerberosPolicyValue

    DES = [ordered]@{
        enabled_accounts = @(
            $KerberosAccounts |
            Where-Object {
                $_.DES_enabled -or
                $_.UseDESKeyOnly
            } |
            Select-Object -ExpandProperty account
        )
    }

    RC4 = [ordered]@{
        enabled_accounts = @(
            $KerberosAccounts |
            Where-Object {
                $_.RC4_enabled
            } |
            Select-Object -ExpandProperty account
        )
    }

    AES = [ordered]@{
        expected = "AES128 + AES256"
        accounts = $KerberosAccounts
    }

    NTLMv1 = [ordered]@{
        lm_compatibility_level = $LmCompatibilityLevel
        refused = (
            $LmCompatibilityLevel -eq 5
        )
    }

    SMBv1 = [ordered]@{
        enabled = [bool]$SmbServer.EnableSMB1Protocol
    }

    SMB_signing = [ordered]@{
        server_required = [bool]$SmbServer.RequireSecuritySignature
        client_required = [bool]$SmbClient.RequireSecuritySignature
    }

    SMB_encryption = [ordered]@{
        server_enabled = [bool]$SmbServer.EncryptData
    }
}

Write-Host `
    "    Exporting authentication protocol posture... OK"

# ===========================================================================
# service_account_posture
# ===========================================================================

Write-Step "Exporting service account posture..."

$DenyRights = Get-DenyLogonRights

$ServiceAccountPosture = @()

foreach ($Account in $ServiceAccounts) {

    $Groups = @(
        Get-GroupNames `
            -Account $Account
    )

    $PrivilegedMembership = @(
        $Groups |
        Where-Object {
            $UnauthorizedPrivilegedGroups -contains $_
        }
    )

    if ($null -eq $Account.PasswordLastSet) {

        $PasswordAgeDays = $null
    }
    else {

        $PasswordAgeDays = [int](
            (
                New-TimeSpan `
                    -Start $Account.PasswordLastSet `
                    -End (Get-Date)
            ).TotalDays
        )
    }

    $SidEntry = "*$($Account.SID.Value)"

    $InteractiveDenied = (
        @($DenyRights.interactive) -contains
        $SidEntry
    )

    $RemoteInteractiveDenied = (
        @($DenyRights.remote_interactive) -contains
        $SidEntry
    )

    $ServiceAccountPosture += [PSCustomObject]@{
        account_name = $Account.SamAccountName
        enabled = [bool]$Account.Enabled

        password_last_set = $Account.PasswordLastSet
        password_age_days = $PasswordAgeDays
        password_never_expires = [bool]$Account.PasswordNeverExpires

        last_logon = $Account.LastLogonDate

        delegation = [ordered]@{
            TrustedForDelegation = [bool]$Account.TrustedForDelegation
            AccountNotDelegated  = [bool]$Account.AccountNotDelegated
        }

        spns = @(
            $Account.ServicePrincipalName
        )

        group_memberships = $Groups

        privileged_membership = $PrivilegedMembership

        interactive_logon = [ordered]@{
            denied_local = $InteractiveDenied
            denied_remote_rdp = $RemoteInteractiveDenied
            risk = if (
                $InteractiveDenied -and
                $RemoteInteractiveDenied
            ) {
                "restricted"
            }
            else {
                "interactive_logon_risk"
            }
        }
    }
}

Write-Host `
    "    Exporting service account posture... $($ServiceAccountPosture.Count) accounts"

# ===========================================================================
# validation_summary
# ===========================================================================

Write-Step "Loading validation summary..."

$ValidationSummary = [ordered]@{
    status = "not_found"
    source_file = $null
    results = $null
}

foreach ($Candidate in $ValidationCandidates) {

    if (Test-Path $Candidate) {

        try {

            $ValidationData = Get-Content `
                -Path $Candidate `
                -Raw |
                ConvertFrom-Json

            $ValidationSummary.status = "found"
            $ValidationSummary.source_file = $Candidate
            $ValidationSummary.results = $ValidationData

            break
        }
        catch {

            $ValidationSummary.status = "parse_error"
            $ValidationSummary.source_file = $Candidate
            $ValidationSummary.results = $null

            break
        }
    }
}

if ($ValidationSummary.status -eq "found") {

    Write-Host "    Loading validation summary... OK"
}
else {

    Write-Host `
        "    Loading validation summary... $($ValidationSummary.status)"
}

# ===========================================================================
# Assemble final evidence bundle
# ===========================================================================

$HardenedState = [ordered]@{
    domain_metadata           = $DomainMetadata
    gpo_inventory             = $GpoInventory
    audit_policy              = $AuditPolicy
    powershell_logging        = $PowerShellLogging
    sysmon_posture            = $SysmonPosture
    firewall_posture          = $FirewallPosture
    applocker_posture         = $AppLockerPosture
    rdp_posture               = $RdpPosture
    authentication_protocols  = $AuthenticationProtocols
    service_account_posture   = $ServiceAccountPosture
    validation_summary        = $ValidationSummary
}

# ===========================================================================
# Write JSON
# ===========================================================================

$HardenedState |
    ConvertTo-Json `
        -Depth 15 |
    Set-Content `
        -Path $OutputFile `
        -Encoding UTF8

if (-not (Test-Path $OutputFile)) {

    throw "windows_hardened_state.json was not created."
}

# Verify valid JSON.
try {

    $null = Get-Content `
        -Path $OutputFile `
        -Raw |
        ConvertFrom-Json
}
catch {

    throw "windows_hardened_state.json is not valid JSON."
}

# ===========================================================================
# Final output
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Hardened State Export Complete"
Write-Host "=============================================="
Write-Host ""

Write-Host `
    "Hardened state exported to: windows_hardened_state.json"

Write-Host ""
Write-Host "Full path:"
Write-Host $OutputFile

exit 0