# File: 6-windows_firewall.ps1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RulesFile = (Join-Path -Path $PSScriptRoot -ChildPath 'segmentation_rules.json'),

    [Parameter()]
    [ValidateSet('DMZ', 'INTERNAL', 'MGMT', 'MEDDEV')]
    [string]$LocalZone = 'INTERNAL',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile = (Join-Path -Path $PSScriptRoot -ChildPath 'windows_firewall_rules.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PrechangeFile = (Join-Path -Path $PSScriptRoot -ChildPath 'windows_firewall_prechange.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rulePrefix = 'MedDefense-'
$logFile = '%systemroot%\system32\LogFiles\Firewall\meddefense.log'
$profiles = @('Domain', 'Private', 'Public')
$computerName = [System.Environment]::MachineName
$isSimulation = [bool]$WhatIfPreference

if (-not (Get-Module -ListAvailable -Name NetSecurity)) {
    throw 'The NetSecurity module is required. Run this script on Windows 10/11 or Windows Server.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$administratorRole = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $principal.IsInRole($administratorRole)) {
    throw 'Run PowerShell as Administrator before executing this script.'
}

if (-not (Test-Path -LiteralPath $RulesFile -PathType Leaf)) {
    throw "Rules file not found: $RulesFile"
}

Write-Information '[*] Reading segmentation_rules.json...' -InformationAction Continue
$contract = Get-Content -LiteralPath $RulesFile -Raw | ConvertFrom-Json

if ($null -eq $contract.zones -or $null -eq $contract.flows) {
    throw 'The rules file must contain top-level zones and flows arrays.'
}

$zoneNames = @($contract.zones | ForEach-Object { [string]$_.name })
if ($LocalZone -notin $zoneNames) {
    throw "Local zone '$LocalZone' does not exist in $RulesFile."
}

$prechangeRules = @(
    Get-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue |
        Select-Object -Property DisplayName, Enabled, Direction, Action, Profile
)
$prechangeProfiles = @(
    Get-NetFirewallProfile |
        Select-Object -Property Name, Enabled, DefaultInboundAction,
        DefaultOutboundAction, LogBlocked, LogFileName
)

$prechangeState = [ordered]@{
    captured_at = (Get-Date).ToUniversalTime().ToString('o')
    hostname = $computerName
    local_zone = $LocalZone
    profiles = $prechangeProfiles
    meddefense_rules = $prechangeRules
}
$prechangeState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $PrechangeFile -Encoding utf8

Write-Information '[*] Setting profile defaults...' -InformationAction Continue
foreach ($profile in $profiles) {
    if ($PSCmdlet.ShouldProcess(
            "Windows Firewall profile $profile",
            'Set inbound Block, outbound Allow and enable blocked-packet logging')) {
        Set-NetFirewallProfile -Profile $profile `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -LogBlocked True `
            -LogFileName $logFile
    }

    $status = if ($isSimulation) { 'PLANNED' } else { 'SET' }
    Write-Information (
        '  {0}: DefaultInboundAction=Block LogBlocked=True [{1}]' -f $profile, $status
    ) -InformationAction Continue
}

Write-Information '[*] Clearing previous MedDefense-* rules...' -InformationAction Continue
if ($prechangeRules.Count -gt 0 -and $PSCmdlet.ShouldProcess(
        "$($prechangeRules.Count) MedDefense firewall rules",
        'Remove before rebuilding')) {
    Get-NetFirewallRule -DisplayName "$rulePrefix*" | Remove-NetFirewallRule
}
$removeStatus = if ($isSimulation) { 'would remove' } else { 'removed' }
Write-Information "  [$($prechangeRules.Count) $removeStatus]" -InformationAction Continue

$allowedInboundFlows = @(
    $contract.flows | Where-Object {
        [string]$_.action -eq 'allow' -and [string]$_.dst_zone -eq $LocalZone
    }
)

$exportedRules = [System.Collections.Generic.List[object]]::new()
$seenDisplayNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

Write-Information '[*] Creating rules from flow matrix...' -InformationAction Continue
foreach ($flow in $allowedInboundFlows) {
    $sourceZone = ([string]$flow.src_zone).ToUpperInvariant()
    $protocol = ([string]$flow.proto).ToUpperInvariant()
    $localPort = [int]$flow.dport
    $displayName = '{0}{1}-{2}-{3}' -f $rulePrefix, $sourceZone, $protocol, $localPort

    if (-not $seenDisplayNames.Add($displayName)) {
        Write-Warning "Duplicate rule name skipped: $displayName"
        continue
    }

    $remoteAddresses = @()
    if ($sourceZone -eq 'ALL') {
        $remoteAddresses = @('Any')
    }
    elseif ($flow.PSObject.Properties.Name -contains 'src_hosts' -and $null -ne $flow.src_hosts) {
        $remoteAddresses = @(
            $flow.src_hosts | ForEach-Object { [string]$_.ip } | Where-Object { $_ -ne '' }
        )
    }

    if ($remoteAddresses.Count -eq 0) {
        $sourceZoneDefinition = $contract.zones |
            Where-Object { [string]$_.name -eq $sourceZone } |
            Select-Object -First 1
        if ($null -eq $sourceZoneDefinition) {
            throw "Source zone '$sourceZone' has no CIDR definition."
        }
        $remoteAddresses = @([string]$sourceZoneDefinition.cidr)
    }

    if ($PSCmdlet.ShouldProcess(
            $displayName,
            "Create inbound allow rule from $($remoteAddresses -join ', ')")) {
        New-NetFirewallRule -DisplayName $displayName `
            -Direction Inbound `
            -Action Allow `
            -Protocol $protocol `
            -LocalPort $localPort `
            -RemoteAddress $remoteAddresses `
            -Profile Any | Out-Null
    }

    $exportedRules.Add([pscustomobject][ordered]@{
            display_name = $displayName
            direction = 'Inbound'
            action = 'Allow'
            protocol = $protocol.ToLowerInvariant()
            local_port = $localPort
            remote_address = $remoteAddresses
            profile = 'Any'
            src_zone = $sourceZone
            dst_zone = $LocalZone
            justification = [string]$flow.justification
            status = if ($isSimulation) { 'planned' } else { 'created' }
        })

    $createStatus = if ($isSimulation) { 'PLANNED' } else { 'CREATED' }
    Write-Information (
        '  {0,-35} Inbound Allow {1} {2} [{3}]' -f `
            $displayName, $protocol.ToLowerInvariant(), $localPort, $createStatus
    ) -InformationAction Continue
}

$desiredProfiles = @(
    foreach ($profile in $profiles) {
        [pscustomobject][ordered]@{
            name = $profile
            default_inbound_action = 'Block'
            default_outbound_action = 'Allow'
            log_blocked = $true
            log_file_name = $logFile
        }
    }
)

$result = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    hostname = $computerName
    source_file = (Resolve-Path -LiteralPath $RulesFile).Path
    local_zone = $LocalZone
    mode = if ($isSimulation) { 'simulation' } else { 'applied' }
    profiles = $desiredProfiles
    rules = $exportedRules
    summary = [ordered]@{
        profile_count = $desiredProfiles.Count
        rule_count = $exportedRules.Count
        previous_meddefense_rules = $prechangeRules.Count
    }
}
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputFile -Encoding utf8

Write-Information "[*] Evidence written to $OutputFile" -InformationAction Continue
Write-Information "[*] Pre-change state written to $PrechangeFile" -InformationAction Continue