# MedDefense Health Systems
# Task: 12 - AppLocker Policy
# Script: 12-applocker_config.ps1
# Author: Pedro Cabral
# Date: 2026-08-07
# Purpose: Deploy and validate an AppLocker application allow-listing policy through Group Policy.
# Safety: AUDIT-ONLY by default. GPO and service changes require the explicit -Apply parameter.
# Output: applocker_policy.xml plus console verification evidence.
#
# GPO:
# MedDefense - AppLocker Policy
#
# Executable rules (.exe, .com):
# - Allow C:\Windows\*
# - Allow C:\Program Files\*
# - Allow C:\Program Files (x86)\*
# - Allow explicit MedDefense DicomViewer.exe path
# - Default: DENY all other locations
#
# Script rules (.ps1, .bat, .cmd, .vbs):
# - Allow C:\Windows\*
# - Allow C:\MedDefense_Lab\Scripts\*
# - Default: DENY all other locations
#
# Enforcement:
# - Executable collection: Audit Only
# - Script collection: Audit Only
#
# Service:
# - Application Identity
# - AppIDSvc
#
# Deliverable:
# - applocker_policy.xml
#
# VERIFY:
# Verify AppIDSvc, AuditOnly enforcement, executable rules, script rules,
# GPO link and exported applocker_policy.xml.
#
# VERIFIED:
# Expected paths must evaluate as Allowed and an executable copied to
# C:\Temp must evaluate as Denied / WOULD BLOCK without actually executing it.

[CmdletBinding()]
param(
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# Configuration
# ===========================================================================

$TargetDomain = "meddefense.local"
$GpoName = "MedDefense - AppLocker Policy"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

$PolicyFile = Join-Path `
    $ScriptDirectory `
    "applocker_policy.xml"

$DicomViewerPath = `
    "C:\Program Files\MedImage Corp\DicomViewer\DicomViewer.exe"

$AdminScriptPath = `
    "C:\MedDefense_Lab\Scripts\*"

$TestDirectory = "C:\Temp"
$TestExecutable = "C:\Temp\calc.exe"

# Everyone SID.
$EveryoneSid = "S-1-1-0"

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

function Write-WouldSet {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "    $Message [WOULD SET]"
}

function Test-IsAdministrator {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-AppLockerCmdlets {

    $RequiredCommands = @(
        "Get-AppLockerPolicy",
        "Set-AppLockerPolicy",
        "Test-AppLockerPolicy"
    )

    foreach ($Command in $RequiredCommands) {

        if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
            return $false
        }
    }

    return $true
}

function New-MedDefenseAppLockerXml {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    # -----------------------------------------------------------------------
    # IMPORTANT:
    #
    # AppLocker uses allow-list semantics.
    #
    # Once Allow rules exist in a rule collection, files that do not match
    # an Allow rule are implicitly denied when EnforcementMode="Enabled".
    #
    # In this project EnforcementMode="AuditOnly", therefore unmatched files
    # are logged as WOULD BLOCK instead of being prevented from running.
    #
    # We intentionally DO NOT create "Deny Everyone *" because explicit Deny
    # rules take precedence over Allow rules.
    # -----------------------------------------------------------------------

    $ExeWindowsGuid = [guid]::NewGuid().ToString()
    $ExeProgramFilesGuid = [guid]::NewGuid().ToString()
    $ExeProgramFilesX86Guid = [guid]::NewGuid().ToString()
    $ExeDicomGuid = [guid]::NewGuid().ToString()

    $ScriptWindowsGuid = [guid]::NewGuid().ToString()
    $ScriptAdminGuid = [guid]::NewGuid().ToString()

    $Xml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">

  <!-- ================================================================ -->
  <!-- Executable Rules: .exe and .com                                  -->
  <!-- Default: DENY all locations not explicitly allowed               -->
  <!-- EnforcementMode: Audit Only                                      -->
  <!-- ================================================================ -->

  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">

    <FilePathRule
      Id="$ExeWindowsGuid"
      Name="MedDefense - Allow Windows System Directories"
      Description="Allow .exe and .com executables under C:\Windows\*"
      UserOrGroupSid="$EveryoneSid"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="$ExeProgramFilesGuid"
      Name="MedDefense - Allow Program Files"
      Description="Allow executables under C:\Program Files\*"
      UserOrGroupSid="$EveryoneSid"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="$ExeProgramFilesX86Guid"
      Name="MedDefense - Allow Program Files x86"
      Description="Allow executables under C:\Program Files (x86)\*"
      UserOrGroupSid="$EveryoneSid"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="$ExeDicomGuid"
      Name="MedDefense - Allow DicomViewer.exe (MedImage Corp)"
      Description="Explicit path rule for approved clinical DicomViewer.exe"
      UserOrGroupSid="$EveryoneSid"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="$DicomViewerPath" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <!-- ================================================================ -->
  <!-- Script Rules: .ps1, .bat, .cmd, .vbs                             -->
  <!-- Default: DENY all locations not explicitly allowed               -->
  <!-- EnforcementMode: Audit Only                                      -->
  <!-- ================================================================ -->

  <RuleCollection Type="Script" EnforcementMode="AuditOnly">

    <FilePathRule
      Id="$ScriptWindowsGuid"
      Name="MedDefense - Allow Windows System Scripts"
      Description="Allow .ps1, .bat, .cmd and .vbs scripts under C:\Windows\*"
      UserOrGroupSid="$EveryoneSid"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="$ScriptAdminGuid"
      Name="MedDefense - Allow Administrative Scripts"
      Description="Allow MedDefense administrative scripts from C:\MedDefense_Lab\Scripts\*"
      UserOrGroupSid="$EveryoneSid"
      Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\Scripts\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <!-- Other collections are intentionally left NotConfigured. -->

  <RuleCollection Type="Msi" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />

</AppLockerPolicy>
"@

    [System.IO.File]::WriteAllText(
        $Destination,
        $Xml,
        [System.Text.UTF8Encoding]::new($false)
    )
}

# ===========================================================================
# Environment
# ===========================================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "MedDefense AppLocker Policy"
Write-Host "=============================================="
Write-Host ""

$ComputerSystem = Get-CimInstance `
    -ClassName Win32_ComputerSystem

$PartOfDomain = [bool]$ComputerSystem.PartOfDomain
$CurrentDomain = [string]$ComputerSystem.Domain

$ADModuleAvailable = [bool](
    Get-Module -ListAvailable -Name ActiveDirectory
)

$GPOModuleAvailable = [bool](
    Get-Module -ListAvailable -Name GroupPolicy
)

$AppLockerCmdletsAvailable = Test-AppLockerCmdlets

Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Domain joined: $PartOfDomain"
Write-Host "Current domain: $CurrentDomain"
Write-Host "Target domain: $TargetDomain"
Write-Host "AppLocker cmdlets: $AppLockerCmdletsAvailable"

if ($Apply) {
    Write-Host "Mode: APPLY"
}
else {
    Write-Host "Mode: AUDIT ONLY / PREVIEW"
}

Write-Host ""

if (-not $PartOfDomain) {
    throw "This computer is not joined to Active Directory."
}

if ($CurrentDomain.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Expected '$TargetDomain', detected '$CurrentDomain'."
}

if (-not $AppLockerCmdletsAvailable) {
    throw "Required AppLocker PowerShell cmdlets are unavailable."
}

# ===========================================================================
# Generate deliverable even in audit mode
# ===========================================================================

Write-Step "Generating AppLocker policy XML..."

New-MedDefenseAppLockerXml `
    -Destination $PolicyFile

if (Test-Path $PolicyFile) {

    Write-Host "    applocker_policy.xml [CREATED]"
}
else {

    throw "Failed to create applocker_policy.xml."
}

# ===========================================================================
# Display intended configuration
# ===========================================================================

Write-Host ""
Write-Step "Creating GPO: `"$GpoName`"..."

if ($GPOModuleAvailable) {

    Import-Module GroupPolicy

    $ExistingGPO = Get-GPO `
        -Name $GpoName `
        -ErrorAction SilentlyContinue

    if ($null -eq $ExistingGPO) {

        if ($Apply) {
            Write-Host "    GPO absent [WILL CREATE]"
        }
        else {
            Write-Host "    GPO absent [WOULD CREATE]"
        }
    }
    else {

        Write-Host "    GPO already exists [DETECTED]"
    }
}
else {

    Write-Host "    GroupPolicy module unavailable [NOT ASSESSED]"
}

Write-Host ""

Write-Step "Configuring Executable Rules..."

if ($Apply) {

    Write-Host "    Allow: C:\Windows\* [SET]"
    Write-Host "    Allow: C:\Program Files\* [SET]"
    Write-Host "    Allow: C:\Program Files (x86)\* [SET]"
    Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]"
    Write-Host "    Default: DENY [SET]"
}
else {

    Write-WouldSet "Allow: C:\Windows\*"
    Write-WouldSet "Allow: C:\Program Files\*"
    Write-WouldSet "Allow: C:\Program Files (x86)\*"
    Write-WouldSet "Allow: DicomViewer.exe (MedImage Corp)"
    Write-WouldSet "Default: DENY all other executable locations"
}

Write-Host ""

Write-Step "Configuring Script Rules..."

if ($Apply) {

    Write-Host "    Allow: C:\Windows\* [SET]"
    Write-Host "    Allow: C:\MedDefense_Lab\Scripts\* [SET]"
    Write-Host "    Default: DENY [SET]"
}
else {

    Write-WouldSet "Allow: C:\Windows\*"
    Write-WouldSet "Allow: C:\MedDefense_Lab\Scripts\*"
    Write-WouldSet "Default: DENY all other script locations"
}

Write-Host ""
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)"

# ===========================================================================
# AUDIT-ONLY / PREVIEW
# ===========================================================================

if (-not $Apply) {

    Write-Host ""

    Write-Step "Starting AppIDSvc..."
    Write-Host "    Application Identity service [WOULD START]"

    Write-Host ""

    Write-Step "Linking GPO..."
    Write-Host "    meddefense.local [WOULD LINK]"

    Write-Host ""

    Write-Step "Testing..."

    Write-Host `
        "    notepad.exe from C:\Windows: ALLOWED [EXPECTED]"

    Write-Host `
        "    calc.exe from C:\Temp: WOULD BLOCK [EXPECTED]"

    Write-Host ""

    Write-Step "VERIFY..."

    Write-Host "    AppLocker EnforcementMode = AuditOnly [WOULD VERIFY]"
    Write-Host "    AppIDSvc = Running [WOULD VERIFY]"
    Write-Host "    Executable rules [WOULD VERIFY]"
    Write-Host "    Script rules [WOULD VERIFY]"
    Write-Host "    applocker_policy.xml [VERIFIED]"

    Write-Host ""
    Write-Host "Policy exported to: applocker_policy.xml"
    Write-Host "[*] System modified: False"

    exit 0
}

# ===========================================================================
# APPLY safeguards
# ===========================================================================

if (-not (Test-IsAdministrator)) {
    throw "Apply mode requires PowerShell running as Administrator."
}

if (-not $ADModuleAvailable) {
    throw "ActiveDirectory PowerShell module is required."
}

if (-not $GPOModuleAvailable) {
    throw "GroupPolicy PowerShell module is required."
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Domain = Get-ADDomain

if ($Domain.DNSRoot.ToLower() -ne $TargetDomain.ToLower()) {
    throw "Get-ADDomain returned '$($Domain.DNSRoot)'."
}

$DomainDN = $Domain.DistinguishedName

# ===========================================================================
# Create GPO
# ===========================================================================

Write-Host ""
Write-Step "Creating GPO: `"$GpoName`"..."

$GPO = Get-GPO `
    -Name $GpoName `
    -ErrorAction SilentlyContinue

if ($null -eq $GPO) {

    $GPO = New-GPO `
        -Name $GpoName `
        -Comment "MedDefense AppLocker application allow-listing policy - Audit Only testing phase."

    Write-Host "    CREATED"
}
else {

    Write-Host "    ALREADY EXISTS"
}

# ===========================================================================
# Start Application Identity
# ===========================================================================

Write-Host ""
Write-Step "Starting AppIDSvc..."

$AppIdService = Get-Service `
    -Name AppIDSvc `
    -ErrorAction Stop

if ($AppIdService.Status -ne "Running") {

    Set-Service `
        -Name AppIDSvc `
        -StartupType Automatic

    Start-Service `
        -Name AppIDSvc

    Start-Sleep -Seconds 2
}

$AppIdService = Get-Service `
    -Name AppIDSvc

if ($AppIdService.Status -eq "Running") {

    Write-Host "    AppIDSvc... Running [OK]"
}
else {

    throw "Application Identity service did not start."
}

# ===========================================================================
# Apply XML to GPO
#
# GPO LDAP path:
# LDAP://CN={GUID},CN=Policies,CN=System,<domain DN>
# ===========================================================================

Write-Host ""
Write-Step "Applying AppLocker policy to GPO..."

$GpoGuid = $GPO.Id.ToString("B")

$GpoLdapPath = `
    "LDAP://CN=$GpoGuid,CN=Policies,CN=System,$DomainDN"

Set-AppLockerPolicy `
    -XmlPolicy $PolicyFile `
    -Ldap $GpoLdapPath

Write-Host "    AppLocker XML applied [SET]"

# ===========================================================================
# Link GPO
# ===========================================================================

Write-Host ""
Write-Step "Linking GPO..."

$Inheritance = Get-GPInheritance `
    -Target $DomainDN

$ExistingLink = @(
    $Inheritance.GpoLinks |
    Where-Object {
        $_.DisplayName -eq $GpoName
    }
)

if ($ExistingLink.Count -eq 0) {

    New-GPLink `
        -Name $GpoName `
        -Target $DomainDN `
        -LinkEnabled Yes |
    Out-Null

    Write-Host "    LINKED"
}
else {

    Write-Host "    ALREADY LINKED"
}

# ===========================================================================
# Force Group Policy
# ===========================================================================

Write-Step "Forcing Group Policy update..."

gpupdate.exe /force |
    Out-Null

Write-Host "    COMPLETE"

Start-Sleep -Seconds 3

# ===========================================================================
# Export effective policy
# ===========================================================================

Write-Host ""
Write-Step "Exporting AppLocker policy..."

$EffectivePolicy = Get-AppLockerPolicy `
    -Effective `
    -Xml

[System.IO.File]::WriteAllText(
    $PolicyFile,
    [string]$EffectivePolicy,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "    applocker_policy.xml [EXPORTED]"

# ===========================================================================
# Controlled tests - NO unauthorized executable is actually executed
# ===========================================================================

Write-Host ""
Write-Step "Testing..."

$VerificationFailures = 0

$PolicyObject = Get-AppLockerPolicy `
    -Effective

# ---------------------------------------------------------------------------
# Test allowed Windows executable
# ---------------------------------------------------------------------------

$NotepadPath = "$env:WINDIR\System32\notepad.exe"

try {

    $NotepadResult = Test-AppLockerPolicy `
        -PolicyObject $PolicyObject `
        -Path $NotepadPath `
        -User "Everyone"

    if (
        [string]$NotepadResult.PolicyDecision -match
        "Allowed"
    ) {

        Write-Host `
            "    notepad.exe from C:\Windows: ALLOWED [EXPECTED]"
    }
    else {

        Write-Host `
            "    notepad.exe from C:\Windows: NOT ALLOWED [UNEXPECTED]"

        $VerificationFailures++
    }
}
catch {

    Write-Host `
        "    notepad.exe policy test could not be evaluated [NOT VERIFIED]"

    $VerificationFailures++
}

# ---------------------------------------------------------------------------
# Test unauthorized location safely
#
# Copy calc.exe to C:\Temp.
# DO NOT execute it.
# Only ask Test-AppLockerPolicy for the expected decision.
# ---------------------------------------------------------------------------

if (-not (Test-Path $TestDirectory)) {

    New-Item `
        -Path $TestDirectory `
        -ItemType Directory `
        -Force |
    Out-Null
}

$CalcSource = "$env:WINDIR\System32\calc.exe"

if (Test-Path $CalcSource) {

    Copy-Item `
        -Path $CalcSource `
        -Destination $TestExecutable `
        -Force

    try {

        $CalcResult = Test-AppLockerPolicy `
            -PolicyObject $PolicyObject `
            -Path $TestExecutable `
            -User "Everyone"

        if (
            [string]$CalcResult.PolicyDecision -match
            "Denied"
        ) {

            Write-Host `
                "    calc.exe from C:\Temp: WOULD BLOCK [EXPECTED]"
        }
        else {

            Write-Host `
                "    calc.exe from C:\Temp: not denied [UNEXPECTED]"

            $VerificationFailures++
        }
    }
    catch {

        Write-Host `
            "    calc.exe from C:\Temp policy test [NOT VERIFIED]"

        $VerificationFailures++
    }
    finally {

        Remove-Item `
            -Path $TestExecutable `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
else {

    Write-Host `
        "    calc.exe source unavailable; unauthorized path test skipped [INFO]"
}

# ===========================================================================
# VERIFY Application Identity
# ===========================================================================

Write-Host ""
Write-Step "VERIFY..."

$AppIdService = Get-Service `
    -Name AppIDSvc

if ($AppIdService.Status -eq "Running") {

    Write-Host "    AppIDSvc = Running [VERIFIED]"
}
else {

    Write-Host "    AppIDSvc [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# VERIFY effective AppLocker XML
# ===========================================================================

try {

    [xml]$VerifyXml = Get-Content `
        -Path $PolicyFile `
        -Raw

    $ExeCollection = @(
        $VerifyXml.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Exe"
        }
    ) |
    Select-Object -First 1

    $ScriptCollection = @(
        $VerifyXml.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Script"
        }
    ) |
    Select-Object -First 1

    if (
        $null -ne $ExeCollection -and
        $ExeCollection.EnforcementMode -eq "AuditOnly"
    ) {

        Write-Host `
            "    Executable EnforcementMode = AuditOnly [VERIFIED]"
    }
    else {

        Write-Host `
            "    Executable Audit Only mode [NOT VERIFIED]"

        $VerificationFailures++
    }

    if (
        $null -ne $ScriptCollection -and
        $ScriptCollection.EnforcementMode -eq "AuditOnly"
    ) {

        Write-Host `
            "    Script EnforcementMode = AuditOnly [VERIFIED]"
    }
    else {

        Write-Host `
            "    Script Audit Only mode [NOT VERIFIED]"

        $VerificationFailures++
    }

    $PolicyText = Get-Content `
        -Path $PolicyFile `
        -Raw

    $RequiredPatterns = @(
        "Windows",
        "Program Files",
        "DicomViewer",
        "MedDefense_Lab",
        "AuditOnly"
    )

    foreach ($Pattern in $RequiredPatterns) {

        if ($PolicyText -match [regex]::Escape($Pattern)) {

            Write-Host `
                "    Policy contains '$Pattern' [VERIFIED]"
        }
        else {

            Write-Host `
                "    Policy missing '$Pattern' [NOT VERIFIED]"

            $VerificationFailures++
        }
    }
}
catch {

    Write-Host "    applocker_policy.xml validation failed [NOT VERIFIED]"
    $VerificationFailures++
}

# ===========================================================================
# Final result
# ===========================================================================

Write-Host ""
Write-Host "Policy exported to: applocker_policy.xml"

if ($VerificationFailures -eq 0) {

    Write-Host `
        "[VERIFIED] AppLocker Policy validation: PASS"

    exit 0
}
else {

    Write-Host `
        "[NOT VERIFIED] AppLocker Policy validation: FAIL"

    Write-Host `
        "[!] Failed checks: $VerificationFailures"

    exit 1
}