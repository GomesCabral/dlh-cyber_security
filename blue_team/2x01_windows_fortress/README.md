# 2x01 - Windows Fortress

## MedDefense Health Systems

This project builds a Windows security hardening and validation workflow
focused on Active Directory, Group Policy, Windows telemetry, endpoint
security and continuous compliance validation.

The original MedDefense environment uses Windows Server 2022 Domain
Controllers and Windows endpoints. The current laboratory workstation may
not have access to the MedDefense Active Directory environment.

For that reason, all scripts must distinguish between:

- controls that can be safely assessed on a standalone Windows workstation;
- controls that require Active Directory;
- controls that would modify the operating system.

No Active Directory evidence is fabricated when a domain is unavailable.

---

## Safety Policy

The current laboratory host may be a personal Windows workstation.

Scripts therefore follow a safety-first methodology.

### Read-only operations

Commands used for discovery and validation may be executed when they do not
change system state.

Examples include:

```powershell
Get-CimInstance
Get-LocalUser
Get-LocalGroup
Get-ADUser
Get-ADGroup
Get-ADDomain
Get-GPO
Get-WinEvent
```

### Configuration changes

Security configuration changes must not be applied blindly to a personal
workstation.

Potentially disruptive operations involving the following technologies
must first be reviewed or implemented in an audit/simulation mode:

- Active Directory
- Group Policy
- Windows Firewall
- AppLocker
- Windows Defender
- Sysmon
- PowerShell logging
- Windows auditing
- SMB
- Kerberos
- Registry security settings
- Windows services
- password and account lockout policies

Domain-specific controls are reported as `NOT ASSESSED` when Active
Directory is unavailable.

---

# Task 0 - Domain Reconnaissance

## Script

`0-domain_baseline.ps1`

## Output

`domain_baseline.json`

## Goal

Capture the complete Windows and Active Directory security baseline before
any hardening actions are performed.

This task establishes the Windows equivalent of the initial Linux security
baseline from the previous MedDefense project.

A security engineer must understand the existing environment before
deciding what should be changed.

---

## Information Collected

When Active Directory is available, the script collects:

- domain name;
- domain and forest functional levels;
- Domain Controllers;
- all domain user accounts;
- enabled and disabled account state;
- last logon;
- password last-set information;
- Password Never Expires configuration;
- all Active Directory groups;
- group membership;
- service accounts;
- Service Principal Names;
- unconstrained delegation;
- Group Policy Objects;
- GPO links to the domain and Organizational Units;
- domain password policy;
- account lockout policy;
- observed Kerberos encryption configuration;
- Domain Admin membership;
- Enterprise Admin membership;
- security findings.

---

## Standalone Windows Mode

When the computer is not joined to Active Directory, the script does not
attempt to simulate or fabricate MedDefense domain information.

Instead, it collects the safe local identity baseline:

- computer identity;
- operating system;
- local users;
- local groups;
- local group membership;
- service-account-like local identities.

Domain-specific evidence is recorded as:

```text
NOT ASSESSED
```

For example:

```json
{
  "status": "NOT ASSESSED",
  "reason": "Computer is not joined to an Active Directory domain."
}
```

---

## Security Findings

The Active Directory assessment can identify issues including:

- accounts with passwords that never expire;
- weak minimum password length;
- disabled password complexity;
- missing account lockout;
- unconstrained Kerberos delegation;
- excessive Domain Admin membership;
- RC4 Kerberos support;
- unavailable GPO visibility.

Findings are classified as:

```text
critical
high
medium
```

---

## Safety

`0-domain_baseline.ps1` is a read-only reconnaissance script.

It does not:

- create users;
- delete users;
- change passwords;
- modify Active Directory;
- modify Group Policy;
- alter Windows Firewall;
- modify Registry settings;
- stop or restart services;
- change audit policies;
- change Kerberos configuration.

The JSON output records:

```json
{
  "mode": "READ_ONLY",
  "modified_system": false
}
```

---

## Usage

From PowerShell:

```powershell
.\0-domain_baseline.ps1
```

If script execution is blocked by the local PowerShell execution policy,
the script can be executed in a temporary PowerShell process:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\0-domain_baseline.ps1
```

This does not permanently modify the workstation execution policy.

---

## Validate the Output

Load the generated JSON:

```powershell
$Report = Get-Content .\domain_baseline.json -Raw |
    ConvertFrom-Json
```

Display the security summary:

```powershell
$Report.summary
```

Display detected findings:

```powershell
$Report.findings |
    Format-Table severity,title -AutoSize
```

Display system identity:

```powershell
$Report.system_identity
```

---

## Expected Active Directory Example

A MedDefense Domain Controller could produce output similar to:

```text
Domain: meddefense.local
DC: DC01.meddefense.local
User Accounts: 14
  Password Never Expires: 6
Service Accounts: 3
  Unconstrained delegation: 3
GPOs: 2
Password Minimum Length: 7
Complexity: False
Lockout Threshold: 0
Kerberos: RC4, AES128, AES256
Domain Admins: Administrator, analyst
Findings: 9
```

These values are examples only and must not be used as evidence when the
MedDefense domain is unavailable.

---

## Expected Standalone Workstation Example

```text
Environment: Standalone Windows
Computer: DESKTOP-XXXX
Domain: NOT ASSESSED
Active Directory: NOT AVAILABLE
Local User Accounts: <detected>
Local Groups: <detected>
Domain Password Policy: NOT ASSESSED
Kerberos: NOT ASSESSED
```

---

## Security Lesson

The main principle of this task is:

> Baseline first. Harden second.

A SOC analyst or security engineer needs to understand the expected
identity and privilege structure before identifying suspicious changes.

For example, if the normal Domain Admin membership is:

```text
Administrator
analyst
```

and a later Windows event shows:

```text
john added to Domain Admins
```

the baseline provides the context needed to recognize the change as
potential privilege escalation or persistence.

The same concept applies to:

- new service accounts;
- unusual group membership;
- GPO modifications;
- password-policy changes;
- Kerberos configuration changes;
- newly privileged identities.

The baseline therefore becomes reference evidence for future Windows
telemetry, SIEM detections and incident investigations.

---

# Task 1 - Domain Risk Findings Extractor

## Script

`1-domain_findings.ps1`

## Output

`domain_security_findings.json`

## Goal

Transform the Windows and Active Directory baseline into an actionable
security findings inventory.

Each finding explains:

- what was detected;
- why it represents risk;
- what should remediate it;
- which later project task owns the remediation.

## Required Finding Fields

Every finding contains:

```text
id
severity
category
asset
evidence
risk
recommended_remediation
mapped_task
```

## Security Areas Assessed

When Active Directory is available:

- PasswordNeverExpires accounts
- privileged group membership
- stale computer objects
- password policy
- account lockout
- Kerberos encryption
- service accounts
- unconstrained delegation
- DES-only Kerberos configuration
- stale service-account passwords
- Advanced Audit Policy
- PowerShell Script Block Logging
- Sysmon readiness
- Group Policy security posture

## Windows Fortress Target State

The findings assessment compares domain policy against:

```text
Minimum password length: 14
Password complexity: enabled
Password history: 24
Account lockout threshold: 5
```

## Standalone Windows Mode

When `meddefense.local` is unavailable, the script does not fabricate
Active Directory evidence.

Domain-specific checks are recorded as:

```text
NOT_ASSESSED
```

The script can still safely inspect local telemetry readiness including:

- Advanced Audit Policy visibility
- PowerShell Script Block Logging
- Sysmon presence

## Safety

The script is read-only.

It does not:

- modify accounts;
- change passwords;
- modify Group Policy;
- modify Windows audit policy;
- install Sysmon;
- enable PowerShell logging;
- change Registry values;
- change Kerberos;
- modify Active Directory.

## Usage

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\1-domain_findings.ps1
```

## Validate Output

```powershell
$Report = Get-Content .\domain_security_findings.json -Raw |
    ConvertFrom-Json

$Report.summary
```

Display findings:

```powershell
$Report.findings |
    Format-Table id,severity,category,asset -AutoSize
```

## Security Lesson

Task 0 establishes the baseline.

Task 1 converts baseline evidence into prioritized security findings:

```text
Observed state
    ↓
Security weakness
    ↓
Severity
    ↓
Risk
    ↓
Recommended remediation
    ↓
Mapped hardening task
```

This is the bridge between security assessment and remediation.

For a SOC analyst, the task also introduces telemetry readiness. Windows
security controls such as Advanced Audit Policy, PowerShell Script Block
Logging and Sysmon determine which events will later be available to a SIEM
for detection and investigation.

---

# Task 2 - Windows Event Log Assessment

## Script

`2-eventlog_assessment.ps1`

## Goal

Assess the current Windows security telemetry capability by comparing
Advanced Audit Policy configuration with Security events actually generated
during the previous 24 hours.

## Critical Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Explicit Credentials |
| 4688 | Process Creation |
| 4720 | Account Created |
| 4726 | Account Deleted |
| 4732 | Member Added to Group |
| 4672 | Special Logon |
| 1102 | Security Audit Log Cleared |

## Assessment Method

The script performs two independent checks.

First, it reads the current Advanced Audit Policy using:

```powershell
auditpol /get /category:*
```

Second, it queries the Windows Security log using:

```powershell
Get-WinEvent
```

for each critical Event ID during the previous 24 hours.

## Status Values

`GENERATING`

The required audit configuration exists and at least one matching Security
event was observed during the assessment window.

`NOT CONFIGURED`

The required audit policy could not be confirmed.

`CONFIGURED - NO EVENTS`

The audit policy is configured but no matching event occurred during the
previous 24 hours.

This does not necessarily indicate a security failure because some events,
such as account deletion, may legitimately not occur every day.

## Safety

The script is read-only.

It does not:

- enable audit policies;
- disable audit policies;
- clear Event Logs;
- modify Registry settings;
- configure Group Policy;
- install software;
- change Windows security configuration.

## Usage

Run from an elevated PowerShell session when Security log access requires
administrator privileges:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\2-eventlog_assessment.ps1
```

## Security Lesson

Audit configuration and telemetry generation are two different concepts.

```text
Audit Policy
    ↓
Windows performs activity
    ↓
Security Event generated
    ↓
Event Log
    ↓
SIEM
    ↓
SOC Analyst
```

A configured audit policy does not automatically prove that useful telemetry
is being generated.

This task verifies both configuration and observable evidence.

For SOC operations, important Windows Security Event IDs include logon
events, privileged logons, process creation, account changes, group
membership changes and Security log clearing.

---

# Task 3 - Windows Telemetry Reference Builder

## Script

`3-telemetry_reference.ps1`

## Output

`windows_event_reference.json`

## Goal

Build a machine-readable Windows security telemetry reference that connects
Windows Event IDs to MedDefense detection and incident-response use cases.

The reference acts as a bridge between:

- Windows Advanced Audit Policy
- Windows Security Event Log
- PowerShell logging
- Sysmon telemetry
- SIEM ingestion
- SOC detection and investigation
- Crimson Tide attack phases

## Why This Matters

A SOC analyst should not only know an Event ID.

For each security event, the analyst should understand:

- where the event is generated;
- which audit policy or sensor is required;
- what the event means from a security perspective;
- how frequently it normally occurs;
- how urgently it should be investigated;
- which attacker behavior it may reveal;
- how to validate that the telemetry is working.

The relationship can be represented as:

```text
Security Activity
        ↓
Windows / PowerShell / Sysmon
        ↓
Event ID
        ↓
Windows Event Log
        ↓
SIEM
        ↓
Detection Rule
        ↓
SOC Alert
        ↓
Investigation
```

If the endpoint does not generate the required telemetry, the SIEM cannot
detect the corresponding activity.

---

## Telemetry Sources

The reference contains three main Windows telemetry sources.

### Windows Security Log

Log source:

```text
Security
```

Events documented:

| Event ID | Event | Security Use |
|---:|---|---|
| 4624 | Successful Logon | Detect unusual successful authentication |
| 4625 | Failed Logon | Detect brute force and password spraying |
| 4648 | Explicit Credentials | Detect alternate credential usage |
| 4672 | Special Privileges Assigned | Detect privileged logons |
| 4688 | Process Creation | Detect suspicious process execution |
| 4720 | User Account Created | Detect suspicious account creation |
| 4726 | User Account Deleted | Detect suspicious account deletion |
| 4732 | Member Added to Group | Detect privilege/group changes |
| 1102 | Security Audit Log Cleared | Detect possible defense evasion |

Total:

```text
9 Security events
```

---

## PowerShell Telemetry

Log source:

```text
Microsoft-Windows-PowerShell/Operational
```

Events documented:

| Event ID | Event | Security Use |
|---:|---|---|
| 4103 | Module Logging | Visibility into PowerShell module/pipeline activity |
| 4104 | Script Block Logging | Visibility into executed PowerShell code |

Total:

```text
2 PowerShell events
```

### Event ID 4104

Event ID `4104` is particularly valuable for SOC investigations because
Script Block Logging can expose PowerShell code executed on the endpoint.

Examples of suspicious patterns include:

```text
Encoded PowerShell
Download commands
Credential-access commands
Security-control modification
Obfuscated scripts
```

Without Script Block Logging, malicious PowerShell activity may have
significantly less command-level visibility.

---

## Sysmon Telemetry

Log source:

```text
Microsoft-Windows-Sysmon/Operational
```

Events documented:

| Event ID | Event | Security Use |
|---:|---|---|
| 1 | Process Creation | Detailed process execution telemetry |
| 3 | Network Connection | Process-to-network correlation |
| 7 | Image Loaded | DLL/image loading visibility |
| 11 | File Create | Payload and suspicious file creation |
| 13 | Registry Value Set | Registry modification and persistence |
| 22 | DNS Query | Process-to-DNS correlation |

Total:

```text
6 Sysmon events
```

Sysmon complements native Windows Security logging by providing richer
endpoint telemetry.

For example:

```text
Sysmon Event ID 1
        ↓
Process
Command line
Parent process
User
Hashes
Image path
        ↓
SIEM
        ↓
Process execution detection
```

---

## Event Reference Structure

Every event in `windows_event_reference.json` contains:

```json
{
  "event_id": 4688,
  "event_name": "Process Creation",
  "log_source": "Security",
  "audit_or_sensor_dependency": "Audit Process Creation - Success / Process Tracking",
  "security_meaning": "Records creation of a new process and provides core execution telemetry.",
  "normal_frequency": "very high",
  "triage_priority": "high",
  "crimson_tide_phase": "Phase 4 - Execution",
  "example_suspicious_pattern": "Suspicious administrative or scripting tools launched by an unusual parent process.",
  "validation_method": "Start a controlled process and query the Security log for Event ID 4688."
}
```

This structure makes the reference machine-readable and suitable for later
automation and SIEM detection engineering.

---

## Crimson Tide Mapping

The reference connects telemetry to attacker activity observed in the
Crimson Tide scenario.

Examples:

```text
Credential attacks
        ↓
4625
Failed Logon

Lateral Movement
        ↓
4624 / 4648
Authentication activity

Privilege Escalation
        ↓
4672 / 4732
Privileged logon or group modification

Execution
        ↓
4688 / Sysmon 1 / PowerShell 4104
Process and script execution

Persistence
        ↓
4720 / Sysmon 13
Account or Registry modification

Command and Control
        ↓
Sysmon 3 / Sysmon 22
Network and DNS activity

Defense Evasion
        ↓
1102
Security log cleared
```

---

## Example SOC Investigation

Suppose a SIEM generates an alert containing:

```text
Event ID: 4688
Process: powershell.exe
User: DOMAIN\user
Parent Process: winword.exe
```

The Event ID alone tells the analyst that a process was created.

The surrounding telemetry provides the context:

```text
winword.exe
    ↓
powershell.exe
    ↓
Network connection
    ↓
Suspicious DNS query
```

This could be correlated with:

```text
4688        Windows process creation
4104        PowerShell script content
Sysmon 1    Detailed process information
Sysmon 3    Network connection
Sysmon 22   DNS query
```

This demonstrates why SOC investigations depend on multiple telemetry
sources rather than a single Event ID.

---

## Machine-Readable Output

The script generates:

```text
windows_event_reference.json
```

Expected summary:

```text
Security events mapped: 9
PowerShell events mapped: 2
Sysmon events mapped: 6
Total events documented: 17
Reference saved to: windows_event_reference.json
```

The JSON contains all 17 documented events.

---

## Safety

The script is safe to run on a personal Windows workstation.

It does not:

- modify Windows Audit Policy;
- modify Group Policy;
- enable PowerShell logging;
- install Sysmon;
- modify the Registry;
- modify Windows Firewall;
- create or delete users;
- clear Event Logs;
- modify Active Directory.

It only builds a reference JSON file.

---

## Usage

Because PowerShell script execution may be restricted on the workstation:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\3-telemetry_reference.ps1
```

The bypass applies only to that PowerShell process and does not permanently
change the machine's Execution Policy.

Verify the generated file:

```powershell
Get-Item .\windows_event_reference.json
```

Load the reference:

```powershell
$Reference = Get-Content .\windows_event_reference.json -Raw |
    ConvertFrom-Json
```

View the summary:

```powershell
$Reference.summary
```

Display the event reference:

```powershell
$Reference.events |
    Format-Table event_id,event_name,log_source,triage_priority -AutoSize
```

---

## SOC Lesson

The important lesson from this task is:

> An Event ID is useful only when the analyst understands the telemetry source,
> configuration dependency, security meaning and attacker behavior behind it.

The workflow is:

```text
Attacker behavior
        ↓
Telemetry source
        ↓
Event ID
        ↓
SIEM ingestion
        ↓
Detection
        ↓
Alert
        ↓
Triage
        ↓
Investigation
```

Task 2 answered:

```text
"What telemetry can my Windows system currently see?"
```

Task 3 answers:

```text
"What does that telemetry mean to a SOC analyst?"
```

The next stages use this knowledge to improve Windows logging and eventually
send the telemetry to the SIEM for detection and investigation.

---

# Task 4 - Password and Lockout Policy

## Script

`4-password_policy.ps1`

## Goal

Deploy a dedicated Group Policy Object for the MedDefense domain password
and account lockout baseline.

The control addresses credential attacks observed during the Crimson Tide
campaign.

## GPO

```text
MedDefense - Password and Lockout Policy
```

The GPO is intended to be linked to the domain root.

## Password Policy Target

| Setting | Target |
|---|---:|
| Minimum password length | 14 |
| Password complexity | Enabled |
| Password history | 24 |
| Maximum password age | 0 |
| Minimum password age | 1 day |

## Account Lockout Target

| Setting | Target |
|---|---:|
| Lockout threshold | 5 failed attempts |
| Lockout duration | 15 minutes |
| Reset lockout counter | 15 minutes |

## Security Purpose

The policy reduces exposure to:

- brute-force attacks;
- password spraying;
- weak passwords;
- password reuse;
- credential harvesting;
- repeated authentication attempts.

The Crimson Tide scenario demonstrated that weak authentication controls
allowed attackers to obtain and reuse credentials for lateral movement.

## Deployment Workflow

```text
Create dedicated GPO
        ↓
Configure password policy
        ↓
Configure account lockout
        ↓
Link GPO to domain root
        ↓
Group Policy update
        ↓
Query effective policy
        ↓
PASS / FAIL
```

## Safety

The script defaults to:

```text
AUDIT ONLY
```

Audit-only mode does not:

- create a GPO;
- modify password policy;
- modify account lockout;
- modify Active Directory;
- link Group Policy;
- force Group Policy updates.

Safe workstation execution:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\4-password_policy.ps1
```

Actual changes require:

```powershell
-Apply
```

Apply mode additionally refuses to proceed unless the computer is joined to:

```text
meddefense.local
```

Therefore `-Apply` must not be used on a personal standalone workstation.

## Expected Audit-Only Behaviour

```text
Minimum Length: 14        [WOULD SET]
Complexity: Enabled       [WOULD SET]
History: 24               [WOULD SET]
Maximum Age: 0            [WOULD SET]
Minimum Age: 1 day        [WOULD SET]

Threshold: 5 attempts     [WOULD SET]
Duration: 15 minutes      [WOULD SET]
Reset Counter: 15 minutes [WOULD SET]
```

## Validation

In the MedDefense domain, effective policy is independently queried using:

```powershell
Get-ADDefaultDomainPasswordPolicy
```

This distinguishes between:

```text
configuration attempted
```

and:

```text
configuration actually effective
```

## SOC Lesson

Weak authentication controls affect both prevention and detection.

For example:

```text
Password spray
      ↓
4625
4625
4625
4625
4625
      ↓
Lockout
```

A SOC analyst can correlate repeated Event ID `4625` failures by:

- source host;
- source IP;
- username;
- time window;
- number of targeted accounts.

A strong password and lockout policy reduces the attacker's ability to turn
credential guessing into successful access.

The broader lesson is:

> Security configuration should prevent common attacks while Windows
> telemetry provides evidence when those attacks are attempted.

---

# Task 5 - Advanced Audit Policy

## Script

`5-audit_policy.ps1`

## Goal

Deploy a dedicated MedDefense Advanced Audit Policy through Group Policy
to provide the Windows security telemetry required by SOC detection and
incident investigation.

## GPO

```text
MedDefense - Advanced Audit Policy
```

## Audit Configuration

### Account Logon

```text
Credential Validation:
Success and Failure

Kerberos Authentication Service:
Success and Failure
```

### Logon / Logoff

```text
Logon:
Success and Failure

Logoff:
Success

Special Logon:
Success
```

### Account Management

```text
User Account Management:
Success and Failure
```

### Privilege Use

```text
Sensitive Privilege Use:
Success and Failure
```

### Object Access

```text
File System:
Success and Failure

Registry:
Success and Failure
```

### Process Tracking

```text
Process Creation:
Success
```

Process Creation auditing enables Windows Security Event ID:

```text
4688
```

---

## Process Command-Line Logging

The policy enables:

```text
Include command line in process creation events
```

This enriches Event ID 4688 with command-line information.

Example:

```text
powershell.exe
```

provides less investigative context than:

```text
powershell.exe -EncodedCommand ...
```

Command-line telemetry can therefore significantly improve SOC detection
and incident reconstruction.

---

## Security Log Protection

The task also configures:

```text
Security log maximum size: 1 GB
```

Increasing the Security log size improves local evidence retention before
events are overwritten.

The policy also restricts Security log management/clearing to authorized
administrators.

Security log clearing is particularly important because Windows generates:

```text
Event ID 1102
```

when the Security audit log is cleared.

Unexpected Event ID 1102 activity should receive high SOC attention because
it may represent defense evasion.

---

## Validation

The effective Advanced Audit Policy is validated using:

```powershell
auditpol /get /category:*
```

The validator checks:

```text
Credential Validation
Kerberos Authentication Service
Logon
Logoff
Special Logon
User Account Management
Sensitive Privilege Use
File System
Registry
Process Creation
```

Each expected state is reported as:

```text
[VERIFIED]
```

or:

```text
[NOT VERIFIED]
```

---

## Safety

The script defaults to:

```text
AUDIT ONLY
```

Safe execution:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\5-audit_policy.ps1
```

Audit-only mode does not:

- create GPOs;
- modify audit policy;
- modify the Registry;
- modify Security Event Log configuration;
- force Group Policy;
- change Active Directory.

Actual changes require:

```powershell
-Apply
```

Apply mode additionally requires the machine to belong to:

```text
meddefense.local
```

The `-Apply` option must not be used on a personal standalone workstation.

---

## SOC Lesson

This task demonstrates an important SOC principle:

> A SIEM cannot detect activity for which the endpoint generates no telemetry.

The telemetry chain is:

```text
Attacker activity
       ↓
Advanced Audit Policy
       ↓
Windows Security Event
       ↓
Event Log
       ↓
SIEM
       ↓
Detection rule
       ↓
SOC alert
       ↓
Investigation
```

For example:

```text
Process executed
      ↓
Event ID 4688
      ↓
Command line
      ↓
SIEM
      ↓
Suspicious execution detection
```

Task 2 identified visibility gaps.

Task 3 documented what each telemetry source means.

Task 5 begins closing those gaps by defining the audit configuration
required to generate useful security evidence.

---

# Task 6 - PowerShell Security

## Script

`6-powershell_security.ps1`

## Goal

Configure PowerShell security logging through Group Policy so that
PowerShell activity produces useful evidence for SOC detection and
investigation.

## GPO

```text
MedDefense - PowerShell Security
```

## Script Block Logging

The policy enables:

```text
EnableScriptBlockLogging = 1
```

Primary event:

```text
Event ID 4104
```

Script Block Logging provides visibility into PowerShell script-block
content, including commands supplied through encoded PowerShell execution.

Example attack behavior:

```text
powershell.exe -EncodedCommand <base64>
```

The security objective is to provide investigators with visibility into the
PowerShell code interpreted during execution.

---

## Module Logging

The policy enables:

```text
EnableModuleLogging = 1
ModuleNames = *
```

Primary event:

```text
Event ID 4103
```

Module Logging records PowerShell module and pipeline activity and provides
additional context about the capabilities used during a PowerShell session.

---

## PowerShell Transcription

The policy enables PowerShell transcription with:

```text
EnableTranscripting = 1
OutputDirectory = C:\PSTranscripts
EnableInvocationHeader = 1
```

Transcription provides a text record of PowerShell session activity.

The combined visibility model is:

```text
PowerShell
   │
   ├── 4103 → Module Logging
   │
   ├── 4104 → Script Block Logging
   │
   └── Transcript → Session record
```

---

## AMSI

AMSI stands for:

```text
Antimalware Scan Interface
```

PowerShell integrates with AMSI so that script content can be submitted to
an installed antimalware provider for inspection.

The script verifies the presence of:

```text
amsi.dll
```

and attempts to confirm its presence in the current PowerShell process.

AMSI and Script Block Logging provide different defensive capabilities:

```text
AMSI
↓
content inspection

4104
↓
security telemetry / investigation
```

---

## Controlled Event ID 4104 Test

The script performs a harmless controlled validation.

Original command:

```powershell
Write-Host "MEDDEFENSE_PS4104_TEST"
```

The command is encoded using UTF-16LE Base64 and executed through:

```powershell
powershell.exe -EncodedCommand
```

The script then queries:

```text
Microsoft-Windows-PowerShell/Operational
```

for:

```text
Event ID 4104
```

and searches for the original decoded marker.

Successful validation produces:

```text
Event ID 4104 found
Decoded content found [VERIFIED]
```

This proves that PowerShell security telemetry is working rather than merely
assuming that the policy was configured successfully.

---

## Crimson Tide Relevance

The Crimson Tide attack chain included encoded PowerShell execution during
post-exploitation.

Without sufficient PowerShell telemetry:

```text
Attacker
   ↓
powershell.exe -EncodedCommand ...
   ↓
execution
   ↓
limited investigation evidence
```

With the MedDefense controls:

```text
Encoded PowerShell
       ↓
Script Block Logging
       ↓
Event ID 4104
       ↓
decoded/interpreted script evidence
       ↓
SIEM
       ↓
SOC investigation
```

---

## Safety

The script defaults to:

```text
AUDIT ONLY
```

Safe assessment:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\6-powershell_security.ps1
```

Actual changes require:

```powershell
-Apply
```

Apply mode refuses to continue unless the machine belongs to:

```text
meddefense.local
```

The script must therefore be applied only to the authorized MedDefense lab
environment.

---

## Deployment

After creating a VirtualBox snapshot, run on DC01:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\6-powershell_security.ps1 -Apply
```

The workflow is:

```text
Create GPO
    ↓
Enable Script Block Logging
    ↓
Enable Module Logging
    ↓
Enable Transcription
    ↓
Link GPO
    ↓
gpupdate /force
    ↓
VERIFY effective settings
    ↓
Run controlled encoded command
    ↓
Query Event ID 4104
    ↓
VERIFIED
```

---

## SOC Lesson

PowerShell is both an administrative tool and a common attacker
post-exploitation tool.

For a SOC analyst, suspicious PowerShell should be investigated using
multiple telemetry sources:

```text
4688       Windows process creation
4103       PowerShell Module Logging
4104       PowerShell Script Block Logging
Sysmon 1   detailed process creation
Sysmon 3   process network activity
```

The important lesson is:

> Logging the execution of powershell.exe is useful, but understanding what
> PowerShell actually executed provides much stronger investigation evidence.