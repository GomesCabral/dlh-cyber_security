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