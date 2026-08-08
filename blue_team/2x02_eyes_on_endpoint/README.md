# 2x02 - Eyes on Endpoint

## MedDefense Health Systems

### Blue Team - Telemetry Engineering

This project focuses on endpoint observability and telemetry validation across
the hardened MedDefense environment.

Hardening reduces what an attacker can do.

Telemetry reveals what an attacker is doing.

The objective of this project is to validate that the defensive
instrumentation deployed during the previous Linux and Windows hardening
projects actually generates the evidence required by SOC analysts.

---

## Lab Environment

### Linux

```text
billing-srv-01
```

The Linux server was hardened during:

```text
2x00 - Locking the Gates
```

Security telemetry includes:

```text
auditd
meddefense.rules
auth.log
system logs
```

### Windows

```text
DC01
```

The Windows domain was hardened during:

```text
2x01 - Windows Fortress
```

Security telemetry includes:

```text
Windows Security Event Log
Advanced Audit Policy
PowerShell Logging
Sysmon
AppLocker
Windows Firewall
Active Directory
```

---

# Task 0 - Sysmon Telemetry Validation

## Script

```text
0-sysmon_validation.ps1
```

## Goal

Validate that Sysmon is correctly capturing security-relevant endpoint
activity.

Deploying Sysmon does not automatically prove that the required telemetry is
being generated.

This task performs controlled actions and verifies that each expected Sysmon
Event ID appears with sufficient detail for SOC investigation.

---

## Required Sysmon Events

The validation covers five event types:

```text
Event ID 1  - Process Creation
Event ID 3  - Network Connection
Event ID 11 - File Creation
Event ID 13 - Registry Modification
Event ID 22 - DNS Query
```

---

## Event ID 1 - Process Creation

Controlled action:

```cmd
cmd.exe /c whoami
```

The validator searches for:

```text
Image
CommandLine
```

Expected evidence:

```text
Image       = ...\cmd.exe
CommandLine = cmd.exe /c whoami
```

Expected result:

```text
Sysmon EID 1 captured, cmdline present
```

This proves that process execution telemetry contains the command-line detail
required for investigation.

---

## Event ID 3 - Network Connection

The script generates a controlled outbound TCP connection using:

```powershell
Test-NetConnection
```

Because the DC01 laboratory may not have Internet connectivity, the script
uses the Domain Controller's reachable IP address and TCP port 53.

The validator checks:

```text
DestinationIp
DestinationPort
Image
```

Expected result:

```text
Sysmon EID 3 captured, dest IP/port/process present
```

This provides network context for the process that initiated the connection.

---

## Event ID 11 - File Creation

Controlled artifact:

```text
C:\Windows\Temp\test.txt
```

The script checks:

```text
TargetFilename
Image
```

Expected result:

```text
C:\Windows\Temp\test.txt -> Sysmon EID 11 captured
```

The file is removed during cleanup.

---

## Event ID 13 - Registry Modification

Controlled Registry location:

```text
HKCU\Software\MedDefense\SysmonTest
```

Controlled value:

```text
TestValue
```

The validator checks:

```text
TargetObject
EventType
```

This proves that the telemetry records:

```text
Registry key path
value name
operation type
```

Expected result:

```text
Sysmon EID 13 captured
```

The test Registry key is removed during cleanup.

---

## Event ID 22 - DNS Query

The project requirement includes the controlled query:

```cmd
nslookup example.com
```

The validator looks for:

```text
QueryName
QueryResults
Image
```

Because DC01 may operate without Internet access, the script can also generate
a controlled query for:

```text
dc01.meddefense.local
```

The fallback allows DNS telemetry to be validated against the local
MedDefense DNS infrastructure.

Expected result:

```text
nslookup example.com -> Sysmon EID 22 captured
```

---

## Validation Method

Each test follows the same workflow:

```text
record timestamp
      ↓
perform controlled action
      ↓
wait for Sysmon
      ↓
query Sysmon Operational log
      ↓
select correct Event ID
      ↓
inspect event fields
      ↓
PASS / FAIL
```

The Sysmon log queried is:

```text
Microsoft-Windows-Sysmon/Operational
```

The validator parses the event XML instead of relying only on formatted event
messages.

This allows fields such as:

```text
CommandLine
DestinationIp
DestinationPort
TargetFilename
TargetObject
EventType
QueryName
QueryResults
```

to be validated directly.

---

## Cleanup

The script removes all temporary artifacts:

```text
C:\Windows\Temp\test.txt
HKCU\Software\MedDefense\SysmonTest
```

The script does not change:

```text
Sysmon configuration
Group Policy
Active Directory
Windows Firewall
audit policy
PowerShell policy
```

---

## Expected Output

```text
[*] Running Sysmon telemetry validation...
    [1/5] Process creation (Event ID 1)...
          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]

    [2/5] Network connection (Event ID 3)...
          Outbound TCP -> Sysmon EID 3 captured, dest IP/port/process present   [PASS]

    [3/5] File creation (Event ID 11)...
          C:\Windows\Temp\test.txt -> Sysmon EID 11 captured   [PASS]

    [4/5] Registry modification (Event ID 13)...
          HKCU\...\SysmonTest -> Sysmon EID 13 captured   [PASS]

    [5/5] DNS query (Event ID 22)...
          nslookup example.com -> Sysmon EID 22 captured   [PASS]

[*] Cleanup: removing test artifacts...

Actions tested: 5 | Captured: 5 | Missed: 0
```

---

## Exit Codes

The script returns:

```text
0
```

when all five telemetry tests pass.

It returns:

```text
1
```

when one or more expected Sysmon events are missing.

---

## SOC Relevance

The five events provide different pieces of an attack timeline:

```text
Event ID 1
Process executed
      ↓
What command was run?

Event ID 3
Network connection
      ↓
Where did the process connect?

Event ID 11
File creation
      ↓
What artifact was written?

Event ID 13
Registry modification
      ↓
What system configuration changed?

Event ID 22
DNS query
      ↓
What domain did the endpoint attempt to resolve?
```

Together, these events allow an analyst to reconstruct endpoint behavior.

---

## Telemetry Engineering Lesson

Instrumentation must be tested.

The incorrect assumption is:

```text
Sysmon installed
      ↓
visibility exists
```

The correct validation model is:

```text
Sysmon installed
      ↓
controlled action
      ↓
expected event generated
      ↓
required fields present
      ↓
telemetry validated
```

The central principle of this task is:

> Deployment does not equal coverage. A telemetry source is only useful when
> the expected security events are proven to exist with enough context for
> detection and investigation.

---

# Task 1 - Sysmon ATT&CK Coverage Matrix

## Script

```text
1-sysmon_coverage_matrix.ps1
```

## Deliverable

```text
sysmon_coverage_matrix.json
```

## Goal

Measure whether the current Sysmon configuration provides sufficient
telemetry to observe attacker techniques defined in MITRE ATT&CK.

The task evaluates coverage using three dimensions:

```text
Event ID enabled
        +
filter behavior
        +
useful evidence fields
```

## Coverage States

Each ATT&CK technique is classified as:

```text
covered
partial
blind
```

### Covered

All required Event IDs are enabled and no obvious filtering conflict was
identified.

### Partial

Only part of the required telemetry exists or filtering could suppress
relevant activity.

### Blind

None of the required Event IDs are available.

## ATT&CK Mappings

The matrix includes:

```text
T1059     Command and Scripting Interpreter
T1053     Scheduled Task/Job
T1547     Boot or Logon Autostart Execution
T1055     Process Injection
T1071     Application Layer Protocol
T1574.002 DLL Side-Loading
T1027     Obfuscated or Compressed Files
```

## Sysmon Event Mapping

Important Sysmon events include:

```text
1  - ProcessCreate
3  - NetworkConnect
7  - ImageLoad
8  - CreateRemoteThread
10 - ProcessAccess
11 - FileCreate
13 - Registry value modification
15 - FileCreateStreamHash
22 - DNSQuery
```

## Filter Analysis

An enabled Event ID does not automatically guarantee visibility.

For example:

```text
NetworkConnect enabled
        ↓
onmatch="exclude"
        ↓
attacker connection matches exclusion
        ↓
event suppressed
```

The coverage matrix therefore inspects both:

```text
include rules
exclude rules
```

that may suppress relevant attacker activity.

## Evidence Fields

Coverage also depends on useful event detail.

Examples include:

```text
CommandLine
ParentImage
DestinationIp
DestinationPort
TargetFilename
TargetObject
QueryName
QueryResults
Hashes
GrantedAccess
```

These fields allow SOC analysts to investigate the context of an event.

## Real-World Example

A malicious document launches:

```text
WINWORD.EXE
      ↓
powershell.exe -enc ...
```

If Sysmon Event ID 1 is available, analysts may observe:

```text
Image
CommandLine
ParentImage
User
Hashes
```

This provides evidence for:

```text
T1059 - Command and Scripting Interpreter
```

Without ProcessCreate telemetry, the endpoint may be blind to that execution
chain.

## Detection Engineering Workflow

```text
ATT&CK behavior
      ↓
required telemetry
      ↓
Sysmon Event ID
      ↓
filter analysis
      ↓
field quality
      ↓
covered / partial / blind
      ↓
tuning recommendation
```

## Output

The script generates:

```text
sysmon_coverage_matrix.json
```

Each row contains:

```text
technique_id
technique_name
required_event_ids
enabled_event_ids
filter_conflicts
coverage_status
evidence_fields_expected
recommendation
```

Additional context includes the reason for the coverage status and a
threat example.

## SOC Lesson

Installing Sysmon does not prove that an attack technique is observable.

A mature SOC asks:

```text
What attacker behavior do we care about?
        ↓
What telemetry should record it?
        ↓
Is that telemetry enabled?
        ↓
Are filters suppressing it?
        ↓
Does the event contain enough evidence?
```

The central principle is:

> Telemetry coverage should be measured against attacker behavior rather
> than against the simple presence of a logging tool.

---

# Task 2 - PowerShell Logging Validation

## Script

```text
2-powershell_logging_validation.ps1
```

## Goal

Validate that the PowerShell logging controls deployed during Windows
hardening produce sufficient telemetry for security investigation.

The validation covers:

```text
Script Block Logging
Module Logging
Transcription
```

The objective is not simply to confirm that the settings are enabled.

The objective is to prove that real PowerShell activity produces usable
evidence.

## PowerShell Event IDs

The primary events validated are:

```text
4103 - Module Logging
4104 - Script Block Logging
```

## Test 1 - Simple Command

Controlled command:

```powershell
Get-Process
```

Expected telemetry:

```text
Event ID 4104
```

The validator checks that the command appears in the Script Block Log.

A real attacker may use commands such as:

```powershell
Get-Process
Get-Service
Get-ChildItem
```

during host discovery.

## Test 2 - Encoded PowerShell

Controlled execution:

```text
powershell.exe -enc <Base64>
```

The encoded payload contains:

```powershell
Write-Host "Test"
```

The validator checks that Event ID `4104` contains the decoded script
content rather than only the Base64 input.

This matters because attackers frequently use encoded PowerShell to make
command lines harder to read.

The telemetry chain is:

```text
powershell.exe -enc ...
        ↓
encoded command
        ↓
PowerShell decodes it
        ↓
Script Block Logging
        ↓
4104
        ↓
decoded script visible to SOC
```

## Test 3 - Module Logging

Controlled action:

```powershell
Import-Module ActiveDirectory
Get-ADDomain
```

Expected telemetry:

```text
Event ID 4103
```

Module Logging helps analysts understand which PowerShell capabilities were
used during a session.

For example, unexpected use of the ActiveDirectory module may indicate
domain reconnaissance.

## Test 4 - Multi-Line Script Block

The validator executes a controlled twelve-line script.

It verifies that Event ID `4104` contains the complete script block or enough
of the expected content to determine its detail level.

This matters because attacker scripts frequently perform several operations
within a single script block.

Partial logging can remove important context from an investigation.

## Test 5 - Transcription

PowerShell Transcription should generate text files under:

```text
C:\PSTranscripts\
```

The validator launches a controlled PowerShell session containing a unique
marker and searches newly created transcript files for that marker.

Expected result:

```text
C:\PSTranscripts\*.txt
```

with the session content recorded.

## CAPTURED and MISSED

Each telemetry test is classified based on whether the expected evidence was
observed.

```text
CAPTURED
MISSED
```

Console validation is represented as:

```text
[PASS]
[FAIL]
```

The script also identifies the level of detail:

```text
full content
partial content
```

## Real-World Example

An attacker executes:

```text
powershell.exe -enc <encoded payload>
```

A process event may reveal only:

```text
powershell.exe
-enc
Base64 data
```

Script Block Logging may reveal:

```text
Invoke-WebRequest
Invoke-Expression
credential discovery
network discovery
```

This changes the SOC analyst's question from:

```text
"PowerShell ran."
```

to:

```text
"What exactly did PowerShell do?"
```

## Detection Workflow

```text
PowerShell execution
       ↓
4104 Script Block Logging
       +
4103 Module Logging
       +
Transcription
       ↓
SIEM
       ↓
Detection
       ↓
SOC triage
       ↓
Incident investigation
```

## Safety

The validation uses only benign commands.

It does not:

```text
modify Group Policy
change PowerShell logging configuration
modify Active Directory
change security controls
download payloads
execute malware
```

## Expected Summary

```text
Tests: 5 | Captured: 5 | Missed: 0
```

If a test reports:

```text
MISSED
```

the result should be investigated as a telemetry coverage gap rather than
changed artificially to PASS.

## SOC Lesson

PowerShell being logged is not the same as PowerShell being logged well.

A useful telemetry source must answer:

```text
What command ran?
Was encoded content decoded?
Which module was used?
Was the complete script visible?
Was the session transcribed?
```

The central principle is:

> Logging configuration is only valuable when controlled testing proves that
> the evidence required for investigation is actually produced.
