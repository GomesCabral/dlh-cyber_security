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