# MedDefense Health Systems
# HEALTHBANE Stage 4 Threat Hunting Report

**Project:** 4x04 Threat Hunting  
**Campaign:** HEALTHBANE  
**Environment:** MedDefense Health Systems  
**Hunt Window:** 2026-05-04 through 2026-05-18  
**Threat Advisory:** HC3-2026-HEALTHBANE-004  
**Prepared for:** SOC Technical Review and Dr. Patricia Morales / Executive Board  
**Classification:** Internal / TLP:AMBER-derived analysis  

---

# 1. Executive Summary

MedDefense conducted a 14-day retrospective threat hunt after the HC3 HEALTHBANE Stage 4 advisory warned healthcare organizations that the campaign had expanded into Living Off The Land lateral movement using legitimate Windows administration technologies.

The hunt identified **high-confidence evidence consistent with HEALTHBANE Stage 4 activity inside the MedDefense environment**. The attacker used `WS-RECV-03` as a pivot workstation, accessed LSASS memory to obtain credential material, abused the `svc_healthsync` service account, and subsequently used legitimate administration technologies including PsExec, WMI and PowerShell Remoting to move through the environment.

The observed attack path reached critical infrastructure including:

- `SRV-HEALTH-DB` — patient health records database
- `SRV-INS-DB` — insurance claims database
- `SRV-DC-01` — primary domain controller

Because these systems contain sensitive healthcare, insurance and authentication information, the incident represents a **critical organizational risk**. Access to these systems was confirmed; however, the Stage 4 hunt alone does not prove exactly which records were viewed or exfiltrated. Potential exposure of PHI, insurance information and domain authentication material must therefore be investigated through full incident response.

Before the hunt, MedDefense's HEALTHBANE ATT&CK model contained **29 techniques**, of which **16 were OBSERVED**, **3 INFERRED**, and **10 NOT COVERED**, producing **55% directly observed coverage** and **66% mapped coverage**.

The hunt exposed previously uncovered Stage 4 behaviors including:

- T1003.001 — OS Credential Dumping: LSASS Memory
- T1021.002 — SMB/Windows Admin Shares / PsExec
- T1021.006 — Windows Remote Management / PowerShell Remoting
- T1047 — Windows Management Instrumentation
- T1078.002 — Valid Accounts: Domain Accounts
- T1550.002 — Pass-the-Hash investigation / NTLM-style activity

Hunt-derived detection rules were produced for these behaviors, increasing the project's target detection posture from approximately **55% to 80% coverage**.

These rules currently represent the **post-hunt detection design** produced by this self-contained project. They must be validated, tuned and deployed to the production SIEM before the 80% figure should be interpreted as live operational detection coverage.

**Overall Assessment:**

> **POSITIVE — HIGH CONFIDENCE**

The correlated MedDefense telemetry is consistent with execution of the HEALTHBANE Stage 4 operational pattern.

Immediate Incident Response escalation is required.

---

# 2. Hunt Methodology

## 2.1 Hypothesis-Driven Threat Hunting

The investigation followed a hypothesis-driven methodology.

The process began with the HC3 Stage 4 advisory rather than existing alerts.

The workflow was:

```text
HC3 Threat Intelligence
        |
        v
Stage 4 TTP Identification
        |
        v
MITRE ATT&CK Gap Analysis
        |
        v
Hunt Hypotheses
        |
        v
Administrative Baseline
        |
        v
Targeted SIEM Queries
        |
        v
Evidence Correlation
        |
        v
Detection Gap Analysis
        |
        v
New Detection Rules
```

HC3 specifically warned that Stage 4 differed from previous HEALTHBANE activity because the attacker relied heavily on legitimate Windows administrative capabilities rather than custom malware.

Traditional IOC-based detection was therefore insufficient.

The investigation focused on behavioral context:

- source host
- user identity
- target host
- time of activity
- authentication method
- process relationships
- deviation from normal administrative behavior

---

## 2.2 Data Sources

The hunt used the following local evidence sources:

### SIEM telemetry

- `siem_export/wazuh_alerts_14d.json`
- `siem_export/wazuh_raw_sysmon_14d.json`

Relevant telemetry included:

- Sysmon Event ID 1 — Process Creation
- Sysmon Event ID 10 — Process Access
- Sysmon network/process telemetry
- Windows Security Event 4624 — Successful Logon
- command-line telemetry
- process-parent relationships
- authentication package information

### Intelligence and reference data

- `reference/hc3_advisory_004.txt`
- `reference/4x03_attack_mapping.json`
- `reference/admin_schedule.txt`
- `reference/service_accounts.txt`
- `reference/network_topology.txt`

### Baseline

- `baseline/robert_kim_activity.json`

---

## 2.3 Administrative Baseline

Before searching for malicious administration activity, the hunt established what legitimate administration looked like.

Robert Kim's baseline contained **93 legitimate administrative events**:

| Tool | Baseline Events |
|---|---:|
| PsExec | 44 |
| WMI | 31 |
| PowerShell Remoting | 18 |
| **Total** | **93** |

Normal administrative behavior was characterized by:

- Source: `WS-ADMIN-01`
- User: `MEDDEFENSE\robert.kim`
- Working hours: authorized business/maintenance windows
- Standard Microsoft/Sysinternals administration tools
- Server infrastructure as expected targets
- No interactive use of `svc_*` service accounts
- No administrative execution from ordinary user workstations
- No routine execution from `C:\Windows\Temp`, `C:\Users\Public` or `C:\ProgramData`

There were no approved exceptions during the 14-day hunt period.

This baseline was essential because tools such as PsExec, WMI and PowerShell are not malicious by themselves.

The hunt therefore detected **deviation from authorized behavior**, rather than simply detecting the existence of administrative tools.

---

# 3. Findings by Hunt Hypothesis

## H1 — PsExec Lateral Movement

**MITRE ATT&CK:** T1021.002 — SMB/Windows Admin Shares  
**Status:** POSITIVE  
**Confidence:** HIGH

### Hypothesis

If HEALTHBANE Stage 4 occurred, PsExec should appear from a workstation or account outside the documented administrative baseline.

### Evidence

PsExec activity originated from:

```text
WS-RECV-03
```

rather than the authorized administrative workstation:

```text
WS-ADMIN-01
```

The activity used:

```text
MEDDEFENSE\svc_healthsync
```

rather than Robert Kim's named administrator account.

Observed targets included:

```text
SRV-HEALTH-DB
SRV-INS-DB
SRV-DC-01
```

Example activity included:

```text
WS-RECV-03
   |
   | PsExec64.exe
   | MEDDEFENSE\svc_healthsync
   v
SRV-HEALTH-DB
```

Later activity expanded to the insurance database and primary domain controller.

### Assessment

This activity falls completely outside the documented administrative baseline.

The combination of:

- non-admin workstation
- service account
- PsExec
- critical server targets
- correlation with credential access

provides high-confidence evidence of unauthorized lateral movement.

---

## H2 — LSASS Credential Access

**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Status:** POSITIVE  
**Confidence:** HIGH

### Hypothesis

If the attacker obtained credentials for lateral movement, an unusual process may have accessed LSASS memory before the service account was abused.

### Evidence

On `WS-RECV-03`, the following process was observed:

```text
C:\Windows\Temp\debug_tool.exe
```

accessing:

```text
C:\Windows\System32\lsass.exe
```

with:

```text
GrantedAccess = 0x1010
```

The first identified sequence occurred on:

```text
2026-05-05 08:22 UTC
```

The suspicious process was launched from a writable temporary directory and its LSASS access matched the credential-access behavior described by the HC3 advisory.

A second suspicious LSASS access event occurred approximately one week later.

### Assessment

The behavior is strongly consistent with credential dumping.

The later appearance of `svc_healthsync` from the same workstation provides strong temporal and contextual correlation between credential access and subsequent credential abuse.

The logs do not directly show the password being extracted from LSASS; therefore, credential theft is a **high-confidence analytical conclusion**, rather than direct observation of the credential material itself.

---

## H3 — WMI Remote Execution

**MITRE ATT&CK:** T1047 — Windows Management Instrumentation  
**Status:** POSITIVE  
**Confidence:** HIGH

### Hypothesis

If HEALTHBANE used WMI after initial lateral movement, WMI-related execution should occur outside Robert Kim's normal administrative baseline.

### Evidence

WMI-related activity was identified as part of the unauthorized sequence originating from the `WS-RECV-03` pivot context.

Remote execution behavior included `WmiPrvSE.exe`-associated processes and PowerShell/command execution on critical targets.

WMI activity was observed in the later expansion toward:

```text
SRV-DC-01
```

using the same compromised operational context associated with `svc_healthsync`.

### Baseline Comparison

Legitimate WMI usage exists in the environment.

Robert Kim normally performs WMI administration from:

```text
WS-ADMIN-01
```

using:

```text
MEDDEFENSE\robert.kim
```

within documented maintenance windows.

The attack activity did not match this profile.

### Assessment

The contextual deviation and correlation with the broader attack sequence support a high-confidence malicious classification.

---

## H4 — PowerShell Remoting

**MITRE ATT&CK:** T1021.006 — Windows Remote Management  
**Status:** POSITIVE  
**Confidence:** HIGH

### Hypothesis

If the attacker followed the HC3 Stage 4 pattern, PowerShell Remoting should follow initial lateral movement and be used for remote execution or staging.

### Evidence

PowerShell Remoting activity was observed from `WS-RECV-03`.

An example included:

```text
Enter-PSSession
    -ComputerName SRV-HEALTH-DB
    -Credential MEDDEFENSE\svc_healthsync
```

Additional PowerShell Remoting behavior was associated with later server access.

Relevant commands included behaviors such as:

```text
Enter-PSSession
New-PSSession
Invoke-Command
Copy-Item -ToSession
```

### Assessment

PowerShell Remoting is legitimate technology, but the source workstation, service-account identity, target systems and correlation with PsExec activity placed this activity outside the authorized administrative baseline.

The finding is therefore assessed as malicious with high confidence.

---

## H5 — Service Account Abuse

**MITRE ATT&CK:** T1078.002 — Valid Accounts: Domain Accounts  
**Related investigation:** T1550.002 — Pass the Hash  
**Status:** POSITIVE  
**Confidence:** CRITICAL / VERY HIGH

### Hypothesis

If HEALTHBANE obtained a service account credential, the account should appear outside its documented service-host authorization context.

### Evidence

`svc_healthsync` is intended for automated operation associated with:

```text
SRV-HEALTH-DB
```

The hunt identified authentication from:

```text
WS-RECV-03
```

including:

```text
Logon Type: 3
Authentication Package: NTLM
```

The same account was subsequently associated with lateral movement to:

```text
SRV-HEALTH-DB
SRV-INS-DB
SRV-DC-01
```

The service-account matrix explicitly prohibits workstation-originated authentication for this account.

### Assessment

This is one of the strongest findings in the investigation because the deviation from the documented baseline is absolute.

`svc_healthsync` should not be used interactively from `WS-RECV-03`.

The subsequent correlation with PsExec, WMI and PowerShell Remoting provides very high confidence that the credential was being used for unauthorized lateral movement.

NTLM Type 3 authentication is also consistent with Pass-the-Hash-style investigation; however:

> **NTLM authentication alone does not prove Pass-the-Hash.**

T1550.002 therefore remains an analytical lead unless additional authentication evidence confirms use of stolen NTLM hash material.

---

# 4. Reconstructed Attack Timeline

The individual hunt findings were correlated into a unified attack sequence.

## 2026-05-05 — Credential Access

```text
WS-RECV-03
MEDDEFENSE\records03

C:\Windows\Temp\debug_tool.exe
              |
              v
           lsass.exe

GrantedAccess: 0x1010
```

The suspicious utility accessed LSASS memory.

This represents the earliest confirmed Stage 4 evidence in the hunt window.

---

## 2026-05-06 — First Lateral Movement Session

The stolen/compromised service-account context appeared during lateral movement.

```text
WS-RECV-03
     |
     | svc_healthsync
     |
     +---- PsExec ----------> SRV-HEALTH-DB
     |
     +---- PSRemoting ------> SRV-HEALTH-DB
```

At approximately:

```text
07:14 UTC
```

PsExec was executed against `SRV-HEALTH-DB`.

Later:

```text
07:48 UTC
```

PowerShell Remoting using `Enter-PSSession` was observed against the same server.

This sequence is consistent with the HC3 pattern of initial lateral movement followed by remote administration/staging.

---

## 2026-05-09 — Expansion to Insurance Infrastructure

Unauthorized `svc_healthsync` authentication occurred from `WS-RECV-03` against:

```text
SRV-INS-DB
```

The authentication used:

```text
Logon Type 3
NTLM
```

At approximately:

```text
08:42:17 UTC
```

the authentication occurred.

Approximately one second later:

```text
08:42:18 UTC
```

PsExec activity followed against the same target.

This close temporal relationship strongly connects credential abuse with lateral movement.

---

## 2026-05-12 — Credential Refresh

A second suspicious LSASS memory access was identified on:

```text
WS-RECV-03
```

again involving:

```text
debug_tool.exe
        |
        v
    lsass.exe
```

with:

```text
GrantedAccess = 0x1010
```

This is consistent with HC3's description of attackers periodically refreshing credential material during longer operations.

---

## 2026-05-13 — Expansion to Domain Controller

Unauthorized authentication using:

```text
MEDDEFENSE\svc_healthsync
```

was observed from:

```text
WS-RECV-03
```

to:

```text
SRV-DC-01
```

using:

```text
Logon Type 3
NTLM
```

Immediately afterward:

```text
WS-RECV-03
     |
     | PsExec64.exe
     | svc_healthsync
     v
SRV-DC-01
```

WMI-associated remote execution activity was also observed in the same attack context.

`SRV-DC-01` is a critical Domain Controller containing Active Directory and authentication infrastructure.

---

## Overall Attack Progression

```text
WS-RECV-03 compromised
        |
        v
debug_tool.exe
        |
        v
LSASS memory access
T1003.001
        |
        v
svc_healthsync credential context
        |
        v
Unauthorized NTLM authentication
T1078.002
        |
        +-------------------------+
        |                         |
        v                         v
      PsExec                     WMI
   T1021.002                    T1047
        |
        v
PowerShell Remoting
T1021.006
        |
        v
SRV-HEALTH-DB
        |
        v
SRV-INS-DB
        |
        v
SRV-DC-01
```

### Observed Dwell Time

Earliest confirmed Stage 4 evidence:

```text
2026-05-05 08:22 UTC
```

The correlated activity continued through at least:

```text
2026-05-13
```

This represents approximately **eight days of observed Stage 4 presence/activity**, including dormant periods between attacker sessions.

This burst-and-dormancy pattern closely matches the operational behavior described in the HC3 advisory.

---

# 5. MITRE ATT&CK Coverage Update

## Pre-Hunt Coverage

Before the Stage 4 hunt:

```text
Total HEALTHBANE techniques: 29

OBSERVED:      16
INFERRED:       3
NOT COVERED:   10

Observed coverage: 55%
Mapped coverage:   66%
```

The organization therefore had direct evidence/detection visibility for only slightly more than half of the known HEALTHBANE threat model.

---

## Newly Confirmed / Investigated Stage 4 Techniques

| Technique | Description | Hunt Result |
|---|---|---|
| T1003.001 | LSASS Memory | OBSERVED |
| T1021.002 | SMB/Windows Admin Shares / PsExec | OBSERVED |
| T1021.006 | Windows Remote Management | OBSERVED |
| T1047 | Windows Management Instrumentation | OBSERVED |
| T1078.002 | Domain Account / Service Account Abuse | OBSERVED |
| T1550.002 | Pass the Hash | INVESTIGATED / NTLM evidence, not independently proven |

---

## Coverage Improvement

```text
BEFORE HUNT

Observed Coverage
███████████░░░░░░░░░ 55%


POST-HUNT TARGET POSTURE

Detection Coverage
████████████████░░░░ 80%
```

The hunt therefore substantially increased visibility into the Stage 4 portion of the HEALTHBANE threat model.

The **80% figure represents the project's updated detection posture after incorporating hunt-derived logic**. Because Task 13 produces local detection-rule drafts rather than performing a live Wazuh/Suricata deployment, operational production coverage must be confirmed after validation, tuning and deployment.

---

# 6. Detection Improvements

The hunt demonstrated that much of the necessary telemetry already existed.

The primary failure was therefore not complete absence of data.

It was a failure to convert the telemetry into behavioral detections using administrative context.

## New Hunt-Derived Rules

### Rule 100100 — PsExec from Non-Admin Workstation

Detects:

```text
PsExec
+
source != WS-ADMIN-01
+
administrative context outside baseline
```

**ATT&CK:** T1021.002  
**Expected false-positive rate:** VERY LOW

---

### Rule 100101 — LSASS Memory Access from Suspicious Process

Detects:

```text
TargetImage = lsass.exe
+
memory-read access
+
non-allowlisted/suspicious SourceImage
```

**ATT&CK:** T1003.001  
**Expected false-positive rate:** LOW

---

### Rule 100102 — Service Account Authentication from Workstation

Detects:

```text
TargetUserName = svc_*
+
WorkstationName = WS-*
```

**ATT&CK:** T1078.002  
**Expected false-positive rate:** VERY LOW

---

### Rule 100103 — WMI Child Process Anomaly

Detects:

```text
WmiPrvSE.exe
      |
      +----> cmd.exe
      |
      +----> powershell.exe
```

**ATT&CK:** T1047  
**Expected false-positive rate:** MEDIUM

The rule requires baseline comparison because legitimate WMI administration exists in the environment.

---

### Rule 100104 — Service Account NTLM Network Logon

Detects:

```text
svc_*
+
Logon Type 3
+
NTLM
+
workstation source
```

**ATT&CK:** T1078.002  
**Related investigation:** T1550.002  
**Expected false-positive rate:** VERY LOW

---

### Rule 100105 — PowerShell Remoting from Non-Admin Workstation

Detects:

```text
Enter-PSSession
New-PSSession
Invoke-Command
Copy-Item -ToSession
```

when initiated outside the approved administrative baseline.

**ATT&CK:** T1021.006  
**Expected false-positive rate:** LOW

---

### Network Rule 9000030 — PsExec SMB Lateral Movement

Detects PsExec/PSEXESVC-related SMB activity over:

```text
TCP/445
```

**ATT&CK:** T1021.002  
**Expected false-positive rate:** LOW

Endpoint and network telemetry should be correlated before escalation.

---

## Detection Gap Closure

Before the hunt:

```text
ATTACK
   |
   v
Telemetry collected
   |
   v
No contextual detection
   |
   X
SOC Alert
```

Post-hunt design:

```text
ATTACK
   |
   v
Telemetry
   |
   v
Behavioral Rule
   |
   v
Baseline Comparison
   |
   v
Cross-Event Correlation
   |
   v
HIGH-SEVERITY ALERT
   |
   v
SOC Investigation
```

The main improvement is therefore not simply collecting more logs.

It is understanding **what normal looks like** and detecting deviations from that baseline.

---

# 7. Remaining Gaps and Recommendations

## 7.1 Remaining Unknowns

The hunt substantially improved visibility, but approximately 20% of the threat model remains outside the project's target detection posture.

Important unresolved questions include:

- Was additional persistence established?
- Were Windows event records selectively modified or destroyed?
- Were additional credentials compromised?
- Did the attacker access additional servers not reconstructed in this hunt?
- What specific patient or insurance records were accessed?
- Was data staged locally?
- Was data exfiltrated during or after Stage 4?
- Were additional service accounts compromised?
- Was actual Pass-the-Hash performed, or were usable credentials obtained through another mechanism?

The hunt should therefore not be interpreted as a complete forensic reconstruction.

---

## 7.2 Immediate Actions — Incident Response

`WS-RECV-03` should be treated as a confirmed/high-confidence compromised pivot system.

Immediate actions:

1. Isolate `WS-RECV-03` from the network.
2. Preserve volatile memory before destructive remediation where operationally possible.
3. Acquire a forensic disk image.
4. Preserve relevant Wazuh, Windows, Sysmon and firewall evidence.
5. Investigate `debug_tool.exe` and associated `.dat` artifacts.
6. Review access to `SRV-HEALTH-DB`.
7. Review access to `SRV-INS-DB`.
8. Conduct priority forensic review of `SRV-DC-01`.
9. Search for additional persistence mechanisms.
10. Determine whether PHI or other regulated information was accessed or removed.

This investigation should transition into the full Incident Response process addressed in Module 5.

---

## 7.3 Short-Term Actions

### Rotate service account credentials

Immediately rotate:

```text
svc_healthsync
```

and review other privileged service accounts.

Service accounts with database access should receive priority.

### Restrict service account authentication

Enforce:

```text
service account
      |
      +--> authorized service host only
```

Workstation authentication should be blocked where technically possible.

### Privileged Access Review

Review:

- administrative group memberships
- service account permissions
- database permissions
- Domain Controller access
- remote administration privileges
- NTLM usage

### Review NTLM

Identify where Kerberos can replace NTLM and investigate unexpected NTLM authentication involving privileged or service accounts.

---

## 7.4 Medium-Term Actions

### Full Sysmon Deployment

Ensure consistent Sysmon coverage across endpoints and servers.

At minimum collect:

```text
Event 1     Process Creation
Event 10    Process Access
Event 12/13 Registry Events
```

Additional network/process telemetry should be retained where operationally practical.

### Behavioral Analytics

Detection should incorporate:

```text
WHO
+
FROM WHERE
+
TO WHAT
+
WHEN
+
WITH WHICH TOOL
+
IS THIS NORMAL?
```

rather than simply:

```text
Was PsExec executed?
```

### Administrative Baselines

Maintain authoritative baselines for:

- administrators
- privileged workstations
- maintenance schedules
- authorized targets
- service accounts
- authentication methods
- remote administration tools

### Detection Validation

The rules produced during Task 13 must be:

```text
Draft
  ↓
Test
  ↓
Tune
  ↓
Validate
  ↓
Deploy
  ↓
Monitor
```

False-positive rates should be reviewed before production enforcement.

---

# 8. Lessons Learned

## 8.1 ATT&CK Coverage Can Create a False Sense of Security

Before the hunt, MedDefense had direct observed coverage for approximately:

```text
55%
```

of the modeled HEALTHBANE techniques.

That number could appear reassuring when viewed without context.

However, several of the missing techniques represented critical attacker actions:

```text
Credential Theft
      ↓
Lateral Movement
      ↓
Remote Execution
      ↓
Service Account Abuse
      ↓
Critical Server Access
```

Coverage percentage alone therefore does not equal security.

Organizations must understand **which techniques are missing**, not only how many.

---

## 8.2 Legitimate Tools Can Be Malicious

PsExec, WMI and PowerShell Remoting are legitimate administration technologies.

Therefore:

```text
PsExec = malicious
```

is incorrect.

Instead:

```text
PsExec
+
WS-ADMIN-01
+
robert.kim
+
authorized maintenance window

= likely legitimate
```

while:

```text
PsExec
+
WS-RECV-03
+
svc_healthsync
+
critical database server

= highly suspicious
```

Context is what converts raw telemetry into actionable security intelligence.

---

## 8.3 Reactive Detection Was Insufficient

Traditional detection asks:

> "Did one of our rules generate an alert?"

Threat hunting asks:

> "If the attacker is already here, what evidence would their behavior leave behind?"

That difference was critical during this investigation.

Stage 4 used legitimate administrative technology and internal network communication, making traditional file hashes, domain reputation and external IP blocklists ineffective against much of the activity.

---

## 8.4 Baselines Are Security Controls

Robert Kim's documented administrative behavior was not merely operational documentation.

It became a detection mechanism.

Because the SOC knew:

```text
WHO:     robert.kim
SOURCE:  WS-ADMIN-01
WHEN:    approved maintenance periods
TOOLS:   PsExec / WMI / PSRemoting
```

the hunt could recognize:

```text
WHO:     svc_healthsync
SOURCE:  WS-RECV-03
TARGET:  critical servers

= ANOMALOUS
```

A well-maintained administrative baseline therefore directly improves detection quality.

---

## 8.5 Threat Hunting Must Be Recurring

HEALTHBANE operated in short bursts separated by periods of inactivity.

A single event could resemble an administrator working unusually late.

Across several days, however, the pattern became clear:

```text
LSASS access
     ↓
dormancy
     ↓
PsExec
     ↓
WMI
     ↓
PSRemoting
     ↓
dormancy
     ↓
second LSASS access
     ↓
Domain Controller access
```

This demonstrates why proactive threat hunting cannot be a one-time exercise.

The operational cycle should be:

```text
HUNT
  ↓
FIND
  ↓
DETECT
  ↓
VALIDATE
  ↓
DEPLOY
  ↓
HUNT AGAIN
```

---

# 9. Final Assessment

The 14-day retrospective hunt identified a coherent sequence of credential access, service-account abuse and lateral movement originating from `WS-RECV-03`.

The sequence included:

```text
LSASS Memory Access
        ↓
svc_healthsync Abuse
        ↓
PsExec
        ↓
WMI
        ↓
PowerShell Remoting
        ↓
SRV-HEALTH-DB
        ↓
SRV-INS-DB
        ↓
SRV-DC-01
```

The temporal sequence, common pivot host, common credential context, critical targets and deviation from MedDefense's documented administrative baseline make accidental or legitimate administration an implausible explanation for the complete pattern.

## Question 1 — Did HEALTHBANE Stage 4 happen to us?

**Assessment: YES — HIGH CONFIDENCE.**

MedDefense telemetry contains activity strongly consistent with the HEALTHBANE Stage 4 operational TTP profile.

This assessment concerns the operational TTP match. Attribution to a specific named threat actor remains outside the evidence available in this hunt.

---

## Question 2 — What have we done to detect it next time?

The hunt converted previously uncovered behavior into new detection logic covering:

- PsExec lateral movement
- LSASS credential access
- WMI remote execution
- PowerShell Remoting
- service-account abuse
- anomalous NTLM network authentication
- SMB/PsExec network behavior

The project's detection posture therefore improves from approximately **55% to a target of 80%** after incorporation of the hunt-derived detections.

The remaining operational requirement is to validate, tune and deploy the local rule drafts into production monitoring.

---

# Conclusion

HEALTHBANE Stage 4 demonstrated that attackers do not need custom malware to evade a security program.

The tools used in this incident were largely legitimate Windows administration technologies.

The failure was therefore not simply a lack of logs.

The failure was a lack of **behavioral context and correlation**.

The threat hunt transformed that weakness into actionable detection engineering:

```text
Threat Intelligence
        ↓
ATT&CK Gap
        ↓
Hypothesis
        ↓
Threat Hunt
        ↓
Evidence
        ↓
Correlation
        ↓
Detection Gap
        ↓
New Detection
        ↓
Improved Security Posture
```

MedDefense should now transition from threat hunting into formal Incident Response, beginning with containment and forensic investigation of `WS-RECV-03`, credential rotation for `svc_healthsync`, and priority investigation of the critical servers reached during the attack.

---

**Final Hunt Status:** `POSITIVE`  
**Confidence:** `HIGH`  
**Incident Response Required:** `YES`  
**Primary Pivot:** `WS-RECV-03`  
**Compromised Credential Context:** `MEDDEFENSE\svc_healthsync`  
**Critical Systems Reached:** `SRV-HEALTH-DB`, `SRV-INS-DB`, `SRV-DC-01`  
**Pre-Hunt Observed ATT&CK Coverage:** `55%`  
**Post-Hunt Target Detection Posture:** `~80%`  
**Next Phase:** `Incident Response / Module 5`