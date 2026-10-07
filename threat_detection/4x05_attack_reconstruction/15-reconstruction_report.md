# HEALTHBANE Attack Reconstruction Report

**Organization:** MedDefense Health Systems\
**Campaign:** HEALTHBANE\
**Assessment period:** 14 April 2026 -- 18 May 2026\
**Primary compromised endpoint:** `WS-RECV-03` (`10.10.3.21`)\
**Overall reconstruction confidence:** **HIGH**\
**Named threat-actor attribution:** **UNCONFIRMED**\
**Classification:** INTERNAL / INCIDENT RESPONSE

------------------------------------------------------------------------

## 1. Executive Summary

MedDefense suffered a multi-stage HEALTHBANE intrusion that began with
targeted phishing on 14 April 2026 and progressed from credential
harvesting to malicious document delivery, RAT installation, persistent
command-and-control, credential dumping, lateral movement, data
collection, local staging, confirmed external exfiltration, and
anti-forensic activity. The attacker established `WS-RECV-03` as the
primary pivot, maintained HTTPS command-and-control to
`185.220.101.45:443`, obtained `svc_healthsync` credential material
after accessing LSASS, and used PsExec, WMI and PowerShell Remoting to
reach `SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01`.
\[E02\]\[E04\]\[E05\]\[E06\]\[E07\]\[E09\]

The intrusion reached MedDefense's highest-value data. Disk forensics
recovered a 14,219,484-byte archive containing **47,138 patient
records**, an 11,802,944-byte archive containing **51,002
insurance/member records**, and an 8,419,232-byte Active Directory
enumeration dataset containing **1,184 directory records**. Firewall
evidence correlates these artifacts with outbound transfers of the same
sizes. The evidence therefore supports **confirmed collection, staging
and external transmission**, not merely potential exposure. The 98,140
patient/insurance rows are not necessarily 98,140 unique individuals
because the authoritative asset inventory states that the cohorts
overlap; the estimated deduplicated affected population is approximately
**50,000--55,000 individuals**. \[E06\]\[E07\]\[E08\]\[E10\]

The intrusion was contained when `WS-RECV-03` was isolated at
**2026-05-15 13:42 CDT**. Memory was acquired at 14:18 CDT and disk
imaging completed at 19:45 CDT. The threat hunt was operationally
decisive: behavioral deviations from Robert Kim's legitimate
administration baseline exposed off-hours PsExec, WMI, PowerShell
Remoting, LSASS access and unauthorized service-account authentication
that IOC-only detection had not explained. \[E05\]\[E08\]

The principal remediation priorities are to preserve and complete
forensic scoping; re-image `WS-RECV-03`; rotate `svc_healthsync` and
other potentially exposed credentials; investigate `SRV-DC-01` for
deeper identity compromise; validate database audit logs; block
confirmed C2; strengthen segmentation and service-account controls;
operationalize detections for scheduled tasks, Run keys, LSASS access,
off-hours remote administration, staging and exfiltration; and complete
Legal/Privacy notification scoping. \[E05\]\[E08\]\[E10\]

### Key metrics

  -----------------------------------------------------------------------
  Metric                              Final assessment
  ----------------------------------- -----------------------------------
  Incident window                     14 Apr 2026 -- 15 May 2026
                                      containment

  Approximate dwell time              \~31 days

  First credential exposure           14 Apr 2026 13:18:42 UTC

  First confirmed C2 beacon           15 Apr 2026 08:51:38 UTC

  First confirmed lateral movement    6 May 2026 \~02:12 CDT

  Breakout time                       \~21.7 days from initial phishing
                                      delivery to first lateral movement

  First confirmed sensitive-data      8 May 2026
  staging                             

  Confirmed staged-file transfer      34,441,660 bytes (\~32.85 MiB)

  Patient records                     47,138

  Insurance/member records            51,002

  AD directory records                1,184

  Estimated unique affected           \~50,000--55,000 after
  population                          deduplication

  Post-4x04 ATT&CK baseline           23/29 observed = \~80%

  Final reassessment                  27/29 confirmed = **93.1%**; 1
                                      probable; 1 possible

  Primary pivot                       `WS-RECV-03`

  Confirmed server targets            `SRV-HEALTH-DB`, `SRV-INS-DB`,
                                      `SRV-DC-01`
  -----------------------------------------------------------------------

> **Coverage note:** the exercise narrative suggests a final value near
> 96%. The evidence-based reassessment produces **27/29 confirmed =
> 93.1%**. Reporting 96% would require treating an analytically
> uncertain technique as confirmed or changing the established
> 29-technique denominator without a defensible basis.

------------------------------------------------------------------------

## 2. Methodology

### 2.1 Evidence sources

  -------------------------------------------------------------------------------------------------
  ID                      Evidence source                                   Role in reconstruction
  ----------------------- ------------------------------------------------- -----------------------
  E01                     `previous_findings/4x00_phishing_summary.txt`     Phishing campaign and
                                                                            credential-harvesting
                                                                            findings

  E02                     `previous_findings/4x01_network_timeline.txt`     DNS, TLS, malware
                                                                            delivery, C2 and early
                                                                            network timeline

  E03                     `previous_findings/4x02_attack_mapping.json`      Earlier
                                                                            intelligence/ATT&CK
                                                                            hypotheses

  E04                     `previous_findings/4x03_malware_summary.txt`      Dropper, RAT and
                                                                            exfiltrator behavior

  E05                     `previous_findings/4x04_hunting_report.txt`       LSASS, PsExec, WMI,
                                                                            PSRemoting and
                                                                            service-account hunt
                                                                            findings

  E06                     `ir_evidence/disk_forensics_report.txt`           Persistence, deleted
                                                                            staging files,
                                                                            Prefetch, registry and
                                                                            anti-forensics

  E07                     `ir_evidence/firewall_sessions_ws_recv_03.json`   Persistent C2, lateral
                                                                            sessions, secondary
                                                                            channel and
                                                                            exfiltration

  E08                     `ir_evidence/ir_team_notes.txt`                   Containment,
                                                                            acquisition and IR
                                                                            decisions

  E09                     `ir_evidence/memory_artifacts.txt`                Live RAT, C2, encoded
                                                                            PowerShell, LSASS
                                                                            residue and scheduled
                                                                            task

  E10                     `reference/meddefense_asset_inventory.txt`        Authoritative data
                                                                            sensitivity and asset
                                                                            impact

  E11                     `reference/network_topology.txt`                  Network/host context

  E12                     `reference/healthbane_ioc_master.json`            Pre-4x05 IOC baseline

  E13                     `reference/attck_navigator_80pct.json`            Post-4x04 ATT&CK
                                                                            baseline
  -------------------------------------------------------------------------------------------------

### 2.2 Analytical approach

The investigation used five steps: source-specific analysis;
cross-evidence correlation; chronological reconstruction; ATT&CK
reassessment; and impact/control analysis. IOCs, timestamps, hosts,
users, processes, files, authentication and network sessions were
correlated across independent sources. Timezone and collection-point
differences were documented rather than silently normalized.

### 2.3 Confidence framework

-   **CONFIRMED:** direct support from at least two independent evidence
    sources.
-   **PROBABLE:** strong direct evidence from one source with supporting
    context.
-   **POSSIBLE:** technique logic or partial evidence supports the
    assessment, but direct evidence is limited or ambiguous.

Absence of evidence is not treated as evidence of absence when a source
lacked the required telemetry.

### 2.4 Limitations and assumptions

The firewall file is an abridged IR export: the underlying dataset
contains 39,412 sessions while the supplied JSON reproduces 168 sessions
plus authoritative aggregate findings. Full internal-versus-external
byte totals therefore cannot be independently recomputed from the
reproduced session list alone. \[E07\]

The 4x01 PCAP ends on 16 April, creating a network-visibility gap before
later host and firewall evidence. \[E02\] Disk acquisition is scoped to
`WS-RECV-03`; absence of disk artifacts on other endpoints cannot prove
that no other endpoint was affected. \[E06\]

A material chronology contradiction remains in administrative metadata:
the 4x04 summary states that R1--R3 were initiated on 15 May and that
the hunt triggered IR, while an IR note contains wording that places
hunt initiation on 18 May, after the 15 May isolation. The containment
timestamp is supported operationally, but an exact
detection-to-containment duration cannot be defensibly calculated until
the hunt metadata is corrected. \[E05\]\[E08\]

------------------------------------------------------------------------

## 3. Attack Reconstruction

### 3.1 Stage 1 --- Initial Access

**Assessment: CONFIRMED**

HEALTHBANE targeted MedDefense with healthcare-themed phishing. On
**2026-04-14 13:14:22 UTC**, the relevant phishing message was
delivered. `WS-RECV-03` subsequently resolved `meddefense-portal.com` at
**13:18:05 UTC**, established TLS to `91.219.236.117`, and generated a
POST to `/collect.php` at **13:18:42 UTC**, consistent with credential
submission. \[E01\]\[E02\]

**ATT&CK:** `T1566.002` Spearphishing Link; `T1078` Valid Accounts.\
**Principal IOCs:** `meddefense-portal.com`, `91.219.236.117`.\
**Confidence:** **CONFIRMED** through convergent phishing and network
evidence.

### 3.2 Stage 2 --- C2 Establishment

**Assessment: CONFIRMED**

On **2026-04-15 08:43:18 UTC**, MedDefense received the second-wave
message carrying `April-Invoice-MD2026.docm`. At **08:51:09 UTC**,
`WS-RECV-03` resolved `update.healthbane-c2.net`; at **08:51:11 UTC**,
the host downloaded `svchost_update.exe`; and at **08:51:38 UTC**, the
first canonical C2 beacon was observed to `185.220.101.45:443` with SNI
`sync.healthbane-c2.net`. The beacon repeated at approximately **300 ±
10 seconds**. \[E02\]\[E04\]

Later firewall evidence establishes that communication to the same
primary C2 persisted through the IR window, with **3,958 beacons over
approximately 13.5 days** in the firewall period. The secondary
attacker-associated channel `203.0.113.47:8443` did **not** exist during
the original Stage 2 PCAP window; its first firewall observation was
**2026-05-07 06:48:11 UTC**, after the primary C2 was already
established. \[E07\]\[E09\]

**ATT&CK:** `T1071.001`, `T1573.001`, `T1105`.\
**Confidence:** primary C2 **CONFIRMED**; secondary/fallback role
**PROBABLE**, while the communication itself is confirmed.

### 3.3 Stage 3 --- Malware Deployment and Persistent Foothold

**Assessment: CONFIRMED**

The macro-enabled document used VBA `Document_Open`/`AutoOpen` execution
to initiate the malware chain. The delivered `svchost_update.exe` was a
287,444-byte PE32+ RAT. Malware triage recovered `sync_healthdata.ps1`,
an exfiltration-capable PowerShell component. \[E04\]

The persistent RAT later appeared in live memory at
`C:\Users\records03\AppData\Roaming\Microsoft\HealthSync\svchost_update.exe`.
Memory showed the RAT maintaining the known connection to
`185.220.101.45:443`. Encoded PowerShell decoded to retrieval of
configuration from `sync.healthbane-c2.net` and execution of
`sync_healthdata.ps1`. \[E09\]

Persistence existed in more than one form. The Registry Run value
`HealthSync` was present, and IR discovered a hidden daily scheduled
task, `HealthSync Update Service`, created on **2026-05-07 01:47:33
CDT**, configured to run encoded PowerShell at 02:00. Memory TaskCache
and on-disk task XML independently support the scheduled task.
\[E06\]\[E09\]

**ATT&CK:** `T1059.001`, `T1059.005`, `T1547.001`, `T1053.005`,
`T1027.010`, `T1105`.\
**Confidence:** **CONFIRMED**.

### 3.4 Stage 4 --- Credential Access, Lateral Movement, Collection and Staging

**Assessment: CONFIRMED**

At **2026-05-05 03:22 CDT**, `debug_tool.exe` accessed LSASS on
`WS-RECV-03`; `out.dat` was written shortly afterwards. Disk recovery
identified Mimikatz-like structures and `svc_healthsync` strings in the
partially recovered dump. Hunt, memory and disk evidence converge on
LSASS credential access. \[E05\]\[E06\]\[E09\]

The attacker then moved laterally: on 6 May to `SRV-HEALTH-DB`; on 9 May
to `SRV-INS-DB`; and on 13 May to `SRV-DC-01`. The hunt found six
anomalous PsExec events, five WMI events, four PSRemoting events, two
LSASS-access events and six unauthorized service-account
authentications. All anomalous administration originated from
`WS-RECV-03`, occurred overnight and differed materially from Robert
Kim's `WS-ADMIN-01` business-hours baseline. \[E05\]

Disk forensics recovered `staging_export_001.zip` with **47,138 patient
rows**, `staging_export_002.zip` with **51,002 insurance/member rows**,
and `query_results.csv` with **1,184 Active Directory records**. Staging
occurred on `WS-RECV-03`, establishing the flow **server → compromised
workstation → local staging → external transfer**. \[E06\]\[E07\]

The attacker also impaired and removed evidence. A Defender exclusion
for `C:\Windows\Temp` was present; `Security.evtx` was deleted/recreated
around the 9 May operation; and staging artifacts were deleted shortly
after use. \[E06\]\[E09\]

**ATT&CK:** `T1003.001`, `T1021.002`, `T1021.006`, `T1047`, `T1078.002`,
`T1005`, `T1074.001`, `T1560.001`, `T1070.001`.\
**Confidence:** **CONFIRMED** for the principal chain. `T1550.002`
Pass-the-Hash remains **PROBABLE**.

------------------------------------------------------------------------

## 4. Unified Timeline

  ----------------------------------------------------------------------------------------------------------------------------------
            \# Timestamp        Event                 Host path            ATT&CK                      Evidence      Confidence
  ------------ ---------------- --------------------- -------------------- --------------------------- ------------- ---------------
             1 14 Apr 13:14:22  Phishing delivered    External →           T1566                       E01,E02       CONFIRMED
               UTC                                    MedDefense                                                     

             2 14 Apr 13:18:05  Phishing domain       WS-RECV-03 →         T1566.002                   E01,E02       CONFIRMED
               UTC              resolved/clicked      phishing infra                                                 

             3 14 Apr 13:18:42  Credential POST       WS-RECV-03 →         T1078                       E01,E02       CONFIRMED
               UTC                                    91.219.236.117                                                 

             4 15 Apr 08:43:18  Malicious DOCM        External →           T1566.001                   E02,E04       CONFIRMED
               UTC              delivered             MedDefense                                                     

             5 15 Apr 08:51:11  RAT downloaded        WS-RECV-03 →         T1105                       E02,E04       CONFIRMED
               UTC                                    185.220.101.45                                                 

             6 15 Apr 08:51:38  First C2 beacon       WS-RECV-03 →         T1071.001                   E02,E04       CONFIRMED
               UTC                                    185.220.101.45:443                                             

             7 22 Apr 06:14:47  Run-key persistence   WS-RECV-03           T1547.001                   E04,E06,E09   CONFIRMED
               UTC              artifact                                                                             

             8 4 May 18:11:08   Defender exclusion    WS-RECV-03           T1562.001                   E06,E09       CONFIRMED
               CDT                                                                                                   

             9 5 May 03:22 CDT  First LSASS dump      WS-RECV-03           T1003.001                   E05,E06,E09   CONFIRMED

            10 6 May \~02:12    First lateral         WS-RECV-03 →         T1021.002                   E05,E06,E07   CONFIRMED
               CDT              movement              HEALTH-DB                                                      

            11 7 May 01:47:33   Scheduled task        WS-RECV-03           T1053.005                   E06,E09       CONFIRMED
               CDT              created                                                                              

            12 7 May 06:48:11   Secondary channel     WS-RECV-03 →         T1571                       E07,E09       CONFIRMED
               UTC              first seen            203.0.113.47:8443                                              communication

            13 8 May 02:36 CDT  Patient dataset       HEALTH-DB →          T1005/T1074.001/T1560.001   E06,E07       CONFIRMED chain
                                staged                WS-RECV-03                                                     

            14 8 May 07:38:14   Patient archive       WS-RECV-03 → C2      T1041                       E06,E07       CONFIRMED
               UTC              transmitted                                                                          

            15 9 May \~03:40    Insurance DB pivot    WS-RECV-03 → INS-DB  T1021/T1047                 E05,E06,E07   CONFIRMED
               CDT                                                                                                   

            16 9 May 03:01:42   Security log          WS-RECV-03           T1070.001                   E06,E09       CONFIRMED
               CDT              deletion/recreation                                                                  

            17 11 May 03:14 CDT Insurance dataset     INS-DB → WS-RECV-03  T1005/T1074.001/T1560.001   E06,E07       CONFIRMED chain
                                staged                                                                               

            18 11 May 08:17:18  Insurance archive     WS-RECV-03 → C2      T1041                       E06,E07       CONFIRMED
               UTC              transmitted                                                                          

            19 12 May 02:45 CDT Second LSASS dump     WS-RECV-03           T1003.001                   E05,E06       CONFIRMED

            20 13 May           Domain-controller     WS-RECV-03 → DC-01   T1021/T1047                 E05,E06,E07   CONFIRMED
               \~01:56--02:09   pivot                                                                                
               CDT                                                                                                   

            21 13 May 02:31 CDT AD results staged     DC-01 → WS-RECV-03   T1087.002/T1074.001         E06,E07       CONFIRMED chain

            22 13 May 07:34:14  AD dataset            WS-RECV-03 → C2      T1041                       E06,E07       CONFIRMED
               UTC              transmitted                                                                          

            23 15 May 02:00 CDT Scheduled exfiltrator WS-RECV-03           T1053.005                   E06,E09       CONFIRMED
                                executes                                                                             

            24 15 May 13:42 CDT Host isolated         IR → WS-RECV-03      ---                         E05,E08       CONFIRMED

            25 15 May 14:18 CDT Memory captured       WS-RECV-03           ---                         E08,E09       CONFIRMED

            26 15 May 19:45 CDT Disk imaging          WS-RECV-03           ---                         E06,E08       CONFIRMED
                                completed                                                                            
  ----------------------------------------------------------------------------------------------------------------------------------

### 4.1 Temporal metrics and gaps

The incident lasted approximately **31 days** from phishing to
isolation. Breakout to first confirmed lateral movement took
approximately **21.7 days**. Stage 4 then accelerated into recurring
overnight activity. An exact detection-to-containment metric is
deliberately not reported because the supplied hunt/IR administrative
chronology conflicts.

Principal visibility gaps include the interval after initial credential
exposure, the post-PCAP period after 16 April, incomplete command-level
visibility between RAT establishment and May Stage 4 activity, and
scheduled-task executions without independently reconstructed operator
actions. These are collection gaps, not proof of dormancy.

------------------------------------------------------------------------

## 5. ATT&CK Analysis

### 5.1 Final technique inventory

  Technique   Behavior                          Final assessment   Change
  ----------- --------------------------------- ------------------ ---------------------------
  T1566.001   Spearphishing Attachment          CONFIRMED          Unchanged
  T1566.002   Spearphishing Link                CONFIRMED          Unchanged
  T1204.002   Malicious File                    CONFIRMED          Unchanged
  T1059.001   PowerShell                        CONFIRMED          Unchanged
  T1059.005   Visual Basic                      CONFIRMED          Unchanged
  T1547.001   Registry Run Keys                 CONFIRMED          Unchanged
  T1071.001   Web Protocols                     CONFIRMED          Unchanged
  T1071.004   DNS                               CONFIRMED          Unchanged
  T1573.001   Encrypted Channel                 CONFIRMED          Unchanged
  T1027       Obfuscated/Compressed Files       CONFIRMED          Unchanged
  T1027.010   Command Obfuscation               CONFIRMED          Unchanged
  T1140       Deobfuscate/Decode                CONFIRMED          Unchanged
  T1105       Ingress Tool Transfer             CONFIRMED          Unchanged
  T1041       Exfiltration Over C2              CONFIRMED          Upgraded
  T1048.003   DNS Exfiltration                  POSSIBLE           Qualified
  T1005       Data from Local System            CONFIRMED          Upgraded
  T1583.001   Acquire Infrastructure: Domains   CONFIRMED          Unchanged
  T1003.001   LSASS Memory                      CONFIRMED          Unchanged
  T1021.002   SMB/Windows Admin Shares          CONFIRMED          Unchanged
  T1021.006   Windows Remote Management         CONFIRMED          Unchanged
  T1047       WMI                               CONFIRMED          Unchanged
  T1078       Valid Accounts                    CONFIRMED          Unchanged
  T1078.002   Domain Accounts                   CONFIRMED          Unchanged
  T1550.002   Pass the Hash                     PROBABLE           Corrected/down-classified
  T1112       Modify Registry                   CONFIRMED          Unchanged
  T1053.005   Scheduled Task                    CONFIRMED          Upgraded
  T1074.001   Local Data Staging                CONFIRMED          Upgraded
  T1560.001   Archive Collected Data            CONFIRMED          Upgraded
  T1070.001   Clear Windows Event Logs          CONFIRMED          Upgraded

Additional reconstruction behaviors outside the fixed 29-technique
denominator include `T1562.001` Impair Defenses, `T1070.004` File
Deletion, `T1571` Non-Standard Port and `T1087.002` Domain Account
Discovery.

### 5.2 Coverage evolution

  -----------------------------------------------------------------------
  Investigation point                 Coverage interpretation
  ----------------------------------- -----------------------------------
  4x02 intelligence                   11/29 observed = 38%; 16/29
                                      observed+inferred = 55%

  4x03 malware                        \~55% direct posture after malware
                                      analysis

  4x04 hunting                        23/29 observed = \~80%

  4x05 reconstruction                 **27/29 confirmed = 93.1%**, 1
                                      probable, 1 possible

  Analytically mapped                 29/29 = 100%, but mapped ≠
                                      confirmed
  -----------------------------------------------------------------------

`T1048.003` remains **POSSIBLE** for actual bulk DNS exfiltration.
`T1550.002` remains **PROBABLE** because NTLM after LSASS dumping is
consistent with Pass-the-Hash but does not directly prove the exact
credential-reuse mechanism.

------------------------------------------------------------------------

## 6. Impact Assessment

### 6.1 Compromised systems

  ----------------------------------------------------------------------------------------
  System            Role              Sensitivity                Assessment
  ----------------- ----------------- -------------------------- -------------------------
  WS-RECV-03        Records           MEDIUM-HIGH, transient PHI Confirmed compromise
                    workstation /                                
                    pivot                                        

  SRV-HEALTH-DB     EHR database      CRITICAL, PHI              Confirmed data access

  SRV-INS-DB        Claims/billing    HIGH, PII/financial/PHI    Confirmed data access
                    database                                     

  SRV-DC-01         Domain Controller HIGH,                      Confirmed
                                      authentication/directory   interaction/enumeration

  SRV-FILE-01       Departmental file MEDIUM with PHI/PII        No confirmed attacker
                    server            repositories               data access

  SRV-BACKUP-01     Backup repository CRITICAL                   No confirmed attacker
                                                                 access
  ----------------------------------------------------------------------------------------

### 6.2 Exfiltration determination

**Data staging:** YES --- confirmed.\
**External transmission:** YES --- confirmed.\
**Primary confirmed destination:** `185.220.101.45:443`.\
**Confirmed staged-file volume:** **34,441,660 bytes (\~32.85 MiB)**.\
**Status:** completed for the three recovered staged datasets before
containment. \[E06\]\[E07\]

### 6.3 Data exposure by type

  ------------------------------------------------------------------------
  Data type             Status                                       Scope
  --------------------- --------------------- ----------------------------
  Patient health        CONFIRMED EXFILTRATED                  47,138 rows
  records                                     

  Insurance/member data CONFIRMED EXFILTRATED                  51,002 rows

  AD/directory data     CONFIRMED TRANSMITTED                1,184 records

  Employee HR           NOT CONFIRMED EXPOSED           No attack evidence
  repository                                  

  Imaging PHI on        NOT CONFIRMED EXPOSED           No attack evidence
  FILE-01                                     

  Backup data           NOT CONFIRMED EXPOSED   No confirmed backup-server
                                                                    access
  ------------------------------------------------------------------------

The raw patient + insurance row count is **98,140**, but the
authoritative inventory says the cohorts overlap; the estimated
deduplicated affected population is approximately **50,000--55,000
individuals**. \[E10\]

### 6.4 Regulatory implications

Within the supplied MedDefense compliance framework, the evidence meets
the incident's reportable-breach threshold: unauthorized PHI access is
confirmed, PHI was collected and staged, and matching external transfers
occurred. IR notes use **15 May 2026** as the discovery date and record
**14 July 2026** as the 60-day notification deadline, with Legal
coordination required. \[E08\]

This report does not substitute for a formal legal determination.
Legal/Privacy should validate identity-level deduplication,
jurisdictional obligations and the final affected-person population.
Isolation, evidence preservation and blocked post-isolation C2 are
mitigating factors, but they do not undo the confirmed disclosure.

------------------------------------------------------------------------

## 7. Defensive Posture Evaluation

### 7.1 What worked

-   Hypothesis-driven hunting identified malicious use of legitimate
    administrative tools by comparing source host, identity, target,
    time and authentication method against Robert Kim's baseline.
    \[E05\]
-   Memory acquisition exposed the live RAT, encoded PowerShell and
    secondary connection. \[E09\]
-   Disk forensics recovered persistence, deleted staging artifacts,
    credential-dump residue and anti-forensic evidence. \[E06\]
-   Firewall analysis confirmed C2 continuity and converted suspected
    exfiltration into confirmed transfer. \[E07\]
-   Cross-source correlation produced conclusions that no single source
    could establish alone.

### 7.2 What failed

-   Detection coverage did not equal operational security coverage.
-   Scheduled-task persistence was outside the 4x04 hunt scope and was
    discovered only during IR. \[E05\]\[E06\]\[E09\]
-   Data staging and anti-forensics were not queried by the hunt.
    \[E05\]
-   Service-account and segmentation controls allowed unauthorized
    workstation-originated access toward sensitive server assets.
-   Periodic HTTPS C2 blended with ordinary traffic.
-   The incident record contains a process-metadata chronology
    inconsistency that prevents a defensible detection-to-containment
    metric.

### 7.3 Structural lessons

PsExec, WMI and PowerShell Remoting are not malicious by themselves.
Their maliciousness became visible through context. ATT&CK percentages
can likewise create a coverage illusion: a technique may be represented
in a matrix while telemetry, correlation, triage or prevention remains
insufficient to stop it.

------------------------------------------------------------------------

## 8. Remediation Plan

### 8.1 Immediate --- 0--48 hours

1.  Keep `WS-RECV-03` isolated and re-image it before reuse.
2.  Block confirmed HEALTHBANE C2 and investigate historical contacts.
3.  Rotate `svc_healthsync`; review all `svc_*` accounts for
    workstation-originated, NTLM or interactive use.
4.  Review `SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01` authentication,
    SQL, PowerShell and administrative logs.
5.  Determine whether deeper Domain Controller credential compromise
    occurred and invoke domain-recovery procedures if established.
6.  Preserve forensic images, memory, firewall exports and
    chain-of-custody records.
7.  Begin identity-level deduplication and Legal/Privacy notification
    scoping.
8.  Hunt enterprise-wide for `debug_tool.exe`, suspicious PsExec64 use,
    `HealthSync Update Service`, the HealthSync Run key, staging
    patterns and confirmed C2.

### 8.2 Short term --- 2 weeks

-   Restrict service accounts to documented source hosts and required
    targets; prefer/enforce Kerberos where operationally possible.
-   Prevent workstation-originated administration into production
    servers except from approved privileged administration systems.
-   Operationalize detections for nonstandard LSASS access,
    PsExec/WMI/PSRemoting from unauthorized sources, `svc_*`
    authentication from workstations, scheduled tasks, Run keys,
    Defender exclusions, log clearing, staging in user-writable paths
    and abnormal outbound transfer after staging.
-   Enable/verify PowerShell Script Block Logging and relevant Task
    Scheduler/Windows auditing.
-   Resolve whether the expected 22 April Run-key alert fired and, if
    so, why it was not actioned.
-   Validate detections against legitimate administrator baselines
    before enforcement.

### 8.3 Medium term --- 30--90 days

-   Correlate email, identity, endpoint, DNS, proxy/firewall and server
    telemetry.
-   Build behavioral analytics around source/user/target/time rather
    than static IOCs alone.
-   Strengthen privileged-access and service-account governance.
-   Improve east-west segmentation and visibility.
-   Establish exfiltration analytics for unusual outbound volume,
    periodic C2 and transfers following database access/staging.
-   Expand forensic readiness, retention and acquisition playbooks.
-   Run recurring threat hunts against ATT&CK gaps and high-risk access
    paths.
-   Reassess ATT&CK coverage only after detections are validated and
    operational.
-   Exercise breach response with Legal, Privacy, Communications and
    executive leadership.

------------------------------------------------------------------------

## 9. Conclusions

Module 4 demonstrates the difference between **detecting individual
signals** and **understanding an intrusion**. Phishing analysis
explained the lure; network forensics exposed the first C2; malware
analysis explained capability; and threat hunting found anomalous
credential access and lateral movement. None alone answered how the
stages connected, what data was actually taken, whether it left the
network and where the defensive blind spots were.

Reconstruction changed the assessment. The scheduled task showed
persistence outside the hunt scope. Deleted archives showed database
collection and staging. Firewall sessions transformed possible
exfiltration into confirmed transfer. Memory connected the live RAT to
known and secondary communications. Cross-evidence analysis also forced
correction of overconfident conclusions, including treating
Pass-the-Hash as probable rather than mechanically equating NTLM with
PtH.

Proactive hunting is therefore an operational necessity for attacks that
abuse legitimate administration. Forensic readiness is equally
necessary: without memory, disk and firewall retention, MedDefense could
not have established breach scope with comparable confidence.

Important uncertainties remain. The exact authentication mechanism
behind suspected Pass-the-Hash is not directly proven; bulk DNS
exfiltration of the recovered MedDefense datasets is not established;
complete command history during collection gaps is unavailable; disk
forensics was scoped primarily to `WS-RECV-03`; and the administrative
record contains an unresolved hunt-date/containment-date contradiction.

**Final conclusion:** HEALTHBANE achieved a persistent foothold,
credential access, lateral movement into critical systems,
sensitive-data collection, local staging and confirmed external
exfiltration before MedDefense isolated the pivot host.

------------------------------------------------------------------------

# Appendices

## Appendix A --- IOC Summary

The pre-4x05 master contains **31 IOCs**. The table below highlights the
indicators most material to the final reconstruction and the new IR
indicators; `reference/healthbane_ioc_master.json` remains the
authoritative full pre-IR list. \[E12\]

  --------------------------------------------------------------------------------------------------------------
  IOC                             Type            Role                      Sources               Final status
  ------------------------------- --------------- ------------------------- --------------------- --------------
  `meddefense-portal.com`         Domain          Credential-phishing       4x00,4x02             CONVERGED /
                                                  landing                                         HIGH

  `91.219.236.117`                IPv4            Phishing infrastructure   4x00,4x01             CONVERGED

  `update.healthbane-c2.net`      Domain          RAT delivery              4x01,4x03             CONVERGED

  `sync.healthbane-c2.net`        Domain          Primary C2                4x01,4x03,IR          CONVERGED

  `185.220.101.45:443`            IP:port         Primary C2                4x01,IR-MEM,IR-FW     CONVERGED

  `data-sync.healthbane-c2.net`   Domain          DNS channel/test          4x01,4x03             CONVERGED;
                                                  capability                                      bulk exfil
                                                                                                  unproven

  `April-Invoice-MD2026.docm`     Filename        Malicious document        4x01,4x03             CONVERGED

  `svchost_update.exe`            Process/file    Stage 2 RAT               4x03,IR-MEM,IR-DISK   CONVERGED

  `sync_healthdata.ps1`           Script          Stage 3 exfiltrator       4x03,IR-MEM,IR-DISK   CONVERGED

  `debug_tool.exe`                File/process    LSASS access              4x04,IR-MEM,IR-DISK   CONVERGED

  `svc_healthsync`                Account         Compromised service       4x04,IR-MEM,IR-DISK   CONVERGED
                                                  credential                                      

  `HealthSync Update Service`     Scheduled task  Persistence/exfiltrator   IR-MEM,IR-DISK        NEW /
                                                  execution                                       CONVERGED

  `203.0.113.47:8443`             IP:port         Attacker-associated       IR-MEM,IR-FW          NEW; role
                                                  secondary channel                               PROBABLE

  `C:\Windows\Temp` Defender      Configuration   Defense evasion           IR-MEM,IR-DISK        NEW /
  exclusion                       IOC                                                             CONVERGED

  `staging_export_<NNN>.zip`      Filename        Data staging              IR-DISK,IR-FW         NEW /
                                  pattern                                                         CONVERGED

  `out_<YYYYMMDDHHMMSS>.csv`      Filename        Collected data            IR-DISK               NEW
                                  pattern                                                         
  --------------------------------------------------------------------------------------------------------------

**IOC identifier note:** the secondary endpoint appears under
inconsistent proposed new-IOC numbering in the IR material; use
`203.0.113.47:8443` as the stable correlation key until the IOC database
is normalized.

## Appendix B --- Evidence Citation Index

  -------------------------------------------------------------------------------------
  Citation                Source                                Key contribution
  ----------------------- ------------------------------------- -----------------------
  E01                     `4x00_phishing_summary.txt`           Email campaign and
                                                                victim interaction

  E02                     `4x01_network_timeline.txt`           DNS/TLS/POST, RAT
                                                                delivery and first C2

  E03                     `4x02_attack_mapping.json`            Earlier ATT&CK
                                                                hypotheses

  E04                     `4x03_malware_summary.txt`            Malware samples and
                                                                capabilities

  E05                     `4x04_hunting_report.txt`             LSASS, lateral movement
                                                                and account abuse

  E06                     `disk_forensics_report.txt`           Persistence, staging
                                                                and anti-forensics

  E07                     `firewall_sessions_ws_recv_03.json`   C2, lateral sessions
                                                                and exfiltration

  E08                     `ir_team_notes.txt`                   Isolation, acquisition
                                                                and IR decisions

  E09                     `memory_artifacts.txt`                Live RAT, PowerShell
                                                                and active connections

  E10                     `meddefense_asset_inventory.txt`      Data sensitivity and
                                                                impact

  E11                     `network_topology.txt`                Network/host context

  E12                     `healthbane_ioc_master.json`          Pre-IR IOC baseline

  E13                     `attck_navigator_80pct.json`          Post-hunt ATT&CK
                                                                baseline
  -------------------------------------------------------------------------------------

## Appendix C --- ATT&CK Navigator Reference

**Baseline layer:** `reference/attck_navigator_80pct.json`\
**Baseline state:** 29-technique HEALTHBANE threat model, post-4x04
hunting posture.\
**Final report state:** 27 CONFIRMED, 1 PROBABLE (`T1550.002`), 1
POSSIBLE (`T1048.003`) within the fixed 29-technique denominator.

The final Navigator layer from the reconstruction workflow is the
machine-readable companion to this report. The report deliberately
distinguishes **analytically mapped** from **confirmed by evidence** so
that a high ATT&CK percentage is not mistaken for proof of operational
control effectiveness.

------------------------------------------------------------------------

**End of Report**
