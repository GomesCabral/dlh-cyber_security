# 8 --- The Detection Gap Analysis

## Objective

Compare the HEALTHBANE ATT&CK mapping from Task 7 with MedDefense's
**documented** detection capability.

This analysis intentionally does not assume that a control exists simply
because a mature SOC would normally deploy it.

Evidence considered:

-   `7-attack_navigator.md`
-   `healthbane_layer.json`
-   `meddefense_4x00_findings.txt`
-   documented 4x01 network-forensics findings and recommendations
-   completed outputs from Tasks 0--7

Tasks 5, 9 and 10 are not yet complete in the current project sequence.
Therefore, this assessment does **not** claim coverage from future
indicator-database actions or HEALTHBANE YARA rules.

## Detection status definitions

-   **DETECTED** --- a documented detection, IOC action or local
    analytic directly covers the technique.
-   **PARTIALLY DETECTED** --- relevant telemetry/indicators exist, but
    coverage is incomplete, narrow, forensic/manual or requires analyst
    review.
-   **NOT DETECTED** --- no documented detection or reliable telemetry
    currently covers the technique.

## Gap priority

1.  **Priority 1:** OBSERVED + NOT DETECTED
2.  **Priority 2:** INFERRED + NOT DETECTED
3.  **Priority 3:** PARTIALLY DETECTED
4.  Existing direct detections are retained and improved but are not
    primary gaps.

------------------------------------------------------------------------

# 1. Technique-by-Technique Detection Assessment

## T1589.002 --- Gather Victim Identity Information: Email Addresses

-   **Campaign status:** OBSERVED
-   **Current detection status:** **NOT DETECTED**
-   **Gap priority:** Priority 1
-   **Evidence:** No documented MedDefense analytic detects external
    collection of employee email addresses.
-   **Gap:** The activity occurs largely outside MedDefense visibility;
    current email/IOC controls only see later delivery.
-   **Recommendation:** Reduce exposed address harvesting where
    practical; monitor exposed identities/credential leaks and use
    threat-intel collection for targeting indicators.

## T1583.001 --- Acquire Infrastructure: Domains

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 investigated lookalike domains using
    WHOIS/registration age and IOC correlation.
-   **Gap:** This is analyst-led and campaign/IOC focused; there is no
    documented continuous analytic for newly registered lookalike
    domains.
-   **Recommendation:** Create domain-age + lexical/lookalike enrichment
    for inbound email, DNS and proxy telemetry; alert on newly
    registered healthcare/MedDefense impersonation domains.

## T1585.002 --- Establish Accounts: Email Accounts

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 email investigation examined sender addresses and
    coordinated phishing characteristics.
-   **Gap:** Sender review can identify campaign mailboxes after
    delivery but does not directly detect attacker account creation.
-   **Recommendation:** Enrich inbound senders with reputation,
    authentication and first-seen data; correlate newly seen senders
    with phishing infrastructure.

## T1587.001 --- Develop Capabilities: Malware

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 performed endpoint/artifact checks and
    IOC/hash-based investigation, but no local HEALTHBANE YARA rules
    exist yet because Tasks 9-10 are pending.
-   **Gap:** Hash/IOC coverage is narrow and misses modified malware
    variants.
-   **Recommendation:** Implement YARA/EDR behavioral detections for
    HEALTHBANE artifacts after Tasks 9-10; retain hash matching as
    supporting coverage.

## T1608.005 --- Stage Capabilities: Link Target

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 extracted and investigated phishing URLs/domains
    from messages.
-   **Gap:** Coverage depends on known or analyst-reviewed links and may
    miss newly staged domains before they are reported.
-   **Recommendation:** Add URL detonation/reputation, domain-age
    enrichment and lexical similarity detection at the secure email
    gateway/proxy.

## T1566.002 --- Phishing: Spearphishing Link

-   **Campaign status:** OBSERVED
-   **Current detection status:** **DETECTED**
-   **Gap priority:** Existing direct coverage
-   **Evidence:** 4x00 directly detected and investigated coordinated
    phishing emails containing malicious credential-harvesting links;
    MedDefense recorded the dmarsh click.
-   **Gap:** Existing coverage is strongest for known campaign
    patterns/IOCs and can still be evaded by new infrastructure.
-   **Recommendation:** Maintain email URL analytics, authentication
    checks, redirect-chain analysis and IOC enrichment; add
    behavior/domain-age signals.

## T1566.001 --- Phishing: Spearphishing Attachment

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 documented email-focused investigation and
    endpoint checks, but MedDefense did not locally observe the Stage 2
    .docm.
-   **Gap:** No documented local analytic specifically demonstrates
    detection of the HEALTHBANE macro attachment/execution chain.
-   **Recommendation:** Enable attachment sandboxing and macro-aware
    email controls; correlate Office child processes and downloaded
    executable behavior in EDR.

## T1204.001 --- User Execution: Malicious Link

-   **Campaign status:** OBSERVED
-   **Current detection status:** **DETECTED**
-   **Gap priority:** Existing direct coverage
-   **Evidence:** 4x00 captured the MedDefense user click at 2026-04-14
    15:02:33 UTC and tied it to the malicious URL.
-   **Gap:** Click visibility is useful but does not by itself prove
    credential submission or prevent future clicks.
-   **Recommendation:** Correlate email click telemetry with proxy/DNS
    sessions, identity events and endpoint/browser telemetry; trigger
    rapid credential reset workflow.

## T1204.002 --- User Execution: Malicious File

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** Endpoint/artifact review is documented, but the Stage
    2 malicious .docm was not observed locally.
-   **Gap:** No documented analytic directly demonstrates detection when
    a user opens the HEALTHBANE document.
-   **Recommendation:** Detect Office opening macro-enabled
    internet/email files and Office spawning script interpreters or
    download tools.

## T1059.005 --- Command and Scripting Interpreter: Visual Basic

-   **Campaign status:** OBSERVED
-   **Current detection status:** **NOT DETECTED**
-   **Gap priority:** Priority 1
-   **Evidence:** No documented local detection directly covers VBA
    execution from the HEALTHBANE .docm.
-   **Gap:** Email/IOC checks do not reliably detect macro execution
    after delivery.
-   **Recommendation:** Use EDR/Sysmon process telemetry and Office
    macro logging; alert on Office spawning suspicious child processes
    or network download activity.

## T1059.001 --- Command and Scripting Interpreter: PowerShell

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** Prior MedDefense work includes
    endpoint/process-oriented investigation, but no documented
    HEALTHBANE analytic directly covers sync_healthdata.ps1.
-   **Gap:** Generic process visibility is insufficient without
    PowerShell-specific logging/analytics.
-   **Recommendation:** Enable PowerShell Script Block Logging (Event ID
    4104), module logging and EDR command-line capture; detect
    encoded/suspicious network and DNS-related scripts.

## T1053.005 --- Scheduled Task/Job: Scheduled Task

-   **Campaign status:** OBSERVED
-   **Current detection status:** **NOT DETECTED**
-   **Gap priority:** Priority 1
-   **Evidence:** No documented current analytic directly detects
    creation of the 'HealthSync Update Service' scheduled task.
-   **Gap:** Known task name could be hunted manually, but that is not
    documented continuous detection.
-   **Recommendation:** Collect Windows Task Scheduler events and
    Sysmon/EDR telemetry; alert on suspicious task creation and
    specifically hunt the HEALTHBANE task name.

## T1547.001 --- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

-   **Campaign status:** OBSERVED
-   **Current detection status:** **NOT DETECTED**
-   **Gap priority:** Priority 1
-   **Evidence:** No documented current analytic directly covers
    HEALTHBANE Registry Run-key persistence.
-   **Gap:** IOC/email controls do not cover registry persistence.
-   **Recommendation:** Collect registry modification telemetry through
    Sysmon/EDR; alert on unusual Run/RunOnce changes and correlate with
    Office/PowerShell execution.

## T1056.003 --- Input Capture: Web Portal Capture

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 identified credential-harvesting pages and
    assessed dmarsh credential submission as likely.
-   **Gap:** MedDefense could identify the phishing site and click, but
    the supplied evidence did not packet-confirm credential submission.
-   **Recommendation:** Correlate click/proxy telemetry with IdP
    authentication, impossible-travel/new-device events and immediate
    credential-reset actions; block known credential-harvest domains.

## T1071.004 --- Application Layer Protocol: DNS

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x01 documented packet/DNS analysis and
    HEALTHBANE-related DNS-tunnel findings/recommendations, including
    anomalous TXT/base32 behavior.
-   **Gap:** Packet-based analysis demonstrates visibility, but no
    documented production analytic guarantees continuous detection of
    the 10--15 second TXT tunnel pattern.
-   **Recommendation:** Operationalize DNS analytics: TXT frequency,
    long/high-entropy labels, Base32-like subdomains, periodicity and
    rare-domain detection. Feed alerts into SIEM.

## T1071.001 --- Application Layer Protocol: Web Protocols

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 investigated HTTPS phishing infrastructure and
    malicious URLs; 4x01 provides network-forensics capability.
-   **Gap:** HTTPS content is often encrypted and IOC-only URL/domain
    matching is fragile when infrastructure rotates.
-   **Recommendation:** Use proxy/SWG metadata, TLS SNI/JA4 where
    available, DNS correlation, URL reputation and endpoint network
    telemetry.

## T1048.003 --- Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x01 analysis documented DNS-tunnel behavior and
    detection recommendations from packet evidence.
-   **Gap:** The capability is currently evidenced as forensic/packet
    analysis rather than a documented continuous exfiltration analytic.
-   **Recommendation:** Deploy DNS exfiltration analytics for TXT
    volume, encoded labels, periodicity and outbound data patterns;
    baseline hosts and escalate deviations.

## T1041 --- Exfiltration Over C2 Channel

-   **Campaign status:** OBSERVED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x01 network-forensics work provides packet-level
    visibility into suspicious C2/exfiltration behavior.
-   **Gap:** No documented analytic demonstrates comprehensive
    C2-channel exfiltration detection across protocols.
-   **Recommendation:** Correlate EDR network events, DNS/proxy
    telemetry and data-volume anomalies; alert when known C2 behavior
    coincides with sensitive-data access.

## T1078 --- Valid Accounts

-   **Campaign status:** INFERRED
-   **Current detection status:** **PARTIALLY DETECTED**
-   **Gap priority:** Priority 3
-   **Evidence:** 4x00 recommended/used identity and account
    investigation around likely credential exposure, but the HEALTHBANE
    use of stolen credentials was not confirmed locally.
-   **Gap:** Identity telemetry can support investigation, but no
    documented campaign-specific analytic proves detection of
    valid-account abuse.
-   **Recommendation:** Use IdP/cloud audit logs for new device, unusual
    geography/ASN, impossible travel, MFA changes, anomalous mailbox
    access and risky sign-ins.

## T1021 --- Remote Services

-   **Campaign status:** INFERRED
-   **Current detection status:** **NOT DETECTED**
-   **Gap priority:** Priority 2
-   **Evidence:** Task 7 classifies Remote Services as inferred and
    there is no documented MedDefense detection tied to HEALTHBANE
    remote-service use.
-   **Gap:** The technique is both unconfirmed in campaign evidence and
    uncovered by a documented local analytic.
-   **Recommendation:** Collect Windows logon, RDP/SMB/WinRM and EDR
    network/process telemetry; baseline administrative remote access and
    alert on anomalous source/target pairs.

------------------------------------------------------------------------

# 2. Coverage Summary

  Detection status        Count   Percentage
  -------------------- -------- ------------
  DETECTED                    2          10%
  PARTIALLY DETECTED         13          65%
  NOT DETECTED                5          25%
  **Total**              **20**     **100%**

The strongest documented coverage is currently around **phishing
investigation and malicious-link activity**.

The largest defensive weakness is that several **post-compromise
endpoint behaviors** are either not directly detected or only supported
by forensic/manual investigation.

------------------------------------------------------------------------

# 3. Prioritized Gap List

## Priority 1 --- OBSERVED and NOT DETECTED

### T1589.002 --- Gather Victim Identity Information: Email Addresses

-   **Why the gap matters:** Target identification enables the phishing
    campaign and may reveal who is likely to be attacked next.
-   **Detection idea:** Reduce exposed address harvesting where
    practical; monitor exposed identities/credential leaks and use
    threat-intel collection for targeting indicators.
-   **Required data source:** External targeting intelligence,
    leaked-credential/identity monitoring and exposed-identity review.
-   **Suggested owner:** Threat Intelligence / Exposure Management

### T1059.005 --- Command and Scripting Interpreter: Visual Basic

-   **Why the gap matters:** VBA is the observed execution bridge from
    the Stage 2 document to malware deployment.
-   **Detection idea:** Use EDR/Sysmon process telemetry and Office
    macro logging; alert on Office spawning suspicious child processes
    or network download activity.
-   **Required data source:** EDR/Sysmon + Office telemetry; detect
    VBA/macro-driven child processes and downloads.
-   **Suggested owner:** Endpoint / Detection Engineering

### T1053.005 --- Scheduled Task/Job: Scheduled Task

-   **Why the gap matters:** Scheduled-task persistence allows malware
    to survive and repeatedly execute.
-   **Detection idea:** Collect Windows Task Scheduler events and
    Sysmon/EDR telemetry; alert on suspicious task creation and
    specifically hunt the HEALTHBANE task name.
-   **Required data source:** Windows Task Scheduler events +
    EDR/Sysmon; detect suspicious task creation and the known task name.
-   **Suggested owner:** Endpoint / Detection Engineering

### T1547.001 --- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

-   **Why the gap matters:** Registry Run-key persistence provides a
    second observed mechanism for continued execution.
-   **Detection idea:** Collect registry modification telemetry through
    Sysmon/EDR; alert on unusual Run/RunOnce changes and correlate with
    Office/PowerShell execution.
-   **Required data source:** Registry telemetry via EDR/Sysmon; detect
    Run/RunOnce persistence.
-   **Suggested owner:** Endpoint / Detection Engineering

## Priority 2 --- INFERRED and NOT DETECTED

### T1021 --- Remote Services

-   **Why the gap matters:** If later confirmed, remote-service abuse
    could enable movement between systems using legitimate protocols.
-   **Detection idea:** Collect Windows logon, RDP/SMB/WinRM and EDR
    network/process telemetry; baseline administrative remote access and
    alert on anomalous source/target pairs.
-   **Required data source:** Windows logon + RDP/SMB/WinRM + EDR
    network telemetry; baseline remote administration.
-   **Suggested owner:** SOC / Detection Engineering

## Priority 3 --- PARTIALLY DETECTED

These techniques already have some visibility, but the current evidence
is too narrow, manual or IOC-dependent to call them fully detected.

### T1583.001 --- Acquire Infrastructure: Domains

-   **Why the gap matters:** This is analyst-led and campaign/IOC
    focused; there is no documented continuous analytic for newly
    registered lookalike domains.
-   **Detection idea:** Create domain-age + lexical/lookalike enrichment
    for inbound email, DNS and proxy telemetry; alert on newly
    registered healthcare/MedDefense impersonation domains.
-   **Required data source:** Email gateway, WHOIS/domain-age, DNS, URL
    reputation
-   **Suggested owner:** Email Security / Threat Intelligence

### T1585.002 --- Establish Accounts: Email Accounts

-   **Why the gap matters:** Sender review can identify campaign
    mailboxes after delivery but does not directly detect attacker
    account creation.
-   **Detection idea:** Enrich inbound senders with reputation,
    authentication and first-seen data; correlate newly seen senders
    with phishing infrastructure.
-   **Required data source:** Email gateway, WHOIS/domain-age, DNS, URL
    reputation
-   **Suggested owner:** Email Security / Threat Intelligence

### T1587.001 --- Develop Capabilities: Malware

-   **Why the gap matters:** Hash/IOC coverage is narrow and misses
    modified malware variants.
-   **Detection idea:** Implement YARA/EDR behavioral detections for
    HEALTHBANE artifacts after Tasks 9-10; retain hash matching as
    supporting coverage.
-   **Required data source:** EDR/Sysmon, Office telemetry, PowerShell
    logs, file/hash/YARA telemetry
-   **Suggested owner:** Endpoint / Detection Engineering

### T1608.005 --- Stage Capabilities: Link Target

-   **Why the gap matters:** Coverage depends on known or
    analyst-reviewed links and may miss newly staged domains before they
    are reported.
-   **Detection idea:** Add URL detonation/reputation, domain-age
    enrichment and lexical similarity detection at the secure email
    gateway/proxy.
-   **Required data source:** Email gateway, WHOIS/domain-age, DNS, URL
    reputation
-   **Suggested owner:** Email Security / Threat Intelligence

### T1566.001 --- Phishing: Spearphishing Attachment

-   **Why the gap matters:** No documented local analytic specifically
    demonstrates detection of the HEALTHBANE macro attachment/execution
    chain.
-   **Detection idea:** Enable attachment sandboxing and macro-aware
    email controls; correlate Office child processes and downloaded
    executable behavior in EDR.
-   **Required data source:** EDR/Sysmon, Office telemetry, PowerShell
    logs, file/hash/YARA telemetry
-   **Suggested owner:** Endpoint / Detection Engineering

### T1204.002 --- User Execution: Malicious File

-   **Why the gap matters:** No documented analytic directly
    demonstrates detection when a user opens the HEALTHBANE document.
-   **Detection idea:** Detect Office opening macro-enabled
    internet/email files and Office spawning script interpreters or
    download tools.
-   **Required data source:** EDR/Sysmon, Office telemetry, PowerShell
    logs, file/hash/YARA telemetry
-   **Suggested owner:** Endpoint / Detection Engineering

### T1059.001 --- Command and Scripting Interpreter: PowerShell

-   **Why the gap matters:** Generic process visibility is insufficient
    without PowerShell-specific logging/analytics.
-   **Detection idea:** Enable PowerShell Script Block Logging (Event ID
    4104), module logging and EDR command-line capture; detect
    encoded/suspicious network and DNS-related scripts.
-   **Required data source:** EDR/Sysmon, Office telemetry, PowerShell
    logs, file/hash/YARA telemetry
-   **Suggested owner:** Endpoint / Detection Engineering

### T1056.003 --- Input Capture: Web Portal Capture

-   **Why the gap matters:** MedDefense could identify the phishing site
    and click, but the supplied evidence did not packet-confirm
    credential submission.
-   **Detection idea:** Correlate click/proxy telemetry with IdP
    authentication, impossible-travel/new-device events and immediate
    credential-reset actions; block known credential-harvest domains.
-   **Required data source:** IdP/cloud audit logs, email click
    telemetry, proxy/DNS
-   **Suggested owner:** Identity / SOC

### T1071.004 --- Application Layer Protocol: DNS

-   **Why the gap matters:** Packet-based analysis demonstrates
    visibility, but no documented production analytic guarantees
    continuous detection of the 10--15 second TXT tunnel pattern.
-   **Detection idea:** Operationalize DNS analytics: TXT frequency,
    long/high-entropy labels, Base32-like subdomains, periodicity and
    rare-domain detection. Feed alerts into SIEM.
-   **Required data source:** DNS, proxy/SWG, PCAP/flow, EDR network
    telemetry
-   **Suggested owner:** Network / Detection Engineering

### T1071.001 --- Application Layer Protocol: Web Protocols

-   **Why the gap matters:** HTTPS content is often encrypted and
    IOC-only URL/domain matching is fragile when infrastructure rotates.
-   **Detection idea:** Use proxy/SWG metadata, TLS SNI/JA4 where
    available, DNS correlation, URL reputation and endpoint network
    telemetry.
-   **Required data source:** DNS, proxy/SWG, PCAP/flow, EDR network
    telemetry
-   **Suggested owner:** Network / Detection Engineering

### T1048.003 --- Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

-   **Why the gap matters:** The capability is currently evidenced as
    forensic/packet analysis rather than a documented continuous
    exfiltration analytic.
-   **Detection idea:** Deploy DNS exfiltration analytics for TXT
    volume, encoded labels, periodicity and outbound data patterns;
    baseline hosts and escalate deviations.
-   **Required data source:** DNS, proxy/SWG, PCAP/flow, EDR network
    telemetry
-   **Suggested owner:** Network / Detection Engineering

### T1041 --- Exfiltration Over C2 Channel

-   **Why the gap matters:** No documented analytic demonstrates
    comprehensive C2-channel exfiltration detection across protocols.
-   **Detection idea:** Correlate EDR network events, DNS/proxy
    telemetry and data-volume anomalies; alert when known C2 behavior
    coincides with sensitive-data access.
-   **Required data source:** DNS, proxy/SWG, PCAP/flow, EDR network
    telemetry
-   **Suggested owner:** Network / Detection Engineering

### T1078 --- Valid Accounts

-   **Why the gap matters:** Identity telemetry can support
    investigation, but no documented campaign-specific analytic proves
    detection of valid-account abuse.
-   **Detection idea:** Use IdP/cloud audit logs for new device, unusual
    geography/ASN, impossible travel, MFA changes, anomalous mailbox
    access and risky sign-ins.
-   **Required data source:** IdP/cloud audit logs, email click
    telemetry, proxy/DNS
-   **Suggested owner:** Identity / SOC

------------------------------------------------------------------------

# 4. Most Important Detection Improvements

## A. Detect the Stage 2 execution chain

Current phishing coverage is stronger than endpoint execution coverage.

Priority analytic:

``` text
Email attachment .docm
        ↓
WINWORD.EXE
        ↓
VBA / suspicious child process
        ↓
PowerShell or network download
        ↓
svchost_update.exe
```

Required telemetry:

-   EDR process creation;
-   Sysmon process events;
-   Office/macro telemetry;
-   PowerShell Script Block Logging;
-   file hash/YARA telemetry.

------------------------------------------------------------------------

## B. Detect HEALTHBANE persistence

Two persistence mechanisms were observed in the campaign:

-   scheduled task `HealthSync Update Service`;
-   Registry Run key.

Required telemetry:

-   Windows Task Scheduler operational logs;
-   Sysmon/EDR process and task telemetry;
-   registry modification telemetry.

Detection should include the known HEALTHBANE artifacts but also
behavioral rules so renamed variants are still detected.

------------------------------------------------------------------------

## C. Operationalize DNS-tunnel detection

4x01 demonstrates that MedDefense can investigate suspicious DNS
behavior from packet evidence.

The remaining gap is to convert that forensic capability into a
repeatable analytic.

Detection features should include:

-   unusual TXT query volume;
-   10--15 second periodicity;
-   long subdomain labels;
-   Base32-like character patterns;
-   high-entropy labels;
-   rare domains;
-   repeated outbound queries from a single host;
-   correlation with sensitive-data access.

This is more resilient than blocking only `data-sync.healthbane-c2.net`.

------------------------------------------------------------------------

## D. Strengthen identity monitoring

Stage 1 exists to obtain credentials.

Useful identity analytics include:

-   new device;
-   new ASN/geography;
-   impossible travel;
-   suspicious mailbox access;
-   MFA/security-setting changes;
-   unusual inbox/forwarding rules;
-   sign-in shortly after a confirmed phishing click.

This would help determine whether a likely credential submission became
actual account compromise.

------------------------------------------------------------------------

# 5. Effect of Future Tasks 5, 9 and 10

This gap analysis represents the documented capability **at the time of
Task 8**.

After Tasks 5, 9 and 10 are completed, the assessment should be
revisited.

Expected changes may include:

-   Task 5 indicator actions improving IOC-based domain/IP/hash
    coverage;
-   Tasks 9--10 YARA rules improving malicious-file and malware-artifact
    detection.

Those future controls are **not counted as current detection
capability** in this version because they do not yet exist as completed
local outputs.

------------------------------------------------------------------------

# 6. SOC Conclusion

The principal defensive lesson is:

``` text
MedDefense currently sees the phishing stage better
than the post-compromise execution and persistence stages.
```

The highest-value improvement is therefore not simply adding more
HEALTHBANE IOCs.

The SOC should prioritize telemetry and behavioral analytics that
detect:

``` text
Macro / VBA execution
        ↓
PowerShell / malware execution
        ↓
Scheduled Task + Registry persistence
        ↓
Suspicious DNS C2 / tunneling
        ↓
Data exfiltration
```

This approach remains useful even after HEALTHBANE changes its domains,
IP addresses, filenames or hashes.
