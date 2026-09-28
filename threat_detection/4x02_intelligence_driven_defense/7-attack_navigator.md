# 7 --- The ATT&CK Navigator

## Objective

Map HEALTHBANE behavior to MITRE ATT&CK while preserving the distinction
between **OBSERVED** behavior and **INFERRED** hunting hypotheses.

Classification rule used in this project:

-   **OBSERVED** --- directly described as observed or supported by
    campaign evidence in `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` and/or
    `meddefense_4x00_findings.txt`.
-   **INFERRED** --- plausible and analytically useful, but not directly
    confirmed by the supplied evidence.

The Navigator layer uses:

-   **OBSERVED = score 100 / red / high priority**
-   **INFERRED = score 50 / amber / medium priority**

------------------------------------------------------------------------

# 1. Techniques by Tactic

## Reconnaissance

### T1589.002 --- Gather Victim Identity Information: Email Addresses

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Target email addresses were collected for
    healthcare spear-phishing operations.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Pre-attack / Stage 1 preparation

## Resource Development

### T1583.001 --- Acquire Infrastructure: Domains

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Healthcare-themed lookalike domains were
    registered shortly before campaign use.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`;
    `meddefense_4x00_findings.txt`
-   **Attack phase:** Pre-attack

### T1585.002 --- Establish Accounts: Email Accounts

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Attacker-controlled email accounts were
    used as part of the phishing infrastructure.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Pre-attack / Stage 1

### T1587.001 --- Develop Capabilities: Malware

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Campaign-specific malware/tooling was
    used, including svchost_update.exe and supporting scripts.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2 preparation

### T1608.005 --- Stage Capabilities: Link Target

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Credential-harvesting URLs were staged on
    lookalike healthcare domains and delivered to targets.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`;
    `meddefense_4x00_findings.txt`
-   **Attack phase:** Stage 1

## Initial Access

### T1566.002 --- Phishing: Spearphishing Link

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Stage 1 emails directed healthcare staff
    to credential-harvesting links. MedDefense directly observed a user
    click.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`;
    `meddefense_4x00_findings.txt`
-   **Attack phase:** Stage 1

### T1566.001 --- Phishing: Spearphishing Attachment

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Compromised mailboxes sent follow-up
    emails containing HEALTHBANE_S2_invoice.docm.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2

## Execution

### T1204.001 --- User Execution: Malicious Link

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Victims were induced to open malicious
    links; MedDefense recorded the dmarsh click.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`;
    `meddefense_4x00_findings.txt`
-   **Attack phase:** Stage 1

### T1204.002 --- User Execution: Malicious File

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Stage 2 required the malicious
    macro-enabled document to be opened by a user.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2

### T1059.005 --- Command and Scripting Interpreter: Visual Basic

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** VBA macro execution in the .docm initiated
    the Stage 2 malware chain.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2

### T1059.001 --- Command and Scripting Interpreter: PowerShell

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** PowerShell artifact sync_healthdata.ps1
    was associated with the campaign execution/exfiltration chain.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2 / Stage 3

## Persistence

### T1053.005 --- Scheduled Task/Job: Scheduled Task

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Persistence used the scheduled task
    'HealthSync Update Service'.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2

### T1547.001 --- Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** A Registry Run key was used as an
    additional persistence mechanism.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2

## Credential Access

### T1056.003 --- Input Capture: Web Portal Capture

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Lookalike web portals captured usernames
    and passwords. MedDefense assessed one local credential submission
    as likely.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`;
    `meddefense_4x00_findings.txt`
-   **Attack phase:** Stage 1

## Command and Control

### T1071.004 --- Application Layer Protocol: DNS

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Stage 3 used DNS TXT traffic and encoded
    subdomain labels for command traffic and tunneling.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 3

### T1071.001 --- Application Layer Protocol: Web Protocols

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** HTTPS/web infrastructure was used for
    credential harvesting and malware retrieval.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`;
    `meddefense_4x00_findings.txt`
-   **Attack phase:** Stages 1--2

## Exfiltration

### T1048.003 --- Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** Patient and insurance data were encoded
    into DNS traffic; HC3 maps the observed alternative-protocol
    exfiltration to T1048.003.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 3

### T1041 --- Exfiltration Over C2 Channel

-   **Classification:** OBSERVED
-   **Evidence / reasoning:** HC3 maps campaign data movement over the
    established attacker-controlled channel to T1041.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 3

## Defense Evasion / Persistence / Privilege Escalation / Initial Access

### T1078 --- Valid Accounts

-   **Classification:** INFERRED
-   **Evidence / reasoning:** HC3 assesses that stolen credentials were
    likely used to access cloud email accounts, but excludes this
    technique from its observed table pending confirmation.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 1 → Stage 2

## Lateral Movement

### T1021 --- Remote Services

-   **Classification:** INFERRED
-   **Evidence / reasoning:** Remote-service use is a plausible
    follow-on behavior and is identified by HC3 as likely, but the
    supplied evidence does not directly confirm it.
-   **Source:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   **Attack phase:** Stage 2

------------------------------------------------------------------------

# 2. Mapping Summary

-   **Total techniques identified:** 20
-   **OBSERVED:** 18
-   **INFERRED:** 2
-   **Observed vs inferred ratio:** 18:2 (**90% observed / 10%
    inferred**)

## Tactics with the most coverage

The largest single-tactic coverage is:

-   **Resource Development --- 4 techniques**
-   **Execution --- 4 techniques**

These areas are well represented because the sources describe both
attacker preparation and the Stage 2 execution chain in detail.

## Tactics with the least coverage

Single-technique areas include:

-   **Reconnaissance --- 1**
-   **Credential Access --- 1**
-   **Lateral Movement --- 1 inferred technique**

`T1078 Valid Accounts` spans multiple ATT&CK tactics, but it remains
**INFERRED** in this assessment rather than being counted as direct
evidence of each tactic.

The limited coverage does not prove that the adversary performed no
other techniques. It means the supplied intelligence does not provide
sufficient evidence to map additional behavior honestly.

------------------------------------------------------------------------

# 3. Detection-Planning Priorities

The most operationally useful techniques for detection planning are:

  -----------------------------------------------------------------------
  Technique                           Why it matters
  ----------------------------------- -----------------------------------
  **T1566.002 --- Spearphishing       Detects the initial Stage 1
  Link**                              delivery mechanism.

  **T1056.003 --- Web Portal          Focuses investigation on
  Capture**                           credential-harvesting pages and
                                      likely credential loss.

  **T1566.001 --- Spearphishing       Detects the transition to Stage 2
  Attachment**                        through trusted/compromised email.

  **T1059.005 --- Visual Basic**      Detects malicious macro execution
                                      from the Stage 2 `.docm`.

  **T1059.001 --- PowerShell**        Detects campaign scripting such as
                                      `sync_healthdata.ps1`.

  **T1053.005 --- Scheduled Task**    Detects the known
                                      `HealthSync Update Service`
                                      persistence mechanism.

  **T1547.001 --- Registry Run Keys** Detects the second observed
                                      persistence mechanism.

  **T1071.004 --- DNS**               Critical for detecting Stage 3 DNS
                                      command traffic/tunneling.

  **T1048.003 --- Alternative         Directly addresses the observed
  Protocol Exfiltration**             DNS-based data exfiltration
                                      behavior.
  -----------------------------------------------------------------------

For HEALTHBANE, detections should cover the chain rather than relying
only on static IOCs:

``` text
Phishing
   ↓
Credential harvesting
   ↓
Malicious internal attachment
   ↓
VBA / PowerShell execution
   ↓
Persistence
   ↓
DNS C2 / tunneling
   ↓
Exfiltration
```

------------------------------------------------------------------------

# 4. Observed vs Inferred Analytical Note

The distinction between `OBSERVED` and `INFERRED` is intentionally
strict.

For example:

### T1078 --- Valid Accounts

Stolen credentials being used to access cloud email accounts is
consistent with the campaign narrative and is identified by HC3 as
likely.

However, because HC3 does not include it in the observed-technique
table, this project records it as:

**INFERRED --- score 50**

### T1021 --- Remote Services

Remote Services is also identified as likely but is not directly
supported by the supplied observed evidence.

It is therefore:

**INFERRED --- score 50**

This prevents the ATT&CK layer from presenting hunting hypotheses as
confirmed attacker behavior.

------------------------------------------------------------------------

# 5. SOC Interpretation

The ATT&CK layer is not a list of everything HEALTHBANE *could* have
done. It represents what the available evidence supports.

A SOC analyst can use the layer in two ways:

-   **Score 100 / OBSERVED:** prioritize detections because the behavior
    has evidence in this campaign.
-   **Score 50 / INFERRED:** use as hunting hypotheses and collect
    additional telemetry before promoting them to observed.

This makes the Navigator layer useful both for immediate detection
engineering and for identifying intelligence gaps.
