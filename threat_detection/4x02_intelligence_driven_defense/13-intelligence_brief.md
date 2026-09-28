# 13 --- HEALTHBANE Intelligence Brief

**Audience:** MedDefense leadership and healthcare-sector partners\
**Campaign:** HEALTHBANE\
**Assessment date:** 2026-09-28\
**Overall campaign reconstruction confidence:** **HIGH**\
**Named threat-actor attribution:** **UNCONFIRMED**

> **Scope note:** This brief synthesizes the supplied intelligence
> sources and the project outputs actually completed to date. Tasks 5
> and 12 are not present as completed local deliverables, and this
> project has no Task 10. Therefore, the IOC table below is
> reconstructed from validated source/triage evidence rather than
> attributed to a nonexistent Task 5 database, and the adversary profile
> is an evidence-based synthesis rather than a claimed Task 12 result.

# 1. Executive Summary

HEALTHBANE is a healthcare-focused phishing and post-compromise campaign
that uses lookalike domains and credential-harvesting pages before
progressing, in confirmed external cases, to malicious document
delivery, malware persistence and DNS-based data exfiltration.\
MedDefense was directly targeted during Stage 1; one employee clicked a
malicious link and likely submitted credentials, but the supplied
MedDefense evidence did not confirm subsequent Stage 2 malware execution
or Stage 3 exfiltration locally.\
HC3 reporting states that at least 14 U.S. healthcare organizations were
targeted, with six directly or partner-observed by HC3 and two of those
six progressing through all three documented stages.\
At those progressed organizations, compromised cloud email accounts were
used for follow-up phishing, a macro-enabled document deployed malware
and persistence, and patient/insurance information was exfiltrated
through encoded DNS TXT traffic.\
MedDefense's documented posture is strongest at phishing/link
investigation and weaker for post-compromise endpoint execution,
persistence and continuous DNS-exfiltration detection.\
The first recommended action is to reset/review potentially exposed
credentials and hunt cloud identity/mailbox activity associated with the
MedDefense phishing victim and campaign period.\
The second is to operationalize endpoint detections for Office/VBA,
PowerShell, scheduled-task and Registry Run-key behavior.\
The third is to deploy continuous DNS-tunneling analytics and campaign
IOC/YARA coverage while avoiding indiscriminate blocking of shared
cloud/CDN infrastructure.

# 2. Adversary Profile

## 2.1 What is known

HEALTHBANE is the campaign designation used throughout this assessment.
The activity is healthcare-focused and demonstrates a multi-stage
operational model:

1.  recently registered healthcare-themed/lookalike infrastructure;
2.  targeted credential-harvesting email;
3.  use of compromised cloud mailboxes in confirmed external cases;
4.  follow-up delivery of a macro-enabled document;
5.  malware execution and persistence;
6.  command-and-control and data exfiltration using DNS.

The campaign shows repeatable infrastructure and tooling patterns,
including `PHPMailer 6.6.0`, healthcare-themed lure pages,
`wkhtmltopdf 0.12.6` PDF generation, macro-enabled documents,
PowerShell-associated tooling and DNS TXT traffic.

## 2.2 Motivation

HC3 assesses the activity with **MODERATE confidence** as financially
motivated mid-tier cybercrime. The observed theft of patient records and
insurance claims data is consistent with financially useful healthcare
data, but the supplied evidence does not establish the actor's ultimate
monetization mechanism.

## 2.3 Attribution

Named actor attribution remains **UNCONFIRMED**.

-   **HEALTHBANE** --- campaign designation; not proof of a named actor.
-   **VITALSCORE** --- Acme commercial feed's proprietary cluster label;
    not established as a one-to-one actor identity.
-   **APT-MEDAGENT** --- researcher's **MEDIUM-confidence** hypothesis
    based on tooling and infrastructure overlap.
-   No supplied evidence is sufficient to convert those labels into
    confirmed actor attribution.

This distinction matters operationally: defenders can act confidently on
confirmed campaign behavior without overstating who is behind it.

# 3. Campaign Analysis

## 3.1 Stage 1 --- Credential Harvesting

**Confidence: HIGH**

Healthcare-themed phishing emails directed victims to lookalike domains
hosting credential-harvesting pages. HC3 reports Stage 1 across all six
organizations within its direct/partner visibility; this means the
phishing stage was observed, not that credentials were successfully
stolen from every organization.

At MedDefense, three coordinated phishing messages were confirmed.
Employee `dmarsh` on `WS-NURSE-04` clicked the malicious link on
**2026-04-14 15:02:33 UTC**. Credential submission at approximately
**15:02:58 UTC** is assessed **LIKELY / MEDIUM confidence** from session
duration and the user's statement, but was not directly confirmed in the
supplied packet evidence.

At the close of the MedDefense 4x00 investigation, there was no
confirmed follow-on exploitation.

## 3.2 Stage 2 --- Malware Delivery and Persistence

**Confidence: HIGH for affected external organizations; not observed
locally at MedDefense**

HC3 reports Stage 2 at two of its six visible organizations. Stolen
credentials were used to access cloud email accounts, and compromised
accounts then sent trusted follow-up messages containing
`HEALTHBANE_S2_invoice.docm`.

The document's VBA macro downloaded `svchost_update.exe`. Persistence
included:

-   scheduled task `HealthSync Update Service`;
-   Registry Run-key persistence.

MedDefense's 4x00 endpoint scan did not identify the known Stage 2 hash,
so the supplied local evidence does **not** establish that MedDefense
reached this phase.

## 3.3 Stage 3 --- Data Exfiltration

**Confidence: HIGH for the two HC3-observed progressed organizations;
scope incomplete**

HC3 reports that the two progressed organizations experienced
exfiltration of patient records and insurance claims data. HEALTHBANE
encoded data in Base32-like DNS subdomain labels and transmitted it
using DNS TXT traffic to:

`data-sync.healthbane-c2.net`

Observed characteristics included approximately 10--15 second query
intervals and long encoded subdomain labels. The supplied evidence does
not establish the exact number of records, bytes, affected patients,
complete exfiltration period or later use of the stolen data.

## 3.4 Timeline

  -----------------------------------------------------------------------
  Date / period           Event                   Confidence
  ----------------------- ----------------------- -----------------------
  2026-04-05 to           Healthcare-themed       HIGH
  2026-04-10              lookalike               
                          infrastructure          
                          registered              

  2026-04-14              Earliest reported       HIGH
                          HEALTHBANE phishing     
                          activity                

  2026-04-14 15:02:33 UTC MedDefense employee     HIGH
                          clicks malicious link   

  \~2026-04-14 15:02:58   MedDefense credential   MEDIUM
  UTC                     submission assessed     
                          likely                  

  2026-04-14 to           Primary Stage 1 window  HIGH
  2026-04-16                                      

  2026-04-16              MedDefense 4x00 closes  HIGH
                          without confirmed Stage 
                          2/3                     

  2026-04-16 to           Stage 2 observed at two HIGH
  2026-04-22              HC3-visible             
                          organizations           

  2026-04-18              Researcher receives     HIGH
                          campaign phishing       
                          sample                  

  \~2026-04-22            Researcher reports kit  MEDIUM/HIGH
                          takedown and shares     
                          findings with HC3       

  2026-04-23 to           Stage 3 window at two   HIGH
  2026-04-26              progressed              
                          organizations           

  2026-04-24              Researcher analysis     HIGH
                          published               

  2026-04-25              HC3 advisory published  HIGH

  2026-04-26              Most recent operational HIGH for represented
                          date represented in     window; exact final
                          supplied intelligence   event unknown
  -----------------------------------------------------------------------

# 4. ATT&CK Mapping

Task 7 mapped **20 ATT&CK techniques**: **18 OBSERVED (90%)** and **2
INFERRED (10%)**.

**OBSERVED** means the behavior is directly described or supported by
supplied campaign evidence. **INFERRED** means it is plausible and
useful for hunting but is not directly confirmed.

Key defensive techniques include:

  -----------------------------------------------------------------------------
  ATT&CK            Technique         Status            Detection relevance
  ----------------- ----------------- ----------------- -----------------------
  T1566.002         Phishing:         OBSERVED          Detect initial
                    Spearphishing                       credential-harvesting
                    Link                                delivery

  T1056.003         Input Capture:    OBSERVED          Identify
                    Web Portal                          credential-harvesting
                    Capture                             sites and exposed
                                                        identities

  T1566.001         Phishing:         OBSERVED          Detect Stage 2 `.docm`
                    Spearphishing                       delivery
                    Attachment                          

  T1059.005         Command and       OBSERVED          Detect macro execution
                    Scripting                           
                    Interpreter:                        
                    Visual Basic                        

  T1059.001         Command and       OBSERVED          Detect script-based
                    Scripting                           post-compromise
                    Interpreter:                        activity
                    PowerShell                          

  T1053.005         Scheduled         OBSERVED          Detect HEALTHBANE
                    Task/Job:                           persistence
                    Scheduled Task                      

  T1547.001         Registry Run Keys OBSERVED          Detect secondary
                    / Startup Folder                    persistence

  T1071.004         Application Layer OBSERVED          Detect DNS C2/tunneling
                    Protocol: DNS                       

  T1048.003         Exfiltration Over OBSERVED          Detect DNS-based
                    Alternative                         exfiltration behavior
                    Protocol                            

  T1041             Exfiltration Over OBSERVED          Correlate C2 with
                    C2 Channel                          sensitive-data movement

  T1078             Valid Accounts    INFERRED          Hunt for
                                                        stolen-credential use

  T1021             Remote Services   INFERRED          Hunt possible lateral
                                                        movement
  -----------------------------------------------------------------------------

The distinction is operationally important: `T1078` and `T1021` should
be hunted, but they should not be reported as confirmed HEALTHBANE
behavior from the supplied evidence.

# 5. Detection Gap Assessment

The Task 8 assessment found:

-   **DETECTED:** 2 / 20 techniques --- 10%
-   **PARTIALLY DETECTED:** 13 / 20 --- 65%
-   **NOT DETECTED:** 5 / 20 --- 25%

## Priority 1 --- OBSERVED and NOT DETECTED

  ------------------------------------------------------------------------------
  Technique               Why it matters          Required improvement
  ----------------------- ----------------------- ------------------------------
  T1589.002 --- Gather    Supports targeting      Exposure/threat-intelligence
  Victim Email Addresses  before delivery         monitoring; reduce unnecessary
                                                  public address exposure

  T1059.005 --- Visual    Execution bridge from   Office macro + EDR/Sysmon
  Basic                   malicious `.docm` to    child-process analytics
                          malware                 

  T1053.005 --- Scheduled Confirmed persistence   Task Scheduler + EDR/Sysmon
  Task                    mechanism               detection

  T1547.001 --- Registry  Confirmed persistence   Registry modification
  Run Keys                mechanism               telemetry and Run/RunOnce
                                                  analytics
  ------------------------------------------------------------------------------

## Priority 2 --- INFERRED and NOT DETECTED

**T1021 --- Remote Services:** collect and baseline RDP, SMB, WinRM,
Windows logon and EDR network telemetry. This remains a hunting
hypothesis, not confirmed campaign behavior.

## Priority 3 --- Partial coverage

The largest partial-coverage areas are malicious attachment/file
execution, PowerShell, credential capture, DNS C2 and exfiltration.
Existing forensic visibility should be converted into continuous
analytics rather than relying on analyst-led retrospective
investigation.

The central defensive finding is:

> MedDefense currently has stronger documented visibility into the
> phishing stage than into post-compromise execution, persistence and
> exfiltration.

# 6. Indicator of Compromise Table

Because no completed Task 5 indicator database is present, this table
uses the strongest validated indicators from the supplied sources and
Task 1 triage. It does **not** represent a fabricated Task 5 output.

  ---------------------------------------------------------------------------------------------------------------------------------------
  Phase          Indicator                                                            Type           Confidence     Recommended action
  -------------- -------------------------------------------------------------------- -------------- -------------- ---------------------
  Stage 1        `meddefense-portal.com`                                              Domain         HIGH           Block/filter where
                                                                                                                    appropriate;
                                                                                                                    DNS/proxy/email hunt

  Stage 1        `medequip-supplies.net`                                              Domain         HIGH           Block/filter;
                                                                                                                    historical hunt

  Stage 1        `meddefense-benefits.org`                                            Domain         HIGH           Block/filter;
                                                                                                                    historical hunt

  Stage 1        `outlook-protection.com`                                             Domain         HIGH           Filter/hunt; note
                                                                                                                    attacker-controlled
                                                                                                                    domain can pass
                                                                                                                    SPF/DKIM/DMARC

  Stage 1        `91.234.99.107`                                                      IP             HIGH           Hunt and scoped block
                                                                                                                    if operationally safe

  Stage 1        `185.176.43.22`                                                      IP             HIGH           Hunt and scoped block
                                                                                                                    if operationally safe

  Stage 1        `164.90.218.73`                                                      IP             HIGH           Hunt/correlate

  Stage 1        `51.38.42.17`                                                        IP             HIGH           Hunt/correlate

  Stage 1        `/verify`, `/portal`, `/enroll`, `token=`, `id=` on confirmed lure   URL pattern    HIGH           Email/proxy
                 infrastructure                                                                      contextual     detection; do not
                                                                                                     pattern        block generic path
                                                                                                                    strings globally

  Stage 2/3      `healthbane-c2.net`                                                  Domain         HIGH           High-priority
                                                                                                                    DNS/proxy/EDR hunt
                                                                                                                    and block

  Stage 3        `data-sync.healthbane-c2.net`                                        Domain         HIGH           Block plus hunt for
                                                                                                                    historical
                                                                                                                    TXT/encoded-label
                                                                                                                    traffic

  Stage 2        `update-healthbane.net`                                              Domain         MEDIUM         Alert/hunt; validate
                                                                                                                    before broad
                                                                                                                    enforcement

  Stage 2/3      `51.38.42.191`                                                       IP             HIGH           High-priority
                                                                                                                    hunt/scoped block

  Stage 2        `45.77.218.9`                                                        IP             MEDIUM         Alert/hunt and
                                                                                                                    corroborate

  Stage 2        `a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456`   SHA-256        HIGH           EDR/file hunt;
                                                                                                                    quarantine confirmed
                                                                                                                    match

  Stage 2        `b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654`   SHA-256        HIGH           EDR/file hunt;
                                                                                                                    quarantine confirmed
                                                                                                                    match

  Stage 2        `c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`   SHA-256        HIGH           EDR/file hunt;
                                                                                                                    quarantine confirmed
                                                                                                                    match

  Stage 2        `https://healthbane-c2.net/update/svchost_update.exe`                URL            HIGH           Block and historical
                                                                                                                    proxy/EDR hunt
  ---------------------------------------------------------------------------------------------------------------------------------------

### IOC handling cautions

Do **not** blindly block shared Azure, Microsoft, Cloudflare, CDN or
multi-tenant hosting IPs identified only through weak commercial
clustering. These were downgraded because broad blocking could disrupt
legitimate services.

The purported SHA-256 for `INV-2026-04891.pdf` is only 62 hexadecimal
characters and is therefore invalid as a SHA-256 value until
corrected/validated.

# 7. YARA Rule Summary

## HEALTHBANE_Phishing_PDF

File:

`9-yara_phishing_pdf.yar`

Purpose: detect HEALTHBANE-style phishing PDF lures through a
combination of:

-   `%PDF` magic;
-   `wkhtmltopdf`;
-   credential-harvesting paths such as `/verify`, `/login`, `/portal`,
    `/enroll`;
-   URL parameters such as `token=` and `id=`.

The rule deliberately requires multiple independent signals rather than
a single campaign domain, improving resilience to infrastructure
rotation.

Controlled corpus evaluation:

  Sample                     Expected    Result
  -------------------------- ----------- ----------
  `phishing_sample.pdf`      Malicious   MATCH
  `healthbane_lure_02.pdf`   Malicious   MATCH
  `clean_invoice.pdf`        Benign      NO MATCH
  `benign_invoice.pdf`       Benign      NO MATCH

For the relevant PDF corpus this corresponds to:

-   TP: 2
-   TN: 2
-   FP: 0
-   FN: 0
-   detection rate: 100%
-   false-positive rate: 0%
-   precision: 100%

**Deployment status: DEPLOY in controlled testing / MONITOR in
production.**

The perfect controlled-corpus result does not prove broad production
performance. The rule should initially be deployed in alert/hunt mode
and measured against a larger benign PDF population.

No Task 10 rule exists in this project. `11-yara_testing.sh` was
therefore adapted to test available `.yar` rules rather than inventing a
nonexistent arsenal.

# 8. Recommendations

## Immediate --- within 48 hours

1.  **Identity containment and retrospective review:** reset or verify
    credentials associated with the likely MedDefense exposure; review
    cloud sign-ins, mailbox access, forwarding/inbox rules, MFA/security
    changes, new devices, geography/ASN anomalies and activity
    immediately following the phishing click.
2.  **Campaign-wide hunt:** search email, DNS, proxy, EDR and available
    historical telemetry for the HIGH-confidence domains, IPs, hashes,
    URLs and the `HealthSync Update Service` persistence name.
3.  **Block high-confidence dedicated infrastructure:** apply scoped
    controls to confirmed HEALTHBANE domains/C2 while avoiding broad
    blocking of shared cloud/CDN infrastructure.

## Short-term --- within 2 weeks

1.  Implement Office/VBA detections for macro-enabled documents,
    suspicious Office child processes and network downloads.
2.  Enable/verify PowerShell Script Block Logging and EDR
    command-line/process visibility.
3.  Implement Scheduled Task and Registry Run/RunOnce persistence
    analytics.
4.  Operationalize DNS analytics for TXT frequency, 10--15 second
    periodicity, long/high-entropy or Base32-like labels and rare
    domains.
5.  Deploy `HEALTHBANE_Phishing_PDF` initially in monitored alert/hunt
    mode and measure production false positives.

## Medium-term --- within 30 days

1.  Correlate secure email gateway, identity, EDR, DNS and proxy events
    into a campaign-aware detection chain.
2.  Add newly registered/lookalike domain analytics rather than
    depending solely on static blocklists.
3.  Establish recurring healthcare-sector intelligence exchange for
    HEALTHBANE infrastructure and victimology.
4.  Build regression testing for detection rules using malicious
    variants and a substantially larger benign corpus.
5.  Reassess the Task 8 gap matrix after the new telemetry and analytics
    are operational.

# 9. Intelligence Gaps and Collection Priorities

  ------------------------------------------------------------------------------
  Intelligence gap  Why it matters    Collection required      Owner / source to
                                                               ask
  ----------------- ----------------- ------------------------ -----------------
  Was the           Determines        Proxy/session evidence,  SOC + Identity
  MedDefense        whether Stage 1   identity logs,           team
  credential        became account    user/account             
  actually          compromise        investigation            
  submitted?                                                   

  Were the exposed  Could reveal      Cloud IdP and mailbox    Identity / M365
  credentials later missed Stage 2    audit logs around/after  administrators
  used?             activity          2026-04-14               

  Did MedDefense    Tests whether a   Mail trace, message      Email Security
  receive internal  mailbox was       audit and sender mailbox 
  follow-up         compromised       logs                     
  phishing?                                                    

  Did any           Determines        EDR/Sysmon, file         Endpoint / DFIR
  MedDefense        whether endpoint  telemetry, Office        
  endpoint execute  compromise        process trees, hash/YARA 
  the Stage 2       occurred          hunt                     
  `.docm` or                                                   
  malware?                                                     

  Was HEALTHBANE    Detects durable   Task Scheduler logs,     Endpoint / DFIR
  persistence       compromise        Registry Run/RunOnce     
  created locally?                    telemetry                

  Did MedDefense    Could reveal      Historical DNS, proxy,   Network/SOC
  communicate with  missed            firewall and EDR network 
  Stage 2/3 C2?     progression       logs                     

  Was there         Determines        Full DNS logs/PCAP, TXT  Network / SOC
  DNS-based         potential data    queries, encoded-label   
  exfiltration from loss              analytics                
  MedDefense?                                                  

  What exact data   Defines sector    Partner/HC3 victim       HC3 / sector
  was stolen at     risk and          reporting and forensic   partners
  external victims? detection         findings                 
                    priorities                                 

  What is the       Current           Additional sector        HC3 / ISAC /
  complete victim   visibility covers reporting and            partners
  scope?            only part of the  infrastructure           
                    campaign          correlation              

  Who operates      Attribution       Higher-confidence        Threat
  HEALTHBANE?       remains           infrastructure           Intelligence /
                    unresolved        ownership, operational   trusted partners
                                      overlap and external     
                                      intelligence             

  What happened to  Clarifies         Partner reporting,       Threat
  stolen healthcare motivation and    criminal-market          Intelligence /
  data?             impact            intelligence,            sector partners
                                      law-enforcement/sector   
                                      intelligence where       
                                      available                
  ------------------------------------------------------------------------------

# Final Assessment

HEALTHBANE should be treated as a **HIGH-confidence healthcare-sector
campaign** with confirmed capability to progress from credential
phishing to trusted internal delivery, malware persistence and DNS-based
healthcare-data exfiltration.

For MedDefense specifically, the supplied evidence supports **Stage 1
targeting and likely credential exposure**, but does **not** establish
local Stage 2 malware execution or Stage 3 data exfiltration.

The immediate operational priority is therefore to determine whether the
likely credential exposure produced account compromise while
simultaneously strengthening endpoint persistence and DNS-exfiltration
detection.

Static IOCs are useful for immediate containment and retrospective
hunting, but durable defense requires behavioral detection across the
full chain:

``` text
Phishing
   ↓
Credential exposure / account abuse
   ↓
Malicious document
   ↓
VBA / PowerShell / malware
   ↓
Scheduled Task + Registry persistence
   ↓
DNS C2 / tunneling
   ↓
Data exfiltration
```

Named threat-actor attribution remains **UNCONFIRMED** and should not
delay defensive action against the well-supported campaign behaviors.
