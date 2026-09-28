# 4x02 --- Intelligence-Driven Defense

## Project Overview

This project develops a threat-intelligence-driven defensive workflow
around the **HEALTHBANE** healthcare campaign.

The investigation combines government reporting, commercial threat
intelligence, independent researcher analysis, internal MedDefense
evidence, MITRE ATT&CK mapping, detection-gap analysis and YARA
detection engineering.

The central analytical principle throughout the project is:

> **Separate confirmed facts from assessments, preserve source
> provenance, and never overstate attribution or detection coverage.**

## Repository

``` text
dlh-cyber_security/
└── threat_detection/
    └── 4x02_intelligence_driven_defense/
```

## Intelligence Sources

The project uses four primary sources:

-   `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   `commercial_feed_extract.json`
-   `researcher_blog_analysis.txt`
-   `meddefense_4x00_findings.txt`

Local samples are stored under:

``` text
samples/
```

Important sample files include:

-   `phishing_sample.pdf`
-   `healthbane_lure_02.pdf`
-   `clean_invoice.pdf`
-   `benign_invoice.pdf`
-   `healthbane_email_01.eml`
-   `healthbane_email_02.eml`
-   `healthbane_email_03.eml`
-   `benign_newsletter.eml`
-   `samples_manifest.txt`

Original evidence and supplied samples should not be modified in place.


# Task 0 --- Intelligence Intake

The four supplied intelligence sources were normalized and compared.

Source-declared indicator occurrences:

-   HC3 advisory: **23**
-   commercial feed: **41**
-   researcher analysis: **14**
-   MedDefense findings: **11**

Total source-declared raw occurrences:

``` text
89
```

The project specification references **64 unique indicators after
deduplication**, but literal validation of the supplied source values
does not cleanly reproduce that number.

The discrepancy is preserved as a **data-quality issue** rather than
forcing the evidence to match an expected result.

A purported SHA-256 for `INV-2026-04891.pdf` is also malformed: it
contains **62 hexadecimal characters rather than 64** and must not be
operationalized as a valid SHA-256 until corrected.

## Attribution position

-   **HEALTHBANE** --- campaign designation used by this project.
-   **VITALSCORE** --- Acme proprietary cluster label.
-   **APT-MEDAGENT** --- researcher's MEDIUM-confidence attribution
    hypothesis.
-   Named threat-actor attribution --- **UNCONFIRMED**.

------------------------------------------------------------------------

# Task 1 --- Indicator Triage

`1-indicator_triage.sh` separates intelligence into:

-   **ACTIONABLE** --- suitable for scoped detection, hunting or
    enforcement;
-   **CONTEXTUAL** --- useful for enrichment/historical correlation;
-   **NOISE** --- too weak, broad or shared for safe operational use.

Literal indicator triage produced:

``` text
ACTIONABLE: 29
CONTEXTUAL: 8
NOISE:      13
TOTAL:      50
```

The 64-vs-50 difference is documented rather than hidden.

## High-priority indicators

``` text
healthbane-c2.net
data-sync.healthbane-c2.net
meddefense-portal.com
medequip-supplies.net
meddefense-benefits.org

91.234.99.107
51.38.42.191
```

Confirmed Stage 2 hashes and the HEALTHBANE malware download URL are
also high-priority hunting indicators.

## Operational lesson

**ACTIONABLE does not automatically mean BLOCK.**

Shared Microsoft, Azure, Cloudflare, CDN and multi-tenant infrastructure
must not be blindly blocked because doing so can create significant
false positives and business impact.

------------------------------------------------------------------------

# Task 2 --- Source Credibility Assessment

The four intelligence sources were evaluated using source reliability,
information credibility, timeliness, relevance and analytical
limitations.

  -----------------------------------------------------------------------------------------------
  Source                                    Reliability       Information       Overall use
                                                              credibility       
  ----------------------------------------- ----------------- ----------------- -----------------
  `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`   A                 1 for core        HIGH-confidence
                                                              findings          sector
                                                                                intelligence

  `commercial_feed_extract.json`            C                 3 overall /       Enrichment and
                                                              variable          discovery

  `researcher_blog_analysis.txt`            B                 2 technical / 3   Technical
                                                              attribution       enrichment

  `meddefense_4x00_findings.txt`            A                 1 for local       HIGH-confidence
                                                              evidence          local evidence
  -----------------------------------------------------------------------------------------------

The strongest defensive conclusions are those supported by direct
MedDefense observations and corroborated HC3 evidence.

Commercial-feed clustering is useful for discovery but is not
automatically suitable for blocking.

------------------------------------------------------------------------

# Task 6 --- HEALTHBANE Kill Chain

The campaign was reconstructed into three principal stages.

## Stage 1 --- Credential Harvesting

``` text
Healthcare-themed phishing
        ↓
Lookalike domain
        ↓
Credential-harvesting page
        ↓
Username/password collection
```

**Confidence: HIGH**

At MedDefense, employee `dmarsh` clicked a malicious URL on:

``` text
2026-04-14 15:02:33 UTC
```

Credential submission approximately 25 seconds later is assessed as
**likely**, but was not directly confirmed by the supplied packet
evidence.

## Stage 2 --- Malware Delivery

At two HC3-visible organizations:

``` text
Stolen credentials
        ↓
Cloud mailbox compromise
        ↓
Internal follow-up phishing
        ↓
HEALTHBANE_S2_invoice.docm
        ↓
VBA macro
        ↓
svchost_update.exe
        ↓
Scheduled Task + Registry persistence
```

**Confidence: HIGH for the affected external organizations.**

This stage was **not observed locally at MedDefense** in the supplied
4x00 evidence.

## Stage 3 --- Data Exfiltration

``` text
Patient / insurance data
        ↓
Base32-style encoding
        ↓
DNS subdomain labels
        ↓
DNS TXT traffic
        ↓
data-sync.healthbane-c2.net
```

**Confidence: HIGH for the two progressed external organizations.**

The exact data-loss volume remains unknown.

## Overall reconstruction

``` text
Phishing
   ↓
Credential harvesting
   ↓
Cloud account compromise
   ↓
Trusted internal phishing
   ↓
Malicious document
   ↓
VBA / malware execution
   ↓
Persistence
   ↓
C2
   ↓
DNS tunneling
   ↓
Healthcare data exfiltration
```

------------------------------------------------------------------------

# Task 7 --- MITRE ATT&CK Mapping

The campaign was mapped to **20 ATT&CK techniques**.

``` text
OBSERVED: 18 (90%)
INFERRED:  2 (10%)
```

The distinction is important:

-   **OBSERVED** --- directly supported by campaign evidence.
-   **INFERRED** --- plausible and useful for hunting but not confirmed.

Important observed techniques include:

-   `T1566.002` --- Phishing: Spearphishing Link
-   `T1566.001` --- Phishing: Spearphishing Attachment
-   `T1204.001` --- User Execution: Malicious Link
-   `T1204.002` --- User Execution: Malicious File
-   `T1059.005` --- Visual Basic
-   `T1059.001` --- PowerShell
-   `T1053.005` --- Scheduled Task
-   `T1547.001` --- Registry Run Keys / Startup Folder
-   `T1056.003` --- Web Portal Capture
-   `T1071.004` --- DNS
-   `T1048.003` --- Exfiltration Over Alternative Protocol
-   `T1041` --- Exfiltration Over C2 Channel

Inferred techniques:

-   `T1078` --- Valid Accounts
-   `T1021` --- Remote Services

The accompanying Navigator layer is:

``` text
healthbane_layer.json
```

Scoring:

``` text
OBSERVED = 100
INFERRED = 50
```

------------------------------------------------------------------------

# Task 8 --- Detection Gap Analysis

Documented MedDefense coverage across the 20 mapped techniques:

``` text
DETECTED:            2 / 20 = 10%
PARTIALLY DETECTED: 13 / 20 = 65%
NOT DETECTED:        5 / 20 = 25%
```

## Priority 1 gaps --- OBSERVED + NOT DETECTED

-   `T1589.002` --- Gather Victim Identity Information: Email Addresses
-   `T1059.005` --- Visual Basic
-   `T1053.005` --- Scheduled Task
-   `T1547.001` --- Registry Run Keys / Startup Folder

## Priority 2 gap --- INFERRED + NOT DETECTED

-   `T1021` --- Remote Services

## Main defensive conclusion

MedDefense has stronger documented visibility into:

``` text
Phishing / malicious links
```

than into:

``` text
Execution
   ↓
Persistence
   ↓
C2
   ↓
Exfiltration
```

The most valuable improvements are therefore behavioral endpoint and
network analytics rather than simply adding more static IOCs.

------------------------------------------------------------------------

# Task 9 --- YARA Foundations

The project created:

``` text
9-yara_phishing_pdf.yar
```

Rule:

``` text
HEALTHBANE_Phishing_PDF
```

The rule requires:

``` text
PDF magic
    +
wkhtmltopdf
    +
at least two credential-harvesting URL signals
```

Relevant URL signals include:

``` text
/verify
/login
/portal
/enroll
token=
id=
```

The campaign domains are retained as contextual strings but are not
mandatory, allowing the rule to survive simple infrastructure rotation.

## Controlled test corpus

``` text
phishing_sample.pdf      → MATCH
healthbane_lure_02.pdf   → MATCH
clean_invoice.pdf        → NO MATCH
benign_invoice.pdf       → NO MATCH
```

Result:

``` text
TP: 2
TN: 2
FP: 0
FN: 0

Detection rate:      100%
False positive rate:   0%
Precision:           100%
```

A perfect result on four controlled samples does **not** prove
production readiness.

------------------------------------------------------------------------

# Task 11 --- YARA Testing

`11-yara_testing.sh` provides a reusable local YARA validation harness.

It:

-   discovers available `.yar` rules;
-   checks that rules compile through YARA;
-   scans relevant files in `samples/`;
-   determines expected malicious/benign status;
-   records TP, TN, FP and FN;
-   calculates detection rate;
-   calculates false-positive rate;
-   calculates precision;
-   reports false-positive/false-negative analysis;
-   produces `DEPLOY`, `TUNE` or `MONITOR` recommendations.

Because this project sequence contains **no Task 10**, Task 11 was
designed to test the YARA rules that actually exist instead of depending
on a nonexistent file.

Run:

``` bash
chmod +x 11-yara_testing.sh
./11-yara_testing.sh
```

Or test a specific rule:

``` bash
./11-yara_testing.sh 9-yara_phishing_pdf.yar
```

------------------------------------------------------------------------

# Task 13 --- Final Intelligence Brief

The final deliverable is:

``` text
13-intelligence_brief.md
```

It is designed for two audiences:

1.  MedDefense leadership;
2.  healthcare-sector security partners.

The brief contains:

-   executive summary;
-   adversary profile;
-   three-stage campaign analysis;
-   campaign timeline;
-   ATT&CK mapping;
-   detection-gap assessment;
-   prioritized IOC table;
-   YARA results;
-   48-hour recommendations;
-   two-week recommendations;
-   30-day recommendations;
-   intelligence gaps and collection priorities.

## Final MedDefense assessment

The supplied evidence supports:

``` text
Stage 1 targeting
        +
malicious link click
        +
likely credential exposure
```

It does **not** establish:

``` text
Stage 2 malware execution at MedDefense
or
Stage 3 data exfiltration at MedDefense
```

Sector intelligence demonstrates that other healthcare organizations
progressed through all three stages, including patient and
insurance-data exfiltration.

------------------------------------------------------------------------

# Recommended Defensive Priorities

## Immediate --- 48 hours

-   Review/reset potentially exposed credentials.
-   Hunt cloud identity and mailbox activity following the phishing
    event.
-   Hunt HIGH-confidence HEALTHBANE domains, IPs, hashes and URLs.
-   Search for `HealthSync Update Service`.
-   Apply scoped blocks to confirmed dedicated campaign infrastructure.

## Short-term --- 2 weeks

-   Detect Office/VBA execution.
-   Enable/verify PowerShell Script Block Logging.
-   Detect suspicious Scheduled Task creation.
-   Detect Registry Run/RunOnce persistence.
-   Deploy DNS-tunneling analytics.
-   Run the HEALTHBANE YARA rule in monitored detection/hunt mode.

## Medium-term --- 30 days

-   Correlate email, identity, EDR, DNS and proxy telemetry.
-   Detect newly registered/lookalike domains.
-   Establish repeatable healthcare threat-intelligence sharing.
-   Expand YARA regression testing with a larger benign corpus.
-   Reassess ATT&CK coverage after new detections are operational.

------------------------------------------------------------------------

# Key Detection Chain

A resilient HEALTHBANE detection strategy should cover the entire chain:

``` text
Email / URL
    ↓
Credential exposure
    ↓
Cloud identity abuse
    ↓
Malicious document
    ↓
VBA
    ↓
PowerShell / malware
    ↓
Scheduled Task / Registry persistence
    ↓
DNS C2 / tunneling
    ↓
Data exfiltration
```

Static IOCs provide immediate value, but behavioral detection remains
effective after domains, IP addresses, filenames and hashes change.

------------------------------------------------------------------------

# Intelligence Gaps

Important unanswered questions include:

-   Were the MedDefense credentials actually submitted?
-   Were those credentials subsequently used?
-   Was a MedDefense cloud mailbox compromised?
-   Did any endpoint execute the Stage 2 document?
-   Was HEALTHBANE persistence created locally?
-   Did any MedDefense host communicate with Stage 2/3 C2?
-   Was DNS tunneling present historically?
-   What exact records and volume were stolen from external victims?
-   What is the complete HEALTHBANE victim scope?
-   Who operates the campaign?
-   How was the stolen healthcare data ultimately used?

Answering these questions requires correlation of:

``` text
Email gateway
Cloud identity / M365 audit
EDR / Sysmon
PowerShell logs
Task Scheduler
Registry telemetry
DNS
Proxy
Firewall
PCAP
Forensic endpoint evidence
Sector-partner intelligence
```

------------------------------------------------------------------------

# Analytical Standards

Throughout this project:

-   source provenance is preserved;
-   facts are separated from assessments;
-   confidence is expressed as HIGH / MEDIUM / LOW;
-   weak commercial clustering is not treated as proof;
-   shared cloud/CDN infrastructure is not blindly blocked;
-   malformed indicators are not silently corrected;
-   inferred ATT&CK behavior is not presented as observed;
-   campaign labels are not treated as confirmed actor attribution;
-   missing project outputs are not fabricated.

------------------------------------------------------------------------

# Final Conclusion

HEALTHBANE is assessed with **HIGH confidence as a healthcare-focused
multi-stage campaign** capable of progressing from credential phishing
to trusted internal delivery, malware persistence and DNS-based
healthcare-data exfiltration.

For MedDefense, the supplied evidence confirms **Stage 1 targeting and a
malicious-link click with likely credential exposure**, but does not
confirm local Stage 2 malware execution or Stage 3 exfiltration.

The most important defensive lesson from this project is that threat
intelligence should not stop at collecting IOCs.

It should convert intelligence into:

``` text
Evidence
   ↓
Triage
   ↓
Campaign reconstruction
   ↓
ATT&CK mapping
   ↓
Detection-gap identification
   ↓
Detection engineering
   ↓
Testing
   ↓
Operational action
```

That workflow turns isolated indicators into actionable, campaign-aware
SOC defense.
