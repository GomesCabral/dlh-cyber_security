# 4x02 --- Intelligence-Driven Defense

## Project Overview

This project develops a threat-intelligence-driven defensive workflow
around the **HEALTHBANE** campaign. The work progresses from raw
intelligence intake through indicator triage, source assessment,
enrichment, infrastructure analysis, ATT&CK mapping, detection
engineering, YARA development/testing, and final intelligence reporting.

The project is designed to be completed locally. It does not depend on a
live SIEM, Wazuh server, Suricata sensor, or infrastructure from
previous modules.

## Repository

``` text
dlh-cyber_security/
└── threat_detection/
    └── 4x02_intelligence_driven_defense/
```

## Lab Sources

-   `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   `commercial_feed_extract.json`
-   `researcher_blog_analysis.txt`
-   `meddefense_4x00_findings.txt`
-   `samples/`

Original intelligence and sample files must not be modified in place.

## Analytical Standards

Throughout the project:

-   preserve source provenance;
-   distinguish confirmed facts from analytical assessments;
-   use `HIGH`, `MEDIUM`, and `LOW` confidence consistently;
-   document the reasoning behind analytical judgments;
-   do not overclaim threat-actor attribution;
-   validate JSON and YARA artifacts before completion;
-   prefer evidence over assumptions;
-   document source conflicts and data-quality issues.

## Progress

  Task                        Deliverable           Status
  --------------------------- --------------------- ----------
  0 --- Intelligence Intake   `0-intel_intake.md`   Complete
  1                           TBD                   Pending
  2                           TBD                   Pending
  3                           TBD                   Pending
  4                           TBD                   Pending
  5                           TBD                   Pending
  6                           TBD                   Pending
  7                           TBD                   Pending
  8                           TBD                   Pending
  9                           TBD                   Pending
  10                          TBD                   Pending
  11                          TBD                   Pending

## Task 0 --- Intelligence Intake

Four intelligence sources were normalized and compared:

-   HC3 government advisory --- 23 indicators declared;
-   Acme commercial CTI feed --- 41 indicators;
-   public researcher analysis --- 14 indicators declared;
-   MedDefense internal 4x00 findings --- 11 indicators declared.

Total source-declared raw occurrences: **89**.

The intake identified substantial cross-source corroboration but also
commercial-feed noise, conflicting attribution labels, URL-normalization
differences, and a malformed value presented as a SHA-256 hash.

### Attribution position

The project currently uses **HEALTHBANE** as the campaign designation.

`VITALSCORE` is retained as Acme's proprietary campaign/cluster label.

`APT-MEDAGENT` is retained as the researcher's MEDIUM-confidence
attribution hypothesis.

Named threat-actor attribution remains **UNCONFIRMED**.

### Data-quality note

The lab specification states an expected **64 unique indicators after
deduplication**. Direct validation of the supplied source values does
not cleanly reproduce that number. The discrepancy is documented in
`0-intel_intake.md` rather than forcing the evidence to match the
reference count.

The purported SHA-256 for `INV-2026-04891.pdf` contains 62 hexadecimal
characters instead of the required 64 and is therefore marked for
validation before operational use.

## Current Defensive Takeaway

The most reliable intelligence is the information corroborated by
multiple independent sources and direct MedDefense observations.
Commercial-only similarity-clustered indicators require additional
validation before blocking because several refer to shared cloud/CDN
infrastructure and are explicitly described as possible noise.

Behavioral patterns such as lookalike healthcare domains, PHPMailer
usage, malicious document execution, persistence, and DNS tunneling are
expected to remain useful even when attacker infrastructure changes.
