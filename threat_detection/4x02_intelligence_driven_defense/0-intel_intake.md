# 0 --- Intelligence Intake

## Objective

Normalize and compare the four intelligence sources supplied for the
HEALTHBANE campaign while preserving source provenance, confidence,
caveats, and data-quality issues.

## Source Intake Summary

  --------------------------------------------------------------------------------------------------------------------------------------
  Source        Source type     Date         TLP /              Indicators Indicator   Intelligence claim     Key limitations / caveats
                                             distribution         provided types                              
  ------------- --------------- ------------ ---------------- ------------ ----------- ---------------------- --------------------------
  HC3           Government      2026-04-25   TLP:CLEAR         23 declared Domains,    HC3 tracks HEALTHBANE  Attribution to a named
  HEALTHBANE    advisory                                                   IPs,        as a coordinated       actor is unconfirmed. HC3
  Advisory                                                                 SHA-256     multi-stage campaign   assesses a financially
                                                                           hashes,     targeting US           motivated mid-tier
                                                                           URLs        healthcare             cybercrime operator with
                                                                                       organizations,         MODERATE confidence and
                                                                                       progressing from       does not endorse
                                                                                       credential harvesting  commercial actor labels.
                                                                                       to malware delivery    
                                                                                       and DNS-based          
                                                                                       exfiltration in some   
                                                                                       victims.               

  Acme CTI      Commercial feed 2026-04-26   TLP:AMBER;                 41 12 domains, Acme clusters the      Not all indicators were
  Commercial                                 MedDefense                    15 IPs, 9   activity under the     human-reviewed. The feed
  Feed                                       internal                      SHA-256     proprietary label      explicitly contains
                                             defensive use                 hashes, 5   VITALSCORE and         shared-hosting/CDN/cloud
                                             only                          URLs        provides               infrastructure and
                                                                                       campaign-related and   low-confidence clustering
                                                                                       similarity-clustered   noise. VITALSCORE is a
                                                                                       indicators.            proprietary label and is
                                                                                                              not confirmed as a 1:1
                                                                                                              actor identity.

  Marcus Weller Open-source     2026-04-24   Public; no TLP    14 declared 5 domains,  The researcher links   Attribution is MEDIUM
  HEALTHBANE    research                     marking                       3 IPs, 4    the phishing kit and   confidence and based only
  Technical                                                                SHA-256     infrastructure to the  on tooling/infrastructure
  Walkthrough                                                              hashes, 2   same operation and     overlap. The researcher is
                                                                           URLs        assesses an overlap    a solo analyst without
                                                                                       with a privately       victim telemetry and warns
                                                                                       tracked actor named    that commercial clustering
                                                                                       APT-MEDAGENT.          creates false positives.

  MedDefense    Internal        2026-04-16   INTERNAL;                  11 3 domains,  MedDefense confirmed a Scope was limited to the
  4x00 Findings investigation                indicator-only                3 IPs, 1    coordinated phishing   local phishing
                                             extract shared                SHA-256     cluster and assessed   investigation. At report
                                             with HC3                      hash, 1     likely credential      close, credential
                                                                           URL, 3      exposure after one     exploitation was not
                                                                           email       user clicked and       confirmed, Stage 2/3
                                                                           addresses   entered a password.    activity had not been
                                                                                                              observed, and attribution
                                                                                                              was intentionally not
                                                                                                              attempted.
  --------------------------------------------------------------------------------------------------------------------------------------

## Declared Indicator Counts

``` text
HC3 advisory:       23
Commercial feed:    41
Researcher blog:    14
MedDefense 4x00:    11
--------------------------------
Total raw:          89
```

These are the source-declared/reference counts supplied by the lab.

## Indicator Types by Source

  Source         Domains   IPs   Hashes   URLs   Email addresses
  ------------ --------- ----- -------- ------ -----------------
  HC3                  8     6        5      4                 0
  Commercial          12    15        9      5                 0
  Researcher           5     3        4      2                 0
  MedDefense           3     3        1      1                 3

## Consolidated View

### Raw total

The four sources declare **89 raw indicator occurrences**.

### Expected deduplicated total

The lab specification provides **64 unique indicators after
deduplication** as the expected reference count.

### Validation note --- observed material does not reproduce 64

A direct value-level comparison of the supplied files does **not**
reproduce the expected 64 unique count. This is recorded as a
data-quality discrepancy rather than silently changing the evidence.

Reasons include:

1.  Many values are repeated across three or four sources.
2.  The same phishing URL is represented at different levels of
    normalization:
    -   HC3/researcher template: `...?id=<user>&token=<8hex>`
    -   Commercial template: `...?id=<user>&token=<hex>`
    -   MedDefense observed instance: `...?id=dmarsh&token=a8f3e2d1`
3.  The value labelled as the SHA-256 of `INV-2026-04891.pdf` contains
    **62 hexadecimal characters**, whereas a valid SHA-256 digest must
    contain 64 hexadecimal characters.
4.  Source-declared indicator counts should therefore be preserved
    separately from machine-validated values.

**Analytical judgment --- HIGH confidence:** do not modify the malformed
hash or manufacture additional indicators to force the expected total.
Preserve provenance and flag the discrepancy for validation.

## Indicators Corroborated by Multiple Sources

### Present in all four sources

-   `meddefense-portal.com`
-   `medequip-supplies.net`
-   `91.234.99.107`

These receive strong corroboration because the same values are
independently present in government, commercial, open-source, and
internal reporting.

### Present in three sources

-   `meddefense-benefits.org` --- HC3, Commercial, MedDefense
-   `185.176.43.22` --- HC3, Commercial, MedDefense
-   `164.90.218.73` --- HC3, Commercial, MedDefense
-   `outlook-protection.com` --- HC3, Commercial, Researcher
-   `healthbane-c2.net` --- HC3, Commercial, Researcher
-   `51.38.42.191` --- HC3, Commercial, Researcher
-   `a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456`
    --- HC3, Commercial, Researcher
-   `c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`
    --- HC3, Commercial, Researcher

### Present in two sources

-   `portal-secure-meddefense.com` --- HC3, Researcher
-   `update-healthbane.net` --- HC3, Commercial
-   `data-sync.healthbane-c2.net` --- HC3, Commercial
-   `51.38.42.17` --- HC3, Commercial
-   `45.77.218.9` --- HC3, Commercial
-   `167.71.222.30` --- Commercial, Researcher
-   `b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654`
    --- HC3, Commercial
-   `dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678`
    --- HC3, Commercial
-   `https://medequip-supplies.net/invoices/pay?id=INV-<YYYY-NNNNN>` ---
    HC3, Commercial
-   `https://meddefense-benefits.org/enroll` --- HC3, Commercial
-   `https://healthbane-c2.net/update/svchost_update.exe` --- HC3,
    Commercial
-   `https://meddefense-portal.com/verify/staff?id=<user>&token=<8hex>`
    --- HC3, Researcher

## Indicators Seen in Only One Source

### Commercial-only

The feed contains several indicators not corroborated by the stronger
HC3 or MedDefense evidence, including:

-   Domains: `rx-benefits-portal.com`, `healthcare-login.com`,
    `verify-health-portal.net`, `secure-insurance-login.com`,
    `claims-verify-portal.net`
-   IPs: `159.89.112.45`, `23.94.138.222`, `104.168.34.58`,
    `192.99.207.114`, `20.83.144.56`, `13.107.42.14`, `172.67.192.40`,
    `104.21.35.7`
-   Hashes:
    `ee1122334455667788990011223344556677889900aabbccddeeff0011223344`,
    `1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677`,
    `3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011`,
    `5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344`,
    `7788990011223344556677aabbccddeeff0011223344556677aabbccddeeff00`
-   URL: `https://outlook-protection.com/verify`

**Assessment --- HIGH confidence:** these indicators must not
automatically be treated as blockable IOCs. The feed itself identifies
Microsoft, Azure, Cloudflare, OVH/CDN/shared-hosting entries and
similarity-clustered artifacts as potential noise.

### Researcher-only

-   `ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899`
    --- phishing kit ZIP
-   `https://healthbane-c2.net/api/ingest` --- exfiltration endpoint

**Assessment --- MEDIUM confidence:** technically relevant, but
provenance is a single open-source researcher without victim telemetry.

### MedDefense-only

-   `noreply@meddefense-portal.com`
-   `invoices@medequip-supplies.net`
-   `hr-notifications@meddefense-benefits.org`
-   Concrete observed phishing URL:
    `https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1`

**Assessment --- HIGH confidence for local observation:** these values
came from MedDefense's own incident evidence. The concrete URL is a
specific instance of the broader URL pattern reported by HC3/researcher.

## Source Conflicts Requiring Later Resolution

### 1. Attribution

**Fact:** HC3 names the campaign HEALTHBANE but states that attribution
to a named actor is unconfirmed.

**Assessment:** The researcher uses `APT-MEDAGENT` with MEDIUM
confidence based on tooling and infrastructure overlap. Acme uses the
proprietary label `VITALSCORE`. These labels must not be treated as
proven aliases.

**Recommendation --- HIGH confidence:** use **HEALTHBANE** as the
campaign name and keep actor attribution **UNCONFIRMED** until stronger
evidence exists.

### 2. Confidence differences

The same indicator can have different confidence depending on the source
and its evidence. Corroborated HC3/internal observations should carry
more analytical weight than automated similarity clustering.

**Recommendation --- HIGH confidence:** preserve per-source confidence
rather than replacing it with one global confidence value during intake.

### 3. Commercial-feed noise

The commercial feed explicitly includes:

-   Microsoft cloud infrastructure
-   Azure CDN infrastructure
-   Cloudflare infrastructure
-   shared OVH/DigitalOcean hosting
-   similarity-clustered hashes and IPs

**Recommendation --- HIGH confidence:** these should be triaged before
any blocking action. Shared infrastructure can produce significant false
positives.

### 4. Indicators absent from stronger sources

Several commercial-only indicators are not present in HC3 reporting or
MedDefense's direct observations.

**Assessment --- MEDIUM confidence:** absence from HC3 does not prove an
indicator is benign, but it reduces corroboration and therefore
actionability.

### 5. Malformed SHA-256 value

The supposed SHA-256 for `INV-2026-04891.pdf` is:

`2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f`

It contains 62 hexadecimal characters.

**Fact --- HIGH confidence:** a SHA-256 digest must be 64 hexadecimal
characters.

**Recommendation:** retain the supplied value for provenance, mark it
**INVALID / REQUIRES VALIDATION**, and do not deploy it as a hash-based
detection until the original sample is hashed locally or the source
corrects the value.

## SOC Interpretation

The intake stage does **not** decide that every IOC is malicious or
blockable. Its purpose is to preserve what each source reported and
prepare the evidence for triage.

A SOC/CTI analyst should distinguish:

-   **corroborated indicators** --- stronger candidates for
    detection/blocking;
-   **single-source indicators** --- require additional validation;
-   **shared infrastructure** --- often useful for context or hunting,
    dangerous for blind blocking;
-   **behavioral intelligence** --- usually survives infrastructure
    rotation better than static IOCs;
-   **attribution claims** --- should remain separate from technical
    evidence unless independently supported.

## Task 0 Conclusion

**Confirmed:** four sources report overlapping intelligence about the
same healthcare-focused campaign and collectively declare 89 raw
indicator occurrences.

**Assessment --- HIGH confidence:** the strongest common evidence
supports the HEALTHBANE campaign designation and the observed
phishing/malware/C2 infrastructure, but it does not support confident
attribution to a named threat actor.

**Assessment --- HIGH confidence:** the commercial feed contains
intentional/acknowledged noise and must be triaged before operational
use.

**Data-quality issue:** the supplied material does not cleanly reproduce
the expected 64 unique indicators, and one purported SHA-256 value is
malformed. These discrepancies are preserved and documented rather than
corrected without evidence.

