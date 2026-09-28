# 6 --- The Kill Chain Reconstruction

## Objective

Reconstruct the HEALTHBANE campaign chronologically across credential
harvesting, malware delivery and data exfiltration using evidence from:

-   `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
-   `researcher_blog_analysis.txt`
-   `meddefense_4x00_findings.txt`
-   `commercial_feed_extract.json`

This reconstruction distinguishes **CONFIRMED**, **CORROBORATED**,
**INFERRED** and **UNKNOWN** information so that analytical judgments
are not presented as facts.

------------------------------------------------------------------------

# 1. HEALTHBANE Campaign Timeline

  -----------------------------------------------------------------------------------------------------
  Date / window     Event                   Evidence                                  Confidence
  ----------------- ----------------------- ----------------------------------------- -----------------
  2026-04-05 to     Lookalike               HC3 and MedDefense WHOIS findings         HIGH
  2026-04-10        healthcare-themed                                                 
                    domains used in Stage 1                                           
                    were registered.                                                  

  **2026-04-14**    Earliest known          `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`   HIGH
                    HEALTHBANE phishing                                               
                    email observed at an                                              
                    HC3 partner                                                       
                    organization.                                                     

  **2026-04-14      MedDefense nurse Diane  `meddefense_4x00_findings.txt`            HIGH
  15:02:33 UTC**    Marsh (`dmarsh`)                                                  
                    clicked the phishing                                              
                    link in Email 2.                                                  

  2026-04-14        MedDefense assesses     MedDefense user report + 47-second HTTPS  MEDIUM
  15:02:58 UTC      that `dmarsh` likely    session; no packet confirmation in 4x00   
                    submitted credentials.                                            

  **2026-04-14 to   Primary Stage 1         HC3                                       HIGH
  2026-04-16**      credential-harvesting                                             
                    window. All six                                                   
                    HC3-visible                                                       
                    organizations                                                     
                    experienced Stage 1.                                              

  2026-04-16        MedDefense 4x00 report  MedDefense                                HIGH
                    closes with likely                                                
                    credential exposure but                                           
                    no confirmed                                                      
                    exploitation or Stage                                             
                    2/3 activity.                                                     

  **2026-04-16 to   Stage 2 malware         HC3 sandbox and victim telemetry          HIGH
  2026-04-22**      delivery occurs at two                                            
                    of six HC3-visible                                                
                    organizations.                                                    

  2026-04-18        Researcher receives a   Researcher blog                           MEDIUM-HIGH
                    HEALTHBANE phishing                                               
                    email from a Midwest                                              
                    hospital contact and                                              
                    later recovers the                                                
                    phishing kit.                                                     

  \~2026-04-22      Researcher reports the  Researcher blog                           MEDIUM-HIGH
                    kit was taken down and                                            
                    shares kit                                                        
                    contents/IOCs with HC3.                                           

  2026-04-24        Researcher publishes    `researcher_blog_analysis.txt`            HIGH
                    technical HEALTHBANE                                              
                    analysis.                                                         

  **2026-04-23 to   Stage 3 DNS-tunnel      HC3 packet captures                       HIGH
  2026-04-26**      exfiltration observed                                             
                    at two HC3-visible                                                
                    organizations.                                                    

  2026-04-25        HC3 publishes the       HC3 document metadata                     HIGH
                    HEALTHBANE sector                                                 
                    advisory.                                                         

  **2026-04-26**    Most recent operational HC3 + commercial feed                     HIGH for date
                    date represented in the                                           window; exact
                    reported Stage 3 window                                           final event
                    and commercial-feed                                               timestamp UNKNOWN
                    `last_seen` data.                                                 
  -----------------------------------------------------------------------------------------------------

## Timeline interpretation

The campaign begins with healthcare-themed spear phishing and credential
harvesting. At two organizations, stolen credentials were subsequently
used to access cloud email accounts and send trusted internal follow-up
messages containing a malicious macro-enabled document. The resulting
malware established persistence and ultimately supported DNS-based
command-and-control and exfiltration of healthcare data.

MedDefense detected the campaign during Stage 1 and, based on the
supplied 4x00 evidence, did **not** observe Stage 2 or Stage 3 locally.

------------------------------------------------------------------------

# 2. Stage 1 --- Credential Harvesting

## 2.1 Phishing operation

**CONFIRMED --- HIGH confidence**

HEALTHBANE used spear-phishing emails containing links to lookalike
healthcare-themed domains.

HC3 reports that the phishing domains were generally registered shortly
before first use. MedDefense independently observed three lookalike
domains registered between 2026-04-08 and 2026-04-10.

The landing pages impersonated legitimate healthcare-related services
and collected usernames and passwords.

The researcher recovered a PHP-based credential-harvesting kit
containing:

-   `index.php` --- target-branded landing page;
-   `handlers/post.php` --- accepts submitted credentials;
-   `logs/creds.log` --- local credential log;
-   PHPMailer 6.6.0;
-   per-target branding assets;
-   references to `healthbane-c2.net`.

The kit forwarded harvested data using PHPMailer and contained an
`EXFIL_ENDPOINT` pointing to:

`https://healthbane-c2.net/api/ingest`

**Assessment:** The researcher's kit analysis technically links Stage 1
phishing infrastructure to later HEALTHBANE infrastructure.

------------------------------------------------------------------------

## 2.2 Targeting pattern

**CONFIRMED --- HIGH confidence**

HC3 reports targeting of US healthcare organizations, with the strongest
signal in the Midwest ISAC region.

Observed target organization types include:

-   hospital systems;
-   outpatient clinics;
-   medical billing services;
-   regional insurance administrators.

The phishing themes impersonated:

-   staff portals;
-   insurance services;
-   HR/benefits;
-   invoices;
-   Microsoft/Outlook security or login workflows.

MedDefense's three confirmed phishing recipients demonstrate role
diversity:

-   `dmarsh` --- nurse, Westside Clinic;
-   `arivera` --- accounts payable;
-   `lpatterson` --- billing.

**Assessment --- HIGH confidence:** HEALTHBANE was not limited to one
job role. The operation targeted clinical and administrative personnel
whose credentials could provide useful organizational access.

------------------------------------------------------------------------

## 2.3 Stage 1 infrastructure

### Domains

High-confidence or corroborated infrastructure includes:

-   `meddefense-portal.com`
-   `medequip-supplies.net`
-   `meddefense-benefits.org`
-   `outlook-protection.com`
-   `portal-secure-meddefense.com`

### IP addresses

HC3 reports:

-   `91.234.99.107`
-   `185.176.43.22`
-   `164.90.218.73`
-   `51.38.42.17`

The commercial feed independently contains these core indicators,
although the feed also includes lower-confidence and noisy
infrastructure that should not automatically be incorporated into the
reconstructed kill chain.

### Operational fingerprint

The sources collectively identify recurring characteristics:

-   recently registered healthcare-themed domains;
-   PHPMailer 6.6.0;
-   Namecheap registration for phishing landing-page domains;
-   Hostinger, DigitalOcean and OVH hosting;
-   target-specific branding;
-   HTTPS credential-harvesting pages.

------------------------------------------------------------------------

## 2.4 Known victims and success rate

HC3 reports:

-   at least **14 healthcare organizations targeted**;
-   direct or partner visibility into **6 organizations**;
-   Stage 1 observed at **6 of 6 visible organizations (100%)**;
-   Stage 2 observed at **2 of 6 (33%)**;
-   Stage 3 observed at **2 of 6 (33%)**.

**Important analytical limitation:** Stage 1 being *observed* at 100% of
HC3-visible organizations does not mean credentials were successfully
stolen at all six.

For MedDefense specifically:

-   3 employees received confirmed campaign phishing emails;
-   1 of those 3 clicked the malicious link;
-   `dmarsh` reported entering her password;
-   credential submission was assessed as **LIKELY**, not
    packet-confirmed at the close of 4x00;
-   no immediate attacker authentication using the account was observed
    during the 4x00 window.

Therefore, a precise campaign-wide **credential-harvest success rate is
UNKNOWN**.

------------------------------------------------------------------------

## 2.5 MedDefense evidence

**CONFIRMED**

-   Three coordinated phishing emails were identified.
-   The emails shared operational characteristics including PHPMailer
    6.6.0 and lookalike infrastructure.
-   `dmarsh` clicked the malicious link at `2026-04-14 15:02:33 UTC`.
-   MedDefense observed the concrete URL:

`https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1`

**ASSESSED / NOT FULLY CONFIRMED IN 4x00**

-   Credential submission at approximately `15:02:58 UTC` was assessed
    as likely.
-   No Stage 2 or Stage 3 activity was observed at MedDefense in the
    supplied internal 4x00 findings.

------------------------------------------------------------------------

# 3. Stage 2 --- Malware Delivery

## 3.1 Transition from credentials to trusted follow-up email

**CONFIRMED --- HIGH confidence from HC3**

At two HC3-visible organizations, Stage 1 credentials were used to
authenticate to cloud email accounts.

The attacker then sent follow-up emails from compromised accounts to
colleagues.

This changes the trust model:

``` text
External phishing
        ↓
Credential theft
        ↓
Compromised legitimate mailbox
        ↓
Internal/trusted-looking follow-up email
        ↓
Malicious attachment
```

This is operationally important because an email originating from a
legitimate compromised account can bypass controls that focus mainly on
external sender reputation.

------------------------------------------------------------------------

## 3.2 Malicious document

The Stage 2 attachment was:

`HEALTHBANE_S2_invoice.docm`

SHA-256 reported by HC3:

`a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456`

**Document type:** Microsoft Office macro-enabled document (`.docm`)

**CONFIRMED --- HIGH confidence**

HC3 reports Stage 2 based on sandbox evidence and observations at two
organizations. The researcher independently reports the same
macro-document hash from a partner.

------------------------------------------------------------------------

## 3.3 Execution and malware artifacts

The macro downloaded:

`svchost_update.exe`

from:

`https://healthbane-c2.net/update/svchost_update.exe`

Reported SHA-256:

`b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654`

Additional Stage 2 artifacts include:

`sync_healthdata.ps1`

SHA-256:

`c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

and a medium-confidence dropper variant:

`dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678`

------------------------------------------------------------------------

## 3.4 Download / C2 infrastructure

Key infrastructure:

-   `healthbane-c2.net`
-   `51.38.42.191`
-   `45.77.218.9` --- HC3 MEDIUM-confidence Stage 2 infrastructure
-   `update-healthbane.net` --- HC3 MEDIUM-confidence Stage 2 domain

The commercial feed corroborates several of these values but also
includes uncorroborated Stage 2 candidates. Commercial-only weak
clusters are not treated as confirmed kill-chain components.

------------------------------------------------------------------------

## 3.5 Persistence

**CONFIRMED --- HIGH confidence**

HC3 reports two persistence mechanisms:

1.  Scheduled task:

`HealthSync Update Service`

2.  Registry Run key.

These correspond to persistent execution after the initial malware
deployment.

------------------------------------------------------------------------

## 3.6 Evidence sources

Primary:

`HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`

Supporting/corroborating:

-   `researcher_blog_analysis.txt`
-   `commercial_feed_extract.json`

MedDefense's internal 4x00 report explicitly states that no matching
Stage 2 artifact was found during its 2026-04-16 EDR scan.

------------------------------------------------------------------------

# 4. Stage 3 --- Data Exfiltration

## 4.1 Data targeted

**CONFIRMED --- HIGH confidence from HC3**

In the two environments that reached Stage 3, the attacker exfiltrated:

-   patient records;
-   insurance claims data.

This is particularly significant because both categories contain
sensitive healthcare/business information.

------------------------------------------------------------------------

## 4.2 Exfiltration method

The RAT deployed during Stage 2 used **DNS tunneling**.

Data was:

1.  encoded into Base32;
2.  placed into DNS subdomain labels;
3.  transmitted through DNS TXT-record queries.

HC3 reports:

-   query interval: approximately **10--15 seconds**;
-   encoded label length: approximately **44--60 characters**;
-   TXT responses containing Base64-encoded command strings.

This means DNS was used bidirectionally for both attacker communication
and data movement.

------------------------------------------------------------------------

## 4.3 Exfiltration infrastructure

Primary domain:

`data-sync.healthbane-c2.net`

Parent C2 domain:

`healthbane-c2.net`

Associated high-confidence IP:

`51.38.42.191`

The researcher additionally recovered:

`https://healthbane-c2.net/api/ingest`

from the phishing kit configuration.

**Assessment --- MEDIUM confidence:** the API endpoint helps establish
infrastructure continuity between the phishing kit and later
infrastructure, but HC3's Stage 3 evidence specifically confirms DNS
tunneling rather than proving that this HTTPS API was the mechanism used
for the observed victim data exfiltration.

------------------------------------------------------------------------

## 4.4 Evidence source

HC3 states Stage 3 confidence is **HIGH**, based on packet captures from
two compromised organizations.

The commercial feed independently tags:

-   `51.38.42.191` as C2 / DNS tunnel;
-   Stage 2/3 infrastructure and related artifacts.

The researcher's kit provides supporting technical linkage but does not
provide victim packet telemetry.

------------------------------------------------------------------------

## 4.5 Confirmed versus unclear

### CONFIRMED

-   Two HC3-visible organizations reached Stage 3.
-   Patient records and insurance claims data were exfiltrated.
-   DNS TXT queries were used.
-   Data was encoded in Base32 subdomain labels.
-   `data-sync.healthbane-c2.net` was used.
-   C2 responses also used DNS TXT data.

### UNCLEAR / UNKNOWN

The supplied intelligence does not establish:

-   the exact number of records stolen;
-   the exact number of bytes exfiltrated;
-   the complete list of affected patients;
-   whether all stolen information was successfully received and
    retained by the attacker;
-   whether additional exfiltration protocols were used;
-   the precise start/end timestamp for every victim's exfiltration;
-   whether the attacker subsequently sold, leaked or otherwise used the
    stolen data.

These gaps must not be replaced with assumptions.

------------------------------------------------------------------------

# 5. Full Campaign Reconstruction

The best-supported campaign sequence is:

``` text
1. Attacker acquires recently registered healthcare-themed domains
                         ↓
2. Targeted spear-phishing emails sent to healthcare staff
                         ↓
3. Victim follows lookalike login/benefits/invoice link
                         ↓
4. PHP/PHPMailer credential-harvesting kit captures credentials
                         ↓
5. Stolen credentials used to access cloud email accounts
                         ↓
6. Compromised mailbox sends follow-up email to colleagues
                         ↓
7. HEALTHBANE_S2_invoice.docm is opened
                         ↓
8. VBA macro executes
                         ↓
9. svchost_update.exe downloaded from healthbane-c2.net
                         ↓
10. Persistence established
    ├── HealthSync Update Service scheduled task
    └── Registry Run key
                         ↓
11. RAT / PowerShell tooling operates on compromised host
                         ↓
12. Patient and insurance data prepared for exfiltration
                         ↓
13. Base32 data encoded into DNS query subdomains
                         ↓
14. DNS TXT traffic to data-sync.healthbane-c2.net
                         ↓
15. Patient / insurance data exfiltrated
```

**Overall campaign reconstruction confidence: HIGH**

The exact actions between malware persistence and data selection/staging
are less completely documented than the initial-access and
DNS-exfiltration mechanisms.

------------------------------------------------------------------------

# 6. Evidence Quality by Phase

  ------------------------------------------------------------------------------------------------------
  Phase          Confirmed evidence      Corroborated     Inferred        Major unknowns   Confidence
                                         evidence         evidence                         
  -------------- ----------------------- ---------------- --------------- ---------------- -------------
  Stage 1 ---    Phishing emails,        HC3 +            Campaign-wide   Exact number of  **HIGH**
  Credential     lookalike domains,      MedDefense +     credential      credentials      
  Harvesting     credential forms,       researcher +     success beyond  successfully     
                 MedDefense click, HC3   core commercial  known cases     stolen           
                 observations            indicators                                        

  Stage 2 ---    `.docm`, macro          Researcher       Exact actions   Full victim      **HIGH**
  Malware        execution chain,        artifacts +      taken with      list, complete   
  Delivery       `svchost_update.exe`,   commercial IOC   every stolen    malware          
                 scheduled task, Run key overlap          account         functionality,   
                 at 2 orgs                                                all variants     

  Stage 3 ---    DNS TXT tunneling,      Commercial C2    Additional      Exact volume,    **HIGH for
  Exfiltration   Base32 labels,          tags +           possible exfil  complete stolen  observed
                 patient/insurance data, researcher       paths           dataset,         activity**,
                 2 victim environments   infrastructure                   post-theft use   incomplete
                                         link                                              scope
  ------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------

# 7. What Is Not Known

## 7.1 Attribution gaps

HC3 assesses the operator as a financially motivated mid-tier cybercrime
actor with MODERATE confidence but explicitly states that named
attribution is unconfirmed.

The researcher proposes `APT-MEDAGENT` with MEDIUM confidence based on:

-   tooling reuse;
-   infrastructure patterns;
-   kit structure.

The commercial feed uses `VITALSCORE`.

**Assessment --- HIGH confidence:** the available evidence is
insufficient to prove that `APT-MEDAGENT`, `VITALSCORE` and HEALTHBANE
represent one confirmed named actor.

Recommended position:

``` text
Campaign: HEALTHBANE
Named actor: UNCONFIRMED
APT-MEDAGENT overlap: MEDIUM-confidence hypothesis
VITALSCORE: proprietary commercial cluster label
```

------------------------------------------------------------------------

## 7.2 Missing victim telemetry

HC3 reports at least 14 targeted organizations but has direct or partner
visibility into only six.

Therefore, the true number of:

-   successful credential thefts;
-   compromised mailboxes;
-   Stage 2 infections;
-   Stage 3 exfiltration events;

may differ from the observed six-organization dataset.

### Collection needed

-   email gateway logs;
-   cloud authentication logs;
-   endpoint telemetry;
-   proxy logs;
-   DNS logs;
-   PCAPs;
-   identity-provider audit logs;
-   affected-host forensic images.

------------------------------------------------------------------------

## 7.3 Incomplete Stage 3 visibility

HC3 has packet evidence from two organizations, but the supplied
material does not quantify the complete data loss.

### Collection needed

-   full PCAP retention;
-   recursive DNS logs;
-   authoritative DNS logs if obtainable;
-   DNS resolver telemetry;
-   host-level staging artifacts;
-   PowerShell logs;
-   EDR process/network telemetry;
-   file-access auditing;
-   database access logs.

These sources could help determine what data was staged and how much was
transmitted.

------------------------------------------------------------------------

## 7.4 Commercial-feed uncertainty

`commercial_feed_extract.json` contains both high-quality corroborated
indicators and acknowledged noise.

Examples of uncertainty include:

-   shared hosting;
-   Microsoft/Azure infrastructure;
-   Cloudflare front-end IPs;
-   keyword clustering;
-   weak ML similarity;
-   indicators without human review.

**Assessment:** commercial-only low-confidence indicators should not be
inserted into the kill chain as confirmed attacker infrastructure
without corroboration.

------------------------------------------------------------------------

## 7.5 Missing transition details

The broad sequence from Stage 2 infection to Stage 3 exfiltration is
confirmed, but the supplied sources do not fully document:

-   internal discovery commands;
-   privilege escalation, if any;
-   exact lateral-movement mechanism;
-   data-discovery commands;
-   staging directories;
-   archive/compression mechanisms;
-   complete RAT command set.

HC3 assesses Valid Accounts and Remote Services as likely but excludes
them from its observed ATT&CK table pending confirmation.

These behaviors should therefore remain **INFERRED / UNCONFIRMED**, not
stated as observed facts.

------------------------------------------------------------------------

# 8. SOC Assessment

HEALTHBANE demonstrates why incident response and threat intelligence
must be combined.

MedDefense's local investigation only showed:

``` text
Phishing → click → likely credential exposure
```

Sector intelligence revealed the potential consequence if the campaign
continued:

``` text
Credential harvesting
        ↓
Cloud account compromise
        ↓
Trusted internal phishing
        ↓
Macro-enabled document
        ↓
Malware execution
        ↓
Persistence
        ↓
C2
        ↓
DNS tunneling
        ↓
Healthcare data exfiltration
```

For a SOC analyst, this changes the investigation question.

It is not enough to ask:

> "Did the user click the phishing link?"

The analyst should also ask:

-   Were credentials submitted?
-   Were those credentials subsequently used?
-   Was a legitimate mailbox compromised?
-   Did that mailbox send internal phishing?
-   Did any endpoint execute the Stage 2 document?
-   Was `svchost_update.exe` observed?
-   Was persistence created?
-   Did endpoints query `healthbane-c2.net`?
-   Are there long encoded DNS labels or unusual TXT queries?
-   Is there evidence of patient or insurance data access before those
    DNS events?

This is how threat intelligence converts an isolated phishing alert into
a **campaign-aware SOC investigation**.

------------------------------------------------------------------------

# 9. Final Assessment

**Stage 1 --- HIGH confidence:** HEALTHBANE conducted healthcare-focused
credential harvesting beginning at least 2026-04-14. MedDefense was
directly targeted and one employee likely submitted credentials.

**Stage 2 --- HIGH confidence:** at two HC3-visible organizations,
compromised credentials were used to send follow-up malicious `.docm`
files that deployed `svchost_update.exe` and established persistence.

**Stage 3 --- HIGH confidence:** those two organizations experienced DNS
TXT-based exfiltration of patient records and insurance claims data
through `data-sync.healthbane-c2.net`.

**MedDefense impact:** based on the supplied internal 4x00 findings,
only Stage 1 was observed locally; Stage 2 and Stage 3 were not
observed.

**Attribution:** named threat-actor attribution remains **UNCONFIRMED**.

**Overall HEALTHBANE campaign reconstruction confidence: HIGH**, while
victim scope, complete Stage 3 data-loss volume and actor identity
remain incomplete or unknown.
