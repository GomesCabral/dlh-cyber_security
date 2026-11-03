# MedDefense Backup Architecture

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Pedro Cabral  
**Date:** 2026-11-03  
**Status:** Proposed architecture; implementation and restore-test evidence pending  
**BIA baseline:** `business_impact_analysis.md`, version 1.0

## Strategy Overview

This is a **target-state design**, not evidence that the controls already operate. Scope is every Tier 1 and Tier 2 system in the supplied BIA (eight systems). The two Tier 3 systems, Email and Secure Messaging and Security Operations Platform, remain dependent services and need separate recovery plans. RTO values are end-to-end *usable clinical service* targets, not merely time to restore a database. The 30-minute LIS laboratory exercise is not proof of production readiness.

A recoverable point must be **completed, consistent, accessible, hash-verified and restorable**. A schedule by itself does not prove an RPO. Target intervals include a safety margin for execution and replication lag. For each system, monitor age of the **last verified recovery point** continuously, alert at 75% of RPO and escalate before the limit. Replication alone cannot protect against ransomware or logical deletion: retain isolated immutable copies and periodically restore them.

For ePHI, require **AES-256 at rest** with envelope encryption, centrally governed KMS/HSM keys, rotation, least-privilege access, dual-control break-glass recovery and geographically separate escrow. Require **TLS 1.2 or later in transit** (prefer TLS 1.3), certificate validation and encrypted transfer to all destinations. The same minimum applies to every system here as a conservative enterprise standard. Geographic copies must be in a different failure domain, protected from primary-site administrator compromise; exact provider region, bucket and network paths are deployment decisions, not asserted existing infrastructure. Restore credentials and KMS availability are prerequisites.

RTO feasibility depends on staffed incident activation, warm infrastructure, tested vendor failover, spare network/GPU hardware, and documented clinical acceptance. These resources have **not** been verified. Actual restore durations must be recorded and gaps escalated rather than marked compliant.

## RPO Compliance Verification

The existing schedule is sourced from `current_backup_schedule.csv`; proposed cadence is a design commitment to be implemented and measured. **Worst-case point age** assumes a completed verified point every interval with negligible extra lag; production monitoring must include transfer/verification lag and tighten cadence if needed. "Gap" means the current evidence cannot establish the BIA target.

| System | Tier | BIA RPO | Current schedule / verified evidence | Current gap | Proposed maximum point interval | Design check | Deployment status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Network Core | Tier 1 | 24 hours (configuration state) | 6-hour configs; diff only | Not a demonstrated restore | After every change and <= 6 h | 6 h <= 24 h | **Not yet verified** |
| Active Directory | Tier 1 | 1 hour | 8-hour snapshots; daily system state; job completion only | 8 h > 1 h | 30 min | 30 min <= 60 min | **Not yet verified** |
| Epic EHR | Tier 1 | 15 minutes | 15-minute replication; vendor monthly certificate | Needs per-point verification and vendor proof | 15 min | 15 min <= 15 min | **Not yet verified** |
| Laboratory Information System | Tier 1 | 1 hour | 24-hour nightly dump; hash only | 24 h > 1 h | 30 min | 30 min <= 60 min | **Not yet verified** |
| PACS/RIS | Tier 2 | 1 hour | 4-hour snapshot; daily metadata; missed restore test | 4 h > 1 h | 30 min | 30 min <= 60 min | **Not yet verified** |
| Pharmacy Dispensing System | Tier 1 | 15 minutes | Hourly database; daily cabinet config | 1 h > 15 min | 10 min | 10 min <= 15 min | **Not yet verified** |
| Medical Device Integration Gateway | Tier 1 | 15 minutes | Daily config export; no off-site copy | 24 h > 15 min | 5 min state / 10 min config | 10 min <= 15 min | **Not yet verified** |
| Backup and DR Infrastructure | Tier 2 | 1 hour (backup catalog/metadata) | 4-hour catalog; daily config | 4 h > 1 h | 30 min | 30 min <= 60 min | **Not yet verified** |

**Example calculation:** LIS current nightly 23:30 backup means a failure just before the next backup can lose nearly **24 hours** of changes: 24 h > 1 h RPO. Under the proposed 30-minute verified cadence, the theoretical maximum point age is 30 minutes plus completion/replication/verification lag; maintain that total at **60 minutes or less**. For pharmacy, hourly database backups cannot meet a 15-minute RPO; 10-minute verified points leave five minutes for lag. Network Core's 24-hour RPO applies **only to configuration state**; configuration must also be captured immediately after each approved change.

**Exception handling:** Missing, failed or stale backups automatically create an RPO exception and trigger the DR coordinator; do not declare compliant until an independently successful restore demonstrates usable data. Vendor certificates are supporting evidence, not substitutes for application-level verification.

## Per-System Backup Specifications

The following retention periods are proposed unless explicitly identified as current in the source schedule. Clinical record retention must be approved by Legal/Records Management; **backup retention is not a substitute for records archiving**. All restore-test evidence should include timestamp, operator, hashes, recovery-point age, record/application checks and reviewer sign-off.

### Network Core (Tier 1)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **15 minutes**; RPO **24 hours (configuration state)** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Configuration full export after every approved change and every 6 hours; immutable versioned snapshot after change; weekly consolidated full. |
| Retention | 90 days recent; 12 monthly copies; 7-year archive only if approved by records schedule. |
| Primary destination | Network management server on redundant encrypted SSD plus recovery-site equipment cache |
| Secondary destination | Encrypted versioned Git repository in geographically separate region AND immutable object-storage copy |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Restore management VLAN and routing from signed known-good config; replace core switches/routers from spare stock; restore DNS/DHCP paths; validate reachability and routing |
| Responsible role | Executes: Network Engineering Lead. Verifies: Independent Network Operations / Incident Commander |

### Active Directory (Tier 1)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **30 minutes**; RPO **1 hour** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Application-consistent system-state full daily 01:00; supported AD-aware incremental every 30 minutes; 8-hour VM snapshots for short rollback only. |
| Retention | 30 days recent; 12 monthly system-state copies; 180 days archive minimum, subject to policy. |
| Primary destination | Backup NAS rack A on encrypted storage |
| Secondary destination | Immutable object storage in independent geographic region and isolated credentials |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Establish clean network and backup access; restore healthy DC/system state via supported AD recovery; validate DNS, replication, Kerberos and dependent service-account authentication |
| Responsible role | Executes: Systems Administrator. Verifies: Identity Services Lead / Security |

### Epic EHR (Tier 1)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **1 hour**; RPO **15 minutes** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Vendor-managed continuous/15-minute recovery points (maximum 15-minute verified gap); nightly application-consistent export; daily full snapshot for rollback. |
| Retention | 35 days recent; 12 monthly snapshots; 7-year archive as specified by current schedule, subject to records policy. |
| Primary destination | Vendor hosted DR site with encrypted replicated block/object storage |
| Secondary destination | Geographically separate vendor cold archive with independent immutable copies |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Restore network, AD and DR access; vendor failover/restore; verify allergy, medication, orders, interfaces, user access and clinical sign-off |
| Responsible role | Executes: Clinical Applications Manager + Epic DR Vendor. Verifies: Clinical Informatics / Patient Safety Lead |

### Laboratory Information System (Tier 1)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **30 minutes**; RPO **1 hour** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Nightly 23:30 full compressed SQL dump; verified incremental/transaction-consistent backup every 30 minutes, including critical-order changes; daily full restore point. |
| Retention | 30 days recent; 12 monthly copies; 1-year archive currently documented; extended clinical retention requires records approval. |
| Primary destination | Backup NAS /backup/lis on encrypted redundant disks |
| Secondary destination | CloudVault Medical backup bucket in geographically separate region with immutability |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Restore network/AD and backup access; verify SHA-256 manifest; restore full then ordered incrementals; validate counts, critical values, LIS-Epic interface and lab sign-off |
| Responsible role | Executes: Laboratory Systems Lead + DBA. Verifies: Laboratory Medical Director / QA |

### PACS/RIS (Tier 2)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **1 hour**; RPO **1 hour** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Application-consistent image/object snapshot every 30 minutes; metadata/database incremental every 30 minutes; daily full metadata export; weekly full integrity checkpoint. |
| Retention | 30 days hot; 12 monthly copies; 7-year archive as in current schedule, subject to imaging policy. |
| Primary destination | PACS storage cluster encrypted block/object snapshot tier |
| Secondary destination | Geographically separate encrypted object archive with verified cross-region replication |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Restore network, AD, storage and imaging GPU nodes; recover metadata before images; validate image-to-order mapping and sample studies |
| Responsible role | Executes: Radiology Systems Lead. Verifies: Radiology Clinical Lead |

### Pharmacy Dispensing System (Tier 1)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **30 minutes**; RPO **15 minutes** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Application-consistent database incremental every 10 minutes; nightly full database; cabinet configuration export on every change and at least every 10 minutes; daily immutable full configuration checkpoint. |
| Retention | 30 days recent; 12 monthly copies; 1-year archive currently documented, pending pharmacy retention review. |
| Primary destination | Pharmacy backup share on encrypted replicated SSD |
| Secondary destination | Encrypted immutable cloud copy in independent region |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Restore network, AD and Epic medication interface; restore database and cabinet configuration; validate formulary, allergy cross-check, cabinet inventory and controlled-drug reconciliation |
| Responsible role | Executes: Pharmacy IT Lead. Verifies: Chief Pharmacist / Medication Safety Officer |

### Medical Device Integration Gateway (Tier 1)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **30 minutes**; RPO **15 minutes** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Configuration full export after each approved change and every 10 minutes; state/queue journal replication every 5 minutes if supported; nightly signed full image. |
| Retention | 14 days recent currently; propose 90 days recent, 12 monthly copies, 1-year archive pending biomedical policy. |
| Primary destination | Biomed file share plus encrypted local failover appliance |
| Secondary destination | NEW geographically separate immutable object-storage copy with separate credentials |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Restore network paths, device trust/certificates and gateway image; restore configuration and queued data; verify ICU telemetry delivery and bedside fallback before release |
| Responsible role | Executes: Biomedical IT Lead. Verifies: ICU Charge Nurse / Clinical Engineering Lead |

### Backup and DR Infrastructure (Tier 2)

| Field | Specification |
| --- | --- |
| BIA recovery objectives | RTO **2 hours**; RPO **1 hour (backup catalog/metadata)** |
| Backup type | Full plus incremental/snapshot/replication as specified below |
| Schedule | Catalog application-consistent snapshot every 30 minutes; daily full catalog/config export; backup keys/escrow and recovery metadata after every change. |
| Retention | 30 days recent; 12 monthly copies; 1-year offsite archive currently documented. |
| Primary destination | DR platform storage on encrypted redundant disks |
| Secondary destination | Isolated backup account in independent region with immutable copy and offline key escrow |
| Encryption at rest | AES-256; envelope keys in segregated KMS/HSM, audited access, rotation and escrow |
| Encryption in transit | TLS 1.2+ with authenticated endpoints and certificate checks |
| Integrity verification | SHA-256 at source and destination for every completed artifact; daily automated consistency checks; monthly isolated test restore and quarterly end-to-end failover exercise; capture results and reviewer sign-off |
| Restoration sequence | Establish clean network and emergency break-glass access; restore catalog, repository mapping, KMS access and restore engine; test retrieval before clinical restores |
| Responsible role | Executes: Infrastructure Manager / Backup Administrator. Verifies: Security + DR Coordinator |

## Full Data Center Loss: Restoration Sequence

**Trigger:** Primary data center power/cooling or physical loss makes production infrastructure unusable. Incident Commander declares disaster, confirms patient-safety escalation and starts a single event clock. Clinical downtime operations begin immediately and continue until clinical leadership accepts restored services.

1. **Safety and command (parallel):** activate incident command, downtime forms, manual medication/allergy checks and clinical escalation; record the incident start, available staff, decisions and evidence.
2. **Clean recovery network:** activate secondary-site connectivity, firewalls, routing, DNS/DHCP prerequisites and verified Network Core configuration from off-site storage; validate VLAN isolation, ICU connectivity and management access. **Network Core RTO: 15 min** is aspirational pending spare capacity and timed drills.
3. **Identity and emergency access:** activate healthy secondary AD where available or recover a domain controller from verified system state; validate DNS, time synchronization, authentication, privileged recovery identities and service accounts. If AD blocks backup access, use documented independently held break-glass credentials under dual control.
4. **Backup control plane:** recover isolated backup catalog, encryption keys, immutable repository access and restore engine. Verify manifests and retrieve test objects. This step can run in parallel with identity when isolated credentials exist.
5. **Life-critical clinical pathways (parallel once prerequisites pass):** recover Medical Device Integration Gateway, Pharmacy Dispensing System, LIS and Epic EHR on prepared failover hosts. Coordinate dependencies: restore Epic core services before validating LIS results interface and pharmacy order flows; allow standalone LIS and pharmacy validation before Epic is ready. Validate patient identity, critical values, medication lists and ICU telemetry with clinical owners.
6. **Radiology:** recover PACS/RIS metadata and imaging data, GPU rendering and Epic order/result links; verify representative urgent studies and clinician access.
7. **Communications and visibility:** recover Email and Secure Messaging (Tier 3) and Security Operations Platform (Tier 3) after network/identity; meanwhile use the approved alternate communications bridge and reduced-mode security monitoring.
8. **Controlled return to service:** verify data reconciliation, clinical sign-off, backlog entry, event/audit logging and post-restoration monitoring. Record actual times, RPO evidence, exceptions and decisions.

**Critical-path caveat:** A sequential interpretation of steps 2–5 cannot automatically satisfy the BIA's 15–60 minute RTOs. To make those targets feasible, pre-stage an operational secondary network, live AD, independent backup access, warmed application capacity and tested automated cutover. Until a timed integrated exercise proves it, the recovery objectives remain **unvalidated and at risk**; the board must fund mitigations or approve revised targets, never quietly change the BIA.

## Dependency Restore Constraints

```text
Alternate site / power / out-of-band incident communications
└── Network Core (routing, segmentation, DNS/DHCP reachability)
    ├── Active Directory (identity, DNS, service accounts)
    │   ├── Epic EHR
    │   │   ├── LIS interface and result delivery
    │   │   ├── Pharmacy orders and medication reconciliation
    │   │   └── PACS/RIS orders and result integration
    │   ├── PACS/RIS user authentication
    │   ├── Email and Secure Messaging (Tier 3)
    │   └── Security Operations Platform (Tier 3)
    ├── Medical Device Integration Gateway (ICU network paths)
    ├── Backup and DR Infrastructure (isolated break-glass alternative)
    └── Backup transfer and off-site replication
```

- **Circular dependency:** backup console may require AD, while AD recovery may require the backup console. Maintain independent break-glass identities, offline runbooks and isolated key escrow; test this bootstrap path.
- **Epic/LIS/pharmacy:** database restoration is not clinical restoration. Validate interfaces, identity mapping, patient/order integrity and clinical workflows before declaring RTO achieved.
- **PACS/RIS:** metadata/image consistency and GPU readiness are required; restoring only image objects does not complete service recovery.
- **Medical devices:** confirm manufacturer-supported configuration, certificates, device associations and bedside validation; do not use an unvalidated gateway for care decisions.
- **Immutable/off-site storage:** secondary storage must be geographically separated and independently administered. CloudVault Medical is the currently named LIS secondary destination, but location, immutability, key custody and retrieval performance are **not established by the materials**.
- **Restoration order versus parallelism:** prerequisites are strict, but independent clinical recoveries can run concurrently after the core network, identity and recovery access are available.

## Implementation, Validation and Open Decisions

| Action | Accountable role | Acceptance evidence |
| --- | --- | --- |
| Confirm BIA targets and allocate warm recovery capacity | CISO + clinical owners | Approved BIA and capacity/contract sign-off |
| Fix LIS 24-hour versus 1-hour RPO conflict | Laboratory Systems Lead | Timestamped verified <= 60-minute recovery points and isolated restore |
| Add gateway off-site copy and <= 15-minute state/config protection | Biomedical IT Lead | Independent-region copy and ICU workflow test |
| Shorten pharmacy DB and cabinet configuration intervals | Pharmacy IT Lead | <= 15-minute usable point and cabinet reconciliation |
| Upgrade AD snapshots, PACS metadata and DR catalog cadence | Infrastructure Manager | Completed-point monitoring and documented restore tests |
| Verify Epic vendor 15-minute RPO and 1-hour clinical RTO | Clinical Applications Manager | Vendor recovery-point proof and timed user acceptance |
| Exercise full-site recovery and record honest RTO/RPO outcomes | DR Coordinator | Signed drill report with failures, actual times and corrective actions |

**Evidence status:** No recovery test was executed for this design; no production backup settings were changed. Source observations come from the provided CSV, log review and dependency seed; frequencies, retention changes, controls and restore timings above are **proposals** until deployed and tested.
