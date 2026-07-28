# 3. The 72-Hour Emergency Response Plan

## Goal

Reduce MedDefense's exposure to the active Crimson Tide ransomware campaign within the next 72 hours by prioritising the highest-impact actions that can realistically be completed with current staffing and operational constraints.

---

# Situation Summary

## Current Constraints

- Sarah Park has **2 IT engineers** available tonight (plus herself).
- FortiGate firmware **cannot be downloaded until the support contract (£2,400 equivalent scenario cost provided: $2,400/year) is renewed**.
- Network segmentation requires approximately **2–3 days**.
- NAS-01 can be physically isolated **immediately**.
- Kerberos hardening requires a maintenance window because authentication could be affected.

---

# Tier 1 – Tonight (0–12 Hours)

These actions require no procurement and have minimal operational risk.

| Action | Phase Blocked | Owner | Prerequisites | Risk of Action | Risk of Inaction |
|---|---|---|---|---|---|
| Freeze all non-essential production changes. | All | James Chen | Notify IT staff. | Delays planned IT work. | Uncontrolled changes complicate incident response. |
| Verify FortiGate firmware version and preserve logs. | Phase 1 | Sarah | Admin access. | None. | Evidence may be lost and compromise missed. |
| Review FortiGate logs for CISA IOCs and unusual VPN sessions. | Phases 1–2 | You | Log access. | False positives. | Existing compromise remains undetected. |
| Physically disconnect NAS-01 from the production network after confirming backup completion. | Phase 5 | Sarah | Backup finished. | Scheduled backups pause until reconnection. | Ransomware could destroy every backup. |
| Verify that no suspicious GPOs, Rclone, vssadmin activity or new administrator accounts exist. | Phases 3–6 | IT Staff | Domain Admin access. | Minor investigation effort. | Active attacker remains inside the environment. |
| Notify executive leadership that emergency change control is active. | Phase 7 | James | None. | None. | Poor communication during a crisis. |

---

# Tier 2 – Tomorrow (12–36 Hours)

These actions require coordination and Board approval.

| Action | Phase Blocked | Owner | Prerequisites | Risk of Action | Risk of Inaction |
|---|---|---|---|---|---|
| Renew the FortiGate support contract. | Phase 1 | James / CFO | Emergency Board approval. | Additional cost. | No access to security updates. |
| Download and install FortiOS 7.0.14 during an approved maintenance window. | Phase 1 | Sarah | Support contract renewed; configuration backup completed. | Temporary VPN outage. | Public RCE vulnerability remains exploitable. |
| Enable MFA for all VPN administrators and remote users. | Phases 2–3 | Sarah | MFA platform available. | Some user disruption. | Stolen credentials remain effective. |
| Begin emergency review of privileged and service accounts. | Phase 3 | You + Sarah | AD access. | Possible application impact if accounts are changed incorrectly. | Excessive privileges continue to assist attackers. |
| Increase monitoring of outbound traffic and alert on transfers >5 GB. | Phase 4 | You | Firewall/SIEM access. | Additional alerts. | Large-scale exfiltration may go unnoticed. |

---

# Tier 3 – This Week (36–72 Hours)

These actions require testing, procurement or significant configuration work.

| Action | Phase Blocked | Owner | Prerequisites | Risk of Action | Risk of Inaction |
|---|---|---|---|---|---|
| Implement network segmentation between servers, workstations, medical devices and management networks. | Phases 2–6 | Sarah | Switch configuration testing. | Temporary connectivity issues. | Flat network allows unrestricted lateral movement. |
| Disable RC4 and DES; enable AES-only Kerberos. | Phase 3 | Sarah | Maintenance window; authentication testing. | Legacy systems may fail authentication. | Kerberoasting remains viable. |
| Deploy immutable and off-site encrypted backups. | Phase 5 | Sarah | Backup validation. | Storage cost and migration effort. | Backup destruction remains possible. |
| Accelerate EDR deployment to all servers and workstations. | Phases 3–6 | External Vendor + Sarah | Licensing and deployment plan. | Performance tuning required. | Malicious activity may not be detected quickly. |
| Validate Incident Response Plan through a tabletop exercise based on Crimson Tide. | Phase 7 | James + You | Updated documentation. | Staff time. | Crisis response remains untested. |

---

# Resource Conflict Assessment

## Conflict 1 – Sarah Park

Sarah is responsible for nearly every technical change.

**Resolution:** Delegate log review and IOC hunting to the security analyst while the two IT engineers handle backup isolation and infrastructure tasks.

## Conflict 2 – FortiGate

The appliance must be investigated before being upgraded.

**Resolution:** Preserve configuration files and logs first, then patch immediately after evidence collection.

## Conflict 3 – Active Directory

Kerberos hardening and privileged-account review both affect authentication.

**Resolution:** Review accounts first, schedule Kerberos encryption changes during the approved maintenance window afterwards.

## Conflict 4 – NAS-01

Backup isolation may interrupt scheduled backups.

**Resolution:** Confirm the latest successful backup before disconnecting the NAS and document temporary manual backup procedures.

---

# Priority Timeline

| Time | Priority |
|---|---|
| 0–12 Hours | Preserve evidence, isolate backups, investigate compromise, activate emergency change control. |
| 12–36 Hours | Renew FortiGate support, patch FortiOS, enable MFA, review privileged accounts, increase monitoring. |
| 36–72 Hours | Implement segmentation, Kerberos hardening, immutable backups, EDR deployment and IR validation. |

---

# Final Recommendation

The immediate priority is to **prevent initial access and preserve recovery capability**. The first night should focus on evidence preservation, FortiGate investigation and isolating NAS-01. The following day should remove the known FortiGate vulnerability and strengthen authentication. The remainder of the 72-hour window should reduce lateral movement and ensure that MedDefense can recover even if an attacker gains an initial foothold.

