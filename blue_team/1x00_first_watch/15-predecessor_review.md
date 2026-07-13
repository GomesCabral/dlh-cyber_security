# Predecessor Review

## Part 1 – Comparative Analysis

| Finding | Marcus's Assessment | Your Assessment | Agree / Disagree | Resolution |
|---------|---------------------|-----------------|------------------|------------|
| Network Segmentation | Flat network allows unrestricted lateral movement. | GAP-004 identified the lack of network segmentation as a Critical risk affecting all clinical systems and medical devices. | Agree | Both assessments conclude that VLAN segmentation and internal firewall rules are the highest infrastructure priority. |
| Backup Isolation | Backup NAS is on the production network and vulnerable to ransomware. | GAP-008 identified backup resilience as inadequate because backups are accessible from the production environment and recovery testing is limited. | Agree | Cloud or immutable off-site backups should be implemented to prevent ransomware from encrypting backup copies. |
| Medical IoT Exposure | Medical devices share the same network as workstations and servers. | GAP-001 and GAP-004 identified medical devices as exposed because no network isolation exists. | Agree | Medical IoT devices require dedicated VLANs and restricted communication paths. |
| Security Monitoring | No SIEM, IDS or centralized log monitoring. | GAP-007 identified the complete absence of centralized monitoring and logging as a Critical gap. | Agree | Deploy centralized log collection and SIEM capabilities beginning with critical infrastructure. |
| Multi-Factor Authentication | MFA is not deployed across VPN, EHR or administrative accounts. | GAP-011 identified weak identity management and recommended automated account management together with stronger authentication controls. | Agree | MFA should be prioritized for VPN, administrative accounts and clinical applications. |
| Westside Clinic Security | Consumer networking equipment and weak physical security increase organizational risk. | Asset Registry identified unmanaged infrastructure at Westside together with weak network protection. | Agree | Replace the consumer router with an enterprise firewall and improve physical security controls. |
| Shared Radiology Credentials | Shared PACS credentials prevent accountability. | The same issue was identified during earlier assessments as a weakness affecting accountability and auditability. | Agree | Replace shared accounts with individual authentication or badge-based login. |
| Print Server End-of-Life | Windows Server 2012 R2 is unsupported but lower priority. | Asset Registry classified print-srv-01 as an unsupported server. | Agree | Upgrade during planned maintenance after higher-risk systems have been addressed. |

---

## Additional Findings Identified by Marcus

The following findings were not explicitly documented in my previous assessment and should be added.

### GAP-013

**Title:** Legacy TLS 1.0 Enabled on Patient Portal

**Risk Level:** High

**Justification:** TLS 1.0 is deprecated and increases the risk of interception or downgrade attacks against patient portal communications.

**Recommended Action:** Disable TLS 1.0 and allow only modern TLS versions.

---

### GAP-014

**Title:** No Data Loss Prevention (DLP)

**Risk Level:** High

**Justification:** Sensitive patient and financial information can be copied to email, USB devices or cloud storage without detection.

**Recommended Action:** Deploy DLP controls for email, removable media and cloud services.

---

### GAP-015

**Title:** Unrestricted USB Storage

**Risk Level:** High

**Justification:** Users can copy Restricted data to removable media, increasing the risk of data exfiltration and malware infection.

**Recommended Action:** Restrict USB storage through Group Policy and endpoint protection.

---

### GAP-016

**Title:** No Formal Change Management Process

**Risk Level:** Medium

**Justification:** Uncontrolled infrastructure changes increase the likelihood of configuration errors such as the failed backup cron job.

**Recommended Action:** Implement a documented change management process with approval and testing requirements.

---

## Findings Identified During My Assessment but Not Mentioned by Marcus

| Finding | Possible Reason |
|----------|-----------------|
| Shadow IT devices (personal NAS, Google Drive, Raspberry Pi) | Marcus likely had limited visibility or insufficient time to investigate unofficial systems. |
| Unknown Linux hosts discovered during the network scan (UNKNOWN-01 and Westside device) | These systems were identified after the network scan requested by James Chen. |
| Comprehensive Asset Registry | Marcus's assessment was incomplete before the full inventory was compiled. |
| Data Classification and Data Lifecycle Mapping | These activities were completed later as part of the formal assessment process. |
| Complete Control Matrix and Risk Treatment Plan | Marcus left before these governance activities were completed. |

---

# Part 2 – The Last Page

Marcus's unfinished assessment naturally extends the work completed in this security posture review. The internal assessment identifies MedDefense's critical assets, existing controls and security gaps, providing a clear picture of the organization's current exposure. The next logical step is to compare these weaknesses against the tactics used by ransomware groups, insider threats and other healthcare-focused attackers using frameworks such as MITRE ATT&CK and STRIDE. Combining internal posture analysis with external threat intelligence enables MedDefense to prioritize security investments based on both organizational weaknesses and the current healthcare threat landscape.
