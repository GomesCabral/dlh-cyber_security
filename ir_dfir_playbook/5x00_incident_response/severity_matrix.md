# MedDefense Severity Matrix

## Purpose

Establish a common severity language for all MedDefense Health Systems security incidents. Apply this matrix from the first alert through incident closure to prioritize patient safety, data protection, and clinical service continuity.

## Severity Matrix

| **Level** | **Patient Safety Impact** | **Data Exposure** | **Service Availability** | **Max Response Time** | **Decision Authority** |
| :-------- | :------------------------ | :---------------- | :----------------------- | :-------------------- | :--------------------- |
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

The columns describe severity thresholds, not conditions that must all occur together. Assign the highest severity justified by any single criterion; the response time is the maximum time to initiate response after identification.

## Level Definitions

### SEV1

- Ransomware disrupting Epic clinical workflows across the Main Hospital and another MedDefense site, creating a high patient-safety risk.
- Confirmed broad exfiltration of patient records from the Epic electronic health record environment.
- Full outage of patient-critical clinical systems at Main Hospital during active care.

### SEV2

- Confirmed compromise of a privileged account with access to the MedDefense LIS, with limited confirmed data exposure.
- Malware causing a partial outage of the laboratory information system while clinical workarounds remain available.
- Security incident causing moderate patient-safety impact at North Site rehabilitation services.

### SEV3

- Suspicious authentication activity involving an on-prem Active Directory account, with possible but unconfirmed data access.
- Degraded performance of Nexus Patient Scheduling linked to suspicious activity, without an outage.
- A suspicious PowerShell execution detected by Wazuh EDR on one West Campus clinical workstation, with low patient-safety impact.

### SEV4

- A blocked malicious email reported by a MedDefense employee, with no execution or exposure.
- A single unsuccessful unauthorized sign-in attempt detected in Azure AD, with no indication of compromise.
- A benign or false-positive endpoint alert verified by the SOC, with no service or patient impact.

## Escalation Rule

Review severity at every incident status update and immediately when new evidence emerges. Raise severity as soon as any patient-safety, data-exposure, or service-availability criterion meets a higher level; notify the decision authority for that level without waiting for the next update. Lower severity only after containment is confirmed, the supporting evidence is documented, and the IR Commander approves the change; record the reason, time, and approver in the incident log.
