# Insider Assessment

## Scenario 1 – The Shared Login

**Classification:** Negligent – Staff share credentials for convenience, reducing accountability rather than intentionally causing harm.

**Behavioral Indicators:**
- Multiple users authenticating with the same account.
- Continuous sessions without logoff.
- No user accountability in audit logs.

**Existing Control (from 1x00):**
Password Policy (Administrative Preventive).

**Gap Exploited (from 1x00):**
GAP-005 – Shared Accounts and Weak Access Management.

**Recommended Mitigation:**
Implement individual user accounts with badge or smart-card authentication for PACS workstations.

---

## Scenario 2 – The Ghost Account

**Classification:** Negligent – The account remained active because the offboarding process failed.

**Behavioral Indicators:**
- VPN logins after contract termination.
- Authentication during unusual hours.
- Continued account activity despite inactive employment.

**Existing Control (from 1x00):**
Account Management Policy (Administrative Preventive).

**Gap Exploited (from 1x00):**
GAP-011 – No Automated Account Lifecycle Management.

**Recommended Mitigation:**
Automatically disable user accounts immediately after HR termination.

---

## Scenario 3 – The Personal NAS

**Classification:** Negligent – The doctor intended to improve convenience but created an unmanaged storage system.

**Behavioral Indicators:**
- Unknown device connected to the network.
- Sensitive files stored outside approved systems.
- Device missing from the Asset Registry.

**Existing Control (from 1x00):**
No existing control adequately covers this scenario.

**Gap Exploited (from 1x00):**
GAP-010 – Shadow IT.

**Recommended Mitigation:**
Implement a formal Shadow IT policy and Network Access Control (NAC).

---

## Scenario 4 – The Curious Employee

**Classification:** Malicious – The employee intentionally accessed patient records without a business need and disclosed confidential information.

**Behavioral Indicators:**
- Access to records outside normal job duties.
- Viewing high-profile patient records.
- Access unrelated to assigned patients.

**Existing Control (from 1x00):**
EHR Audit Logging (Technical Detective).

**Gap Exploited (from 1x00):**
GAP-008 – No User Activity Monitoring.

**Recommended Mitigation:**
Deploy user behavior monitoring with alerts for inappropriate EHR access.

---

## Scenario 5 – The Overworked Admin

**Classification:** Negligent – The administrator exposed privileged credentials while trying to simplify routine work.

**Behavioral Indicators:**
- Administrative passwords stored in plaintext.
- Credential files shared by email.
- Unapproved automation scripts.

**Existing Control (from 1x00):**
Password Policy (Administrative Preventive).

**Gap Exploited (from 1x00):**
GAP-009 – Poor Privileged Credential Management.

**Recommended Mitigation:**
Implement a Privileged Access Management (PAM) solution and prohibit plaintext credential storage.

---

## Pattern Assessment

The main weakness at MedDefense is weak identity and access management combined with limited monitoring. Shared accounts, inactive user accounts, Shadow IT and the lack of centralized monitoring reduce accountability and make suspicious behavior difficult to detect. These weaknesses directly relate to the gaps identified in Project 1x00, particularly the lack of automated account management, insufficient user activity monitoring and poor control over unauthorized systems.
