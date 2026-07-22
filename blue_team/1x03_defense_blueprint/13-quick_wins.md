# 13. Quick Wins
## MedDefense Health Systems

---

# Quick Win #1: Enforce Multi-Factor Authentication (MFA) on VPN and Administrative Accounts

**Risk Addressed:** RISK-001 – VPN Compromise Leading to Full Network Access

**Action:**
1. Enable MFA for all VPN users.
2. Enable MFA for all privileged and administrative accounts.
3. Remove any temporary MFA exceptions.
4. Test authentication with selected users.
5. Notify all employees of the new login procedure.

**Owner:** IT Director (Sarah Park) with Security Analyst support

**Timeline:** 3–5 days

**Cost:** $0 (covered by existing Microsoft 365 licensing)

**Risk Reduction:**
Blocks credential theft attacks and significantly disrupts Kill Chain #1 by preventing attackers from using stolen passwords for initial access.

**Verification:**
- Review VPN authentication logs.
- Confirm 100% of administrative accounts require MFA.
- Perform successful and unsuccessful login tests.

---

# Quick Win #2: Disable Dormant and Unused Accounts

**Risk Addressed:** RISK-002 – Unauthorized Access Through Stale Accounts

**Action:**
1. Export all Active Directory accounts.
2. Identify accounts inactive for more than 45 days.
3. Disable unused user accounts.
4. Remove unnecessary administrative privileges.
5. Document all account changes.

**Owner:** IT Director

**Timeline:** 2 days

**Cost:** $0

**Risk Reduction:**
Reduces opportunities for attackers to abuse forgotten accounts and limits lateral movement described in Kill Chains #1 and #2.

**Verification:**
- Review Active Directory.
- Confirm inactive accounts are disabled.
- Verify administrative group membership.

---

# Quick Win #3: Block Unauthorized USB Storage Devices

**Risk Addressed:** RISK-003 – Insider Data Theft

**Action:**
1. Enable Group Policy to block USB storage devices.
2. Allow exceptions only for approved encrypted devices.
3. Notify employees of the new policy.
4. Document approved exceptions.

**Owner:** IT Director

**Timeline:** 3 days

**Cost:** $0

**Risk Reduction:**
Disrupts Kill Chain #3 by reducing data exfiltration and malware introduction through removable media.

**Verification:**
- Test unauthorized USB devices.
- Confirm only approved encrypted devices function.
- Review endpoint logs.

---

# Quick Win #4: Patch Critical Internet-Facing Systems

**Risk Addressed:** RISK-004 – Exploitation of Critical Vulnerabilities

**Action:**
1. Review outstanding Critical and High vulnerabilities.
2. Patch Internet-facing servers.
3. Update VPN gateway.
4. Reboot systems during maintenance windows.
5. Perform vulnerability rescan.

**Owner:** IT Operations Team

**Timeline:** 5–7 days

**Cost:** Minimal (existing maintenance contracts)

**Risk Reduction:**
Reduces known CVEs, removes publicly exploitable vulnerabilities and interrupts Kill Chain #1 before initial compromise.

**Verification:**
- Vulnerability rescan.
- Verify software versions.
- Confirm CVEs no longer detected.

---

# Quick Win #5: Centralize Security Logging with Wazuh

**Risk Addressed:** RISK-005 – Delayed Threat Detection

**Action:**
1. Deploy Wazuh Manager.
2. Configure Windows and Linux log collection.
3. Enable authentication and security event logging.
4. Create alerts for failed logins, privilege escalation and malware.
5. Test alert generation.

**Owner:** Security Analyst

**Timeline:** 7–10 days

**Cost:** $0 (Open-source software)

**Risk Reduction:**
Improves visibility across the environment and shortens attacker dwell time during Kill Chains #1 and #2.

**Verification:**
- Confirm endpoints are reporting.
- Generate test security events.
- Verify alerts appear in the Wazuh dashboard.

---

# Why Quick Wins Matter

Quick wins provide immediate risk reduction while demonstrating that the security program is delivering measurable results. They increase confidence among executives, staff and the Board by showing that meaningful security improvements can be achieved without waiting for major purchases or long implementation projects. Quick wins also build momentum, encourage cooperation between IT and Security, and create a stronger foundation for larger initiatives such as network segmentation, SIEM expansion and medical device isolation. During the first month of a security program, they establish credibility, improve security culture and reduce the organization's exposure to common attack paths using existing resources.
