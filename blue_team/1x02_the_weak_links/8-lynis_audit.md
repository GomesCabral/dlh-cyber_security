# 8. Lynis Audit

## Part 1 – Install and Run

The Lynis security audit was performed on a Kali Linux virtual machine using **Lynis 3.1.6**. The audit completed successfully and analyzed the operating system, authentication, kernel configuration, networking, services, logging, cryptography, file permissions, hardening settings and installed software.

**Hardening Index:** **63**

The audit reported:
- **279 tests performed**
- **3 warnings**
- **61 suggestions**

---

# Part 2 – Analyze Results

## Hardening Index

**Score:** **63**

A score of 63 indicates that the system follows many recommended Linux security practices but still has several areas that require additional hardening.

## Top 5 Warnings

### 1. Only one responsive DNS server
**What Lynis checks:** DNS redundancy.

**Why it matters:** A single DNS server creates a single point of failure.

**Remediation:** Configure at least two working DNS servers.

### 2. IPv6 DNS server not responding
**What Lynis checks:** Availability of configured IPv6 DNS servers.

**Why it matters:** Failed DNS servers reduce reliability.

**Remediation:** Correct or remove unused IPv6 DNS entries.

### 3. Insufficient DNS redundancy
**What Lynis checks:** Number of operational name servers.

**Why it matters:** Loss of DNS may interrupt authentication and software updates.

**Remediation:** Configure multiple responsive name servers.

### 4. Home directory permissions
**What Lynis checks:** User home directory permissions.

**Why it matters:** Weak permissions may expose user files.

**Remediation:** Restrict permissions using `chmod` and verify ownership.

### 5. Kernel hardening settings
**What Lynis checks:** Linux kernel security parameters.

**Why it matters:** Weak kernel settings increase the attack surface.

**Remediation:** Apply the recommended `sysctl` hardening settings.

---

## Top 5 Suggestions

### 1. Install Fail2Ban
Blocks repeated authentication failures to reduce brute-force attacks.

### 2. Protect GRUB with a password
Prevents unauthorized users from modifying boot options.

### 3. Install a PAM password-strength module
Enforces stronger password policies.

### 4. Configure password aging
Forces periodic password changes and reduces long-term credential exposure.

### 5. Disable unused USB storage
Reduces malware infection and data exfiltration risks.

---

## Category Breakdown

The strongest categories were logging, firewall configuration, package management and time synchronization.

The weakest categories were authentication, kernel hardening, SSH configuration, file permissions and boot security.

Overall, the audit indicates a reasonably secure system with room for improvement through better hardening rather than major software changes.

---

# Part 3 – MedDefense Projection

If Lynis were executed on **billing-srv-01**, the following findings would likely be reported:

### 1. Ubuntu 18.04 is outdated
Lynis would recommend upgrading to a supported operating system because Ubuntu 18.04 no longer receives standard security updates.

### 2. Apache 2.4.29 is outdated
The installed Apache version contains known vulnerabilities and should be upgraded.

### 3. SSH password authentication is enabled
Lynis would recommend using SSH key authentication and disabling password logins.

### 4. Poor patch management
The scan report indicates delayed package updates. Lynis would recommend a regular patch management process.

### 5. Additional hardening required
Because the server previously suffered a cryptocurrency miner compromise, Lynis would likely recommend stronger system hardening, stricter SSH settings, firewall improvements and enhanced monitoring.

---

# Conclusion

The Lynis audit demonstrates that many security issues are related to configuration and system hardening rather than software vulnerabilities. Running security audits regularly helps identify weaknesses before attackers can exploit them. Applying the same methodology to MedDefense would likely reveal both outdated software and insecure configurations that should be prioritized for remediation.
