# 15. Red Team Your Blueprint – MedDefense Health Systems

## Part 1 – The Attacker's Perspective

### Remaining Viable Kill Chain

Even after implementing the funded security controls (Network Segmentation, MFA, Enterprise SIEM, Immutable Backups, and the Dedicated Firewall for Westside Clinic), **Kill Chain #3 (Insider Data Theft)** remains the most viable attack path.

Unlike external ransomware attacks, insider threats originate from trusted users who already possess legitimate access to MedDefense systems. The funded controls significantly reduce unauthorized external access and lateral movement but cannot fully prevent a malicious or negligent employee from abusing authorized privileges. Since the organization deferred Endpoint Detection and Response (EDR) and Medical Device Network Isolation, insider activity is less likely to be detected immediately and sensitive information may still be copied before an incident is identified.

---

## Alternative Attack Path

As a BlackReef ransomware affiliate, I would avoid directly attacking the network perimeter and instead target an employee with legitimate access.

### Step 1 – Spear Phishing

Deliver a convincing phishing email to a billing employee or physician containing a malicious Microsoft Office attachment or credential harvesting page.

**Objective**

Obtain valid user credentials or execute malware on a trusted workstation.

---

### Step 2 – Abuse Legitimate Access

Log in using the stolen credentials through the VPN protected by MFA.

Rather than attacking MFA directly, compromise an already authenticated workstation using malware or session hijacking.

**Objective**

Operate under the identity of a legitimate employee.

---

### Step 3 – Credential Escalation

Search local browsers, cached credentials and mapped network drives for additional privileged credentials.

Because Sophos Intercept X (EDR) was deferred, advanced endpoint behavior monitoring is unavailable.

**Objective**

Obtain higher privileges without generating strong endpoint alerts.

---

### Step 4 – Data Exfiltration

Copy sensitive patient records and financial information before launching ransomware.

Although segmentation limits movement, authorized users can still access many business-critical systems.

**Objective**

Steal data for double-extortion.

---

### Step 5 – Target Critical Servers

Encrypt the Billing Server and selected file shares while avoiding protected backup repositories.

Network segmentation limits organization-wide encryption, but disruption of key business services still causes operational and financial damage.

---

## Remaining Insider Threat

The most dangerous remaining insider threat is the negligent employee identified in **Threat T3** from Project **1x01**.

Examples include:

- Copying patient records onto unauthorized USB devices.
- Uploading sensitive files to personal cloud storage.
- Falling victim to phishing attacks.
- Sharing passwords with coworkers.
- Accidentally executing malicious attachments.

Although MFA, segmentation and SIEM reduce overall organizational risk, these controls do not eliminate insider misuse of legitimate access. Until EDR, Data Loss Prevention (DLP), continuous monitoring and additional user-awareness improvements are implemented, insider threats remain a significant concern.

---

# Part 2 – Honest Assessment

## Overall Residual Risk

**Residual Risk Rating: Medium**

The proposed security program substantially improves MedDefense's security posture.

High-risk weaknesses such as flat network architecture, lack of MFA, insufficient monitoring, weak backup protection and insecure remote connectivity have been addressed.

However, several important risks remain because budget constraints prevented implementation of every recommended control.

---

## Biggest Remaining Gap

The single largest remaining weakness is the absence of **Endpoint Detection and Response (EDR)** across workstations and servers.

Without advanced endpoint visibility:

- Malware may remain undetected longer.
- Credential theft is harder to identify.
- Insider activity is more difficult to investigate.
- Security analysts have reduced forensic capability.
- Attackers can establish persistence before SIEM alerts become available.

Although the SIEM improves centralized visibility, endpoint telemetry remains limited without EDR.

---

## Priority for Next Year's Budget

The highest priority for the next fiscal year should be the deployment of **Sophos Intercept X (Enterprise EDR)** across all servers and workstations.

Reasons:

- Detects ransomware before encryption completes.
- Identifies credential theft and privilege escalation.
- Improves investigation and forensic capabilities.
- Complements the SIEM by providing endpoint telemetry.
- Reduces residual risk from insider threats and advanced malware.

Once EDR is fully deployed, MedDefense should then implement **Medical Device Network Isolation** followed by an outsourced **24/7 Managed Security Operations Center (SOC)** to further improve continuous monitoring and incident response.

---

# Final Assessment

The proposed Defense Blueprint significantly reduces MedDefense's exposure to ransomware, external compromise and lateral movement while remaining within the approved **$120,000** annual budget.

A motivated attacker could still exploit trusted users or insider weaknesses, but successful attacks would be substantially more difficult, easier to detect and far less likely to compromise the entire organization. The remaining residual risks are well understood, documented in the Risk Register and provide a clear roadmap for future security investments.
