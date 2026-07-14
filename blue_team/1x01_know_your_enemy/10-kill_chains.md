# Kill Chain #1: Phishing Leading to Ransomware

**Threat Actor:** Ransomware Group (Organized Crime)

**Target Asset:** EHR System

**Expected Impact:** Clinical disruption, patient data exposure and financial loss (Confidentiality, Integrity, Availability).

### Step 1 – Initial Access
**Vector:** Phishing email

**Surface:** Human

**Detail:** A clinician opens a malicious attachment and enters their credentials into a fake login page.

### Step 2 – Establish Foothold
**Action:** Malware is installed and attacker obtains persistent access.

**MedDefense Weakness:** No centralized monitoring (GAP-007).

### Step 3 – Lateral Movement / Escalation
**Action:** The attacker moves through the flat network toward critical servers.

**MedDefense Weakness:** No network segmentation (GAP-004).

### Step 4 – Objective Execution
**Action:** Encrypts the EHR servers and databases.

**Data/System Affected:** Patient records and clinical services.

### Step 5 – Impact
**Business Impact:** Hospital operations are disrupted, patient care is delayed and regulatory reporting is required.

**CIA Pillars:** Confidentiality, Integrity and Availability.

**Gaps Exploited:** GAP-004, GAP-007.

**Break Points:**
- Email filtering and phishing awareness training.
- SIEM or IDS detecting suspicious activity before ransomware deployment.

---

# Kill Chain #2: VPN Exploit to Active Directory

**Threat Actor:** Ransomware Group (Organized Crime)

**Target Asset:** Active Directory

**Expected Impact:** Full domain compromise and loss of administrative control.

### Step 1 – Initial Access
**Vector:** VPN vulnerability.

**Surface:** External

**Detail:** The attacker exploits an unpatched VPN service.

### Step 2 – Establish Foothold
**Action:** Creates persistence on an internal system.

**MedDefense Weakness:** Unsupported software (GAP-003).

### Step 3 – Lateral Movement / Escalation
**Action:** Uses unrestricted network access to reach Domain Controllers.

**MedDefense Weakness:** Flat network (GAP-004).

### Step 4 – Objective Execution
**Action:** Obtains Domain Administrator privileges and deploys ransomware.

**Data/System Affected:** Active Directory and all Windows systems.

### Step 5 – Impact
**Business Impact:** Organization-wide outage affecting all departments.

**CIA Pillars:** Integrity and Availability.

**Gaps Exploited:** GAP-003, GAP-004, GAP-007.

**Break Points:**
- Timely patch management.
- Internal network segmentation.

---

# Kill Chain #3: Shared Credentials Used for Data Theft

**Threat Actor:** Insider (Malicious)

**Target Asset:** PACS and EHR System

**Expected Impact:** Unauthorized disclosure of patient information.

### Step 1 – Initial Access
**Vector:** Shared credentials.

**Surface:** Internal

**Detail:** An employee logs in using the shared Radiology account.

### Step 2 – Establish Foothold
**Action:** Access remains anonymous because multiple users share the account.

**MedDefense Weakness:** Shared credentials (GAP-005).

### Step 3 – Lateral Movement / Escalation
**Action:** Accesses additional patient records beyond normal duties.

**MedDefense Weakness:** Lack of monitoring (GAP-007).

### Step 4 – Objective Execution
**Action:** Exports patient records.

**Data/System Affected:** PACS and EHR databases.

### Step 5 – Impact
**Business Impact:** HIPAA violation, reputational damage and legal penalties.

**CIA Pillars:** Confidentiality.

**Gaps Exploited:** GAP-005, GAP-007, GAP-013.

**Break Points:**
- Individual user accounts with MFA.
- Audit log monitoring and DLP.

---

# Kill Chain #4: Supply Chain Compromise

**Threat Actor:** Organized Crime

**Target Asset:** EHR System

**Expected Impact:** Compromise of critical healthcare systems.

### Step 1 – Initial Access
**Vector:** Compromised vendor remote access.

**Surface:** External

**Detail:** The attacker abuses trusted vendor credentials.

### Step 2 – Establish Foothold
**Action:** Maintains remote access through the vendor connection.

**MedDefense Weakness:** Weak third-party access controls (GAP-010).

### Step 3 – Lateral Movement / Escalation
**Action:** Accesses servers through the flat network.

**MedDefense Weakness:** No segmentation (GAP-004).

### Step 4 – Objective Execution
**Action:** Installs malware and steals patient data.

**Data/System Affected:** EHR servers and databases.

### Step 5 – Impact
**Business Impact:** Data breach, ransomware and interruption of clinical operations.

**CIA Pillars:** Confidentiality, Integrity and Availability.

**Gaps Exploited:** GAP-004, GAP-007, GAP-010.

**Break Points:**
- MFA for vendor accounts.
- Least-privilege vendor access.

---

# Kill Chain #5: Insider Data Exfiltration

**Threat Actor:** Insider (Malicious)

**Target Asset:** Patient Database

**Expected Impact:** Large-scale patient data breach.

### Step 1 – Initial Access
**Vector:** Legitimate employee credentials.

**Surface:** Internal

**Detail:** An employee accesses records beyond their normal responsibilities.

### Step 2 – Establish Foothold
**Action:** Continues accessing systems using valid credentials.

**MedDefense Weakness:** No behavioral monitoring (GAP-007).

### Step 3 – Lateral Movement / Escalation
**Action:** Collects sensitive records from multiple systems.

**MedDefense Weakness:** Excessive user privileges (GAP-011).

### Step 4 – Objective Execution
**Action:** Copies patient records to removable media or cloud storage.

**Data/System Affected:** Patient database.

### Step 5 – Impact
**Business Impact:** Regulatory fines, legal action and reputational damage.

**CIA Pillars:** Confidentiality.

**Gaps Exploited:** GAP-007, GAP-011, GAP-013.

**Break Points:**
- Data Loss Prevention (DLP).
- User behavior monitoring and audit log review.
