# Reality Check

## Breach 1 – Regional Hospital Alpha

### Attack Vector Identification

The attackers exploited an unpatched VPN appliance with a known vulnerability to gain initial access. Once inside the network, they moved laterally across a flat network, compromised Active Directory and deployed ransomware to servers and workstations.

### MedDefense Correlation

This attack could also affect MedDefense because the following gaps already exist:

- GAP-003 – Unsupported Billing Server
- GAP-004 – Flat Network Architecture
- GAP-007 – No Centralized Security Monitoring
- GAP-008 – Untested Backup Recovery
- GAP-009 – Network Infrastructure Weaknesses

### Blind Spot Check

No new gap was identified. The existing gap analysis already covers patch management, network segmentation, monitoring, backup protection and incident response weaknesses.

---

## Breach 2 – Health Network Beta

### Attack Vector Identification

A former employee retained active credentials after termination. The organization lacked automated account deactivation, MFA, behavioral monitoring and Data Loss Prevention (DLP), allowing unauthorized access and large-scale patient record downloads.

### MedDefense Correlation

Relevant existing gaps include:

- GAP-002 – Unattended EHR Sessions
- GAP-007 – No Centralized Security Monitoring

### Blind Spot Check

This breach highlights an additional weakness that was not explicitly identified.

### New Gap

**Gap ID:** GAP-011

**Title:** No automated account lifecycle management

**Affected Asset(s):** Active Directory (Critical)

**Data at Risk:** Patient medical records (Restricted)

**Current Control Status:** Manual account management through IT requests.

**What is Missing:** Administrative Preventive controls integrating HR termination events with automatic account deactivation.

**Risk Level:** Critical

**Risk Justification:** Former employees may retain access to clinical systems and sensitive patient data.

**Potential Impact:** Unauthorized access to EHR systems, regulatory violations, financial penalties and reputational damage.

---

## Breach 3 – Community Hospital Gamma

### Attack Vector Identification

Attackers exploited an unpatched patient portal, bypassed a poorly configured DMZ, moved laterally through the flat network and accessed medical devices protected only by default credentials.

### MedDefense Correlation

The following gaps already cover most of this attack:

- GAP-001 – Legacy MRI Workstation
- GAP-004 – Flat Network Architecture
- GAP-007 – No Centralized Security Monitoring

### Blind Spot Check

This breach identifies an additional weakness not previously documented.

### New Gap

**Gap ID:** GAP-012

**Title:** Default credentials on medical device management interfaces

**Affected Asset(s):** Medical IoT Devices (Critical)

**Data at Risk:** Patient monitoring and medication data (Restricted)

**Current Control Status:** Basic network connectivity only.

**What is Missing:** Technical Preventive controls requiring replacement of vendor default credentials and secure device configuration.

**Risk Level:** Critical

**Risk Justification:** Default credentials provide attackers with immediate administrative access to patient-care devices.

**Potential Impact:** Unauthorized access to medical device management systems, manipulation of clinical information and potential impact on patient safety.

---

# Priority Reassessment

The real-world breach data confirms that MedDefense's current priorities are appropriate, particularly regarding network segmentation, unsupported systems, centralized monitoring and backup resilience. However, two additional gaps should be elevated to Critical priority: automated account lifecycle management (GAP-011) and default credential management on medical devices (GAP-012). These weaknesses have repeatedly contributed to successful healthcare breaches and directly affect systems containing Restricted patient information.

---

# Pattern Analysis

The three healthcare breaches demonstrate consistent attack patterns. Attackers exploited known but unpatched vulnerabilities, weak identity management, flat network architectures and the absence of effective monitoring. In every case, organizations had preventive controls but lacked sufficient detective and compensating controls to identify or contain attacks before they affected critical systems. MedDefense should therefore prioritize its security investment in network segmentation, centralized monitoring, identity lifecycle management and medical device security before expanding lower-priority security initiatives.
