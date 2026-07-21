# 4. Governance Architecture – MedDefense Health Systems

## Part 1 – RACI Matrix

| Security Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Department Heads | Security Analyst (You) |
|-------------------|:---:|:-------------------:|:-------------------:|:----------------:|:----------------------:|
| Security budget approval | **A** | C | C | I | I |
| Vulnerability remediation | I | **A** | **R** | C | **R** |
| Incident response execution | I | **A** | **R** | I | **R** |
| Security policy approval | **A** | **R** | C | C | C |
| Risk acceptance decisions | **A** | **R** | C | C | I |
| Security awareness training | I | **A** | C | **R** | **R** |
| Vendor risk assessment | I | **A** | C | I | **R** |
| Audit coordination | I | **A** | C | I | **R** |

### RACI Legend

- **R – Responsible:** Performs the work.
- **A – Accountable:** Ultimately owns the outcome and approves decisions.
- **C – Consulted:** Provides expertise before decisions are made.
- **I – Informed:** Kept informed of progress and outcomes.

---

# Part 2 – Role Definitions

## Data Owner

**Assigned Role:** Department Heads (e.g., Dr. Patel for Cardiology, Finance Director for billing data)

**Definition:**

The Data Owner is responsible for determining how data should be classified, who may access it and how it supports business operations.

**Why**

Department Heads understand the business value and sensitivity of the information generated within their departments and therefore decide how it should be protected.

---

## Data Controller

**Assigned Role:** MedDefense Health Systems (represented by Executive Management)

**Definition:**

The Data Controller determines why and how personal information is processed and is legally responsible for compliance with regulations such as GDPR and healthcare privacy laws.

**Why**

The organization—not an individual employee—determines the purpose and lawful processing of patient and employee data.

---

## Data Processor

**Assigned Role:** Third-party service providers (e.g., SecurePoint Consulting, cloud service providers, external payroll providers)

**Definition:**

A Data Processor processes personal information on behalf of the Data Controller according to contractual instructions.

**Why**

External vendors provide services using MedDefense data but do not determine how or why that data is processed.

---

## Data Custodian (Data Steward)

**Assigned Role:** IT Director (Sarah Park) and the IT Infrastructure Team

**Definition:**

The Data Custodian is responsible for implementing the technical controls required to protect organizational data.

**Responsibilities include:**

- Backup management
- Storage administration
- Access control implementation
- Patch management
- Encryption
- System maintenance

**Why**

The IT department manages the infrastructure where organizational data is stored and processed but does not own the data itself.

---

# Part 3 – The CISO Question

## Current Situation

MedDefense currently has no Chief Information Security Officer (CISO). James Chen is serving as Deputy CISO but does not have full executive authority.

### Consequences

- Cybersecurity lacks executive representation during strategic business decisions.
- Security responsibilities are shared informally between IT and Security, creating ownership confusion.
- Risk acceptance decisions may not receive independent security oversight.
- Long-term cybersecurity strategy depends heavily on operational priorities instead of business governance.
- Regulatory and Board reporting are more difficult without a senior security executive.

## Recommendation

MedDefense should initially adopt a **virtual Chief Information Security Officer (vCISO)** rather than hiring a full-time CISO.

With an annual security budget of **$120,000**, employing an experienced full-time CISO would consume a significant portion of the available budget, leaving fewer resources for critical improvements such as network segmentation, vulnerability remediation, centralized monitoring and staff training. A vCISO can provide strategic leadership, governance, policy development, Board reporting and regulatory guidance at a much lower cost while James Chen continues managing day-to-day security operations. As the organization's cybersecurity maturity increases and additional funding becomes available, MedDefense can transition to a permanent full-time CISO.

---

# Governance Summary

The proposed governance model clearly separates **business ownership**, **technical implementation** and **executive accountability**.

- The **CEO** remains accountable for strategic decisions, budget approval and risk acceptance.
- The **Deputy CISO** leads the cybersecurity program, defines policies and coordinates security activities.
- The **IT Director** implements technical controls and maintains infrastructure.
- **Department Heads** own the business data produced by their departments.
- The **Security Analyst** performs operational security activities including vulnerability management, monitoring, assessments, training and audit support.

This governance structure aligns with **NIST CSF 2.0 Govern (GV)**, **ISO/IEC 27001 leadership requirements** and **CIS Controls**, providing MedDefense with clear accountability and sustainable security governance.
