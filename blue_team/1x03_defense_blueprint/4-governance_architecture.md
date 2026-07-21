# 4. Governance Architecture – MedDefense Health Systems

# Part 1 – RACI Matrix

| Security Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
|-------------------|:---:|:-------------------:|:-------------------:|:----------:|:----------------------:|
| Security budget approval | **A** | **C** | C | C | I |
| Vulnerability remediation | I | **A** | **R** | C | R |
| Incident response execution | **A** | **R** | **R** | C | R |
| Security policy approval | **A** | **R** | C | C | I |
| Risk acceptance decisions | **A** | C | C | **R** | I |
| Security awareness training | I | **A** | C | **R** | R |
| Vendor risk assessment | I | **A** | C | C | **R** |
| Audit coordination | I | **A** | **R** | C | **R** |

## RACI Legend

- **R – Responsible:** Performs the work.
- **A – Accountable:** Final decision maker.
- **C – Consulted:** Provides advice before decisions are made.
- **I – Informed:** Receives updates.

---

# Part 2 – Role Definitions

## Data Owner

**Assigned Role:** Dept Heads (e.g., Dr. Patel for Cardiology, Finance Director for Billing).

### Definition

The Data Owner determines how business data is classified, who is allowed to access it and how it supports clinical or business operations.

### Why

Department Heads understand the operational value and sensitivity of their departmental information and therefore own the business risk associated with that data.

---

## Data Controller

**Assigned Role:** MedDefense Health Systems (Executive Management).

### Definition

The Data Controller determines why and how personal information is processed and is legally responsible for compliance with GDPR and healthcare privacy regulations.

### Why

Only MedDefense determines the lawful purposes for processing patient and employee information.

---

## Data Processor

**Assigned Role:** Third-party providers such as SecurePoint Consulting, Microsoft 365 and other contracted vendors.

### Definition

A Data Processor processes personal information on behalf of the Data Controller according to contractual instructions.

### Why

External providers process MedDefense information but do not determine the purpose for processing it.

---

## Data Custodian (Data Steward)

**Assigned Role:** Sarah Park (IT Director) and the IT Infrastructure Team.

### Definition

The Data Custodian implements and maintains the technical controls that protect organizational data.

### Responsibilities

- Backup administration
- Storage management
- Patch management
- Access control implementation
- Encryption
- Server administration
- Disaster recovery support

### Why

IT manages the systems that store and process information but does not own the information itself.

---

# Governance Ownership vs Technical Custody

Business ownership belongs to the **Data Owner (Dept Heads)**, who determines how organizational information should be used, classified and protected according to business needs. Technical custody belongs to the **Data Custodian (IT Director and Infrastructure Team)**, who implements and operates the technical safeguards protecting that information. This separation ensures that business ownership remains with operational leadership while technical implementation remains with IT.

---

# Part 3 – The CISO Question

## Current Situation

The **CISO position is currently vacant** at MedDefense Health Systems.

James Chen currently serves as **Deputy CISO**, providing operational leadership for the cybersecurity program, but he does not possess the executive authority of a permanent Chief Information Security Officer.

## Consequences of the Vacant CISO Position

- Cybersecurity lacks executive representation at Board level.
- Strategic security decisions depend on executive management rather than a dedicated security executive.
- Risk acceptance decisions require greater involvement from business leadership.
- Long-term cybersecurity governance is more difficult to coordinate.
- Regulatory reporting and strategic planning become less effective.
- Security priorities may compete with operational IT priorities.

## Recommendation

MedDefense has two realistic options:

- **Option 1:** Hire a full-time CISO.
- **Option 2:** Outsource the function to a virtual Chief Information Security Officer (vCISO).

### Recommended Option

MedDefense should initially adopt a **vCISO**.

With an annual cybersecurity budget of approximately **$120,000**, hiring an experienced full-time CISO would consume a significant portion of the available budget and reduce funding for vulnerability remediation, network segmentation, SIEM deployment and medical device security improvements.

A vCISO can provide executive security governance, Board reporting, policy development and risk management while James Chen continues leading day-to-day security operations. As MedDefense's cybersecurity maturity grows and funding increases, the organization can later transition to a permanent full-time CISO.

---

# Overall Governance Assessment

This governance model clearly separates executive governance, business ownership, cybersecurity leadership and technical implementation. Executive leadership owns business risk, James Chen coordinates the security program, Sarah Park manages technical implementation, Department Heads own business data and operational impact, and the Security Analyst performs technical security operations. The model aligns with NIST CSF 2.0, CIS Controls v8 and ISO/IEC 27001 governance principles while remaining realistic for MedDefense's staffing and budget.
