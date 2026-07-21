# 4. Governance Architecture – MedDefense Health Systems

# Part 1 – RACI Matrix

| Security Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
|-------------------|:---:|:-------------------:|:-------------------:|:----------:|:----------------------:|
| Security budget approval | **A** | **R** | C | I | I |
| Vulnerability remediation | I | **A** | **R** | C | R |
| Incident response execution | I | **A** | **R** | C | R |
| Security policy approval | **A** | **R** | C | C | C |
| Risk acceptance decisions | **A** | C | C | C | I |
| Security awareness training | I | **A** | C | **R** | R |
| Vendor risk assessment | I | **A** | C | C | **R** |
| Audit coordination | I | **A** | C | C | **R** |

## RACI Legend

- **R – Responsible:** Performs the work.
- **A – Accountable:** Final decision maker and owner.
- **C – Consulted:** Provides advice before decisions.
- **I – Informed:** Receives updates.

---

# Part 2 – Role Definitions

## Data Owner

**Assigned Role:** Dept Heads (for example Dr. Patel for Cardiology and the Finance Director for Billing).

### Definition

The Data Owner decides how business data is classified, who should have access to it and how it supports clinical or business operations.

### Why

Department Heads understand the value and sensitivity of their own information and therefore own the business risk associated with that data.

---

## Data Controller

**Assigned Role:** MedDefense Health Systems (Executive Management).

### Definition

The Data Controller determines why and how personal information is processed and is legally responsible for compliance with GDPR and healthcare privacy regulations.

### Why

Only the organization can legally determine the purpose for processing patient and employee information.

---

## Data Processor

**Assigned Role:** Third-party providers such as SecurePoint Consulting, Microsoft 365 and other contracted service providers.

### Definition

A Data Processor handles personal data on behalf of the Data Controller following contractual instructions.

### Why

These providers process MedDefense information but never determine its purpose.

---

## Data Custodian (Data Steward)

**Assigned Role:** Sarah Park (IT Director) and the Infrastructure Team.

### Definition

The Data Custodian is responsible for implementing and maintaining the technical controls that protect organizational data.

### Responsibilities

- Backup administration
- Storage management
- Patch management
- Access control implementation
- Encryption
- Server maintenance
- Disaster recovery support

### Why

IT manages the systems that store and process information but does not own the data itself.

---

# Governance Ownership vs Technical Custody

Business ownership of data belongs to the **Data Owner** (Dept Heads), who decides how information should be used and protected. Technical custody belongs to the **Data Custodian** (IT Director and Infrastructure Team), who implements the security controls that protect the systems where the data resides. This separation ensures that business decisions remain with the departments while technical implementation remains with IT.

---

# Part 3 – The CISO Question

## Current Situation

The **CISO position is currently vacant** at MedDefense Health Systems.

James Chen currently serves as **Deputy CISO**, providing operational leadership for the security program, but he does not possess the executive authority or organizational independence normally associated with a permanent Chief Information Security Officer.

## Consequences of the Vacant CISO Position

- Cybersecurity lacks executive representation during strategic planning.
- Security priorities may compete with operational IT priorities.
- Risk acceptance decisions rely heavily on executive management instead of an independent security executive.
- Long-term cybersecurity governance is weaker.
- Board reporting and regulatory communication become more difficult.
- Strategic security initiatives may be delayed because no dedicated executive owns the entire program.

## Recommendation

MedDefense has two realistic options:

**Option 1:** Hire a full-time Chief Information Security Officer (CISO).

**Option 2:** Outsource the role to a virtual Chief Information Security Officer (vCISO).

### Recommended Option

MedDefense should adopt a **virtual CISO (vCISO)** during the next 12–24 months.

With an annual cybersecurity budget of approximately **$120,000**, hiring an experienced full-time CISO would consume a large percentage of the available budget and reduce funding for higher-priority improvements such as vulnerability remediation, SIEM deployment, network segmentation and medical-device security. A vCISO provides strategic governance, Board reporting, regulatory guidance, policy development and risk management at a significantly lower cost while James Chen continues managing day-to-day security operations. As the cybersecurity program matures and the budget increases, MedDefense can later transition to a permanent full-time CISO.

---

# Overall Governance Assessment

This governance architecture clearly separates executive decision-making, security leadership, IT operations and business ownership. Executive management owns business risk, James Chen coordinates the cybersecurity program, Sarah Park manages technical implementation, Department Heads own business data and operational impact, and the Security Analyst provides technical analysis and operational support. This structure aligns with NIST CSF 2.0 Govern (GV), CIS Controls v8 and ISO/IEC 27001 governance principles.
