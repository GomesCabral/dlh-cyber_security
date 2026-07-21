# 0. The Framework Landscape

## Part 1 — Three-Framework Summary

### NIST Cybersecurity Framework 2.0

The NIST Cybersecurity Framework (CSF) 2.0 is a voluntary cybersecurity risk-management framework published by the United States National Institute of Standards and Technology (NIST). It is designed to help organizations understand, communicate, assess and improve how they manage cybersecurity risk, without prescribing one specific technology or implementation method. Its Core is organized into six continuous Functions: **Govern, Identify, Protect, Detect, Respond and Recover**, which are further divided into Categories and Subcategories; organizations can also create Current and Target Profiles to compare their present and desired security posture. It is used by private companies, government organizations, critical infrastructure, healthcare providers and organizations of any size that need a strategic, business-aligned view of cybersecurity.

### CIS Critical Security Controls v8

The CIS Critical Security Controls v8 are published by the Center for Internet Security (CIS). They are a prioritized and prescriptive set of defensive actions designed to protect organizations against the most common and important cyberattacks. Version 8 contains **18 top-level Controls and 153 Safeguards**, organized into three Implementation Groups: **IG1, IG2 and IG3**; IG1 represents essential cyber hygiene, while IG2 and IG3 progressively add safeguards for organizations with greater risk, complexity and resources. CIS Controls are commonly used by organizations that need a practical implementation checklist, especially small and medium-sized organizations, IT operations teams and security teams that need to know which technical and procedural actions to implement first.

### ISO/IEC 27001:2022

ISO/IEC 27001:2022 is an international standard for Information Security Management Systems (ISMS), jointly published by the International Organization for Standardization (ISO) and the International Electrotechnical Commission (IEC). Its purpose is to define auditable requirements for establishing, implementing, maintaining and continually improving a risk-based information security management system. The standard is structured around management-system Clauses 4 through 10, covering organizational context, leadership, planning, support, operation, performance evaluation and improvement, supported by Annex A information security controls. It is used by organizations of every size and sector that need formal governance, repeatable risk management, regulatory assurance, customer confidence or independent certification.

---

## Part 2 — Relationship Map

The three frameworks are complementary rather than competing. **NIST CSF 2.0** provides the strategic structure and desired cybersecurity outcomes: it helps leadership decide **what the organization must achieve** across governance, prevention, detection, response and recovery. **CIS Controls v8** provides prioritized, practical safeguards that help technical teams decide **how to implement those outcomes**, beginning with IG1 essential cyber hygiene and expanding as maturity and resources increase. **ISO/IEC 27001** provides the formal management system, documentation, accountability, audit and continual-improvement requirements that help the organization demonstrate **that security is governed, measured and consistently performed**. MedDefense can therefore map CIS Safeguards to NIST CSF outcomes and manage the resulting policies, risks, evidence and review processes inside an ISO/IEC 27001-aligned ISMS.

A useful mental model is:

```text
NIST CSF 2.0:  What cybersecurity outcomes should we achieve?
CIS Controls:  What practical safeguards should we implement first?
ISO 27001:     How do we govern, document, audit and prove the program?
```

---

## Part 3 — MedDefense Framework Selection

### Recommendation

MedDefense should adopt:

1. **NIST CSF 2.0 as the strategic backbone**
2. **CIS Controls v8, beginning with IG1 and selected IG2 Safeguards, as the implementation baseline**
3. **ISO/IEC 27001 as the long-term governance and assurance model**

### Why NIST CSF 2.0 Should Be the Backbone

NIST CSF 2.0 is the best primary framework for MedDefense because the hospital currently has no formal framework and needs a structure that executives, IT teams, clinical leadership and the Board can understand. Its six Functions create a complete lifecycle that fits the findings from the previous MedDefense projects:

- **Govern:** establish policies, ownership, risk appetite and oversight;
- **Identify:** maintain asset inventories, criticality ratings and risk assessments;
- **Protect:** implement segmentation, access control, patching and data protection;
- **Detect:** improve monitoring, logging and medical-device visibility;
- **Respond:** formalize incident containment and communication;
- **Recover:** protect backups and maintain clinical continuity.

NIST CSF is outcome-based and flexible, so MedDefense can adopt it without building a large compliance team or implementing every control at once.

### Why CIS Controls Should Support Implementation

MedDefense has only one security analyst and one Deputy CISO, so the security strategy must be practical and prioritized. CIS Controls provide specific safeguards that can be assigned directly to IT, networking, clinical engineering and management.

MedDefense should begin with **IG1**, because it represents essential cyber hygiene, and then add high-value IG2 safeguards where the hospital's risk requires them. Early CIS priorities should include:

- enterprise and software asset inventories;
- secure configuration;
- account and access management;
- continuous vulnerability management;
- audit-log management;
- malware defenses;
- data recovery;
- network infrastructure management;
- network monitoring and defense;
- incident response.

This gives MedDefense a realistic sequence of actions rather than an unprioritized list of controls.

### Why ISO/IEC 27001 Should Be the Long-Term Assurance Model

MedDefense must demonstrate to regulators, auditors, patients and the Board that security decisions are controlled and repeatable. ISO/IEC 27001 provides the management-system structure needed to document:

- the scope of the security program;
- leadership responsibility;
- risk assessment and risk treatment;
- policies and objectives;
- control selection;
- performance measurement;
- internal audits;
- corrective actions;
- continual improvement.

Immediate certification should not be the first objective because it could consume limited staff and budget before foundational controls are implemented. MedDefense should first build an **ISO/IEC 27001-aligned ISMS**, collect evidence and improve maturity, then consider certification when the core security program is stable and audit-ready.

### Proposed Adoption Model

| Framework | MedDefense Role | Initial Use |
|---|---|---|
| NIST CSF 2.0 | Strategic backbone | Build Current and Target Profiles and organize the six-month roadmap |
| CIS Controls v8 | Technical implementation guide | Implement IG1 first, then risk-selected IG2 Safeguards |
| ISO/IEC 27001 | Governance and assurance model | Establish an ISMS, policies, evidence, audits and continual improvement |

### Final Selection

MedDefense should not select only one framework. The recommended combination is:

> **NIST CSF 2.0 for strategy, CIS Controls v8 for execution, and ISO/IEC 27001 for governance and proof.**

This combination matches MedDefense's limited staffing, urgent technical weaknesses and need for executive and regulatory assurance. NIST gives the organization a common language, CIS gives the small team an achievable implementation sequence, and ISO/IEC 27001 creates the evidence and accountability required for long-term maturity.

---

## Sources

- NIST, Cybersecurity Framework 2.0:  
  https://www.nist.gov/cyberframework

- NIST, Cybersecurity Framework 2.0 FAQs:  
  https://www.nist.gov/cyberframework/faqs

- CIS Critical Security Controls v8:  
  https://www.cisecurity.org/controls/v8

- CIS Implementation Groups:  
  https://www.cisecurity.org/controls/implementation-groups

- ISO/IEC 27001:2022:  
  https://www.iso.org/standard/27001
