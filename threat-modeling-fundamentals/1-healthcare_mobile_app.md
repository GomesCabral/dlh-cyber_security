# Healthcare Mobile App Threat Model

## System Overview

The system is a healthcare mobile application that allows patients to view medical records, schedule appointments, message healthcare providers, and receive prescription refills.


##  Architecture

```
Patient Mobile App (iOS/Android)
    |
    v
REST API Backend
    |
    v
Hospital Systems
```

### Most Critical Asset
The most critical asset in this system is **patient medical data**, also known as **Protected Health Information (PHI)**.

### Reasoning Using the CIA Triad

| CIA Component| Explanation
|----------------|-------------------------------
|Confidentiality|Medical records contain highly sensitive personal health information. Unauthorized disclosure could violate patient privacy and healthcare regulations.|
|Integrity| Medical data must be accurate. If prescriptions, diagnoses, or treatment notes are modified, patients could receive incorrect care.
|Availability| Doctors and patients need timely access to medical records, prescriptions, and messages. If the system is unavailable, treatment or medication refills may be delayed.

### Conclusion

Patient medical data is the most critical asset because a breach could harm patient privacy, patient safety, and trust in the healthcare provider.
---


### STRIDE Analysis: Message Healthcare Providers Feature
|Stride Category | Threat Description | Attack Scenario | Potential Impact | Suggested Mitigation
|----------------|----------------|---------------|----------------|---------------|
|Spoofing | An attacker pretends to be a doctor or patient.| An attacker steals a doctor’s credentials and sends false medical advice to patients.| Patient harm, loss of trust, unauthorized access to conversations. | Use MFA, strong authentication, secure session management, and device verification.
|Tampering | A message is modified before it reaches the recipient. | An attacker alters a prescription-related message from “take 1 pill” to “take 3 pills.” | Incorrect treatment, patient safety risk, legal consequences. | Use TLS, message integrity checks, secure APIs, and database access controls.
|Repudiation | A user denies sending or receiving a message. | A provider sends medical instructions but later denies sending them. | Legal disputes, lack of accountability, difficulty investigating incidents. | Use audit logs, timestamps, user IDs, and tamper-resistant logging.
|Information Disclosure | Private medical messages are exposed to unauthorized users. | A broken access control flaw allows one patient to view another patient’s messages. | PHI breach, privacy violation, regulatory penalties. | Enforce role-based access control, encrypt data, and validate authorization on every request.
|Denial of Service | Messaging service becomes unavailable. | An attacker floods the messaging API with requests, preventing patients from contacting providers. | Delayed care, missed urgent messages, reduced trust. | Use rate limiting, monitoring, autoscaling, and DDoS protection.
|Elevation of Privilege | A normal patient gains provider-level access. | A patient manipulates API parameters to access provider-only message functions. | Unauthorized access to multiple patient conversations or medical data. | Enforce server-side authorization, least privilege, and role-based access control.

### Prioritized Security Controls to Protect Patient Data

|Priority|Security Control| Why It Matters
|----------|----------|----------|
|1| Strong authentication with MFA | Prevents attackers from easily accessing patient or provider accounts, especially if passwords are stolen.
|2| Role-Based Access Control (RBAC) |Ensures patients, doctors, nurses, and admins only access the data and functions they are authorized to use.
|3| Encryption in transit and at rest |Protects PHI when it is sent between the mobile app, API, database, and hospital systems, and when stored.
|4| Audit logging and monitoring | Records who accessed or changed patient data, helping detect abuse and support investigations.
|5| Secure API validation and authorization checks | Prevents attackers from manipulating API requests to access other patients’ records or provider-only functions.
---

### 
### Additional Recommended Controls

-   Use secure session management with short token expiration.
-   Store tokens securely on mobile devices using Keychain or Android Keystore.
-   Verify hospital system integrations.
-   Apply least privilege to backend services and database accounts.
-   Perform regular penetration testing and vulnerability scanning.
-   Avoid logging sensitive medical information.
-   Implement alerting for suspicious access patterns.
