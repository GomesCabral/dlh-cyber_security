# Security Control Inventory

## Control C-001

**Control ID:** C-001

**Control Name:** Firewall Default Deny Rule

**Description:** Blocks all network traffic that is not explicitly permitted by previous firewall rules.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Internal network and server subnet

**Source:** Artifact 1 – Firewall Configuration

---

## Control C-002

**Control ID:** C-002

**Control Name:** Firewall Traffic Logging

**Description:** Logs firewall traffic for monitoring and investigation purposes.

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** Network infrastructure

**Source:** Artifact 1 – Firewall Configuration

---

## Control C-003

**Control ID:** C-003

**Control Name:** SSH Root Login Disabled

**Description:** Prevents direct SSH login using the root account.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Linux servers

**Source:** Artifact 2 – SSH Configuration

---

## Control C-004

**Control ID:** C-004

**Control Name:** SSH Public Key Authentication

**Description:** Requires public key authentication instead of passwords on ehr-srv-01.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** ehr-srv-01

**Source:** Artifact 2 – SSH Configuration

---

## Control C-005

**Control ID:** C-005

**Control Name:** SSH Authentication Attempt Limit

**Description:** Limits failed SSH authentication attempts to reduce brute-force attacks.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Linux servers

**Source:** Artifact 2 – SSH Configuration

---

## Control C-006

**Control ID:** C-006

**Control Name:** SSH Verbose Logging

**Description:** Records detailed SSH authentication events for auditing and investigation.

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** Linux servers

**Source:** Artifact 2 – SSH Configuration

---

## Control C-007

**Control ID:** C-007

**Control Name:** Password Policy

**Description:** Defines password complexity, minimum length, password history and rotation requirements for user accounts.

**Category:** Administrative

**Function:** Preventive

**Asset(s) Protected:** User accounts

**Source:** Artifact 3 – Password Policy

---

## Control C-008

**Control ID:** C-008

**Control Name:** Account Lockout Policy

**Description:** Locks user accounts after five failed authentication attempts for thirty minutes.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Active Directory user accounts

**Source:** Artifact 3 – Password Policy

---

## Control C-009

**Control ID:** C-009

**Control Name:** Sophos Endpoint Protection

**Description:** Provides real-time malware protection for managed Windows workstations.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Windows workstations

**Source:** Artifact 4 – Sophos Antivirus Status Report

---

## Control C-010

**Control ID:** C-010

**Control Name:** Malware Detection and Quarantine

**Description:** Detects malicious software and automatically blocks or quarantines identified threats.

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** Managed Windows workstations

**Source:** Artifact 4 – Sophos Antivirus Status Report

---

## Control C-011

**Control ID:** C-011

**Control Name:** Veeam Backup System

**Description:** Performs scheduled daily backups of selected production servers to support system recovery.

**Category:** Technical

**Function:** Corrective

**Asset(s) Protected:** Critical production servers

**Source:** Artifact 5 – Backup Configuration

---

## Control C-012

**Control ID:** C-012

**Control Name:** Security Awareness Training

**Description:** Provides mandatory annual cybersecurity awareness training for employees.

**Category:** Administrative

**Function:** Preventive

**Asset(s) Protected:** Organization personnel

**Source:** Artifact 7 – Training Records

---

## Control C-013

**Control ID:** C-013

**Control Name:** Security Guard

**Description:** A uniformed security guard verifies visitors and reports security incidents at the main entrance.

**Category:** Physical

**Function:** Deterrent

**Asset(s) Protected:** MedDefense Central Hospital main entrance

**Source:** Artifact 6 – Physical Security Contract

---

## Control C-014

**Control ID:** C-014

**Control Name:** Visitor Registration

**Description:** Visitors are registered and their badges verified before entering the facility.

**Category:** Physical

**Function:** Preventive

**Asset(s) Protected:** MedDefense Central Hospital

**Source:** Artifact 6 – Physical Security Contract

---

## Control C-015

**Control ID:** C-015

**Control Name:** CCTV Monitoring

**Description:** CCTV cameras record activity at selected entrances and parking areas.

**Category:** Physical

**Function:** Detective

**Asset(s) Protected:** Main entrance, emergency entrance and parking garage

**Source:** Artifact 6 – Physical Security Contract

---

## Control C-016

**Control ID:** C-016

**Control Name:** System and Firewall Log Collection

**Description:** Firewall, Windows, Linux, Apache and Active Directory logs are retained for operational review.

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** Network devices, servers and Active Directory

**Source:** Artifact 8 – Log Management

---

# Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|----------|------------|-----------|------------|--------------|-----------|
| **Technical** | C-001, C-003, C-004, C-005, C-008, C-009 | C-002, C-006, C-010, C-016 | C-011 | — | — |
| **Administrative** | C-007, C-012 | — | — | — | — |
| **Physical** | C-014 | C-015 | — | — | C-013 |
