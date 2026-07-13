# Complete Control Matrix

## Part 1 – Control Registry

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence / Source |
|------------|--------------|----------|----------|--------------------|---------------|-------------------|
| C-001 | Firewall Allow Web Rule | Technical | Preventive | Web Server, DMZ | Strong | Firewall Configuration |
| C-002 | Firewall Default Deny Rule | Technical | Preventive | Internal Network | Strong | Firewall Configuration |
| C-003 | Firewall Traffic Logging | Technical | Detective | Network Infrastructure | Adequate | Firewall Configuration |
| C-004 | SSH Root Login Disabled | Technical | Preventive | Linux Servers | Strong | SSH Configuration |
| C-005 | SSH Public Key Authentication | Technical | Preventive | Linux Servers | Strong | SSH Configuration |
| C-006 | SSH Verbose Logging | Technical | Detective | Linux Servers | Adequate | SSH Configuration |
| C-007 | Password Policy | Administrative | Preventive | User Accounts | Adequate | Password Policy |
| C-008 | Account Lockout Policy | Technical | Preventive | Active Directory | Strong | Password Policy |
| C-009 | Sophos Endpoint Protection | Technical | Preventive | Windows Workstations | Adequate | Antivirus Report |
| C-010 | Daily Backups (Veeam) | Technical | Corrective | Production Servers | Adequate | Backup Configuration |
| C-011 | Visitor Registration | Physical | Preventive | Hospital Facilities | Adequate | Physical Security Contract |
| C-012 | Security Guard | Physical | Deterrent | Main Entrance | Adequate | Physical Security Contract |
| C-013 | CCTV Monitoring | Physical | Detective | Entrances and Parking | Weak | Physical Security Contract |
| C-014 | Security Awareness Training | Administrative | Preventive | Employees | Adequate | Training Records |
| C-015 | Active Directory Logging | Technical | Detective | Active Directory | Weak | Log Management |
| C-016 | EHR Audit Logging | Technical | Detective | EHR System | Adequate | Log Management |
| C-017 | Network Segmentation (Proposed) | Technical | Compensating | MRI Workstation | Strong | Task 6 |
| C-018 | Firewall ACLs for MRI | Technical | Compensating | MRI Workstation | Strong | Task 6 |
| C-019 | Restricted Physical Access to MRI | Physical | Preventive | MRI Control Room | Adequate | Task 6 |

---

# Part 2 – Updated Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|----------|------------|-----------|------------|--------------|-----------|
| Technical | 6 (Strong) | 4 (Adequate) | 1 (Adequate) | 2 (Strong) | 0 |
| Administrative | 2 (Adequate) | 0 | 0 | 0 | 0 |
| Physical | 2 (Adequate) | 1 (Weak) | 0 | 0 | 1 (Adequate) |

---

# Part 3 – Control Coverage Map

| Critical Asset | Preventive | Detective | Corrective | Compensating | Coverage Assessment |
|---------------|------------|-----------|------------|--------------|---------------------|
| EHR System | Firewall, Password Policy, Active Directory | EHR Audit Logs | Daily Backups | None | Partially Protected |
| Active Directory | Password Policy, Account Lockout | AD Logging | Daily Backups | None | Partially Protected |
| Medical IoT | Firewall | None | None | Network Segmentation, Firewall ACLs | Under-Protected |
| PACS / Imaging | Firewall, Authentication | None | Daily Backups | None | Under-Protected |
| Network Core | Firewall Rules | Firewall Logs | None | None | Partially Protected |
