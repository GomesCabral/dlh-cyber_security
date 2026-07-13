# Shadow Systems Assessment

## Shadow System 1 – Personal NAS

### Risk Assessment

**Sensitive Data:**  
The NAS may contain research data, medical images, patient information or other clinical files related to cardiology research.

**Missing Security Controls:**  
The device is not protected by the organization's backup process, endpoint protection, centralized logging, asset management or security monitoring.

**Worst-Case Scenario:**  
An attacker could steal sensitive research or patient data, encrypt the files with ransomware or use the NAS as an entry point for lateral movement into the MedDefense network.

### Recommended Response

**Strategy:** Migrate

**Justification:**  
Research data should be migrated to an approved hospital storage platform protected by existing security controls. After confirming successful migration, the personal NAS should be removed from the network.

### Asset Registry Update

| Asset ID | Name | Type | Location | Owner | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|-------|-------------|-------------------|-----------------|--------|-------|
| A-028 | Personal Research NAS | Data Store | Cardiology Office | Cardiology | Unknown NAS OS | Research Data Storage | Unknown | Shadow IT | Personally purchased device connected without IT approval |

---

## Shadow System 2 – Personal Google Drive

### Risk Assessment

**Sensitive Data:**  
Marketing media files, internal communications, public relations documents and vendor information.

**Missing Security Controls:**  
The system is outside Active Directory, backup processes, centralized logging, password policy and corporate access management.

**Worst-Case Scenario:**  
Compromise of the personal Gmail account could expose internal business information or allow unauthorized modification or deletion of organizational files.

### Recommended Response

**Strategy:** Migrate

**Justification:**  
All files should be transferred to an approved corporate collaboration platform managed by MedDefense IT. The personal Google Drive should no longer be used for organizational business.

### Asset Registry Update

| Asset ID | Name | Type | Location | Owner | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|-------|-------------|-------------------|-----------------|--------|-------|
| A-029 | Personal Google Drive | Application | Marketing Department | Marketing | Google Drive | File Sharing | Cloud | Shadow IT | Linked to a personal Gmail account |

---

## Shadow System 3 – Raspberry Pi Network Monitor

### Risk Assessment

**Sensitive Data:**  
The Raspberry Pi may have access to network traffic, monitoring data, system information or administrative credentials depending on its original configuration.

**Missing Security Controls:**  
The device is not included in asset management, vulnerability management, security monitoring or formal maintenance processes.

**Worst-Case Scenario:**  
An attacker could compromise the Raspberry Pi and use it as a persistent foothold to monitor network traffic or launch attacks against internal systems.

### Recommended Response

**Strategy:** Legitimize and Secure

**Justification:**  
The device appears to have been deployed for a legitimate operational purpose. It should be documented, fully reviewed, patched, hardened and incorporated into MedDefense's official security management processes.

### Asset Registry Update

| Asset ID | Name | Type | Location | Owner | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|-------|-------------|-------------------|-----------------|--------|-------|
| A-030 | Raspberry Pi Network Monitor | Network Device | Central Hospital – Second Floor | IT | Raspberry Pi OS | Network Monitoring | Unknown | Shadow IT | Installed by previous intern without formal documentation |

---

## Shadow IT Policy Recommendation

MedDefense should implement a formal **Technology Approval and Asset Registration Policy** requiring that every new device, application or cloud service be reviewed and approved by the IT department before being connected to the corporate environment. The policy should require all assets to be recorded in the official Asset Registry, managed through standard security controls and periodically audited to identify unauthorized systems before they become operational or store sensitive organizational data.
