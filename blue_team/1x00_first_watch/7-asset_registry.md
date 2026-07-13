# Asset Registry

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|--------------|-------------|-------------------|-----------------|--------|-------|
| A-001 | ehr-srv-01 | Server | Central Hospital | IT | Ubuntu 20.04 | Electronic Health Record (EHR) | 10.10.2.0/24 | Active | Hosts the EHR application |
| A-002 | ehr-db-01 | Data Store | Central Hospital | IT | PostgreSQL / Ubuntu 20.04 | EHR Database | 10.10.2.0/24 | Active | Stores patient medical records |
| A-003 | pacs-srv-01 | Server | Central Hospital | Radiology | Windows Server 2016 | PACS Imaging System | 10.10.2.0/24 | Active | Stores and distributes medical images |
| A-004 | billing-srv-01 | Server | Central Hospital | Finance | Ubuntu 18.04 | Billing and Claims Processing | 10.10.2.0/24 | Deprecated | Previously affected by ransomware and cryptominer |
| A-005 | ad-dc-01 | Server | Central Hospital | IT | Windows Server 2019 | Active Directory | 10.10.2.0/24 | Active | Primary Domain Controller |
| A-006 | ad-dc-02 | Server | Central Hospital | IT | Windows Server 2019 | Active Directory | 10.10.2.0/24 | Active | Secondary Domain Controller |
| A-007 | file-srv-01 | Server | Central Hospital | IT | Windows Server 2016 | File Sharing | 10.10.2.0/24 | Active | Department file storage |
| A-008 | print-srv-01 | Server | Central Hospital | IT | Windows Server 2012 | Print Services | 10.10.2.0/24 | Deprecated | End-of-life operating system |
| A-009 | backup-srv-01 | Server | Central Hospital | IT | Ubuntu 22.04 | Backup Services | 10.10.2.0/24 | Active | Veeam backup server |
| A-010 | NAS-01 | Data Store | Central Hospital | IT | Synology DSM 7 | Backup Repository | 10.10.2.0/24 | Active | Backup storage device |
| A-011 | web-srv-01 | Server | Central Hospital | IT | Ubuntu 20.04 | Public Website / Patient Portal | 10.10.2.0/24 | Active | Internet-facing server |
| A-012 | FortiGate Firewall | Network Device | Central Hospital | IT | FortiOS | Firewall / VPN | Core Network | Active | Main perimeter firewall |
| A-013 | Cisco Core Switch | Network Device | Central Hospital | IT | Cisco IOS | Core Network Switching | Core Network | Active | Connects all hospital networks |
| A-014 | UniFi Wireless Infrastructure | Network Device | Central Hospital | IT | Ubiquiti UniFi | Wireless Network | 10.10.1.0/24 | Active | Twelve wireless access points |
| A-015 | Netgear Router | Network Device | Westside Clinic | IT | Netgear Firmware | IPSec VPN | 10.10.10.0/24 | Active | VPN connection to Central Hospital |
| A-016 | Central Hospital Workstations | Endpoint | Central Hospital | IT | Windows 10 | Clinical and Administrative Access | 10.10.1.0/24 | Active | Approximately 320 Windows workstations |
| A-017 | Westside Clinic Workstations | Endpoint | Westside Clinic | IT | Windows 10 | Clinical and Administrative Access | 10.10.10.0/24 | Active | Approximately 45 Windows workstations |
| A-018 | Corporate HQ Workstations | Endpoint | Corporate HQ | IT | Windows 10/11 | Administrative Services | 10.10.20.0/24 | Active | Approximately 120 workstations |
| A-019 | Thin Clients | Endpoint | Central Hospital | IT | Linux Thin Client | EHR Access | 10.10.1.0/24 | Active | Approximately 60 thin clients used in the Emergency Department |
| A-020 | MRI Control Workstation (WS-RAD-01) | Endpoint | Central Hospital - Radiology | Radiology | Windows XP SP3 Embedded | MRI Scanner Control | 10.10.1.0/24 | Deprecated | End-of-life operating system required by vendor certification |
| A-021 | Philips IntelliVue Patient Monitors | IoT Medical | Central Hospital | Clinical Engineering | Philips IntelliVue Firmware | Patient Monitoring | 10.10.3.0/24 | Active | Approximately 80 devices |
| A-022 | BD Alaris Infusion Pumps | IoT Medical | Central Hospital | Clinical Engineering | BD Alaris Firmware 12.1.2 | Medication Delivery | 10.10.3.0/24 | Active | Approximately 120 pumps; known security bulletin recommends network isolation |
| A-023 | Vital Signs Monitor (MON-VITALS-3F-01) | IoT Medical | Central Hospital | Clinical Engineering | Unknown Firmware | Patient Vital Signs Monitoring | 10.10.3.0/24 | Active | Observed during physical walk-through |
| A-024 | Nurse Call System | Physical Infrastructure | Central Hospital | Facilities | IP-Based System | Nurse Call Services | 10.10.3.0/24 | Active | Network-connected nurse call infrastructure |
| A-025 | HID Badge Access System | Physical Infrastructure | Central Hospital | Facilities | HID Global | Physical Access Control | 10.10.3.0/24 | Active | Badge readers at secured entrances |
| A-026 | UNKNOWN-01 | Server | Central Hospital | Unknown | Linux 4.x | Unknown | 10.10.2.0/24 | Shadow IT | Responds on SSH and web ports but is not documented anywhere |
| A-027 | Unknown Linux Device | Server | Westside Clinic | Unknown | Linux 5.x | Unknown | 10.10.10.0/24 | Shadow IT | Responds on SSH, HTTP and port 3000; unofficial device |

# Reconciliation Notes

## Assets Found in the Network Scan but Not in Documentation

- **UNKNOWN-01 (10.10.2.99):** Linux server responding on SSH and web services. This system does not appear in any MedDefense documentation and should be investigated as potential Shadow IT.
- **Unknown Linux Device (10.10.10.200):** Linux system at Westside Clinic exposing SSH, HTTP and port 3000. It is undocumented and may represent an unauthorized monitoring or development system.
- **NAS-01:** Detected during the network scan but not included in the onboarding documentation. It appears to be a backup storage device that should be added to the official asset inventory.

## Assets Mentioned in Documentation but Not Found in the Network Scan

- The possible second server at Westside Clinic mentioned in the onboarding documentation was not detected during the network scan. It may have been decommissioned, powered off or incorrectly documented.
- The Siemens MRI scanner and GE CT scanner are referenced in the documentation but do not appear as network hosts. They may communicate through their control workstations rather than directly on the network.
- Approximately 25 iPads mentioned in the onboarding documentation were not detected during the scan. They were likely powered off, disconnected or using a different wireless network during the scan window.

## Discrepancies Between Sources

- The MRI workstation was previously described as running Windows XP Embedded. The network scan identifies it as Windows XP SP3, confirming that it is an end-of-life system.
- The print server, previously marked as unverified, was confirmed during the network scan as `print-srv-01` running Windows Server 2012.
- The network scan confirms that medical devices, workstations and servers are reachable across the environment without network segmentation, validating previous observations made during the physical assessment and the MRI risk analysis.
- The network scan identifies billing-srv-01 running Ubuntu 18.04, confirming it remains on an operating system with expired standard support.
